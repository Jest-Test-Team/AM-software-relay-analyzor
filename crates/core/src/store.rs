use crate::model::*;
use crate::Mac;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;

/// A device is considered Online if seen within this window.
pub const ONLINE_WINDOW_MINUTES: i64 = 10;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS device (
    id            INTEGER PRIMARY KEY,
    mac           TEXT NOT NULL UNIQUE,
    vendor        TEXT,
    hostname      TEXT,
    mdns_name     TEXT,
    device_type   TEXT NOT NULL DEFAULT 'unknown',
    services      TEXT NOT NULL DEFAULT '[]',
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    acknowledged  INTEGER NOT NULL DEFAULT 0,
    trusted       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ip_binding (
    mac         TEXT NOT NULL,
    ip          TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (mac, ip)
);
CREATE INDEX IF NOT EXISTS ip_binding_ip ON ip_binding(ip, last_seen);
CREATE TABLE IF NOT EXISTS flow (
    id        INTEGER PRIMARY KEY,
    ts        TEXT NOT NULL,
    pid       INTEGER,
    process   TEXT,
    proto     TEXT NOT NULL,
    src_ip    TEXT NOT NULL,
    src_port  INTEGER NOT NULL,
    dst_ip    TEXT NOT NULL,
    dst_port  INTEGER NOT NULL,
    dst_mac   TEXT,
    state     TEXT,
    bytes_in  INTEGER,
    bytes_out INTEGER
);
CREATE INDEX IF NOT EXISTS flow_dst ON flow(dst_ip, ts);
CREATE TABLE IF NOT EXISTS event (
    id    INTEGER PRIMARY KEY,
    ts    TEXT NOT NULL,
    kind  TEXT NOT NULL,
    mac   TEXT,
    detail TEXT NOT NULL
);
"#;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct IngestReport {
    pub observations: usize,
    pub new_devices: Vec<Mac>,
    pub updated_devices: usize,
    /// Observations that carried neither a MAC nor an IP we could resolve.
    pub unmatched: usize,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref())
            .with_context(|| format!("opening store {}", path.as_ref().display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn)
    }

    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Merge a batch of observations. `enrich` fills vendor / type for new or
    /// changed devices (kept as a callback so `core` stays free of OUI data).
    pub fn ingest(
        &mut self,
        obs: &[Observation],
        enrich: &dyn Fn(&mut Device),
    ) -> Result<IngestReport> {
        let tx = self.conn.transaction()?;
        let mut report = IngestReport {
            observations: obs.len(),
            ..Default::default()
        };
        let mut touched = BTreeSet::new();

        for o in obs {
            let mac = match o.mac {
                Some(m) if !m.is_multicast() && !m.is_broadcast() => Some(m),
                Some(_) => continue,
                None => match o.ip {
                    Some(ip) => mac_for_ip(&tx, ip)?,
                    None => None,
                },
            };
            let Some(mac) = mac else {
                report.unmatched += 1;
                continue;
            };
            let ts = o.seen_at.to_rfc3339();
            let existed: bool = tx
                .query_row(
                    "SELECT 1 FROM device WHERE mac=?1",
                    [mac.to_string()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !existed {
                tx.execute(
                    "INSERT INTO device (mac, first_seen, last_seen) VALUES (?1, ?2, ?2)",
                    params![mac.to_string(), ts],
                )?;
                tx.execute(
                    "INSERT INTO event (ts, kind, mac, detail) VALUES (?1, 'new_device', ?2, ?3)",
                    params![
                        ts,
                        mac.to_string(),
                        format!("{:?} via {:?}", o.ip, o.source)
                    ],
                )?;
                report.new_devices.push(mac);
            }
            // Only MAC-bearing sightings (ARP/NDP) prove liveness at L2; IP-only
            // sightings still count as "seen".
            tx.execute(
                "UPDATE device SET last_seen = max(last_seen, ?2) WHERE mac=?1",
                params![mac.to_string(), ts],
            )?;
            if let (Some(ip), Some(_)) = (o.ip, o.mac) {
                tx.execute(
                    "INSERT INTO ip_binding (mac, ip, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)
                     ON CONFLICT(mac, ip) DO UPDATE SET last_seen = max(last_seen, excluded.last_seen)",
                    params![mac.to_string(), ip.to_string(), ts],
                )?;
            }
            if let Some(h) = o.hostname.as_deref().filter(|h| !h.is_empty()) {
                let col = match o.source {
                    Source::Mdns => "mdns_name",
                    _ => "hostname",
                };
                // Prefer names from mDNS/SSDP/rDNS over nothing, never overwrite with empty.
                tx.execute(
                    &format!("UPDATE device SET {col} = ?2 WHERE mac=?1"),
                    params![mac.to_string(), h],
                )?;
            }
            if !o.services.is_empty() {
                let cur: String = tx.query_row(
                    "SELECT services FROM device WHERE mac=?1",
                    [mac.to_string()],
                    |r| r.get(0),
                )?;
                let mut set: BTreeSet<String> = serde_json::from_str(&cur).unwrap_or_default();
                set.extend(o.services.iter().cloned());
                tx.execute(
                    "UPDATE device SET services=?2 WHERE mac=?1",
                    params![mac.to_string(), serde_json::to_string(&set)?],
                )?;
            }
            touched.insert(mac);
        }

        // Enrichment pass over every touched device.
        let now = Utc::now();
        for mac in &touched {
            if let Some(mut d) = load_device(&tx, *mac, now)? {
                let before = (d.vendor.clone(), d.device_type);
                enrich(&mut d);
                if (d.vendor.clone(), d.device_type) != before {
                    tx.execute(
                        "UPDATE device SET vendor=?2, device_type=?3 WHERE mac=?1",
                        params![mac.to_string(), d.vendor, d.device_type.as_str()],
                    )?;
                }
            }
        }
        report.updated_devices = touched.len() - report.new_devices.len();
        tx.commit()?;
        Ok(report)
    }

    pub fn devices(&self) -> Result<Vec<Device>> {
        self.devices_at(Utc::now())
    }

    pub fn devices_at(&self, now: DateTime<Utc>) -> Result<Vec<Device>> {
        let mut stmt = self.conn.prepare("SELECT mac FROM device")?;
        let macs: Vec<String> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut out = Vec::with_capacity(macs.len());
        for m in macs {
            if let Some(d) = load_device(&self.conn, m.parse()?, now)? {
                out.push(d);
            }
        }
        out.sort_by_key(|d| d.ips.iter().map(sort_key_ip).min().unwrap_or(u128::MAX));
        Ok(out)
    }

    pub fn device(&self, mac: Mac) -> Result<Option<Device>> {
        load_device(&self.conn, mac, Utc::now())
    }

    pub fn ip_history(&self, mac: Mac) -> Result<Vec<IpBinding>> {
        let mut stmt = self.conn.prepare(
            "SELECT ip, first_seen, last_seen FROM ip_binding WHERE mac=?1 ORDER BY first_seen",
        )?;
        let rows = stmt.query_map([mac.to_string()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (ip, f, l) = row?;
            out.push(IpBinding {
                mac,
                ip: ip.parse()?,
                first_seen: parse_ts(&f)?,
                last_seen: parse_ts(&l)?,
            });
        }
        Ok(out)
    }

    /// All MACs ever bound to an IP, oldest first (gateway-MAC-change detection).
    pub fn macs_for_ip(&self, ip: IpAddr) -> Result<Vec<IpBinding>> {
        let mut stmt = self.conn.prepare(
            "SELECT mac, first_seen, last_seen FROM ip_binding WHERE ip=?1 ORDER BY first_seen",
        )?;
        let rows = stmt.query_map([ip.to_string()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (m, f, l) = row?;
            out.push(IpBinding {
                mac: m.parse()?,
                ip,
                first_seen: parse_ts(&f)?,
                last_seen: parse_ts(&l)?,
            });
        }
        Ok(out)
    }

    pub fn set_flag(&self, mac: Mac, flag: Flag, value: bool) -> Result<bool> {
        let col = match flag {
            Flag::Acknowledged => "acknowledged",
            Flag::Trusted => "trusted",
        };
        let n = self.conn.execute(
            &format!("UPDATE device SET {col}=?2 WHERE mac=?1"),
            params![mac.to_string(), value as i64],
        )?;
        Ok(n > 0)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Flag {
    Acknowledged,
    Trusted,
}

fn mac_for_ip(conn: &Connection, ip: IpAddr) -> Result<Option<Mac>> {
    let m: Option<String> = conn
        .query_row(
            "SELECT mac FROM ip_binding WHERE ip=?1 ORDER BY last_seen DESC LIMIT 1",
            [ip.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    Ok(m.map(|s| s.parse()).transpose()?)
}

fn load_device(conn: &Connection, mac: Mac, now: DateTime<Utc>) -> Result<Option<Device>> {
    let row = conn
        .query_row(
            "SELECT id, vendor, hostname, mdns_name, device_type, services, first_seen, last_seen,
                    acknowledged, trusted
             FROM device WHERE mac=?1",
            [mac.to_string()],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, bool>(8)?,
                    r.get::<_, bool>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((id, vendor, hostname, mdns_name, dtype, services, first, last, ack, trusted)) = row
    else {
        return Ok(None);
    };
    // Current IPs: bindings seen within the online window of the device's last sighting.
    let last_seen = parse_ts(&last)?;
    let cutoff = (last_seen - Duration::minutes(ONLINE_WINDOW_MINUTES)).to_rfc3339();
    let mut stmt = conn.prepare(
        "SELECT ip FROM ip_binding WHERE mac=?1 AND last_seen >= ?2 ORDER BY last_seen DESC",
    )?;
    let ips = stmt
        .query_map(params![mac.to_string(), cutoff], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok()?.parse().ok())
        .collect();
    let status = if now - last_seen <= Duration::minutes(ONLINE_WINDOW_MINUTES) {
        ConnectionStatus::Online
    } else {
        ConnectionStatus::Offline
    };
    Ok(Some(Device {
        id,
        mac,
        mac_randomized: mac.is_randomized(),
        vendor,
        hostname,
        mdns_name,
        device_type: DeviceType::parse(&dtype),
        ips,
        services: serde_json::from_str(&services).unwrap_or_default(),
        first_seen: parse_ts(&first)?,
        last_seen,
        connection_status: status,
        acknowledged: ack,
        trusted,
    }))
}

fn parse_ts(s: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))
}

fn sort_key_ip(ip: &IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from(*v4) as u128,
        IpAddr::V6(v6) => u128::from(*v6) | (1 << 127),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arp(ip: &str, mac: &str, at: DateTime<Utc>) -> Observation {
        Observation {
            ip: Some(ip.parse().unwrap()),
            mac: Some(mac.parse().unwrap()),
            ..Observation::new(Source::Arp, at)
        }
    }

    fn noop(_: &mut Device) {}

    #[test]
    fn new_device_then_update() {
        let mut s = Store::in_memory().unwrap();
        let t0 = Utc::now();
        let r = s
            .ingest(&[arp("172.16.200.112", "1a:9d:d1:46:63:73", t0)], &noop)
            .unwrap();
        assert_eq!(r.new_devices.len(), 1);
        let r = s
            .ingest(
                &[arp(
                    "172.16.200.112",
                    "1a:9d:d1:46:63:73",
                    t0 + Duration::seconds(30),
                )],
                &noop,
            )
            .unwrap();
        assert!(r.new_devices.is_empty());
        assert_eq!(r.updated_devices, 1);
        let d = &s.devices().unwrap()[0];
        assert!(d.mac_randomized);
        assert_eq!(d.connection_status, ConnectionStatus::Online);
        assert_eq!(d.vendor_label(), "Randomized MAC");
        assert_eq!(d.display_name(), "Unknown Device");
        let mut r = d.clone();
        r.device_type = DeviceType::Router;
        assert_eq!(r.display_name(), "Router");
    }

    #[test]
    fn ip_only_observation_attaches_by_binding() {
        let mut s = Store::in_memory().unwrap();
        let t0 = Utc::now();
        s.ingest(&[arp("172.16.200.50", "c8:4c:87:11:13:0a", t0)], &noop)
            .unwrap();
        let mdns = Observation {
            ip: Some("172.16.200.50".parse().unwrap()),
            hostname: Some("LGwebOSTV".into()),
            services: vec!["_airplay._tcp".into()],
            ..Observation::new(Source::Mdns, t0)
        };
        let orphan = Observation {
            ip: Some("172.16.200.99".parse().unwrap()),
            ..Observation::new(Source::Ssdp, t0)
        };
        let r = s.ingest(&[mdns, orphan], &noop).unwrap();
        assert_eq!(r.unmatched, 1);
        let d = &s.devices().unwrap()[0];
        assert_eq!(d.display_name(), "LGwebOSTV");
        assert_eq!(d.services, vec!["_airplay._tcp".to_string()]);
    }

    #[test]
    fn offline_after_window_and_ip_history() {
        let mut s = Store::in_memory().unwrap();
        let t0 = Utc::now() - Duration::hours(2);
        s.ingest(&[arp("172.16.200.10", "90:ca:fa:b6:33:66", t0)], &noop)
            .unwrap();
        s.ingest(
            &[arp(
                "172.16.200.11",
                "90:ca:fa:b6:33:66",
                t0 + Duration::minutes(30),
            )],
            &noop,
        )
        .unwrap();
        let d = &s.devices().unwrap()[0];
        assert_eq!(d.connection_status, ConnectionStatus::Offline);
        assert_eq!(d.ips, vec!["172.16.200.11".parse::<IpAddr>().unwrap()]);
        assert_eq!(s.ip_history(d.mac).unwrap().len(), 2);
    }

    #[test]
    fn multicast_and_broadcast_ignored_and_enrich_runs() {
        let mut s = Store::in_memory().unwrap();
        let t0 = Utc::now();
        let r = s
            .ingest(
                &[
                    arp("172.16.200.255", "ff:ff:ff:ff:ff:ff", t0),
                    arp("224.0.0.251", "01:00:5e:00:00:fb", t0),
                    arp("172.16.200.1", "bc:d0:74:1e:5b:f1", t0),
                ],
                &|d: &mut Device| d.vendor = Some("Fortinet, Inc.".into()),
            )
            .unwrap();
        assert_eq!(r.new_devices.len(), 1);
        assert_eq!(s.devices().unwrap()[0].vendor_label(), "Fortinet, Inc.");
    }

    #[test]
    fn flags() {
        let mut s = Store::in_memory().unwrap();
        let m: Mac = "bc:d0:74:1e:5b:f1".parse().unwrap();
        s.ingest(&[arp("172.16.200.1", &m.to_string(), Utc::now())], &noop)
            .unwrap();
        assert!(s.set_flag(m, Flag::Trusted, true).unwrap());
        assert!(s.device(m).unwrap().unwrap().trusted);
    }
}
