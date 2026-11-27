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

const SCHEMA_VERSION: i64 = 2;

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
    id         INTEGER PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    pid        INTEGER NOT NULL DEFAULT -1,
    process    TEXT,
    proto      TEXT NOT NULL,
    src_ip     TEXT NOT NULL,
    src_port   INTEGER NOT NULL,
    dst_ip     TEXT NOT NULL,
    dst_port   INTEGER NOT NULL,
    dst_mac    TEXT,
    state      TEXT,
    bytes_in   INTEGER,
    bytes_out  INTEGER,
    UNIQUE (proto, src_ip, src_port, dst_ip, dst_port, pid)
);
CREATE INDEX IF NOT EXISTS flow_dst ON flow(dst_ip, first_seen);
CREATE INDEX IF NOT EXISTS flow_last ON flow(last_seen);
CREATE TABLE IF NOT EXISTS intel_hit (
    indicator  TEXT NOT NULL,
    source     TEXT NOT NULL,
    verdict    TEXT,            -- JSON Verdict, NULL = looked up, nothing found
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (indicator, source)
);
CREATE TABLE IF NOT EXISTS assessment (
    mac  TEXT PRIMARY KEY,
    at   TEXT NOT NULL,
    json TEXT NOT NULL
);
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
        let ver: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if ver < SCHEMA_VERSION {
            // v1 → v2: flow became one row per connection (no data worth keeping).
            conn.execute_batch("DROP TABLE IF EXISTS flow;")?;
        }
        conn.execute_batch(SCHEMA)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
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

impl Store {
    /// Upsert a flow snapshot: one row per (5-tuple, pid); counters and
    /// last_seen advance, first_seen is kept. Returns rows that were new.
    pub fn upsert_flows(&mut self, flows: &[Flow]) -> Result<usize> {
        let tx = self.conn.transaction()?;
        let mut new = 0;
        for f in flows {
            let n = tx.execute(
                "INSERT INTO flow (first_seen, last_seen, pid, process, proto, src_ip, src_port,
                                   dst_ip, dst_port, dst_mac, state, bytes_in, bytes_out)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT (proto, src_ip, src_port, dst_ip, dst_port, pid) DO NOTHING",
                params![
                    f.first_seen.to_rfc3339(),
                    f.last_seen.to_rfc3339(),
                    f.pid.map(i64::from).unwrap_or(-1),
                    f.process,
                    f.proto.as_str(),
                    f.src_ip.to_string(),
                    f.src_port,
                    f.dst_ip.to_string(),
                    f.dst_port,
                    f.dst_mac.map(|m| m.to_string()),
                    f.state,
                    f.bytes_in.map(|b| b as i64),
                    f.bytes_out.map(|b| b as i64),
                ],
            )?;
            if n == 0 {
                tx.execute(
                    "UPDATE flow SET last_seen = max(last_seen, ?7), state = ?8,
                        bytes_in = max(coalesce(bytes_in, 0), coalesce(?9, 0)),
                        bytes_out = max(coalesce(bytes_out, 0), coalesce(?10, 0))
                     WHERE proto=?1 AND src_ip=?2 AND src_port=?3 AND dst_ip=?4 AND dst_port=?5 AND pid=?6",
                    params![
                        f.proto.as_str(),
                        f.src_ip.to_string(),
                        f.src_port,
                        f.dst_ip.to_string(),
                        f.dst_port,
                        f.pid.map(i64::from).unwrap_or(-1),
                        f.last_seen.to_rfc3339(),
                        f.state,
                        f.bytes_in.map(|b| b as i64),
                        f.bytes_out.map(|b| b as i64),
                    ],
                )?;
            } else {
                new += 1;
            }
        }
        tx.commit()?;
        Ok(new)
    }

    /// Flows seen at or after `since`, newest first.
    pub fn flows_since(&self, since: DateTime<Utc>) -> Result<Vec<Flow>> {
        let mut stmt = self.conn.prepare(
            "SELECT first_seen, last_seen, pid, process, proto, src_ip, src_port, dst_ip, dst_port,
                    dst_mac, state, bytes_in, bytes_out
             FROM flow WHERE last_seen >= ?1 ORDER BY last_seen DESC",
        )?;
        let rows = stmt.query_map([since.to_rfc3339()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, u16>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, u16>(8)?,
                r.get::<_, Option<String>>(9)?,
                r.get::<_, Option<String>>(10)?,
                r.get::<_, Option<i64>>(11)?,
                r.get::<_, Option<i64>>(12)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (fs, ls, pid, process, proto, sip, sport, dip, dport, dmac, state, bi, bo) = row?;
            out.push(Flow {
                first_seen: parse_ts(&fs)?,
                last_seen: parse_ts(&ls)?,
                pid: u32::try_from(pid).ok(),
                process,
                proto: if proto == "udp" {
                    Proto::Udp
                } else {
                    Proto::Tcp
                },
                src_ip: sip.parse()?,
                src_port: sport,
                dst_ip: dip.parse()?,
                dst_port: dport,
                dst_mac: dmac.map(|m| m.parse()).transpose()?,
                state,
                bytes_in: bi.map(|b| b as u64),
                bytes_out: bo.map(|b| b as u64),
            });
        }
        Ok(out)
    }

    /// Recent events (e.g. `new_device`), newest first.
    pub fn events(&self, limit: usize) -> Result<Vec<Event>> {
        let mut stmt = self
            .conn
            .prepare("SELECT ts, kind, mac, detail FROM event ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit as i64], |r| {
            Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (ts, k, m, d) = row?;
            out.push(Event {
                ts: parse_ts(&ts)?,
                kind: k,
                mac: m,
                detail: d,
            });
        }
        Ok(out)
    }
}

impl Store {
    /// Cached TI answer if younger than `ttl`. `Some(None)` = cached negative.
    pub fn intel_cached(
        &self,
        indicator: IpAddr,
        source: &str,
        ttl: Duration,
    ) -> Result<Option<Option<Verdict>>> {
        let row: Option<(Option<String>, String)> = self
            .conn
            .query_row(
                "SELECT verdict, fetched_at FROM intel_hit WHERE indicator=?1 AND source=?2",
                params![indicator.to_string(), source],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((v, at)) = row else { return Ok(None) };
        if Utc::now() - parse_ts(&at)? > ttl {
            return Ok(None);
        }
        Ok(Some(v.map(|j| serde_json::from_str(&j)).transpose()?))
    }

    pub fn intel_put(&self, indicator: IpAddr, source: &str, v: Option<&Verdict>) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO intel_hit (indicator, source, verdict, fetched_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                indicator.to_string(),
                source,
                v.map(serde_json::to_string).transpose()?,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// All cached positive verdicts for an indicator (any age).
    pub fn intel_verdicts(&self, indicator: IpAddr) -> Result<Vec<Verdict>> {
        let mut stmt = self
            .conn
            .prepare("SELECT verdict FROM intel_hit WHERE indicator=?1 AND verdict IS NOT NULL")?;
        let rows = stmt.query_map([indicator.to_string()], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for j in rows {
            out.push(serde_json::from_str(&j?)?);
        }
        Ok(out)
    }
}

impl Store {
    /// Keep the latest assessment per device; log level changes as events.
    pub fn save_assessment(&self, a: &crate::risk::Assessment) -> Result<()> {
        let prev = self.assessment(a.mac)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO assessment (mac, at, json) VALUES (?1, ?2, ?3)",
            params![
                a.mac.to_string(),
                a.at.to_rfc3339(),
                serde_json::to_string(a)?
            ],
        )?;
        if prev.as_ref().map(|p| p.level) != Some(a.level) {
            self.conn.execute(
                "INSERT INTO event (ts, kind, mac, detail) VALUES (?1, 'risk_level', ?2, ?3)",
                params![
                    a.at.to_rfc3339(),
                    a.mac.to_string(),
                    format!(
                        "{:?} -> {:?} (score {})",
                        prev.map(|p| p.level),
                        a.level,
                        a.score
                    )
                ],
            )?;
        }
        Ok(())
    }

    pub fn assessment(&self, mac: Mac) -> Result<Option<crate::risk::Assessment>> {
        let j: Option<String> = self
            .conn
            .query_row(
                "SELECT json FROM assessment WHERE mac=?1",
                [mac.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(j.map(|j| serde_json::from_str(&j)).transpose()?)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub ts: DateTime<Utc>,
    pub kind: String,
    pub mac: Option<String>,
    pub detail: String,
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
    fn flow_upsert_keeps_first_seen_and_grows_counters() {
        let mut s = Store::in_memory().unwrap();
        let t0 = Utc::now() - Duration::minutes(5);
        let mut f = Flow {
            first_seen: t0,
            last_seen: t0,
            pid: Some(392),
            process: Some("apsd".into()),
            proto: Proto::Tcp,
            src_ip: "192.168.50.2".parse().unwrap(),
            src_port: 63020,
            dst_ip: "17.57.145.132".parse().unwrap(),
            dst_port: 5223,
            dst_mac: None,
            state: Some("Established".into()),
            bytes_in: Some(100),
            bytes_out: Some(10),
        };
        assert_eq!(s.upsert_flows(std::slice::from_ref(&f)).unwrap(), 1);
        f.first_seen = t0 + Duration::minutes(1);
        f.last_seen = t0 + Duration::minutes(1);
        f.bytes_in = Some(500);
        assert_eq!(s.upsert_flows(&[f]).unwrap(), 0);
        let got = s.flows_since(t0).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].first_seen.timestamp(), t0.timestamp());
        assert_eq!(got[0].bytes_in, Some(500));
        assert!(got[0].dst_mac.is_none());
    }

    #[test]
    fn intel_cache_roundtrip_and_ttl() {
        let s = Store::in_memory().unwrap();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(
            s.intel_cached(ip, "feodo", Duration::hours(1)).unwrap(),
            None
        );
        s.intel_put(ip, "abuseipdb", None).unwrap();
        assert_eq!(
            s.intel_cached(ip, "abuseipdb", Duration::hours(1)).unwrap(),
            Some(None)
        );
        let v = Verdict {
            indicator: ip,
            source: "feodo".into(),
            malicious: true,
            reporters: None,
            confidence: 0.95,
            category: "botnet_cc".into(),
            detail: "test".into(),
            fetched_at: Utc::now(),
        };
        s.intel_put(ip, "feodo", Some(&v)).unwrap();
        assert_eq!(
            s.intel_cached(ip, "feodo", Duration::hours(1)).unwrap(),
            Some(Some(v.clone()))
        );
        assert_eq!(
            s.intel_cached(ip, "feodo", Duration::seconds(-1)).unwrap(),
            None
        );
        assert_eq!(s.intel_verdicts(ip).unwrap(), vec![v]);
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
