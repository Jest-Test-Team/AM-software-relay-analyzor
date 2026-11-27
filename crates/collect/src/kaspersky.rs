//! Optional Kaspersky (consumer, macOS) adapter — schema-agnostic and read-only.
//!
//! Kaspersky publishes no consumer telemetry API and no schema for its local
//! SQLite files. Instead of guessing a schema, `probe` lists tables/columns
//! and finds IP- and MAC-shaped values; `import` turns rows that carry both an
//! IP and a MAC into observations (Source::Kaspersky).
//!
//! Always run against a *copy* of the files (including `-wal`/`-shm`); never
//! disable Kaspersky Self-Defense to obtain them.

use anyhow::{Context, Result};
use chrono::Utc;
use relay_core::{Mac, Observation, Source};
use rusqlite::{types::ValueRef, Connection, OpenFlags};
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Default)]
pub struct TableReport {
    pub name: String,
    pub columns: Vec<String>,
    pub rows: i64,
    pub ip_values: usize,
    pub mac_values: usize,
    /// Up to 3 example (ip, mac, name) rows that would be imported.
    pub samples: Vec<(Option<IpAddr>, Option<Mac>, Option<String>)>,
}

pub fn open_ro(path: &Path) -> Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| {
        format!(
            "opening {} read-only (copy it, with -wal/-shm, first)",
            path.display()
        )
    })
}

/// Pull IP and MAC tokens out of free text.
pub fn tokens(s: &str) -> (Vec<IpAddr>, Vec<Mac>) {
    let mut ips = Vec::new();
    let mut macs = Vec::new();
    for t in s.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '.' || c == '-')) {
        let t = t.trim_matches(|c| c == '.' || c == ':' || c == '-');
        if t.len() < 7 {
            continue;
        }
        if let Ok(m) = t.parse::<Mac>() {
            if !m.is_multicast() && m.0 != [0; 6] {
                macs.push(m);
            }
        } else if let Ok(ip) = t.parse::<IpAddr>() {
            // LAN devices only: private / link-local / CGNAT v4 and real v6 forms.
            // This also screens out version strings like 27.1.0.5.
            let plausible = match ip {
                IpAddr::V4(v4) => {
                    let o = v4.octets();
                    v4.is_private() || v4.is_link_local() || (o[0] == 100 && (o[1] & 0xc0) == 64)
                }
                IpAddr::V6(_) => t.contains("::") || t.matches(':').count() >= 5,
            };
            if plausible && !ip.is_unspecified() && !ip.is_loopback() {
                ips.push(ip);
            }
        }
    }
    (ips, macs)
}

const NAME_COLS: &[&str] = &[
    "name",
    "hostname",
    "host_name",
    "device_name",
    "devicename",
    "title",
    "friendly_name",
];

fn cell_text(v: ValueRef) -> Option<String> {
    match v {
        ValueRef::Text(t) => Some(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => std::str::from_utf8(b).ok().map(str::to_string),
        _ => None,
    }
}

fn scan_table(
    conn: &Connection,
    table: &str,
    mut on_row: impl FnMut(Vec<IpAddr>, Vec<Mac>, Option<String>),
) -> Result<TableReport> {
    let q = format!("SELECT * FROM \"{}\"", table.replace('"', "\"\""));
    let mut stmt = conn.prepare(&q)?;
    let columns: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
    let name_idx = columns
        .iter()
        .position(|c| NAME_COLS.contains(&c.to_ascii_lowercase().as_str()));
    let mut rep = TableReport {
        name: table.into(),
        columns: columns.clone(),
        ..Default::default()
    };
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        rep.rows += 1;
        let mut ips = Vec::new();
        let mut macs = Vec::new();
        let mut name = None;
        for i in 0..columns.len() {
            let Some(text) = cell_text(row.get_ref(i)?) else {
                continue;
            };
            if Some(i) == name_idx {
                name = Some(text.clone()).filter(|n| !n.is_empty());
            }
            let (a, b) = tokens(&text);
            ips.extend(a);
            macs.extend(b);
        }
        rep.ip_values += ips.len();
        rep.mac_values += macs.len();
        if (ips.len() == 1 || macs.len() == 1) && rep.samples.len() < 3 {
            rep.samples
                .push((ips.first().copied(), macs.first().copied(), name.clone()));
        }
        on_row(ips, macs, name);
    }
    Ok(rep)
}

fn tables(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?;
    let names = stmt
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(names)
}

pub fn probe(path: &Path) -> Result<Vec<TableReport>> {
    let conn = open_ro(path)?;
    tables(&conn)?
        .iter()
        .map(|t| scan_table(&conn, t, |_, _, _| {}))
        .collect()
}

/// Rows with exactly one MAC (and at most one IP) become observations.
pub fn import(path: &Path) -> Result<Vec<Observation>> {
    let conn = open_ro(path)?;
    let now = Utc::now();
    let mut out = Vec::new();
    for t in tables(&conn)? {
        scan_table(&conn, &t, |ips, macs, name| {
            if macs.len() == 1 && ips.len() <= 1 {
                out.push(Observation {
                    ip: ips.first().copied(),
                    mac: macs.first().copied(),
                    hostname: name,
                    ..Observation::new(Source::Kaspersky, now)
                });
            }
        })?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_extraction() {
        let (ips, macs) =
            tokens(r#"{"ip":"192.168.50.112","mac":"1A-9D-D1-46-63-73","ver":"21.7.0.1"}"#);
        assert_eq!(ips, vec!["192.168.50.112".parse::<IpAddr>().unwrap()]);
        assert_eq!(macs[0].to_string(), "1a:9d:d1:46:63:73");
    }

    #[test]
    fn probe_and_import_on_synthetic_db() {
        let dir = std::env::temp_dir().join(format!("relayscan-k-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k.db");
        let _ = std::fs::remove_file(&path);
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE devices (id INTEGER, name TEXT, payload TEXT);
                 INSERT INTO devices VALUES (1, 'Android_OUJZGW45', 'ip=192.168.50.112 mac=1a:9d:d1:46:63:73');
                 INSERT INTO devices VALUES (2, 'Router', '{\"addr\":\"192.168.50.254\",\"hw\":\"00:09:0f:aa:00:1a\"}');
                 CREATE TABLE settings (k TEXT, v TEXT);
                 INSERT INTO settings VALUES ('version', '27.1.0.5');",
            )
            .unwrap();
        }
        let rep = probe(&path).unwrap();
        let dev = rep.iter().find(|t| t.name == "devices").unwrap();
        assert_eq!((dev.rows, dev.ip_values, dev.mac_values), (2, 2, 2));
        let obs = import(&path).unwrap();
        assert_eq!(obs.len(), 2);
        assert_eq!(obs[0].hostname.as_deref(), Some("Android_OUJZGW45"));
        assert_eq!(obs[0].source, Source::Kaspersky);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
