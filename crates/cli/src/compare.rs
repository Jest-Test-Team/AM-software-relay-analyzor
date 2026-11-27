//! Benchmark our discovery against a device list transcribed from Kaspersky
//! Smart Home Monitor (CSV: `name,ip,mac`; ip or mac may be empty).

use anyhow::{Context, Result};
use relay_core::{Device, Mac};
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub struct Expected {
    pub name: String,
    pub ip: Option<IpAddr>,
    pub mac: Option<Mac>,
}

pub fn parse_csv(text: &str) -> Vec<Expected> {
    text.lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty() && !l.starts_with('#') && !l.to_ascii_lowercase().starts_with("name,")
        })
        .map(|l| {
            let f: Vec<&str> = l.split(',').map(str::trim).collect();
            Expected {
                name: f.first().unwrap_or(&"").to_string(),
                ip: f.get(1).and_then(|s| s.parse().ok()),
                mac: f.get(2).and_then(|s| s.parse().ok()),
            }
        })
        .collect()
}

/// Generic labels Kaspersky shows when it has no real name; useless for matching.
const GENERIC: &[&str] = &[
    "unknown device",
    "mobile phone",
    "router",
    "computer",
    "tablet",
];

/// Match by MAC first (stable), then current IP, then name prefix (Kaspersky
/// truncates long names with "…").
pub fn matches<'a>(e: &Expected, devs: &'a [Device]) -> Option<&'a Device> {
    if let Some(m) = e.mac {
        return devs.iter().find(|d| d.mac == m);
    }
    if let Some(ip) = e.ip {
        return devs.iter().find(|d| d.ips.contains(&ip));
    }
    let want = e.name.trim_end_matches(['…', '.']).to_lowercase();
    if want.is_empty() || GENERIC.contains(&want.as_str()) {
        return None;
    }
    devs.iter().find(|d| {
        [&d.hostname, &d.mdns_name]
            .into_iter()
            .flatten()
            .any(|n| n.to_lowercase().starts_with(&want))
    })
}

pub fn run(devs: &[Device], path: &Path) -> Result<()> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let expected = parse_csv(&text);
    anyhow::ensure!(!expected.is_empty(), "no rows in {}", path.display());
    let mut hit = 0;
    for e in &expected {
        match matches(e, devs) {
            Some(d) => {
                hit += 1;
                println!(
                    "  ✔ {:<28} → {} {} [{}]",
                    e.name,
                    d.mac,
                    d.display_name(),
                    d.device_type.as_str()
                );
            }
            None => println!("  ✘ {:<28} not found", e.name),
        }
    }
    let recall = hit as f64 / expected.len() as f64 * 100.0;
    println!(
        "recall {hit}/{} = {recall:.0}%  (we see {} devices in total)",
        expected.len(),
        devs.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rows() {
        let rows = parse_csv("name,ip,mac\n# comment\nAndroid_X,192.168.50.112,1a:9d:d1:46:63:73\nRouter,192.168.50.254,\nTV,,\n");
        assert_eq!(rows.len(), 3);
        assert!(rows[0].mac.is_some());
        assert!(rows[1].mac.is_none() && rows[1].ip.is_some());
        assert!(rows[2].ip.is_none());
    }
}
