//! Passive neighbour-table collection (`arp -an`, `ndp -an`) on macOS/BSD.

use chrono::{DateTime, Utc};
use relay_core::{Mac, Observation, Source};
use std::net::IpAddr;

/// Parse `arp -an`. Skips incomplete, multicast and broadcast entries.
/// If `iface` is given, only that interface's entries are returned.
pub fn parse_arp(text: &str, iface: Option<&str>, now: DateTime<Utc>) -> Vec<Observation> {
    text.lines()
        .filter_map(|line| {
            // "<name> (<ip>) at <mac> on <iface> [ifscope] [permanent] [ethernet]"
            let open = line.find('(')?;
            let close = line[open..].find(')')? + open;
            let ip: IpAddr = line[open + 1..close].parse().ok()?;
            let mut rest = line[close + 1..].split_whitespace();
            if rest.next()? != "at" {
                return None;
            }
            let mac: Mac = rest.next()?.parse().ok()?;
            if rest.next()? != "on" {
                return None;
            }
            let ifname = rest.next()?;
            if iface.is_some_and(|want| want != ifname) {
                return None;
            }
            if mac.is_multicast() || mac.is_broadcast() {
                return None;
            }
            let name = line[..open].trim();
            Some(Observation {
                ip: Some(ip),
                mac: Some(mac),
                hostname: (name != "?" && !name.is_empty()).then(|| name.to_string()),
                interface: Some(ifname.to_string()),
                ..Observation::new(Source::Arp, now)
            })
        })
        .collect()
}

/// Parse `ndp -an`. Stale (`S`) entries can linger for a day after a device
/// leaves, so only reachable/delay/probe states count as a live sighting.
pub fn parse_ndp(text: &str, iface: Option<&str>, now: DateTime<Utc>) -> Vec<Observation> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 5 {
                return None;
            }
            let (neighbor, lladdr, netif, state) = (cols[0], cols[1], cols[2], cols[4]);
            if iface.is_some_and(|want| want != netif) {
                return None;
            }
            if !matches!(state, "R" | "D" | "P") {
                return None;
            }
            let mac: Mac = lladdr.parse().ok()?;
            if mac.is_multicast() {
                return None;
            }
            let ip: IpAddr = neighbor.split('%').next()?.parse().ok()?;
            Some(Observation {
                ip: Some(ip),
                mac: Some(mac),
                interface: Some(netif.to_string()),
                ..Observation::new(Source::Ndp, now)
            })
        })
        .collect()
}

/// Read the live ARP + NDP tables.
pub fn collect(iface: Option<&str>) -> anyhow::Result<Vec<Observation>> {
    let now = Utc::now();
    let mut obs = parse_arp(&crate::run("arp", &["-an"])?, iface, now);
    // NDP is best-effort: hosts without IPv6 still work.
    if let Ok(text) = crate::run("ndp", &["-an"]) {
        obs.extend(parse_ndp(&text, iface, now));
    }
    Ok(obs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARP: &str = include_str!("../tests/fixtures/arp_macos.txt");
    const NDP: &str = include_str!("../tests/fixtures/ndp_macos.txt");

    #[test]
    fn arp_filters_incomplete_multicast_broadcast() {
        let obs = parse_arp(ARP, Some("en0"), Utc::now());
        let ips: Vec<String> = obs.iter().map(|o| o.ip.unwrap().to_string()).collect();
        assert_eq!(
            ips,
            [
                "192.168.50.1",
                "192.168.50.2",
                "192.168.50.10",
                "192.168.50.41",
                "192.168.50.112"
            ]
        );
        let android = obs
            .iter()
            .find(|o| o.ip.unwrap().to_string() == "192.168.50.112")
            .unwrap();
        assert!(android.mac.unwrap().is_randomized());
        assert_eq!(obs[0].mac.unwrap().to_string(), "00:09:0f:aa:00:1a");
    }

    #[test]
    fn arp_keeps_resolved_hostname_and_other_ifaces() {
        let obs = parse_arp(ARP, None, Utc::now());
        let gw = obs
            .iter()
            .find(|o| o.interface.as_deref() == Some("en7"))
            .unwrap();
        assert_eq!(gw.hostname.as_deref(), Some("gateway.lan"));
    }

    #[test]
    fn ndp_skips_stale_incomplete_and_multicast() {
        let obs = parse_ndp(NDP, Some("en0"), Utc::now());
        let ips: Vec<String> = obs.iter().map(|o| o.ip.unwrap().to_string()).collect();
        assert_eq!(
            ips,
            [
                "fe80::46:1282:cad9:9aa5",
                "fe80::9:fff:feaa:1a",
                "fd00::1234"
            ]
        );
        assert!(obs.iter().all(|o| o.source == Source::Ndp));
    }
}
