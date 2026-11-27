//! Per-process connections on this host via `nettop` (macOS; no root needed).
//! This is the macOS stand-in for Windows Sysmon Event ID 3.

use chrono::{DateTime, Utc};
use relay_core::{Flow, Mac, Proto};
use std::collections::HashMap;
use std::net::IpAddr;

/// Parse `nettop -L 1 -n -x -J state,bytes_in,bytes_out`.
/// Drops listeners, wildcard peers and loopback traffic.
pub fn parse_nettop(text: &str, now: DateTime<Utc>) -> Vec<Flow> {
    let mut out = Vec::new();
    let mut proc_: Option<(String, Option<u32>)> = None;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 4 {
            continue;
        }
        let head = cols[0];
        let Some((kind, tuple)) = head.split_once(' ').filter(|(k, _)| is_proto(k)) else {
            // Process header: "<name>.<pid>" (name may contain spaces/dots).
            proc_ = Some(match head.rsplit_once('.') {
                Some((n, pid)) if pid.chars().all(|c| c.is_ascii_digit()) => {
                    (n.to_string(), pid.parse().ok())
                }
                _ => (head.to_string(), None),
            });
            continue;
        };
        let state = cols[1].trim();
        if state.eq_ignore_ascii_case("listen") {
            continue;
        }
        let v6 = kind.ends_with('6');
        let Some((src, dst)) = tuple.split_once("<->") else {
            continue;
        };
        let (Some((src_ip, src_port)), Some((dst_ip, dst_port))) =
            (endpoint(src, v6), endpoint(dst, v6))
        else {
            continue;
        };
        if dst_ip.is_loopback() || dst_ip.is_unspecified() {
            continue;
        }
        let (process, pid) = proc_.clone().unzip();
        out.push(Flow {
            first_seen: now,
            last_seen: now,
            pid: pid.flatten(),
            process,
            proto: if kind.starts_with("udp") {
                Proto::Udp
            } else {
                Proto::Tcp
            },
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            dst_mac: None,
            state: (!state.is_empty()).then(|| state.to_string()),
            bytes_in: cols[2].trim().parse().ok(),
            bytes_out: cols[3].trim().parse().ok(),
            origin: relay_core::FlowOrigin::Nettop,
            src_mac: None,
            outcome: relay_core::FlowOutcome::from_tcp_state(state),
        });
    }
    out
}

fn is_proto(s: &str) -> bool {
    matches!(s, "tcp4" | "tcp6" | "udp4" | "udp6")
}

/// `1.2.3.4:443` (v4) or `fe80::1%en0.443` (v6, nettop uses '.' before port).
fn endpoint(s: &str, v6: bool) -> Option<(IpAddr, u16)> {
    let (ip, port) = if v6 {
        s.rsplit_once('.')?
    } else {
        s.rsplit_once(':')?
    };
    let ip = ip.split('%').next()?;
    Some((ip.parse().ok()?, port.parse().ok()?))
}

/// Fill `dst_mac` only for on-link peers. A remote server's MAC is unknowable
/// (we'd only see the gateway's), so off-link flows keep `None`.
pub fn attach_dst_mac(
    flows: &mut [Flow],
    on_link: impl Fn(&IpAddr) -> bool,
    neighbours: &HashMap<IpAddr, Mac>,
) {
    for f in flows {
        if on_link(&f.dst_ip) {
            f.dst_mac = neighbours.get(&f.dst_ip).copied();
        }
    }
}

pub fn collect() -> anyhow::Result<Vec<Flow>> {
    let text = crate::run(
        "nettop",
        &["-L", "1", "-n", "-x", "-J", "state,bytes_in,bytes_out"],
    )?;
    Ok(parse_nettop(&text, Utc::now()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETTOP: &str = include_str!("../tests/fixtures/nettop_macos.txt");

    #[test]
    fn parses_processes_and_drops_noise() {
        let flows = parse_nettop(NETTOP, Utc::now());
        let summary: Vec<String> = flows
            .iter()
            .map(|f| {
                format!(
                    "{}:{} {}:{}",
                    f.process.as_deref().unwrap(),
                    f.pid.unwrap(),
                    f.dst_ip,
                    f.dst_port
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                "apsd:392 17.57.145.132:5223",
                "Google Chrome H:1234 142.250.66.78:443",
                "Google Chrome H:1234 142.250.66.78:443",
                "rapportd:698 fe80::46:1282:cad9:9aa5:50784",
                "curl:4321 192.168.50.184:554",
            ]
        );
        assert_eq!(flows[0].bytes_out, Some(1074591));
        assert_eq!(flows[2].proto, Proto::Udp);
        assert_eq!(flows[4].state.as_deref(), Some("SynSent"));
    }

    #[test]
    fn dst_mac_only_on_link() {
        let mut flows = parse_nettop(NETTOP, Utc::now());
        let cam: IpAddr = "192.168.50.184".parse().unwrap();
        let gw_mac: Mac = "00:09:0f:aa:00:1a".parse().unwrap();
        let cam_mac: Mac = "b0:c5:54:00:00:01".parse().unwrap();
        let mut n = HashMap::new();
        n.insert(cam, cam_mac);
        n.insert("17.57.145.132".parse().unwrap(), gw_mac); // must never be used
        let on_link =
            |ip: &IpAddr| matches!(ip, IpAddr::V4(v4) if v4.octets()[..3] == [192, 168, 50]);
        attach_dst_mac(&mut flows, on_link, &n);
        assert_eq!(flows[0].dst_mac, None);
        assert_eq!(flows[4].dst_mac, Some(cam_mac));
    }
}
