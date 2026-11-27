//! FortiGate REST monitor API (read-only token):
//! - `GET /api/v2/monitor/firewall/session` → live sessions (Active flows)
//! - `GET /api/v2/monitor/system/dhcp`      → leases (MAC ↔ IP ↔ hostname)
//!
//! Response shapes differ between FortiOS versions (`results` is either the
//! list itself or `{details: [...]}`) and field names drift (`sentbyte` vs
//! `sent_bytes`), so the parsers look for several spellings.
//!
//! HTTP goes through `curl`, with the token fed on stdin (`-H @-`) so it never
//! appears in the process list. These calls only reach the user's own gateway.

use super::Batch;
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, Utc};
use relay_core::{Flow, FlowOrigin, FlowOutcome, Mac, Observation, Proto, Source};
use serde_json::Value;
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

fn results(v: &Value) -> Vec<&Value> {
    let r = v.get("results").unwrap_or(v);
    match r {
        Value::Array(a) => a.iter().collect(),
        Value::Object(o) => o
            .get("details")
            .and_then(Value::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_default(),
        _ => vec![],
    }
}

fn s(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| match v.get(*k)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

fn n(v: &Value, keys: &[&str]) -> Option<u64> {
    s(v, keys)?.parse().ok()
}

/// Parse the session table. Every listed session is running (Active).
pub fn parse_sessions(json: &str, now: DateTime<Utc>) -> Result<Batch> {
    let v: Value = serde_json::from_str(json).context("session JSON")?;
    let mut b = Batch::default();
    for r in results(&v) {
        let proto = match s(r, &["proto", "protocol"]).map(|p| p.to_ascii_lowercase()) {
            Some(p) if p == "tcp" || p == "6" => Proto::Tcp,
            Some(p) if p == "udp" || p == "17" => Proto::Udp,
            _ => {
                b.skipped += 1;
                continue;
            }
        };
        let (Some(src_ip), Some(dst_ip)) = (
            s(r, &["saddr", "srcip", "src"]).and_then(|x| x.parse::<IpAddr>().ok()),
            s(r, &["daddr", "dstip", "dst"]).and_then(|x| x.parse::<IpAddr>().ok()),
        ) else {
            b.skipped += 1;
            continue;
        };
        let src_mac: Option<Mac> =
            s(r, &["src_mac", "srcmac", "smac"]).and_then(|m| m.parse().ok());
        let dur = n(r, &["duration"]).unwrap_or(0) as i64;
        b.flows.push(Flow {
            first_seen: now - Duration::seconds(dur),
            last_seen: now,
            pid: None,
            process: s(r, &["service", "app", "application"]),
            proto,
            src_ip,
            src_port: n(r, &["sport", "srcport"]).unwrap_or(0) as u16,
            dst_ip,
            dst_port: n(r, &["dport", "dstport"]).unwrap_or(0) as u16,
            dst_mac: None,
            state: Some("session".into()),
            bytes_in: n(r, &["rcvdbyte", "rcvd_bytes", "rcvdbytes"]),
            bytes_out: n(r, &["sentbyte", "sent_bytes", "sentbytes"]),
            origin: FlowOrigin::Fortigate,
            src_mac,
            outcome: FlowOutcome::Active,
        });
        if src_mac.is_some() {
            b.observations.push(Observation {
                ip: Some(src_ip),
                mac: src_mac,
                ..Observation::new(Source::Fortigate, now)
            });
        }
    }
    Ok(b)
}

/// Parse DHCP leases into identity observations.
pub fn parse_dhcp(json: &str, now: DateTime<Utc>) -> Result<Vec<Observation>> {
    let v: Value = serde_json::from_str(json).context("DHCP JSON")?;
    Ok(results(&v)
        .into_iter()
        .filter_map(|r| {
            let mac: Mac = s(r, &["mac"])?.parse().ok()?;
            let ip: IpAddr = s(r, &["ip"])?.parse().ok()?;
            Some(Observation {
                ip: Some(ip),
                mac: Some(mac),
                hostname: s(r, &["hostname", "host"]),
                interface: s(r, &["interface"]),
                ..Observation::new(Source::Fortigate, now)
            })
        })
        .collect())
}

/// Sessions present in the previous poll but gone now have ended: re-emit
/// them as Closed (keeping their last observed time).
pub fn closed_since(prev: &[Flow], current: &[Flow]) -> Vec<Flow> {
    let key = |f: &Flow| (f.proto, f.src_ip, f.src_port, f.dst_ip, f.dst_port);
    let live: std::collections::HashSet<_> = current.iter().map(key).collect();
    prev.iter()
        .filter(|f| !live.contains(&key(f)))
        .map(|f| Flow {
            outcome: FlowOutcome::Closed,
            state: Some("ended".into()),
            ..f.clone()
        })
        .collect()
}

pub struct Client {
    pub host: String,
    pub token: String,
    pub insecure: bool,
    pub vdom: Option<String>,
}

impl Client {
    /// GET `path` (e.g. `/api/v2/monitor/system/dhcp`), returning the body.
    pub fn get(&self, path: &str) -> Result<String> {
        let mut url = format!("{}{path}", self.host.trim_end_matches('/'));
        if let Some(v) = &self.vdom {
            url.push(if url.contains('?') { '&' } else { '?' });
            url.push_str(&format!("vdom={v}"));
        }
        let mut cmd = Command::new("curl");
        cmd.args(["-sS", "--fail", "--max-time", "20", "-H", "@-"]);
        if self.insecure {
            cmd.arg("-k");
        }
        let mut child = cmd
            .arg(&url)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawning curl")?;
        writeln!(
            child.stdin.take().context("curl stdin")?,
            "Authorization: Bearer {}",
            self.token
        )?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!(
                "GET {url} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    pub fn sessions(&self, now: DateTime<Utc>) -> Result<Batch> {
        parse_sessions(
            &self.get("/api/v2/monitor/firewall/session?count=1000")?,
            now,
        )
    }

    pub fn dhcp(&self, now: DateTime<Utc>) -> Result<Vec<Observation>> {
        parse_dhcp(&self.get("/api/v2/monitor/system/dhcp")?, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn sessions_both_shapes() {
        let now = Utc::now();
        let b = parse_sessions(&fx("fortigate_session.json"), now).unwrap();
        assert_eq!(b.flows.len(), 2);
        assert_eq!(b.skipped, 1, "icmp");
        assert_eq!(b.flows[0].src_mac.unwrap().to_string(), "5a:37:28:13:4c:74");
        assert_eq!(b.flows[0].first_seen, now - Duration::seconds(30));
        assert_eq!(b.flows[1].proto, Proto::Udp);
        // 6.x shape: results is the list itself
        let old = r#"{"results":[{"proto":"TCP","saddr":"192.168.50.9","daddr":"1.1.1.1","sport":1,"dport":443}]}"#;
        assert_eq!(parse_sessions(old, now).unwrap().flows.len(), 1);
    }

    #[test]
    fn dhcp_leases_become_observations() {
        let o = parse_dhcp(&fx("fortigate_dhcp.json"), Utc::now()).unwrap();
        assert_eq!(o.len(), 2);
        assert_eq!(o[0].hostname.as_deref(), Some("Pixel-7"));
        assert_eq!(o[0].source, Source::Fortigate);
    }

    #[test]
    fn vanished_sessions_are_closed() {
        let now = Utc::now();
        let b = parse_sessions(&fx("fortigate_session.json"), now).unwrap();
        let gone = closed_since(&b.flows, &b.flows[1..]);
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].outcome, FlowOutcome::Closed);
    }
}
