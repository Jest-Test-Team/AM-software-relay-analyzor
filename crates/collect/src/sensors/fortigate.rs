//! FortiGate (FortiOS) traffic logs. The same `key=value` format arrives via
//! syslog push, the GUI "Download raw logs" export, or FortiAnalyzer export.
//!
//! ```text
//! date=2026-11-27 time=14:05:01 tz="+0800" type="traffic" subtype="forward"
//! srcip=192.168.50.13 srcport=51515 srcmac="5a:37:28:13:4c:74" srcname="iPhone"
//! dstip=198.51.100.7 dstport=443 proto=6 action="close" service="HTTPS"
//! duration=12 sentbyte=1234 rcvdbyte=5678
//! ```

use super::{kv_pairs, Batch};
use chrono::{DateTime, Duration, FixedOffset, Local, NaiveDateTime, TimeZone, Utc};
use relay_core::{Flow, FlowOrigin, FlowOutcome, Mac, Observation, Proto, Source};
use std::collections::HashMap;
use std::net::IpAddr;

/// FortiOS `action` → normalised outcome.
pub fn outcome(action: &str) -> FlowOutcome {
    match action {
        "close" => FlowOutcome::Closed,
        "deny" | "ip-conn" | "blocked" | "dropped" => FlowOutcome::Denied,
        "timeout" | "server-rst" | "client-rst" => FlowOutcome::Failed,
        // "accept", "start" (session-start logging) and anything new: running.
        _ => FlowOutcome::Active,
    }
}

/// Parse one log line. `None` for non-traffic logs or lines missing the
/// 5-tuple; `Some(Batch)` holds at most one flow and one observation.
pub fn parse_line(line: &str, now: DateTime<Utc>) -> Option<Batch> {
    let kv: HashMap<&str, &str> = kv_pairs(line)
        .into_iter()
        .map(|(k, v)| (k.rsplit('>').next().unwrap_or(k), v))
        .collect();
    if kv.get("type").is_some_and(|t| *t != "traffic") {
        return None;
    }
    let src_ip: IpAddr = kv.get("srcip")?.parse().ok()?;
    let dst_ip: IpAddr = kv.get("dstip")?.parse().ok()?;
    let proto = match *kv.get("proto")? {
        "6" => Proto::Tcp,
        "17" => Proto::Udp,
        _ => return None, // ICMP etc.: no ports, not modelled
    };
    let ts = timestamp(&kv).unwrap_or(now);
    let num = |k: &str| kv.get(k).and_then(|v| v.parse::<u64>().ok());
    let action = kv.get("action").copied().unwrap_or("accept");
    let src_mac: Option<Mac> = kv
        .get("srcmac")
        .and_then(|m| m.parse().ok())
        .filter(|m: &Mac| !m.is_broadcast() && !m.is_multicast());
    let label = kv
        .get("app")
        .or(kv.get("service"))
        .map(|s| s.to_string());
    let flow = Flow {
        first_seen: ts - Duration::seconds(num("duration").unwrap_or(0) as i64),
        last_seen: ts,
        pid: None,
        process: label,
        proto,
        src_ip,
        src_port: num("srcport").unwrap_or(0) as u16,
        dst_ip,
        dst_port: num("dstport").unwrap_or(0) as u16,
        dst_mac: None,
        state: Some(action.to_string()),
        bytes_in: num("rcvdbyte"),
        bytes_out: num("sentbyte"),
        origin: FlowOrigin::Fortigate,
        src_mac,
        outcome: outcome(action),
    };
    let mut b = Batch {
        flows: vec![flow],
        ..Default::default()
    };
    if src_mac.is_some() {
        b.observations.push(Observation {
            ip: Some(src_ip),
            mac: src_mac,
            hostname: kv
                .get("srcname")
                .filter(|n| !n.is_empty())
                .map(|n| n.to_string()),
            services: kv
                .get("osname")
                .map(|o| vec![format!("os:{o}")])
                .unwrap_or_default(),
            ..Observation::new(Source::Fortigate, ts)
        });
    }
    Some(b)
}

/// `date`+`time` (+ `tz`), else `eventtime` (s / ms / µs / ns since epoch).
fn timestamp(kv: &HashMap<&str, &str>) -> Option<DateTime<Utc>> {
    if let (Some(d), Some(t)) = (kv.get("date"), kv.get("time")) {
        let naive = NaiveDateTime::parse_from_str(&format!("{d} {t}"), "%Y-%m-%d %H:%M:%S").ok()?;
        let tz = kv.get("tz").and_then(|z| parse_tz(z));
        return match tz {
            Some(off) => off.from_local_datetime(&naive).single().map(|t| t.to_utc()),
            None => Local.from_local_datetime(&naive).earliest().map(|t| t.to_utc()),
        };
    }
    let e: i64 = kv.get("eventtime")?.parse().ok()?;
    let (secs, nanos) = match e {
        e if e > 1_000_000_000_000_000 => (e / 1_000_000_000, e % 1_000_000_000),
        e if e > 1_000_000_000_000 => (e / 1_000_000, (e % 1_000_000) * 1000),
        e if e > 10_000_000_000 => (e / 1000, (e % 1000) * 1_000_000),
        e => (e, 0),
    };
    DateTime::from_timestamp(secs, nanos as u32)
}

/// `+0800` / `-05:00` / `UTC`.
fn parse_tz(z: &str) -> Option<FixedOffset> {
    let z = z.replace(':', "");
    if z.eq_ignore_ascii_case("utc") || z == "Z" {
        return FixedOffset::east_opt(0);
    }
    let (sign, rest) = match z.as_bytes().first()? {
        b'+' => (1, &z[1..]),
        b'-' => (-1, &z[1..]),
        _ => return None,
    };
    let h: i32 = rest.get(0..2)?.parse().ok()?;
    let m: i32 = rest.get(2..4).unwrap_or("0").parse().ok()?;
    FixedOffset::east_opt(sign * (h * 3600 + m * 60))
}

/// Parse a whole exported log (one record per line).
pub fn parse_log(text: &str, now: DateTime<Utc>) -> Batch {
    let mut out = Batch::default();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        match parse_line(line, now) {
            Some(b) => out.extend(b),
            None => out.skipped += 1,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/fortigate.log"
        ))
        .unwrap()
    }

    #[test]
    fn parses_traffic_lines() {
        let b = parse_log(&fixture(), Utc::now());
        assert_eq!(b.flows.len(), 5);
        assert_eq!(b.skipped, 2, "event log + icmp skipped");
        let f = &b.flows[0];
        assert_eq!(f.src_ip.to_string(), "192.168.50.13");
        assert_eq!(f.src_mac.unwrap().to_string(), "5a:37:28:13:4c:74");
        assert_eq!(f.dst_port, 443);
        assert_eq!(f.outcome, FlowOutcome::Closed);
        assert_eq!(f.origin, FlowOrigin::Fortigate);
        assert_eq!((f.bytes_out, f.bytes_in), (Some(1234), Some(5678)));
        assert_eq!(f.last_seen.to_rfc3339(), "2026-11-27T06:05:01+00:00");
        assert_eq!(f.last_seen - f.first_seen, Duration::seconds(12));
        assert_eq!(f.process.as_deref(), Some("HTTPS"));
        let outcomes: Vec<_> = b.flows.iter().map(|f| f.outcome).collect();
        assert_eq!(
            outcomes,
            [
                FlowOutcome::Closed,
                FlowOutcome::Active,
                FlowOutcome::Denied,
                FlowOutcome::Failed,
                FlowOutcome::Closed
            ]
        );
        assert_eq!(b.observations[0].hostname.as_deref(), Some("Pixel-7"));
    }

    #[test]
    fn syslog_prefix_and_eventtime_ns() {
        let line = "<189>1 2026-11-27T06:05:01Z fgt - - - eventtime=1795759501000000000 type=\"traffic\" srcip=10.0.0.5 srcport=1 dstip=8.8.8.8 dstport=53 proto=17 action=\"accept\"";
        let b = parse_line(line, Utc::now()).unwrap();
        assert_eq!(b.flows[0].last_seen.timestamp(), 1_795_759_501);
        assert_eq!(b.flows[0].proto, Proto::Udp);
        assert!(b.observations.is_empty(), "no srcmac, no identity");
    }
}
