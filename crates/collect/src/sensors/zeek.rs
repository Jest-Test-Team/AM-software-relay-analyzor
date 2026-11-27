//! Zeek `conn.log`, either the default TSV (with `#fields` header) or JSON
//! lines (`LogAscii::use_json=T`). Load `policy/protocols/conn/mac-logging`
//! in Zeek to get `orig_l2_addr`, which attributes flows by MAC.

use super::Batch;
use chrono::{DateTime, Duration, Utc};
use relay_core::{Flow, FlowOrigin, FlowOutcome, Mac, Observation, Proto, Source};
use std::collections::HashMap;
use std::net::IpAddr;

/// Zeek `conn_state` → outcome.
pub fn outcome(state: &str) -> FlowOutcome {
    match state {
        "SF" | "S2" | "S3" | "RSTO" | "RSTR" => FlowOutcome::Closed,
        "S0" | "REJ" | "RSTOS0" | "RSTRH" | "SH" | "SHR" => FlowOutcome::Failed,
        // S1 (established, still open), OTH (mid-stream), unknown.
        _ => FlowOutcome::Active,
    }
}

fn record(get: &dyn Fn(&str) -> Option<String>) -> Option<Batch> {
    let val = |k: &str| get(k).filter(|v| v != "-" && v != "(empty)" && !v.is_empty());
    let ts: f64 = val("ts")?.parse().ok()?;
    let start = DateTime::from_timestamp(ts.trunc() as i64, (ts.fract() * 1e9) as u32)?;
    let dur: f64 = val("duration").and_then(|d| d.parse().ok()).unwrap_or(0.0);
    let proto = match val("proto")?.as_str() {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        _ => return None,
    };
    let src_ip: IpAddr = val("id.orig_h")?.parse().ok()?;
    let dst_ip: IpAddr = val("id.resp_h")?.parse().ok()?;
    let num = |k: &str| val(k).and_then(|v| v.parse::<u64>().ok());
    let state = val("conn_state");
    let src_mac: Option<Mac> = val("orig_l2_addr").and_then(|m| m.parse().ok());
    let dst_mac: Option<Mac> = val("resp_l2_addr").and_then(|m| m.parse().ok());
    let last = start + Duration::milliseconds((dur * 1000.0) as i64);
    let mut b = Batch::default();
    b.flows.push(Flow {
        first_seen: start,
        last_seen: last,
        pid: None,
        process: val("service"),
        proto,
        src_ip,
        src_port: num("id.orig_p").unwrap_or(0) as u16,
        dst_ip,
        dst_port: num("id.resp_p").unwrap_or(0) as u16,
        // resp_l2_addr is the next hop (gateway) for off-link peers; the
        // assessor only trusts dst_mac for on-link destinations.
        dst_mac,
        outcome: state.as_deref().map(outcome).unwrap_or_default(),
        state,
        bytes_in: num("resp_bytes"),
        bytes_out: num("orig_bytes"),
        origin: FlowOrigin::Zeek,
        src_mac,
    });
    if src_mac.is_some() {
        b.observations.push(Observation {
            ip: Some(src_ip),
            mac: src_mac,
            ..Observation::new(Source::Zeek, last)
        });
    }
    Some(b)
}

/// Parse a conn.log (TSV or JSON lines). Pass the same `fields` across calls
/// when tailing so the TSV header is remembered.
pub fn parse(text: &str, fields: &mut Vec<String>) -> Batch {
    let mut out = Batch::default();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("#fields") {
            *fields = rest.split('\t').filter(|s| !s.is_empty()).map(String::from).collect();
            continue;
        }
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let parsed = if line.starts_with('{') {
            match serde_json::from_str::<HashMap<String, serde_json::Value>>(line) {
                Ok(m) => record(&|k| {
                    m.get(k).map(|v| match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                }),
                Err(_) => None,
            }
        } else {
            let cols: Vec<&str> = line.split('\t').collect();
            record(&|k| {
                let i = fields.iter().position(|f| f == k)?;
                cols.get(i).map(|s| s.to_string())
            })
        };
        match parsed {
            Some(b) => out.extend(b),
            None => out.skipped += 1,
        }
    }
    out
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
    fn parses_tsv_conn_log() {
        let b = parse(&fx("zeek_conn.tsv"), &mut vec![]);
        assert_eq!(b.flows.len(), 3);
        assert_eq!(b.skipped, 1, "icmp skipped");
        let f = &b.flows[0];
        assert_eq!(f.src_ip.to_string(), "192.168.50.13");
        assert_eq!(f.src_mac.unwrap().to_string(), "5a:37:28:13:4c:74");
        assert_eq!(f.outcome, FlowOutcome::Closed);
        assert_eq!(f.process.as_deref(), Some("ssl"));
        assert_eq!((f.bytes_out, f.bytes_in), (Some(1200), Some(4800)));
        assert_eq!(f.last_seen - f.first_seen, Duration::milliseconds(2500));
        assert_eq!(b.flows[1].outcome, FlowOutcome::Failed, "S0");
        assert_eq!(b.flows[2].src_mac, None, "missing l2 addr");
        assert_eq!(b.observations.len(), 2);
    }

    #[test]
    fn parses_json_conn_log() {
        let b = parse(&fx("zeek_conn.json"), &mut vec![]);
        assert_eq!(b.flows.len(), 2);
        assert_eq!(b.flows[0].dst_port, 443);
        assert_eq!(b.flows[0].outcome, FlowOutcome::Closed);
        assert_eq!(b.flows[1].outcome, FlowOutcome::Failed, "REJ");
        assert_eq!(b.flows[0].origin, FlowOrigin::Zeek);
    }
}
