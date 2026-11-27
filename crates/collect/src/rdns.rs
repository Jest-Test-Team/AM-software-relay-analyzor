//! Reverse DNS (PTR) via the system resolver, in parallel, LAN addresses only.

use chrono::Utc;
use relay_core::{Observation, Source};
use std::net::IpAddr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub fn collect(ips: &[IpAddr], wait: Duration) -> Vec<Observation> {
    let (tx, rx) = mpsc::channel();
    for chunk in ips.chunks(16) {
        let chunk = chunk.to_vec();
        let tx = tx.clone();
        // Detached: a hung resolver call cannot block the caller past `wait`.
        std::thread::spawn(move || {
            for ip in chunk {
                if let Ok(name) = dns_lookup::lookup_addr(&ip) {
                    if name != ip.to_string() {
                        let _ = tx.send((ip, name));
                    }
                }
            }
        });
    }
    drop(tx);
    let deadline = Instant::now() + wait;
    let now = Utc::now();
    let mut out = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok((ip, name)) => out.push(Observation {
                ip: Some(ip),
                hostname: Some(crate::mdns::clean_host(&name)),
                ..Observation::new(Source::ReverseDns, now)
            }),
            Err(_) => break,
        }
    }
    out
}
