//! mDNS / DNS-SD browse: enumerate advertised service types, then resolve
//! instances to (ip, hostname, service) observations.

use chrono::Utc;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use relay_core::{Observation, Source};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

const META: &str = "_services._dns-sd._udp.local.";

/// Common types queried even if no one answers the meta query.
const SEED: &[&str] = &[
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_companion-link._tcp.local.",
    "_device-info._tcp.local.",
    "_hap._tcp.local.",
    "_ipp._tcp.local.",
    "_printer._tcp.local.",
    "_smb._tcp.local.",
    "_ssh._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_http._tcp.local.",
];

/// `host.local.` → `host`
pub fn clean_host(h: &str) -> String {
    h.trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string()
}

/// `_airplay._tcp.local.` → `_airplay._tcp`
pub fn short_type(t: &str) -> String {
    t.trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string()
}

pub fn collect(wait: Duration) -> anyhow::Result<Vec<Observation>> {
    let mdns = ServiceDaemon::new()?;
    let mut types: BTreeSet<String> = SEED.iter().map(|s| s.to_string()).collect();
    let meta = mdns.browse(META)?;
    let meta_deadline = Instant::now() + wait / 3;
    while let Some(left) = meta_deadline.checked_duration_since(Instant::now()) {
        match meta.recv_timeout(left) {
            Ok(ServiceEvent::ServiceFound(_, full)) => {
                // fullname of a meta answer is the service type itself
                let t = if full.ends_with('.') {
                    full
                } else {
                    format!("{full}.")
                };
                types.insert(t);
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = mdns.stop_browse(META);

    let receivers: Vec<_> = types
        .iter()
        .filter_map(|t| mdns.browse(t).ok().map(|r| (t.clone(), r)))
        .collect();
    let deadline = Instant::now() + wait * 2 / 3;
    let mut found: HashMap<IpAddr, (Option<String>, BTreeSet<String>)> = HashMap::new();
    while Instant::now() < deadline {
        let mut idle = true;
        for (t, rx) in &receivers {
            while let Ok(ev) = rx.try_recv() {
                if let ServiceEvent::ServiceResolved(info) = ev {
                    idle = false;
                    for ip in info.get_addresses() {
                        let e = found.entry(ip.to_ip_addr()).or_default();
                        e.0.get_or_insert_with(|| clean_host(info.get_hostname()));
                        e.1.insert(short_type(t));
                    }
                }
            }
        }
        if idle {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    for (t, _) in &receivers {
        let _ = mdns.stop_browse(t);
    }
    let _ = mdns.shutdown();
    let now = Utc::now();
    Ok(found
        .into_iter()
        .map(|(ip, (host, svcs))| Observation {
            ip: Some(ip),
            hostname: host.filter(|h| !h.is_empty()),
            services: svcs.into_iter().collect(),
            ..Observation::new(Source::Mdns, now)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(clean_host("Mo-IPAD-8.local."), "Mo-IPAD-8");
        assert_eq!(short_type("_airplay._tcp.local."), "_airplay._tcp");
    }
}
