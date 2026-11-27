//! Threat-intelligence sources behind one trait, with a privacy guard and a
//! SQLite-backed TTL cache.
//!
//! Privacy rule: only *public* IP addresses ever leave this host. RFC 1918,
//! CGNAT, link-local, ULA, loopback and MAC addresses are never sent.

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use relay_core::{Store, Verdict};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub trait IntelSource {
    fn name(&self) -> &str;
    /// True if `lookup` sends the indicator over the network.
    fn remote(&self) -> bool;
    fn lookup(&self, ip: IpAddr) -> Result<Option<Verdict>>;
}

pub fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s0 & 0xfe00) == 0xfc00 // ULA
                || (s0 & 0xffc0) == 0xfe80 // link-local
                || s0 == 0x2001 && v6.segments()[1] == 0x0db8) // documentation
        }
    }
}

// ---------------------------------------------------------------- blocklist

/// Offline IP/CIDR blocklist (Feodo Tracker, Spamhaus DROP, …). Lookups never
/// leave the host, so they also run for non-public addresses.
pub struct Blocklist {
    name: String,
    category: String,
    confidence: f32,
    v4: Vec<(u32, u8)>,
    v6: Vec<(u128, u8)>,
}

impl Blocklist {
    /// Lines: `ip`, `cidr`, optionally followed by `; comment`. `#`/`;` comments skipped.
    pub fn parse(name: &str, category: &str, confidence: f32, text: &str) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for line in text.lines() {
            let tok = line
                .split([';', '#', ' ', '\t', ','])
                .next()
                .unwrap_or("")
                .trim();
            if tok.is_empty() {
                continue;
            }
            let (ip, prefix) = match tok.split_once('/') {
                Some((ip, p)) => (ip, p.parse::<u8>().ok()),
                None => (tok, None),
            };
            match ip.parse::<IpAddr>() {
                Ok(IpAddr::V4(a)) => {
                    let p = prefix.unwrap_or(32).min(32);
                    v4.push((u32::from(a) & mask4(p), p));
                }
                Ok(IpAddr::V6(a)) => {
                    let p = prefix.unwrap_or(128).min(128);
                    v6.push((u128::from(a) & mask6(p), p));
                }
                Err(_) => {}
            }
        }
        Self {
            name: name.into(),
            category: category.into(),
            confidence,
            v4,
            v6,
        }
    }

    pub fn load(name: &str, category: &str, confidence: f32, path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Ok(Self::parse(name, category, confidence, &text))
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn matched(&self, ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(a) => {
                let x = u32::from(a);
                self.v4
                    .iter()
                    .find(|(net, p)| x & mask4(*p) == *net)
                    .map(|(n, p)| format!("{}/{}", Ipv4Addr::from(*n), p))
            }
            IpAddr::V6(a) => {
                let x = u128::from(a);
                self.v6
                    .iter()
                    .find(|(net, p)| x & mask6(*p) == *net)
                    .map(|(n, p)| format!("{}/{}", Ipv6Addr::from(*n), p))
            }
        }
    }
}

fn mask4(p: u8) -> u32 {
    if p == 0 {
        0
    } else {
        u32::MAX << (32 - p as u32)
    }
}

fn mask6(p: u8) -> u128 {
    if p == 0 {
        0
    } else {
        u128::MAX << (128 - p as u32)
    }
}

impl IntelSource for Blocklist {
    fn name(&self) -> &str {
        &self.name
    }
    fn remote(&self) -> bool {
        false
    }
    fn lookup(&self, ip: IpAddr) -> Result<Option<Verdict>> {
        Ok(self.matched(ip).map(|net| Verdict {
            indicator: ip,
            source: self.name.clone(),
            malicious: true,
            reporters: None,
            confidence: self.confidence,
            category: self.category.clone(),
            detail: format!("listed in {} ({net})", self.name),
            fetched_at: Utc::now(),
        }))
    }
}

// ---------------------------------------------------------------- AbuseIPDB

pub struct AbuseIpDb {
    key: String,
}

impl AbuseIpDb {
    pub fn from_env() -> Option<Self> {
        std::env::var("ABUSEIPDB_API_KEY")
            .ok()
            .filter(|k| !k.is_empty())
            .map(|key| Self { key })
    }

    pub fn parse(ip: IpAddr, body: &serde_json::Value) -> Option<Verdict> {
        let d = body.get("data")?;
        let score = d.get("abuseConfidenceScore")?.as_u64()?;
        let users = d
            .get("numDistinctUsers")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let total = d.get("totalReports").and_then(|v| v.as_u64()).unwrap_or(0);
        if score == 0 && total == 0 {
            return None;
        }
        Some(Verdict {
            indicator: ip,
            source: "abuseipdb".into(),
            // Reports ≠ IOC: AbuseIPDB alone never counts as a confirmed IOC.
            malicious: false,
            reporters: Some(users),
            confidence: score as f32 / 100.0,
            category: "abuse-reports".into(),
            detail: format!("abuse score {score}%, {total} reports from {users} users"),
            fetched_at: Utc::now(),
        })
    }
}

impl IntelSource for AbuseIpDb {
    fn name(&self) -> &str {
        "abuseipdb"
    }
    fn remote(&self) -> bool {
        true
    }
    fn lookup(&self, ip: IpAddr) -> Result<Option<Verdict>> {
        let body: serde_json::Value = ureq::get("https://api.abuseipdb.com/api/v2/check")
            .set("Key", &self.key)
            .set("Accept", "application/json")
            .query("ipAddress", &ip.to_string())
            .query("maxAgeInDays", "90")
            .timeout(std::time::Duration::from_secs(10))
            .call()?
            .into_json()?;
        Ok(Self::parse(ip, &body))
    }
}

// ---------------------------------------------------------------- ThreatFox

pub struct ThreatFox {
    key: String,
}

impl ThreatFox {
    pub fn from_env() -> Option<Self> {
        std::env::var("THREATFOX_AUTH_KEY")
            .ok()
            .filter(|k| !k.is_empty())
            .map(|key| Self { key })
    }

    pub fn parse(ip: IpAddr, body: &serde_json::Value) -> Option<Verdict> {
        if body.get("query_status")?.as_str()? != "ok" {
            return None;
        }
        let first = body.get("data")?.as_array()?.first()?;
        let conf = first
            .get("confidence_level")
            .and_then(|v| v.as_u64())
            .unwrap_or(50);
        let threat = first
            .get("threat_type")
            .and_then(|v| v.as_str())
            .unwrap_or("ioc");
        let malware = first
            .get("malware_printable")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        Some(Verdict {
            indicator: ip,
            source: "threatfox".into(),
            malicious: conf >= 75,
            reporters: None,
            confidence: conf as f32 / 100.0,
            category: threat.into(),
            detail: format!("ThreatFox: {malware} ({threat}, confidence {conf}%)"),
            fetched_at: Utc::now(),
        })
    }
}

impl IntelSource for ThreatFox {
    fn name(&self) -> &str {
        "threatfox"
    }
    fn remote(&self) -> bool {
        true
    }
    fn lookup(&self, ip: IpAddr) -> Result<Option<Verdict>> {
        let body: serde_json::Value = ureq::post("https://threatfox-api.abuse.ch/api/v1/")
            .set("Auth-Key", &self.key)
            .timeout(std::time::Duration::from_secs(10))
            .send_json(serde_json::json!({"query": "search_ioc", "search_term": ip.to_string()}))?
            .into_json()?;
        Ok(Self::parse(ip, &body))
    }
}

// ---------------------------------------------------------------- engine

pub struct Intel {
    pub sources: Vec<Box<dyn IntelSource>>,
    pub ttl: Duration,
}

impl Intel {
    /// Load blocklists from `feeds_dir` (if present) and keyed APIs from env.
    pub fn from_env(feeds_dir: &Path) -> (Self, Vec<String>) {
        let mut sources: Vec<Box<dyn IntelSource>> = Vec::new();
        let mut notes = Vec::new();
        for (file, name, cat, conf) in [
            ("feodo.txt", "feodo", "botnet_cc", 0.95),
            ("spamhaus-drop.txt", "spamhaus-drop", "drop", 0.9),
        ] {
            match Blocklist::load(name, cat, conf, &feeds_dir.join(file)) {
                Ok(b) => {
                    notes.push(format!("{name}: {} entries", b.len()));
                    sources.push(Box::new(b));
                }
                Err(_) => notes.push(format!("{name}: missing (run scripts/fetch-feeds.sh)")),
            }
        }
        match ThreatFox::from_env() {
            Some(t) => sources.push(Box::new(t)),
            None => notes.push("threatfox: THREATFOX_AUTH_KEY not set, skipped".into()),
        }
        match AbuseIpDb::from_env() {
            Some(a) => sources.push(Box::new(a)),
            None => notes.push("abuseipdb: ABUSEIPDB_API_KEY not set, skipped".into()),
        }
        (
            Self {
                sources,
                ttl: Duration::hours(24),
            },
            notes,
        )
    }

    /// Positive verdicts for `ip`. Remote sources are skipped for non-public
    /// addresses or when `offline`. Answers (incl. negatives) are cached.
    pub fn check(&self, store: &Store, ip: IpAddr, offline: bool) -> Result<Vec<Verdict>> {
        let mut out = Vec::new();
        for s in &self.sources {
            if s.remote() && (offline || !is_public(&ip)) {
                continue;
            }
            // Local lists are cheap and change on refresh; only cache remote answers.
            if s.remote() {
                if let Some(cached) = store.intel_cached(ip, s.name(), self.ttl)? {
                    out.extend(cached);
                    continue;
                }
            }
            match s.lookup(ip) {
                Ok(v) => {
                    if s.remote() {
                        store.intel_put(ip, s.name(), v.as_ref())?;
                    } else if let Some(v) = &v {
                        store.intel_put(ip, s.name(), Some(v))?;
                    }
                    out.extend(v);
                }
                Err(e) => eprintln!("warning: {} lookup failed for {ip}: {e:#}", s.name()),
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_guard() {
        for ip in [
            "192.168.50.2",
            "172.16.200.41",
            "10.1.2.3",
            "100.64.0.1",
            "fe80::1",
            "fd00::1",
            "127.0.0.1",
            "224.0.0.251",
        ] {
            assert!(!is_public(&ip.parse().unwrap()), "{ip}");
        }
        for ip in ["17.57.145.132", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public(&ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn blocklist_feodo_and_drop_formats() {
        let feodo = Blocklist::parse(
            "feodo",
            "botnet_cc",
            0.95,
            "# header\n#\n# DstIP\n162.243.103.246\n178.62.3.223\n",
        );
        let drop = Blocklist::parse(
            "spamhaus-drop",
            "drop",
            0.9,
            "; Spamhaus DROP\n1.10.16.0/20 ; SBL256894\n2.26.75.0/24 ; SBL698389\n",
        );
        assert_eq!((feodo.len(), drop.len()), (2, 2));
        let v = feodo
            .lookup("162.243.103.246".parse().unwrap())
            .unwrap()
            .unwrap();
        assert!(v.malicious && v.category == "botnet_cc");
        assert!(drop.lookup("1.10.20.5".parse().unwrap()).unwrap().is_some());
        assert!(drop.lookup("1.10.32.1".parse().unwrap()).unwrap().is_none());
    }

    #[test]
    fn api_parsers() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let a = serde_json::json!({"data": {"abuseConfidenceScore": 88, "totalReports": 40, "numDistinctUsers": 12}});
        let v = AbuseIpDb::parse(ip, &a).unwrap();
        assert!(!v.malicious);
        assert_eq!(v.reporters, Some(12));
        assert!(AbuseIpDb::parse(
            ip,
            &serde_json::json!({"data": {"abuseConfidenceScore": 0, "totalReports": 0}})
        )
        .is_none());
        let t = serde_json::json!({"query_status": "ok", "data": [{"threat_type": "botnet_cc", "malware_printable": "Cobalt Strike", "confidence_level": 100}]});
        let v = ThreatFox::parse(ip, &t).unwrap();
        assert!(v.malicious && v.category == "botnet_cc");
        assert!(ThreatFox::parse(ip, &serde_json::json!({"query_status": "no_result"})).is_none());
    }

    struct Spy(std::cell::Cell<usize>);
    impl IntelSource for Spy {
        fn name(&self) -> &str {
            "spy"
        }
        fn remote(&self) -> bool {
            true
        }
        fn lookup(&self, _: IpAddr) -> Result<Option<Verdict>> {
            self.0.set(self.0.get() + 1);
            Ok(None)
        }
    }

    #[test]
    fn remote_never_sees_private_ips_and_is_cached() {
        let store = Store::in_memory().unwrap();
        let spy = std::rc::Rc::new(Spy(Default::default()));
        struct Wrap(std::rc::Rc<Spy>);
        impl IntelSource for Wrap {
            fn name(&self) -> &str {
                self.0.name()
            }
            fn remote(&self) -> bool {
                true
            }
            fn lookup(&self, ip: IpAddr) -> Result<Option<Verdict>> {
                self.0.lookup(ip)
            }
        }
        let intel = Intel {
            sources: vec![Box::new(Wrap(spy.clone()))],
            ttl: Duration::hours(1),
        };
        intel
            .check(&store, "192.168.50.184".parse().unwrap(), false)
            .unwrap();
        assert_eq!(spy.0.get(), 0);
        intel
            .check(&store, "8.8.8.8".parse().unwrap(), true)
            .unwrap();
        assert_eq!(spy.0.get(), 0, "offline");
        intel
            .check(&store, "8.8.8.8".parse().unwrap(), false)
            .unwrap();
        intel
            .check(&store, "8.8.8.8".parse().unwrap(), false)
            .unwrap();
        assert_eq!(spy.0.get(), 1, "second call served from cache");
    }
}
