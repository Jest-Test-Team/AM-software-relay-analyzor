//! Rule-based risk engine (no ML). Weights follow ref.txt §6 and are NOT
//! calibrated against ground truth — they live in a TOML config so they can be
//! tuned without code changes.
//!
//! Score, level and confidence are separate outputs: a device with no
//! behavioural data and no positive signals is `Gray`, never `Green`.

use crate::model::*;
use crate::Mac;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RiskConfig {
    pub w_ioc: i32,
    pub w_ip_churn: i32,
    pub w_gateway_takeover: i32,
    pub w_multi_source_reports: i32,
    pub w_beaconing: i32,
    pub w_baseline_deviation: i32,
    pub w_large_egress: i32,
    pub w_trusted_baseline: i32,

    /// Minimum TI confidence for an IOC hit to count.
    pub ioc_min_confidence: f32,
    /// Distinct IPv4 addresses within 24h that count as abnormal churn.
    pub ip_churn_threshold: usize,
    /// AbuseIPDB-style reputation: min distinct reporters and confidence.
    pub reports_min_reporters: u32,
    pub reports_min_confidence: f32,
    /// Beaconing: min connections, max coefficient of variation, interval range (s).
    pub beacon_min_conns: usize,
    pub beacon_max_cv: f64,
    pub beacon_min_interval_s: f64,
    pub beacon_max_interval_s: f64,
    /// Baseline deviation: min baseline flows, min new destinations, min new ratio.
    pub baseline_min_flows: usize,
    pub baseline_min_new: usize,
    pub baseline_min_new_ratio: f64,
    /// The baseline must cover at least this many hours before deviation counts.
    pub baseline_min_span_hours: i64,
    /// Bytes sent off-link within the evaluation window.
    pub egress_bytes_threshold: u64,
    /// Below this confidence (and with no positive signals) the level is Gray.
    pub gray_below_confidence: f32,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            w_ioc: 100,
            w_ip_churn: 35,
            w_gateway_takeover: 45,
            w_multi_source_reports: 40,
            w_beaconing: 35,
            w_baseline_deviation: 20,
            w_large_egress: 25,
            w_trusted_baseline: -15,
            ioc_min_confidence: 0.75,
            ip_churn_threshold: 3,
            reports_min_reporters: 2,
            reports_min_confidence: 0.5,
            beacon_min_conns: 6,
            beacon_max_cv: 0.15,
            beacon_min_interval_s: 10.0,
            beacon_max_interval_s: 3600.0,
            baseline_min_flows: 20,
            baseline_min_new: 5,
            baseline_min_new_ratio: 0.5,
            baseline_min_span_hours: 24,
            egress_bytes_threshold: 500 * 1024 * 1024,
            gray_below_confidence: 0.5,
        }
    }
}

impl RiskConfig {
    pub fn from_toml(s: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(s)?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Signal {
    IocHit,
    IpChurn,
    GatewayTakeover,
    MultiSourceReports,
    Beaconing,
    BaselineDeviation,
    LargeEgress,
    TrustedBaseline,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reason {
    pub signal: Signal,
    pub delta: i32,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assessment {
    pub mac: Mac,
    pub at: DateTime<Utc>,
    pub score: u8,
    pub level: RiskLevel,
    pub confidence: f32,
    pub reasons: Vec<Reason>,
    /// One plain-language sentence explaining the level.
    #[serde(default)]
    pub summary: String,
    /// What confidence is built from — present and missing factors.
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// Suggested follow-up actions, most important first.
    #[serde(default)]
    pub actions: Vec<String>,
}

/// One factor of the confidence score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub factor: String,
    pub weight: f32,
    pub present: bool,
    pub note: String,
}

/// Everything the engine needs about one device. Built by the caller.
pub struct Inputs<'a> {
    pub device: &'a Device,
    pub ip_history: &'a [IpBinding],
    /// If this device is bound to the gateway IP: the MAC that held it first.
    pub gateway_original_mac: Option<Mac>,
    /// Flows originated by this device in the evaluation window (self only).
    pub window_flows: &'a [Flow],
    /// Older flows from this device, forming its behavioural baseline.
    pub baseline_flows: &'a [Flow],
    /// TI verdicts keyed by destination IP.
    pub verdicts: &'a HashMap<IpAddr, Vec<Verdict>>,
    /// Whether flow destinations were checked against any TI source.
    pub ti_checked: bool,
    /// True if this device's connections can be observed at all (today: only
    /// the host running relayscan). False ⇒ Gray means "not observable",
    /// not "idle".
    pub traffic_visible: bool,
    pub is_on_link: &'a dyn Fn(&IpAddr) -> bool,
}

pub fn assess(cfg: &RiskConfig, inp: &Inputs, now: DateTime<Utc>) -> Assessment {
    let d = inp.device;
    let mut reasons: Vec<Reason> = Vec::new();
    fn add(reasons: &mut Vec<Reason>, signal: Signal, delta: i32, detail: String) {
        if delta != 0 {
            reasons.push(Reason {
                signal,
                delta,
                detail,
            })
        }
    }

    // --- threat intel on destinations -------------------------------------
    let mut ioc: BTreeSet<String> = BTreeSet::new();
    let mut reported: BTreeSet<String> = BTreeSet::new();
    let dsts: BTreeSet<IpAddr> = inp.window_flows.iter().map(|f| f.dst_ip).collect();
    for ip in &dsts {
        let Some(vs) = inp.verdicts.get(ip) else {
            continue;
        };
        for v in vs {
            if v.malicious && v.confidence >= cfg.ioc_min_confidence {
                ioc.insert(format!("{ip} ({}: {})", v.source, v.category));
            }
        }
        let sources: BTreeSet<&str> = vs.iter().map(|v| v.source.as_str()).collect();
        let crowd = vs.iter().any(|v| {
            v.reporters.unwrap_or(0) >= cfg.reports_min_reporters
                && v.confidence >= cfg.reports_min_confidence
        });
        if crowd || sources.len() >= 2 {
            reported.insert(ip.to_string());
        }
    }
    if !ioc.is_empty() {
        add(
            &mut reasons,
            Signal::IocHit,
            cfg.w_ioc,
            format!("destination matches malicious IOC: {}", join(&ioc)),
        );
    }
    if !reported.is_empty() {
        add(
            &mut reasons,
            Signal::MultiSourceReports,
            cfg.w_multi_source_reports,
            format!(
                "destination has multi-source abuse reports: {}",
                join(&reported)
            ),
        );
    }

    // --- L2 identity --------------------------------------------------------
    let day_ago = now - Duration::hours(24);
    let recent_v4: BTreeSet<IpAddr> = inp
        .ip_history
        .iter()
        .filter(|b| b.ip.is_ipv4() && b.last_seen >= day_ago)
        .map(|b| b.ip)
        .collect();
    if recent_v4.len() >= cfg.ip_churn_threshold {
        add(
            &mut reasons,
            Signal::IpChurn,
            cfg.w_ip_churn,
            format!(
                "MAC bound to {} IPv4 addresses in 24h: {}",
                recent_v4.len(),
                join(&recent_v4)
            ),
        );
    }
    if let Some(orig) = inp.gateway_original_mac.filter(|m| *m != d.mac) {
        add(
            &mut reasons,
            Signal::GatewayTakeover,
            cfg.w_gateway_takeover,
            format!("claims the gateway IP previously held by {orig} (possible ARP spoofing)"),
        );
    }

    // --- behaviour ----------------------------------------------------------
    let beacons = beaconing(cfg, inp.window_flows.iter().chain(inp.baseline_flows));
    if let Some(b) = beacons.first() {
        add(
            &mut reasons,
            Signal::Beaconing,
            cfg.w_beaconing,
            format!(
                "periodic connections {} → {}:{} every {:.0}s (cv {:.2}, n={})",
                b.process, b.dst, b.port, b.mean_s, b.cv, b.n
            ),
        );
    }
    let deviation = baseline_deviation(cfg, inp);
    if let Some(msg) = &deviation {
        add(
            &mut reasons,
            Signal::BaselineDeviation,
            cfg.w_baseline_deviation,
            msg.clone(),
        );
    }
    let egress: u64 = inp
        .window_flows
        .iter()
        .filter(|f| !(inp.is_on_link)(&f.dst_ip))
        .filter_map(|f| f.bytes_out)
        .sum();
    if egress >= cfg.egress_bytes_threshold {
        add(
            &mut reasons,
            Signal::LargeEgress,
            cfg.w_large_egress,
            format!("{} MB sent off-link in window", egress / (1024 * 1024)),
        );
    }
    let (has_baseline, span_h) = baseline_ready(cfg, inp.baseline_flows);
    let any_positive = reasons.iter().any(|r| r.delta > 0);
    if d.trusted && !any_positive && (has_baseline || inp.window_flows.is_empty()) {
        add(
            &mut reasons,
            Signal::TrustedBaseline,
            cfg.w_trusted_baseline,
            "trusted device, matches baseline".into(),
        );
    }

    // --- score, confidence, level ------------------------------------------
    let raw: i32 = reasons.iter().map(|r| r.delta).sum();
    let score = raw.clamp(0, 100) as u8;
    let named = d.hostname.is_some() || d.mdns_name.is_some();
    let vendor_known = d.vendor.is_some() && !d.mac_randomized;
    let flows_seen = !inp.window_flows.is_empty();
    let stable = inp.ip_history.len() > 1 || d.last_seen - d.first_seen > Duration::hours(1);
    let ev = |factor: &str, weight: f32, present: bool, yes: String, no: String| Evidence {
        factor: factor.into(),
        weight,
        present,
        note: if present { yes } else { no },
    };
    let evidence = vec![
        ev(
            "Identity",
            0.25,
            named || vendor_known,
            format!("{} / {}", d.display_name(), d.vendor_label()),
            if d.mac_randomized {
                "no name, and a randomized MAC hides the vendor".into()
            } else {
                "no name and vendor not in the IEEE registry".into()
            },
        ),
        ev(
            "Advertised services",
            0.05,
            !d.services.is_empty(),
            d.services
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
            "nothing announced via mDNS/SSDP".into(),
        ),
        ev(
            "Stable presence",
            0.1,
            stable,
            format!("seen since {}", d.first_seen.format("%Y-%m-%d %H:%M")),
            "only just appeared".into(),
        ),
        ev(
            "Traffic visible",
            0.3,
            flows_seen,
            format!("{} connections in the window", inp.window_flows.len()),
            if inp.traffic_visible {
                "no connections captured yet (run `relayscan watch` or press r)".into()
            } else if d.device_type == DeviceType::Router {
                "it forwards everyone's traffic, but only its own logs can show that".into()
            } else {
                "its connections go straight to the gateway, not through this Mac".into()
            },
        ),
        ev(
            "Threat-intel check",
            0.15,
            inp.ti_checked && flows_seen,
            "destinations checked against blocklists/APIs".into(),
            if inp.traffic_visible {
                "no destinations to check yet".into()
            } else {
                "not observable from this Mac".into()
            },
        ),
        ev(
            "Behaviour baseline",
            0.1,
            has_baseline,
            format!(
                "{} older connections over {span_h}h to compare against",
                inp.baseline_flows.len()
            ),
            if !inp.traffic_visible {
                "not observable from this Mac".into()
            } else {
                format!(
                    "still learning: {} connections over {span_h}h (needs ≥{} over ≥{}h)",
                    inp.baseline_flows.len(),
                    cfg.baseline_min_flows,
                    cfg.baseline_min_span_hours
                )
            },
        ),
        ev(
            "Owner confirmed",
            0.2,
            d.trusted,
            "marked trusted".into(),
            "not marked trusted".into(),
        ),
    ];
    let confidence: f32 = evidence
        .iter()
        .filter(|e| e.present)
        .map(|e| e.weight)
        .sum::<f32>()
        .min(1.0);
    let positive = reasons.iter().any(|r| r.delta > 0);
    let level = if !ioc.is_empty() {
        RiskLevel::Red
    } else if !positive && confidence < cfg.gray_below_confidence {
        RiskLevel::Gray
    } else {
        level_for(score)
    };

    let signals: BTreeSet<Signal> = reasons
        .iter()
        .filter(|r| r.delta > 0)
        .map(|r| r.signal)
        .collect();
    let summary = match level {
        RiskLevel::Red => "Contacts known-malicious infrastructure or shows strong attack signs — act now.".to_string(),
        RiskLevel::Orange => format!("High risk: {} warning signal(s) need prompt investigation.", signals.len()),
        RiskLevel::Yellow => format!("Suspicious: {} signal(s) worth checking.", signals.len()),
        RiskLevel::Green => "No risk signals in the observed traffic.".to_string(),
        RiskLevel::Gray if !inp.traffic_visible => "Unrated, not idle: it is online (answers ARP on the LAN), but its traffic does not pass through this Mac, so its behaviour cannot be judged.".to_string(),
        RiskLevel::Gray => "Unrated: not enough data collected yet.".to_string(),
    };
    let actions = next_actions(d, &signals, inp, flows_seen, named || vendor_known);

    Assessment {
        mac: d.mac,
        at: now,
        score,
        level,
        confidence,
        reasons,
        summary,
        evidence,
        actions,
    }
}

fn next_actions(
    d: &Device,
    signals: &BTreeSet<Signal>,
    inp: &Inputs,
    flows_seen: bool,
    identified: bool,
) -> Vec<String> {
    let mut a: Vec<String> = Vec::new();
    for s in signals {
        a.push(match s {
            Signal::IocHit => "Isolate the device (unplug it or move it to a quarantine VLAN), block the IOC destination on the FortiGate, then find the process with `relayscan flows` and scan the host.",
            Signal::GatewayTakeover => "Possible ARP spoofing: compare this MAC with the FortiGate's real MAC on its console. If they differ, find the switch port or Wi-Fi client and disconnect it, and enable ARP inspection.",
            Signal::IpChurn => "Check the FortiGate DHCP log for this MAC: frequent IP changes can mean MAC spoofing or a misbehaving client.",
            Signal::MultiSourceReports => "Look up the reported destination (AbuseIPDB/OTX) and block it if the connection is not expected.",
            Signal::Beaconing => "Periodic connections: identify the process and confirm it is a legitimate updater or heartbeat. Otherwise treat it as possible C2.",
            Signal::BaselineDeviation => "New destinations compared with the baseline: confirm that a recent install or update explains them.",
            Signal::LargeEgress => "Large upload: confirm it is an expected backup or sync.",
            Signal::TrustedBaseline => continue,
        }.to_string());
    }
    if !identified {
        a.push(if d.mac_randomized {
            format!("Identify the owner: look up {} in the FortiGate DHCP / Wi-Fi client list. Randomized MACs are normal for phones and laptops, but they hide the vendor.", d.mac)
        } else {
            format!("Identify the device: vendor unknown. Check the FortiGate DHCP lease hostname for {}.", d.mac)
        });
    }
    if !inp.traffic_visible {
        a.push("To rate its behaviour, its traffic must be observed: export FortiGate traffic logs or mirror the gateway port to a Zeek sensor. On a switched or Wi-Fi LAN this Mac cannot see other devices' traffic.".into());
    } else if !flows_seen {
        a.push(
            "Collect this host's connections: run `relayscan watch` (or press r in the TUI)."
                .into(),
        );
    }
    match d.device_type {
        DeviceType::Camera | DeviceType::Iot => a.push(
            "IoT/camera hygiene: change the default password, update the firmware, and isolate it on an IoT VLAN.".into(),
        ),
        DeviceType::Router => a.push(
            "Gateway: keep FortiOS patched. Its traffic logs are the best source for rating every other device.".into(),
        ),
        _ => {}
    }
    if !d.acknowledged {
        a.push(format!(
            "If this device is expected here, acknowledge it (press a, or `relayscan ack {}`).",
            d.mac
        ));
    }
    if !d.trusted && identified && signals.is_empty() {
        a.push("If you recognise it, mark it trusted (press t). That raises confidence, and it gets −15 while it matches its baseline.".into());
    }
    a
}

pub fn level_for(score: u8) -> RiskLevel {
    match score {
        0..=19 => RiskLevel::Green,
        20..=49 => RiskLevel::Yellow,
        50..=79 => RiskLevel::Orange,
        _ => RiskLevel::Red,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Beacon {
    pub process: String,
    pub dst: IpAddr,
    pub port: u16,
    pub n: usize,
    pub mean_s: f64,
    pub cv: f64,
}

/// Find (process, dst, port) groups whose connection start times are periodic.
pub fn beaconing<'a>(cfg: &RiskConfig, flows: impl Iterator<Item = &'a Flow>) -> Vec<Beacon> {
    let mut groups: BTreeMap<(String, IpAddr, u16), BTreeSet<i64>> = BTreeMap::new();
    for f in flows {
        groups
            .entry((f.process.clone().unwrap_or_default(), f.dst_ip, f.dst_port))
            .or_default()
            .insert(f.first_seen.timestamp());
    }
    let mut out: Vec<Beacon> = groups
        .into_iter()
        .filter(|(_, ts)| ts.len() >= cfg.beacon_min_conns)
        .filter_map(|((process, dst, port), ts)| {
            let ts: Vec<i64> = ts.into_iter().collect();
            let gaps: Vec<f64> = ts.windows(2).map(|w| (w[1] - w[0]) as f64).collect();
            let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
            if mean < cfg.beacon_min_interval_s || mean > cfg.beacon_max_interval_s {
                return None;
            }
            let var = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
            let cv = var.sqrt() / mean;
            (cv <= cfg.beacon_max_cv).then_some(Beacon {
                process,
                dst,
                port,
                n: ts.len(),
                mean_s: mean,
                cv,
            })
        })
        .collect();
    out.sort_by(|a, b| a.cv.total_cmp(&b.cv));
    out
}

/// Destination "network" used for baselining until ASN data exists:
/// /24 for IPv4, /48 for IPv6.
pub fn dst_bucket(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

/// (ready, hours covered). A young baseline makes almost every destination
/// look "new", so deviation only counts once it is old and large enough.
fn baseline_ready(cfg: &RiskConfig, flows: &[Flow]) -> (bool, i64) {
    let span = match (
        flows.iter().map(|f| f.first_seen).min(),
        flows.iter().map(|f| f.last_seen).max(),
    ) {
        (Some(a), Some(b)) => (b - a).num_hours(),
        _ => 0,
    };
    (
        flows.len() >= cfg.baseline_min_flows && span >= cfg.baseline_min_span_hours,
        span,
    )
}

fn baseline_deviation(cfg: &RiskConfig, inp: &Inputs) -> Option<String> {
    if !baseline_ready(cfg, inp.baseline_flows).0 {
        return None;
    }
    let off = |f: &&Flow| !(inp.is_on_link)(&f.dst_ip);
    let known: BTreeSet<(String, u16)> = inp
        .baseline_flows
        .iter()
        .filter(off)
        .map(|f| (dst_bucket(&f.dst_ip), f.dst_port))
        .collect();
    let recent: BTreeSet<(String, u16)> = inp
        .window_flows
        .iter()
        .filter(off)
        .map(|f| (dst_bucket(&f.dst_ip), f.dst_port))
        .collect();
    if recent.is_empty() {
        return None;
    }
    let new: Vec<String> = recent
        .difference(&known)
        .map(|(b, p)| format!("{b}:{p}"))
        .collect();
    let ratio = new.len() as f64 / recent.len() as f64;
    (new.len() >= cfg.baseline_min_new && ratio >= cfg.baseline_min_new_ratio).then(|| {
        format!(
            "{} of {} destinations are new vs baseline ({:.0}%), e.g. {}",
            new.len(),
            recent.len(),
            ratio * 100.0,
            new.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
        )
    })
}

fn join<T: std::fmt::Display>(xs: &BTreeSet<T>) -> String {
    let v: Vec<String> = xs.iter().take(5).map(|x| x.to_string()).collect();
    let more = xs.len().saturating_sub(5);
    if more > 0 {
        format!("{} (+{more} more)", v.join(", "))
    } else {
        v.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(trusted: bool, named: bool) -> Device {
        let t = Utc::now() - Duration::days(2);
        Device {
            id: 1,
            mac: "92:ef:1f:12:0e:00".parse().unwrap(),
            mac_randomized: true,
            vendor: None,
            hostname: named.then(|| "host".to_string()),
            mdns_name: None,
            device_type: DeviceType::Computer,
            ips: vec!["192.168.50.2".parse().unwrap()],
            services: vec![],
            first_seen: t,
            last_seen: Utc::now(),
            connection_status: ConnectionStatus::Online,
            acknowledged: true,
            trusted,
        }
    }

    fn flow(dst: &str, port: u16, at: DateTime<Utc>, out: u64) -> Flow {
        Flow {
            first_seen: at,
            last_seen: at,
            pid: Some(1),
            process: Some("proc".into()),
            proto: Proto::Tcp,
            src_ip: "192.168.50.2".parse().unwrap(),
            src_port: 50000,
            dst_ip: dst.parse().unwrap(),
            dst_port: port,
            dst_mac: None,
            state: None,
            bytes_in: Some(0),
            bytes_out: Some(out),
        }
    }

    fn verdict(
        ip: &str,
        source: &str,
        malicious: bool,
        conf: f32,
        reporters: Option<u32>,
    ) -> Verdict {
        Verdict {
            indicator: ip.parse().unwrap(),
            source: source.into(),
            malicious,
            reporters,
            confidence: conf,
            category: "x".into(),
            detail: String::new(),
            fetched_at: Utc::now(),
        }
    }

    fn on_link(ip: &IpAddr) -> bool {
        matches!(ip, IpAddr::V4(v) if v.octets()[..3] == [192, 168, 50])
    }

    struct Case {
        dev: Device,
        hist: Vec<IpBinding>,
        gw_orig: Option<Mac>,
        window: Vec<Flow>,
        base: Vec<Flow>,
        verdicts: HashMap<IpAddr, Vec<Verdict>>,
    }

    impl Case {
        fn new(dev: Device) -> Self {
            Self {
                dev,
                hist: vec![],
                gw_orig: None,
                window: vec![],
                base: vec![],
                verdicts: HashMap::new(),
            }
        }
        fn run(&self) -> Assessment {
            self.run_cfg(&RiskConfig::default())
        }
        fn run_cfg(&self, cfg: &RiskConfig) -> Assessment {
            assess(
                cfg,
                &Inputs {
                    device: &self.dev,
                    ip_history: &self.hist,
                    gateway_original_mac: self.gw_orig,
                    window_flows: &self.window,
                    baseline_flows: &self.base,
                    verdicts: &self.verdicts,
                    ti_checked: true,
                    traffic_visible: true,
                    is_on_link: &on_link,
                },
                Utc::now(),
            )
        }
    }

    fn signals(a: &Assessment) -> Vec<Signal> {
        a.reasons.iter().map(|r| r.signal).collect()
    }

    fn baseline(n: usize) -> Vec<Flow> {
        let t = Utc::now() - Duration::days(3);
        (0..n)
            .map(|i| {
                flow(
                    "17.57.145.132",
                    443,
                    t + Duration::seconds((i * i * 111 + i * 5) as i64), // irregular: not a beacon
                    10,
                )
            })
            .collect()
    }

    #[test]
    fn no_data_is_gray() {
        let a = Case::new(device(false, false)).run();
        assert_eq!((a.score, a.level), (0, RiskLevel::Gray));
        assert!(a.reasons.is_empty());
    }

    #[test]
    fn ioc_is_red_regardless_of_score() {
        let mut c = Case::new(device(true, true));
        c.window = vec![flow("162.243.103.246", 443, Utc::now(), 10)];
        c.verdicts.insert(
            "162.243.103.246".parse().unwrap(),
            vec![verdict("162.243.103.246", "feodo", true, 0.95, None)],
        );
        let a = c.run();
        assert_eq!(a.level, RiskLevel::Red);
        assert_eq!(a.score, 100);
        assert!(signals(&a).contains(&Signal::IocHit));
        assert!(a.reasons[0].detail.contains("162.243.103.246"));
    }

    #[test]
    fn low_confidence_ioc_is_ignored() {
        let mut c = Case::new(device(false, true));
        c.window = vec![flow("203.0.113.5", 443, Utc::now(), 10)];
        c.verdicts.insert(
            "203.0.113.5".parse().unwrap(),
            vec![verdict("203.0.113.5", "threatfox", true, 0.5, None)],
        );
        assert!(!signals(&c.run()).contains(&Signal::IocHit));
    }

    #[test]
    fn multi_source_reports_yellow() {
        let mut c = Case::new(device(false, true));
        c.window = vec![flow("203.0.113.5", 443, Utc::now(), 10)];
        c.verdicts.insert(
            "203.0.113.5".parse().unwrap(),
            vec![verdict("203.0.113.5", "abuseipdb", false, 0.8, Some(9))],
        );
        let a = c.run();
        assert_eq!(signals(&a), vec![Signal::MultiSourceReports]);
        assert_eq!((a.score, a.level), (40, RiskLevel::Yellow));
    }

    #[test]
    fn ip_churn_and_gateway_takeover_orange() {
        let mut c = Case::new(device(false, true));
        let now = Utc::now();
        let mac = c.dev.mac;
        c.hist = ["192.168.50.2", "192.168.50.3", "192.168.50.254"]
            .iter()
            .map(|ip| IpBinding {
                mac,
                ip: ip.parse().unwrap(),
                first_seen: now,
                last_seen: now,
            })
            .collect();
        c.gw_orig = Some("00:09:0f:aa:00:1a".parse().unwrap());
        let a = c.run();
        assert_eq!(signals(&a), vec![Signal::IpChurn, Signal::GatewayTakeover]);
        assert_eq!((a.score, a.level), (80, RiskLevel::Red));
        // Same MAC as the original holder is not a takeover.
        c.gw_orig = Some(mac);
        c.hist.truncate(1);
        assert!(c.run().reasons.is_empty());
    }

    #[test]
    fn beaconing_detected_and_jitter_rejected() {
        let mut c = Case::new(device(false, true));
        let t = Utc::now() - Duration::minutes(30);
        c.window = (0..8)
            .map(|i| flow("198.51.100.7", 8443, t + Duration::seconds(i * 60), 1))
            .collect();
        let a = c.run();
        assert_eq!(signals(&a), vec![Signal::Beaconing]);
        assert!(a.reasons[0].detail.contains("every 60s"));
        // Irregular gaps → no beacon.
        let gaps = [5, 200, 13, 900, 40, 61, 300];
        let mut at = t;
        c.window = vec![flow("198.51.100.7", 8443, at, 1)];
        for g in gaps {
            at += Duration::seconds(g);
            c.window.push(flow("198.51.100.7", 8443, at, 1));
        }
        assert!(!signals(&c.run()).contains(&Signal::Beaconing));
    }

    #[test]
    fn baseline_deviation_and_trusted_bonus() {
        let mut c = Case::new(device(true, true));
        c.base = baseline(30);
        c.window = vec![flow("17.57.145.132", 443, Utc::now(), 10)];
        let a = c.run();
        assert_eq!(signals(&a), vec![Signal::TrustedBaseline]);
        assert_eq!((a.score, a.level), (0, RiskLevel::Green));
        assert!(a.confidence >= 0.9);

        c.window = (0..6)
            .map(|i| flow(&format!("198.51.{i}.9"), 443, Utc::now(), 10))
            .collect();
        let a = c.run();
        assert_eq!(signals(&a), vec![Signal::BaselineDeviation]);
        assert_eq!((a.score, a.level), (20, RiskLevel::Yellow));
    }

    #[test]
    fn young_baseline_never_flags_deviation() {
        let mut c = Case::new(device(false, true));
        let t = Utc::now() - Duration::hours(2);
        c.base = (0..40)
            .map(|i| flow("17.57.145.132", 443, t + Duration::seconds(i * i * 3), 10))
            .collect();
        c.window = (0..6)
            .map(|i| flow(&format!("198.51.{i}.9"), 443, Utc::now(), 10))
            .collect();
        let a = c.run();
        assert!(!signals(&a).contains(&Signal::BaselineDeviation));
        let b = a
            .evidence
            .iter()
            .find(|e| e.factor == "Behaviour baseline")
            .unwrap();
        assert!(!b.present && b.note.starts_with("still learning"));
    }

    #[test]
    fn large_egress_off_link_only() {
        let mut c = Case::new(device(false, true));
        c.window = vec![flow("192.168.50.10", 445, Utc::now(), 2 << 30)];
        assert!(c.run().reasons.is_empty(), "LAN transfer is not egress");
        c.window
            .push(flow("203.0.113.9", 443, Utc::now(), 600 << 20));
        assert_eq!(signals(&c.run()), vec![Signal::LargeEgress]);
    }

    #[test]
    fn clamps_to_100_and_config_overrides() {
        let mut c = Case::new(device(false, true));
        let now = Utc::now();
        let mac = c.dev.mac;
        c.hist = (1..=4)
            .map(|i| IpBinding {
                mac,
                ip: format!("192.168.50.{i}").parse().unwrap(),
                first_seen: now,
                last_seen: now,
            })
            .collect();
        c.gw_orig = Some("00:09:0f:aa:00:1a".parse().unwrap());
        c.window = vec![flow("203.0.113.9", 443, now, 600 << 20)];
        c.verdicts.insert(
            "203.0.113.9".parse().unwrap(),
            vec![verdict("203.0.113.9", "abuseipdb", false, 0.9, Some(5))],
        );
        assert_eq!(c.run().score, 100);
        let cfg = RiskConfig::from_toml("w_large_egress = 0\nw_multi_source_reports = 1\nw_ip_churn = 1\nw_gateway_takeover = 1").unwrap();
        let a = c.run_cfg(&cfg);
        assert_eq!(a.score, 3);
        assert_eq!(a.level, RiskLevel::Green);
    }

    #[test]
    fn explains_gray_and_suggests_actions() {
        let mut d = device(false, false);
        d.device_type = DeviceType::Camera;
        let empty_f: Vec<Flow> = vec![];
        let v = HashMap::new();
        let a = assess(
            &RiskConfig::default(),
            &Inputs {
                device: &d,
                ip_history: &[],
                gateway_original_mac: None,
                window_flows: &empty_f,
                baseline_flows: &empty_f,
                verdicts: &v,
                ti_checked: true,
                traffic_visible: false,
                is_on_link: &on_link,
            },
            Utc::now(),
        );
        assert_eq!(a.level, RiskLevel::Gray);
        assert!(a.summary.contains("not pass through this Mac"));
        let missing: Vec<&str> = a
            .evidence
            .iter()
            .filter(|e| !e.present)
            .map(|e| e.factor.as_str())
            .collect();
        assert!(missing.contains(&"Traffic visible") && missing.contains(&"Identity"));
        let sum: f32 = a
            .evidence
            .iter()
            .filter(|e| e.present)
            .map(|e| e.weight)
            .sum();
        assert!((sum.min(1.0) - a.confidence).abs() < 1e-6);
        let acts = a.actions.join("\n");
        assert!(acts.contains("DHCP"), "identify via DHCP");
        assert!(acts.contains("Zeek"), "how to get visibility");
        assert!(acts.contains("IoT/camera"));
    }

    #[test]
    fn ioc_actions_come_first() {
        let mut c = Case::new(device(false, true));
        c.window = vec![flow("162.243.103.246", 443, Utc::now(), 10)];
        c.verdicts.insert(
            "162.243.103.246".parse().unwrap(),
            vec![verdict("162.243.103.246", "feodo", true, 0.95, None)],
        );
        let a = c.run();
        assert!(a.actions[0].starts_with("Isolate"));
        assert!(a.summary.contains("act now"));
    }

    #[test]
    fn levels() {
        assert_eq!(level_for(0), RiskLevel::Green);
        assert_eq!(level_for(19), RiskLevel::Green);
        assert_eq!(level_for(20), RiskLevel::Yellow);
        assert_eq!(level_for(50), RiskLevel::Orange);
        assert_eq!(level_for(80), RiskLevel::Red);
    }
}
