//! Rule-based risk engine (no ML). Weights follow ref.txt §6 and are NOT
//! calibrated against ground truth — they live in a TOML config so they can be
//! tuned without code changes.
//!
//! Score, level and confidence are separate outputs: a device with no
//! behavioural data and no positive signals is `Gray`, never `Green`.

use crate::i18n::{self, Lang};
use crate::model::*;
use crate::tr;
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
    pub w_denied_by_firewall: i32,
    pub w_conn_failures: i32,
    pub w_lan_scan: i32,

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
    /// Firewall-denied connections in the window (FortiGate `action=deny`).
    pub denied_min: usize,
    /// Failed connections (no answer / reset) in the window: count and share.
    pub failures_min: usize,
    pub failures_min_ratio: f64,
    /// Distinct LAN hosts, or LAN host:port pairs, contacted in the window.
    pub lan_scan_min_hosts: usize,
    pub lan_scan_min_ports: usize,
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
            w_denied_by_firewall: 15,
            w_conn_failures: 10,
            w_lan_scan: 30,
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
            denied_min: 5,
            failures_min: 10,
            failures_min_ratio: 0.3,
            lan_scan_min_hosts: 20,
            lan_scan_min_ports: 50,
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
    LanScan,
    BaselineDeviation,
    LargeEgress,
    DeniedByFirewall,
    ConnFailures,
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
    /// Connections in the window: active / closed / other. `None` when this
    /// device's traffic cannot be observed at all.
    #[serde(default)]
    pub counts: Option<ConnCounts>,
    #[serde(default)]
    pub lang: Lang,
}

/// One factor of the confidence score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Stable identifier (English), independent of the display language.
    #[serde(default)]
    pub key: String,
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
    /// Flows originated by this device in the evaluation window.
    pub window_flows: &'a [Flow],
    /// Older flows from this device, forming its behavioural baseline.
    pub baseline_flows: &'a [Flow],
    /// TI verdicts keyed by destination IP.
    pub verdicts: &'a HashMap<IpAddr, Vec<Verdict>>,
    /// Whether flow destinations were checked against any TI source.
    pub ti_checked: bool,
    /// True if this device's connections can be observed at all: it is the
    /// host running relayscan, or a network sensor (FortiGate/Zeek) has
    /// reported its traffic. False ⇒ Gray means "not observable", not "idle".
    pub traffic_visible: bool,
    /// Whether any network sensor (FortiGate/Zeek) is feeding the store.
    pub sensors_active: bool,
    pub is_on_link: &'a dyn Fn(&IpAddr) -> bool,
    pub lang: Lang,
}

fn origins_label(flows: &[Flow]) -> String {
    let mut o: Vec<&str> = Vec::new();
    for f in flows {
        let s = match f.origin {
            FlowOrigin::Nettop => "nettop",
            FlowOrigin::Fortigate => "FortiGate",
            FlowOrigin::Zeek => "Zeek",
        };
        if !o.contains(&s) {
            o.push(s);
        }
    }
    o.join("+")
}

pub fn assess(cfg: &RiskConfig, inp: &Inputs, now: DateTime<Utc>) -> Assessment {
    let d = inp.device;
    let l = inp.lang;
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
        let s = join(&ioc);
        add(
            &mut reasons,
            Signal::IocHit,
            cfg.w_ioc,
            tr!(
                l,
                "destination matches malicious IOC: {s}",
                "目的地命中惡意 IOC：{s}"
            ),
        );
    }
    if !reported.is_empty() {
        let s = join(&reported);
        add(
            &mut reasons,
            Signal::MultiSourceReports,
            cfg.w_multi_source_reports,
            tr!(
                l,
                "destination has multi-source abuse reports: {s}",
                "目的地有多來源惡意活動回報：{s}"
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
        let (n, s) = (recent_v4.len(), join(&recent_v4));
        add(
            &mut reasons,
            Signal::IpChurn,
            cfg.w_ip_churn,
            tr!(
                l,
                "MAC bound to {n} IPv4 addresses in 24h: {s}",
                "此 MAC 在 24 小時內綁定了 {n} 個 IPv4 位址：{s}"
            ),
        );
    }
    if let Some(orig) = inp.gateway_original_mac.filter(|m| *m != d.mac) {
        add(
            &mut reasons,
            Signal::GatewayTakeover,
            cfg.w_gateway_takeover,
            tr!(
                l,
                "claims the gateway IP previously held by {orig} (possible ARP spoofing)",
                "宣告擁有原屬於 {orig} 的閘道 IP（可能是 ARP 欺騙）"
            ),
        );
    }

    // --- behaviour ----------------------------------------------------------
    let beacons = beaconing(cfg, inp.window_flows.iter().chain(inp.baseline_flows));
    if let Some(b) = beacons.first() {
        let (p, dst, port, mean, cv, n) = (&b.process, b.dst, b.port, b.mean_s, b.cv, b.n);
        add(
            &mut reasons,
            Signal::Beaconing,
            cfg.w_beaconing,
            tr!(
                l,
                "periodic connections {p} → {dst}:{port} every {mean:.0}s (cv {cv:.2}, n={n})",
                "週期性連線 {p} → {dst}:{port}，每 {mean:.0} 秒一次（變異係數 {cv:.2}，n={n}）"
            ),
        );
    }
    // LAN scanning: many distinct on-link peers (ignore our own sweep).
    let lan: Vec<&Flow> = inp
        .window_flows
        .iter()
        .filter(|f| (inp.is_on_link)(&f.dst_ip))
        .filter(|f| !f.process.as_deref().unwrap_or("").starts_with("relayscan"))
        .collect();
    let lan_hosts: BTreeSet<IpAddr> = lan.iter().map(|f| f.dst_ip).collect();
    let lan_ports: BTreeSet<(IpAddr, u16)> = lan.iter().map(|f| (f.dst_ip, f.dst_port)).collect();
    if lan_hosts.len() >= cfg.lan_scan_min_hosts || lan_ports.len() >= cfg.lan_scan_min_ports {
        let (h, p) = (lan_hosts.len(), lan_ports.len());
        add(
            &mut reasons,
            Signal::LanScan,
            cfg.w_lan_scan,
            tr!(
                l,
                "contacted {h} LAN hosts / {p} host:port pairs in the window (looks like scanning)",
                "時間窗內連線 {h} 台區網主機／{p} 組主機:埠（疑似掃描）"
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
        let mb = egress / (1024 * 1024);
        add(
            &mut reasons,
            Signal::LargeEgress,
            cfg.w_large_egress,
            tr!(
                l,
                "{mb} MB sent off-link in window",
                "時間窗內對外傳送 {mb} MB"
            ),
        );
    }
    let denied = inp
        .window_flows
        .iter()
        .filter(|f| f.outcome == FlowOutcome::Denied)
        .count();
    if denied >= cfg.denied_min {
        let eg = denied_examples(inp.window_flows);
        add(
            &mut reasons,
            Signal::DeniedByFirewall,
            cfg.w_denied_by_firewall,
            tr!(
                l,
                "{denied} connections blocked by the firewall, e.g. {eg}",
                "{denied} 條連線被防火牆阻擋，例如 {eg}"
            ),
        );
    }
    let failed = inp
        .window_flows
        .iter()
        .filter(|f| f.outcome == FlowOutcome::Failed)
        .count();
    let total = inp.window_flows.len().max(1);
    if failed >= cfg.failures_min && failed as f64 / total as f64 >= cfg.failures_min_ratio {
        let pct = failed * 100 / total;
        add(
            &mut reasons,
            Signal::ConnFailures,
            cfg.w_conn_failures,
            tr!(
                l,
                "{failed} of {total} connections failed ({pct}%): unanswered or reset",
                "{total} 條連線中有 {failed} 條失敗（{pct}%）：無回應或被重置"
            ),
        );
    }
    let (has_baseline, span_h) = baseline_ready(cfg, inp.baseline_flows);
    let any_positive = reasons.iter().any(|r| r.delta > 0);
    if d.trusted && !any_positive && (has_baseline || inp.window_flows.is_empty()) {
        add(
            &mut reasons,
            Signal::TrustedBaseline,
            cfg.w_trusted_baseline,
            tr!(
                l,
                "trusted device, matches baseline",
                "受信任裝置，行為符合基線"
            ),
        );
    }

    // --- score, confidence, level ------------------------------------------
    let raw: i32 = reasons.iter().map(|r| r.delta).sum();
    let score = raw.clamp(0, 100) as u8;
    let named = d.hostname.is_some() || d.mdns_name.is_some();
    let vendor_known = d.vendor.is_some() && !d.mac_randomized;
    let flows_seen = !inp.window_flows.is_empty();
    let stable = inp.ip_history.len() > 1 || d.last_seen - d.first_seen > Duration::hours(1);
    let ev =
        |key: &str, factor: String, weight: f32, present: bool, yes: String, no: String| Evidence {
            key: key.into(),
            factor,
            weight,
            present,
            note: if present { yes } else { no },
        };
    let not_observable = tr!(l, "not observable from this Mac", "從這台 Mac 無法觀測");
    let (n_win, n_base, via) = (
        inp.window_flows.len(),
        inp.baseline_flows.len(),
        origins_label(inp.window_flows),
    );
    let (min_flows, min_span) = (cfg.baseline_min_flows, cfg.baseline_min_span_hours);
    let first = d.first_seen.format("%Y-%m-%d %H:%M").to_string();
    let svc = d
        .services
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let (dn, vl) = (i18n::display_name(l, d), i18n::vendor_label(l, d));
    let evidence = vec![
        ev(
            "Identity",
            tr!(l, "Identity", "身分識別"),
            0.25,
            named || vendor_known,
            format!("{dn} / {vl}"),
            if d.mac_randomized {
                tr!(
                    l,
                    "no name, and a randomized MAC hides the vendor",
                    "沒有名稱，且隨機化 MAC 隱藏了廠商"
                )
            } else {
                tr!(
                    l,
                    "no name and vendor not in the IEEE registry",
                    "沒有名稱，廠商也不在 IEEE 登錄中"
                )
            },
        ),
        ev(
            "Advertised services",
            tr!(l, "Advertised services", "公告的服務"),
            0.05,
            !d.services.is_empty(),
            svc,
            tr!(
                l,
                "nothing announced via mDNS/SSDP",
                "未透過 mDNS/SSDP 公告任何服務"
            ),
        ),
        ev(
            "Stable presence",
            tr!(l, "Stable presence", "穩定存在"),
            0.1,
            stable,
            tr!(l, "seen since {first}", "自 {first} 起可見"),
            tr!(l, "only just appeared", "剛剛才出現"),
        ),
        ev(
            "Traffic visible",
            tr!(l, "Traffic visible", "流量可見"),
            0.3,
            flows_seen,
            tr!(
                l,
                "{n_win} connections in the window via {via}",
                "時間窗內 {n_win} 條連線（來源：{via}）"
            ),
            if inp.traffic_visible {
                if inp.sensors_active {
                    tr!(
                        l,
                        "sensor is reporting, but no connections from it in the window (idle?)",
                        "感測器運作中，但時間窗內沒有它的連線（閒置？）"
                    )
                } else {
                    tr!(
                        l,
                        "no connections captured yet (run `relayscan watch` or press r)",
                        "尚未擷取到連線（執行 `relayscan watch` 或按 r）"
                    )
                }
            } else if d.device_type == DeviceType::Router {
                tr!(
                    l,
                    "it forwards everyone's traffic, but only its own logs can show that",
                    "它轉送所有人的流量，但只有它自己的日誌能呈現"
                )
            } else {
                tr!(
                    l,
                    "its connections go straight to the gateway, not through this Mac",
                    "它的連線直接送往閘道，不經過這台 Mac"
                )
            },
        ),
        ev(
            "Threat-intel check",
            tr!(l, "Threat-intel check", "威脅情資比對"),
            0.15,
            inp.ti_checked && flows_seen,
            tr!(
                l,
                "destinations checked against blocklists/APIs",
                "目的地已與黑名單／API 比對"
            ),
            if inp.traffic_visible {
                tr!(l, "no destinations to check yet", "尚無目的地可比對")
            } else {
                not_observable.clone()
            },
        ),
        ev(
            "Behaviour baseline",
            tr!(l, "Behaviour baseline", "行為基線"),
            0.1,
            has_baseline,
            tr!(
                l,
                "{n_base} older connections over {span_h}h to compare against",
                "{span_h} 小時內 {n_base} 條較早的連線可供比對"
            ),
            if !inp.traffic_visible {
                not_observable
            } else {
                tr!(
                    l,
                    "still learning: {n_base} connections over {span_h}h (needs ≥{min_flows} over ≥{min_span}h)",
                    "學習中：{span_h} 小時內 {n_base} 條連線（需要 ≥{min_span} 小時內 ≥{min_flows} 條）"
                )
            },
        ),
        ev(
            "Owner confirmed",
            tr!(l, "Owner confirmed", "擁有者確認"),
            0.2,
            d.trusted,
            tr!(l, "marked trusted", "已標記為信任"),
            tr!(l, "not marked trusted", "尚未標記為信任"),
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
    let ns = signals.len();
    let summary = match level {
        RiskLevel::Red => tr!(l, "Contacts known-malicious infrastructure or shows strong attack signs — act now.", "連線到已知惡意設施或出現明顯攻擊跡象 — 請立即處理。"),
        RiskLevel::Orange => tr!(l, "High risk: {ns} warning signal(s) need prompt investigation.", "高風險：{ns} 個警示訊號需要儘快調查。"),
        RiskLevel::Yellow => tr!(l, "Suspicious: {ns} signal(s) worth checking.", "可疑：{ns} 個訊號值得檢查。"),
        RiskLevel::Green => tr!(l, "No risk signals in the observed traffic.", "觀測到的流量中沒有風險訊號。"),
        RiskLevel::Gray if !inp.traffic_visible => tr!(l, "Unrated, not idle: it is online (answers ARP on the LAN), but its traffic does not pass through this Mac, so its behaviour cannot be judged.", "未評級，並非閒置：它在線上（會回應區網 ARP），但流量不經過這台 Mac，因此無法判斷其行為。"),
        RiskLevel::Gray if !flows_seen => tr!(l, "Unrated: no connections from it in the window.", "未評級：時間窗內沒有它的連線。"),
        RiskLevel::Gray => tr!(l, "Unrated: not enough data collected yet.", "未評級：收集的資料還不夠。"),
    };
    let actions = next_actions(d, &signals, inp, flows_seen, named || vendor_known);
    let counts = inp
        .traffic_visible
        .then(|| ConnCounts::tally(inp.window_flows, now));

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
        counts,
        lang: l,
    }
}

fn denied_examples(flows: &[Flow]) -> String {
    let s: BTreeSet<String> = flows
        .iter()
        .filter(|f| f.outcome == FlowOutcome::Denied)
        .map(|f| format!("{}:{}", f.dst_ip, f.dst_port))
        .collect();
    join(&s)
}

fn next_actions(
    d: &Device,
    signals: &BTreeSet<Signal>,
    inp: &Inputs,
    flows_seen: bool,
    identified: bool,
) -> Vec<String> {
    let l = inp.lang;
    let mac = d.mac;
    let mut a: Vec<String> = Vec::new();
    for s in signals {
        a.push(match s {
            Signal::IocHit => tr!(l, "Isolate the device (unplug it or move it to a quarantine VLAN), block the IOC destination on the FortiGate, then find the process (`relayscan flows` on a Mac, or EDR) and scan the host.", "隔離此裝置（拔線或移到隔離 VLAN），在 FortiGate 封鎖該 IOC 目的地，接著找出對應程序（Mac 上用 `relayscan flows`，或用 EDR）並掃描主機。"),
            Signal::GatewayTakeover => tr!(l, "Possible ARP spoofing: compare this MAC with the FortiGate's real MAC on its console. If they differ, find the switch port or Wi-Fi client and disconnect it, and enable ARP inspection.", "可能遭 ARP 欺騙：在 FortiGate 主控台比對其真實 MAC。若不同，找出對應的交換器埠或 Wi-Fi 用戶端並中斷連線，並啟用 ARP 檢查。"),
            Signal::IpChurn => tr!(l, "Check the FortiGate DHCP log for this MAC: frequent IP changes can mean MAC spoofing or a misbehaving client.", "查看 FortiGate 對此 MAC 的 DHCP 紀錄：IP 頻繁變動可能代表 MAC 偽造或用戶端異常。"),
            Signal::MultiSourceReports => tr!(l, "Look up the reported destination (AbuseIPDB/OTX) and block it if the connection is not expected.", "查詢被回報的目的地（AbuseIPDB/OTX），若連線非預期就封鎖它。"),
            Signal::Beaconing => tr!(l, "Periodic connections: identify the process and confirm it is a legitimate updater or heartbeat. Otherwise treat it as possible C2.", "週期性連線：找出程序並確認是合法的更新或心跳；否則視為可能的 C2。"),
            Signal::LanScan => tr!(l, "It is probing many LAN hosts: find out what runs on it (inventory/backup tools scan legitimately). If unexplained, quarantine it and check it for malware.", "它正在探測許多區網主機：確認它上面執行什麼（盤點／備份工具也會合法掃描）。若無法解釋，請隔離並檢查是否中毒。"),
            Signal::BaselineDeviation => tr!(l, "New destinations compared with the baseline: confirm that a recent install or update explains them.", "與基線相比出現新目的地：確認是否為近期安裝或更新所致。"),
            Signal::LargeEgress => tr!(l, "Large upload: confirm it is an expected backup or sync.", "大量上傳：確認是否為預期的備份或同步。"),
            Signal::DeniedByFirewall => tr!(l, "The FortiGate is blocking its connections: review the deny log for this source (Log & Report → Forward Traffic, filter srcip). Repeated blocked attempts to odd ports can mean malware.", "FortiGate 正在阻擋它的連線：檢視此來源的拒絕紀錄（Log & Report → Forward Traffic，篩選 srcip）。反覆嘗試連到異常埠可能代表中毒。"),
            Signal::ConnFailures => tr!(l, "Many connections fail: a dead service it depends on, or blind scanning / an offline C2 server. Check which destinations fail.", "大量連線失敗：可能是依賴的服務失效，或是盲目掃描／離線的 C2 伺服器。請檢查哪些目的地失敗。"),
            Signal::TrustedBaseline => continue,
        });
    }
    if !identified {
        a.push(if d.mac_randomized {
            tr!(l, "Identify the owner: look up {mac} in the FortiGate DHCP / Wi-Fi client list (or run `relayscan fortigate poll`, which imports DHCP hostnames). Randomized MACs are normal for phones and laptops, but they hide the vendor.", "找出擁有者：在 FortiGate DHCP／Wi-Fi 用戶端清單查詢 {mac}（或執行 `relayscan fortigate poll` 匯入 DHCP 主機名稱）。手機與筆電使用隨機化 MAC 很正常，但會隱藏廠商。")
        } else {
            tr!(l, "Identify the device: vendor unknown. Check the FortiGate DHCP lease hostname for {mac}.", "識別此裝置：廠商未知。請查看 FortiGate DHCP 租約中 {mac} 的主機名稱。")
        });
    }
    if !inp.traffic_visible {
        a.push(if inp.sensors_active {
            tr!(l, "A sensor is feeding traffic, but none of it is from this device: it may be on a VLAN/SSID whose policy has logging off. Enable 'Log Allowed Traffic: All Sessions' on that FortiGate policy.", "已有感測器提供流量，但沒有這台裝置的：它可能位於未開啟日誌的 VLAN／SSID。請在該 FortiGate 政策啟用「Log Allowed Traffic: All Sessions」。")
        } else {
            tr!(l, "To rate its behaviour, feed the gateway's view of its traffic: `relayscan syslog` + FortiGate syslog push, `relayscan import fortigate <log>`, `relayscan fortigate poll`, or a Zeek sensor on a mirror port (`relayscan import zeek conn.log --follow`). See docs/TRAFFIC-SOURCES.md. This Mac alone cannot see other devices' traffic on a switched/Wi-Fi LAN.", "要評估它的行為，需要匯入閘道看到的流量：`relayscan syslog` 搭配 FortiGate syslog 推送、`relayscan import fortigate <日誌>`、`relayscan fortigate poll`，或在鏡像埠架設 Zeek（`relayscan import zeek conn.log --follow`）。詳見 docs/TRAFFIC-SOURCES.md。在交換式／Wi-Fi 區網中，這台 Mac 本身看不到其他裝置的流量。")
        });
    } else if !flows_seen && !inp.sensors_active {
        a.push(tr!(
            l,
            "Collect this host's connections: run `relayscan watch` (or press r in the TUI).",
            "收集本機連線：執行 `relayscan watch`（或在 TUI 按 r）。"
        ));
    }
    match d.device_type {
        DeviceType::Camera | DeviceType::Iot => a.push(tr!(l, "IoT/camera hygiene: change the default password, update the firmware, and isolate it on an IoT VLAN.", "IoT／攝影機防護：更改預設密碼、更新韌體，並隔離到 IoT VLAN。")),
        DeviceType::Router => a.push(if inp.sensors_active {
            tr!(l, "Gateway: traffic logs are being ingested ✔. Keep FortiOS patched.", "閘道：流量日誌已在匯入 ✔。請持續更新 FortiOS。")
        } else {
            tr!(l, "Gateway: keep FortiOS patched. Its traffic logs are the best source for rating every other device: see docs/TRAFFIC-SOURCES.md.", "閘道：請持續更新 FortiOS。它的流量日誌是評估其他所有裝置的最佳來源：詳見 docs/TRAFFIC-SOURCES.md。")
        }),
        _ => {}
    }
    if !d.acknowledged {
        a.push(tr!(
            l,
            "If this device is expected here, acknowledge it (press a, or `relayscan ack {mac}`).",
            "若這台裝置本來就該在這裡，請確認它（按 a，或 `relayscan ack {mac}`）。"
        ));
    }
    if !d.trusted && identified && signals.is_empty() {
        a.push(tr!(l, "If you recognise it, mark it trusted (press t). That raises confidence, and it gets −15 while it matches its baseline.", "若你認得它，請標記為信任（按 t）。這會提高信心度，且行為符合基線時分數 −15。"));
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
        let (n, r, pct) = (new.len(), recent.len(), ratio * 100.0);
        let eg = new.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
        tr!(
            inp.lang,
            "{n} of {r} destinations are new vs baseline ({pct:.0}%), e.g. {eg}",
            "{r} 個目的地中有 {n} 個是基線外的新目的地（{pct:.0}%），例如 {eg}"
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
            origin: Default::default(),
            src_mac: None,
            outcome: Default::default(),
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
        sensors: bool,
        lang: Lang,
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
                sensors: false,
                lang: Lang::En,
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
                    sensors_active: self.sensors,
                    is_on_link: &on_link,
                    lang: self.lang,
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
                sensors_active: false,
                is_on_link: &on_link,
                lang: Lang::En,
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

    fn sensor_flow(dst: &str, port: u16, at: DateTime<Utc>, outcome: FlowOutcome) -> Flow {
        Flow {
            origin: FlowOrigin::Fortigate,
            outcome,
            process: Some("HTTPS".into()),
            src_ip: "192.168.50.13".parse().unwrap(),
            ..flow(dst, port, at, 100)
        }
    }

    #[test]
    fn sensor_fed_device_is_rated_with_counts() {
        let mut c = Case::new(device(false, true));
        c.sensors = true;
        let now = Utc::now();
        c.window = (0..4)
            .map(|i| sensor_flow(&format!("198.51.100.{i}"), 443, now, FlowOutcome::Closed))
            .collect();
        c.window
            .push(sensor_flow("198.51.100.9", 443, now, FlowOutcome::Active));
        let a = c.run();
        assert_ne!(a.level, RiskLevel::Gray, "traffic visible via FortiGate");
        let tv = a
            .evidence
            .iter()
            .find(|e| e.key == "Traffic visible")
            .unwrap();
        assert!(tv.present && tv.note.contains("FortiGate"), "{}", tv.note);
        let n = a.counts.unwrap();
        assert_eq!((n.active, n.closed, n.other()), (1, 4, 0));
    }

    #[test]
    fn lan_scan_and_denies_fire() {
        let mut c = Case::new(device(false, true));
        let now = Utc::now();
        c.window = (1..=25)
            .map(|i| sensor_flow(&format!("192.168.50.{i}"), 445, now, FlowOutcome::Failed))
            .collect();
        c.window.extend(
            (0..6).map(|i| sensor_flow(&format!("192.0.2.{i}"), 23, now, FlowOutcome::Denied)),
        );
        let a = c.run();
        let s = signals(&a);
        assert!(s.contains(&Signal::LanScan), "{s:?}");
        assert!(s.contains(&Signal::DeniedByFirewall));
        assert!(s.contains(&Signal::ConnFailures));
        assert_eq!(a.score, 55);
        assert_eq!(a.level, RiskLevel::Orange);
        assert!(a.actions[0].contains("LAN hosts"), "{}", a.actions[0]);
        assert_eq!(a.counts.unwrap().other(), 31);
    }

    #[test]
    fn traditional_chinese_output() {
        let mut c = Case::new(device(false, false));
        c.lang = Lang::ZhTw;
        c.window = vec![flow("162.243.103.246", 443, Utc::now(), 10)];
        c.verdicts.insert(
            "162.243.103.246".parse().unwrap(),
            vec![verdict("162.243.103.246", "feodo", true, 0.95, None)],
        );
        let a = c.run();
        assert_eq!(a.level, RiskLevel::Red);
        assert!(a.summary.contains("立即處理"), "{}", a.summary);
        assert!(a.reasons[0].detail.starts_with("目的地命中惡意 IOC"));
        assert!(a.actions[0].starts_with("隔離此裝置"));
        assert!(a
            .evidence
            .iter()
            .any(|e| e.factor == "流量可見" && e.key == "Traffic visible"));
        assert_eq!(a.lang, Lang::ZhTw);
    }
}
