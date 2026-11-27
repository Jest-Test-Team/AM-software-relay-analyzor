use anyhow::Result;
use chrono::Local;
use chrono::{DateTime, Duration, Utc};
use relay_collect::netinfo::NetInfo;
use relay_core::risk::{assess, Assessment, Inputs, RiskConfig};
use relay_core::{i18n, tr};
use relay_core::{
    ConnCounts, Device, Flow, FlowOrigin, IpBinding, Lang, Mac, RiskLevel, Store, Verdict,
};
use relay_intel::ti::{is_public, Intel};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct Args {
    /// Evaluation window in minutes; older flows form the baseline.
    #[arg(long, default_value_t = 60)]
    window: i64,
    /// Baseline history in days.
    #[arg(long, default_value_t = 7)]
    baseline_days: i64,
    /// Risk weights/thresholds TOML (see docs/risk.example.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Never contact remote TI APIs.
    #[arg(long)]
    offline: bool,
    #[arg(long, default_value = "data/feeds")]
    feeds: PathBuf,
    /// Include offline devices.
    #[arg(long, short)]
    all: bool,
    #[arg(long)]
    json: bool,
    /// Print summary, confidence breakdown and next steps per device.
    #[arg(long)]
    explain: bool,
    /// Only these devices (MAC); implies nothing else changes.
    #[arg(long = "mac")]
    macs: Vec<relay_core::Mac>,
    #[arg(long)]
    iface: Option<String>,
}

pub struct Opts<'a> {
    pub cfg: &'a RiskConfig,
    pub window: Duration,
    pub baseline: Duration,
    pub offline: bool,
    pub lang: Lang,
}

/// Result of [`assess_all`]: rated devices (highest score first) and each
/// device's attributed flows (window + baseline), newest first.
pub struct Assessed {
    pub rows: Vec<(Device, Assessment)>,
    pub flows: HashMap<Mac, Vec<Flow>>,
}

/// Decide which device sent each flow:
/// - nettop flows are this host's;
/// - a sensor-reported sender MAC wins;
/// - otherwise the device bound to `src_ip` around the flow's time (DHCP may
///   reuse addresses, so the binding closest in time is chosen).
pub fn attribute(
    flows: Vec<Flow>,
    bindings: &HashMap<IpAddr, Vec<IpBinding>>,
    self_mac: Option<Mac>,
    known: &BTreeSet<Mac>,
) -> HashMap<Mac, Vec<Flow>> {
    let slack = Duration::hours(1);
    let mut out: HashMap<Mac, Vec<Flow>> = HashMap::new();
    for f in flows {
        let mac = match (f.origin, f.src_mac) {
            (FlowOrigin::Nettop, _) => self_mac,
            (_, Some(m)) if known.contains(&m) => Some(m),
            _ => bindings.get(&f.src_ip).and_then(|bs| {
                bs.iter()
                    .filter(|b| {
                        b.first_seen - slack <= f.last_seen && b.last_seen + slack >= f.first_seen
                    })
                    .max_by_key(|b| b.last_seen)
                    .or_else(|| bs.iter().max_by_key(|b| b.last_seen))
                    .map(|b| b.mac)
            }),
        };
        if let Some(m) = mac {
            out.entry(m).or_default().push(f);
        }
    }
    out
}

/// Assess every device and persist the result. A device's behaviour can be
/// judged when its flows are visible: this host via nettop, every other
/// device via a network sensor (FortiGate logs/API, Zeek).
pub fn assess_all(
    store: &Store,
    net: &NetInfo,
    intel: &Intel,
    o: &Opts,
    now: DateTime<Utc>,
) -> Result<Assessed> {
    let devices = store.devices_at(now)?;
    let self_ip = IpAddr::V4(net.ip);
    let all_flows = store.flows_since(now - o.baseline)?;
    let sensors_active = all_flows.iter().any(|f| f.origin.is_sensor());
    let cut = now - o.window;

    let mut hist: HashMap<Mac, Vec<IpBinding>> = HashMap::new();
    let mut by_ip: HashMap<IpAddr, Vec<IpBinding>> = HashMap::new();
    for d in &devices {
        let h = store.ip_history(d.mac)?;
        for b in &h {
            by_ip.entry(b.ip).or_default().push(b.clone());
        }
        hist.insert(d.mac, h);
    }
    let self_mac = devices
        .iter()
        .find(|d| d.ips.contains(&self_ip))
        .map(|d| d.mac);
    let known: BTreeSet<Mac> = devices.iter().map(|d| d.mac).collect();
    let flows = attribute(all_flows, &by_ip, self_mac, &known);

    let mut verdicts: HashMap<IpAddr, Vec<Verdict>> = HashMap::new();
    let dsts: BTreeSet<IpAddr> = flows
        .values()
        .flatten()
        .filter(|f| f.last_seen >= cut)
        .map(|f| f.dst_ip)
        .filter(is_public)
        .collect();
    for ip in dsts {
        let v = intel.check(store, ip, o.offline)?;
        if !v.is_empty() {
            verdicts.insert(ip, v);
        }
    }
    let ti_checked = !intel.sources.is_empty();

    let gw_orig = match net.gateway {
        Some(g) => store
            .macs_for_ip(IpAddr::V4(g))?
            .first()
            .map(|b| (b.ip, b.mac)),
        None => None,
    };
    let on_link = |ip: &IpAddr| crate::flows::is_on_link(ip, net);

    let mut rows = Vec::with_capacity(devices.len());
    for d in devices {
        let h = hist.remove(&d.mac).unwrap_or_default();
        let is_self = Some(d.mac) == self_mac;
        let mine = flows.get(&d.mac).map(Vec::as_slice).unwrap_or(&[]);
        let (window, base): (Vec<Flow>, Vec<Flow>) =
            mine.iter().cloned().partition(|f| f.last_seen >= cut);
        let gateway_original_mac = gw_orig
            .filter(|(gip, _)| h.iter().any(|b| b.ip == *gip))
            .map(|(_, m)| m);
        let a = assess(
            o.cfg,
            &Inputs {
                device: &d,
                ip_history: &h,
                gateway_original_mac,
                window_flows: &window,
                baseline_flows: &base,
                verdicts: &verdicts,
                ti_checked,
                traffic_visible: is_self || mine.iter().any(|f| f.origin.is_sensor()),
                sensors_active,
                is_on_link: &on_link,
                lang: o.lang,
            },
            now,
        );
        store.save_assessment(&a)?;
        rows.push((d, a));
    }
    rows.sort_by(|a, b| b.1.score.cmp(&a.1.score).then(b.1.level.cmp(&a.1.level)));
    Ok(Assessed { rows, flows })
}

/// "▲3 active · ●12 closed (last 14:05) · ✕1 other", or n/a.
pub fn counts_line(l: Lang, c: Option<&ConnCounts>) -> String {
    let Some(c) = c else {
        return tr!(
            l,
            "connections n/a (traffic not observable)",
            "連線數 不適用（流量無法觀測）"
        );
    };
    let (act, cls, oth) = (c.active, c.closed, c.other());
    let last = c
        .last_closed
        .map(|t| t.with_timezone(&Local).format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "-".into());
    let (f, dn, st) = (c.failed, c.denied, c.stale);
    tr!(
        l,
        "▲{act} connecting · ●{cls} disconnected (last {last}) · ✕{oth} other (failed {f}, denied {dn}, stale {st})",
        "▲{act} 連線中 · ●{cls} 已中斷（最後 {last}）· ✕{oth} 其他（失敗 {f}、被阻擋 {dn}、逾時未更新 {st}）"
    )
}

fn explain(l: Lang, d: &Device, a: &Assessment) {
    println!(
        "{} {} ({}, {})  {} {}  {} {:.0}%",
        i18n::level(l, a.level),
        i18n::display_name(l, d),
        d.ips
            .iter()
            .find(|i| i.is_ipv4())
            .map(|i| i.to_string())
            .unwrap_or_default(),
        d.mac,
        tr!(l, "score", "分數"),
        a.score,
        tr!(l, "confidence", "信心度"),
        a.confidence * 100.0
    );
    println!("  {}", a.summary);
    println!("  {}", counts_line(l, a.counts.as_ref()));
    for r in &a.reasons {
        println!("  {:+4}  {}", r.delta, r.detail);
    }
    println!("  {}", tr!(l, "confidence:", "信心度構成："));
    for e in &a.evidence {
        println!(
            "    {} {} +{:<3.0} {}",
            if e.present { "✔" } else { "✘" },
            crate::table::pad(&e.factor, 20),
            e.weight * 100.0,
            e.note
        );
    }
    println!("  {}", tr!(l, "next steps:", "下一步："));
    for (i, act) in a.actions.iter().enumerate() {
        println!("    {}. {act}", i + 1);
    }
    println!();
}

pub fn load_config(path: Option<&std::path::Path>) -> Result<RiskConfig> {
    match path {
        Some(p) => RiskConfig::from_toml(&std::fs::read_to_string(p)?),
        None => Ok(RiskConfig::default()),
    }
}

pub fn run(store: &Store, args: &Args, lang: Lang) -> Result<()> {
    let l = lang;
    let net = relay_collect::netinfo::detect(args.iface.as_deref())?;
    let cfg = load_config(args.config.as_deref())?;
    let intel = crate::intel::load(&args.feeds, false);
    let res = assess_all(
        store,
        &net,
        &intel,
        &Opts {
            cfg: &cfg,
            window: Duration::minutes(args.window),
            baseline: Duration::days(args.baseline_days),
            offline: args.offline,
            lang,
        },
        Utc::now(),
    )?;
    let res: Vec<_> = res
        .rows
        .into_iter()
        .filter(|(d, _)| args.all || d.connection_status == relay_core::ConnectionStatus::Online)
        .filter(|(d, _)| args.macs.is_empty() || args.macs.contains(&d.mac))
        .collect();
    if args.explain {
        for (d, a) in &res {
            explain(l, d, a);
        }
        return Ok(());
    }
    if args.json {
        let v: Vec<_> = res
            .iter()
            .map(|(d, a)| serde_json::json!({"device": d, "assessment": a}))
            .collect();
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    let mut counts: HashMap<RiskLevel, usize> = HashMap::new();
    println!(
        "{} {} {}  {} {} {} {}",
        crate::table::pad(&tr!(l, "LEVEL", "等級"), 12),
        crate::table::pad_left(&tr!(l, "SCORE", "分數"), 5),
        crate::table::pad_left(&tr!(l, "CONF", "信心"), 5),
        crate::table::pad(&tr!(l, "▲ACT ●CLS ✕OTH", "▲連線 ●中斷 ✕其他"), 17),
        crate::table::pad("IP", 15),
        crate::table::pad(&tr!(l, "NAME", "名稱"), 26),
        tr!(l, "REASON", "原因")
    );
    for (d, a) in &res {
        *counts.entry(a.level).or_default() += 1;
        if a.level == RiskLevel::Gray && a.reasons.is_empty() && a.counts.is_none() {
            continue; // summarised below
        }
        let conns = a
            .counts
            .as_ref()
            .map(|c| format!("▲{} ●{} ✕{}", c.active, c.closed, c.other()))
            .unwrap_or_else(|| "n/a".into());
        println!(
            "{} {:>5} {:>4.0}%  {} {} {} {}",
            crate::table::pad(&i18n::level(l, a.level), 12),
            a.score,
            a.confidence * 100.0,
            crate::table::pad(&conns, 17),
            crate::table::pad(
                &d.ips
                    .iter()
                    .find(|i| i.is_ipv4())
                    .map(|i| i.to_string())
                    .unwrap_or_default(),
                15
            ),
            crate::table::pad(&i18n::display_name(l, d), 26),
            a.reasons
                .first()
                .map(|r| r.detail.clone())
                .unwrap_or_else(|| a.summary.clone())
        );
        for r in a.reasons.iter().skip(1) {
            println!("{:>70} {:+} {}", "", r.delta, r.detail);
        }
    }
    let c = |lv| counts.get(&lv).copied().unwrap_or(0);
    let (n, red, ora, yel, gre, gra) = (
        res.len(),
        c(RiskLevel::Red),
        c(RiskLevel::Orange),
        c(RiskLevel::Yellow),
        c(RiskLevel::Green),
        c(RiskLevel::Gray),
    );
    println!(
        "{}",
        tr!(
            l,
            "{n} devices: {red} red, {ora} orange, {yel} yellow, {gre} green, {gra} gray (gray = unrated: online, but their traffic is not observable; feed FortiGate/Zeek data, see --explain)",
            "{n} 台裝置：紅 {red}、橙 {ora}、黃 {yel}、綠 {gre}、灰 {gra}（灰 = 未評級：在線但流量無法觀測；請匯入 FortiGate/Zeek 資料，詳見 --explain）"
        )
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_core::{Observation, Proto, Source};
    use relay_intel::ti::Blocklist;
    use std::net::Ipv4Addr;

    fn net() -> NetInfo {
        NetInfo {
            iface: "en0".into(),
            ip: Ipv4Addr::new(192, 168, 50, 2),
            prefix: 24,
            mac: None,
            gateway: Some(Ipv4Addr::new(192, 168, 50, 254)),
        }
    }

    fn arp(ip: &str, mac: &str, at: DateTime<Utc>) -> Observation {
        Observation {
            ip: Some(ip.parse().unwrap()),
            mac: Some(mac.parse().unwrap()),
            hostname: Some("host".into()),
            ..Observation::new(Source::Arp, at)
        }
    }

    /// Plan verification: a known IOC IP injected as a synthetic flow ⇒ Red.
    #[test]
    fn synthetic_ioc_flow_turns_self_red_and_spoofer_flagged() {
        let mut store = Store::in_memory().unwrap();
        let now = Utc::now();
        let earlier = now - Duration::hours(2);
        store
            .ingest(
                &[
                    arp("192.168.50.2", "92:ef:1f:12:0e:00", now),
                    arp("192.168.50.254", "00:09:0f:aa:00:1a", earlier),
                    arp("192.168.50.10", "bc:d0:74:11:22:33", now),
                ],
                &|_| {},
            )
            .unwrap();
        // Later, another MAC answers for the gateway IP (ARP spoofing).
        store
            .ingest(&[arp("192.168.50.254", "de:ad:be:ef:00:01", now)], &|_| {})
            .unwrap();
        store
            .upsert_flows(&[Flow {
                first_seen: now,
                last_seen: now,
                pid: Some(4242),
                process: Some("implant".into()),
                proto: Proto::Tcp,
                src_ip: "192.168.50.2".parse().unwrap(),
                src_port: 51515,
                dst_ip: "162.243.103.246".parse().unwrap(),
                dst_port: 443,
                dst_mac: None,
                state: Some("Established".into()),
                bytes_in: Some(1),
                bytes_out: Some(1),
                origin: Default::default(),
                src_mac: None,
                outcome: Default::default(),
            }])
            .unwrap();
        let intel = Intel {
            sources: vec![Box::new(Blocklist::parse(
                "feodo",
                "botnet_cc",
                0.95,
                "162.243.103.246\n",
            ))],
            ttl: Duration::hours(1),
        };
        let cfg = RiskConfig::default();
        let res = assess_all(
            &store,
            &net(),
            &intel,
            &Opts {
                cfg: &cfg,
                window: Duration::minutes(60),
                baseline: Duration::days(7),
                offline: true,
                lang: Lang::En,
            },
            now,
        )
        .unwrap()
        .rows;
        let by_mac = |m: &str| res.iter().find(|(d, _)| d.mac.to_string() == m).unwrap();

        let (_, me) = by_mac("92:ef:1f:12:0e:00");
        assert_eq!(me.level, RiskLevel::Red);
        assert!(me.reasons[0]
            .detail
            .contains("162.243.103.246 (feodo: botnet_cc)"));

        let (_, spoofer) = by_mac("de:ad:be:ef:00:01");
        assert_eq!(spoofer.score, 45);
        assert_eq!(spoofer.level, RiskLevel::Yellow);

        let (_, gw) = by_mac("00:09:0f:aa:00:1a");
        assert!(
            gw.reasons.is_empty(),
            "original gateway MAC is not penalised"
        );

        let (_, other) = by_mac("bc:d0:74:11:22:33");
        assert_eq!(
            other.level,
            RiskLevel::Gray,
            "no flows visible for other hosts"
        );

        assert_eq!(
            store.assessment(me.mac).unwrap().unwrap().level,
            RiskLevel::Red
        );
        assert_eq!(res[0].1.level, RiskLevel::Red, "sorted by score");
    }

    #[test]
    fn sensor_flows_rate_other_devices() {
        let mut store = Store::in_memory().unwrap();
        let now = Utc::now();
        store
            .ingest(
                &[
                    arp("192.168.50.2", "92:ef:1f:12:0e:00", now),
                    arp("192.168.50.40", "98:da:c4:00:00:40", now),
                ],
                &|_| {},
            )
            .unwrap();
        let ts = (now - Duration::minutes(5))
            .with_timezone(&Local)
            .format("date=%Y-%m-%d time=%H:%M:%S")
            .to_string();
        let log: String = (0..6)
            .map(|i| format!(
                "{ts} type=traffic srcip=192.168.50.13 srcport={} dstip=192.0.2.{i} dstport=23 proto=6 action=deny srcmac=5a:37:28:13:4c:74 srcname=Pixel-7\n",
                40000 + i
            ))
            .chain(std::iter::once(format!(
                // No srcmac: attributed through the ARP binding of .40
                "{ts} type=traffic srcip=192.168.50.40 srcport=5 dstip=198.51.100.1 dstport=443 proto=6 action=close\n"
            )))
            .collect();
        let b = relay_collect::sensors::fortigate::parse_log(&log, now);
        store.ingest(&b.observations, &|_| {}).unwrap();
        store.upsert_flows(&b.flows).unwrap();

        let cfg = RiskConfig::default();
        let intel = Intel {
            sources: vec![],
            ttl: Duration::hours(1),
        };
        let res = assess_all(
            &store,
            &net(),
            &intel,
            &Opts {
                cfg: &cfg,
                window: Duration::minutes(60),
                baseline: Duration::days(7),
                offline: true,
                lang: Lang::En,
            },
            now,
        )
        .unwrap();
        let get = |m: &str| {
            res.rows
                .iter()
                .find(|(d, _)| d.mac.to_string() == m)
                .unwrap()
        };
        let (phone, a) = get("5a:37:28:13:4c:74");
        assert_eq!(
            phone.hostname.as_deref(),
            Some("Pixel-7"),
            "srcname → hostname"
        );
        assert_eq!(a.level, RiskLevel::Green, "denied 15 < 20: {:?}", a.reasons);
        assert_eq!(a.score, 15);
        assert_eq!(a.counts.as_ref().unwrap().denied, 6);
        let (_, other) = get("98:da:c4:00:00:40");
        assert_eq!(
            other.counts.as_ref().unwrap().closed,
            1,
            "IP-only flow attributed"
        );
        let (_, me) = get("92:ef:1f:12:0e:00");
        assert!(me.counts.is_some(), "self is always observable");
        assert!(res.flows[&phone.mac]
            .iter()
            .all(|f| f.origin == FlowOrigin::Fortigate));
    }
}
