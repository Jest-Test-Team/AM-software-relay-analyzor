use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use relay_collect::netinfo::NetInfo;
use relay_core::risk::{assess, Assessment, Inputs, RiskConfig};
use relay_core::{Device, Flow, RiskLevel, Store, Verdict};
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
    #[arg(long)]
    iface: Option<String>,
}

pub struct Opts<'a> {
    pub cfg: &'a RiskConfig,
    pub window: Duration,
    pub baseline: Duration,
    pub offline: bool,
}

/// Assess every device and persist the result. Behavioural signals are only
/// available for this host (flows come from nettop on this machine).
pub fn assess_all(
    store: &Store,
    net: &NetInfo,
    intel: &Intel,
    o: &Opts,
    now: DateTime<Utc>,
) -> Result<Vec<(Device, Assessment)>> {
    let devices = store.devices_at(now)?;
    let self_ip = IpAddr::V4(net.ip);
    let all_flows = store.flows_since(now - o.baseline)?;
    let cut = now - o.window;
    let (window, base): (Vec<Flow>, Vec<Flow>) = all_flows
        .into_iter()
        .filter(|f| f.src_ip == self_ip || !f.src_ip.is_ipv4())
        .partition(|f| f.last_seen >= cut);

    let mut verdicts: HashMap<IpAddr, Vec<Verdict>> = HashMap::new();
    let dsts: BTreeSet<IpAddr> = window.iter().map(|f| f.dst_ip).filter(is_public).collect();
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
    let empty: Vec<Flow> = Vec::new();

    let mut out = Vec::with_capacity(devices.len());
    for d in devices {
        let hist = store.ip_history(d.mac)?;
        let is_self = d.ips.contains(&self_ip);
        let gateway_original_mac = gw_orig
            .filter(|(gip, _)| hist.iter().any(|b| b.ip == *gip))
            .map(|(_, m)| m);
        let a = assess(
            o.cfg,
            &Inputs {
                device: &d,
                ip_history: &hist,
                gateway_original_mac,
                window_flows: if is_self { &window } else { &empty },
                baseline_flows: if is_self { &base } else { &empty },
                verdicts: &verdicts,
                ti_checked,
                is_on_link: &on_link,
            },
            now,
        );
        store.save_assessment(&a)?;
        out.push((d, a));
    }
    out.sort_by(|a, b| b.1.score.cmp(&a.1.score).then(b.1.level.cmp(&a.1.level)));
    Ok(out)
}

pub fn badge(l: RiskLevel) -> &'static str {
    match l {
        RiskLevel::Green => "GREEN ",
        RiskLevel::Yellow => "YELLOW",
        RiskLevel::Orange => "ORANGE",
        RiskLevel::Red => "RED   ",
        RiskLevel::Gray => "GRAY  ",
    }
}

pub fn load_config(path: Option<&std::path::Path>) -> Result<RiskConfig> {
    match path {
        Some(p) => RiskConfig::from_toml(&std::fs::read_to_string(p)?),
        None => Ok(RiskConfig::default()),
    }
}

pub fn run(store: &Store, args: &Args) -> Result<()> {
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
        },
        Utc::now(),
    )?;
    let res: Vec<_> = res
        .into_iter()
        .filter(|(d, _)| args.all || d.connection_status == relay_core::ConnectionStatus::Online)
        .collect();
    if args.json {
        let v: Vec<_> = res
            .iter()
            .map(|(d, a)| serde_json::json!({"device": d, "assessment": a}))
            .collect();
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    let mut counts: HashMap<RiskLevel, usize> = HashMap::new();
    for (d, a) in &res {
        *counts.entry(a.level).or_default() += 1;
        if a.level == RiskLevel::Gray && a.reasons.is_empty() {
            continue; // summarised below
        }
        println!(
            "{} {:>3}  conf {:>3.0}%  {:<15} {:<26} {}",
            badge(a.level),
            a.score,
            a.confidence * 100.0,
            d.ips
                .iter()
                .find(|i| i.is_ipv4())
                .map(|i| i.to_string())
                .unwrap_or_default(),
            crate::table::trunc(&d.display_name(), 26),
            a.reasons
                .first()
                .map(|r| r.detail.as_str())
                .unwrap_or("no risk signals")
        );
        for r in a.reasons.iter().skip(1) {
            println!("{:>64} {:+} {}", "", r.delta, r.detail);
        }
    }
    let c = |l| counts.get(&l).copied().unwrap_or(0);
    println!(
        "{} devices: {} red, {} orange, {} yellow, {} green, {} gray (insufficient data — no flows visible from this host)",
        res.len(),
        c(RiskLevel::Red),
        c(RiskLevel::Orange),
        c(RiskLevel::Yellow),
        c(RiskLevel::Green),
        c(RiskLevel::Gray)
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
            },
            now,
        )
        .unwrap();
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
}
