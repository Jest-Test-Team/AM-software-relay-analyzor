use anyhow::Result;
use chrono::Utc;
use relay_collect::{arp, mdns, netinfo, rdns, ssdp, sweep};
use relay_core::{Observation, Source, Store};
use relay_intel::{enricher, Context, OuiDb};
use std::net::IpAddr;
use std::time::Duration;

#[derive(clap::Args)]
pub struct Args {
    /// Light active probing: UDP ARP sweep of the local subnet + mDNS/SSDP queries.
    #[arg(long)]
    active: bool,
    /// Interface (default: the default route's).
    #[arg(long)]
    iface: Option<String>,
    /// Seconds to listen for mDNS / SSDP answers.
    #[arg(long, default_value_t = 4)]
    listen: u64,
    /// Delay between sweep packets in milliseconds.
    #[arg(long, default_value_t = 4)]
    pace_ms: u64,
}

impl Args {
    pub fn new(active: bool, iface: Option<String>) -> Self {
        Self {
            active,
            iface,
            listen: 4,
            pace_ms: 4,
        }
    }
}

pub fn run(store: &mut Store, oui: &OuiDb, args: &Args) -> Result<()> {
    let net = netinfo::detect(args.iface.as_deref())?;
    eprintln!(
        "interface {} {}/{} gateway {}",
        net.iface,
        net.ip,
        net.prefix,
        net.gateway.map(|g| g.to_string()).unwrap_or("-".into())
    );
    let ctx = Context {
        gateway: net.gateway.map(IpAddr::V4),
        self_ip: Some(IpAddr::V4(net.ip)),
    };
    let enrich = enricher(oui, &ctx);

    let (mut extra, mut active_note) = (Vec::new(), String::new());
    if args.active {
        let targets = net.sweep_targets()?;
        let rep = sweep::udp_sweep(&targets, Duration::from_millis(args.pace_ms))?;
        active_note = format!("sweep {} sent / {} unreachable; ", rep.sent, rep.errors);
        let wait = Duration::from_secs(args.listen);
        // mDNS and SSDP listen concurrently.
        let ssdp_h = std::thread::spawn(move || ssdp::collect(wait));
        match mdns::collect(wait) {
            Ok(o) => extra.extend(o),
            Err(e) => eprintln!("warning: mDNS failed: {e:#}"),
        }
        match ssdp_h.join() {
            Ok(Ok(o)) => extra.extend(o),
            Ok(Err(e)) => eprintln!("warning: SSDP failed: {e}"),
            Err(_) => eprintln!("warning: SSDP thread panicked"),
        }
    }

    // L2 sightings first so IP-only observations can attach to a MAC.
    let mut l2 = arp::collect(Some(&net.iface))?;
    if let Some(mac) = net.mac {
        l2.push(Observation {
            ip: Some(IpAddr::V4(net.ip)),
            mac: Some(mac),
            hostname: local_hostname(),
            interface: Some(net.iface.clone()),
            ..Observation::new(Source::Arp, Utc::now())
        });
    }
    let r1 = store.ingest(&l2, &enrich)?;

    // Names: rDNS for every IPv4 neighbour (answers come from the LAN resolver).
    let ips: Vec<IpAddr> = l2
        .iter()
        .filter_map(|o| o.ip)
        .filter(IpAddr::is_ipv4)
        .collect();
    extra.extend(rdns::collect(&ips, Duration::from_secs(3)));
    let r2 = store.ingest(&extra, &enrich)?;

    let online = store
        .devices()?
        .iter()
        .filter(|d| d.connection_status == relay_core::ConnectionStatus::Online)
        .count();
    println!(
        "{}",
        relay_core::tr!(
            crate::lang(),
            "{active_note}{} neighbour sightings, {} name/service sightings ({} unmatched); {online} devices online, {} new",
            "{active_note}鄰居紀錄 {} 筆、名稱／服務紀錄 {} 筆（{} 筆無法對應）；{online} 台在線，{} 台新裝置",
            r1.observations,
            r2.observations,
            r2.unmatched,
            r1.new_devices.len() + r2.new_devices.len()
        )
    );
    for mac in r1.new_devices.iter().chain(&r2.new_devices) {
        if let Some(d) = store.device(*mac)? {
            let l = crate::lang();
            println!(
                "  {}  {:<15} {}  {}  {}",
                relay_core::tr!(l, "NEW DEVICE", "新裝置"),
                d.ips.first().map(|i| i.to_string()).unwrap_or_default(),
                d.mac,
                relay_core::i18n::display_name(l, &d),
                relay_core::i18n::vendor_label(l, &d)
            );
        }
    }
    Ok(())
}

fn local_hostname() -> Option<String> {
    let out = std::process::Command::new("scutil")
        .args(["--get", "LocalHostName"])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !s.is_empty()).then_some(s)
}
