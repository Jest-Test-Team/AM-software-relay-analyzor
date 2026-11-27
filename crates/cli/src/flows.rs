use anyhow::Result;
use chrono::{Duration, Utc};
use relay_collect::{flows, netinfo::NetInfo};
use relay_core::{Flow, Mac, Store};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

#[derive(clap::Args)]
pub struct Args {
    /// Show flows seen in the last N minutes.
    #[arg(long, default_value_t = 60)]
    since: i64,
    /// Don't take a fresh nettop snapshot first.
    #[arg(long)]
    no_snapshot: bool,
    /// Only off-link (internet) destinations.
    #[arg(long)]
    remote: bool,
    #[arg(long)]
    json: bool,
}

/// Take one nettop snapshot, attach on-link MACs, store it. Returns (seen, new).
pub fn snapshot(store: &mut Store, net: &NetInfo) -> Result<(usize, usize)> {
    let mut fl = flows::collect()?;
    let neighbours: HashMap<IpAddr, Mac> = store
        .devices()?
        .into_iter()
        .flat_map(|d| d.ips.into_iter().map(move |ip| (ip, d.mac)))
        .collect();
    attach(&mut fl, net, &neighbours);
    let new = store.upsert_flows(&fl)?;
    Ok((fl.len(), new))
}

fn attach(fl: &mut [Flow], net: &NetInfo, n: &HashMap<IpAddr, Mac>) {
    let on_link = |ip: &IpAddr| is_on_link(ip, net);
    flows::attach_dst_mac(fl, on_link, n);
}

pub fn is_on_link(ip: &IpAddr, net: &NetInfo) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let m = relay_collect::netinfo::mask(net.prefix);
            u32::from(*v4) & m == u32::from(net.network())
        }
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

pub fn run(store: &mut Store, net: &NetInfo, args: &Args) -> Result<()> {
    if !args.no_snapshot {
        let (seen, new) = snapshot(store, net)?;
        eprintln!("snapshot: {seen} connections, {new} new");
    }
    let fl: Vec<Flow> = store
        .flows_since(Utc::now() - Duration::minutes(args.since))?
        .into_iter()
        .filter(|f| !args.remote || !is_on_link(&f.dst_ip, net))
        .collect();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&fl)?);
        return Ok(());
    }
    // Aggregate per (process, dst ip, port, proto).
    #[derive(Default)]
    struct Agg {
        conns: usize,
        bytes_in: u64,
        bytes_out: u64,
        dst_mac: Option<Mac>,
        first: Option<chrono::DateTime<Utc>>,
        last: Option<chrono::DateTime<Utc>>,
    }
    let mut agg: BTreeMap<(String, IpAddr, u16, &str), Agg> = BTreeMap::new();
    for f in &fl {
        let key = (
            f.process.clone().unwrap_or_else(|| "?".into()),
            f.dst_ip,
            f.dst_port,
            f.proto.as_str(),
        );
        let a = agg.entry(key).or_default();
        a.conns += 1;
        a.bytes_in += f.bytes_in.unwrap_or(0);
        a.bytes_out += f.bytes_out.unwrap_or(0);
        a.dst_mac = a.dst_mac.or(f.dst_mac);
        a.first = Some(a.first.map_or(f.first_seen, |t| t.min(f.first_seen)));
        a.last = Some(a.last.map_or(f.last_seen, |t| t.max(f.last_seen)));
    }
    println!(
        "{:<11} {:<8} {:<24} {:<4} {:<40} {:>5} {:>6} {:>10} {:>10}  DST MAC",
        "FIRST SEEN", "LAST", "PROCESS", "PROTO", "DESTINATION", "PORT", "CONNS", "IN", "OUT"
    );
    let mut rows: Vec<_> = agg.iter().collect();
    rows.sort_by_key(|b| std::cmp::Reverse(b.1.last));
    let local = |t: Option<chrono::DateTime<Utc>>, f: &str| {
        t.map(|t| t.with_timezone(&chrono::Local).format(f).to_string())
            .unwrap_or_default()
    };
    for ((proc_, ip, port, proto), a) in rows {
        println!(
            "{:<11} {:<8} {:<24} {:<4} {:<40} {:>5} {:>6} {:>10} {:>10}  {}",
            local(a.first, "%m-%d %H:%M"),
            local(a.last, "%H:%M:%S"),
            crate::table::trunc(proc_, 24),
            proto,
            ip.to_string(),
            port,
            a.conns,
            human(a.bytes_in),
            human(a.bytes_out),
            a.dst_mac
                .map(|m| m.to_string())
                .unwrap_or_else(|| "-".into())
        );
    }
    println!(
        "{} connections, {} distinct process→destination pairs",
        fl.len(),
        agg.len()
    );
    Ok(())
}

pub fn human(b: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}
