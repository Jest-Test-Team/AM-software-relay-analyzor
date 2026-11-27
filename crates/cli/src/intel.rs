use anyhow::Result;
use chrono::{Duration, Utc};
use relay_core::Store;
use relay_intel::ti::{is_public, Intel};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct Args {
    /// Check specific IPs instead of recent flow destinations.
    #[arg(long = "ip")]
    ips: Vec<IpAddr>,
    /// Use flows seen in the last N minutes.
    #[arg(long, default_value_t = 60)]
    since: i64,
    /// Only local blocklists; never contact remote TI APIs.
    #[arg(long)]
    offline: bool,
    /// Directory with offline feeds (see scripts/fetch-feeds.sh).
    #[arg(long, default_value = "data/feeds")]
    feeds: PathBuf,
}

pub fn load(feeds: &std::path::Path, verbose: bool) -> Intel {
    let (intel, notes) = Intel::from_env(feeds);
    if verbose {
        for n in notes {
            eprintln!("intel: {n}");
        }
    }
    intel
}

pub fn run(store: &Store, args: &Args) -> Result<()> {
    let intel = load(&args.feeds, true);
    let targets: BTreeSet<IpAddr> = if args.ips.is_empty() {
        store
            .flows_since(Utc::now() - Duration::minutes(args.since))?
            .into_iter()
            .map(|f| f.dst_ip)
            .filter(is_public)
            .collect()
    } else {
        args.ips.iter().copied().collect()
    };
    eprintln!(
        "checking {} destination(s){}",
        targets.len(),
        if args.offline { " (offline)" } else { "" }
    );
    let mut hits = 0;
    for ip in &targets {
        let vs = intel.check(store, *ip, args.offline)?;
        for v in &vs {
            hits += 1;
            println!(
                "{} {:<40} {:<14} {:<14} conf {:>3.0}%  {}",
                if v.malicious { "IOC " } else { "rep " },
                ip.to_string(),
                v.source,
                v.category,
                v.confidence * 100.0,
                v.detail
            );
        }
    }
    println!("{hits} hit(s) across {} destination(s)", targets.len());
    Ok(())
}
