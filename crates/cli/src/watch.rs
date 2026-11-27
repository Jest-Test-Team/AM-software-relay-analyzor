use crate::{discover, flows};
use anyhow::Result;
use relay_collect::netinfo;
use relay_core::Store;
use relay_intel::OuiDb;
use std::time::Duration;

#[derive(clap::Args)]
pub struct Args {
    /// Seconds between passes.
    #[arg(long, default_value_t = 30)]
    interval: u64,
    /// Run an active pass (sweep + mDNS/SSDP) every N passes; 0 = never.
    #[arg(long, default_value_t = 10)]
    active_every: u64,
    #[arg(long)]
    iface: Option<String>,
    /// Stop after N passes (0 = run forever).
    #[arg(long, default_value_t = 0)]
    count: u64,
}

pub fn run(store: &mut Store, oui: &OuiDb, args: &Args) -> Result<()> {
    let mut pass = 0u64;
    loop {
        let active = args.active_every > 0 && pass.is_multiple_of(args.active_every);
        let d = discover::Args::new(active, args.iface.clone());
        if let Err(e) = discover::run(store, oui, &d) {
            eprintln!("discover failed: {e:#}");
        }
        match netinfo::detect(args.iface.as_deref()) {
            Ok(net) => match flows::snapshot(store, &net) {
                Ok((seen, new)) => println!(
                    "[{}] flows: {seen} live connections, {new} new",
                    chrono::Local::now().format("%H:%M:%S")
                ),
                Err(e) => eprintln!("flow snapshot failed: {e:#}"),
            },
            Err(e) => eprintln!("netinfo failed: {e:#}"),
        }
        pass += 1;
        if args.count > 0 && pass >= args.count {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(args.interval));
    }
}
