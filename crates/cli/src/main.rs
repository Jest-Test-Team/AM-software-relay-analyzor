//! relayscan — vendor-neutral LAN device discovery and risk analysis.

mod assess;
mod compare;
mod discover;
mod flows;
mod intel;
mod table;
mod watch;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use relay_core::{store::Flag, Mac, Store};
use relay_intel::OuiDb;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "relayscan", version, about)]
struct Cli {
    /// SQLite store (default: $RELAYSCAN_DB or ~/.local/share/relayscan/relayscan.sqlite)
    #[arg(long, global = true)]
    db: Option<PathBuf>,
    /// IEEE OUI CSV (default: $RELAYSCAN_OUI or ./data/oui.csv)
    #[arg(long, global = true)]
    oui: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run one discovery pass and store the results.
    Discover(discover::Args),
    /// Continuously discover devices and snapshot flows.
    Watch(watch::Args),
    /// Show this host's connections per process and destination.
    Flows {
        #[command(flatten)]
        args: flows::Args,
        #[arg(long)]
        iface: Option<String>,
    },
    /// Look up flow destinations (or --ip) in threat intelligence.
    Intel(intel::Args),
    /// Score every device (Green/Yellow/Orange/Red/Gray) with reasons.
    Assess(assess::Args),
    /// List known devices.
    Devices {
        #[arg(long)]
        json: bool,
        /// Include offline devices.
        #[arg(long, short)]
        all: bool,
    },
    /// Benchmark discovery against a CSV (name,ip,mac) transcribed from Kaspersky.
    Compare {
        #[arg(long)]
        kaspersky: PathBuf,
    },
    /// Acknowledge a device (clears the NEW badge).
    Ack { mac: Mac },
    /// Mark a device as trusted (known-good).
    Trust {
        mac: Mac,
        #[arg(long)]
        revoke: bool,
    },
}

fn db_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(p) = cli
        .db
        .clone()
        .or_else(|| std::env::var_os("RELAYSCAN_DB").map(Into::into))
    {
        return Ok(p);
    }
    let home = std::env::var_os("HOME").context("HOME not set; pass --db")?;
    let dir = PathBuf::from(home).join(".local/share/relayscan");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("relayscan.sqlite"))
}

fn load_oui(cli: &Cli) -> OuiDb {
    let path = cli
        .oui
        .clone()
        .or_else(|| std::env::var_os("RELAYSCAN_OUI").map(Into::into))
        .unwrap_or_else(|| PathBuf::from("data/oui.csv"));
    match OuiDb::load(&path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("warning: no OUI vendor data ({e:#}); run scripts/fetch-oui.sh");
            OuiDb::default()
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut store = Store::open(db_path(&cli)?)?;
    match &cli.cmd {
        Cmd::Discover(args) => discover::run(&mut store, &load_oui(&cli), args),
        Cmd::Watch(args) => watch::run(&mut store, &load_oui(&cli), args),
        Cmd::Flows { args, iface } => {
            let net = relay_collect::netinfo::detect(iface.as_deref())?;
            flows::run(&mut store, &net, args)
        }
        Cmd::Intel(args) => intel::run(&store, args),
        Cmd::Assess(args) => assess::run(&store, args),
        Cmd::Devices { json, all } => {
            let devs: Vec<_> = store
                .devices()?
                .into_iter()
                .filter(|d| *all || d.connection_status == relay_core::ConnectionStatus::Online)
                .collect();
            if *json {
                println!("{}", serde_json::to_string_pretty(&devs)?);
            } else {
                table::print_devices(&devs);
            }
            Ok(())
        }
        Cmd::Compare { kaspersky } => compare::run(&store.devices()?, kaspersky),
        Cmd::Ack { mac } => flag(&store, *mac, Flag::Acknowledged, true),
        Cmd::Trust { mac, revoke } => flag(&store, *mac, Flag::Trusted, !revoke),
    }
}

fn flag(store: &Store, mac: Mac, f: Flag, v: bool) -> Result<()> {
    anyhow::ensure!(store.set_flag(mac, f, v)?, "unknown device {mac}");
    println!("{mac}: {f:?} = {v}");
    Ok(())
}
