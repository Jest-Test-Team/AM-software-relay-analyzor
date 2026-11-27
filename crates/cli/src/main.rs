//! relayscan — vendor-neutral LAN device discovery and risk analysis.

mod assess;
mod compare;
mod discover;
mod flows;
mod intel;
#[cfg(feature = "kaspersky")]
mod kaspersky;
mod sensors;
mod table;
mod tui;
mod watch;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use relay_core::{store::Flag, tr, Mac, Store};
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
    /// Display language: en | zh-TW (default: $RELAYSCAN_LANG, then $LANG / macOS setting)
    #[arg(long, global = true)]
    lang: Option<String>,
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
    /// Import other devices' traffic from a FortiGate log export or Zeek conn.log.
    #[command(subcommand)]
    Import(sensors::ImportCmd),
    /// Receive FortiGate traffic logs pushed over syslog (UDP).
    Syslog(sensors::SyslogArgs),
    /// FortiGate REST API: poll sessions + DHCP leases.
    #[command(subcommand)]
    Fortigate(sensors::FortigateCmd),
    /// Look up flow destinations (or --ip) in threat intelligence.
    Intel(intel::Args),
    /// Score every device (Green/Yellow/Orange/Red/Gray) with reasons.
    Assess(assess::Args),
    /// Interactive two-pane device view (Kaspersky Smart Home Monitor style).
    Tui(tui::Args),
    /// Kaspersky local-DB spike tools (build with --features kaspersky).
    #[cfg(feature = "kaspersky")]
    #[command(subcommand)]
    Kaspersky(kaspersky::Cmd),
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

static LANG: std::sync::OnceLock<relay_core::Lang> = std::sync::OnceLock::new();

/// Display language chosen at startup (`--lang`, env, OS setting).
pub fn lang() -> relay_core::Lang {
    LANG.get().copied().unwrap_or_default()
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
    let lang = relay_core::Lang::detect(cli.lang.as_deref(), &|k| std::env::var(k).ok());
    let _ = LANG.set(lang);
    match &cli.cmd {
        Cmd::Discover(args) => discover::run(&mut store, &load_oui(&cli), args),
        Cmd::Watch(args) => watch::run(&mut store, &load_oui(&cli), args),
        Cmd::Flows { args, iface } => {
            let net = relay_collect::netinfo::detect(iface.as_deref())?;
            flows::run(&mut store, &net, args)
        }
        Cmd::Import(c) => sensors::import(&mut store, &load_oui(&cli), c),
        Cmd::Syslog(a) => sensors::syslog(&mut store, &load_oui(&cli), a),
        Cmd::Fortigate(c) => sensors::fortigate(&mut store, &load_oui(&cli), c),
        Cmd::Intel(args) => intel::run(&store, args),
        Cmd::Assess(args) => assess::run(&store, args, lang),
        Cmd::Tui(args) => tui::run(&mut store, &load_oui(&cli), args, lang),
        #[cfg(feature = "kaspersky")]
        Cmd::Kaspersky(c) => kaspersky::run(&mut store, &load_oui(&cli), c),
        Cmd::Devices { json, all } => {
            let devs: Vec<_> = store
                .devices()?
                .into_iter()
                .filter(|d| *all || d.connection_status == relay_core::ConnectionStatus::Online)
                .collect();
            if *json {
                println!("{}", serde_json::to_string_pretty(&devs)?);
            } else {
                table::print_devices(lang, &devs);
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
    let what = match (f, v) {
        (Flag::Acknowledged, _) => tr!(lang(), "acknowledged", "已確認"),
        (Flag::Trusted, true) => tr!(lang(), "trusted", "已信任"),
        (Flag::Trusted, false) => tr!(lang(), "no longer trusted", "已取消信任"),
    };
    println!("{mac}: {what}");
    Ok(())
}
