use anyhow::Result;
use relay_collect::kaspersky;
use relay_core::Store;
use relay_intel::{enricher, Context, OuiDb};
use std::path::PathBuf;

#[derive(clap::Subcommand)]
pub enum Cmd {
    /// List tables/columns and count IP/MAC-shaped values (read-only).
    Probe { file: PathBuf },
    /// Import rows carrying a MAC (+ optional IP/name) as Kaspersky sightings.
    Import {
        file: PathBuf,
        #[arg(long)]
        dry_run: bool,
    },
}

pub fn run(store: &mut Store, oui: &OuiDb, cmd: &Cmd) -> Result<()> {
    match cmd {
        Cmd::Probe { file } => {
            for t in kaspersky::probe(file)? {
                println!(
                    "{:<32} rows {:>7}  ip-like {:>6}  mac-like {:>6}  cols: {}",
                    t.name,
                    t.rows,
                    t.ip_values,
                    t.mac_values,
                    t.columns.join(",")
                );
                for (ip, mac, name) in &t.samples {
                    println!("    e.g. ip={ip:?} mac={mac:?} name={name:?}");
                }
            }
            Ok(())
        }
        Cmd::Import { file, dry_run } => {
            let obs = kaspersky::import(file)?;
            println!("{} candidate sightings", obs.len());
            if *dry_run {
                for o in obs.iter().take(20) {
                    println!("  {:?} {:?} {:?}", o.ip, o.mac, o.hostname);
                }
                return Ok(());
            }
            let ctx = Context::default();
            let r = store.ingest(&obs, &enricher(oui, &ctx))?;
            println!(
                "imported: {} new devices, {} updated",
                r.new_devices.len(),
                r.updated_devices
            );
            Ok(())
        }
    }
}
