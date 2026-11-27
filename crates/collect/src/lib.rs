//! Collectors: ARP/NDP, sweep, mDNS, SSDP, reverse DNS, flows.
//!
//! Every collector is split into a pure parser (unit-tested against fixtures)
//! and a thin function that touches the system or network.

pub mod arp;
pub mod mdns;
pub mod netinfo;
pub mod rdns;
pub mod ssdp;
pub mod sweep;

use anyhow::{bail, Context, Result};
use std::process::Command;

/// Run a command and return stdout. Non-zero exit is an error.
pub(crate) fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("spawning {cmd}"))?;
    if !out.status.success() {
        bail!(
            "{cmd} {} exited with {}: {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
