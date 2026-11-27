//! Feed other devices' traffic into the store from network sensors:
//! `import fortigate|zeek <file>`, `syslog` (FortiGate push) and
//! `fortigate poll` (FortiGate REST API). See docs/TRAFFIC-SOURCES.md.

use anyhow::{bail, Context as _, Result};
use chrono::{Local, Utc};
use relay_collect::netinfo;
use relay_collect::sensors::{fortigate, fortigate_api, zeek, Batch};
use relay_core::{Flow, Store};
use relay_intel::{enricher, Context, OuiDb};
use std::io::{Read, Seek, SeekFrom};
use std::net::{IpAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(clap::Subcommand)]
pub enum ImportCmd {
    /// FortiGate traffic log export (Log & Report → Forward Traffic →
    /// Download raw logs, or FortiAnalyzer), one key=value record per line.
    Fortigate { files: Vec<PathBuf> },
    /// Zeek conn.log (TSV or JSON lines).
    Zeek {
        file: PathBuf,
        /// Keep reading new lines as Zeek appends them (like `tail -f`).
        #[arg(long)]
        follow: bool,
    },
}

#[derive(clap::Args)]
pub struct SyslogArgs {
    /// Address to listen on; point FortiGate `log syslogd setting` here.
    #[arg(long, default_value = "0.0.0.0:5514")]
    listen: String,
    /// Seconds between writes to the store.
    #[arg(long, default_value_t = 5)]
    flush: u64,
    /// Stop after this many seconds (0 = run forever).
    #[arg(long, default_value_t = 0)]
    duration: u64,
}

#[derive(clap::Subcommand)]
pub enum FortigateCmd {
    /// Poll the session table and DHCP leases via the REST API. The token is
    /// read from $FORTIGATE_API_TOKEN (create a read-only REST API admin).
    Poll {
        /// e.g. https://172.16.200.254 (add :port if the admin GUI uses one)
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = 60)]
        interval: u64,
        /// Accept the FortiGate's self-signed certificate.
        #[arg(long)]
        insecure: bool,
        #[arg(long)]
        vdom: Option<String>,
        /// Stop after N polls (0 = run forever).
        #[arg(long, default_value_t = 0)]
        count: u64,
    },
}

fn ctx() -> Context {
    match netinfo::detect(None) {
        Ok(net) => Context {
            gateway: net.gateway.map(IpAddr::V4),
            self_ip: Some(IpAddr::V4(net.ip)),
        },
        Err(_) => Context {
            gateway: None,
            self_ip: None,
        },
    }
}

/// Write a batch: identities first (so flows can be attributed), then flows.
pub fn store_batch(store: &mut Store, oui: &OuiDb, ctx: &Context, b: &Batch) -> Result<Stored> {
    let enrich = enricher(oui, ctx);
    let rep = store.ingest(&b.observations, &enrich)?;
    let new_flows = store.upsert_flows(&b.flows)?;
    Ok(Stored {
        flows: b.flows.len(),
        new_flows,
        new_devices: rep.new_devices.len(),
        skipped: b.skipped,
    })
}

pub struct Stored {
    pub flows: usize,
    pub new_flows: usize,
    pub new_devices: usize,
    pub skipped: usize,
}

impl std::fmt::Display for Stored {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} flows ({} new), {} new devices, {} non-traffic/unparsed records skipped",
            self.flows, self.new_flows, self.new_devices, self.skipped
        )
    }
}

fn read_text(p: &Path) -> Result<String> {
    let bytes = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
    if bytes.starts_with(&[0x1f, 0x8b]) {
        bail!(
            "{} is gzip-compressed; unpack it first (gunzip -k {})",
            p.display(),
            p.display()
        );
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn import(store: &mut Store, oui: &OuiDb, cmd: &ImportCmd) -> Result<()> {
    let ctx = ctx();
    match cmd {
        ImportCmd::Fortigate { files } => {
            anyhow::ensure!(!files.is_empty(), "give at least one log file");
            for p in files {
                let b = fortigate::parse_log(&read_text(p)?, Utc::now());
                println!("{}: {}", p.display(), store_batch(store, oui, &ctx, &b)?);
            }
            hint();
            Ok(())
        }
        ImportCmd::Zeek { file, follow } => {
            let mut fields = Vec::new();
            let text = read_text(file)?;
            let b = zeek::parse(&text, &mut fields);
            println!("{}: {}", file.display(), store_batch(store, oui, &ctx, &b)?);
            if !follow {
                hint();
                return Ok(());
            }
            let mut pos = text.len() as u64;
            println!("following {} (Ctrl-C to stop)…", file.display());
            loop {
                std::thread::sleep(Duration::from_secs(2));
                let mut f = std::fs::File::open(file)?;
                let len = f.metadata()?.len();
                if len < pos {
                    pos = 0; // rotated
                    fields.clear();
                }
                if len == pos {
                    continue;
                }
                f.seek(SeekFrom::Start(pos))?;
                let mut buf = String::new();
                f.read_to_string(&mut buf)?;
                // Only complete lines; the rest is read next time.
                let Some(end) = buf.rfind('\n') else { continue };
                pos += end as u64 + 1;
                let b = zeek::parse(&buf[..end], &mut fields);
                if !b.flows.is_empty() {
                    println!(
                        "[{}] {}",
                        Local::now().format("%H:%M:%S"),
                        store_batch(store, oui, &ctx, &b)?
                    );
                }
            }
        }
    }
}

fn hint() {
    println!("next: `relayscan assess --explain` or `relayscan tui` to see the rated devices");
}

pub fn syslog(store: &mut Store, oui: &OuiDb, a: &SyslogArgs) -> Result<()> {
    let ctx = ctx();
    let sock = UdpSocket::bind(&a.listen).with_context(|| format!("binding {}", a.listen))?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;
    println!(
        "listening for FortiGate syslog on udp/{} (Ctrl-C to stop)",
        a.listen
    );
    let started = Instant::now();
    let mut last = Instant::now();
    let mut pending = Batch::default();
    let mut buf = vec![0u8; 65535];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _peer)) => {
                let text = String::from_utf8_lossy(&buf[..n]);
                for line in text.lines() {
                    match fortigate::parse_line(line, Utc::now()) {
                        Some(b) => pending.extend(b),
                        None => pending.skipped += 1,
                    }
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e.into()),
        }
        let done = a.duration > 0 && started.elapsed().as_secs() >= a.duration;
        if last.elapsed().as_secs() >= a.flush || done {
            if !pending.flows.is_empty() || pending.skipped > 0 {
                println!(
                    "[{}] {}",
                    Local::now().format("%H:%M:%S"),
                    store_batch(store, oui, &ctx, &pending)?
                );
            }
            pending = Batch::default();
            last = Instant::now();
        }
        if done {
            return Ok(());
        }
    }
}

pub fn fortigate(store: &mut Store, oui: &OuiDb, cmd: &FortigateCmd) -> Result<()> {
    let FortigateCmd::Poll {
        host,
        interval,
        insecure,
        vdom,
        count,
    } = cmd;
    let token = std::env::var("FORTIGATE_API_TOKEN").context(
        "set FORTIGATE_API_TOKEN (System → Administrators → REST API Admin, read-only profile)",
    )?;
    let client = fortigate_api::Client {
        host: host.clone(),
        token,
        insecure: *insecure,
        vdom: vdom.clone(),
    };
    let ctx = ctx();
    let mut prev: Vec<Flow> = Vec::new();
    let mut n = 0u64;
    loop {
        let now = Utc::now();
        let mut b = Batch::default();
        match client.dhcp(now) {
            Ok(obs) => b.observations.extend(obs),
            Err(e) => eprintln!("DHCP poll failed: {e:#}"),
        }
        match client.sessions(now) {
            Ok(s) => {
                let gone = fortigate_api::closed_since(&prev, &s.flows);
                prev = s.flows.clone();
                b.extend(s);
                b.flows.extend(gone);
            }
            Err(e) => eprintln!("session poll failed: {e:#}"),
        }
        println!(
            "[{}] {}",
            Local::now().format("%H:%M:%S"),
            store_batch(store, oui, &ctx, &b)?
        );
        n += 1;
        if *count > 0 && n >= *count {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(*interval));
    }
}
