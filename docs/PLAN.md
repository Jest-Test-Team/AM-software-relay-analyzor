# Plan: AM-software-relay-analyzor — vendor-neutral LAN device & risk analyzer (Rust CLI/TUI MVP)

## Context
`.ignore/ref.txt` evaluates whether Kaspersky Plus can feed device and connection telemetry into a self-built app that rates IP/MAC risk with colors (Green/Yellow/Orange/Red/Gray). Its conclusion: Kaspersky has no public consumer API, so treat it as a **benchmark plus an optional source**, not the core. Build our own discovery, flow collection, threat-intel lookups and a rule-based risk engine.

What the screenshots and this Mac show (these correct parts of ref.txt):
- The product is **Kaspersky Plus for macOS** ("Kaspersky Anti-Virus For Mac.app"), not Windows. The `%allusersprofile%\...\AVP21.7` path and Sysmon do not apply.
- The Smart Home Monitor row has:
  - a **green dot**, which means online/connected;
  - an **orange dot / "NEW DEVICE" badge**, which means not yet acknowledged. Neither is a risk score.
  - Detail panel fields: name, vendor (OUI), Last seen, IP, MAC, and a type icon (router/laptop/phone/tablet/TV/unknown).
- Many MACs are **randomized**. `1a:9d:…` and `5a:26:…` have the locally-administered bit set, so OUI lookup must flag "Randomized MAC" instead of calling the device unknown.
- Network: `172.16.200.0/x`, Fortinet gateway `172.16.200.1` (`bc:d0:74:…`), this Mac is `.2` on `en0`, about 258 ARP entries. It is a large shared LAN.
- Local Kaspersky data lives in `/Library/Application Support/Kaspersky Lab/KAV/Data/`:
  - world-readable SQLite files with WAL: `reports.db`, `detects.db`, `persistent_q.db`, `Report/Database/reports.db`;
  - root-only `data.kvdb`;
  - an `nhdp/` dir that probably holds Smart Home Monitor ("network home device protection") data;
  - proprietary `Report/*.dat` files.

  Reading them was **not verified**: the permission classifier blocked copying them. That stays a gated spike that you run yourself.
- Toolchain: rustc/cargo, python3, flutter are present; nmap/tshark/zeek are not. macOS 26.5.

Decisions: **Rust CLI/TUI only**. **Passive discovery plus light active probing** (ARP-cache refresh ping sweep of own subnet, mDNS/SSDP queries; no port scans).

## Architecture (single Cargo workspace, repo is empty)
```
crates/
  core/        data model, SQLite store (rusqlite), risk engine
  collect/     collectors: arp, sweep, mdns, ssdp, flows, kaspersky (feature-gated)
  intel/       OUI db, randomized-MAC detection, TI adapters (cached)
  cli/         `relayscan` binary: subcommands + ratatui TUI
data/oui.csv   IEEE OUI snapshot (downloaded by a script, gitignored)
```

### Data model (`core`), keeping status, risk and confidence separate as ref.txt §1 says
- `device { id, mac, mac_randomized: bool, vendor, hostname, mdns_name, device_type, ips[], first_seen, last_seen, connection_status (Online|Offline), acknowledged: bool, trusted: bool }`
- `ip_binding_history { mac, ip, seen_at }`, used to detect MAC↔IP changes and gateway-MAC changes
- `flow { ts, pid, process, src_ip, src_port, dst_ip, dst_port, proto, dst_mac: Option }`. `dst_mac` is always null when the peer is off-link (ref.txt §4).
- `intel_hit { indicator, source, verdict, confidence, fetched_at }`, with a TTL cache
- `assessment { device_id, score 0-100, level (Green|Yellow|Orange|Red|Gray), confidence, reasons[] }`

### Collectors (`collect`)
1. **ARP/NDP**: parse `arp -an` and `ndp -an`. Use `sysctl` route dump later if needed. This is P0 and passive.
2. **Light active**:
   - Ping sweep (ICMP via `surge-ping`, or a UDP connect to port 9) over the `en0` subnet, rate-limited, only to fill the ARP cache.
   - mDNS browse (`mdns-sd` crate: `_services._dns-sd._udp`, `_airplay`, `_googlecast`, …) for names and types.
   - SSDP M-SEARCH for TVs and speakers, such as LGwebOSTV and Mu-so Qb.
3. **Hostname**: reverse DNS (PTR) via the gateway, plus NetBIOS name later.
4. **Flows (this Mac only)**: `nettop -L 1 -P -x` or `lsof -i -n -P`, parsed to get process, src, dst and port. This is the macOS stand-in for Sysmon EID 3.
5. **Kaspersky adapter (P5, `--features kaspersky`)**: read-only. Open the SQLite files with `?mode=ro`, copying first to a temp dir to include the WAL. Only after you run the spike below.

### Enrichment (`intel`)
- Do the OUI lookup from the IEEE CSV.
- Detect randomized MACs with `(first_octet & 0x02) != 0`.
- Infer device type from rules over vendor, mDNS service, hostname pattern (`Android_*`, `*-iPad*`, `DCS-*` means D-Link camera) and SSDP server string.
- TI adapters behind a trait `IntelSource`: AbuseIPDB, ThreatFox, GreyNoise community, OTX, VirusTotal. API keys come from env vars; skip a source when its key is missing. Do lookups only for **public** dst IPs from flows, and never send RFC1918 addresses or MACs out.

### Risk engine (`core::risk`), using the ref.txt §6 weights and clamped to 0..100
| Signal | Δ |
|---|---|
| dst IP hits a high-confidence malicious IOC | +100 |
| MAC→IP binding changed abnormally | +35 |
| gateway MAC changed (possible ARP spoof) | +45 |
| IP has multi-source abuse reports | +40 |
| periodic beaconing (low jitter in inter-arrival times) | +35 |
| deviates from baseline (new dst ASN or port) | +20 |
| unusually large egress | +25 |
| known trusted device that matches its baseline | −15 |

Map scores to levels: 0–19 Green, 20–49 Yellow, 50–79 Orange, ≥80 or any IOC hit Red. Use **Gray** when confidence is low, meaning no flows and no identity (for example a randomized MAC with no name). Weights go in a TOML config so they can be tuned without code changes, since they are not calibrated against ground truth. Each assessment stores the human-readable `reasons[]`.

### CLI / TUI (`cli`, using clap + ratatui)
- `relayscan discover [--active]`: one discovery pass, written to the store.
- `relayscan watch`: a loop that does discovery plus flows every N seconds, and raises a "NEW DEVICE" event for each unseen MAC, as Kaspersky does.
- `relayscan devices [--json]`, `relayscan flows`, `relayscan assess`.
- `relayscan tui`: device list on the left and a detail pane on the right, like the Kaspersky layout:
  - each list row shows two indicators, a status dot (green or gray) and a risk badge (G/Y/O/R/Gray) with a NEW flag;
  - the detail pane shows Last seen, IP, MAC (+ randomized), vendor, type, score, reasons and recent flows.
- `relayscan trust <mac>` / `ack <mac>`.
- `relayscan compare --kaspersky <export.csv>`: benchmark against a manual list of Kaspersky devices (name, IP, MAC typed from the UI) to report recall of our discovery.

## Phases
1. **P0 Discovery**: workspace, store, ARP/NDP, sweep, mDNS/SSDP, OUI and randomized-MAC handling, `discover` and `devices`. Goal: reproduce the Kaspersky Smart Home Monitor list.
2. **P1 Flows**: nettop/lsof collector, `flows`.
3. **P2 TI**: `IntelSource` trait, 2 adapters (ThreatFox, keyless; AbuseIPDB), SQLite cache.
4. **P3 Baseline and risk**: per-device baseline, beaconing detector, risk engine, `assess`.
5. **P4 TUI** with ratatui.
6. **P5 Kaspersky adapter**, after the spike.
7. (Later) MCP server and Flutter front end, or merging into `rp_app`. Off-host visibility needs a Pi plus Zeek at the gateway or a mirror port, as ref.txt notes.

### Kaspersky spike (you run it, read-only)
Run this in your own terminal:
```
D="/Library/Application Support/Kaspersky Lab/KAV/Data"
mkdir -p /tmp/kdb && cp "$D"/reports.db* "$D"/detects.db* /tmp/kdb/
ls -la "$D/nhdp"
sqlite3 /tmp/kdb/reports.db .schema
```
Then check whether the Smart Home Monitor devices (IP/MAC/name) appear anywhere readable. If they do not, the adapter only imports detection and block events, and device benchmarking uses the manual `compare` CSV. Do not disable Kaspersky Self-Defense.

## Execution workflow (user directive)
- Run autonomously and do not pause for confirmation between tasks.
- Branch off `main` first (`feat/relayscan-mvp`). Add `.ignore/` and `data/oui.csv` to `.gitignore`.
- **Commit after each finished task/todo**: a small, conventional message, with `cargo fmt`, `cargo clippy` and `cargo test` passing before every commit.
- **At the end of each phase (P0…P5)**, check alignment against this plan:
  - re-read this file;
  - diff the delivered work against the phase goal and the data model/CLI spec;
  - run that phase's verification;
  - note any deviations in `docs/PROGRESS.md` and commit before starting the next phase.
- Save the workflow preference to memory so later sessions follow it.

## Verification
- `cargo test`:
  - parsers use fixture outputs of `arp -an`, `ndp -an`, `nettop`, `lsof`;
  - randomized-MAC tests cover `1a:9d:d1:46:63:73` → true and `bc:d0:74:1e:5b:f1` → false;
  - risk-engine table tests cover each signal, clamping, Gray on low confidence, and Red on an IOC.
- Live check: `cargo run -p cli -- discover --active` on en0. Confirm that Android_OUJZGW45 `172.16.200.112 / 1a:9d:d1:46:63:73` and the unknown device `172.16.200.41 / 5a:26:5d:31:3f:18` from the screenshots appear, flagged as randomized. Also confirm the gateway shows as Fortinet.
- `relayscan compare` against a hand-made CSV of the Kaspersky list, targeting ≥ 90% recall.
- TI: test with a known ThreatFox IOC IP injected as a synthetic flow, and expect Red with reason text.
