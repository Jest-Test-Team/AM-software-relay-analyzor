# Progress

Plan: [PLAN.md](PLAN.md)

| Phase | Status | Notes |
|---|---|---|
| P0 Discovery | ✅ done | 8/8 recall vs Kaspersky Smart Home Monitor list |
| P1 Flows | ✅ done | nettop collector, `flows`, `watch` |
| P2 Threat intel | ✅ done | offline Feodo + Spamhaus DROP; keyed ThreatFox + AbuseIPDB |
| P3 Baseline & risk | ✅ done | `assess`; synthetic IOC test → Red |
| P4 TUI | ✅ done | `relayscan tui` |
| P5 Kaspersky adapter | 🟡 tooling done; needs a user-run spike | `--features kaspersky` |

## P0 — alignment check (2026-11-27)

Delivered vs plan:

| Plan item | Status |
|---|---|
| Cargo workspace (`core`, `collect`, `intel`, `cli`) | ✅ Package names `relay-core` / `relay-collect` / `relay-intel` / `relayscan`. A package called `core` would clash with Rust's built-in `core` crate. |
| SQLite store, `device` + `ip_binding` model, status/risk/confidence separated | ✅ `flow` and `event` tables are created as well. `intel_hit` and `assessment` come in P2/P3. |
| ARP/NDP passive collector | ✅ NDP `S` (stale) entries are skipped. |
| Light active: sweep, mDNS, SSDP | ✅ The sweep is UDP/9, one datagram per host, rate-limited, and refuses subnets larger than /22. There is no port scanning. |
| Reverse DNS hostnames | ✅ Implemented, but it returns nothing on this LAN: the resolver gives NXDOMAIN for PTR. **mDNS is the real name source**: Android Nearby (`_FC9F5ED42C8A._tcp`, `_nearbypresence._tcp`), AirPlay and so on. |
| OUI lookup + randomized-MAC flag | ✅ `scripts/fetch-oui.sh`. `data/oui.csv` is gitignored. |
| `discover [--active]`, `devices [--json]`, `ack`, `trust` | ✅ |
| `compare --kaspersky` | ✅ Pulled forward from the CLI spec, since it is P0's verification. |

Live verification (`discover --active` on en0, 172.16.200.0/24):
- Took about 13 s and found 101 devices online. 253 sweep packets were sent and 0 failed.
- `172.16.200.112 / 1a:9d:d1:46:63:73` and `172.16.200.41 / 5a:26:5d:31:3f:18` were found, both flagged as randomized.
- The gateway resolves as `Fortinet, Inc.` with type router.
- `compare` against the 8 devices from the screenshots matched 8/8. The names and types agree for 7.

Deviations / findings:
1. **The gateway is `172.16.200.254`, not `.1`.** The plan's context section had this wrong. `.1` is an Apple device. Nothing is hard-coded: the gateway comes from `route -n get default`.
2. **Android_OUJZGW45 has no name.** The names come from mDNS, and Android only advertises Nearby services intermittently, so this device did not advertise during the 4 s listen window. Kaspersky may also use DHCP option 12. Longer or repeated `watch` active passes should help. Passive DHCP sniffing needs pcap and root, so it is backlog item B1.
3. Test fixtures are synthetic (192.168.50.0/24) in the real macOS output format. Real LAN MACs are not committed.

Backlog:
- B1: passive DHCP/LLMNR/NetBIOS name capture (pcap, optional root).

## P1 — alignment check (2026-11-27)

| Plan item | Status |
|---|---|
| Flow collector: nettop or lsof → process, src, dst, port | ✅ Uses `nettop -L 1 -n -x -J state,bytes_in,bytes_out`. It covers every process with byte counters and needs no root. lsof is not needed. |
| `flow` model with `dst_mac = None` off-link | ✅ Has a unit test proving that the gateway MAC is never attached to a remote host. |
| `flows` command | ✅ Aggregates per process and destination. `--remote`, `--json` and `--since` are supported. |
| `watch` (planned in the CLI spec) | ✅ Passive pass every `--interval`, active pass every `--active-every`. Each pass prints NEW DEVICE lines. |

Design change: a flow is now **one row per connection** (5-tuple + pid), with `first_seen`/`last_seen` and counters that only increase. The plan had one row per snapshot. This was needed so P3 beaconing can use the start times of distinct connections. A `user_version` guard migrates the old schema.

Limits:
- Flows are visible **only for this host**, as the plan expects.
- nettop truncates process names to about 15 characters.
- Byte counters are cumulative per connection, so P3 "large egress" must look at deltas or at per-connection totals.

## P2 — alignment check (2026-11-27)

| Plan item | Status |
|---|---|
| `IntelSource` trait | ✅ `relay_intel::ti`. |
| 2 adapters: ThreatFox ("keyless") + AbuseIPDB | ⚠️ Both are implemented, but **ThreatFox is no longer keyless**. Since 21 Oct 2026 abuse.ch requires an Auth-Key, and the old exports now return 410 Gone. It is enabled by setting `THREATFOX_AUTH_KEY`. AbuseIPDB is enabled by setting `ABUSEIPDB_API_KEY`. |
| SQLite cache | ✅ `intel_hit` table with a 24 h TTL. Negative answers are cached too, so a host is not queried again within the TTL. |
| Only public dst IPs leave the host; never RFC 1918 or MACs | ✅ `is_public()` guard plus a unit test with a spy source. `--offline` turns off every remote source. |

Additions beyond the plan:
- **Offline blocklists** (Feodo Tracker C2 and Spamhaus DROP) via `scripts/fetch-feeds.sh`. These still work without keys, so the tool can flag IOCs with no account at all.
- AbuseIPDB results are recorded as *reputation* (`malicious = false`), not as an IOC. In P3 they feed the "+40 multi-source reports" signal, never the "+100 IOC" signal.

Verification:
- `intel --ip 162.243.103.246 --ip 1.10.20.5 --ip 192.168.1.1` returns 2 IOC hits, from Feodo and DROP. The private IP is skipped for remote sources.
- Checking the 68 live public destinations returned 0 hits.

Not done (as planned): GreyNoise, OTX, VirusTotal and RIPEstat ASN. Backlog B3: ASN lookup, which the P3 "new destination ASN" baseline signal needs. Until then the baseline uses /24 (v4) and /48 (v6) prefixes as a stand-in for ASN.

## P3 — alignment check (2026-11-27)

| Plan item | Status |
|---|---|
| Risk engine in `core::risk` with the ref.txt §6 weights, clamped to 0..100 | ✅ All 8 signals are implemented, with one table test per signal plus clamping and config-override tests. |
| Levels: 0–19 Green, 20–49 Yellow, 50–79 Orange, ≥80 or any IOC Red, low confidence Gray | ✅ |
| Weights in TOML | ✅ `--config`, see `docs/risk.example.toml`. |
| Human-readable `reasons[]` stored per assessment | ✅ `assessment` table holds the latest result per device. Level changes are written to `event`. |
| Per-device baseline | ⚠️ Flows exist for **this host only**, so the baseline and beaconing apply to the self device. Other devices get L2 signals only: IP churn and gateway takeover. |
| Beaconing detector | ✅ Coefficient of variation of the gaps between connection start times, per (process, dst, port), at least 6 connections, interval 10 s–1 h. |
| `assess` | ✅ `--window`, `--baseline-days`, `--offline`, `--json`, `--all`. |

Design decisions made during P3:
- **Gateway takeover** goes to the *new* MAC that claims the gateway IP (the likely spoofer). The original gateway MAC is not penalised.
- **Trusted bonus (−15)** applies only when no positive signal fired, so it can never hide a real finding.
- **Baseline buckets** are /24 (v4) and /48 (v6) for now, since ASN data is not available yet (backlog B3).
- **Beaconing granularity:** `first_seen` comes from snapshots, so its resolution equals the `watch --interval` (default 30 s). Beacons faster than about 2× the interval cannot be resolved.

Verification:
- Unit test: a synthetic flow from this host to Feodo C2 `162.243.103.246` makes the self device **Red**, with "(feodo: botnet_cc)" in the reason. A second MAC that claims the gateway IP scores **45 (Yellow)**. The original gateway gets no penalty, and the other hosts stay **Gray**.
- Live: this Mac is Green (score 0, confidence 90%) and the other 92 online devices are Gray.

## P4 — alignment check (2026-11-27)

| Plan item | Status |
|---|---|
| Device list on the left, detail pane on the right (Kaspersky layout) | ✅ |
| Each row: status dot (green/gray) and risk badge (G/Y/O/R/Gray) with a NEW flag | ✅ The badge shows the level name in its colour. A second line shows the IP and vendor. |
| Detail: Last seen, IP, MAC (+randomized), vendor, type, score, reasons, recent flows | ✅ Also shows Trusted and confidence. Flows appear only on this host's own row. |
| `ack` / `trust` from the UI | ✅ The `a` and `t` keys. |

Additions:
- `o` toggles offline devices.
- `r` runs a passive rescan (ARP/NDP plus a flow snapshot).
- Auto-reloads every `--reload` seconds, so `relayscan watch` in another terminal keeps the view live.
- Re-assessment inside the TUI always uses `offline` TI (local blocklists plus the cache). The UI loop therefore never makes network calls.

Verification:
- Unit tests use ratatui `TestBackend` to render the list and detail, and check that navigation clamps at the ends.
- Live smoke test under a pseudo-TTY (150×40) against the real store: it rendered "Devices — 93 online", MAC, Last seen, "NEW DEVICE" and "Risk: Green", and `q` exited with status 0.

## P5 — alignment check (2026-11-27)

| Plan item | Status |
|---|---|
| Read-only adapter behind `--features kaspersky` | ✅ `relayscan kaspersky probe|import <file>`. Uses SQLite `SQLITE_OPEN_READ_ONLY`. |
| "Only after the spike" | ⚠️ The permission classifier blocked Claude from reading the live Kaspersky files, which is correct. So the adapter is **schema-agnostic**: `probe` *is* the spike tool, and you run it on your own copies. |
| Do not disable Self-Defense | ✅ Documented; the tool only reads copies. |

**Spike for you to run** (copy first, so Kaspersky's live files are never opened):
```
D="/Library/Application Support/Kaspersky Lab/KAV/Data"
mkdir -p /tmp/kdb && cp "$D"/reports.db* "$D"/detects.db* "$D"/persistent_q.db* /tmp/kdb/
ls -la "$D/nhdp"                    # likely Smart Home Monitor data
cargo run --features kaspersky -- kaspersky probe /tmp/kdb/reports.db
cargo run --features kaspersky -- kaspersky import /tmp/kdb/reports.db --dry-run
```
If no table shows `mac-like > 0`, the Smart Home Monitor list is not stored in these readable DBs; it may be in root-only `data.kvdb` or in `nhdp/`. In that case keep using `compare --kaspersky` with a hand-made CSV as the benchmark, as the plan's fallback says.

Verification: a unit test builds a synthetic SQLite DB. `probe` finds 2 IPs and 2 MACs, and `import` yields 2 `Source::Kaspersky` observations with names. Version strings such as `27.1.0.5` are not mistaken for IPs.

## Summary of open backlog
- **B1** Passive DHCP option 12 / LLMNR / NetBIOS names (pcap, root). This would name devices like Android_OUJZGW45 that advertise no mDNS.
- **B3** ASN lookup (RIPEstat or a local DB), to replace the /24 and /48 baseline buckets.
- **B4** Run the Kaspersky spike above, then specialise `import` for whichever table holds devices.
- **Later (plan §7):** MCP server, Flutter UI or merging into `rp_app`, and a Pi + Zeek sensor at the gateway for traffic from other devices.

## Follow-up: score/confidence explainability (2026-11-27)

Triggered by TUI screenshots showing every device as Gray with an unexplained confidence of 0% or 30%.

- **Confidence is now an explicit breakdown** (`Assessment.evidence`):

  | Factor | Weight |
  |---|---|
  | Identity | +25 |
  | Advertised services | +5 |
  | Stable presence | +10 |
  | Traffic visible | +30 |
  | Threat-intel check | +15 |
  | Behaviour baseline | +10 |
  | Owner confirmed | +20 |

  Each factor shows ✔ or ✘ with a note saying what is known or missing.
- **`summary`** is one sentence per level. Gray on a device this Mac cannot observe now reads "Unrated, not idle…" instead of "no traffic".
- **`actions`** are next steps, generated from the fired signals (IOC → isolate and block, ARP takeover → verify the gateway MAC, …) and from what is missing:
  - identify the device via the FortiGate DHCP list;
  - get traffic visibility via FortiGate logs or a Zeek mirror port;
  - IoT hygiene;
  - ack or trust the device.
- **False-positive fix:** baseline deviation now requires the baseline to span ≥ 24 h (`baseline_min_span_hours`). Previously a 1-hour-old baseline flagged this Mac as Yellow, with "41/53 new destinations".
- **The TUI takes a nettop snapshot at startup**, so this host is rated straight away. The detail pane shows the summary, the reasons, the confidence breakdown and the next steps; J/K scroll it.
- `relayscan assess --explain [--mac …]` prints the same information in the CLI.

Why online devices show no traffic: "Online" means the device answered ARP on the LAN. Its own connections go straight to the FortiGate. On a switched or Wi-Fi network this Mac only receives its own unicast traffic plus broadcast and multicast, so other devices' flows are invisible here. Rating them needs FortiGate traffic logs (next adapter: backlog B5) or a mirror-port sensor.

## Iteration 3: timestamps, network sensors, connection counts, zh-TW (2026-11-27)

The user asked for four things:
1. timestamps on "Recent connections";
2. a way to get other devices' traffic, analyse it, and score it with next steps;
3. per-device connection counts: connecting / disconnected (last seen) / other;
4. a Traditional Chinese UI.

### Alignment check against the plan

| Plan item | Delivered | Notes |
|---|---|---|
| E: timestamps | ✔ | TUI shows last-seen `HH:MM:SS`, "since" and an outcome per connection, for **any** device with flows, tagged `[nettop/fortigate/zeek]`. `relayscan flows` has FIRST SEEN / LAST columns sorted newest first. This also fixed the J/K scroll, which was never applied. |
| A: schema v3 | ✔ | `Flow.origin/src_mac/outcome` and `ConnCounts::tally`. The v2→v3 migration keeps existing rows (tested; ran on the live DB). |
| B: sensors | ✔ | FortiGate key=value (syslog prefix, tz, eventtime s/ms/µs/ns), FortiGate REST (sessions in both 6.x and 7.x shapes, DHCP, vanished sessions → closed), Zeek conn.log in TSV and JSON. CLI: `import fortigate`, `import zeek [--follow]`, `syslog`, `fortigate poll`. Verified live: import plus UDP syslog via `nc`. |
| C: rate every device | ✔ | Attribution: nettop → self; sensor srcmac; otherwise the IP binding closest in time. New signals LanScan +30, DeniedByFirewall +15, ConnFailures +10. Evidence and next steps now name the exact `relayscan` command. FortiGate `srcname` and DHCP hostnames fill device names (backlog B1). |
| D: counts | ✔ | List row `▲active ●closed ✕other`, or `conn n/a` when not observable. Detail adds the last close time and a failed/denied/stale split. Also shown in the assess table, `--explain` and JSON. |
| F: zh-TW | ✔ | See the deviation note below. |
| G: docs | ✔ | `docs/TRAFFIC-SOURCES.md` (EN + 繁中), README, `risk.example.toml`. |

### Deviations
- **i18n mechanism:** a `tr!(lang, "en", "中文", …)` macro replaces the planned `Key` enum catalogue. Both strings sit at each call site, so a missing translation is still a compile error, with far less boilerplate.
- **FortiGate REST transport:** it uses `curl` with the token sent on stdin, not ureq. This keeps the token out of `ps` and gives `-k` for self-signed certificates without adding a TLS dependency.
- **Flow uniqueness key:** no separate key including `origin`. If FortiGate and Zeek report the same 5-tuple, the two reports merge into one row; the outcome and src_mac update, and the first origin is kept.
- **Commit granularity:** tasks C, D and F share one commit (43ab5d5) because they touch the same strings. The schema v3 and parser work were committed from the working tree by the user's own "asalc" commits (be3ff79..ab355e0), so those changes have no task-specific commit messages.
- **Still English:**
  - `--help` text from clap;
  - `intel`, `compare` and `kaspersky` output;
  - `flows` column headers.

  The user-facing TUI, `assess`, `devices`, `discover`, `import` and ack/trust output are all bilingual.

### Verification
- **Automated:** `cargo fmt`; `clippy -D warnings`, both with and without `--features relayscan/kaspersky`. 61 tests pass (collect 18, core 30, intel 6, cli 7). New tests cover:
  - parsers;
  - `ConnCounts`;
  - schema migration;
  - a sensor-fed device getting rated, and LanScan/Denied/ConnFailures firing;
  - zh-TW risk output;
  - `Lang::detect` precedence;
  - CJK width;
  - a zh-TW TUI render with counts and timestamps;
  - end-to-end `assess_all` from FortiGate lines, including IP-only attribution.
- **Live:**
  - fixture import gives rated devices in `assess --lang zh-TW`;
  - syslog over UDP was received;
  - `RELAYSCAN_LANG=zh-TW relayscan tui` on the real LAN renders Chinese labels, counts and timestamped connections.
- **Not verified:** a real FortiGate or Zeek feed. That needs gateway admin access, so the user sets it up following TRAFFIC-SOURCES.md.
