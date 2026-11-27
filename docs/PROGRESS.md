# Progress

Plan: [PLAN.md](PLAN.md)

| Phase | Status | Notes |
|---|---|---|
| P0 Discovery | ✅ done | 8/8 recall vs Kaspersky Smart Home Monitor list |
| P1 Flows | ✅ done | nettop collector, `flows`, `watch` |
| P2 Threat intel | ✅ done | offline Feodo + Spamhaus DROP; keyed ThreatFox + AbuseIPDB |
| P3 Baseline & risk | todo | |
| P4 TUI | todo | |
| P5 Kaspersky adapter | blocked on user spike | |

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
