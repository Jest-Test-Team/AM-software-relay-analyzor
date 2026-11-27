# Progress

Plan: [PLAN.md](PLAN.md)

| Phase | Status | Notes |
|---|---|---|
| P0 Discovery | ✅ done | 8/8 recall vs Kaspersky Smart Home Monitor list |
| P1 Flows | todo | |
| P2 Threat intel | todo | |
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
| Reverse DNS hostnames | ✅ This is the main source of names: the Fortinet resolver holds DHCP hostnames. |
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
2. **Android_OUJZGW45 has no name.** It currently has no PTR record. Kaspersky probably learns the name from DHCP option 12. Passive DHCP sniffing needs pcap and root, so it is backlog item B1.
3. Test fixtures are synthetic (192.168.50.0/24) in the real macOS output format. Real LAN MACs are not committed.

Backlog:
- B1: passive DHCP/LLMNR/NetBIOS name capture (pcap, optional root).
- B2: `watch` loop, planned for P1 next to the flow collector.
