# relayscan

Vendor-neutral LAN device discovery and rule-based risk rating (Green / Yellow / Orange / Red / Gray) for macOS. It was built to reproduce, and then go beyond, Kaspersky Plus **Smart Home Monitor**, which is used only as a benchmark. See [docs/PLAN.md](docs/PLAN.md) and [docs/PROGRESS.md](docs/PROGRESS.md).

```
scripts/fetch-oui.sh        # IEEE OUI vendor table   → data/oui.csv
scripts/fetch-feeds.sh      # Feodo C2 + Spamhaus DROP → data/feeds/
cargo build --release
```

| Command | What it does |
|---|---|
| `relayscan discover [--active]` | Reads ARP/NDP. `--active` adds a UDP ARP-refresh sweep of your own subnet (no port scan), plus mDNS and SSDP. |
| `relayscan devices [--all] [--json]` | Device table. ● online / ○ offline, N = new, T = trusted. |
| `relayscan flows [--remote]` | This host's connections per process and destination (`nettop`). |
| `relayscan intel [--ip X] [--offline]` | Checks flow destinations against threat intel. |
| `relayscan assess [--config risk.toml]` | Score, level, confidence and reasons per device. |
| `relayscan watch` | Loop: passive discovery and flow snapshots, with an active pass every N iterations. |
| `relayscan tui` | Two-pane interactive view (pairs with `watch`). |
| `relayscan ack/trust <mac>` | Clear the NEW badge, or mark a device as known-good. |
| `relayscan compare --kaspersky list.csv` | Recall against a hand-made `name,ip,mac` list taken from Kaspersky. |
| `relayscan kaspersky probe/import <copy.db>` | Optional, needs `--features kaspersky`. Read-only spike/import on *copies* of Kaspersky DBs. |

Optional keyed threat intel (only **public** IPs are ever sent):
- `THREATFOX_AUTH_KEY`
- `ABUSEIPDB_API_KEY`

Limits:
- Flows are visible for this host only. Other devices are rated on L2 signals, and are **Gray** when there is not enough data.
- MAC addresses cannot be seen across a router, so `dst_mac` is set only for on-link peers.
