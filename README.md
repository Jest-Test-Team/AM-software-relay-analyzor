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
| `relayscan syslog --listen 0.0.0.0:5514` | Receives FortiGate traffic logs pushed over syslog, which rates **every** device. |
| `relayscan import fortigate <log>` / `import zeek <conn.log> [--follow]` | Imports a FortiGate log export or a Zeek conn.log. |
| `relayscan fortigate poll --host https://<gw>` | FortiGate REST API: live sessions + DHCP hostnames (`FORTIGATE_API_TOKEN`). |
| `relayscan ack/trust <mac>` | Clear the NEW badge, or mark a device as known-good. |
| `relayscan compare --kaspersky list.csv` | Recall against a hand-made `name,ip,mac` list taken from Kaspersky. |
| `relayscan kaspersky probe/import <copy.db>` | Optional, needs `--features kaspersky`. Read-only spike/import on *copies* of Kaspersky DBs. |

Optional keyed threat intel (only **public** IPs are ever sent):
- `THREATFOX_AUTH_KEY`
- `ABUSEIPDB_API_KEY`

Language: `--lang zh-TW` (or `RELAYSCAN_LANG=zh-TW`, or a `zh_TW` locale) switches every screen to 繁體中文. In the TUI, `L` toggles the language.

Limits:
- On its own, relayscan only sees this host's flows. Other devices are **Gray** (unrated, not idle) until a network sensor reports their traffic. See **[docs/TRAFFIC-SOURCES.md](docs/TRAFFIC-SOURCES.md)** for the FortiGate syslog/export/API and Zeek setup.
- MAC addresses cannot be seen across a router, so `dst_mac` is set only for on-link peers.

## 繁體中文說明

relayscan 是與廠商無關的區網裝置探索與風險評級工具（綠／黃／橙／紅／灰）。

- `relayscan --lang zh-TW tui`：互動介面（按 `L` 切換中英文）。左側裝置清單顯示「▲連線中 ●已中斷 ✕其他」連線數；右側顯示分數、信心度構成、下一步與帶時間戳的最近連線。
- `relayscan --lang zh-TW assess --explain`：每台裝置的評分原因、信心度與建議動作。
- 要評估 **其他裝置**，必須匯入看得到它們流量的來源（FortiGate syslog／日誌匯出／REST API，或鏡像埠上的 Zeek）。設定步驟見 [docs/TRAFFIC-SOURCES.md](docs/TRAFFIC-SOURCES.md)。
