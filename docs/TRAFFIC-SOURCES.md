# Getting other devices' traffic (取得其他裝置的流量)

**Why this is needed.** "Online" means a device answered ARP on the LAN. Its connections go straight from the device to the FortiGate. On a switched or Wi-Fi LAN this Mac only receives its own traffic plus broadcast/multicast (ARP, mDNS, SSDP), so `nettop` can rate **this Mac only**. Every other device stays **Gray: unrated, not idle** until something that *does* see its traffic reports it. That means the gateway (FortiGate) or a mirror port (Zeek).

**為什麼需要這一步。** 「在線」只代表裝置回應了區網 ARP。它的連線直接送往 FortiGate。在交換式或 Wi-Fi 區網中，這台 Mac 只會收到自己的流量和廣播／多播（ARP、mDNS、SSDP），所以 `nettop` **只能評估這台 Mac**。其他裝置會維持 **灰色：未評級（並非閒置）**，直到有「看得到它流量」的來源回報為止，也就是閘道（FortiGate）或鏡像埠（Zeek）。

Each source below feeds the same store. Run `relayscan assess --explain` or `relayscan tui` afterwards: those devices then get scores, confidence, connection counts and next steps.
以下任一來源都會寫入同一個資料庫。之後執行 `relayscan assess --explain` 或 `relayscan tui`，這些裝置就會有分數、信心度、連線數與下一步建議。

| Source / 來源 | Command / 指令 | Live? / 即時 | Gives / 提供 |
|---|---|---|---|
| FortiGate syslog push | `relayscan syslog --listen 0.0.0.0:5514` | yes / 是 | every logged session, srcmac, srcname |
| FortiGate log export | `relayscan import fortigate traffic.log` | no / 否 | same as above, past period |
| FortiGate REST API | `relayscan fortigate poll --host https://172.16.200.254 --insecure` | every 60 s | live sessions + DHCP hostnames |
| Zeek on mirror port | `relayscan import zeek conn.log --follow` | yes / 是 | all mirrored flows incl. LAN↔LAN |

Recommended / 建議：**syslog push** (live, no credentials stored). Add **REST poll** for DHCP hostnames, which names the "Unknown Device" rows.
**syslog 推送**（即時、不需存放帳密），再加上 **REST 輪詢** 取得 DHCP 主機名稱，讓「未知裝置」有名字。

---

## 1. FortiGate syslog push (推送 syslog)

On the FortiGate CLI (replace `172.16.200.2` with this Mac's IP):
在 FortiGate CLI 輸入（把 `172.16.200.2` 換成這台 Mac 的 IP）：

```
config log syslogd setting
    set status enable
    set server "172.16.200.2"
    set port 5514
    set mode udp
    set format default
end
config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic disable
    set multicast-traffic disable
    set sniffer-traffic disable
end
```

Each firewall policy must log its sessions. In the GUI, open Policy & Objects → Firewall Policy → (policy) → **Log Allowed Traffic: All Sessions**. In the CLI, set `set logtraffic all` on the policy. Without this, only denied/UTM events are logged.
每條防火牆政策都要記錄流量：GUI 在 Policy & Objects → Firewall Policy →（政策）→ **Log Allowed Traffic: All Sessions**；CLI 在政策中 `set logtraffic all`。否則只會記錄被拒絕／UTM 事件。

Then on this Mac / 然後在這台 Mac：

```
relayscan syslog --listen 0.0.0.0:5514     # leave running (保持執行)
relayscan tui                              # in another terminal (另開終端機)
```

macOS may ask to allow incoming connections for `relayscan`: allow it. Port 5514 needs no root.
macOS 可能詢問是否允許 `relayscan` 接受連入連線，請允許。5514 埠不需要 root。

## 2. FortiGate log export (匯出日誌檔)

GUI: **Log & Report → Forward Traffic** → set the time range → **Download** (raw / `.log`). FortiAnalyzer: Log View → Download, raw format. Unzip `.gz` first.
GUI：**Log & Report → Forward Traffic** → 選時間範圍 → **下載**（原始 `.log`）。FortiAnalyzer：Log View → Download（raw）。`.gz` 請先解壓。

```
relayscan import fortigate ~/Downloads/traffic-*.log
```

## 3. FortiGate REST API (poll sessions + DHCP / 輪詢連線與 DHCP)

1. Create a read-only profile under System → Admin Profiles, with read on *System* and *Log & Report*.
   System → Admin Profiles 建立唯讀設定檔（*System*、*Log & Report* 讀取）。
2. Create the API user under System → Administrators → Create New → **REST API Admin**. Use the read-only profile and set **Trusted Hosts** = this Mac's IP/32. Copy the token.
   System → Administrators → Create New → **REST API Admin**，套用唯讀設定檔，**Trusted Hosts** 設為這台 Mac 的 IP/32，複製 token。
3. Run the poller / 執行：

```
export FORTIGATE_API_TOKEN='…'        # env only, never written to disk by relayscan
relayscan fortigate poll --host https://172.16.200.254 --insecure --interval 60
```

`--insecure` accepts the FortiGate's self-signed certificate. Leave it off if the admin GUI has a trusted certificate. The token is passed to `curl` on stdin, so it never appears in the process list. These calls only go to your own gateway.
`--insecure` 接受 FortiGate 自簽憑證（若管理介面已有受信任憑證則可省略）。token 透過 stdin 傳給 `curl`，不會出現在程序清單中；這些呼叫只連到你自己的閘道。

## 4. Zeek on a mirror port (鏡像埠 + Zeek)

Use this when you want LAN↔LAN traffic too (the FortiGate does not see traffic between two devices on the same switch).
若也想看到區網內裝置之間的流量（同一台交換器上的裝置互連，FortiGate 看不到），請用這個方式。

1. Configure a SPAN/mirror port on the switch, copying the uplink to the FortiGate. Plug a Raspberry Pi's second NIC into it.
   在交換器設定 SPAN／鏡像埠（鏡像通往 FortiGate 的上行埠），把 Raspberry Pi 的第二張網卡接上。
2. On the Pi, install Zeek and log MACs. Add to `local.zeek`:
   在 Pi 上安裝 Zeek 並記錄 MAC，`local.zeek` 加入：
   ```
   @load policy/protocols/conn/mac-logging
   ```
   Then run `zeek -i eth1 local` (or `zeekctl deploy`).
3. Read the conn.log. Either copy it to this Mac (`rsync`, or a shared folder) and run:
   讀取 conn.log：複製到這台 Mac（rsync／共享資料夾），然後：
   ```
   relayscan import zeek /path/to/conn.log --follow
   ```
   Or run relayscan on the Pi itself (Linux build). TSV and JSON logs both work.
   或直接在 Pi 上執行 relayscan（Linux 版）。TSV 與 JSON 格式皆支援。

---

## What gets analysed (分析內容)

Flows are attributed to a device by sender MAC (FortiGate `srcmac`, Zeek `orig_l2_addr`). When the sender MAC is missing, the source IP is matched to the device that held that IP at the time.
連線依送出端 MAC 歸屬到裝置（FortiGate `srcmac`、Zeek `orig_l2_addr`），沒有 MAC 時則以當時持有該 IP 的裝置判定。

| Signal / 訊號 | Points / 分數 | Meaning / 意義 |
|---|---|---|
| IOC hit / 命中 IOC | +100 → Red | destination on Feodo/DROP/ThreatFox (public IPs only) |
| Gateway takeover / 閘道冒用 | +45 | ARP spoofing sign |
| Multi-source reports / 多來源回報 | +40 | AbuseIPDB etc. |
| IP churn / IP 頻繁變動 | +35 | MAC used ≥3 IPs in 24 h |
| Beaconing / 週期連線 | +35 | regular-interval connections (possible C2) |
| **LAN scan / 區網掃描** | +30 | ≥20 LAN hosts or ≥50 host:port pairs in the window |
| Large egress / 大量上傳 | +25 | ≥500 MB off-link in the window |
| Baseline deviation / 偏離基線 | +20 | mostly new destinations vs ≥24 h baseline |
| **Denied by firewall / 被防火牆阻擋** | +15 | ≥5 FortiGate `deny` in the window |
| **Connection failures / 連線失敗** | +10 | ≥10 and ≥30 % unanswered/reset |
| Trusted + baseline / 受信任且符合基線 | −15 | |

Levels: 0–19 Green, 20–49 Yellow, 50–79 Orange, ≥80 or any IOC Red. **Gray** means no warning signal and confidence < 50 %.
等級：0–19 綠、20–49 黃、50–79 橙、≥80 或命中 IOC 為紅；沒有警示訊號且信心度 < 50% 為 **灰**。

**Connection counts / 連線數** (last 60 min / 最近 60 分鐘):
- **▲ connecting / 連線中**: session still running.
- **● disconnected / 已中斷**: closed normally. The time shown is the last one.
- **✕ other / 其他**: covers three cases:
  - *failed / 失敗*: no answer, reset or timeout;
  - *denied / 被阻擋*: blocked by the firewall;
  - *stale / 逾時未更新*: reported as running, but with no update for 15 min.

Weights are tunable in `docs/risk.example.toml` (`--config`). / 權重可在 `docs/risk.example.toml` 調整（`--config`）。

**Privacy / 隱私**: only *public* destination IPs are ever sent to threat-intel APIs. LAN IPs, MACs and hostnames stay local.
只有 *公網* 目的地 IP 會送往威脅情資 API；區網 IP、MAC、主機名稱都只留在本機。
