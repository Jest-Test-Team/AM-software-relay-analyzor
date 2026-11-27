#!/usr/bin/env bash
# Download keyless offline blocklists used by `relayscan intel`.
# ThreatFox / AbuseIPDB are queried live instead (THREATFOX_AUTH_KEY, ABUSEIPDB_API_KEY).
set -euo pipefail
dir="$(dirname "$0")/../data/feeds"
mkdir -p "$dir"
fetch() { curl -fsSL --retry 3 -A "relayscan/0.1" -o "$dir/$1.tmp" "$2" && mv "$dir/$1.tmp" "$dir/$1" && echo "$1: $(grep -cvE '^[#;]|^$' "$dir/$1") entries"; }
fetch feodo.txt https://feodotracker.abuse.ch/downloads/ipblocklist.txt
fetch spamhaus-drop.txt https://www.spamhaus.org/drop/drop.txt
