#!/usr/bin/env bash
# Download the IEEE MA-L (OUI) registry used for MAC vendor lookup.
set -euo pipefail
dest="$(dirname "$0")/../data/oui.csv"
curl -fsSL --retry 3 -A "relayscan/0.1" -o "$dest.tmp" https://standards-oui.ieee.org/oui/oui.csv
mv "$dest.tmp" "$dest"
echo "wrote $(wc -l < "$dest") lines to $dest"
