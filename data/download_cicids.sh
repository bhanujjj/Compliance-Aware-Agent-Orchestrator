#!/usr/bin/env bash
# Downloads a CICIDS2017 subset for Sentinel development.
# Full dataset: https://www.unb.ca/cic/datasets/ids-2017.html
# This downloads the Friday afternoon file from a public mirror.

set -euo pipefail

DATA_DIR="$(dirname "$0")/cicids2017"
mkdir -p "$DATA_DIR"

BASE_URL="https://intrusion-detection.distrinet-research.be/WTMC2021/Dataset"
FILE="Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

if [ -f "$DATA_DIR/$FILE" ]; then
  echo "✅  $FILE already exists, skipping download."
  exit 0
fi

echo "⬇️   Downloading $FILE (~24 MB)..."
curl -L --retry 3 --progress-bar \
  "$BASE_URL/$FILE" \
  -o "$DATA_DIR/$FILE"

echo "✅  Saved to $DATA_DIR/$FILE"
echo "    Rows: $(wc -l < "$DATA_DIR/$FILE")"
