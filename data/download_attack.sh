#!/usr/bin/env bash
# Downloads the MITRE ATT&CK Enterprise STIX bundle for Sentinel RAG.
# Source: https://github.com/mitre/cti (official, public domain)

set -euo pipefail

DATA_DIR="$(dirname "$0")/attack_stix"
mkdir -p "$DATA_DIR"

FILE="enterprise-attack.json"
URL="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

if [ -f "$DATA_DIR/$FILE" ]; then
  echo "✅  $FILE already exists, skipping download."
  exit 0
fi

echo "⬇️   Downloading MITRE ATT&CK Enterprise STIX bundle (~12 MB)..."
curl -L --retry 3 --progress-bar "$URL" -o "$DATA_DIR/$FILE"

echo "✅  Saved to $DATA_DIR/$FILE"
echo "    Size: $(du -sh "$DATA_DIR/$FILE" | cut -f1)"
