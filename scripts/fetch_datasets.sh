#!/usr/bin/env bash
# Downloads the large Mordor datasets into src/data/mordor (git-ignored).
# Safe to re-run: anything already present is skipped.
set -euo pipefail
cd "$(dirname "$0")/.."

DEST="src/data/mordor"
BASE="https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets"
mkdir -p "$DEST"

fetch() {
  local url="$1" marker="$2" tmp
  if compgen -G "$DEST/$marker" > /dev/null; then
    echo "already present: $marker"
    return
  fi
  tmp="$(mktemp -d)"
  echo "downloading $url"
  curl -fL --retry 3 -o "$tmp/data.zip" "$url"
  python3 -m zipfile -e "$tmp/data.zip" "$DEST"
  rm -rf "$tmp"
}

fetch "$BASE/compound/apt29/day1/apt29_evals_day1_manual.zip" "apt29_evals_day1_manual_*.json"
fetch "$BASE/atomic/windows/defense_evasion/host/cmd_wevtutil_modify_security_eventlog_path.zip" "cmd_wevtutil_modify_security_eventlog_path*.json"

echo "Datasets ready in $DEST (git-ignored)."
