#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || -z "${1:-}" ]]; then
  echo "Usage: $0 /path/to/macstealer [artifact-directory]" >&2
  exit 2
fi

if ! macstealer_dir=$(realpath -e "$1" 2>/dev/null); then
  echo "Error: MacStealer path does not exist: $1" >&2
  echo "Example: $0 \"$HOME/macstealer\" recording-artifacts" >&2
  exit 2
fi
if [[ ! -f "$macstealer_dir/research/macstealer.py" || \
      ! -x "$macstealer_dir/research/venv/bin/python3" || \
      ! -x "$macstealer_dir/wpa_supplicant/wpa_supplicant" ]]; then
  echo "Error: $macstealer_dir is not a built MacStealer repository." >&2
  echo "Expected research/macstealer.py, research/venv/bin/python3," >&2
  echo "and wpa_supplicant/wpa_supplicant." >&2
  exit 2
fi
artifact_dir=$(realpath -m "${2:-recording-artifacts}")
lab_dir=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$artifact_dir"

{
  date -u +'%Y-%m-%dT%H:%M:%SZ'
  uname -a
  # Some hostapd development builds return nonzero after printing -v.
  hostapd -v 2>&1 || true
  if git -C "$macstealer_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    printf 'MacStealer commit: '
    git -C "$macstealer_dir" rev-parse HEAD
  else
    echo "MacStealer commit: unavailable (directory is not a Git checkout)"
  fi
} | tee "$artifact_dir/environment.txt"

sudo mn -c >/dev/null 2>&1 || true
echo
echo "Start the screen recorder now, then press Enter."
read -r

sudo script -q -e -c \
  "python3 '$lab_dir/macstealer_lab.py' --macstealer '$macstealer_dir' --recording-sequence" \
  "$artifact_dir/terminal.typescript"

echo "Recording-side artifacts written to $artifact_dir"
