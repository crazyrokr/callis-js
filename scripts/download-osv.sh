#!/usr/bin/env bash
# Fetch the OSV npm snapshot and write the pin file (plan section 5.2).
#
# Usage: scripts/download-osv.sh <target-dir>
#
# The pin algorithm lives in scripts/compute-pin.sh (single source of
# truth, parity-tested against the TypeScript loader).
set -euo pipefail

TARGET="${1:?usage: download-osv.sh <target-dir>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
URL="https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "downloading ${URL}"
curl -fsSL --retry 3 -o "${WORK}/all.zip" "$URL"
echo "unzipping into ${TARGET}"
mkdir -p "$TARGET"
# Reject path traversal in zip entries before extracting.
while IFS= read -r entry; do
  case "$entry" in
    ../*|*/../*|/*) echo "unsafe zip entry: $entry" >&2; exit 2 ;;
  esac
done < <(unzip -Z1 "${WORK}/all.zip")
unzip -q -o "${WORK}/all.zip" -d "$TARGET"

echo "computing pin"
PIN="$(bun "$SCRIPT_DIR/compute-pin.sh" "$TARGET" 2>/dev/null || bash "$SCRIPT_DIR/compute-pin.sh" "$TARGET")"
printf '%s\n' "$PIN" > "${TARGET}.pin"
echo "pin: ${PIN}"
echo "wrote ${TARGET}.pin"
