#!/usr/bin/env bash
# Fetch the OSV npm snapshot and write the pin file (plan section 5.2).
#
# Usage: scripts/download-osv.sh <target-dir>
#
# The pin is sha256 over the sorted "name:filesha256" lines, sorted in byte
# order (LC_ALL=C). The TypeScript loader computes the same pin (UTF-8 byte
# comparison) so script and analyzer always agree.
set -euo pipefail

TARGET="${1:?usage: download-osv.sh <target-dir>}"
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
PINDIR="$(mktemp -d)"
trap 'rm -rf "$WORK" "$PINDIR"' EXIT
(
  cd "$TARGET"
  # One "name:filesha256" line per record file, byte-order sorted.
  find . -type f -print0 | LC_ALL=C sort -z | while IFS= read -r -d '' f; do
    rel="${f#./}"
    sum="$(sha256sum "$f" | cut -d' ' -f1)"
    printf '%s:%s\n' "$rel" "$sum"
  done
) | LC_ALL=C sort > "$PINDIR/lines"
PIN="$(sha256sum "$PINDIR/lines" | cut -d' ' -f1)"
printf '%s\n' "$PIN" > "${TARGET}.pin"
echo "pin: ${PIN}"
echo "wrote ${TARGET}.pin"
