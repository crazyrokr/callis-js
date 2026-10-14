#!/usr/bin/env bash
# Compute the OSV snapshot pin for a directory (plan section 5.2).
#
# Usage: scripts/compute-pin.sh <dir>
#
# The pin is sha256 over the "name:filesha256" lines, sorted in byte order
# (LC_ALL=C). The TypeScript implementation (packages/core/src/osv/
# checksum.ts) computes the identical pin — parity is tested in
# packages/core/test/osv.checksum.test.ts.
set -euo pipefail

TARGET="${1:?usage: compute-pin.sh <dir>}"
PINDIR="$(mktemp -d)"
trap 'rm -rf "$PINDIR"' EXIT

(
  cd "$TARGET"
  find . -type f -print0 | LC_ALL=C sort -z | while IFS= read -r -d '' f; do
    rel="${f#./}"
    sum="$(sha256sum "$f" | cut -d' ' -f1)"
    printf '%s:%s\n' "$rel" "$sum"
  done
) | LC_ALL=C sort > "$PINDIR/lines"

sha256sum "$PINDIR/lines" | cut -d' ' -f1
