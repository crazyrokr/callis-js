#!/usr/bin/env bash
# Golden-demo end-to-end gate (plan sections 9/10, M6).
#
# For every example/ demo: run the (compiled or interpreted) callis binary,
# collect the JSON report, and diff the verdicts against
# expected-reachable.txt. The demo OSV directories are fixture snapshots
# (small, hand-pinned) so the e2e gate does not need the 208 MB snapshot.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN="${1:-dist/callis-$(uname -s)-$(uname -m)}"
if [[ ! -x "$BIN" ]]; then
  echo "e2e: using interpreted core (bun run) because $BIN is absent"
  RUN=(bun run packages/cli/src/main.ts)
else
  RUN=("$BIN")
fi

status=0
for demo in examples/vulnerable-demo-*/; do
  name="$(basename "$demo")"
  echo "== ${name}"
  mkdir -p "$demo/out"
  mapping_args=()
  [[ -f "$demo/vuln-mappings.json" ]] && mapping_args=(--mappings "$demo/vuln-mappings.json")
  # Optional per-demo extra flags (one per line), e.g. --sbom-only.
  extra_args=()
  [[ -f "$demo/extra-flags.txt" ]] && mapfile -t extra_args < <(grep -v '^\s*#' "$demo/extra-flags.txt")
  code=0
  "${RUN[@]}" \
    --project "$demo" \
    --sbom "$demo/sbom.json" \
    --osv-dir "$demo/osv" \
    "${mapping_args[@]}" \
    "${extra_args[@]}" \
    --format json \
    --output "$demo/out/callis-report" \
    --cache-dir "$demo/out/cache" \
    > "$demo/out/console.log" 2>&1 || code=$?
  # Expected exit code per demo lives in expected-exit.txt when nonzero.
  want=0
  [[ -f "$demo/expected-exit.txt" ]] && want="$(cat "$demo/expected-exit.txt")"
  if [[ "$code" -ne "$want" ]]; then
    echo "FAIL: ${name}: exit ${code} != expected ${want}"
    status=1
  fi
  if [[ -f "$demo/expected-reachable.txt" ]]; then
    bun scripts/check-expected.ts "$demo/out/callis-report.json" "$demo/expected-reachable.txt" "$name" || status=1
  fi
done
exit "$status"
