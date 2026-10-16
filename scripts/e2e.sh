#!/usr/bin/env bash
# Golden-demo end-to-end gate (plan sections 9/10, M6).
#
# For every example/ demo: run the (compiled or interpreted) callis binary,
# collect the JSON report, and diff the verdicts against
# expected-reachable.txt. The demo OSV directories are fixture snapshots
# (small, hand-pinned) so the e2e gate does not need the 208 MB snapshot.
set -euo pipefail
cd "$(dirname "$0")/.."

# Host uname -> canonical dist name (the names scripts/build.ts emits).
host_target() {
  local sys machine
  sys="$(uname -s | tr '[:upper:]' '[:lower:]')"
  machine="$(uname -m)"
  case "${sys}/${machine}" in
    linux/x86_64 | linux/amd64) echo "linux-x64" ;;
    linux/aarch64 | linux/arm64) echo "linux-arm64" ;;
    darwin/x86_64 | darwin/amd64) echo "darwin-x64" ;;
    darwin/arm64 | darwin/aarch64) echo "darwin-arm64" ;;
    msys* | cygwin* | windows*) echo "windows-x64" ;;
    *) echo "unknown" ;;
  esac
}

BIN="${1:-dist/callis-$(host_target)}"
if [[ ! -x "$BIN" ]]; then
  echo "e2e: using interpreted core (bun run) because $BIN is absent"
  RUN=(bun run packages/cli/src/main.ts)
else
  RUN=("$BIN")
fi

status=0
for demo in examples/vulnerable-demo-*/; do
  demo="${demo%/}"
  name="$(basename "$demo")"
  echo "== ${name}"
  # Materialize the installed tree from the committed fixture (install/ is
  # the committed name; node_modules/ is gitignored package-manager output).
  # cp -a preserves the .pnpm layout and the symlinks inside it.
  if [[ -d "$demo/install" ]]; then
    rm -rf "$demo/node_modules"
    cp -a "$demo/install" "$demo/node_modules"
  fi
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
  # Expected exit code + verdicts + notices, all from the shared table in
  # scripts/golden-expected.ts (the in-suite test e2e.demos.test.ts checks
  # the interpreted core against the same table).
  if ! bun scripts/check-expected.ts "$demo/out/callis-report.json" "$demo/out/console.log" "$name" "$code"; then
    sed 's/^/  | /' "$demo/out/console.log"
    status=1
  fi
done
exit "$status"
