#!/usr/bin/env bun
// callis CLI entry point. The full flag set and exit-code mapping land with
// the M5 pipeline; this bootstrap entry already pins the brand surface:
// `callis --version`, `--help`, and the stale-report deletion contract.
import { parseArgs } from "node:util";
import { TOOL_VERSION } from "@callis/core";

const HELP = `callis ${TOOL_VERSION}

Is this vulnerability in the SBOM actually reachable from application code?

Usage: callis --sbom=<file> --osv-dir=<dir> [--project=<dir>] [options]

Options (JVM-compatible flag vocabulary; see implementation-plan section 6):
  --project=<dir>            Project root (default: cwd)
  --sbom=<file>              CycloneDX 1.4-1.6 or SPDX 2.x SBOM (required)
  --osv-dir=<dir>            Local OSV npm snapshot directory (required)
  --osv-checksum=<sha256>    Expected snapshot pin
  --mappings=<file>          vuln-mappings.json
  --entry-points=<a,b>       Extend the curated entry points
  --entry-points-only        Replace the curated entry points
  --callback-interfaces=<a>  Extend the curated callback list
  --cha                      Names mode (over-approximate)
  --pointer-analysis         Inclusion-based analysis (post-v1, M7a)
  --package-evidence=call|load
  --call-evidence=any|direct
  --include-dev              Analyze dev-only components
  --include-tests            Analyze test files
  --malware=fail|warn|ignore Policy for MAL-* records (default: fail)
  --fail-on-applicable       sbom-only: fail on any applicable advisory
  --strict-sources           Any non-RESOLVED component => exit 3
  --require-complete         analysisStatus PARTIAL => exit 3
  --allow-empty-sbom         Opt out of the empty-SBOM guard
  --match-installed          Also match installed instances not in the SBOM
  --opaque-native=fail|warn|ignore
  --sbom-only                SBOM x OSV only, no call graph
  --over-approximate-dynamic Name-based fallback for computed calls
  --cache-dir=<dir>          IR/OSV-index cache (default: $XDG_CACHE_HOME/callis)
  --source-exclude=<dirs>    Override the input-key source exclusion list
  --source-include=<dirs>    Force-include directories in the source hash
  --print-cache-key          Print the pre-run input cache key
  --hash-installed           Include installed-file content hashes in the key
  --format=json,junitxml,sarif
  --output=<base>            Report base name (default: callis-report)
  -v, --verbose              Verbose diagnostics
`;

function main(): void {
  const { values } = parseArgs({
    allowPositionals: false,
    options: {
      version: { type: "boolean" },
      help: { type: "boolean" },
      project: { type: "string" },
      sbom: { type: "string" },
      "osv-dir": { type: "string" },
      "osv-checksum": { type: "string" },
      mappings: { type: "string" },
      format: { type: "string" },
      output: { type: "string" },
      verbose: { type: "boolean", short: "v" },
    },
    strict: false,
  });

  if (values.version === true) {
    console.log(`callis ${TOOL_VERSION}`);
    process.exit(0);
  }
  if (values.help === true || values.sbom === undefined) {
    console.log(HELP);
    process.exit(values.help === true ? 0 : 2);
  }
  // The full pipeline is wired in M5; until then, a run without the pipeline
  // is a usage error (exit 2), never a silent green.
  console.error(
    "callis: the analysis pipeline is not yet built in this checkout (M5); a run cannot " +
      "exit green without one (fail-visibly contract, plan section 1)",
  );
  process.exit(2);
}

main();
