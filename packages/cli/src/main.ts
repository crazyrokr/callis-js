#!/usr/bin/env bun
// callis CLI — the full flag set (plan section 6) over the M5 engine.
//
// Exit-code precedence (v3.2): 2 > 3 > 1 > 0. Usage/config errors exit 2
// (UsageError, before any analysis); analysis failures exit 3; reachable
// findings exit 1; otherwise 0. The report lists EVERY triggered reason
// (exitReasons), independent of the precedence winner.

import { parseArgs } from "node:util";
import { type EngineOptions, runAnalysis, validateFlags } from "@callis/core";
import { TOOL_VERSION } from "@callis/core";
import { UsageError } from "@callis/core";

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
  --entry-points-only=<a,b>  Replace the curated entry points
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
  --format=json,junitxml,sarif
  --output=<base>            Report base name (default: callis-report)
  -v, --verbose              Verbose diagnostics
`;

function csv(v: string | undefined): string[] {
  if (v === undefined) return [];
  return v
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function oneOf(v: string | undefined, allowed: string[], flag: string): string {
  if (v === undefined) return allowed[0] as string;
  if (!allowed.includes(v)) throw new UsageError(`invalid value for ${flag}: ${v} (allowed: ${allowed.join("|")})`);
  return v;
}

export function optionsOf(values: Record<string, unknown>): EngineOptions {
  const str = (k: string): string | undefined => (typeof values[k] === "string" ? (values[k] as string) : undefined);
  const bool = (k: string): boolean => values[k] === true;
  const opts: EngineOptions = {
    project: str("project") ?? process.cwd(),
    sbom: str("sbom") as string,
    osvDir: str("osv-dir") as string,
    entryPoints: csv(str("entry-points")),
    entryPointsOnly: csv(str("entry-points-only")),
    callbackInterfaces: csv(str("callback-interfaces")),
    cha: bool("cha"),
    pointerAnalysis: bool("pointer-analysis"),
    packageEvidence: oneOf(str("package-evidence"), ["call", "load"], "--package-evidence") as "call" | "load",
    callEvidence: oneOf(str("call-evidence"), ["any", "direct"], "--call-evidence") as "any" | "direct",
    includeDev: bool("include-dev"),
    includeTests: bool("include-tests"),
    malware: oneOf(str("malware"), ["fail", "warn", "ignore"], "--malware") as "fail" | "warn" | "ignore",
    failOnApplicable: bool("fail-on-applicable"),
    strictSources: bool("strict-sources"),
    requireComplete: bool("require-complete"),
    allowEmptySbom: bool("allow-empty-sbom"),
    matchInstalled: bool("match-installed"),
    opaqueNative: oneOf(str("opaque-native"), ["fail", "warn", "ignore"], "--opaque-native") as
      | "fail"
      | "warn"
      | "ignore",
    sbomOnly: bool("sbom-only"),
    overApproximateDynamic: bool("over-approximate-dynamic"),
    cacheDir: str("cache-dir") ?? `${process.env.XDG_CACHE_HOME ?? `${process.env.HOME}/.cache`}/callis`,
    formats: csv(str("format")).length > 0 ? csv(str("format")) : ["json", "junitxml"],
    output: str("output") ?? "callis-report",
    verbose: bool("verbose"),
  };
  const checksum = str("osv-checksum");
  if (checksum !== undefined) opts.osvChecksum = checksum;
  const mappings = str("mappings");
  if (mappings !== undefined) opts.mappings = mappings;
  if (bool("dry-run-sbom")) opts.dryRunSbom = true;
  if (bool("dry-run-match")) opts.dryRunMatch = true;
  if (bool("dry-run-graph")) opts.dryRunGraph = true;
  return opts;
}

const OPTION_DEFS = {
  version: { type: "boolean" },
  help: { type: "boolean" },
  project: { type: "string" },
  sbom: { type: "string" },
  "osv-dir": { type: "string" },
  "osv-checksum": { type: "string" },
  mappings: { type: "string" },
  "entry-points": { type: "string" },
  "entry-points-only": { type: "string" },
  "callback-interfaces": { type: "string" },
  cha: { type: "boolean" },
  "pointer-analysis": { type: "boolean" },
  "package-evidence": { type: "string" },
  "call-evidence": { type: "string" },
  "include-dev": { type: "boolean" },
  "include-tests": { type: "boolean" },
  malware: { type: "string" },
  "fail-on-applicable": { type: "boolean" },
  "strict-sources": { type: "boolean" },
  "require-complete": { type: "boolean" },
  "allow-empty-sbom": { type: "boolean" },
  "match-installed": { type: "boolean" },
  "opaque-native": { type: "string" },
  "sbom-only": { type: "boolean" },
  "over-approximate-dynamic": { type: "boolean" },
  "cache-dir": { type: "string" },
  "source-exclude": { type: "string" },
  "source-include": { type: "string" },
  "print-cache-key": { type: "boolean" },
  "hash-installed": { type: "boolean" },
  format: { type: "string" },
  output: { type: "string" },
  verbose: { type: "boolean", short: "v" },
  "dry-run-sbom": { type: "boolean" },
  "dry-run-match": { type: "boolean" },
  "dry-run-graph": { type: "boolean" },
} as const;

async function main(): Promise<number> {
  const { values } = parseArgs({ allowPositionals: false, options: OPTION_DEFS, strict: false });

  if (values.version === true) {
    console.log(`callis ${TOOL_VERSION}`);
    return 0;
  }
  if (values.help === true) {
    console.log(HELP);
    return 0;
  }
  if (values.sbom === undefined || values["osv-dir"] === undefined) {
    console.log(HELP);
    return 2;
  }
  // M8 flags: accepted (contract) but not yet implemented — say so, keep going.
  if (values["print-cache-key"] === true || values["hash-installed"] === true) {
    console.error("note: --print-cache-key/--hash-installed land with the M8 cache keys; ignored for this run");
  }

  let opts: EngineOptions;
  try {
    opts = optionsOf(values);
    validateFlags(opts);
  } catch (e) {
    if (e instanceof UsageError) {
      console.error(`error: ${e.message}`);
      return 2;
    }
    throw e;
  }

  try {
    return await runAnalysis(opts);
  } catch (e) {
    if (e instanceof UsageError) {
      console.error(`error: ${e.message}`);
      return 2;
    }
    console.error(`error: ${(e as Error).message}`);
    return 3;
  }
}

main().then(
  (code) => {
    process.exit(code);
  },
  (e) => {
    console.error(`error: ${(e as Error).stack ?? String(e)}`);
    process.exit(3);
  },
);
