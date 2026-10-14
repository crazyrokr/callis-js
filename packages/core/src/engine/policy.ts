// Exit-code policy layer (plan section 6, ADR 0016).
//
// PURE and separately tested: maps a finished AnalysisResult + policy flags
// to {code, reasons}. It never builds a graph. Exit-code precedence
// (v3.2): 2 > 3 > 1 > 0 — this layer returns 3/1/0; 2 is a usage error
// raised before any analysis (UsageError, CLI level).
//
// `exitReasons` lists EVERY condition triggered, independent of the
// precedence winner (v3.5): a run with a REACHABLE finding AND a guard
// failure exits 3 and lists both.

import type { AnalysisResult, ExitReason } from "../report/types.js";
import type { Finding } from "../verdict/types.js";

export interface PolicyFlags {
  malware: "fail" | "warn" | "ignore";
  opaqueNative: "fail" | "warn" | "ignore";
  sbomOnly: boolean;
  failOnApplicable: boolean;
  requireComplete: boolean;
}

export interface PolicyDecision {
  code: 0 | 1 | 3;
  reasons: ExitReason[];
}

const CODE_3_REASONS: Set<string> = new Set([
  "TOTAL_RESOLUTION_GUARD",
  "EMPTY_SBOM_GUARD",
  "STRICT_SOURCES",
  "REQUIRE_COMPLETE",
  "ANALYSIS_FAILURE",
]);

/** Findings that trigger REACHABLE_FINDINGS (verdict + policy). */
export function reachableFindings(findings: Finding[], flags: PolicyFlags): Finding[] {
  return findings.filter((f) => {
    if (f.verdict === "REACHABLE") return true;
    // --sbom-only + --fail-on-applicable: any applicable non-malicious
    // advisory fails (v3.4 item 9). Outside sbom-only the flag is a usage
    // error (the CLI rejects it before the policy sees the result).
    if (flags.sbomOnly && flags.failOnApplicable && f.verdict === "APPLICABLE") return true;
    return false;
  });
}

/** The full decision over a finished result (plan section 6 matrix). */
export function decideExitCode(result: AnalysisResult, flags: PolicyFlags): PolicyDecision {
  const reasons = new Set<ExitReason>();

  if (reachableFindings(result.findings, flags).length > 0) reasons.add("REACHABLE_FINDINGS");

  // MAL-* records fail regardless of dev scope (v3.1): a malicious
  // devDependency still runs install scripts at `npm ci` time.
  if (flags.malware === "fail" && result.findings.some((f) => f.verdict === "MALICIOUS_PACKAGE")) {
    reasons.add("MALWARE_FAIL");
  }

  // Reached native boundaries fail closed only under --opaque-native=fail
  // (warn is the default; ignore suppresses the exit-code effect only).
  if (
    flags.opaqueNative === "fail" &&
    result.findings.some((f) => f.verdict === "NATIVE_OPAQUE" && f.nativeBoundary === "reached")
  ) {
    reasons.add("OPAQUE_NATIVE_FAIL");
  }

  const g = result.guards;
  if (g.totalResolution) reasons.add("TOTAL_RESOLUTION_GUARD");
  if (g.emptySbom) reasons.add("EMPTY_SBOM_GUARD");
  if (g.strictSources) reasons.add("STRICT_SOURCES");
  if (flags.requireComplete && result.analysisStatus === "PARTIAL") reasons.add("REQUIRE_COMPLETE");
  if (g.analysisFailed) reasons.add("ANALYSIS_FAILURE");

  const sorted = [...reasons].sort();
  if (sorted.some((r) => CODE_3_REASONS.has(r))) return { code: 3, reasons: sorted };
  if (sorted.length > 0) return { code: 1, reasons: sorted };
  return { code: 0, reasons: [] };
}
