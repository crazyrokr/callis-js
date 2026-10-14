// Analysis completeness (plan section 5.6 v3.3/v3.4/v3.5, ADR 0012).
//
// COMPLETE   — every component RESOLVED, no COUNTING unresolved imports,
//             every loaded instance listed in the SBOM, graph built.
// PARTIAL    — >=1 component non-RESOLVED, or >=1 counting unresolved import,
//             or >=1 loaded instance not in the SBOM (unlistedInstalled).
// INCOMPLETE — the total-resolution guard fired, or the analysis failed
//             (graph construction failed, or zero entry points — nothing
//             could be reached).
// NOT_PERFORMED — --sbom-only (no call graph at all).
//
// Dynamic markers never demote the status (v3.4): they belong in
// exposure/limitations — nearly every real project has some.

import type { Notice } from "../util/errors.js";
import type { Finding } from "../verdict/types.js";
import type {
  AnalysisResult,
  AnalysisStatus,
  Completeness,
  Exposure,
  GuardStates,
  ReportMeta,
  UnresolvedImport,
} from "./types.js";

export interface StatusInput {
  sbomOnly: boolean;
  graphBuilt: boolean;
  /** INCOMPLETE input: the total-resolution guard fired or the graph failed. */
  guards: GuardStates;
  /** True when any component is non-RESOLVED (NOT_CHECKED never counts). */
  anyNonResolved: boolean;
  unresolvedImports: UnresolvedImport[];
  /** True when any loaded instance is not listed in the SBOM. */
  anyUnlistedLoaded: boolean;
}

export function computeAnalysisStatus(input: StatusInput): AnalysisStatus {
  if (input.sbomOnly) return "NOT_PERFORMED";
  if (input.guards.totalResolution || input.guards.analysisFailed || !input.graphBuilt) return "INCOMPLETE";
  const counting = input.unresolvedImports.filter((u) => u.counts).length;
  if (input.anyNonResolved || counting > 0 || input.anyUnlistedLoaded) return "PARTIAL";
  return "COMPLETE";
}

/** Exposure counts over the finding set (plan section 5.6). */
export function computeExposure(findings: Finding[], dynamicRiskFindings: number, dynamicUnscoped: number): Exposure {
  let noSource = 0;
  let nativeOpaque = 0;
  let loadedNotCalled = 0;
  for (const f of findings) {
    if (f.verdict === "NO_SOURCE") noSource += 1;
    if (f.verdict === "NATIVE_OPAQUE") nativeOpaque += 1;
    if (f.verdict === "UNREACHABLE" && f.evidence.loaded && !f.evidence.called && !f.evidence.callbackRegistered)
      loadedNotCalled += 1;
  }
  return {
    dynamicRisk: dynamicRiskFindings,
    noSource,
    nativeOpaque,
    dynamicUnscoped,
    loadedNotCalled,
  };
}

/**
 * Limitations of THIS run (v3.3): the soundness-contract forms actually met,
 * the import-time caveat, the callback-invocation gap, native opacity.
 */
export function computeLimitations(input: {
  dynamicMarkers: number;
  importTimeReachable: boolean;
  callbackRegisteredUsed: boolean;
  nativeOpaque: number;
  overApproximateDynamic: boolean;
  cha: boolean;
}): string[] {
  const out: string[] = [];
  if (input.dynamicMarkers > 0) out.push("dynamic-constructs: unresolved dynamic calls recorded but not resolved");
  if (input.importTimeReachable)
    out.push("import-time: module evaluation runs on import; import edges are over-approximated");
  if (input.callbackRegisteredUsed)
    out.push("callback-invocation: handler registration is evidence, invocation is not verified");
  if (input.nativeOpaque > 0) out.push("native-opacity: .node/WASM boundaries are not visible to the analysis");
  if (input.cha) out.push("cha: member calls resolve to every loaded function of the same name");
  if (input.overApproximateDynamic)
    out.push("over-approximate-dynamic: unknown-key computed calls resolve to instantiated-class methods");
  return out;
}

/** Deterministic sort order for findings (report normalization contract). */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const key = (f: Finding): string => `${f.id}\u0000${f.purl}\u0000${f.verdict}\u0000${f.source}`;
    const ka = key(a);
    const kb = key(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

export interface ResultParts {
  meta: ReportMeta;
  findings: Finding[];
  completeness: Completeness;
  limitations: string[];
  exposure: Exposure;
  guards: GuardStates;
  warnings: string[];
  notices: Notice[];
}

/** Assemble the full structured result (the policy layer input, ADR 0016). */
export function assembleResult(p: ResultParts): AnalysisResult {
  const status = computeAnalysisStatus({
    sbomOnly: p.meta.noCallGraph === true,
    graphBuilt: p.completeness.graphBuilt,
    guards: p.guards,
    anyNonResolved: p.completeness.components.some((c) => c.state !== "RESOLVED" && c.state !== "NOT_CHECKED"),
    unresolvedImports: p.completeness.unresolvedImports,
    anyUnlistedLoaded: p.completeness.unlistedInstalled.length > 0,
  });
  return {
    meta: p.meta,
    analysisStatus: status,
    findings: sortFindings(p.findings),
    completeness: p.completeness,
    limitations: p.limitations,
    exposure: p.exposure,
    guards: p.guards,
    warnings: p.warnings,
    notices: p.notices,
  };
}
