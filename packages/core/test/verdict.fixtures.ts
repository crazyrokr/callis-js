// Shared fixtures for the M5 report/policy tests: Finding and AnalysisResult
// factories with deterministic defaults (Given-When-Then tests override the
// fields they exercise).

import type { AnalysisResult, Completeness, Exposure, GuardStates, ReportMeta } from "../src/report/types.js";
import type { Evidence, Finding, Verdict } from "../src/verdict/types.js";

export const emptyEvidence: Evidence = { loaded: false, called: false, callbackRegistered: false };

export function finding(over: Partial<Finding> = {}): Finding {
  const base: Finding = {
    id: "CVE-1",
    aliases: ["GHSA-1"],
    purl: "pkg:npm/lodash@4.17.20",
    component: "lodash",
    componentVersion: "4.17.20",
    verdict: "UNREACHABLE",
    installed: true,
    evidence: { ...emptyEvidence },
    resolutionState: "RESOLVED",
    matchedOn: "sbom",
    source: "sbom",
    relatedIds: [],
    matchLevel: "artifact",
    summary: "s",
    severity: "HIGH",
    affectedRange: "[introduced:0 fixed:4.17.21]",
    path: [],
    supplyPath: ["app", "express", "lodash"],
  };
  return { ...base, ...over };
}

export function meta(over: Partial<ReportMeta> = {}): ReportMeta {
  const base: ReportMeta = {
    toolVersion: "0.1.0",
    schemaVersion: "1",
    callGraphBuilder: "demand-0cfa",
    entryPointCount: 1,
    callGraphNodes: 10,
    callGraphCalls: 5,
    osvSnapshotSha256: "a".repeat(64),
    osvSkippedRecords: 0,
    sbomFile: "/proj/sbom.json",
    durationMillis: 1,
    exitReasons: [],
  };
  return { ...base, ...over };
}

export function guards(over: Partial<GuardStates> = {}): GuardStates {
  return {
    totalResolution: false,
    emptySbom: false,
    strictSources: false,
    requireComplete: false,
    analysisFailed: false,
    ...over,
  };
}

export function completeness(over: Partial<Completeness> = {}): Completeness {
  return {
    components: [{ purl: "pkg:npm/lodash@4.17.20", state: "RESOLVED" }],
    unresolvedImports: [],
    dynamicUnscoped: 0,
    opaqueBoundaries: 0,
    graphBuilt: true,
    unlistedInstalled: [],
    dependencyGraph: "present",
    ...over,
  };
}

export function exposure(over: Partial<Exposure> = {}): Exposure {
  return { dynamicRisk: 0, noSource: 0, nativeOpaque: 0, dynamicUnscoped: 0, loadedNotCalled: 0, ...over };
}

export function result(over: Partial<AnalysisResult> = {}): AnalysisResult {
  const base: AnalysisResult = {
    meta: meta(),
    analysisStatus: "COMPLETE",
    findings: [],
    completeness: completeness(),
    limitations: [],
    exposure: exposure(),
    guards: guards(),
    warnings: [],
    notices: [],
  };
  return { ...base, ...over };
}

export function findingWithVerdict(verdict: Verdict, over: Partial<Finding> = {}): Finding {
  return finding({ verdict, ...over });
}
