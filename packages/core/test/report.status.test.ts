// M5 — analysis status / exposure / limitations tests (plan section 5.6 v3.3-v3.5, ADR 0012).
//
// Given-When-Then over computeAnalysisStatus (COMPLETE / PARTIAL /
// INCOMPLETE / NOT_PERFORMED), computeExposure (all five counters),
// computeLimitations (soundness-contract forms met), sortFindings
// (deterministic order) and assembleResult (the policy-layer input).

import { describe, expect, test } from "bun:test";
import {
  type StatusInput,
  assembleResult,
  computeAnalysisStatus,
  computeExposure,
  computeLimitations,
  sortFindings,
} from "../src/report/status.js";
import { completeness, exposure, finding, findingWithVerdict, guards, meta, result } from "./verdict.fixtures.js";

function input(over: Partial<StatusInput> = {}): StatusInput {
  return {
    sbomOnly: false,
    graphBuilt: true,
    guards: guards(),
    anyNonResolved: false,
    unresolvedImports: [],
    anyUnlistedLoaded: false,
    ...over,
  };
}

describe("computeAnalysisStatus", () => {
  test("given a fully resolved run, when computed, then COMPLETE", () => {
    expect(computeAnalysisStatus(input())).toBe("COMPLETE");
  });

  test("given a non-RESOLVED component, when computed, then PARTIAL", () => {
    expect(computeAnalysisStatus(input({ anyNonResolved: true }))).toBe("PARTIAL");
  });

  test("given only library-optional unresolved imports (counts=false), when computed, then COMPLETE (they do not count)", () => {
    const i = input({ unresolvedImports: [{ location: "src/a.js", cls: "library-optional", counts: false }] });
    expect(computeAnalysisStatus(i)).toBe("COMPLETE");
  });

  test("given a counting unresolved import (app or candidate code), when computed, then PARTIAL", () => {
    const i = input({
      unresolvedImports: [
        { location: "src/a.js", cls: "app", counts: true },
        { location: "node_modules/x/index.js", cls: "candidate", counts: true },
        { location: "node_modules/y/index.js", cls: "library-optional", counts: false },
      ],
    });
    expect(computeAnalysisStatus(i)).toBe("PARTIAL");
  });

  test("given a loaded instance the SBOM never listed, when computed, then PARTIAL", () => {
    expect(computeAnalysisStatus(input({ anyUnlistedLoaded: true }))).toBe("PARTIAL");
  });

  test("given a fired total-resolution guard, when computed, then INCOMPLETE (it beats PARTIAL)", () => {
    const i = input({ guards: guards({ totalResolution: true }), anyNonResolved: true });
    expect(computeAnalysisStatus(i)).toBe("INCOMPLETE");
  });

  test("given a failed graph construction, when computed, then INCOMPLETE", () => {
    expect(computeAnalysisStatus(input({ graphBuilt: false }))).toBe("INCOMPLETE");
  });

  test("given --sbom-only, when computed, then NOT_PERFORMED (before every other check)", () => {
    const i = input({
      sbomOnly: true,
      guards: guards({ totalResolution: true }),
      graphBuilt: false,
      anyNonResolved: true,
    });
    expect(computeAnalysisStatus(i)).toBe("NOT_PERFORMED");
  });

  test("given dynamic markers only, when computed, then they never demote the status (v3.4)", () => {
    expect(
      computeAnalysisStatus(input({ unresolvedImports: [{ location: "src/a.js", cls: "app", counts: false }] })),
    ).toBe("COMPLETE");
  });
});

describe("computeExposure", () => {
  test("given the full finding set, when counted, then every counter reflects the findings", () => {
    const f = [
      findingWithVerdict("NO_SOURCE"),
      findingWithVerdict("NO_SOURCE"),
      findingWithVerdict("NATIVE_OPAQUE", { nativeBoundary: "reached", opaque: true }),
      findingWithVerdict("UNREACHABLE", { evidence: { loaded: true, called: false, callbackRegistered: false } }),
      findingWithVerdict("UNREACHABLE", { evidence: { loaded: true, called: true, callbackRegistered: false } }),
      findingWithVerdict("UNREACHABLE"),
      findingWithVerdict("REACHABLE", { evidence: { loaded: true, called: true, callbackRegistered: false } }),
      findingWithVerdict("MALICIOUS_PACKAGE"),
    ];
    const e = computeExposure(f, 3, 2);
    expect(e.noSource).toBe(2);
    expect(e.nativeOpaque).toBe(1);
    expect(e.loadedNotCalled).toBe(1);
    expect(e.dynamicRisk).toBe(3);
    expect(e.dynamicUnscoped).toBe(2);
  });

  test("given no findings, when counted, then all counters are zero", () => {
    const e = computeExposure([], 0, 0);
    expect(e).toEqual({ dynamicRisk: 0, noSource: 0, nativeOpaque: 0, dynamicUnscoped: 0, loadedNotCalled: 0 });
  });

  test("given an UNREACHABLE finding with a registered callback, when counted, then it is NOT loaded-not-called (the tier was met)", () => {
    const f = [
      findingWithVerdict("UNREACHABLE", { evidence: { loaded: true, called: false, callbackRegistered: true } }),
    ];
    expect(computeExposure(f, 0, 0).loadedNotCalled).toBe(0);
  });
});

describe("computeLimitations", () => {
  test("given a run with every soundness-contract form met, when computed, then every limitation is present", () => {
    const l = computeLimitations({
      dynamicMarkers: 2,
      importTimeReachable: true,
      callbackRegisteredUsed: true,
      nativeOpaque: 1,
      overApproximateDynamic: true,
      cha: true,
    });
    expect(l.length).toBe(6);
    expect(l).toContain("dynamic-constructs: unresolved dynamic calls recorded but not resolved");
    expect(l).toContain("import-time: module evaluation runs on import; import edges are over-approximated");
    expect(l).toContain("callback-invocation: handler registration is evidence, invocation is not verified");
    expect(l).toContain("native-opacity: .node/WASM boundaries are not visible to the analysis");
    expect(l).toContain("cha: member calls resolve to every loaded function of the same name");
    expect(l).toContain("over-approximate-dynamic: unknown-key computed calls resolve to instantiated-class methods");
  });

  test("given a clean precise run, when computed, then no limitations", () => {
    const l = computeLimitations({
      dynamicMarkers: 0,
      importTimeReachable: false,
      callbackRegisteredUsed: false,
      nativeOpaque: 0,
      overApproximateDynamic: false,
      cha: false,
    });
    expect(l.length).toBe(0);
  });

  test("given a zero nativeOpaque count, when computed, then no native-opacity limitation (the count gate)", () => {
    const l = computeLimitations({
      dynamicMarkers: 0,
      importTimeReachable: false,
      callbackRegisteredUsed: false,
      nativeOpaque: 0,
      overApproximateDynamic: true,
      cha: false,
    });
    expect(l).not.toContain("native-opacity: .node/WASM boundaries are not visible to the analysis");
  });

  test("given an active --pointer-analysis run with refinement stats, when computed, then the pointer limitation carries the site/edge counts", () => {
    const l = computeLimitations({
      dynamicMarkers: 0,
      importTimeReachable: false,
      callbackRegisteredUsed: false,
      nativeOpaque: 0,
      overApproximateDynamic: false,
      cha: false,
      pointer: true,
      pointerStats: { sites: 4, added: 2, pruned: 1 },
    });
    expect(l).toContain(
      "pointer-analysis: inclusion-based receiver typing refined dispatch at 4 site(s) (added 2, pruned 1 edges; unknown receivers keep the default edges)",
    );
  });

  test("given an active --pointer-analysis run whose stats are absent (false-positive guard), when computed, then the limitation reports zero counts", () => {
    const l = computeLimitations({
      dynamicMarkers: 0,
      importTimeReachable: false,
      callbackRegisteredUsed: false,
      nativeOpaque: 0,
      overApproximateDynamic: false,
      cha: false,
      pointer: true,
    });
    expect(l).toContain(
      "pointer-analysis: inclusion-based receiver typing refined dispatch at 0 site(s) (added 0, pruned 0 edges; unknown receivers keep the default edges)",
    );
  });
});

describe("sortFindings", () => {
  test("given findings in arbitrary order, when sorted, then the order is deterministic (id, purl, verdict, source)", () => {
    const a = finding({ id: "CVE-B", purl: "pkg:npm/b@1.0.0", component: "b", verdict: "REACHABLE" });
    const b = finding({ id: "CVE-A", purl: "pkg:npm/a@1.0.0", component: "a", verdict: "UNREACHABLE" });
    const c = finding({ id: "CVE-A", purl: "pkg:npm/a@2.0.0", component: "a", verdict: "UNREACHABLE" });
    const sorted = sortFindings([a, c, b]);
    expect(sorted.map((f) => `${f.id}\u0000${f.purl}`)).toEqual([
      "CVE-A\u0000pkg:npm/a@1.0.0",
      "CVE-A\u0000pkg:npm/a@2.0.0",
      "CVE-B\u0000pkg:npm/b@1.0.0",
    ]);
    // The input is not mutated.
    expect([a, c, b].map((f) => f.id)).toEqual(["CVE-B", "CVE-A", "CVE-A"]);
  });

  test("given findings that tie on id+purl, when sorted, then verdict and source break the tie", () => {
    const r = finding({ verdict: "REACHABLE", source: "sbom" });
    const u = finding({ verdict: "UNREACHABLE", source: "sbom" });
    const r2 = finding({ verdict: "REACHABLE", source: "installed" });
    const sorted = sortFindings([r2, r, u]);
    expect(sorted.map((f) => `${f.verdict}\u0000${f.source}`)).toEqual([
      "REACHABLE\u0000installed",
      "REACHABLE\u0000sbom",
      "UNREACHABLE\u0000sbom",
    ]);
  });
});

describe("assembleResult", () => {
  test("given complete parts, when assembled, then the status is computed and the findings sorted (the policy layer input)", () => {
    const r = assembleResult({
      meta: meta(),
      findings: [finding({ id: "CVE-2" }), finding({ id: "CVE-1" })],
      completeness: completeness(),
      limitations: [],
      exposure: exposure(),
      guards: guards(),
      warnings: [],
      notices: [],
    });
    expect(r.analysisStatus).toBe("COMPLETE");
    expect(r.findings.map((f) => f.id)).toEqual(["CVE-1", "CVE-2"]);
  });

  test("given parts with a non-RESOLVED component, when assembled, then PARTIAL", () => {
    const r = assembleResult({
      meta: meta(),
      findings: [],
      completeness: completeness({
        components: [{ purl: "pkg:npm/x@1.0.0", state: "VERSION_MISMATCH", installedVersion: "0.9.0" }],
      }),
      limitations: [],
      exposure: exposure(),
      guards: guards(),
      warnings: [],
      notices: [],
    });
    expect(r.analysisStatus).toBe("PARTIAL");
  });

  test("given sbom-only meta (noCallGraph), when assembled, then NOT_PERFORMED", () => {
    const r = assembleResult({
      meta: meta({ noCallGraph: true }),
      findings: [],
      completeness: completeness({
        graphBuilt: false,
        dependencyGraph: "absent",
        components: [{ purl: "pkg:npm/x@1.0.0", state: "NOT_CHECKED" }],
      }),
      limitations: [],
      exposure: exposure(),
      guards: guards(),
      warnings: [],
      notices: [],
    });
    expect(r.analysisStatus).toBe("NOT_PERFORMED");
  });

  test("given parts with a fired guard, when assembled, then INCOMPLETE", () => {
    const r = assembleResult({
      meta: meta(),
      findings: [],
      completeness: completeness({ graphBuilt: false }),
      limitations: [],
      exposure: exposure(),
      guards: guards({ totalResolution: true }),
      warnings: [],
      notices: [],
    });
    expect(r.analysisStatus).toBe("INCOMPLETE");
  });

  test("given the assembled result, when used, then it is a valid report input (meta/guards/exposure intact)", () => {
    const r = result({ findings: [finding()] });
    expect(r.meta.exitReasons).toEqual([]);
    expect(r.guards).toEqual(guards());
    expect(r.findings).toHaveLength(1);
  });
});
