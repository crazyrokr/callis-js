// M5 — exit-code policy layer tests (plan section 6, ADR 0016).
//
// Given-When-Then over decideExitCode — PURE (no graph building): the
// v3.2 precedence 3 > 1 > 0, the v3.5 exitReasons contract (EVERY
// condition listed, independent of the precedence winner), and every
// policy-flag combination of the section 9 exit-code matrix.

import { describe, expect, test } from "bun:test";
import { type PolicyFlags, decideExitCode, reachableFindings } from "../src/engine/policy.js";
import { finding, findingWithVerdict, guards, result } from "./verdict.fixtures.js";

function flags(over: Partial<PolicyFlags> = {}): PolicyFlags {
  return {
    malware: "fail",
    opaqueNative: "warn",
    sbomOnly: false,
    failOnApplicable: false,
    requireComplete: false,
    ...over,
  };
}

describe("baseline", () => {
  test("given no findings and no guards, when decided, then exit 0 with no reasons", () => {
    expect(decideExitCode(result({ findings: [] }), flags())).toEqual({ code: 0, reasons: [] });
  });

  test("given only UNREACHABLE / DEV_ONLY / NO_SOURCE findings, when decided, then exit 0 (they never fail the run)", () => {
    const r = result({
      findings: [findingWithVerdict("UNREACHABLE"), findingWithVerdict("DEV_ONLY"), findingWithVerdict("NO_SOURCE")],
    });
    expect(decideExitCode(r, flags())).toEqual({ code: 0, reasons: [] });
  });

  test("given a REACHABLE finding, when decided, then exit 1 with REACHABLE_FINDINGS", () => {
    const d = decideExitCode(result({ findings: [findingWithVerdict("REACHABLE")] }), flags());
    expect(d.code).toBe(1);
    expect(d.reasons).toEqual(["REACHABLE_FINDINGS"]);
  });
});

describe("malware policy (v3.1: regardless of dev scope)", () => {
  test("given a MALICIOUS_PACKAGE finding with --malware=fail, when decided, then exit 1 with MALWARE_FAIL", () => {
    const d = decideExitCode(
      result({ findings: [findingWithVerdict("MALICIOUS_PACKAGE")] }),
      flags({ malware: "fail" }),
    );
    expect(d.code).toBe(1);
    expect(d.reasons).toEqual(["MALWARE_FAIL"]);
  });

  test("given the same finding with --malware=warn, when decided, then exit 0 (warn keeps the finding, drops the fail)", () => {
    const d = decideExitCode(
      result({ findings: [findingWithVerdict("MALICIOUS_PACKAGE")] }),
      flags({ malware: "warn" }),
    );
    expect(d.code).toBe(0);
    expect(d.reasons).toEqual([]);
  });

  test("given the same finding with --malware=ignore, when decided, then exit 0", () => {
    const d = decideExitCode(
      result({ findings: [findingWithVerdict("MALICIOUS_PACKAGE")] }),
      flags({ malware: "ignore" }),
    );
    expect(d.code).toBe(0);
    expect(d.reasons).toEqual([]);
  });
});

describe("opaque-native policy (v3.4 item 11)", () => {
  const reached = () => findingWithVerdict("NATIVE_OPAQUE", { nativeBoundary: "reached", opaque: true });

  test("given a REACHED boundary with --opaque-native=fail, when decided, then exit 1 with OPAQUE_NATIVE_FAIL", () => {
    const d = decideExitCode(result({ findings: [reached()] }), flags({ opaqueNative: "fail" }));
    expect(d.code).toBe(1);
    expect(d.reasons).toEqual(["OPAQUE_NATIVE_FAIL"]);
  });

  test("given an UNRESOLVED boundary with --opaque-native=fail, when decided, then exit 0 (only reached boundaries fail closed)", () => {
    const d = decideExitCode(
      result({ findings: [findingWithVerdict("NATIVE_OPAQUE", { nativeBoundary: "unresolved", opaque: true })] }),
      flags({ opaqueNative: "fail" }),
    );
    expect(d.code).toBe(0);
  });

  test("given a reached boundary with the default --opaque-native=warn, when decided, then exit 0", () => {
    const d = decideExitCode(result({ findings: [reached()] }), flags({ opaqueNative: "warn" }));
    expect(d.code).toBe(0);
  });

  test("given a reached boundary with --opaque-native=ignore, when decided, then exit 0", () => {
    const d = decideExitCode(result({ findings: [reached()] }), flags({ opaqueNative: "ignore" }));
    expect(d.code).toBe(0);
  });
});

describe("sbom-only policy (v3.4 item 9)", () => {
  test("given an APPLICABLE finding with --sbom-only --fail-on-applicable, when decided, then exit 1 with REACHABLE_FINDINGS", () => {
    const d = decideExitCode(
      result({ findings: [findingWithVerdict("APPLICABLE")] }),
      flags({ sbomOnly: true, failOnApplicable: true }),
    );
    expect(d.code).toBe(1);
    expect(d.reasons).toEqual(["REACHABLE_FINDINGS"]);
  });

  test("given the same finding without --fail-on-applicable, when decided, then exit 0", () => {
    const d = decideExitCode(result({ findings: [findingWithVerdict("APPLICABLE")] }), flags({ sbomOnly: true }));
    expect(d.code).toBe(0);
  });

  test("given an APPLICABLE finding OUTSIDE sbom-only, when decided, then exit 0 (the flag is a usage error there, the CLI rejects it first)", () => {
    const d = decideExitCode(
      result({ findings: [findingWithVerdict("APPLICABLE")] }),
      flags({ failOnApplicable: true }),
    );
    expect(d.code).toBe(0);
  });
});

describe("guards (the exit-3 family)", () => {
  test("given the total-resolution guard, when decided, then exit 3 with TOTAL_RESOLUTION_GUARD", () => {
    const d = decideExitCode(result({ findings: [], guards: guards({ totalResolution: true }) }), flags());
    expect(d.code).toBe(3);
    expect(d.reasons).toEqual(["TOTAL_RESOLUTION_GUARD"]);
  });

  test("given the empty-SBOM guard, when decided, then exit 3 with EMPTY_SBOM_GUARD", () => {
    const d = decideExitCode(result({ findings: [], guards: guards({ emptySbom: true }) }), flags());
    expect(d.code).toBe(3);
    expect(d.reasons).toEqual(["EMPTY_SBOM_GUARD"]);
  });

  test("given the strict-sources guard, when decided, then exit 3 with STRICT_SOURCES", () => {
    const d = decideExitCode(result({ findings: [], guards: guards({ strictSources: true }) }), flags());
    expect(d.code).toBe(3);
    expect(d.reasons).toEqual(["STRICT_SOURCES"]);
  });

  test("given --require-complete on a PARTIAL run, when decided, then exit 3 with REQUIRE_COMPLETE", () => {
    const d = decideExitCode(result({ findings: [], analysisStatus: "PARTIAL" }), flags({ requireComplete: true }));
    expect(d.code).toBe(3);
    expect(d.reasons).toEqual(["REQUIRE_COMPLETE"]);
  });

  test("given --require-complete on a COMPLETE run, when decided, then exit 0", () => {
    const d = decideExitCode(result({ findings: [], analysisStatus: "COMPLETE" }), flags({ requireComplete: true }));
    expect(d.code).toBe(0);
  });

  test("given a failed analysis, when decided, then exit 3 with ANALYSIS_FAILURE", () => {
    const d = decideExitCode(result({ findings: [], guards: guards({ analysisFailed: true }) }), flags());
    expect(d.code).toBe(3);
    expect(d.reasons).toEqual(["ANALYSIS_FAILURE"]);
  });
});

describe("precedence 3 > 1 (v3.2) with exitReasons co-occurrence (v3.5)", () => {
  test("given a REACHABLE finding AND the strict-sources guard, when decided, then exit 3 with BOTH reasons listed", () => {
    const r = result({ findings: [findingWithVerdict("REACHABLE")], guards: guards({ strictSources: true }) });
    const d = decideExitCode(r, flags());
    expect(d.code).toBe(3);
    expect(d.reasons).toEqual(["REACHABLE_FINDINGS", "STRICT_SOURCES"]);
  });

  test("given a REACHABLE finding AND the total-resolution guard, when decided, then exit 3 with BOTH reasons listed", () => {
    const r = result({ findings: [findingWithVerdict("REACHABLE")], guards: guards({ totalResolution: true }) });
    const d = decideExitCode(r, flags());
    expect(d.code).toBe(3);
    expect(d.reasons).toEqual(["REACHABLE_FINDINGS", "TOTAL_RESOLUTION_GUARD"]);
  });

  test("given a MALICIOUS finding AND a failed analysis, when decided, then exit 3 with BOTH reasons (the finding is retained in the report)", () => {
    const r = result({ findings: [findingWithVerdict("MALICIOUS_PACKAGE")], guards: guards({ analysisFailed: true }) });
    const d = decideExitCode(r, flags({ malware: "fail" }));
    expect(d.code).toBe(3);
    expect(d.reasons).toEqual(["ANALYSIS_FAILURE", "MALWARE_FAIL"]);
  });

  test("given REACHABLE + MALWARE_FAIL + OPAQUE_NATIVE_FAIL at once, when decided, then exit 1 with all three reasons", () => {
    const r = result({
      findings: [
        findingWithVerdict("REACHABLE"),
        findingWithVerdict("MALICIOUS_PACKAGE"),
        findingWithVerdict("NATIVE_OPAQUE", { nativeBoundary: "reached", opaque: true }),
      ],
    });
    const d = decideExitCode(r, flags({ opaqueNative: "fail" }));
    expect(d.code).toBe(1);
    expect(d.reasons).toEqual(["MALWARE_FAIL", "OPAQUE_NATIVE_FAIL", "REACHABLE_FINDINGS"]);
  });
});

describe("reachableFindings", () => {
  test("given the mixed finding set with default flags, when filtered, then only REACHABLE findings", () => {
    const f = [
      findingWithVerdict("REACHABLE"),
      findingWithVerdict("UNREACHABLE"),
      findingWithVerdict("APPLICABLE"),
      findingWithVerdict("MALICIOUS_PACKAGE"),
    ];
    const r = reachableFindings(f, flags());
    expect(r).toHaveLength(1);
    expect(r[0]?.verdict).toBe("REACHABLE");
  });

  test("given the sbom-only fail-on-applicable flags, when filtered, then APPLICABLE joins REACHABLE", () => {
    const f = [
      findingWithVerdict("APPLICABLE"),
      findingWithVerdict("UNREACHABLE"),
      findingWithVerdict("MALICIOUS_PACKAGE"),
    ];
    const r = reachableFindings(f, flags({ sbomOnly: true, failOnApplicable: true }));
    expect(r).toHaveLength(1);
    expect(r[0]?.verdict).toBe("APPLICABLE");
  });

  test("given an empty finding set, when filtered, then nothing", () => {
    expect(reachableFindings([], flags({ sbomOnly: true, failOnApplicable: true }))).toEqual([]);
  });
});
