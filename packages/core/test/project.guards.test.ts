// M2 — fail-visibly guards (plan sections 1, 5.3, ADR 0014).

import { describe, expect, test } from "bun:test";
import { allDevNotice, emptySbomGuard, totalResolutionGuard } from "../src/project/guards.js";
import type { ComponentResolution } from "../src/project/tie.js";
import { sbomComponents } from "./project.fixtures.js";

function res(name: string, version: string, state: ComponentResolution["state"]): ComponentResolution {
  return {
    component: { purl: `pkg:npm/${name}@${version}`, name, version },
    state,
    instances: [],
    triedDirs: ["/proj/node_modules"],
    graphSource: "absent",
  };
}

describe("empty-SBOM guard (plan v3.4 item 12, v3.5 item 6)", () => {
  test("given zero npm components, when checked, then the guard fires (exit 3)", () => {
    const g = emptySbomGuard(sbomComponents([]).components, false);
    expect(g.fail).toBe(true);
    expect(g.message).toContain("--allow-empty-sbom");
  });

  test("given zero npm components with the opt-out, when checked, then the guard does not fire", () => {
    expect(emptySbomGuard(sbomComponents([]).components, true).fail).toBe(false);
  });

  test("given at least one npm component, when checked, then the guard does not fire", () => {
    const sbom = sbomComponents([{ ref: "qs", name: "qs", version: "6.7.0" }]);
    expect(emptySbomGuard(sbom.components, false).fail).toBe(false);
  });

  test("given an all-dev SBOM, when checked, then it is NOT empty (exit 0 with the notice)", () => {
    const sbom = sbomComponents([{ ref: "jest", name: "jest", version: "29.0.0", devOnly: true }]);
    expect(emptySbomGuard(sbom.components, false).fail).toBe(false);
    expect(allDevNotice(sbom.components)).toBe("all components dev-only — use --include-dev to analyze them");
  });

  test("given a mixed dev/prod SBOM, when checked, then no all-dev notice is emitted", () => {
    const sbom = sbomComponents([
      { ref: "jest", name: "jest", version: "29.0.0", devOnly: true },
      { ref: "qs", name: "qs", version: "6.7.0" },
    ]);
    expect(allDevNotice(sbom.components)).toBeNull();
  });
});

describe("total-resolution guard (plan v3.1, defined over components v3.2)", () => {
  test("given every analyzable component non-RESOLVED, when checked, then the guard fires with the minimal-report input", () => {
    const g = totalResolutionGuard([res("a", "1", "MISSING"), res("b", "2", "VERSION_MISMATCH")], false);
    expect(g.fail).toBe(true);
    expect(g.components?.map((c) => c.purl)).toEqual(["pkg:npm/a@1", "pkg:npm/b@2"]);
    expect(g.components?.every((c) => c.triedDirs.length > 0)).toBe(true);
  });

  test("given at least one RESOLVED component, when checked, then the guard does not fire (partial resolution is PARTIAL, not broken)", () => {
    const g = totalResolutionGuard([res("a", "1", "RESOLVED"), res("b", "2", "MISSING")], false);
    expect(g.fail).toBe(false);
  });

  test("given no analyzable components (all NOT_CHECKED), when checked, then the guard does not fire", () => {
    const g = totalResolutionGuard([res("a", "1", "NOT_CHECKED")], false);
    expect(g.fail).toBe(false);
  });

  test("given --strict-sources with ANY non-RESOLVED component, when checked, then the guard fires (mismatch and ambiguity included)", () => {
    const g = totalResolutionGuard([res("a", "1", "RESOLVED"), res("b", "2", "AMBIGUOUS")], true);
    expect(g.fail).toBe(true);
    expect(g.components?.map((c) => c.state)).toContain("AMBIGUOUS");
  });

  test("given --strict-sources with all RESOLVED, when checked, then the guard does not fire", () => {
    expect(totalResolutionGuard([res("a", "1", "RESOLVED"), res("b", "2", "RESOLVED")], true).fail).toBe(false);
  });

  test("given a drifted install (VERSION_MISMATCH is non-RESOLVED), when checked without strict, then the guard fires only when EVERY analyzable component is non-RESOLVED", () => {
    expect(totalResolutionGuard([res("a", "1", "VERSION_MISMATCH")], false).fail).toBe(true);
    expect(totalResolutionGuard([res("a", "1", "VERSION_MISMATCH"), res("b", "2", "RESOLVED")], false).fail).toBe(
      false,
    );
  });
});
