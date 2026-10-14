// M5 — candidate generation tests (plan section 5.6, v3.5 items 1/7/8).
//
// Given-When-Then over SBOM x OSV matching: range/versions match with the
// M1 boundary semantics, matchedOn (installed | sbom | both), source
// (sbom | installed), --match-installed gating on LOADED instances only,
// and dedup of (advisory, purl, source).

import { describe, expect, test } from "bun:test";
import { normalizeRange } from "../src/osv/matcher.js";
import type { PackageRecord } from "../src/osv/normalize.js";
import type { ComponentResolution } from "../src/project/tie.js";
import type { PackageInstance } from "../src/project/types.js";
import type { NpmComponent, SbomParseResult } from "../src/sbom/types.js";
import { buildCandidates, supplyRoot } from "../src/verdict/candidate.js";

function record(canonicalId: string, packageName: string, fixed: string, versions: string[] = []): PackageRecord {
  const range = normalizeRange({ type: "SEMVER", events: [{ introduced: "0" }, { fixed }] });
  return {
    sourceIds: [canonicalId],
    aliases: [],
    packageName,
    ecosystem: "npm",
    ranges: range === null ? [] : [range],
    versions,
    malicious: false,
    severity: "HIGH",
    summary: "s",
    canonicalId,
  } as PackageRecord;
}

function sbomOf(components: NpmComponent[], deps: SbomParseResult["dependencies"] = []): SbomParseResult {
  return {
    format: "CycloneDX",
    components,
    dependencies: deps,
    hasDevMarkers: components.some((c) => c.devOnly),
    warnings: [],
    fileSha256: "0".repeat(64),
    file: "/in/sbom.json",
  };
}

function component(name: string, version: string | undefined, devOnly = false, ref = name): NpmComponent {
  const purl = `pkg:npm/${name.toLowerCase()}${version !== undefined ? `@${version}` : ""}`;
  return { purl, name, ...(version !== undefined ? { version } : {}), devOnly, ref };
}

function instance(name: string, version: string, realDir: string): PackageInstance {
  return {
    name,
    version,
    realDir,
    relPath: realDir.replace("/inst/", ""),
    library: true,
    parent: null,
    pkgType: "commonjs",
  };
}

function resolution(
  purl: string,
  state: ComponentResolution["state"],
  instances: PackageInstance[] = [],
): ComponentResolution {
  return {
    component: { purl, name: purl.split("/")[2] as string },
    state,
    instances,
    triedDirs: [],
    graphSource: "absent",
  };
}

const inst = instance("lodash", "4.17.20", "/inst/node_modules/lodash");

describe("SBOM x OSV matching", () => {
  test("given an in-range SBOM component, when built, then a candidate exists with the SBOM evidence", () => {
    const s = sbomOf([component("lodash", "4.17.20")]);
    const res = new Map([["pkg:npm/lodash@4.17.20", resolution("pkg:npm/lodash@4.17.20", "RESOLVED", [inst])]]);
    const c = buildCandidates(s, [record("CVE-1", "lodash", "4.17.21")], res, {
      matchInstalled: false,
      loadedRealDirs: new Set([inst.realDir]),
      instances: [inst],
    });
    expect(c.length).toBe(1);
    expect(c[0]?.source).toBe("sbom");
    expect(c[0]?.matchedOn).toBe("sbom");
    expect(c[0]?.instance?.realDir).toBe(inst.realDir);
    expect(c[0]?.affectedRange).toContain("fixed:4.17.21");
  });

  test("given a component OUT of every range (SBOM AND installed), when built, then no candidate (the false-positive guard)", () => {
    const patched = instance("lodash", "4.17.21", "/inst/node_modules/lodash");
    const s = sbomOf([component("lodash", "4.17.21")]);
    const res = new Map([["pkg:npm/lodash@4.17.21", resolution("pkg:npm/lodash@4.17.21", "RESOLVED", [patched])]]);
    const c = buildCandidates(s, [record("CVE-1", "lodash", "4.17.21")], res, {
      matchInstalled: false,
      loadedRealDirs: new Set(),
      instances: [patched],
    });
    expect(c.length).toBe(0);
  });

  test("given an explicit-versions record, when the version matches, then a candidate exists", () => {
    const s = sbomOf([component("minimist", "1.2.5")]);
    const res = new Map([["pkg:npm/minimist@1.2.5", resolution("pkg:npm/minimist@1.2.5", "RESOLVED", [inst])]]);
    const c = buildCandidates(s, [record("CVE-2", "minimist", "999", ["1.2.5"])], res, {
      matchInstalled: false,
      loadedRealDirs: new Set(),
      instances: [inst],
    });
    expect(c.length).toBe(1);
    expect(c[0]?.affectedRange).toContain("versions:{1.2.5}");
  });

  test("given a non-npm record, when built, then it never matches", () => {
    const s = sbomOf([component("lodash", "4.17.20")]);
    const rec = record("CVE-3", "lodash", "4.17.21");
    rec.ecosystem = "maven";
    const c = buildCandidates(s, [rec], new Map(), { matchInstalled: false, loadedRealDirs: new Set(), instances: [] });
    expect(c.length).toBe(0);
  });
});

describe("matchedOn (v3.5 item 8: stale-SBOM range drift)", () => {
  test("given SBOM version out of range but INSTALLED version in range, when built, then the finding is kept with matchedOn: installed and both versions", () => {
    const sbomInst = instance("qs", "6.7.0", "/inst/node_modules/qs");
    const s = sbomOf([component("qs", "6.7.2")]);
    const res = new Map([["pkg:npm/qs@6.7.2", resolution("pkg:npm/qs@6.7.2", "VERSION_MISMATCH", [sbomInst])]]);
    const c = buildCandidates(s, [record("CVE-4", "qs", "6.7.1")], res, {
      matchInstalled: false,
      loadedRealDirs: new Set([sbomInst.realDir]),
      instances: [sbomInst],
    });
    expect(c.length).toBe(1);
    expect(c[0]?.matchedOn).toBe("installed");
    expect(c[0]?.componentVersion).toBe("6.7.2");
    expect(c[0]?.instance?.version).toBe("6.7.0");
  });
});

describe("--match-installed (v3.5 item 1)", () => {
  test("given an instance the SBOM never listed, LOADED, when built, then an installed-source candidate exists", () => {
    const hidden = instance("hidden-pkg", "2.0.0", "/inst/node_modules/hidden-pkg");
    const s = sbomOf([component("other", "1.0.0")]);
    const c = buildCandidates(s, [record("CVE-5", "hidden-pkg", "2.1.0")], new Map(), {
      matchInstalled: true,
      loadedRealDirs: new Set([hidden.realDir]),
      instances: [hidden],
    });
    expect(c.length).toBe(1);
    expect(c[0]?.source).toBe("installed");
    expect(c[0]?.matchedOn).toBe("installed");
    expect(c[0]?.ref).toBe("");
  });

  test("given the same instance NOT loaded, when built, then no candidate (an unlisted package never imported cannot reach)", () => {
    const hidden = instance("hidden-pkg", "2.0.0", "/inst/node_modules/hidden-pkg");
    const s = sbomOf([component("other", "1.0.0")]);
    const c = buildCandidates(s, [record("CVE-5", "hidden-pkg", "2.1.0")], new Map(), {
      matchInstalled: true,
      loadedRealDirs: new Set(),
      instances: [hidden],
    });
    expect(c.length).toBe(0);
  });

  test("given an instance the SBOM DID list, when built, then no installed-source duplicate (the SBOM candidate stays, once)", () => {
    const s = sbomOf([component("lodash", "4.17.20")]);
    const c = buildCandidates(s, [record("CVE-1", "lodash", "4.17.21")], new Map(), {
      matchInstalled: true,
      loadedRealDirs: new Set([inst.realDir]),
      instances: [inst],
    });
    expect(c.length).toBe(1);
    expect(c[0]?.source).toBe("sbom");
  });
});

describe("supplyRoot", () => {
  test("given a dependency chain, when resolved, then the first reaching root wins (lexicographic)", () => {
    const deps = [
      { ref: "app", dependsOn: ["express"] },
      { ref: "express", dependsOn: ["qs"] },
      { ref: "zroot", dependsOn: ["qs"] },
    ];
    expect(supplyRoot(deps, "qs")).toBe("app");
    expect(supplyRoot(deps, "missing")).toBeNull();
  });

  test("given a ref that is itself a root, when resolved, then the ref itself (a ref absent from the SBOM has no root)", () => {
    expect(supplyRoot([{ ref: "a", dependsOn: [] }], "a")).toBe("a");
    expect(supplyRoot([], "a")).toBeNull();
  });
});
