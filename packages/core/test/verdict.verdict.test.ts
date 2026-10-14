// M5 — verdict decision tests (plan section 5.6, ADRs 0012-0013).
//
// Given-When-Then over the verdict precedence: MALICIOUS_PACKAGE regardless
// of dev scope, DEV_ONLY, NO_SOURCE, --sbom-only APPLICABLE, the evidence
// tier (call/load, callEvidence any/direct), mapping-level precision
// (PRECISE/NAME_BASED, import-time below the tier, absent target =>
// UNREACHABLE), NATIVE_OPAQUE (reached boundary), and the --sbom-only
// contract (no REACHABLE/UNREACHABLE without a graph).

import { describe, expect, test } from "bun:test";
import type { CallGraph } from "../src/callgraph/types.js";
import type { PackageRecord } from "../src/osv/normalize.js";
import type { ComponentResolution } from "../src/project/tie.js";
import type { PackageInstance } from "../src/project/types.js";
import { parseMappings } from "../src/verdict/mapping.js";
import type { Candidate } from "../src/verdict/types.js";
import { type VerdictOptions, decideVerdict, unmappedIds } from "../src/verdict/verdict.js";

const PKG = "/inst/node_modules/vulnpkg";
const APP = "/proj/src";

function graphOf(nodes: CallGraph["nodes"], edges: CallGraph["edges"] = []): CallGraph {
  return {
    nodes,
    edges,
    markers: [],
    entryPoints: [{ file: `${APP}/main.js`, name: "main", source: "main", line: 1 }],
    stats: { modules: 2, nodes: nodes.length, edges: edges.length, dynamicMarkers: 0, unscopedMarkers: 0 },
  };
}

const fn = (file: string, name: string) => ({ id: `${file}#${name}`, kind: "function" as const, file, name, line: 1 });

const inst = {
  name: "vulnpkg",
  version: "1.0.0",
  realDir: PKG,
  relPath: "node_modules/vulnpkg",
  library: true,
  parent: null,
  pkgType: "commonjs",
} satisfies PackageInstance;

function record(canonicalId: string, malicious = false): PackageRecord {
  return {
    sourceIds: [canonicalId],
    aliases: [`${canonicalId}-alias`],
    packageName: "vulnpkg",
    ecosystem: "npm",
    ranges: [],
    versions: [],
    malicious,
    severity: "HIGH",
    summary: "bad",
    canonicalId,
  } as PackageRecord;
}

function resolution(state: ComponentResolution["state"] = "RESOLVED"): ComponentResolution {
  return {
    component: { purl: "pkg:npm/vulnpkg@1.0.0", name: "vulnpkg", version: "1.0.0" },
    state,
    instances: [inst],
    triedDirs: [],
    graphSource: "absent",
  };
}

function candidate(record: PackageRecord, devOnly = false): Candidate {
  return {
    record,
    purl: "pkg:npm/vulnpkg@1.0.0",
    component: "vulnpkg",
    componentVersion: "1.0.0",
    devOnly,
    ref: "ref-vulnpkg",
    matchedOn: "sbom",
    source: "sbom",
    affectedRange: "[introduced:0 fixed:1.0.1]",
    resolution: resolution(),
    instance: inst,
  };
}

function opts(over: Partial<VerdictOptions> = {}): VerdictOptions {
  const base: VerdictOptions = {
    packageEvidence: "call",
    callEvidence: "any",
    includeDev: false,
    sbomOnly: false,
    mappings: new Map(),
    entryRoots: [`${APP}/main.js#main`],
    graph: null,
    loadedRealDirs: new Set([PKG]),
    nativeRealDirs: new Set(),
  };
  return { ...base, ...over };
}

// The app main calls the package's vulnerable function.
const CALLED = graphOf(
  [
    fn(`${APP}/main.js`, "main"),
    fn(`${PKG}/index.js`, "vuln"),
    {
      id: `${PKG}/index.js#<module-init>`,
      kind: "module-init",
      file: `${PKG}/index.js`,
      name: "<module-init>",
      line: 0,
    },
  ],
  [
    { from: `${APP}/main.js#main`, to: `${PKG}/index.js#vuln`, kind: "call", line: 2 },
    { from: `${APP}/main.js#<module-init>`, to: `${PKG}/index.js#<module-init>`, kind: "import", line: 1 },
  ],
);

describe("verdict precedence", () => {
  test("given a MAL-* record on a dev component, when decided, then MALICIOUS_PACKAGE regardless of dev scope (v3.1)", () => {
    const f = decideVerdict(candidate(record("MAL-1", true), true), [], opts());
    expect(f.verdict).toBe("MALICIOUS_PACKAGE");
  });

  test("given a dev component without --include-dev, when decided, then DEV_ONLY (the malware gate above is unaffected)", () => {
    const f = decideVerdict(candidate(record("CVE-1"), true), [], opts());
    expect(f.verdict).toBe("DEV_ONLY");
    const f2 = decideVerdict(candidate(record("CVE-1"), true), [], opts({ includeDev: true }));
    expect(f2.verdict).not.toBe("DEV_ONLY");
  });

  test("given a component with no instance on disk, when decided, then NO_SOURCE", () => {
    const c = candidate(record("CVE-1"));
    c.instance = null;
    c.resolution = { ...resolution("MISSING"), instances: [] };
    const f = decideVerdict(c, [], opts({ graph: CALLED }));
    expect(f.verdict).toBe("NO_SOURCE");
    expect(f.installed).toBe(false);
  });

  test("given a non-malicious advisory under --sbom-only, when decided, then APPLICABLE (no REACHABLE/UNREACHABLE without a graph; resolution not performed)", () => {
    const c = candidate(record("CVE-1"));
    c.resolution = null;
    const f = decideVerdict(c, [], opts({ sbomOnly: true }));
    expect(f.verdict).toBe("APPLICABLE");
    expect(f.resolutionState).toBe("NOT_CHECKED");
    const dev = candidate(record("CVE-1"), false);
    dev.resolution = null;
    expect(decideVerdict(dev, [], opts({ sbomOnly: true })).verdict).toBe("APPLICABLE");
  });
});

describe("evidence tiers", () => {
  test("given a called package function at the default call tier, when decided, then REACHABLE (artifact level) with a trace", () => {
    const f = decideVerdict(candidate(record("CVE-1")), [], opts({ graph: CALLED }));
    expect(f.verdict).toBe("REACHABLE");
    expect(f.matchLevel).toBe("artifact");
    expect(f.confidence).toBe("PRECISE");
    expect(f.evidence.called).toBe(true);
    expect(f.path.length).toBeGreaterThan(1);
    expect(f.path[f.path.length - 1]).toBe(`${PKG}/index.js#vuln`);
  });

  test("given a package loaded but never called at the default call tier, when decided, then UNREACHABLE with evidence.loaded (loaded-not-called)", () => {
    const g = graphOf(
      [
        fn(`${APP}/main.js`, "main"),
        fn(`${PKG}/index.js`, "vuln"),
        {
          id: `${PKG}/index.js#<module-init>`,
          kind: "module-init",
          file: `${PKG}/index.js`,
          name: "<module-init>",
          line: 0,
        },
      ],
      [{ from: `${APP}/main.js#<module-init>`, to: `${PKG}/index.js#<module-init>`, kind: "import", line: 1 }],
    );
    const f = decideVerdict(candidate(record("CVE-1")), [], opts({ graph: g }));
    expect(f.verdict).toBe("UNREACHABLE");
    expect(f.evidence.loaded).toBe(true);
    expect(f.evidence.called).toBe(false);
  });

  test("given the same loaded package at the load tier, when decided, then REACHABLE (import evidence meets the load tier)", () => {
    const g = graphOf(
      [
        fn(`${APP}/main.js`, "main"),
        fn(`${PKG}/index.js`, "vuln"),
        {
          id: `${PKG}/index.js#<module-init>`,
          kind: "module-init",
          file: `${PKG}/index.js`,
          name: "<module-init>",
          line: 0,
        },
      ],
      [{ from: `${APP}/main.js#<module-init>`, to: `${PKG}/index.js#<module-init>`, kind: "import", line: 1 }],
    );
    const f = decideVerdict(candidate(record("CVE-1")), [], opts({ graph: g, packageEvidence: "load" }));
    expect(f.verdict).toBe("REACHABLE");
  });

  test("given a registered callback handler under callEvidence=any, when decided, then REACHABLE; under callEvidence=direct, then UNREACHABLE", () => {
    const g = graphOf(
      [fn(`${APP}/main.js`, "main"), fn(`${APP}/main.js`, "subscribe"), fn(`${PKG}/index.js`, "handler")],
      [
        { from: `${APP}/main.js#main`, to: `${APP}/main.js#subscribe`, kind: "call", line: 2 },
        { from: `${APP}/main.js#subscribe`, to: `${PKG}/index.js#handler`, kind: "call", line: 3, via: "model:emit" },
      ],
    );
    const any = decideVerdict(candidate(record("CVE-1")), [], opts({ graph: g, callEvidence: "any" }));
    expect(any.verdict).toBe("REACHABLE");
    expect(any.evidence.callbackRegistered).toBe(true);
    const direct = decideVerdict(candidate(record("CVE-1")), [], opts({ graph: g, callEvidence: "direct" }));
    expect(direct.verdict).toBe("UNREACHABLE");
  });
});

describe("mapping-level precision", () => {
  const mappings = parseMappings({ "CVE-2": [{ package: "vulnpkg", export: "vuln" }] });

  test("given a mapping target reached by precise edges, when decided, then REACHABLE method-level PRECISE", () => {
    const f = decideVerdict(candidate(record("CVE-2")), [], opts({ graph: CALLED, mappings }));
    expect(f.verdict).toBe("REACHABLE");
    expect(f.matchLevel).toBe("method");
    expect(f.confidence).toBe("PRECISE");
  });

  test("given a path using a name-based fallback edge (--cha), when decided, then confidence NAME_BASED", () => {
    const g = graphOf(
      [fn(`${APP}/main.js`, "main"), fn(`${APP}/main.js`, "x"), fn(`${PKG}/index.js`, "vuln")],
      [
        { from: `${APP}/main.js#main`, to: `${APP}/main.js#x`, kind: "call", line: 2 },
        { from: `${APP}/main.js#x`, to: `${PKG}/index.js#vuln`, kind: "call", line: 3, via: "cha" },
      ],
    );
    const f = decideVerdict(candidate(record("CVE-2")), [], opts({ graph: g, mappings }));
    expect(f.verdict).toBe("REACHABLE");
    expect(f.confidence).toBe("NAME_BASED");
  });

  test("given a mapping target executing at IMPORT TIME below the call tier, when decided, then REACHABLE (absence of a call edge is not evidence of non-execution)", () => {
    const g = graphOf(
      [
        fn(`${APP}/main.js`, "main"),
        fn(`${PKG}/index.js`, "boot"),
        fn(`${PKG}/lib/vuln.js`, "vuln"),
        {
          id: `${PKG}/index.js#<module-init>`,
          kind: "module-init",
          file: `${PKG}/index.js`,
          name: "<module-init>",
          line: 0,
        },
      ],
      [
        { from: `${APP}/main.js#<module-init>`, to: `${PKG}/index.js#<module-init>`, kind: "import", line: 1 },
        { from: `${PKG}/index.js#<module-init>`, to: `${PKG}/index.js#boot`, kind: "call", line: 2 },
        { from: `${PKG}/index.js#boot`, to: `${PKG}/lib/vuln.js#vuln`, kind: "call", line: 3 },
      ],
    );
    const m = parseMappings({ "CVE-3": [{ package: "vulnpkg", file: "lib/vuln.js", function: "vuln" }] });
    const f = decideVerdict(candidate(record("CVE-3")), [], opts({ graph: g, mappings: m }));
    expect(f.verdict).toBe("REACHABLE");
    expect(f.matchLevel).toBe("method");
    expect(f.evidence.called).toBe(false);
  });

  test("given a mapping present but its target NOT reached and not import-time, when decided, then UNREACHABLE (not an error)", () => {
    const g = graphOf([fn(`${APP}/main.js`, "main"), fn(`${PKG}/index.js`, "vuln")], []);
    const f = decideVerdict(candidate(record("CVE-2")), [], opts({ graph: g, mappings }));
    expect(f.verdict).toBe("UNREACHABLE");
    expect(f.matchLevel).toBe("method");
  });

  test("given a mapping whose target is absent from the graph, when decided, then UNREACHABLE (a mapping entry absent from the call graph is UNREACHABLE, not an error)", () => {
    const g = graphOf([fn(`${APP}/main.js`, "main"), fn(`${PKG}/index.js`, "other")], []);
    const f = decideVerdict(candidate(record("CVE-2")), [], opts({ graph: g, mappings }));
    expect(f.verdict).toBe("UNREACHABLE");
  });
});

describe("native opacity (v3.4 item 11)", () => {
  test("given a loaded native package below the tier, when decided, then NATIVE_OPAQUE reached (the boundary crossing is the only evidence)", () => {
    const g = graphOf(
      [
        fn(`${APP}/main.js`, "main"),
        fn(`${PKG}/index.js`, "vuln"),
        {
          id: `${PKG}/index.js#<module-init>`,
          kind: "module-init",
          file: `${PKG}/index.js`,
          name: "<module-init>",
          line: 0,
        },
      ],
      [{ from: `${APP}/main.js#<module-init>`, to: `${PKG}/index.js#<module-init>`, kind: "import", line: 1 }],
    );
    const f = decideVerdict(candidate(record("CVE-1")), [], opts({ graph: g, nativeRealDirs: new Set([PKG]) }));
    expect(f.verdict).toBe("NATIVE_OPAQUE");
    expect(f.nativeBoundary).toBe("reached");
    expect(f.opaque).toBe(true);
  });

  test("given a native package whose tier IS met (a call into its JS wrapper), when decided, then REACHABLE wins over NATIVE_OPAQUE", () => {
    const f = decideVerdict(candidate(record("CVE-1")), [], opts({ graph: CALLED, nativeRealDirs: new Set([PKG]) }));
    expect(f.verdict).toBe("REACHABLE");
  });

  test("given an unloaded native package, when decided, then UNREACHABLE (never a boundary: the path does not even reach the package)", () => {
    const g = graphOf([fn(`${APP}/main.js`, "main")], []);
    const f = decideVerdict(
      candidate(record("CVE-1")),
      [],
      opts({ graph: g, nativeRealDirs: new Set([PKG]), loadedRealDirs: new Set() }),
    );
    expect(f.verdict).toBe("UNREACHABLE");
  });
});

describe("unmappedIds", () => {
  test("given a mapping id matching no candidate, when checked, then a warning (never fatal)", () => {
    const w = unmappedIds(
      new Map([
        ["CVE-X", []],
        ["CVE-1", []],
      ]),
      [record("CVE-1")],
    );
    expect(w.length).toBe(1);
    expect(w[0]).toContain("CVE-X");
  });
});
