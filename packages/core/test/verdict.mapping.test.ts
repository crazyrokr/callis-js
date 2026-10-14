// M5 — vuln-mappings tests (plan section 5.6, ADR 0013).
//
// Given-When-Then over the mapping contract: malformed documents reject
// (exit 2 material), target resolution addresses graph nodes (export via
// the loaded functions, file+function for internals), import-time targets
// are detected through module-init reachability, package mismatches skip.

import { describe, expect, test } from "bun:test";
import type { CallGraph } from "../src/callgraph/types.js";
import type { PackageRecord } from "../src/osv/normalize.js";
import { UsageError } from "../src/util/errors.js";
import { parseMappings, resolveMappingTargets } from "../src/verdict/mapping.js";

const PKG = "/inst/lodash";

function graphOf(nodes: CallGraph["nodes"], edges: CallGraph["edges"] = []): CallGraph {
  return {
    nodes,
    edges,
    markers: [],
    entryPoints: [],
    stats: { modules: 1, nodes: nodes.length, edges: edges.length, dynamicMarkers: 0, unscopedMarkers: 0 },
  };
}

const fn = (file: string, name: string) => ({ id: `${file}#${name}`, kind: "function" as const, file, name, line: 1 });
const init = (file: string) => ({
  id: `${file}#<module-init>`,
  kind: "module-init" as const,
  file,
  name: "<module-init>",
  line: 0,
});

const record = (canonicalId: string, packageName: string): PackageRecord =>
  ({
    sourceIds: [canonicalId],
    aliases: [],
    packageName,
    ecosystem: "npm",
    ranges: [],
    versions: [],
    malicious: false,
    severity: "HIGH",
    summary: "s",
    canonicalId,
  }) as PackageRecord;

describe("parseMappings (malformed => exit 2 material)", () => {
  test("given a well-formed document, when parsed, then entries keep their targets", () => {
    const m = parseMappings({
      CVE_A: [{ package: "lodash", export: "template" }],
      CVE_B: [{ package: "foo", file: "lib/parse.js", function: "parseHeader" }],
    });
    expect(m.get("CVE_A")?.[0]?.export).toBe("template");
    expect(m.get("CVE_B")?.[0]?.file).toBe("lib/parse.js");
    expect(m.get("CVE_B")?.[0]?.function).toBe("parseHeader");
  });

  test("given a non-object document or a non-array value, when parsed, then it throws UsageError", () => {
    expect(() => parseMappings(null)).toThrow(UsageError);
    expect(() => parseMappings([])).toThrow(UsageError);
    expect(() => parseMappings({ A: "not-an-array" })).toThrow(UsageError);
    expect(() => parseMappings({ A: [42] })).toThrow(UsageError);
  });

  test("given entries with missing package, wrong types, file without function, or no target, when parsed, then they throw", () => {
    expect(() => parseMappings({ A: [{ export: "x" }] })).toThrow(UsageError);
    expect(() => parseMappings({ A: [{ package: "p", export: 5 }] })).toThrow(UsageError);
    expect(() => parseMappings({ A: [{ package: "p", file: "a.js" }] })).toThrow(UsageError);
    expect(() => parseMappings({ A: [{ package: "p", file: "a.js", function: "" }] })).toThrow(UsageError);
    expect(() => parseMappings({ A: [{ package: "p" }] })).toThrow(UsageError);
  });

  test("given absolute or parent-traversing file paths, when parsed, then they throw (package-relative only)", () => {
    expect(() => parseMappings({ A: [{ package: "p", file: "/etc/passwd", function: "x" }] })).toThrow(UsageError);
    expect(() => parseMappings({ A: [{ package: "p", file: "../x.js", function: "x" }] })).toThrow(UsageError);
  });
});

describe("resolveMappingTargets", () => {
  test("given an export target present in the instance, when resolved, then the function node is returned", () => {
    const g = graphOf([fn(`${PKG}/lodash.js`, "template"), fn(`${PKG}/lodash.js`, "chunk")]);
    const m = parseMappings({ CVE_A: [{ package: "lodash", export: "template" }] });
    const t = resolveMappingTargets(record("CVE_A", "lodash"), m, g, PKG);
    expect(t.length).toBe(1);
    expect(t[0]?.nodeId).toBe(`${PKG}/lodash.js#template`);
    expect(t[0]?.importTime).toBe(false);
  });

  test("given an export target ABSENT from the graph, when resolved, then nothing is returned (UNREACHABLE material, not an error)", () => {
    const g = graphOf([fn(`${PKG}/lodash.js`, "chunk")]);
    const m = parseMappings({ CVE_A: [{ package: "lodash", export: "template" }] });
    expect(resolveMappingTargets(record("CVE_A", "lodash"), m, g, PKG).length).toBe(0);
  });

  test("given a file+function target, when resolved, then the exact node is addressed (or null when absent)", () => {
    const g = graphOf([fn(`${PKG}/lib/parse.js`, "parseHeader")]);
    const m = parseMappings({ CVE_B: [{ package: "lodash", file: "lib/parse.js", function: "parseHeader" }] });
    const t = resolveMappingTargets(record("CVE_B", "lodash"), m, g, PKG);
    expect(t[0]?.nodeId).toBe(`${PKG}/lib/parse.js#parseHeader`);
    const missing = parseMappings({ CVE_C: [{ package: "lodash", file: "lib/nope.js", function: "nope" }] });
    const t2 = resolveMappingTargets(record("CVE_C", "lodash"), missing, g, PKG);
    expect(t2[0]?.nodeId).toBeNull();
  });

  test("given a target reached from the instance module-init, when resolved, then importTime is true", () => {
    const g = graphOf(
      [init(`${PKG}/index.js`), fn(`${PKG}/index.js`, "boot"), fn(`${PKG}/lib/vuln.js`, "vuln")],
      [
        { from: `${PKG}/index.js#<module-init>`, to: `${PKG}/index.js#boot`, kind: "call", line: 1 },
        { from: `${PKG}/index.js#boot`, to: `${PKG}/lib/vuln.js#vuln`, kind: "call", line: 2 },
      ],
    );
    const m = parseMappings({ CVE_D: [{ package: "lodash", file: "lib/vuln.js", function: "vuln" }] });
    const t = resolveMappingTargets(record("CVE_D", "lodash"), m, g, PKG);
    expect(t.length).toBe(1);
    expect(t[0]?.importTime).toBe(true);
  });

  test("given a mapping for ANOTHER package, when resolved, then nothing is returned (package mismatch skips)", () => {
    const g = graphOf([fn(`${PKG}/lodash.js`, "template")]);
    const m = parseMappings({ CVE_E: [{ package: "other", export: "template" }] });
    expect(resolveMappingTargets(record("CVE_E", "lodash"), m, g, PKG).length).toBe(0);
  });

  test("given a mapping id with no entries at all, when resolved, then nothing is returned", () => {
    const g = graphOf([fn(`${PKG}/lodash.js`, "template")]);
    const m = parseMappings({});
    expect(resolveMappingTargets(record("CVE_F", "lodash"), m, g, PKG).length).toBe(0);
  });
});
