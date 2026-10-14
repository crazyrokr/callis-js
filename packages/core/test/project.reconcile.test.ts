// M2 — reverse reconciliation (plan section 5.3 v3.5 item 1, ADR 0014).

import { describe, expect, test } from "bun:test";
import { unlistedInstalled } from "../src/project/reconcile.js";
import type { PackageInstance } from "../src/project/types.js";
import { sbomComponents } from "./project.fixtures.js";

function inst(name: string, version: string, relPath: string): PackageInstance {
  return {
    name,
    version,
    realDir: `/proj/${relPath}`,
    relPath,
    library: true,
    parent: null,
    pkgType: "commonjs",
  };
}

describe("reverse reconciliation (v3.5 item 1)", () => {
  test("given a loaded instance with no SBOM component, when reconciled, then it is unlisted (the stale-SBOM hole is visible)", () => {
    const components = sbomComponents([{ ref: "qs", name: "qs", version: "6.7.0" }]).components;
    const out = unlistedInstalled(
      [inst("qs", "6.7.0", "node_modules/qs"), inst("hidden", "1.0.0", "node_modules/hidden")],
      components,
      null,
    );
    expect(out).toEqual([
      { name: "hidden", version: "1.0.0", realDir: "/proj/node_modules/hidden", relPath: "node_modules/hidden" },
    ]);
  });

  test("given only the loaded set, when reconciled, then unloaded unlisted instances are NOT reported (no graph, no load set)", () => {
    const components = sbomComponents([{ ref: "qs", name: "qs", version: "6.7.0" }]).components;
    const loaded = new Set(["/proj/node_modules/qs"]);
    const out = unlistedInstalled(
      [inst("qs", "6.7.0", "node_modules/qs"), inst("hidden", "1.0.0", "node_modules/hidden")],
      components,
      loaded,
    );
    expect(out).toEqual([]);
  });

  test("given instances all covered by the SBOM, when reconciled, then nothing is unlisted", () => {
    const components = sbomComponents([
      { ref: "qs", name: "qs", version: "6.7.0" },
      { ref: "lodash", name: "lodash", version: "4.17.21" },
    ]).components;
    const out = unlistedInstalled(
      [inst("qs", "6.7.0", "node_modules/qs"), inst("lodash", "4.17.21", "node_modules/lodash")],
      components,
      null,
    );
    expect(out).toEqual([]);
  });

  test("given a version-drifted instance (SBOM 6.7.0, installed 6.8.0), when reconciled, then it IS unlisted by exact name+version (drift is visible, not silent)", () => {
    const components = sbomComponents([{ ref: "qs", name: "qs", version: "6.7.0" }]).components;
    const out = unlistedInstalled([inst("qs", "6.8.0", "node_modules/qs")], components, null);
    expect(out.map((u) => `${u.name}@${u.version}`)).toEqual(["qs@6.8.0"]);
  });

  test("given duplicate realpaths in the input, when reconciled, then each instance is reported once", () => {
    const a = inst("hidden", "1.0.0", "node_modules/hidden");
    const b = { ...a };
    const out = unlistedInstalled([a, b], sbomComponents([]).components, null);
    expect(out.length).toBe(1);
  });
});
