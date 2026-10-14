// M2 fixture matrix — per-component resolution states + tie graph
// (plan section 5.3 v3.3/v3.4/v3.5, ADR 0014).

import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { npmLockfileGraph, pnpmLockfileGraph } from "../src/project/lockfile.js";
import { buildProjectModel } from "../src/project/scan.js";
import { allComponentResolutions, componentResolution, tieGraphFor } from "../src/project/tie.js";
import type { PackageInstance, ProjectModel, TieGraph, TieNode } from "../src/project/types.js";
import { mkFixture, pkg, sbomComponents } from "./project.fixtures.js";

function inst(name: string, version: string, relPath: string, realDir?: string): PackageInstance {
  return {
    name,
    version,
    realDir: realDir ?? `/proj/${relPath}`,
    relPath,
    library: true,
    parent: null,
    pkgType: "commonjs",
  };
}

function graphOf(source: TieGraph["source"], nodes: TieNode[] = [], edges: [string, string][] = []): TieGraph {
  return { source, nodes: new Map(nodes.map((n) => [n.key, n])), edges };
}

const model = (instances: PackageInstance[], installRoot = "/proj"): ProjectModel => ({
  root: "/proj",
  layout: "npm",
  workspaces: [],
  instances,
  scannedDirs: [join(installRoot, "node_modules")],
  installRoot,
});

const comp = (name: string, version?: string, ref = name) => {
  const c: { purl: string; name: string; version?: string; ref: string } = {
    purl: `pkg:npm/${name}@${version ?? "x"}`,
    name,
    ref,
  };
  if (version !== undefined) c.version = version;
  return c;
};

describe("tie graph selection (ADR 0014)", () => {
  test("given an SBOM with dependencies[], when selected, then the sbom graph is used", () => {
    const sbom = sbomComponents(
      [
        { ref: "app", name: "app" },
        { ref: "lodash", name: "lodash", version: "4.17.21" },
      ],
      [{ ref: "app", dependsOn: ["lodash"] }],
    );
    const g = tieGraphFor(sbom, null);
    expect(g.source).toBe("sbom");
    expect(g.nodes.get("lodash")?.version).toBe("4.17.21");
    expect(g.edges).toEqual([["app", "lodash"]]);
  });

  test("given an SBOM without dependencies[] and a lockfile graph, when selected, then the lockfile graph is used", () => {
    const sbom = sbomComponents([{ ref: "lodash", name: "lodash", version: "4.17.21" }]);
    const lock = graphOf("lockfile", [
      { key: "node_modules/lodash", name: "lodash", version: "4.17.21", path: "node_modules/lodash" },
    ]);
    expect(tieGraphFor(sbom, lock).source).toBe("lockfile");
  });

  test("given no SBOM dependencies[] and no lockfile graph, when selected, then the graph is absent", () => {
    const sbom = sbomComponents([{ ref: "lodash", name: "lodash", version: "4.17.21" }]);
    expect(tieGraphFor(sbom, null).source).toBe("absent");
  });
});

describe("resolution states (plan 5.3 v3.3)", () => {
  test("given a name+version on disk, when resolved, then the state is RESOLVED", () => {
    const m = model([inst("lodash", "4.17.21", "node_modules/lodash")]);
    const r = componentResolution(comp("lodash", "4.17.21"), m, graphOf("absent"));
    expect(r.state).toBe("RESOLVED");
    expect(r.instances.length).toBe(1);
  });

  test("given no instance with that name, when resolved, then the state is MISSING", () => {
    const m = model([inst("qs", "6.7.0", "node_modules/qs")]);
    const r = componentResolution(comp("lodash", "4.17.21"), m, graphOf("absent"));
    expect(r.state).toBe("MISSING");
    expect(r.instances).toEqual([]);
  });

  test("given a drifted install (name present, version differs), when resolved, then the state is VERSION_MISMATCH with the installed instances", () => {
    const m = model([inst("lodash", "4.17.21", "node_modules/lodash")]);
    const r = componentResolution(comp("lodash", "4.17.20"), m, graphOf("absent"));
    expect(r.state).toBe("VERSION_MISMATCH");
    expect(r.instances.map((i) => i.version)).toEqual(["4.17.21"]);
  });

  test("given duplicate instances (same name+version, different dirs), when resolved with an ABSENT graph, then they stay separate instances, never AMBIGUOUS", () => {
    const m = model([
      inst("lodash", "4.17.21", "node_modules/lodash"),
      inst("lodash", "4.17.21", "node_modules/a/node_modules/lodash"),
    ]);
    const r = componentResolution(comp("lodash", "4.17.21"), m, graphOf("absent"));
    expect(r.state).toBe("RESOLVED");
    expect(r.instances.length).toBe(2);
    expect(r.graphSource).toBe("absent");
  });

  test("given pnpm peer-variant duplicates, when resolved, then each keeps its own identity (no collapse, no AMBIGUOUS)", () => {
    const m = model([
      inst("lodash", "4.17.21", "node_modules/.pnpm/lodash@4.17.21/node_modules/lodash"),
      inst("lodash", "4.17.21", "node_modules/.pnpm/lodash@4.17.21_lodash.merge@4.7.4/node_modules/lodash"),
    ]);
    const r = componentResolution(comp("lodash", "4.17.21"), m, graphOf("absent"));
    expect(r.state).toBe("RESOLVED");
    expect(r.instances.length).toBe(2);
  });

  test("given a component not in the lockfile but an instance node on disk, when resolved with a lockfile graph, then it stays tied (never AMBIGUOUS for on-disk evidence)", () => {
    const m = model([inst("lodash", "4.17.21", "node_modules/lodash", "/proj/node_modules/lodash")]);
    const g = graphOf("lockfile", [
      { key: "", name: "" },
      { key: "node_modules/qs", name: "qs", version: "6.7.0", path: "node_modules/qs" },
      { key: "node_modules/lodash", name: "lodash", version: "4.17.21", path: "node_modules/lodash" },
    ]);
    const r = componentResolution(comp("lodash", "4.17.21"), m, g);
    expect(r.state).toBe("RESOLVED");
  });

  test("given a lockfile graph whose path matches no on-disk instance and no node for the component, when resolved, then the state is AMBIGUOUS", () => {
    // The instance exists on disk at a path the lockfile never names, and the
    // lockfile carries no node for that name+version at all: the component
    // cannot be tied to any instance through the tie graph.
    const m = model([inst("lodash", "4.17.21", "node_modules/patched-lodash", "/proj/node_modules/patched-lodash")]);
    const g = graphOf("lockfile", [{ key: "", name: "" }]);
    const r = componentResolution(comp("lodash", "4.17.21"), m, g);
    expect(r.state).toBe("AMBIGUOUS");
    expect(r.instances.length).toBe(1);
  });

  test("given an sbom tie graph, when resolved, then matching instances are tied by name+version (SBOM refs carry no path)", () => {
    const m = model([
      inst("lodash", "4.17.21", "node_modules/lodash"),
      inst("lodash", "4.17.21", "node_modules/a/node_modules/lodash"),
    ]);
    const sbom = sbomComponents(
      [
        { ref: "app", name: "app" },
        { ref: "lodash", name: "lodash", version: "4.17.21" },
      ],
      [{ ref: "app", dependsOn: ["lodash"] }],
    );
    const g = tieGraphFor(sbom, null);
    const r = componentResolution(comp("lodash", "4.17.21"), m, g);
    expect(r.state).toBe("RESOLVED");
    expect(r.instances.length).toBe(2);
  });
});

describe("component states on real fixtures (M2 exit criteria)", () => {
  test("given the npm flat demo layout, when all components are resolved, then every SBOM component maps (exit criterion)", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0", { dependencies: { express: "^4.18.0", qs: "^6.7.0" } }),
        "package-lock.json": JSON.stringify({
          name: "app",
          lockfileVersion: 3,
          packages: {
            "": { name: "app" },
            "node_modules/express": { name: "express", version: "4.18.2" },
            "node_modules/qs": { name: "qs", version: "6.7.0" },
          },
        }),
        "node_modules/express/package.json": pkg("express", "4.18.2"),
        "node_modules/express/index.js": "",
        "node_modules/qs/package.json": pkg("qs", "6.7.0"),
        "node_modules/qs/index.js": "",
      },
    });
    const model = buildProjectModel(root);
    const lock = npmLockfileGraph(root);
    const sbom = sbomComponents(
      [
        { ref: "app", name: "app" },
        { ref: "express", name: "express", version: "4.18.2" },
        { ref: "qs", name: "qs", version: "6.7.0" },
      ],
      [{ ref: "app", dependsOn: ["express", "qs"] }],
    );
    const graph = tieGraphFor(sbom, lock);
    const states = allComponentResolutions(sbom.components, model, graph, false);
    expect(states.find((s) => s.component.name === "express")?.state).toBe("RESOLVED");
    expect(states.find((s) => s.component.name === "qs")?.state).toBe("RESOLVED");
  });

  test("given a deliberately drifted install, when states are computed, then the drifted component is VERSION_MISMATCH", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0"),
        "node_modules/qs/package.json": pkg("qs", "6.8.0"),
        "node_modules/qs/index.js": "",
      },
    });
    const model = buildProjectModel(root);
    const sbom = sbomComponents([{ ref: "qs", name: "qs", version: "6.7.0" }]);
    const r = allComponentResolutions(sbom.components, model, tieGraphFor(sbom, null), false);
    expect(r[0]?.state).toBe("VERSION_MISMATCH");
  });

  test("given --sbom-only, when states are computed, then every component is NOT_CHECKED (never NO_SOURCE)", async () => {
    const root = await mkFixture({ files: { "package.json": pkg("app", "1.0.0") } });
    const model = buildProjectModel(root);
    const sbom = sbomComponents([{ ref: "qs", name: "qs", version: "6.7.0" }]);
    const r = allComponentResolutions(sbom.components, model, tieGraphFor(sbom, null), true);
    expect(r[0]?.state).toBe("NOT_CHECKED");
    expect(r[0]?.instances).toEqual([]);
  });

  test("given a monorepo subfolder as --project, when states are computed, then hoisted components resolve at the repo root (guard not tripped wrongly)", async () => {
    const repo = await mkFixture({
      files: {
        "package.json": pkg("repo", "1.0.0", { workspaces: ["packages/*"] }),
        "package-lock.json": JSON.stringify({
          lockfileVersion: 3,
          packages: {
            "": { name: "repo" },
            "node_modules/lodash": { name: "lodash", version: "4.17.21" },
          },
        }),
        "packages/app/package.json": pkg("app", "1.0.0", { dependencies: { lodash: "^4.17.0" } }),
        "node_modules/lodash/package.json": pkg("lodash", "4.17.21"),
        "node_modules/lodash/index.js": "",
      },
    });
    const model = buildProjectModel(join(repo, "packages", "app"));
    const lock = npmLockfileGraph(repo);
    const sbom = sbomComponents([{ ref: "lodash", name: "lodash", version: "4.17.21" }]);
    const r = allComponentResolutions(sbom.components, model, tieGraphFor(sbom, lock), false);
    expect(r[0]?.state).toBe("RESOLVED");
  });
});

describe("lockfile graphs (ADR 0014)", () => {
  test("given a v3 package-lock.json, when parsed, then the nesting becomes the graph edges", async () => {
    const root = await mkFixture({
      files: {
        "package-lock.json": JSON.stringify({
          name: "app",
          lockfileVersion: 3,
          packages: {
            "": { name: "app" },
            "node_modules/a": { name: "a", version: "1.0.0" },
            "node_modules/a/node_modules/lodash": { name: "lodash", version: "3.10.1" },
            "node_modules/lodash": { name: "lodash", version: "4.17.21" },
          },
        }),
      },
    });
    const g = npmLockfileGraph(root);
    expect(g).not.toBeNull();
    expect(g?.edges).toContainEqual(["node_modules/a", "node_modules/a/node_modules/lodash"]);
    expect(g?.edges).toContainEqual(["", "node_modules/lodash"]);
    expect(g?.nodes.get("node_modules/a/node_modules/lodash")?.version).toBe("3.10.1");
  });

  test("given a v1 nested package-lock.json, when parsed, then the nesting becomes the graph edges", async () => {
    const root = await mkFixture({
      files: {
        "package-lock.json": JSON.stringify({
          lockfileVersion: 1,
          dependencies: {
            a: { version: "1.0.0", dependencies: { lodash: { version: "3.10.1" } } },
            lodash: { version: "4.17.21" },
          },
        }),
      },
    });
    const g = npmLockfileGraph(root);
    expect(g).not.toBeNull();
    const names = [...(g?.nodes.values() ?? [])].map((n) => n.name);
    expect(names).toContain("a");
    expect(names).toContain("lodash");
  });

  test("given a pnpm store with dependency symlinks, when parsed, then the edges follow the store links", async () => {
    const root = await mkFixture({
      files: {
        "pnpm-lock.yaml": "lockfileVersion: '9.0'",
        "node_modules/.pnpm/a@1.0.0/node_modules/a/package.json": pkg("a", "1.0.0"),
        "node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/package.json": pkg("lodash", "4.17.21"),
        "node_modules/lodash/package.json": pkg("lodash", "4.17.21"),
      },
      symlinks: [
        ["node_modules/.pnpm/a@1.0.0/node_modules/lodash", "node_modules/.pnpm/lodash@4.17.21/node_modules/lodash"],
        ["node_modules/lodash", "node_modules/.pnpm/lodash@4.17.21/node_modules/lodash"],
      ],
    });
    const g = pnpmLockfileGraph(root);
    expect(g).not.toBeNull();
    expect(g?.edges).toContainEqual(["store/a@1.0.0", "store/lodash@4.17.21"]);
    expect(g?.edges).toContainEqual(["root", "store/lodash@4.17.21"]);
  });

  test("given no lockfile and no store, when parsed, then null is returned (the gap is recorded, not guessed)", async () => {
    const root = await mkFixture({ files: { "package.json": pkg("app", "1.0.0") } });
    expect(npmLockfileGraph(root)).toBeNull();
    expect(pnpmLockfileGraph(root)).toBeNull();
  });

  test("given a bun.lock (unparsed in v1), when the graph is requested, then it is absent, not fabricated", async () => {
    const root = await mkFixture({
      files: {
        "bun.lock": "zstd-magic-bytes",
        "node_modules/qs/package.json": pkg("qs", "6.7.0"),
      },
    });
    expect(npmLockfileGraph(root)).toBeNull();
  });
});
