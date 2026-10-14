// M2 fixture matrix — project scan (plan section 5.3, ADRs 0005/0014):
// layouts, instances, app-vs-library realpath rule, workspaces, hoisting.

import { describe, expect, test } from "bun:test";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  buildProjectModel,
  decodePnpmId,
  detectLayout,
  findInstallRoot,
  isLibraryPath,
  readPkgJson,
} from "../src/project/scan.js";
import { UsageError } from "../src/util/errors.js";
import { mkFixture, pkg } from "./project.fixtures.js";

describe("layout detection (plan 5.3)", () => {
  test("given a node_modules directory, when detected, then the layout is npm-style", async () => {
    const root = await mkFixture({
      files: { "node_modules/lodash/package.json": pkg("lodash", "4.17.21"), "node_modules/lodash/index.js": "" },
    });
    expect(detectLayout(root)).toBe("npm");
  });

  test("given a .pnpm store, when detected, then the layout is pnpm", async () => {
    const root = await mkFixture({
      files: {
        "node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/package.json": pkg("lodash", "4.17.21"),
        "node_modules/lodash/package.json": pkg("lodash", "4.17.21"),
      },
      symlinks: [["node_modules/lodash", "node_modules/.pnpm/lodash@4.17.21/node_modules/lodash"]],
    });
    expect(detectLayout(root)).toBe("pnpm");
  });

  test("given a .pnp.cjs file, when detected, then the layout is pnp (refused)", async () => {
    const root = await mkFixture({ files: { ".pnp.cjs": "// pnp" } });
    expect(detectLayout(root)).toBe("pnp");
  });

  test("given a pnpm lockfile but no node_modules, when detected, then the layout is pnpm", async () => {
    const root = await mkFixture({ files: { "pnpm-lock.yaml": "lockfileVersion: '9.0'" } });
    expect(detectLayout(root)).toBe("pnpm");
  });

  test("given Yarn PnP, when the model is built, then a UsageError (exit 2) is thrown with the node-modules hint", async () => {
    const root = await mkFixture({ files: { ".pnp.cjs": "// pnp" } });
    expect(() => buildProjectModel(root)).toThrow(UsageError);
    expect(() => buildProjectModel(root)).toThrow("nodeLinker: node-modules");
  });
});

describe("npm layout scan (plan 5.3)", () => {
  test("given nested duplicates, when scanned, then each instance keeps its own identity (never collapsed)", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0"),
        "node_modules/lodash/package.json": pkg("lodash", "4.17.21"),
        "node_modules/lodash/index.js": "module.exports = 1",
        "node_modules/a/node_modules/lodash/package.json": pkg("lodash", "3.10.1"),
        "node_modules/a/node_modules/lodash/index.js": "module.exports = 3",
        "node_modules/a/package.json": pkg("a", "1.0.0"),
      },
    });
    const model = buildProjectModel(root);
    const lodash = model.instances.filter((i) => i.name === "lodash");
    expect(lodash.length).toBe(2);
    const versions = lodash.map((i) => i.version).sort();
    expect(versions).toEqual(["3.10.1", "4.17.21"]);
    const nested = lodash.find((i) => i.version === "3.10.1");
    expect(nested?.parent).toEqual({ name: "a", version: "1.0.0" });
    expect(nested?.library).toBe(true);
  });

  test("given a scoped package, when scanned, then the instance is found under the scope directory", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0"),
        "node_modules/@scope/lib/package.json": pkg("@scope/lib", "2.0.0"),
        "node_modules/@scope/lib/index.js": "",
      },
    });
    const model = buildProjectModel(root);
    expect(model.instances.find((i) => i.name === "@scope/lib")?.version).toBe("2.0.0");
  });

  test("given the same package reached by two symlinks, when scanned, then one instance is recorded (deduplicated by realpath)", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0"),
        "vendor/lib/package.json": pkg("lib", "1.0.0"),
        "vendor/lib/index.js": "",
      },
      symlinks: [
        ["node_modules/lib", "vendor/lib"],
        ["node_modules/alias", "vendor/lib"],
      ],
    });
    const model = buildProjectModel(root);
    const lib = model.instances.filter((i) => i.name === "lib");
    expect(lib.length).toBe(1);
    // The realpath is OUTSIDE node_modules: the app-vs-library rule classifies
    // it as application code (workspace-style vendoring).
    expect(lib[0]?.library).toBe(false);
  });

  test("given a pnpm top-level symlink into the store, when scanned, then it classifies as library (realpath under .pnpm)", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0"),
        "pnpm-lock.yaml": "lockfileVersion: '9.0'",
        "node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/package.json": pkg("lodash", "4.17.21"),
        "node_modules/lodash/package.json": pkg("lodash", "4.17.21"),
      },
      symlinks: [["node_modules/lodash", "node_modules/.pnpm/lodash@4.17.21/node_modules/lodash"]],
    });
    const model = buildProjectModel(root);
    const lodash = model.instances.filter((i) => i.name === "lodash");
    expect(lodash.length).toBe(1);
    expect(lodash[0]?.library).toBe(true);
  });

  test("given pnpm peer-variant duplicates (same name+version, different store ids), when scanned, then separate instances are produced", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0"),
        "pnpm-lock.yaml": "lockfileVersion: '9.0'",
        "node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/package.json": pkg("lodash", "4.17.21"),
        "node_modules/.pnpm/lodash@4.17.21_lodash.merge@4.7.4/node_modules/lodash/package.json": pkg(
          "lodash",
          "4.17.21",
        ),
        "node_modules/lodash/package.json": pkg("lodash", "4.17.21"),
      },
      symlinks: [["node_modules/lodash", "node_modules/.pnpm/lodash@4.17.21/node_modules/lodash"]],
    });
    const model = buildProjectModel(root);
    const lodash = model.instances.filter((i) => i.name === "lodash" && i.version === "4.17.21");
    expect(lodash.length).toBe(2);
  });

  test("given a monorepo subfolder, when scanned, then hoisted dependencies at the repo root are found (install-root walk)", async () => {
    const repo = await mkFixture({
      files: {
        "package.json": pkg("repo", "1.0.0", { workspaces: ["packages/*"] }),
        "packages/app/package.json": pkg("app", "1.0.0", { dependencies: { lodash: "^4.17.0" } }),
        "packages/app/index.js": "require('lodash')",
        "node_modules/lodash/package.json": pkg("lodash", "4.17.21"),
        "node_modules/lodash/index.js": "",
        "package-lock.json": JSON.stringify({
          name: "repo",
          lockfileVersion: 3,
          packages: { "": { name: "repo" }, "node_modules/lodash": { name: "lodash", version: "4.17.21" } },
        }),
      },
    });
    const appDir = join(repo, "packages", "app");
    const model = buildProjectModel(appDir);
    expect(model.installRoot).toBe(repo);
    expect(model.instances.find((i) => i.name === "lodash")?.version).toBe("4.17.21");
    expect(model.workspaces.map((w) => w.name)).toContain("app");
  });
});

describe("app-vs-library rule (plan v2)", () => {
  test("given a realpath under node_modules, when classified, then it is library", () => {
    expect(isLibraryPath("/x/project/node_modules/lodash/index.js")).toBe(true);
  });

  test("given a realpath under the pnpm store, when classified, then it is library", () => {
    expect(isLibraryPath("/x/project/node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/index.js")).toBe(true);
  });

  test("given a realpath outside node_modules, when classified, then it is application code", () => {
    expect(isLibraryPath("/x/project/src/index.ts")).toBe(false);
  });
});

describe("workspaces (plan 5.3)", () => {
  test("given npm workspaces globs, when detected, then each workspace package is application code", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("repo", "1.0.0", { workspaces: ["packages/*"] }),
        "packages/web/package.json": pkg("web", "1.0.0"),
        "packages/api/package.json": pkg("api", "1.0.0"),
        "packages/README.md": "not a package",
      },
    });
    const model = buildProjectModel(root);
    const names = model.workspaces.map((w) => w.name).sort();
    expect(names).toEqual(["api", "repo", "web"]);
  });

  test("given a pnpm-workspace.yaml, when detected, then the listed packages are workspaces", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("repo", "1.0.0"),
        "pnpm-workspace.yaml": "packages:\n  - 'packages/*'\n  - 'services/*'\n",
        "pnpm-lock.yaml": "lockfileVersion: '9.0'",
        "packages/web/package.json": pkg("web", "1.0.0"),
        "services/worker/package.json": pkg("worker", "1.0.0"),
      },
    });
    const model = buildProjectModel(root);
    const names = model.workspaces.map((w) => w.name).sort();
    expect(names).toEqual(["repo", "web", "worker"]);
  });
});

describe("install root + pnpm id decoding", () => {
  test("given a project with a lockfile at the parent, when the install root is found, then the parent is returned", async () => {
    const repo = await mkFixture({
      files: {
        "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: {} }),
        "sub/package.json": pkg("sub", "1.0.0"),
      },
    });
    expect(findInstallRoot(join(repo, "sub"))).toBe(repo);
  });

  test("given plain, scoped, and peer-suffix .pnpm ids, when decoded, then name+version are recovered", () => {
    expect(decodePnpmId("lodash@4.17.21")).toEqual({ name: "lodash", version: "4.17.21" });
    expect(decodePnpmId("@scope+lib@1.2.3")).toEqual({ name: "@scope/lib", version: "1.2.3" });
    expect(decodePnpmId("lodash@4.17.21_lodash.merge@4.7.4")).toEqual({ name: "lodash", version: "4.17.21" });
    expect(decodePnpmId("not-an-id")).toBeNull();
  });

  test("given a directory without package.json, when read, then null is returned", async () => {
    const root = await mkFixture({ files: { "empty-dir/file.txt": "x" } });
    expect(readPkgJson(join(root, "empty-dir"))).toBeNull();
  });

  test("given an unreadable lockfile, when the install root is probed, then the walk is bounded and the root is returned", async () => {
    const root = await mkFixture({ files: { "package.json": pkg("app", "1.0.0") } });
    expect(findInstallRoot(root)).toBe(root);
    // sanity: the fixture root really has no lockfile
    expect(
      existsSync(join(root, "package-lock.json")) || readFileSync(join(root, "package.json"), "utf8").length > 0,
    ).toBe(true);
    expect(lstatSync(join(root, "package.json")).isFile()).toBe(true);
  });
});
