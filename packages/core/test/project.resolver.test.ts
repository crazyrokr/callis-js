// M2 fixture matrix — runtime resolution profile (plan section 5.3 item 4,
// ADR 0005): conditional exports (ordering matters), self-references, #
// imports, require vs ESM, the type field, symlinks, npm: aliases, and the
// v3.4 tsconfig-alias pair (mechanism present -> marked edge; absent -> none).

import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import {
  BUILTIN_MODULES,
  buildProjectModel,
  detectAliasMechanism,
  moduleFormatOf,
  resolveSpecifier,
  resolveTsconfigAlias,
  tsconfigOf,
} from "../src/project/index.js";
import { mkFixture, pkg } from "./project.fixtures.js";

/** An app with a node_modules tree; returns [root, model]. */
async function app(
  files: Record<string, string>,
  symlinks: [string, string][] = [],
): Promise<[string, ReturnType<typeof buildProjectModel>]> {
  const root = await mkFixture({ files: { "package.json": pkg("app", "1.0.0"), ...files }, symlinks });
  return [root, buildProjectModel(root)];
}

describe("builtins (plan v3.5 item 2)", () => {
  test("given node: prefixed and bare core names, when resolved, then the status is builtin", async () => {
    const [, model] = await app({});
    expect(resolveSpecifier("node:fs", join(model.root, "src"), model).status).toBe("builtin");
    expect(resolveSpecifier("path", join(model.root, "src"), model).status).toBe("builtin");
    expect(resolveSpecifier("node:crypto", join(model.root, "src"), model).status).toBe("builtin");
  });

  test("given a non-core bare specifier not in node_modules, when resolved, then it stays unresolved (never a silent fallback)", async () => {
    const [, model] = await app({});
    const d = resolveSpecifier("not-installed-at-all", join(model.root, "src"), model);
    expect(d.status).toBe("unresolved");
    expect(d.candidates.length).toBeGreaterThan(0);
  });

  test("given a long core-module name, when checked against the builtin table, then it is listed", () => {
    expect((BUILTIN_MODULES as readonly string[]).includes("worker_threads")).toBe(true);
    expect((BUILTIN_MODULES as readonly string[]).includes("fs/promises")).toBe(false);
  });
});

describe("relative imports + extension probing (plan 5.3 item 4)", () => {
  test("given ./util, when resolved, then the .js file is found", async () => {
    const [root, model] = await app({ "src/util.js": "exports.x = 1", "src/main.js": "" });
    const d = resolveSpecifier("./util", join(root, "src"), model);
    expect(d.status).toBe("resolved");
    expect(d.target).toBe(join(root, "src", "util.js"));
  });

  test("given a TS source importing a TS module, when resolved, then the .ts file is found and formats are typed", async () => {
    const [root, model] = await app({ "src/main.ts": "", "src/lib.ts": "" });
    const d = resolveSpecifier("./lib", join(root, "src"), model);
    expect(d.status).toBe("resolved");
    expect(d.target).toBe(join(root, "src", "lib.ts"));
    expect(d.moduleFormat).toBe("esm");
  });

  test("given a directory import, when resolved, then the index file is probed", async () => {
    const [root, model] = await app({ "src/mod/index.cjs": "" });
    const d = resolveSpecifier("./mod", join(root, "src"), model);
    expect(d.status).toBe("resolved");
    expect(d.target).toBe(join(root, "src", "mod", "index.cjs"));
  });

  test("given a missing relative path, when resolved, then it stays unresolved with the candidates recorded", async () => {
    const [root, model] = await app({ "src/main.js": "" });
    const d = resolveSpecifier("./nope", join(root, "src"), model);
    expect(d.status).toBe("unresolved");
    expect(d.candidates).toContain(join(root, "src", "nope"));
  });

  test("given .mjs/.cjs files, when the format is computed, then esm/cjs are returned", async () => {
    const [root, model] = await app({
      "lib/a.mjs": "",
      "lib/b.cjs": "",
      "lib/c.js": "",
      "lib/package.json": pkg("lib", "1.0.0"),
    });
    expect(moduleFormatOf(join(root, "lib", "a.mjs"))).toBe("esm");
    expect(moduleFormatOf(join(root, "lib", "b.cjs"))).toBe("cjs");
    // .js without a type field: commonjs by default (Node semantics)
    expect(moduleFormatOf(join(root, "lib", "c.js"))).toBe("cjs");
    const [root2, model2] = await app({
      "lib2/package.json": pkg("lib2", "1.0.0", { type: "module" }),
      "lib2/c.js": "",
    });
    expect(moduleFormatOf(join(root2, "lib2", "c.js"))).toBe("esm");
  });
});

describe("package resolution: exports (plan 5.3 item 4, ADR 0005)", () => {
  test("given a string exports with a main file, when resolved, then the exports target wins over main", async () => {
    const [root, model] = await app({
      "node_modules/p/package.json": pkg("p", "1.0.0", { exports: "./dist/index.js", main: "src/main.js" }),
      "node_modules/p/dist/index.js": "",
      "node_modules/p/src/main.js": "",
    });
    const d = resolveSpecifier("p", join(root, "src"), model);
    expect(d.status).toBe("resolved");
    expect(d.target).toBe(join(root, "node_modules", "p", "dist", "index.js"));
    expect(d.reason).toBe("package exports");
  });

  test("given conditional exports, when resolved under require, then the require condition wins (condition ordering matters)", async () => {
    const [root, model] = await app({
      "node_modules/p/package.json": pkg("p", "1.0.0", {
        exports: { ".": { require: "./cjs.js", import: "./esm.js", default: "./d.js" } },
      }),
      "node_modules/p/cjs.js": "",
      "node_modules/p/esm.js": "",
      "node_modules/p/d.js": "",
    });
    expect(resolveSpecifier("p", join(root, "src"), model, { format: "require" }).target).toBe(
      join(root, "node_modules", "p", "cjs.js"),
    );
    expect(resolveSpecifier("p", join(root, "src"), model, { format: "import" }).target).toBe(
      join(root, "node_modules", "p", "esm.js"),
    );
  });

  test("given a condition without require/import, when resolved, then the default condition is used", async () => {
    const [root, model] = await app({
      "node_modules/p/package.json": pkg("p", "1.0.0", {
        exports: { ".": { node: { browser: "./browser.js", default: "./node.js" } } },
      }),
      "node_modules/p/browser.js": "",
      "node_modules/p/node.js": "",
    });
    // "node" condition first, then "default": no browser condition here.
    expect(resolveSpecifier("p", join(root, "src"), model, { format: "require" }).target).toBe(
      join(root, "node_modules", "p", "node.js"),
    );
  });

  test("given subpath exports with an exact and a * pattern, when resolved, then exact wins over the pattern", async () => {
    const [root, model] = await app({
      "node_modules/p/package.json": pkg("p", "1.0.0", {
        exports: { "./lib/*": "./dist/*", "./lib/exact": "./dist/exact.js", ".": "./index.js" },
      }),
      "node_modules/p/index.js": "",
      "node_modules/p/dist/exact.js": "",
      "node_modules/p/dist/other.js": "",
    });
    expect(resolveSpecifier("p/lib/exact", join(root, "src"), model).target).toBe(
      join(root, "node_modules", "p", "dist", "exact.js"),
    );
    expect(resolveSpecifier("p/lib/other", join(root, "src"), model).target).toBe(
      join(root, "node_modules", "p", "dist", "other.js"),
    );
    expect(resolveSpecifier("p", join(root, "src"), model).target).toBe(join(root, "node_modules", "p", "index.js"));
  });

  test("given exports present but no matching target, when resolved, then NO main/index fallback happens (Node semantics)", async () => {
    const [root, model] = await app({
      "node_modules/p/package.json": pkg("p", "1.0.0", { exports: { "./only": "./only.js" }, main: "index.js" }),
      "node_modules/p/only.js": "",
      "node_modules/p/index.js": "",
    });
    // Root subpath "." not in exports: the package root is not importable.
    expect(resolveSpecifier("p", join(root, "src"), model).status).toBe("unresolved");
    expect(resolveSpecifier("p/only", join(root, "src"), model).status).toBe("resolved");
  });

  test("given no exports field, when resolved, then main (and subpath probing) are used", async () => {
    const [root, model] = await app({
      "node_modules/p/package.json": pkg("p", "1.0.0", { main: "src/entry.js" }),
      "node_modules/p/src/entry.js": "",
      "node_modules/p/index.js": "",
    });
    const d = resolveSpecifier("p", join(root, "src"), model);
    expect(d.target).toBe(join(root, "node_modules", "p", "src", "entry.js"));
    expect(d.reason).toBe("package main");
  });

  test("given a package with only an index file, when resolved, then the index is found", async () => {
    const [root, model] = await app({
      "node_modules/p/package.json": pkg("p", "1.0.0"),
      "node_modules/p/index.js": "",
    });
    const d = resolveSpecifier("p", join(root, "src"), model);
    expect(d.target).toBe(join(root, "node_modules", "p", "index.js"));
    expect(d.reason).toBe("package index");
  });
});

describe("self-references and # imports (plan 5.3 item 4)", () => {
  test("given a package importing its own name, when resolved, then the package's own entry is returned", async () => {
    const [root, model] = await app({
      "node_modules/p/package.json": pkg("p", "1.0.0", { exports: { ".": "./index.js", "./sub": "./sub.js" } }),
      "node_modules/p/index.js": "",
      "node_modules/p/sub.js": "",
      "node_modules/p/inside.js": "require('p/sub')",
    });
    const d = resolveSpecifier("p/sub", join(root, "node_modules", "p"), model);
    expect(d.status).toBe("resolved");
    expect(d.target).toBe(join(root, "node_modules", "p", "sub.js"));
  });

  test("given a # import mapped by the package's imports field, when resolved, then the mapping target is returned", async () => {
    const [root, model] = await app({
      "node_modules/p/package.json": pkg("p", "1.0.0", {
        imports: { "#internal/util": "./lib/util.js" },
        exports: "./*",
      }),
      "node_modules/p/lib/util.js": "",
    });
    const d = resolveSpecifier("#internal/util", join(root, "node_modules", "p"), model);
    expect(d.status).toBe("resolved");
    expect(d.target).toBe(join(root, "node_modules", "p", "lib", "util.js"));
  });

  test("given a # import outside any imports mapping, when resolved, then it stays unresolved", async () => {
    const [root, model] = await app({ "src/app.js": "" });
    const d = resolveSpecifier("#unmapped", join(root, "src"), model);
    expect(d.status).toBe("unresolved");
    expect(d.reason).toContain("imports mapping");
  });
});

describe("hoisting + nested resolution (plan 5.3)", () => {
  test("given a dependency that is only at the repo root, when resolved from a workspace subfolder, then the hoisted instance is found", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("repo", "1.0.0", { workspaces: ["packages/*"] }),
        "packages/app/package.json": pkg("app", "1.0.0"),
        "packages/app/src/index.js": "require('lodash')",
        "node_modules/lodash/package.json": pkg("lodash", "4.17.21"),
        "node_modules/lodash/index.js": "",
      },
    });
    const model = buildProjectModel(join(root, "packages", "app"));
    const d = resolveSpecifier("lodash", join(root, "packages", "app", "src"), model);
    expect(d.status).toBe("resolved");
    expect(d.target).toBe(join(root, "node_modules", "lodash", "index.js"));
  });

  test("given a nested duplicate shadowing the hoisted one, when resolved from the dependent, then the NEAREST wins (Node semantics)", async () => {
    const [root, model] = await app({
      "node_modules/lodash/package.json": pkg("lodash", "4.17.21"),
      "node_modules/lodash/index.js": "v4",
      "node_modules/a/node_modules/lodash/package.json": pkg("lodash", "3.10.1"),
      "node_modules/a/node_modules/lodash/index.js": "v3",
      "node_modules/a/package.json": pkg("a", "1.0.0"),
    });
    const fromA = resolveSpecifier("lodash", join(root, "node_modules", "a"), model);
    expect(fromA.target).toBe(join(root, "node_modules", "a", "node_modules", "lodash", "index.js"));
    const fromRoot = resolveSpecifier("lodash", join(root, "src"), model);
    expect(fromRoot.target).toBe(join(root, "node_modules", "lodash", "index.js"));
  });
});

describe("npm: aliases (plan 5.3, R7)", () => {
  test("given an alias install (directory name differs, package.json name is the target), when matched, then matching is by name+version, never by path", async () => {
    const [root, model] = await app({
      "package.json": pkg("app", "1.0.0", { dependencies: { "my-lodash": "npm:lodash@4.17.21" } }),
      "node_modules/my-lodash/package.json": pkg("lodash", "4.17.21"),
      "node_modules/my-lodash/index.js": "",
    });
    const instance = model.instances.find((i) => i.name === "lodash" && i.version === "4.17.21");
    expect(instance).toBeDefined();
    expect(instance?.relPath).toBe("node_modules/my-lodash");
    // The app imports the ALIAS name; the specifier resolves by directory, and
    // the instance carries the target package's name+version.
    const d = resolveSpecifier("my-lodash", join(root, "src"), model);
    expect(d.status).toBe("resolved");
    expect(d.instanceDir).toBe(join(root, "node_modules", "my-lodash"));
    expect(instance?.name).toBe("lodash");
  });
});

describe("symlinks (plan 5.3 item 4)", () => {
  test("given a symlinked package whose realpath is outside node_modules, when resolved, then the target file is found", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0"),
        "vendor/tool/package.json": pkg("tool", "2.0.0"),
        "vendor/tool/index.js": "module.exports = 2",
      },
      symlinks: [["node_modules/tool", "vendor/tool"]],
    });
    const model = buildProjectModel(root);
    const d = resolveSpecifier("tool", join(root, "src"), model);
    expect(d.status).toBe("resolved");
    expect(d.target).toBe(join(root, "vendor", "tool", "index.js"));
    // app-vs-library follows the realpath: application code, not library
    const inst = model.instances.find((i) => i.name === "tool");
    expect(inst?.library).toBe(false);
  });
});

describe("tsconfig alias pair (plan v3.4 item 1, ADR 0005 b2)", () => {
  test("given a tsconfig alias WITH a detected runtime mechanism, when resolved from app code, then the edge is marked tsconfig-alias", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0", { devDependencies: { "tsc-alias": "1.0.0" } }),
        "tsconfig.json": JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@/lib/*": ["src/lib/*"] } } }),
        "src/lib/util.js": "",
        "src/app.js": "import util from '@/lib/util'",
      },
    });
    const model = buildProjectModel(root);
    expect(detectAliasMechanism(root)).toBe(true);
    const d = resolveSpecifier("@/lib/util", join(root, "src"), model, { allowTsconfigAliases: true });
    expect(d.status).toBe("tsconfig-alias");
    expect(d.target).toBe(join(root, "src", "lib", "util.js"));
    expect(d.reason).toContain("tsconfig paths");
  });

  test("given a tsconfig alias WITHOUT any runtime mechanism, when resolved, then NO edge is produced (the negative fixture holds)", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0"),
        "tsconfig.json": JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@/lib/*": ["src/lib/*"] } } }),
        "src/lib/util.js": "",
        "src/app.js": "import util from '@/lib/util'",
      },
    });
    const model = buildProjectModel(root);
    expect(detectAliasMechanism(root)).toBe(false);
    // Mechanism absent: the engine does not pass allowTsconfigAliases; the
    // specifier runtime-resolves to nothing — no edge is invented.
    const d = resolveSpecifier("@/lib/util", join(root, "src"), model);
    expect(d.status).toBe("unresolved");
  });

  test("given a Next.js config (mechanism), when detected, then the mechanism is present", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0"),
        "next.config.js": "module.exports = {}",
      },
    });
    expect(detectAliasMechanism(root)).toBe(true);
  });

  test("given an alias used from LIBRARY code, when resolved with the mechanism, then no tsconfig-alias edge is produced (app code only)", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0", { devDependencies: { "tsconfig-paths": "1.0.0" } }),
        "tsconfig.json": JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@/*": ["src/*"] } } }),
        "src/lib/util.js": "",
        "node_modules/lib/package.json": pkg("lib", "1.0.0"),
        "node_modules/lib/entry.js": "require('@/lib/util')",
      },
    });
    const model = buildProjectModel(root);
    const d = resolveSpecifier("@/lib/util", join(root, "node_modules", "lib"), model, { allowTsconfigAliases: true });
    expect(d.status).not.toBe("tsconfig-alias");
  });

  test("given a tsconfig with baseUrl-only mapping, when resolved, then the baseUrl fallback is used", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0", { devDependencies: { "module-alias": "1.0.0" } }),
        "tsconfig.json": JSON.stringify({ compilerOptions: { baseUrl: "src" } }),
        "src/util.js": "",
        "src/app.js": "",
      },
    });
    const model = buildProjectModel(root);
    const alias = resolveTsconfigAlias("util", join(root, "src"), model);
    expect(alias?.target).toBe(join(root, "src", "util.js"));
    expect(tsconfigOf(join(root, "src"), root)?.baseUrl).toBe(join(root, "src"));
  });
});
