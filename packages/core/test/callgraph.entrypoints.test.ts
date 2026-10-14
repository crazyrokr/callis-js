// M4 — entry-point detection tests (plan section 5.5 "Entry points").
//
// Given-When-Then over small temporary projects on disk: package.json
// main/module/exports/bin, scripts, framework route registration, Next.js
// route files, callback interfaces, user tokens, and the annotation globs.

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { type DetectContext, detectEntryPoints, globMatch, parseEntryTokens } from "../src/callgraph/index.js";
import { type ModelCatalog, loadModels } from "../src/callgraph/models.js";
import { parseModule } from "../src/frontend/parse.js";
import type { ModuleIR } from "../src/frontend/types.js";
import type { ProjectModel } from "../src/project/types.js";

type Cat = Pick<ModelCatalog, "annotations" | "callbackInterfaces">;

async function makeProject(files: Record<string, string>, pkg: Record<string, unknown> = {}): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "callis-proj-"));
  for (const [rel, text] of Object.entries(files)) {
    const full = join(root, rel);
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, text, "utf8");
  }
  await writeFile(join(root, "package.json"), JSON.stringify({ name: "proj", ...pkg }, null, 2), "utf8");
  return root;
}

function modelOf(root: string): ProjectModel {
  return {
    root,
    layout: "npm",
    workspaces: [{ dir: root, name: "proj" }],
    instances: [],
    scannedDirs: [],
    installRoot: root,
  };
}

function ctxOf(model: ProjectModel, cat: Cat): DetectContext {
  const irOf = (file: string): ModuleIR | null => {
    try {
      return parseModule(file, readFileSync(file, "utf8"), {});
    } catch {
      return null;
    }
  };
  return { model, irOf, annotations: cat.annotations, callbackInterfaces: cat.callbackInterfaces };
}

/** One real workspace catalogue for the whole test file (the integration point). */
const catalog = (): Promise<Cat> => loadModels() as unknown as Promise<Cat>;

describe("package.json entries", () => {
  test("given a package with main + module + bin, when detected, then module-init entries for each exist", async () => {
    const root = await makeProject(
      {
        "server.js": "exports.listen = function () { };",
        "lib.mjs": "export function lib() { }",
        "cli.js": `console.log("c");`,
      },
      { main: "server.js", module: "lib.mjs", bin: { callis: "cli.js" } },
    );
    const r = await detectEntryPoints(ctxOf(modelOf(root), await catalog()), {});
    const bySource = new Map(r.entries.map((e) => [e.source, e.file]));
    expect(bySource.get("main")).toBe(join(root, "server.js"));
    expect(bySource.get("module")).toBe(join(root, "lib.mjs"));
    expect(bySource.get("bin")).toBe(join(root, "cli.js"));
    await rm(root, { recursive: true, force: true });
  });

  test("given package exports (string form and object form), when detected, then an exports entry exists", async () => {
    const root1 = await makeProject({ "index.js": "module.exports = function () { };" }, { exports: "index.js" });
    const cat = await catalog();
    const r1 = await detectEntryPoints(ctxOf(modelOf(root1), cat), {});
    expect(r1.entries.some((e) => e.source === "exports" && e.file === join(root1, "index.js"))).toBe(true);

    const root2 = await makeProject(
      { "lib/index.cjs": "module.exports = {};" },
      {
        exports: { ".": { require: "./lib/index.cjs", import: "./lib/index.cjs" } },
      },
    );
    const r2 = await detectEntryPoints(ctxOf(modelOf(root2), cat), {});
    expect(r2.entries.some((e) => e.source === "exports" && e.file === join(root2, "lib/index.cjs"))).toBe(true);
    await rm(root1, { recursive: true, force: true });
    await rm(root2, { recursive: true, force: true });
  });

  test("given scripts, when detected, then a script entry exists only for plain node/bun files", async () => {
    const root = await makeProject(
      { "start-app.js": `console.log("hi");` },
      {
        scripts: {
          start: "node start-app.js",
          test: "bun test",
          build: "tsc",
          "@x": "node x.js",
          prestart: "node y.js",
        },
      },
    );
    const r = await detectEntryPoints(ctxOf(modelOf(root), await catalog()), {});
    expect(r.entries.some((e) => e.source === "script" && e.file === join(root, "start-app.js"))).toBe(true);
    expect(r.entries.filter((e) => e.source === "script").length).toBe(1);
    await rm(root, { recursive: true, force: true });
  });
});

describe("test-file exclusion", () => {
  test("given a main pointing at a test file, when detected, then NO entry (tests excluded by default)", async () => {
    const root = await makeProject({ "src/app.test.js": "exports.t = function () { };" }, { main: "src/app.test.js" });
    const r = await detectEntryPoints(ctxOf(modelOf(root), await catalog()), {});
    expect(r.entries.some((e) => e.file === join(root, "src/app.test.js"))).toBe(false);
    await rm(root, { recursive: true, force: true });
  });

  test("given the same project with includeTests, when detected, then the test file becomes an entry", async () => {
    const root = await makeProject({ "src/app.test.js": "exports.t = function () { };" }, { main: "src/app.test.js" });
    const r = await detectEntryPoints(ctxOf(modelOf(root), await catalog()), { includeTests: true });
    expect(r.entries.some((e) => e.file === join(root, "src/app.test.js") && e.source === "main")).toBe(true);
    await rm(root, { recursive: true, force: true });
  });
});

describe("framework route entries", () => {
  test("given an express app (const app = express(); app.get(path, handler)), when detected, then the handler is a framework entry", async () => {
    const root = await makeProject({
      "routes.js": `const express = require("express");
        const app = express();
        exports.handler = function (req, res) { res.end("ok"); };
        app.get("/x", handler);`,
    });
    const r = await detectEntryPoints(ctxOf(modelOf(root), await catalog()), {});
    const fw = r.entries.find((e) => e.source === "framework" && e.framework === "express");
    expect(fw).toBeDefined();
    expect(fw?.name).toBe("handler");
    await rm(root, { recursive: true, force: true });
  });

  test("given a koa app (const app = new Koa()), when detected, then the route handler is a framework entry", async () => {
    const root = await makeProject({
      "server.js": `const Koa = require("koa");
        const app = new Koa();
        function serve() { }
        app.post("/p", serve);`,
    });
    const r = await detectEntryPoints(ctxOf(modelOf(root), await catalog()), {});
    expect(r.entries.some((e) => e.source === "framework" && e.framework === "koa" && e.name === "serve")).toBe(true);
    await rm(root, { recursive: true, force: true });
  });

  test("given an app variable NOT created by a curated constructor, when detected, then no framework entry (negative)", async () => {
    const root = await makeProject({
      "server.js": `const app = makeMyApp();
        function serve() { }
        app.get("/x", serve);`,
    });
    const r = await detectEntryPoints(ctxOf(modelOf(root), await catalog()), {});
    expect(r.entries.filter((e) => e.source === "framework").length).toBe(0);
    await rm(root, { recursive: true, force: true });
  });

  test("given a Next.js-style route file (app/route.ts), when detected, then a module-init framework entry exists", async () => {
    const root = await makeProject({ "app/route.ts": "export function GET() { return Response.json({ ok: true }); }" });
    const r = await detectEntryPoints(ctxOf(modelOf(root), await catalog()), {});
    const next = r.entries.find((e) => e.source === "framework" && e.framework === "next");
    expect(next).toBeDefined();
    expect(next?.file).toBe(join(root, "app", "route.ts"));
    expect(next?.name).toBe("<module-init>");
    await rm(root, { recursive: true, force: true });
  });
});

describe("callback-interface entries", () => {
  test("given a module exporting handler (the curated module#handler interface), when detected, then a callback-interface entry exists", async () => {
    const root = await makeProject({
      "worker.js": `exports.handler = function (msg) { process(msg); };
          function process(m) { }`,
    });
    const r = await detectEntryPoints(ctxOf(modelOf(root), await catalog()), {});
    const ci = r.entries.find((e) => e.source === "callback-interface");
    expect(ci).toBeDefined();
    expect(ci?.name).toBe("handler");
    expect(ci?.file).toBe(join(root, "worker.js"));
    await rm(root, { recursive: true, force: true });
  });

  test("given --callback-interfaces user tokens, when detected, then the extra interface is honored", async () => {
    const root = await makeProject({
      "job.js": "exports.consume = function (job) { };",
    });
    const r = await detectEntryPoints(ctxOf(modelOf(root), await catalog()), { callbackInterfaces: ["job#consume"] });
    expect(
      r.entries.some(
        (e) => e.source === "callback-interface" && e.name === "consume" && e.file === join(root, "job.js"),
      ),
    ).toBe(true);
    await rm(root, { recursive: true, force: true });
  });
});

describe("user tokens", () => {
  test("given valid tokens, when parsed, then user entries are produced", () => {
    const r = parseEntryTokens(
      ["src/main.js#main", "/abs/file#<module-init>"],
      "/proj",
      new Set(["/proj/src/main.js", "/abs/file"]),
    );
    expect(r.entries).toEqual([
      { file: "/proj/src/main.js", name: "main", source: "user", line: 0 },
      { file: "/abs/file", name: "<module-init>", source: "user", line: 0 },
    ]);
    expect(r.warnings).toEqual([]);
  });

  test("given malformed or unknown tokens, when parsed, then they WARN (never fail the run)", () => {
    const r = parseEntryTokens(["nohash", "#name", "missing.js#main", "ok.mjs#x"], "/proj", new Set(["/proj/ok.mjs"]));
    expect(r.entries).toEqual([{ file: "/proj/ok.mjs", name: "x", source: "user", line: 0 }]);
    expect(r.warnings.length).toBe(3);
    for (const w of r.warnings) expect(w).toContain("token");
  });

  test("given --entry-points (extend), when detected, then curated AND user entries exist", async () => {
    const root = await makeProject(
      { "main.js": "exports.f = function () { }", "extra.js": "exports.g = function () { }" },
      { main: "main.js" },
    );
    const r = await detectEntryPoints(ctxOf(modelOf(root), await catalog()), { extra: ["extra.js#g"] });
    expect(r.entries.some((e) => e.source === "main")).toBe(true);
    expect(r.entries.some((e) => e.source === "user" && e.name === "g")).toBe(true);
    await rm(root, { recursive: true, force: true });
  });

  test("given --entry-points-only (replace, JVM contract), when detected, then ONLY user entries exist", async () => {
    const root = await makeProject(
      { "main.js": "exports.f = function () { }", "extra.js": "exports.g = function () { }" },
      { main: "main.js" },
    );
    const r = await detectEntryPoints(ctxOf(modelOf(root), await catalog()), { extraOnly: ["extra.js#g"] });
    expect(r.entries.length).toBe(1);
    expect(r.entries[0]?.source).toBe("user");
    expect(r.entries[0]?.name).toBe("g");
    await rm(root, { recursive: true, force: true });
  });

  test("given a project with no entry sources at all, when detected, then zero entries (the CLI exits 3 later)", async () => {
    const root = await makeProject({ "quiet.js": "exports.q = function () { }" });
    const r = await detectEntryPoints(ctxOf(modelOf(root), await catalog()), {});
    expect(r.entries.length).toBe(0);
    await rm(root, { recursive: true, force: true });
  });
});

describe("annotation globs", () => {
  test("given test patterns, when matched, then test files match and sources do not", () => {
    expect(globMatch("**/*.test.js", "src/a.test.js")).toBe(true);
    expect(globMatch("**/*.test.js", "src/a.js")).toBe(false);
    expect(globMatch("**/__tests__/**", "src/__tests__/a.js")).toBe(true);
    // ?(c|m) is OPTIONAL: .test.js matches, .test.min.js does not
    expect(globMatch("**/*.test.?(c|m)js", "deep/nested/b.test.cjs")).toBe(true);
    expect(globMatch("**/*.test.?(c|m)js", "deep/b.test.js")).toBe(true);
    expect(globMatch("**/*.test.?(c|m)js", "deep/b.test.min.js")).toBe(false);
  });

  test("given group and star patterns, when matched, then ** crosses directories and * does not", () => {
    expect(globMatch("app/**/route.ts", "app/route.ts")).toBe(true);
    expect(globMatch("app/**/route.ts", "app/sub/dir/route.ts")).toBe(true);
    expect(globMatch("app/*/route.ts", "app/a/route.ts")).toBe(true);
    expect(globMatch("app/*/route.ts", "app/a/b/route.ts")).toBe(false);
    expect(globMatch("x.(js|ts)", "x.js")).toBe(true);
    expect(globMatch("x.(js|ts)", "x.ts")).toBe(true);
    expect(globMatch("x.(js|ts)", "x.mjs")).toBe(false);
    expect(globMatch("a?c.js", "abc.js")).toBe(true);
    expect(globMatch("a?c.js", "ac.js")).toBe(false);
  });
});
