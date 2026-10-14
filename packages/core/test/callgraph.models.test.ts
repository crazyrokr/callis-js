// M4 — model catalogue tests (plan section 5.5 item 4, ADR 0011).
//
// Given-When-Then over the declarative catalogue: the workspace @callis/models
// data (the soundness contract), explicit directories, and the validation
// boundaries (malformed docs must throw or be dropped, never trusted).

import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type LibraryModel,
  callbackArgsOf,
  emptyCatalog,
  loadModels,
  modelForCall,
  validateCatalog,
} from "../src/callgraph/models.js";

describe("loadModels", () => {
  test("given the workspace @callis/models data, when loaded, then all three sections are non-empty and shaped", async () => {
    const cat = await loadModels();
    expect(cat.models.length).toBeGreaterThan(0);
    for (const m of cat.models) {
      expect(m.name.length).toBeGreaterThan(0);
      expect(["callback", "emitter", "emitter-emit", "alias"]).toContain(m.kind);
    }
    expect(Object.keys(cat.annotations.routes).length).toBeGreaterThan(0);
    expect(Object.keys(cat.annotations.constructors).length).toBeGreaterThan(0);
    expect(cat.annotations.nextRoutePatterns.length).toBeGreaterThan(0);
    expect(cat.annotations.testPatterns.length).toBeGreaterThan(0);
    expect(cat.callbackInterfaces.interfaces.length).toBeGreaterThan(0);
    // every callback-interface token carries the <module>#<export> shape
    for (const i of cat.callbackInterfaces.interfaces) expect(i).toContain("#");
  });

  test("given an explicit data directory, when loaded, then the three files are read from there", async () => {
    const dir = await mkdtemp(join(tmpdir(), "callis-models-"));
    try {
      await writeFile(
        join(dir, "library-models.json"),
        JSON.stringify({ models: [{ name: "tick", callbackArg: 0, kind: "callback" }] }),
      );
      await writeFile(
        join(dir, "entry-point-annotations.json"),
        JSON.stringify({
          routes: { express: ["get"] },
          constructors: { express: ["express"] },
          nextRoutePatterns: [],
          testPatterns: [],
        }),
      );
      await writeFile(join(dir, "callback-interfaces.json"), JSON.stringify({ interfaces: ["module#handler"] }));
      const cat = await loadModels(dir);
      expect(cat.models).toEqual([{ name: "tick", callbackArg: 0, kind: "callback" }]);
      expect(cat.annotations.routes.express).toEqual(["get"]);
      expect(cat.callbackInterfaces.interfaces).toEqual(["module#handler"]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("given a missing data directory, when loaded, then it rejects (models are part of the soundness contract)", async () => {
    await expect(loadModels("/nonexistent/callis-models-data")).rejects.toThrow();
  });
});

describe("validateCatalog", () => {
  const okModels = () => ({ models: [{ name: "map", method: true, callbackArgs: [0], kind: "callback" }] });
  const okAnnotations = () => ({
    routes: { express: ["get"] },
    constructors: { express: ["express"] },
    nextRoutePatterns: ["app/**/route.ts"],
    testPatterns: ["**/*.test.js"],
  });
  const okInterfaces = () => ({ interfaces: ["module#handler"] });

  test("given well-formed docs, when validated, then the catalog is normalized", () => {
    const cat = validateCatalog(okModels(), okAnnotations(), okInterfaces());
    expect(cat.models[0]?.name).toBe("map");
    expect(cat.annotations.routes.express).toEqual(["get"]);
    expect(cat.annotations.nextRoutePatterns).toEqual(["app/**/route.ts"]);
    expect(cat.callbackInterfaces.interfaces).toEqual(["module#handler"]);
  });

  test("given a missing or non-array models section, when validated, then it throws", () => {
    expect(() => validateCatalog(null, okAnnotations(), okInterfaces())).toThrow(/models/);
    expect(() => validateCatalog({ models: "nope" }, okAnnotations(), okInterfaces())).toThrow(/models/);
  });

  test("given a malformed model entry (missing name/kind, or an unknown kind), when validated, then it throws", () => {
    expect(() => validateCatalog({ models: [{ name: "x" }] }, okAnnotations(), okInterfaces())).toThrow(/malformed/);
    expect(() => validateCatalog({ models: [{ kind: "callback" }] }, okAnnotations(), okInterfaces())).toThrow(
      /malformed/,
    );
    expect(() => validateCatalog({ models: [{ name: "x", kind: "bogus" }] }, okAnnotations(), okInterfaces())).toThrow(
      /unknown kind/,
    );
  });

  test("given malformed annotations or interface tokens, when validated, then bad rows are dropped or it throws", () => {
    expect(() => validateCatalog(okModels(), "not-an-object", okInterfaces())).toThrow(/annotations/);
    expect(() => validateCatalog(okModels(), okAnnotations(), null)).toThrow(/interfaces/);
    // interface tokens without "#" are untrusted: dropped, not an error
    const cat = validateCatalog(okModels(), okAnnotations(), { interfaces: ["module#handler", "broken", 42] });
    expect(cat.callbackInterfaces.interfaces).toEqual(["module#handler"]);
    // non-string routes are dropped silently
    const cat2 = validateCatalog(okModels(), { routes: { express: ["get", 5] }, constructors: {} }, okInterfaces());
    expect(cat2.annotations.routes.express).toEqual(["get"]);
  });
});

describe("modelForCall + callbackArgsOf", () => {
  const models: LibraryModel[] = [
    { name: "setTimeout", module: "timers", callbackArg: 0, kind: "callback" },
    { name: "map", method: true, callbackArgs: [0], kind: "callback" },
    { name: "on", method: true, callbackArgs: [1], kind: "emitter", eventArg: 0 },
  ];

  test("given a global call shape, when matched, then only non-method models match (method/global shape check)", () => {
    expect(modelForCall("setTimeout", false, models)?.kind).toBe("callback");
    expect(modelForCall("map", false, models)).toBeNull();
  });

  test("given a method call shape, when matched, then only method models match", () => {
    expect(modelForCall("map", true, models)?.kind).toBe("callback");
    expect(modelForCall("on", true, models)?.eventArg).toBe(0);
    expect(modelForCall("setTimeout", true, models)).toBeNull();
  });

  test("given an unknown name, when matched, then null", () => {
    expect(modelForCall("nope", false, models)).toBeNull();
    expect(modelForCall("nope", true, models)).toBeNull();
  });

  test("given the callbackArg sugar or no callback positions, when read, then callbackArgsOf normalizes", () => {
    expect(callbackArgsOf(models[0] as LibraryModel)).toEqual([0]);
    expect(callbackArgsOf(models[1] as LibraryModel)).toEqual([0]);
    expect(callbackArgsOf({ name: "bind", kind: "alias" })).toEqual([]);
  });
});

test("given emptyCatalog, when called, then all three sections are present and empty", () => {
  const cat = emptyCatalog();
  expect(cat.models).toEqual([]);
  expect(cat.annotations.routes).toEqual({});
  expect(cat.annotations.testPatterns).toEqual([]);
  expect(cat.callbackInterfaces.interfaces).toEqual([]);
});
