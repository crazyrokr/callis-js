// M4 — call-graph builder tests (plan section 5.5, ADR 0011).
//
// Given-When-Then over in-memory module fixtures: a stub IR loader (M3
// parseModule) and a stub linker (specifier → file table) keep the builder
// independent of the filesystem; every expectation is about the emitted
// graph (nodes, edges, markers).

import { describe, expect, test } from "bun:test";
import { type BuildInput, type CallGraph, type EntryPoint, buildGraph } from "../src/callgraph/index.js";
import type { LibraryModel } from "../src/callgraph/models.js";
import { parseModule } from "../src/frontend/parse.js";

const A = "/app/a.mjs";
const B = "/app/b.mjs";
const C = "/app/c.mjs";

function ep(file: string, name: string, source: EntryPoint["source"] = "user"): EntryPoint {
  return { file, name, source, line: 0 };
}

function makeInput(
  files: Record<string, string>,
  links: Record<string, string>,
  entryPoints: EntryPoint[],
  options?: BuildInput["options"],
  models: LibraryModel[] = [],
): BuildInput {
  const ir: BuildInput["ir"] = (file) => {
    const text = files[file];
    return text === undefined ? Promise.resolve(null) : Promise.resolve(parseModule(file, text, {}));
  };
  const linker = {
    resolve: (fromFile: string, spec: string): string | null => links[`${fromFile}\u0000${spec}`] ?? null,
  };
  return options === undefined ? { ir, linker, entryPoints, models } : { ir, linker, entryPoints, models, options };
}

function id(file: string, name: string): string {
  return `${file}#${name}`;
}

function init(file: string): string {
  return `${file}#<module-init>`;
}

function hasEdge(g: CallGraph, from: string, to: string, kind?: string, via?: string): boolean {
  return g.edges.some(
    (e) =>
      e.from === from && e.to === to && (kind === undefined || e.kind === kind) && (via === undefined || e.via === via),
  );
}

function build(
  files: Record<string, string>,
  entry: EntryPoint,
  options?: BuildInput["options"],
  models: LibraryModel[] = [],
  links: Record<string, string> = {},
): Promise<CallGraph> {
  return buildGraph(makeInput(files, links, [entry], options, models)).then((r) => r.graph);
}

describe("direct and cross-module calls (plan 5.5 item 1)", () => {
  test("given a module whose entry function calls a local function, when built, then a call edge exists and the callee is expanded", async () => {
    const files = {
      [A]: `export function f() { g(); }
        function g() { sink(); }`,
    };
    const g = await build(files, ep(A, "f"));
    expect(hasEdge(g, id(A, "f"), id(A, "g"), "call")).toBe(true);
    // sink is not declared in the module: no edge, no marker (ordinary unresolved global)
    expect(hasEdge(g, id(A, "g"), id(A, "sink"))).toBe(false);
    expect(g.nodes.some((n) => n.name === "g")).toBe(true);
  });

  test("given a cross-module call through a named import, when built, then import + call edges exist", async () => {
    const files = {
      [A]: `import { b } from "./b.mjs";
          export function f() { b(); }`,
      [B]: `export function b() { work(); }
          function work() { }`,
    };
    const links = { [`${A}\u0000./b.mjs`]: B };
    const g = await build(files, ep(A, "f"), undefined, [], links);
    expect(hasEdge(g, init(A), init(B), "import")).toBe(true);
    expect(hasEdge(g, id(A, "f"), id(B, "b"), "call")).toBe(true);
    expect(hasEdge(g, id(B, "b"), id(B, "work"), "call")).toBe(true);
  });

  test("given a cross-module call through a renamed named import (b as c), when built, then the local binding maps to the export", async () => {
    const files = {
      [A]: `import { b as c } from "./b.mjs";
          export function f() { c(); }`,
      [B]: "export function b() { }",
    };
    const links = { [`${A}\u0000./b.mjs`]: B };
    const g = await build(files, ep(A, "f"), undefined, [], links);
    expect(hasEdge(g, id(A, "f"), id(B, "b"), "call")).toBe(true);
  });

  test("given a default import call, when built, then the default export function is targeted", async () => {
    const files = {
      [A]: `import def from "./b.mjs";
          export function f() { def(); }`,
      [B]: "export default function handler() { }",
    };
    const links = { [`${A}\u0000./b.mjs`]: B };
    const g = await build(files, ep(A, "f"), undefined, [], links);
    expect(hasEdge(g, id(A, "f"), id(B, "handler"), "call")).toBe(true);
  });

  test("given a namespace import member call (ns.m()), when built, then the export named m is targeted", async () => {
    const files = {
      [A]: `import * as ns from "./b.mjs";
          export function f() { ns.m(); }`,
      [B]: "export function m() { }",
    };
    const links = { [`${A}\u0000./b.mjs`]: B };
    const g = await build(files, ep(A, "f"), undefined, [], links);
    expect(hasEdge(g, id(A, "f"), id(B, "m"), "call")).toBe(true);
  });

  test("given a require module object member call (dep.m()), when built, then the export named m is targeted", async () => {
    const files = {
      [A]: `const dep = require("dep-pkg");
          exports.f = function () { dep.m(); };`,
      [B]: "exports.m = function () { }",
    };
    const links = { [`${A}\u0000dep-pkg`]: B };
    const g = await build(files, ep(A, "f"), undefined, [], links);
    expect(hasEdge(g, id(A, "f"), id(B, "m"), "call")).toBe(true);
  });

  test("given a call through a require default (dep() with module.exports = fn), when built, then the default export is targeted", async () => {
    const files = {
      [A]: `const dep = require("dep-pkg");
          exports.f = function () { dep(); };`,
      [B]: "module.exports = function handler() { }",
    };
    const links = { [`${A}\u0000dep-pkg`]: B };
    const g = await build(files, ep(A, "f"), undefined, [], links);
    expect(hasEdge(g, id(A, "f"), id(B, "default"), "call")).toBe(true);
  });

  test("given an entry naming a function no module provides, when built, then it is reported unresolved", async () => {
    const files = { [A]: "export function f() { }" };
    const r = await buildGraph(makeInput(files, {}, [ep(A, "nope")]));
    expect(r.unresolvedEntries).toContain(`${A}#nope`);
  });

  test("given zero entry points, when built, then the graph is empty", async () => {
    const files = { [A]: "export function f() { g(); } function g() {}" };
    const r = await buildGraph(makeInput(files, {}, []));
    expect(r.graph.stats.modules).toBe(0);
    expect(r.graph.stats.nodes).toBe(0);
    expect(r.graph.stats.edges).toBe(0);
  });
});

describe("re-exports (plan 5.5 item 1)", () => {
  test("given a named re-export (C re-exports handler from B), when A imports handler from C, then B's function is targeted", async () => {
    const files = {
      [A]: `import { handler } from "./c.mjs";
          export function main() { handler(); }`,
      [B]: `export function handler() { work(); }
          function work() { }`,
      [C]: `export { handler } from "./b.mjs";`,
    };
    const links = {
      [`${A}\u0000./c.mjs`]: C,
      [`${C}\u0000./b.mjs`]: B,
    };
    const g = await build(files, ep(A, "main"), undefined, [], links);
    expect(hasEdge(g, id(A, "main"), id(B, "handler"), "call")).toBe(true);
    expect(hasEdge(g, id(C, "<module-init>"), id(B, "<module-init>"), "import")).toBe(true);
    expect(hasEdge(g, id(B, "handler"), id(B, "work"), "call")).toBe(true);
  });

  test("given a star re-export (C: export * from B), when A imports x from C, then B's export x is targeted", async () => {
    const files = {
      [A]: `import { x } from "./c.mjs";
          export function main() { x(); }`,
      [B]: "export function x() { }",
      [C]: `export * from "./b.mjs";`,
    };
    const links = {
      [`${A}\u0000./c.mjs`]: C,
      [`${C}\u0000./b.mjs`]: B,
    };
    const g = await build(files, ep(A, "main"), undefined, [], links);
    expect(hasEdge(g, id(A, "main"), id(B, "x"), "call")).toBe(true);
  });

  test("given a circular re-export pair (A↔B) with a name exported from both but defined nowhere, when built, then the build terminates and resolves the real names only", async () => {
    const entry = "/app/entry.mjs";
    const files = {
      [A]: `export { y, ghost } from "./b.mjs";
          export function x() { }`,
      [B]: `export { x, ghost } from "./a.mjs";
          export function y() { }`,
      [entry]: `import { x, y, ghost } from "./a.mjs";
          export function main() { x(); y(); ghost(); }`,
    };
    const links = {
      [`${A}\u0000./b.mjs`]: B,
      [`${B}\u0000./a.mjs`]: A,
      [`${entry}\u0000./a.mjs`]: A,
    };
    const g = await build(files, ep(entry, "main"), undefined, [], links);
    expect(hasEdge(g, id(entry, "main"), id(A, "x"), "call")).toBe(true);
    expect(hasEdge(g, id(entry, "main"), id(B, "y"), "call")).toBe(true);
    // ghost is re-exported in a cycle but defined nowhere: no edge, no hang
    expect(g.edges.some((e) => e.from === id(entry, "main") && e.to.endsWith("#ghost"))).toBe(false);
  });
});

describe("module-init nodes (plan v3.3 P0.2)", () => {
  test("given a top-level call to a declared function, when the entry is module-init, then the call edge exists", async () => {
    const files = {
      [A]: `function init() { setup(); }
          init();
          function setup() { }
          export function main() { }`,
    };
    const g = await build(files, ep(A, "<module-init>"));
    expect(hasEdge(g, init(A), id(A, "init"), "call")).toBe(true);
    expect(hasEdge(g, id(A, "init"), id(A, "setup"), "call")).toBe(true);
  });

  test("given a top-level IIFE, when the entry is module-init, then the normalized function is reached", async () => {
    const files = {
      [A]: `(function () {
            doWork();
          })();
          function doWork() { }
          export function main() { }`,
    };
    const g = await build(files, ep(A, "<module-init>"));
    const iife = g.nodes.find((n) => n.name.startsWith("<iife@"));
    expect(iife).toBeDefined();
    expect(hasEdge(g, init(A), iife?.id ?? "", "call")).toBe(true);
    expect(hasEdge(g, iife?.id ?? "", id(A, "doWork"), "call")).toBe(true);
  });

  test("given an entry function (not module-init), when built, then the entry file's import-time calls are still reached", async () => {
    const files = {
      [A]: `function bootstrap() { }
          bootstrap();
          export function main() { }`,
    };
    const g = await build(files, ep(A, "main"));
    expect(hasEdge(g, init(A), id(A, "bootstrap"), "call")).toBe(true);
  });

  test("given an import-time side effect in the imported module, when built, then it is reached via the import edge", async () => {
    const files = {
      [A]: `import "./b.mjs";
          export function main() { }`,
      [B]: `configure();
          function configure() { load(); }
          function load() { }
          export function unused() { }`,
    };
    const links = { [`${A}\u0000./b.mjs`]: B };
    const g = await build(files, ep(A, "main"), undefined, [], links);
    expect(hasEdge(g, init(A), init(B), "import")).toBe(true);
    expect(hasEdge(g, init(B), id(B, "configure"), "call")).toBe(true);
    expect(hasEdge(g, id(B, "configure"), id(B, "load"), "call")).toBe(true);
  });

  test("given a top-level literal dynamic import (const m = import(...)), when built, then an eager import edge exists (over-approximation)", async () => {
    const files = {
      [A]: `const m = import("./b.mjs");
          export async function f() { m.lazy(); }`,
      [B]: "export function lazy() { }",
    };
    const links = { [`${A}\u0000./b.mjs`]: B };
    const g = await build(files, ep(A, "f"), undefined, [], links);
    expect(hasEdge(g, init(A), init(B), "import")).toBe(true);
    expect(hasEdge(g, id(A, "f"), id(B, "lazy"), "call")).toBe(true);
  });
});

describe("classes and RTA (plan 5.5 item 2)", () => {
  test("given new C(), when built, then instantiation + constructor edges exist", async () => {
    const files = {
      [A]: `class C {
            constructor() { ctorBody(); }
          }
          function ctorBody() { }
          export function f() { const c = new C(); }`,
    };
    const g = await build(files, ep(A, "f"));
    const cls = g.nodes.find((n) => n.kind === "class" && n.name === "C");
    expect(cls).toBeDefined();
    expect(hasEdge(g, id(A, "f"), cls?.id ?? "", "instantiation")).toBe(true);
    expect(hasEdge(g, id(A, "f"), id(A, "C.#constructor"), "call")).toBe(true);
    expect(hasEdge(g, id(A, "C.#constructor"), id(A, "ctorBody"), "call")).toBe(true);
  });

  test("given x = new C(); x.m(), when built, then the method is reached (RTA)", async () => {
    const files = {
      [A]: `class C {
            m() { work(); }
          }
          function work() { }
          export function f() { const x = new C(); x.m(); }`,
    };
    const g = await build(files, ep(A, "f"));
    expect(hasEdge(g, id(A, "f"), id(A, "C.m"), "call")).toBe(true);
    expect(hasEdge(g, id(A, "C.m"), id(A, "work"), "call")).toBe(true);
  });

  test("given x.m() without a known instantiation, when built, then NO method edge (RTA pruning, negative)", async () => {
    const files = {
      [A]: `class C {
            m() { work(); }
          }
          function work() { }
          export function f(x) { x.m(); }`,
    };
    const g = await build(files, ep(A, "f"));
    expect(hasEdge(g, id(A, "f"), id(A, "C.m"), "call")).toBe(false);
  });

  test("given Foo.prototype.m = fn; x = new Foo(); x.m(), when built, then the assigned function is reached", async () => {
    const files = {
      [A]: `class Foo {
            init() { }
          }
          function handler() { serve(); }
          function serve() { }
          export function f() {
            const x = new Foo();
            Foo.prototype.m = handler;
            x.m();
          }`,
    };
    const g = await build(files, ep(A, "f"));
    expect(hasEdge(g, id(A, "f"), id(A, "handler"), "call")).toBe(true);
    expect(hasEdge(g, id(A, "handler"), id(A, "serve"), "call")).toBe(true);
  });

  test("given super() in a constructor of a subclass, when built, then a super edge to the parent constructor exists", async () => {
    const files = {
      [A]: `class B {
            constructor() { baseBody(); }
          }
          class D extends B {
            constructor() {
              super(1);
              subBody();
            }
          }
          function baseBody() { }
          function subBody() { }
          export function f() { new D(); }`,
    };
    const g = await build(files, ep(A, "f"));
    expect(hasEdge(g, id(A, "D.#constructor"), id(A, "B.#constructor"), "super")).toBe(true);
  });
});

describe("0-CFA function flow (plan 5.5 item 3)", () => {
  test("given f(handler) with cb() inside f, when built, then the argument flows into the parameter", async () => {
    const files = {
      [A]: `export function run(cb) { cb(); }
          export function handler() { doWork(); }
          function doWork() { }
          export function f() { run(handler); }`,
    };
    const g = await build(files, ep(A, "f"));
    expect(hasEdge(g, id(A, "f"), id(A, "run"), "call")).toBe(true);
    expect(hasEdge(g, id(A, "run"), id(A, "handler"), "call")).toBe(true);
    expect(hasEdge(g, id(A, "handler"), id(A, "doWork"), "call")).toBe(true);
  });

  test("given const fn = make(); fn() where make returns handler, when built, then the return flow reaches handler", async () => {
    const files = {
      [A]: `export function make() { return handler; }
          export function handler() { doWork(); }
          function doWork() { }
          export function f() { const fn = make(); fn(); }`,
    };
    const g = await build(files, ep(A, "f"));
    expect(hasEdge(g, id(A, "f"), id(A, "handler"), "call")).toBe(true);
    expect(hasEdge(g, id(A, "handler"), id(A, "doWork"), "call")).toBe(true);
  });

  test("given a two-hop return chain (a = makeA(); b = makeB(a); b()), when built, then the deepest return is reached", async () => {
    const files = {
      [A]: `export function makeA() { return handler; }
          export function makeB(x) { return x; }
          export function handler() { deep(); }
          function deep() { }
          export function f() {
            const a = makeA();
            const b = makeB(a);
            b();
          }`,
    };
    const g = await build(files, ep(A, "f"));
    expect(hasEdge(g, id(A, "f"), id(A, "handler"), "call")).toBe(true);
    expect(hasEdge(g, id(A, "handler"), id(A, "deep"), "call")).toBe(true);
  });

  test("given obj.m = fn; obj.m(), when built, then the member flow reaches fn", async () => {
    const files = {
      [A]: `const obj = {};
          export function fn() { work(); }
          function work() { }
          export function f() {
            obj.m = fn;
            obj.m();
          }`,
    };
    const g = await build(files, ep(A, "f"));
    expect(hasEdge(g, id(A, "f"), id(A, "fn"), "call")).toBe(true);
  });

  test("given const f2 = g.bind(o); f2(), when built, then the bind alias reaches g", async () => {
    const files = {
      [A]: `export function g() { body(); }
          function body() { }
          export function f() {
            const o = {};
            const f2 = g.bind(o);
            f2();
          }`,
    };
    const g = await build(files, ep(A, "f"));
    expect(hasEdge(g, id(A, "f"), id(A, "g"), "call")).toBe(true);
    expect(hasEdge(g, id(A, "g"), id(A, "body"), "call")).toBe(true);
  });
});

describe("library models (plan 5.5 item 4)", () => {
  const models = (): LibraryModel[] => [
    { name: "setTimeout", module: "timers", callbackArg: 0, kind: "callback" },
    { name: "map", method: true, callbackArgs: [0], kind: "callback" },
    { name: "on", method: true, callbackArgs: [1], kind: "emitter", eventArg: 0 },
    { name: "emit", method: true, callbackArg: 0, kind: "emitter-emit", eventArg: 0 },
  ];

  test("given arr.map(handler), when built, then the callback edge is via the model", async () => {
    const files = {
      [A]: `export function handler(item) { process(item); }
          function process(item) { }
          export function f(arr) { arr.map(handler); }`,
    };
    const g = await build(files, ep(A, "f"), undefined, models());
    expect(hasEdge(g, id(A, "f"), id(A, "handler"), "call", "model:map")).toBe(true);
    expect(hasEdge(g, id(A, "handler"), id(A, "process"), "call")).toBe(true);
  });

  test("given setTimeout(cb, 0), when built, then the callback edge is via the model", async () => {
    const files = {
      [A]: `export function cb() { tick(); }
          export function f() { setTimeout(cb, 0); }`,
    };
    const g = await build(files, ep(A, "f"), undefined, models());
    expect(hasEdge(g, id(A, "f"), id(A, "cb"), "call", "model:setTimeout")).toBe(true);
  });

  test("given em.on('evt', h) + em.emit('evt'), when built, then the paired handler is reached", async () => {
    const files = {
      [A]: `const em = {};
          export function h() { notify(); }
          function notify() { }
          export function f() {
            em.on("evt", h);
            em.emit("evt");
          }`,
    };
    const g = await build(files, ep(A, "f"), undefined, models());
    expect(hasEdge(g, id(A, "f"), id(A, "h"), "call", "model:emit")).toBe(true);
    expect(hasEdge(g, id(A, "h"), id(A, "notify"), "call")).toBe(true);
  });

  test("given an emitter registration with a NON-identifier handler, when built, then no callback edge (negative)", async () => {
    const files = {
      [A]: `const em = {};
          export function f() {
            em.on("evt", (x) => { });
            em.emit("evt");
          }`,
    };
    const g = await build(files, ep(A, "f"), undefined, models());
    // anonymous arrow: no function node to target — the model edge is absent
    expect(g.edges.some((e) => e.via === "model:emit")).toBe(false);
  });

  test("given a callback registered through an UNMODELED user wrapper, when built, then no model callback edge (negative)", async () => {
    const files = {
      [A]: `export function wrapper(cb) { register(cb); }
          export function cb() { side(); }
          export function f() { wrapper(cb); }`,
    };
    const g = await build(files, ep(A, "f"), undefined, models());
    expect(hasEdge(g, id(A, "f"), id(A, "wrapper"), "call")).toBe(true);
    expect(g.edges.some((e) => e.to === id(A, "cb") && e.via?.startsWith("model:"))).toBe(false);
  });
});

describe("dynamic-risk markers (plan 5.5 item 5, ADR 0011)", () => {
  test("given eval(code) inside a function, when built, then the marker is scoped to that function", async () => {
    const files = {
      [A]: "export function f(code) { eval(code); }",
    };
    const g = await build(files, ep(A, "f"));
    const marker = g.markers.find((m) => m.kind === "eval");
    expect(marker).toBeDefined();
    expect(marker?.scopedTo).toBe(id(A, "f"));
  });

  test("given eval at module scope, when built, then the marker is scoped to module-init", async () => {
    const files = {
      [A]: `eval("top");
          export function f() { }`,
    };
    const g = await build(files, ep(A, "<module-init>"));
    const marker = g.markers.find((m) => m.kind === "eval");
    expect(marker?.scopedTo).toBe(init(A));
  });

  test("given require(expr), when built, then a require-expr marker is recorded", async () => {
    const files = {
      [A]: "export function f(mod) { const m = require(mod); m.x(); }",
    };
    const g = await build(files, ep(A, "f"));
    expect(g.markers.some((m) => m.kind === "require-expr" && m.scopedTo === id(A, "f"))).toBe(true);
  });

  test("given new Function(code) at top level, when built, then a new-function marker is recorded", async () => {
    const files = {
      [A]: `new Function("return 1")();
          export function f() { }`,
    };
    const g = await build(files, ep(A, "<module-init>"));
    expect(g.markers.some((m) => m.kind === "new-function" && m.scopedTo === init(A))).toBe(true);
  });

  test('given a computed call with a literal key o["m"](), when built, then it resolves like a member', async () => {
    const files = {
      [A]: `const o = {};
          export function fn() { work(); }
          function work() { }
          export function f() {
            o.m = fn;
            o["m"]();
          }`,
    };
    const g = await build(files, ep(A, "f"));
    expect(hasEdge(g, id(A, "f"), id(A, "fn"), "call")).toBe(true);
  });

  test("given a computed call with a NON-literal key, when built, then no call edge (negative) but the marker stays", async () => {
    const files = {
      [A]: `const o = {};
          export function f(o, k) { o[k](); }`,
    };
    const g = await build(files, ep(A, "f"));
    expect(g.edges.some((e) => e.from === id(A, "f") && e.kind === "call" && e.via === "over-approx")).toBe(false);
    expect(g.markers.some((m) => m.kind === "computed-call")).toBe(true);
  });

  test("given a non-literal computed call WITH --over-approximate-dynamic, when built, then all instantiated-class methods are targeted", async () => {
    const files = {
      [A]: `class C {
            a() { wa(); }
            b() { wb(); }
          }
          function wa() { }
          function wb() { }
          export function f(k) { const o = new C(); o[k](); }`,
    };
    const g = await build(files, ep(A, "f"), { overApproximateDynamic: true });
    expect(hasEdge(g, id(A, "f"), id(A, "C.a"), "call", "over-approx")).toBe(true);
    expect(hasEdge(g, id(A, "f"), id(A, "C.b"), "call", "over-approx")).toBe(true);
  });
});

describe("--cha names mode (plan 5.5)", () => {
  const files: Record<string, string> = {
    [A]: `import * as b from "./b.mjs";
        import * as c from "./c.mjs";
        export function f(x) { x.m(); }`,
    [B]: `export function m() { w1(); }
        function w1() { }`,
    [C]: `export function other() { w2(); }
        function w2() { }`,
  };
  const links = { [`${A}\u0000./b.mjs`]: B, [`${A}\u0000./c.mjs`]: C };

  test("given x.m() with --cha, when built, then every loaded function named m is targeted", async () => {
    const g = await build(files, ep(A, "f"), { cha: true }, [], links);
    expect(hasEdge(g, id(A, "f"), id(B, "m"), "call", "cha")).toBe(true);
    expect(hasEdge(g, id(A, "f"), id(C, "other"), "call", "cha")).toBe(false);
  });

  test("given the same call WITHOUT --cha, when built, then no name-based edges (negative)", async () => {
    const g = await build(files, ep(A, "f"), undefined, [], links);
    expect(g.edges.some((e) => e.via === "cha")).toBe(false);
  });
});

describe("demand-driven loading and determinism", () => {
  test("given two modules, only one imported, when built, then only the reachable module is loaded", async () => {
    const files = {
      [A]: `import { b } from "./b.mjs";
          export function f() { b(); }`,
      [B]: "export function b() { }",
      [C]: "export function orphan() { }",
    };
    const links = { [`${A}\u0000./b.mjs`]: B };
    const g = await build(files, ep(A, "f"), undefined, [], links);
    expect(g.stats.modules).toBe(2);
    expect(g.nodes.every((n) => n.file !== C)).toBe(true);
  });

  test("given an unreadable entry file, when built, then it is reported unresolved and the build succeeds", async () => {
    const files = { [A]: "export function f() { }" };
    const r = await buildGraph(makeInput(files, {}, [ep("/missing/x.mjs", "f")]));
    expect(r.unresolvedEntries).toContain("/missing/x.mjs#<unreadable>");
    expect(r.graph.stats.modules).toBe(0);
  });

  test("given the same build twice, when serialized, then the graph is byte-identical", async () => {
    const files = {
      [A]: `import { b } from "./b.mjs";
          export function f() { b(); }
          eval("x");`,
      [B]: `export function b() { work(); }
          function work() { }`,
    };
    const links = { [`${A}\u0000./b.mjs`]: B };
    const make = () => makeInput(files, links, [ep(A, "f")]);
    const a = JSON.stringify((await buildGraph(make())).graph);
    const b = JSON.stringify((await buildGraph(make())).graph);
    expect(a).toBe(b);
  });
});
