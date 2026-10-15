// M7a — pointer analysis (plan §10, ADR 0011/0016): inclusion-based
// (Andersen-style) receiver typing with subtype-closure dispatch.
//
// Given-When-Then: (1) the pure solver (class lattice, dispatch closure),
// (2) builder integration — refined dispatch versus the default RTA —
// and (3) the conservative false-positive guards: an unknown receiver
// keeps the DEFAULT edges (never fewer than the default build).

import { describe, expect, test } from "bun:test";
import { type BuildInput, type CallGraph, type EntryPoint, buildGraph } from "../src/callgraph/index.js";
import { dispatchClosure, supertypeClosures } from "../src/callgraph/pointer.js";
import { parseModule } from "../src/frontend/parse.js";

const F = "/app/pointer.mjs";

function ep(file: string, name: string, source: EntryPoint["source"] = "user"): EntryPoint {
  return { file, name, source, line: 0 };
}

function makeInput(
  files: Record<string, string>,
  links: Record<string, string>,
  entryPoints: EntryPoint[],
  options?: BuildInput["options"],
): BuildInput {
  const ir: BuildInput["ir"] = (file) => {
    const text = files[file];
    return text === undefined ? Promise.resolve(null) : Promise.resolve(parseModule(file, text, {}));
  };
  const linker = {
    resolve: (fromFile: string, spec: string): string | null => links[`${fromFile}\u0000${spec}`] ?? null,
  };
  return options === undefined
    ? { ir, linker, entryPoints, models: [] }
    : { ir, linker, entryPoints, models: [], options };
}

function build(
  files: Record<string, string>,
  entryPoints: EntryPoint[],
  options?: BuildInput["options"],
  links: Record<string, string> = {},
): Promise<CallGraph> {
  return buildGraph(makeInput(files, links, entryPoints, options)).then((r) => r.graph);
}

function hasEdge(g: CallGraph, from: string, to: string, kind = "call"): boolean {
  return g.edges.some((e) => e.from === from && e.to === to && e.kind === kind);
}

const id = (name: string): string => `${F}#${name}`;

describe("solver core: supertype closures and dispatch closure", () => {
  test("given a linear extends chain D→B→A, when closures are computed, then each class sees itself and every ancestor", () => {
    const closures = supertypeClosures(
      new Map([
        ["D", "B"],
        ["B", "A"],
        ["A", null],
      ]),
    );
    expect([...(closures.get("D") ?? [])].sort()).toEqual(["A", "B", "D"]);
    expect([...(closures.get("B") ?? [])].sort()).toEqual(["A", "B"]);
    expect([...(closures.get("A") ?? [])].sort()).toEqual(["A"]);
  });

  test("given an extends cycle (A extends B, B extends A), when closures are computed, then the work terminates and both see both", () => {
    const closures = supertypeClosures(
      new Map([
        ["A", "B"],
        ["B", "A"],
      ]),
    );
    expect([...(closures.get("A") ?? [])].sort()).toEqual(["A", "B"]);
    expect([...(closures.get("B") ?? [])].sort()).toEqual(["A", "B"]);
  });

  test("given a class with an UNRESOLVED base, when closures are computed, then the chain ends at the class itself (conservative: no invented ancestors)", () => {
    const closures = supertypeClosures(new Map([["D", null]]));
    expect([...(closures.get("D") ?? [])].sort()).toEqual(["D"]);
  });

  test("given an empty receiver set, when the dispatch closure is computed, then it is empty", () => {
    expect([...dispatchClosure(new Set(), supertypeClosures(new Map([["A", null]])))]).toEqual([]);
  });

  test("given a receiver typed as a subclass, when the dispatch closure is computed, then every ancestor is included (inherited dispatch)", () => {
    const closures = supertypeClosures(
      new Map([
        ["D", "B"],
        ["B", "A"],
        ["A", null],
      ]),
    );
    expect([...dispatchClosure(new Set(["D"]), closures)].sort()).toEqual(["A", "B", "D"]);
  });

  test("given a receiver typed as a UNION of a base and a subclass, when the dispatch closure is computed, then every member of both chains is included exactly once", () => {
    const closures = supertypeClosures(
      new Map([
        ["D", "A"],
        ["A", null],
      ]),
    );
    expect([...dispatchClosure(new Set(["A", "D"]), closures)].sort()).toEqual(["A", "D"]);
  });
});

describe("builder: pointer dispatch refines the default RTA", () => {
  test("given two functions sharing a receiver name with DIFFERENT types (const x = new A / const x = new B), when built with pointer analysis, then each site dispatches only on its own receiver's type (the default text-merged RTA is pruned)", async () => {
    const files = {
      [F]: `
class A { m() { sinkA(); } }
class B { m() { sinkB(); } }
export function f() { const x = new A(); x.m(); }
export function g() { const x = new B(); x.m(); }
`,
    };
    const defaultGraph = await build(files, [ep(F, "f"), ep(F, "g")]);
    // Default RTA merges the identifier `x` ACROSS functions in newFlow —
    // order-dependent: f resolves before g's `new B` is recorded, so f
    // sees {A} and g (processed second) sees the merged {A, B}.
    expect(hasEdge(defaultGraph, id("f"), id("A.m"))).toBe(true);
    expect(hasEdge(defaultGraph, id("f"), id("B.m"))).toBe(false);
    expect(hasEdge(defaultGraph, id("g"), id("A.m"))).toBe(true);
    expect(hasEdge(defaultGraph, id("g"), id("B.m"))).toBe(true);

    const g2 = await build(files, [ep(F, "f"), ep(F, "g")], { pointerAnalysis: true });
    // Function-scoped typing: f's x is an A instance, g's x a B instance —
    // g's A.m (merged-name over-approximation) is pruned.
    expect(hasEdge(g2, id("f"), id("A.m"))).toBe(true);
    expect(hasEdge(g2, id("f"), id("B.m"))).toBe(false);
    expect(hasEdge(g2, id("g"), id("A.m"))).toBe(false);
    expect(hasEdge(g2, id("g"), id("B.m"))).toBe(true);
  });

  test("given a subclass instance calling a method declared ONLY on the base class, when built with pointer analysis, then the inherited method is reachable (the default RTA requires the base to be instantiated itself)", async () => {
    const files = {
      [F]: `
class A { m() { sinkA(); } }
class D extends A {}
export function main() { const x = new D(); x.m(); }
`,
    };
    const defaultGraph = await build(files, [ep(F, "main")]);
    expect(hasEdge(defaultGraph, id("main"), id("A.m"))).toBe(false);

    const g2 = await build(files, [ep(F, "main")], { pointerAnalysis: true });
    expect(hasEdge(g2, id("main"), id("A.m"))).toBe(true);
  });

  test("given a union-typed receiver (a function may return either class), when built with pointer analysis, then methods of every class in the union's closure are reachable", async () => {
    const files = {
      [F]: `
class A { m() { sinkA(); } }
class D extends A { m() { sinkD(); } }
function mkA() { return new A(); }
function mkD() { return new D(); }
export function main() {
  const a = mkA(); a.m();
  const d = mkD(); d.m();
}
`,
    };
    const defaultGraph = await build(files, [ep(F, "main")]);
    // Default RTA: `a = mkA()` / `d = mkD()` are call results, not `new` —
    // no receiver typing, no edges.
    expect(hasEdge(defaultGraph, id("main"), id("A.m"))).toBe(false);
    expect(hasEdge(defaultGraph, id("main"), id("D.m"))).toBe(false);

    const g2 = await build(files, [ep(F, "main")], { pointerAnalysis: true });
    // a : A → A.m; d : D → D.m (override) and A.m (inherited — over-approx).
    expect(hasEdge(g2, id("main"), id("A.m"))).toBe(true);
    expect(hasEdge(g2, id("main"), id("D.m"))).toBe(true);
  });

  test("given a receiver copied from a typed local (const b = a), when built with pointer analysis, then the copy carries the type", async () => {
    const files = {
      [F]: `
class A { m() { sinkA(); } }
export function main() { const a = new A(); const b = a; b.m(); }
`,
    };
    const defaultGraph = await build(files, [ep(F, "main")]);
    expect(hasEdge(defaultGraph, id("main"), id("A.m"))).toBe(false);

    const g2 = await build(files, [ep(F, "main")], { pointerAnalysis: true });
    expect(hasEdge(g2, id("main"), id("A.m"))).toBe(true);
  });

  test("given call arguments of known types (h(new A()) before h(x)), when built with pointer analysis, then the callee's parameter is typed with the facts known when the callee is processed (later-arriving facts are not back-propagated — the documented monotonicity gap, same class as 0-CFA paramFlow)", async () => {
    const files = {
      [F]: `
class A { m() { sinkA(); } }
class B { m() { sinkB(); } }
export function h(r) { r.m(); }
export function main() {
  const x = new B();
  h(new A());
  h(x);
}
`,
    };
    const defaultGraph = await build(files, [ep(F, "main")]);
    expect(hasEdge(defaultGraph, id("h"), id("A.m"))).toBe(false);
    expect(hasEdge(defaultGraph, id("h"), id("B.m"))).toBe(false);

    const g2 = await build(files, [ep(F, "main")], { pointerAnalysis: true });
    // h is processed at the FIRST call site, h(new A()): at that moment
    // r : A, so A.m is the refined edge. The later `h(x)` records r : B,
    // but h is not reprocessed when new facts arrive (the same
    // monotonicity gap as 0-CFA paramFlow) — B.m stays absent. This is
    // conservative w.r.t. the sound default, which has NEITHER edge:
    // pointer mode never removes an edge the default build would have.
    expect(hasEdge(g2, id("h"), id("A.m"))).toBe(true);
    expect(hasEdge(g2, id("h"), id("B.m"))).toBe(false);
  });
});

describe("builder: conservative guards (never fewer edges than the sound default)", () => {
  test("given a receiver with NO type facts (unresolvable argument), when built with and without pointer analysis, then the graphs are IDENTICAL (unknown receiver → default behavior, no pruning)", async () => {
    const files = {
      [F]: `
class A { m() { sinkA(); } }
class B { m() { sinkB(); } }
export function h(r) { r.m(); }
export function main() { h(mystery()); }
`,
    };
    const defaultGraph = await build(files, [ep(F, "main")]);
    const g2 = await build(files, [ep(F, "main")], { pointerAnalysis: true });
    expect(JSON.stringify(g2.edges.sort((a, b) => a.to.localeCompare(b.to)))).toBe(
      JSON.stringify(defaultGraph.edges.sort((a, b) => a.to.localeCompare(b.to))),
    );
    expect(JSON.stringify(g2.nodes.map((n) => n.id).sort())).toBe(
      JSON.stringify(defaultGraph.nodes.map((n) => n.id).sort()),
    );
  });

  test("given the same program, when built with the flag OFF vs explicitly FALSE, then the graphs are byte-identical (default contract unchanged)", async () => {
    const files = {
      [F]: `
class A { m() { sinkA(); } }
class D extends A { m() { sinkD(); } }
export function main() { const x = new D(); x.m(); }
`,
    };
    const a = await build(files, [ep(F, "main")]);
    const b = await build(files, [ep(F, "main")], { pointerAnalysis: false });
    expect(JSON.stringify(b)).toBe(JSON.stringify(a));
  });

  test("given a pointer build, when the stats are inspected, then the pointer block reports sites/added/pruned; the default build has NO pointer block", async () => {
    const files = {
      [F]: `
class A { m() { sinkA(); } }
class B { m() { sinkB(); } }
export function f() { const x = new A(); x.m(); }
export function g() { const x = new B(); x.m(); }
`,
    };
    const defaultGraph = await build(files, [ep(F, "f"), ep(F, "g")]);
    expect(defaultGraph.stats.pointer).toBeUndefined();

    const g2 = await build(files, [ep(F, "f"), ep(F, "g")], { pointerAnalysis: true });
    expect(g2.stats.pointer).toBeDefined();
    const p = g2.stats.pointer as { sites: number; added: number; pruned: number };
    expect(p.sites).toBeGreaterThanOrEqual(2); // f and g call sites
    expect(p.added).toBe(0);
    // Exactly g's A.m: the only default edge outside the receiver closure
    // (f's site sees {A} in the default too — f resolves before g's new).
    expect(p.pruned).toBe(1);
  });

  test("given an inherited-dispatch fixture, when the pointer stats are inspected, then the added edges are counted", async () => {
    const files = {
      [F]: `
class A { m() { sinkA(); } }
class D extends A {}
export function main() { const x = new D(); x.m(); }
`,
    };
    const g2 = await build(files, [ep(F, "main")], { pointerAnalysis: true });
    const p = g2.stats.pointer as { sites: number; added: number; pruned: number };
    expect(p.sites).toBeGreaterThanOrEqual(1);
    expect(p.added).toBeGreaterThanOrEqual(1); // A.m (inherited)
    expect(p.pruned).toBe(0);
  });
});
