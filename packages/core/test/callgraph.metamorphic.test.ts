// M4 — metamorphic soundness contract (plan v3.3 P0.1).
//
// Semantically equivalent program transformations must NEVER remove known
// reachability: if the canonical program proves a sink reachable, every
// transformed variant (alias, re-export, IIFE-wrap, rename) must prove the
// same sink reachable. The negative half: a function that is never called
// is never reached — until --cha over-approximates member calls.

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
): BuildInput {
  const ir: BuildInput["ir"] = (file) => {
    const text = files[file];
    return text === undefined ? Promise.resolve(null) : Promise.resolve(parseModule(file, text, {}));
  };
  const linker = {
    resolve: (fromFile: string, spec: string): string | null => links[`${fromFile}\u0000${spec}`] ?? null,
  };
  const models: LibraryModel[] = [];
  return options === undefined ? { ir, linker, entryPoints, models } : { ir, linker, entryPoints, models, options };
}

async function build(
  files: Record<string, string>,
  links: Record<string, string>,
  options?: BuildInput["options"],
): Promise<CallGraph> {
  const entry = ep(A, "main");
  return buildGraph(makeInput(files, links, [entry], options)).then((r) => r.graph);
}

function id(file: string, name: string): string {
  return `${file}#${name}`;
}

function init(file: string): string {
  return `${file}#<module-init>`;
}

/** All nodes reachable from the activated roots (entry inits + entry functions). */
function reached(g: CallGraph, roots: string[]): Set<string> {
  const seen = new Set<string>(roots);
  const queue = [...roots];
  while (queue.length > 0) {
    const cur = queue.pop();
    if (cur === undefined) break;
    for (const e of g.edges) {
      if (e.from === cur && !seen.has(e.to)) {
        seen.add(e.to);
        queue.push(e.to);
      }
    }
  }
  return seen;
}

const ROOTS = [init(A), id(A, "main")];

describe("known reachability survives equivalent transformations", () => {
  const canonical: Record<string, string> = {
    [A]: `import { handler } from "./b.mjs";
        export function main() { handler(); }`,
    [B]: `export function handler() { sink(); }
        function sink() { }`,
  };
  const linkAB: Record<string, string> = { [`${A}\u0000./b.mjs`]: B };

  test("given the canonical program, when built, then handler and sink are reachable (baseline)", async () => {
    const g = await build(canonical, linkAB);
    const r = reached(g, ROOTS);
    expect(r.has(id(B, "handler"))).toBe(true);
    expect(r.has(id(B, "sink"))).toBe(true);
  });

  test("given an alias (const alias = handler; alias()), when built, then handler and sink are STILL reachable", async () => {
    const files: Record<string, string> = {
      [A]: `import { handler } from "./b.mjs";
          export function main() { const alias = handler; alias(); }`,
      [B]: canonical[B] as string,
    };
    const g = await build(files, linkAB);
    const r = reached(g, ROOTS);
    expect(r.has(id(B, "handler"))).toBe(true);
    expect(r.has(id(B, "sink"))).toBe(true);
  });

  test("given a re-export in the middle (A -> C -> B), when built, then handler and sink are STILL reachable", async () => {
    const files: Record<string, string> = {
      [A]: `import { h } from "./c.mjs";
          export function main() { h(); }`,
      [C]: `export { handler as h } from "./b.mjs";`,
      [B]: canonical[B] as string,
    };
    const links = { [`${A}\u0000./c.mjs`]: C, [`${C}\u0000./b.mjs`]: B };
    const g = await build(files, links);
    const r = reached(g, ROOTS);
    expect(r.has(id(B, "handler"))).toBe(true);
    expect(r.has(id(B, "sink"))).toBe(true);
  });

  test("given the call moved into an import-time IIFE, when built, then handler and sink are STILL reachable", async () => {
    const files: Record<string, string> = {
      [A]: `import { handler } from "./b.mjs";
          (function () { handler(); })();
          export function main() { }`,
      [B]: canonical[B] as string,
    };
    const g = await build(files, linkAB);
    const r = reached(g, ROOTS);
    expect(r.has(id(B, "handler"))).toBe(true);
    expect(r.has(id(B, "sink"))).toBe(true);
  });

  test("given a rename (export h2, import { h2 as handler }), when built, then h2 and sink are STILL reachable", async () => {
    const files: Record<string, string> = {
      [A]: `import { h2 as handler } from "./b.mjs";
          export function main() { handler(); }`,
      [B]: `export function h2() { sink(); }
          function sink() { }`,
    };
    const g = await build(files, linkAB);
    const r = reached(g, ROOTS);
    expect(r.has(id(B, "h2"))).toBe(true);
    expect(r.has(id(B, "sink"))).toBe(true);
  });
});

describe("never-called functions are not reached", () => {
  test("given an exported function that is never called, when built (default), then it is NOT reached", async () => {
    const files: Record<string, string> = {
      [A]: `import { unused } from "./b.mjs";
          export function main() { const x = make(); x.unused(); }`,
      [B]: `export function unused() { }
          function make() { return {}; }`,
    };
    const links = { [`${A}\u0000./b.mjs`]: B };
    const g = await build(files, links);
    const r = reached(g, ROOTS);
    expect(r.has(id(B, "unused"))).toBe(false);
  });

  test("given the same program with --cha, when built, then every loaded function named unused IS reached (over-approximation)", async () => {
    const files: Record<string, string> = {
      [A]: `import { unused } from "./b.mjs";
          export function main() { const x = make(); x.unused(); }`,
      [B]: `export function unused() { }
          function make() { return {}; }`,
    };
    const links = { [`${A}\u0000./b.mjs`]: B };
    const g = await build(files, links, { cha: true });
    const r = reached(g, ROOTS);
    expect(r.has(id(B, "unused"))).toBe(true);
  });
});
