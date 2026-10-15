// M6 — dynamic require in a declaration initializer (golden demo
// vulnerable-demo-dynamic-risk): `const mod = require(which);` with a
// non-literal specifier is an unresolved dynamic construct — it must produce
// a require-expr marker (dynamic-risk exposure), not only an unresolved
// import row. The import() form already recorded both (M3).

import { describe, expect, test } from "bun:test";
import { parseModule } from "../src/frontend/parse.js";

describe("dynamic require in declaration initializers (plan 5.5, golden demo dynamic-risk)", () => {
  test("given `const mod = require(which);` at module scope, when parsed, then a require-expr marker is recorded (module scope) and the specifier stays unresolved", () => {
    const ir = parseModule("m.js", "const mod = require(which);");
    const marker = ir.dynamic.find((d) => d.kind === "require-expr");
    expect(marker).toBeDefined();
    // Module-scope marker: no enclosing function.
    expect(marker?.functionName).toBeUndefined();
    expect(ir.unresolvedImports).toEqual(["which"]);
    // The non-literal require is a require-dynamic import, never a plain require edge.
    const imp = ir.imports.find((i) => i.kind === "require-dynamic");
    expect(imp?.dynamic).toBe(true);
  });

  test("given `const mod = require(which);` inside a function, when parsed, then the marker is scoped to that function", () => {
    const ir = parseModule("m.js", "function f() { const mod = require(which); return mod; }");
    const marker = ir.dynamic.find((d) => d.kind === "require-expr");
    expect(marker?.functionName).toBe("f");
  });

  test('given a literal `const mod = require("dep");`, when parsed, then no dynamic marker is recorded', () => {
    const ir = parseModule("m.js", `const mod = require("dep");`);
    expect(ir.dynamic.find((d) => d.kind === "require-expr")).toBeUndefined();
    expect(ir.imports.some((i) => i.kind === "require" && i.module === "dep" && i.dynamic === false)).toBe(true);
  });

  test("given a bare expression `require(which);` (not in an initializer), when parsed, then a require-expr marker is recorded", () => {
    const ir = parseModule("m.js", "require(which);");
    expect(ir.dynamic.some((d) => d.kind === "require-expr")).toBe(true);
  });
});
