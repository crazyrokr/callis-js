// M3 — IR snapshot tests, ESM forms (plan section 5.4).

import { describe, expect, test } from "bun:test";
import { parseModule } from "../src/frontend/parse.js";
import type { ModuleIR } from "../src/frontend/types.js";

describe("ESM imports (plan 5.4)", () => {
  test("given named/default/named-rename imports, when parsed, then the bindings are recorded", () => {
    const ir = parseModule(
      "m.mjs",
      `
      import def, { a, b as c } from "dep";
      import * as ns from "dep2";
      export { a };
    `,
    );
    expect(ir.imports[0]).toEqual({ module: "dep", kind: "esm", bindings: ["def", "a", "c"], dynamic: false, line: 2 });
    expect(ir.imports[1]?.bindings).toEqual(["ns"]);
  });

  test("given a dynamic import() of a literal, when parsed, then it is a dynamic import, not unresolved", () => {
    const ir = parseModule("m.mjs", `const p = import("dep");`);
    expect(ir.imports.some((i) => i.kind === "import-dynamic" && i.module === "dep")).toBe(true);
    expect(ir.unresolvedImports).toEqual([]);
  });

  test("given a dynamic import(expr), when parsed, then it is an import-expr marker AND unresolved", () => {
    const ir = parseModule("m.mjs", "const p = import(name);");
    expect(ir.dynamic.some((d) => d.kind === "import-expr")).toBe(true);
    expect(ir.unresolvedImports.length).toBe(1);
  });

  test("given a non-literal static import (grammar error shape), when parsed, then it is unresolved", () => {
    const ir = parseModule("m.mjs", "import x from name;");
    expect(ir.imports[0]?.dynamic).toBe(true);
    expect(ir.unresolvedImports.length).toBe(1);
  });
});

describe("ESM exports (plan 5.4)", () => {
  test("given export default function, when parsed, then default export + exported function summary", () => {
    const ir = parseModule(
      "m.mjs",
      `
      export default function handler(req, res) {
        const v = inner(req);
        return v;
      }
    `,
    );
    expect(ir.exports.some((e) => e.kind === "default" && e.local === "handler")).toBe(true);
    const fn = ir.functions.find((f) => f.name === "handler");
    expect(fn?.exported).toBe(true);
    expect(fn?.params).toEqual(["req", "res"]);
    expect(fn?.calls.some((c) => c.callee === "inner" && c.shape === "direct")).toBe(true);
    expect(fn?.returns).toContain("v");
  });

  test("given export {a, b as c}, when parsed, then named entries with local mapping", () => {
    const ir = parseModule(
      "m.mjs",
      `
      const a = 1;
      const b = 2;
      export { a, b as c };
    `,
    );
    expect(ir.exports.find((e) => e.name === "a")?.local).toBe("a");
    expect(ir.exports.find((e) => e.name === "c")?.local).toBe("b");
  });

  test("given export * from, when parsed, then a star re-export entry", () => {
    const ir = parseModule("m.mjs", `export * from "other";`);
    expect(ir.exports[0]).toEqual({ name: "*", from: "other", kind: "star", line: 1 });
  });

  test("given export {x} from, when parsed, then a named re-export with from", () => {
    const ir = parseModule("m.mjs", `export { x } from "other";`);
    expect(ir.exports[0]).toEqual({ name: "x", local: "x", from: "other", kind: "named", line: 1 });
  });

  test("given export function (modifier form), when parsed, then the function is exported and top-level", () => {
    const ir = parseModule("m.mjs", "export function f() { return 1; }");
    expect(ir.exports.some((e) => e.name === "f" && e.kind === "named")).toBe(true);
    const fn = ir.functions.find((x) => x.name === "f");
    expect(fn?.exported).toBe(true);
    expect(fn?.top).toBe(true);
    expect(fn?.kind).toBe("function");
  });

  test("given export const arrow, when parsed, then the function summary is exported", () => {
    const ir = parseModule("m.mjs", "export const f = async (x) => { await g(x); return x * 2; };");
    const fn = ir.functions.find((x) => x.name === "f");
    expect(fn?.exported).toBe(true);
    expect(fn?.isAsync).toBe(true);
    expect(fn?.kind).toBe("async");
  });
});

describe("top-level statements = module-init body (plan v3.3)", () => {
  test("given a top-level call, when parsed, then it is recorded with the called function name", () => {
    const ir = parseModule(
      "m.mjs",
      `
      function init() { setup(); }
      init();
    `,
    );
    const call = ir.topLevel.find((t) => t.kind === "call");
    expect(call?.functionName).toBe("init");
  });

  test("given a top-level assignment, when parsed, then it is recorded as an assignment", () => {
    const ir = parseModule("m.mjs", "let x = 1;");
    expect(ir.topLevel.length).toBeGreaterThan(0);
  });

  test("given a top-level IIFE, when parsed, then it is normalized to an ordinary function summary (interop)", () => {
    const ir = parseModule(
      "m.mjs",
      `(function () {
      doWork();
    })();`,
    );
    expect(ir.interop).toContain("iife");
    expect(ir.functions.length).toBe(1);
    expect(ir.functions[0]?.name.startsWith("<iife@")).toBe(true);
    expect(ir.functions[0]?.top).toBe(true);
    expect(ir.functions[0]?.calls.some((c) => c.callee === "doWork")).toBe(true);
  });
});

describe("call-site shapes (plan 5.4)", () => {
  test("given direct/member/optional/computed/new/tagged calls, when parsed, then the shapes are classified", () => {
    const ir = parseModule(
      "m.mjs",
      `
      export function f(a, o, obj, key, tpl, C) {
        a();
        o.m();
        o?.m();
        obj[key]();
        C2 = new C();
        tpl\`tag\${a}\`;
        return 1;
      }
    `,
    );
    const calls = ir.functions.find((x) => x.name === "f")?.calls ?? [];
    const shapes: string[] = calls.map((c) => c.shape).sort();
    expect(shapes).toEqual(["computed", "direct", "member", "new", "optional", "tagged"].sort());
    expect(calls.find((c) => c.shape === "optional")?.callee).toBe("o.m");
  });

  test("given super calls, when parsed, then the shape is super", () => {
    const ir = parseModule(
      "m.mjs",
      `
      export class D extends B {
        constructor() {
          super(1);
        }
      }
    `,
    );
    const ctor = ir.functions.find((x) => x.name === "D.#constructor");
    expect(ctor?.calls.some((c) => c.shape === "super" && c.callee === "super")).toBe(true);
  });
});

describe("function summaries (plan 5.4)", () => {
  test("given a class with constructor/methods/getter/setter/fields, when parsed, then qualified summaries are produced", () => {
    const ir = parseModule(
      "m.mjs",
      `
      export class Svc {
        count = 0;
        constructor(x) { this.count = x; }
        get value() { return this.count; }
        set value(v) { this.count = v; }
        bump() { this.count += 1; return this; }
      }
    `,
    );
    const names = ir.functions.map((f) => f.name).sort();
    expect(names).toEqual(["Svc.#constructor", "Svc.bump", "Svc.value", "Svc.value"]);
    const ctor = ir.functions.find((f) => f.name === "Svc.#constructor");
    expect(ctor?.kind).toBe("constructor");
    const getter = ir.functions.filter((f) => f.name === "Svc.value").find((f) => f.kind === "getter");
    expect(getter).toBeDefined();
    expect(ctor?.assignments.some((a) => a.target === "this.count" && a.kind === "member")).toBe(true);
  });

  test("given arrow function values flowing through assignments, when parsed, then the flow is recorded", () => {
    const ir = parseModule(
      "m.mjs",
      `
      export function f() {
        const fn = () => 1;
        a.b = fn;
        Foo.prototype.m = fn;
        return { go: fn };
      }
    `,
    );
    const fn = ir.functions.find((x) => x.name === "f");
    expect(fn?.assignments.some((a) => a.target === "a.b" && a.kind === "member" && a.value === "fn")).toBe(true);
    expect(fn?.assignments.some((a) => a.target === "Foo.prototype.m" && a.kind === "prototype")).toBe(true);
  });

  test("given an object literal with method members, when parsed, then qualified member summaries are produced", () => {
    const ir = parseModule(
      "m.mjs",
      `
      const obj = {
        run(x) { return work(x); },
      };
      export default obj;
    `,
    );
    const fn = ir.functions.find((x) => x.name === "obj.run");
    expect(fn).toBeDefined();
    expect(fn?.kind).toBe("method");
    expect(fn?.calls.some((c) => c.callee === "work")).toBe(true);
  });
});

describe("dynamic-risk markers (plan 5.5, ADR 0011)", () => {
  test("given eval / new Function / require(expr) / computed-call, when parsed, then markers are recorded with the nearest function", () => {
    const ir = parseModule(
      "m.mjs",
      `
      export function f(code, mod, obj, k) {
        eval(code);
        new Function(code)();
        require(mod);
        obj[k]();
        return 0;
      }
      eval("top");
    `,
    );
    const kinds: string[] = ir.dynamic.map((d) => d.kind).sort();
    expect(kinds).toEqual(["computed-call", "eval", "eval", "new-function", "require-expr"].sort());
    const inFn = ir.dynamic.find((d) => d.kind === "eval" && d.functionName === "f");
    expect(inFn).toBeDefined();
    const atTop = ir.dynamic.find((d) => d.kind === "eval" && d.functionName === undefined);
    expect(atTop).toBeDefined();
  });

  test("given require with a literal, when parsed, then NO require-expr marker (it is a normal import)", () => {
    const ir = parseModule("m.js", `const x = require("dep");`);
    expect(ir.dynamic.some((d) => d.kind === "require-expr")).toBe(false);
    expect(ir.imports.some((i) => i.kind === "require" && i.module === "dep")).toBe(true);
  });

  test("given a string-literal computed call, when parsed, then no computed-call marker", () => {
    const ir = parseModule("m.mjs", `const o = { m() { return 1; } }; o["m"]();`);
    expect(ir.dynamic.some((d) => d.kind === "computed-call")).toBe(false);
  });
});

describe("CJS forms (plan 5.4)", () => {
  test("given require with destructuring, when parsed, then the bindings are recorded", () => {
    const ir = parseModule("m.js", `const { a, b } = require("dep");\nconst c = require("dep2");`);
    expect(ir.imports[0]).toEqual({ module: "dep", kind: "require", bindings: [], dynamic: false, line: 1 });
    expect(ir.imports[1]?.bindings).toEqual(["c"]);
  });

  test("given module.exports = { fn }, when parsed, then module-exports + named entries + member summaries", () => {
    const ir = parseModule(
      "m.js",
      `
      module.exports = {
        run(x) {
          const r = work(x);
          return r;
        },
      };
    `,
    );
    expect(ir.exports.some((e) => e.kind === "module-exports")).toBe(true);
    expect(ir.exports.find((e) => e.name === "run")?.kind).toBe("named");
    const fn = ir.functions.find((f) => f.name === "run");
    expect(fn).toBeDefined();
    expect(fn?.returns).toContain("r");
  });

  test("given exports.x = function, when parsed, then a named export + exported function", () => {
    const ir = parseModule(
      "m.js",
      `
      exports.go = function (x) {
        return step(x);
      };
    `,
    );
    expect(ir.exports.find((e) => e.name === "go")?.kind).toBe("named");
    const fn = ir.functions.find((f) => f.name === "go");
    expect(fn?.exported).toBe(true);
  });

  test("given Object.defineProperty(exports, ...) accessors, when parsed, then getter/setter summaries + named exports", () => {
    const ir = parseModule(
      "m.js",
      `
      Object.defineProperty(exports, "value", {
        enumerable: true,
        get: function () {
          return read();
        },
      });
    `,
    );
    expect(ir.exports.find((e) => e.name === "value")?.kind).toBe("named");
    const fn = ir.functions.find((f) => f.name === "value");
    expect(fn?.kind).toBe("getter");
    expect(fn?.exported).toBe(true);
    expect(fn?.calls.some((c) => c.callee === "read")).toBe(true);
  });

  test("given interop helpers __exportStar/__importDefault, when parsed, then the interop list carries them", () => {
    const ir = parseModule(
      "m.js",
      `
      var __exportStar = Object.assign ? Object.assign : function (o) { for (var n in o) o[n] = o[n]; return o; };
      var dep = require("dep");
      __exportStar(dep, exports);
      var mod = __importDefault(require("mod"));
    `,
    );
    expect(ir.interop).toEqual(["exportStar", "importDefault"]);
  });

  test("given module.exports = <function> (function module), when parsed, then a default function summary", () => {
    const ir = parseModule(
      "m.js",
      `
      module.exports = function (x) {
        return x + 1;
      };
    `,
    );
    const fn = ir.functions.find((f) => f.name === "default");
    expect(fn).toBeDefined();
    expect(fn?.exported).toBe(true);
    expect(ir.exports.some((e) => e.kind === "module-exports")).toBe(true);
  });
});

describe("TS/JSX forms (plan 5.4)", () => {
  test("given TS with type annotations, when parsed, then types are ignored and the IR is the same shape", () => {
    const ir = parseModule(
      "m.ts",
      `
      export function add(a: number, b: number): number {
        return a + b;
      }
    `,
    );
    const fn = ir.functions.find((f) => f.name === "add");
    expect(fn?.params).toEqual(["a", "b"]);
    expect(fn?.returns).toContain("a + b");
    expect(ir.moduleFormat).toBe("esm");
  });

  test("given a JSX component, when parsed, then the component function is a summary and the format is esm", () => {
    const ir = parseModule(
      "m.jsx",
      `
      import React from "react";
      export const App = () => {
        return <div>{count()}</div>;
      };
    `,
    );
    const fn = ir.functions.find((f) => f.name === "App");
    expect(fn).toBeDefined();
    expect(ir.moduleFormat).toBe("esm");
  });

  test("given a .cjs file, when parsed, then the format is cjs", () => {
    const ir = parseModule("m.cjs", "module.exports = 1;");
    expect(ir.moduleFormat).toBe("cjs");
  });
});

describe("IR determinism + serialization (plan 5.4)", () => {
  test("given the same source parsed twice, when serialized, then the IR is byte-identical", () => {
    const src = `
      export function f(x) {
        const o = { m() { return x; } };
        return o.m();
      }
      f(1);
    `;
    const a = parseModule("m.mjs", src);
    const b = parseModule("m.mjs", src);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });

  test("given an IR, when serialized, then it is plain data (no AST, no functions)", () => {
    const ir: ModuleIR = parseModule("m.mjs", "export function f() { return 1; }");
    const round = JSON.parse(JSON.stringify(ir));
    expect(round.functions[0]?.name).toBe("f");
    expect(typeof round.functions[0]).toBe("object");
  });
});
