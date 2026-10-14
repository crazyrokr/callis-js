// @callis/core — runtime-agnostic pipeline core.
// The core never imports Bun APIs directly; platform-specific behavior goes
// through src/platform/ (plan section 3.1, ADR 0002). Submodule exports are
// added per milestone (M1 data layer, M2 project/resolver, M3 IR/frontend,
// M4 call graph, M5 verdict/report/engine/policy).

export const TOOL_VERSION = "0.1.0";
// Bumped to 2 in M4: ModuleIR gained classBases (super edges, plan 5.5) —
// older cache entries lack the field and must not be reused.
export const IR_VERSION = "2";
export const SCHEMA_VERSION = "1";

export * from "./util/errors.js";
export * from "./util/hash.js";
export * from "./sbom/index.js";
export * from "./osv/index.js";
export * from "./project/index.js";
export * from "./frontend/index.js";
export * from "./callgraph/index.js";
export * from "./verdict/index.js";
export * from "./report/index.js";
export * from "./engine/index.js";
