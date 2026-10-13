// @callis/core — runtime-agnostic pipeline core.
// The core never imports Bun APIs directly; platform-specific behavior goes
// through src/platform/ (plan section 3.1, ADR 0002). Submodule exports are
// added per milestone (M1 data layer, M2 project/resolver, M3 IR/frontend,
// M4 call graph, M5 verdict/report/engine/policy).

export const TOOL_VERSION = "0.1.0";
export const IR_VERSION = "1";
export const SCHEMA_VERSION = "1";
