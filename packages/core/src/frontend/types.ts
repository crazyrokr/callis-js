// Front-end IR types (plan section 5.4).
//
// Per-file extraction produces a SERIALIZABLE IR; nothing downstream sees an
// AST. Every module has a module-init node conceptually: top-level
// statements (executed on load) are recorded here and M4 connects them to
// the module-init graph node via the import edges.

/** How the file is interpreted (the type field, ADR 0005). */
export type ModuleFormat = "cjs" | "esm" | "unknown";

/** One local binding of an import: `import {b as c}` → {local: c, exported: b}. */
export interface ImportBinding {
  local: string;
  /** The exported name ("default" for default imports, "*" for a namespace). */
  exported: string;
}

export interface ImportDecl {
  /** Literal specifier, or the (capped) expression text when non-literal. */
  module: string;
  kind: "esm" | "require" | "import-dynamic" | "require-dynamic";
  /** Local binding → exported name (the call graph resolves through these). */
  bindings: ImportBinding[];
  /** True for import(expr) / require(expr) — dynamic-risk markers (plan 5.5). */
  dynamic: boolean;
  line: number;
}

export interface ExportDecl {
  /** Exported name ("default" for default exports, "*" for re-export stars). */
  name: string;
  /** Local identifier for named exports (undefined for default/star). */
  local?: string;
  /** Re-export source module (export ... from "..."). */
  from?: string;
  kind: "named" | "default" | "star" | "module-exports";
  line: number;
}

export type CallShape = "direct" | "member" | "computed" | "new" | "optional" | "tagged" | "super" | "dynamic";

export interface CallSite {
  shape: CallShape;
  /** Best-effort callee name (a / a.b / the capped expression text). */
  callee: string;
  isOptional: boolean;
  /** Argument shapes (capped). */
  args: string[];
  line: number;
}

export type AssignmentKind =
  | "identifier"
  | "member"
  | "prototype"
  | "object-literal"
  | "class-field"
  | "defineProperty";

/** Assignments relevant to function-valued flow (plan 5.4). */
export interface Assignment {
  /** Target shape: a / a.b / Foo.prototype.m. */
  target: string;
  /** Value shape (identifier / call / the capped expression text). */
  value: string;
  kind: AssignmentKind;
  line: number;
}

export type FunctionKind =
  | "function"
  | "arrow"
  | "method"
  | "constructor"
  | "getter"
  | "setter"
  | "generator"
  | "async";

export interface FunctionSummary {
  /** Qualified name (local id, a.b, Name.member, Name.#constructor, <iife@N>). */
  name: string;
  kind: FunctionKind;
  isAsync: boolean;
  isGenerator: boolean;
  /** Parameter names. */
  params: string[];
  /** Return expression shapes (capped; [] when none). */
  returns: string[];
  calls: CallSite[];
  assignments: Assignment[];
  line: number;
  /** True when the function is (directly) exported from the module. */
  exported: boolean;
  /** True when the function is a top-level declaration (module-init body). */
  top: boolean;
}

/** A top-level statement (executed on load — the module-init body, plan v3.3). */
export interface TopLevelStmt {
  kind: "call" | "assignment" | "expression" | "other";
  /** Compact shape description (capped expression text). */
  shape: string;
  line: number;
  /** The declared function it calls, when the callee is a module function. */
  functionName?: string;
}

/** A class declaration and its `extends` target (super edges, plan 5.5). */
export interface ClassDecl {
  name: string;
  /** The `extends` target name (undefined for classes without a base). */
  base?: string;
  line: number;
}

/** Unresolvable constructs, recorded never dropped (plan 5.5, ADR 0011). */
export interface DynamicMarker {
  kind: "eval" | "new-function" | "require-expr" | "import-expr" | "computed-call";
  /** Capped expression text. */
  shape: string;
  line: number;
  /** Nearest enclosing function (undefined at module scope = module-init). */
  functionName?: string;
}

export interface ModuleIR {
  schemaVersion: number;
  /** File path the IR was parsed from. */
  file: string;
  moduleFormat: ModuleFormat;
  imports: ImportDecl[];
  exports: ExportDecl[];
  /** Top-level statements, in source order (the module-init body). */
  topLevel: TopLevelStmt[];
  /**
   * Module-scope assignments to call/new values (`const app = express()`),
   * in source order — framework creator detection (M4 entry points).
   */
  moduleAssignments: Assignment[];
  functions: FunctionSummary[];
  /** Class declarations and their `extends` target (super edges, plan 5.5). */
  classBases: ClassDecl[];
  dynamic: DynamicMarker[];
  /** Recognized interop forms: UMD wrapper, IIFE, __exportStar, __importDefault... */
  interop: string[];
  /** Import specifiers that are not string literals (dynamic; M4 markers). */
  unresolvedImports: string[];
}

/** Parse options — part of the IR cache key (plan section 5.4, v3.3). */
export interface ParseOptions {
  /** Script kind hint (auto-detected from the extension when absent). */
  scriptKind?: "js" | "jsx" | "ts" | "tsx";
  /** Module format hint (from the resolver's type-field decision). */
  moduleFormat?: ModuleFormat;
}
