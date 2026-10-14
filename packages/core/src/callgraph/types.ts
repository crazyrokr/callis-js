// M4: call-graph data model (plan section 5.5).
//
// The graph is demand-driven: only modules reachable from the entry points
// are loaded and only their functions are expanded. Every node and edge is
// plain data (JSON-serializable); nothing downstream sees an AST or an IR.

export type NodeKind = "module-init" | "function" | "class";

/** One graph node. `id` is `${file}#${name}`; module-init uses `<module-init>`. */
export interface GraphNode {
  id: string;
  kind: NodeKind;
  file: string;
  name: string;
  line: number;
}

export type EdgeKind = "call" | "import" | "flow" | "instantiation" | "super";

/** One graph edge between node ids. */
export interface GraphEdge {
  from: string;
  to: string;
  kind: EdgeKind;
  line: number;
  /** How the edge was established: "model:map", "cha", "over-approx", "flow", ... */
  via?: string;
}

/** A dynamic-risk marker (ADR 0011) attached to the nearest reachable node. */
export interface MarkerRecord {
  kind: string;
  line: number;
  shape: string;
  /** The node the marker is scoped to, or null when it cannot be attributed. */
  scopedTo: string | null;
}

export type EntryPointSource =
  | "main"
  | "bin"
  | "exports"
  | "module"
  | "script"
  | "framework"
  | "callback-interface"
  | "user";

/** One curated or user-supplied entry point. */
export interface EntryPoint {
  file: string;
  /** Function name, or `<module-init>` for import-time entry. */
  name: string;
  source: EntryPointSource;
  line: number;
  framework?: string;
}

export interface GraphStats {
  /** Modules actually loaded into the graph (demand-driven). */
  modules: number;
  nodes: number;
  edges: number;
  dynamicMarkers: number;
  /** Markers not attributable to any function (exposure.dynamicUnscoped, 5.6). */
  unscopedMarkers: number;
}

/** The finished graph: plain data, ready for verdicts (M5) or `--dry-run-graph`. */
export interface CallGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  markers: MarkerRecord[];
  entryPoints: EntryPoint[];
  stats: GraphStats;
}

export const MODULE_INIT_NAME = "<module-init>";

export function moduleInitId(file: string): string {
  return `${file}#${MODULE_INIT_NAME}`;
}

export function functionId(file: string, name: string): string {
  return `${file}#${name}`;
}

export function classId(file: string, name: string): string {
  return `${file}#${name}`;
}

/** Options for the demand-driven builder. */
export interface BuildOptions {
  /** `--cha`: `x.m()` targets every loaded function named `m` (plan 5.5). */
  cha?: boolean;
  /** Computed calls with unknown keys: name-based fallback (plan 5.5). */
  overApproximateDynamic?: boolean;
}

/** Resolves an import specifier to a target file (the M2 resolver adapter). */
export interface Linker {
  resolve(fromFile: string, specifier: string, format: "import" | "require"): string | null;
}

/** Loads (parses) one file into IR; null when the file cannot be read. */
export type IrLoader = (file: string) => Promise<import("../frontend/index.js").ModuleIR | null>;

export interface BuildInput {
  ir: IrLoader;
  linker: Linker;
  /** Entry points from curated detection or user tokens (M5 wires the CLI). */
  entryPoints: EntryPoint[];
  models: import("./models.js").LibraryModel[];
  options?: BuildOptions;
}
