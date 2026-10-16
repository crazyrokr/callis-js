// Project model types (plan section 5.3, ADR 0014).
//
// An *instance* is one installed package *directory* (its realpath). Nested
// duplicates and pnpm peer-variant store entries with the same name+version
// are separate instances, never collapsed, each carrying its own verdict.

/** Per-component resolution state (ADR 0014; NOT_CHECKED under --sbom-only). */
export type ResolutionState = "RESOLVED" | "MISSING" | "VERSION_MISMATCH" | "AMBIGUOUS" | "NOT_CHECKED";

export interface PackageInstance {
  name: string;
  version: string;
  /** realpath of the package directory (symlinks resolved). */
  realDir: string;
  /** Path relative to the project root. */
  relPath: string;
  /** App-vs-library rule: realpath under a node_modules/ or .pnpm/ directory. */
  library: boolean;
  /** Nearest enclosing non-node_modules package (nested installs), null at top. */
  parent: { name: string; version: string } | null;
  /** package.json "type" field (module-format for .js files in the package). */
  pkgType: string;
  /** package.json "main" field, when present. */
  main?: string;
  /** package.json "bin" field, when present (entry-point detection, M4). */
  bin?: string;
}

export interface Workspace {
  dir: string;
  name: string;
}

export type Layout = "npm" | "pnpm" | "pnp" | "unknown";

/**
 * PnP layout context (M7c, ADR 0005 profile (c)): the data-driven install
 * facts the resolver needs. The `.pnp.cjs` itself is a marker only — never
 * executed or parsed (ADR 0017); these come from install-state + yarn.lock.
 */
export interface PnpContext {
  /** name@version → content-addressed extraction dir (zip found in a cache). */
  byLocator: Map<string, string>;
  /** Normalized descriptor (`name@npm:range`) → canonical lockfile entry key. */
  canonical: Map<string, string>;
  /** Workspace project dirs (application code; `workspace:` deps resolve there). */
  workspaceDirs: string[];
}

export interface ProjectModel {
  /** Absolute project root (the --project value). */
  root: string;
  /** Detected install layout (pnp carries the `pnp` context when supported). */
  layout: Layout;
  /** Workspace package directories (application code, analyzed per workspace). */
  workspaces: Workspace[];
  /** Every installed package instance (never collapsed by name+version). */
  instances: PackageInstance[];
  /** node_modules directories actually scanned (walked up for hoisting). */
  scannedDirs: string[];
  /**
   * The install root: the nearest ancestor of the project root that carries a
   * lockfile (npm workspaces hoist there). Walked-up scans stop there.
   */
  installRoot: string;
  /** PnP layout context (absent for the npm/pnpm layouts). */
  pnp?: PnpContext;
}

/** One node in the tie graph (SBOM ref or lockfile resolved entry). */
export interface TieNode {
  key: string;
  name: string;
  version?: string;
  /** Install path (lockfile graphs only; SBOM refs carry none). */
  path?: string;
}

/** The tie graph (ADR 0014): SBOM dependencies[] when present, else lockfile. */
export interface TieGraph {
  source: "sbom" | "lockfile" | "absent";
  nodes: Map<string, TieNode>;
  /** from -> to keys. */
  edges: Array<[string, string]>;
}

export interface ResolutionDecision {
  spec: string;
  fromDir: string;
  /**
   * resolved | builtin | unresolved | tsconfig-alias (profile b2, app code with
   * a detected runtime mechanism; no mechanism stays "unresolved").
   */
  status: "resolved" | "builtin" | "unresolved" | "tsconfig-alias";
  /** The resolved file (status resolved / tsconfig-alias). */
  target?: string;
  /** The instance directory the target lives in, when inside a package. */
  instanceDir?: string;
  moduleFormat: "cjs" | "esm" | "unknown";
  /** Candidate paths tried, in order (diagnostics, ADR 0005). */
  candidates: string[];
  /** Why this target was chosen (or why nothing resolved). */
  reason: string;
}
