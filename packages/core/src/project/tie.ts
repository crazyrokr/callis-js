// Per-component resolution states + tie graph (plan section 5.3, ADR 0014).
//
// States: RESOLVED (name+version on disk), MISSING (none), VERSION_MISMATCH
// (name present, version differs), AMBIGUOUS (name+version exists but the
// component cannot be tied to ANY instance through the tie graph), NOT_CHECKED
// (--sbom-only: no filesystem reconciliation).
//
// The tie graph is the SBOM dependencies[] when present, else the lockfile's
// resolved graph, else absent — with neither graph, duplicate instances stay
// separate instances, never AMBIGUOUS.

import { resolve as resolvePath } from "node:path";
import type { SbomParseResult } from "../sbom/types.js";
import type { PackageInstance, ProjectModel, ResolutionState, TieGraph, TieNode } from "./types.js";

export interface ComponentResolution {
  component: { purl: string; name: string; version?: string };
  state: ResolutionState;
  /** Instances tied to this component (or all same-name instances, un-tied). */
  instances: PackageInstance[];
  /** Directories the resolver tried (MISSING diagnostics). */
  triedDirs: string[];
  /** The tie graph used for the state decision. */
  graphSource: "sbom" | "lockfile" | "absent";
}

/**
 * Select the tie graph (ADR 0014): SBOM dependencies[] when present, else the
 * lockfile graph (already built by the caller), else absent.
 */
export function tieGraphFor(sbom: SbomParseResult, lockfileGraph: TieGraph | null): TieGraph {
  if (sbom.dependencies.length > 0) {
    const nodes = new Map<string, TieNode>();
    const byRef = new Map<string, { name: string; version?: string }>();
    for (const c of sbom.components) {
      const rec: { name: string; version?: string } = { name: c.name };
      if (c.version !== undefined) rec.version = c.version;
      byRef.set(c.ref, rec);
    }
    for (const edge of sbom.dependencies) {
      const c = byRef.get(edge.ref) ?? null;
      const node: TieNode = {
        key: edge.ref,
        name: c?.name ?? edge.ref,
      };
      if (c !== null && c.version !== undefined) node.version = c.version;
      if (!nodes.has(edge.ref)) nodes.set(edge.ref, node);
    }
    for (const c of sbom.components) {
      if (!nodes.has(c.ref)) {
        const node: TieNode = { key: c.ref, name: c.name };
        if (c.version !== undefined) node.version = c.version;
        nodes.set(c.ref, node);
      }
    }
    const edges: Array<[string, string]> = [];
    for (const edge of sbom.dependencies) {
      for (const dep of edge.dependsOn) {
        edges.push([edge.ref, dep]);
      }
    }
    return { source: "sbom", nodes, edges };
  }
  if (lockfileGraph !== null) return lockfileGraph;
  return { source: "absent", nodes: new Map(), edges: [] };
}

/** Path in the tie graph (BFS, bounded) from key `from` to any of `toKeys`. */
function reaches(graph: TieGraph, from: string, toKeys: Set<string>): boolean {
  if (!graph.nodes.has(from)) return false;
  if (toKeys.has(from)) return true;
  const adjacency = new Map<string, string[]>();
  for (const [a, b] of graph.edges) {
    const list = adjacency.get(a) ?? [];
    list.push(b);
    adjacency.set(a, list);
  }
  const seen = new Set<string>([from]);
  const queue = [from];
  while (queue.length > 0) {
    const cur = queue.shift() as string;
    for (const next of adjacency.get(cur) ?? []) {
      if (seen.has(next)) continue;
      if (toKeys.has(next)) return true;
      seen.add(next);
      queue.push(next);
    }
  }
  return false;
}

/** Graph nodes tied to an instance (name+version, and path when the node has one). */
function nodesTiedToInstance(graph: TieGraph, instance: PackageInstance, installRoot: string): Set<string> {
  const out = new Set<string>();
  for (const node of graph.nodes.values()) {
    if (node.name !== instance.name) continue;
    if (node.version !== undefined && node.version !== instance.version) continue;
    if (
      node.path !== undefined &&
      normalizePath(resolvePath(installRoot, node.path)) !== normalizePath(instance.realDir)
    )
      continue;
    out.add(node.key);
  }
  return out;
}

function normalizePath(p: string): string {
  return p.replace(/\\/g, "/").replace(/^\.\//, "");
}

/**
 * The resolution state of one SBOM component (independent of OSV matches —
 * computed before candidate generation, plan v3.5 item 8).
 */
export function componentResolution(
  component: { purl: string; name: string; version?: string },
  model: ProjectModel,
  graph: TieGraph,
  triedDirs: string[] = [],
): ComponentResolution {
  const sameName = model.instances.filter((i) => i.name === component.name);
  const matching = sameName.filter((i) => component.version === undefined || i.version === component.version);

  if (sameName.length === 0) {
    return { component, state: "MISSING", instances: [], triedDirs, graphSource: graph.source };
  }
  if (matching.length === 0) {
    return { component, state: "VERSION_MISMATCH", instances: sameName, triedDirs, graphSource: graph.source };
  }

  // AMBIGUOUS: name+version instances exist but the component cannot be tied
  // to ANY of them through the tie graph.
  const tied = tiedInstancesForComponent(component, matching, graph, model.installRoot);
  if (graph.source !== "absent" && tied.length === 0) {
    return { component, state: "AMBIGUOUS", instances: matching, triedDirs, graphSource: graph.source };
  }
  return {
    component,
    state: "RESOLVED",
    instances: tied.length > 0 ? tied : matching,
    triedDirs,
    graphSource: graph.source,
  };
}

/**
 * The matching instances this component is tied to.
 * - sbom graph: tie by name+version (SBOM refs carry no install path) — every
 *   matching instance is tied; duplicates stay separate, never AMBIGUOUS.
 * - lockfile graph: tie through nodes that reach the component's own node.
 * - absent graph: every matching instance (no graph to check).
 */
function tiedInstancesForComponent(
  component: { name: string; version?: string },
  matching: PackageInstance[],
  graph: TieGraph,
  installRoot: string,
): PackageInstance[] {
  if (graph.source === "absent") return matching;
  if (graph.source === "sbom") return matching;
  // lockfile graph: find the component's own node (by name+version).
  const ownKeys = new Set<string>();
  for (const node of graph.nodes.values()) {
    if (node.name !== component.name) continue;
    if (node.version !== undefined && component.version !== undefined && node.version !== component.version) continue;
    ownKeys.add(node.key);
  }
  const out: PackageInstance[] = [];
  for (const instance of matching) {
    const tiedKeys = nodesTiedToInstance(graph, instance, installRoot);
    if (tiedKeys.size === 0) continue;
    if (ownKeys.size === 0) {
      // The component is not in the lockfile at all, but an instance node with
      // its name+version exists on disk: tied (the lockfile is stale, the
      // instance is real). Never AMBIGUOUS for on-disk evidence.
      out.push(instance);
      continue;
    }
    if (
      reaches(graph, ownKeyForInstance(ownKeys, instance, graph, installRoot), tiedKeys) ||
      intersects(ownKeys, tiedKeys)
    ) {
      out.push(instance);
    }
  }
  return out;
}

function ownKeyForInstance(
  ownKeys: Set<string>,
  instance: PackageInstance,
  graph: TieGraph,
  installRoot: string,
): string {
  const tiedKeys = nodesTiedToInstance(graph, instance, installRoot);
  for (const key of tiedKeys) if (ownKeys.has(key)) return key;
  return [...ownKeys][0] as string;
}

function intersects(a: Set<string>, b: Set<string>): boolean {
  for (const x of a) if (b.has(x)) return true;
  return false;
}

/**
 * States for all components (the completeness block input, ADR 0012).
 * `sbomOnly` marks everything NOT_CHECKED (no filesystem in that mode).
 */
export function allComponentResolutions(
  components: { purl: string; name: string; version?: string; ref: string }[],
  model: ProjectModel,
  graph: TieGraph,
  sbomOnly: boolean,
): ComponentResolution[] {
  if (sbomOnly) {
    return components.map((c) => ({
      component: c,
      state: "NOT_CHECKED",
      instances: [],
      triedDirs: [],
      graphSource: graph.source,
    }));
  }
  const dirs = model.scannedDirs;
  return components.map((c) => componentResolution(c, model, graph, dirs));
}
