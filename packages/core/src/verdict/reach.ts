// Graph reachability queries (plan section 5.6 "Call traces").
//
// Shortest path from the entry roots to a node, multi-source BFS with
// lexicographic-first tie-break (JVM ADR 0006 pinning: identical graphs
// yield identical traces).

import type { CallGraph, GraphEdge } from "../callgraph/types.js";

function adjacencyOf(g: CallGraph): Map<string, GraphEdge[]> {
  const adj = new Map<string, GraphEdge[]>();
  for (const e of g.edges) {
    const list = adj.get(e.from);
    if (list === undefined) adj.set(e.from, [e]);
    else list.push(e);
  }
  // Sorted adjacency: the lexicographic-first tie-break.
  for (const list of adj.values()) list.sort((a, b) => (a.to < b.to ? -1 : a.to > b.to ? 1 : 0));
  return adj;
}

/** All node ids reachable from any root (roots included). */
export function reachableFrom(g: CallGraph, roots: string[]): Set<string> {
  const adj = adjacencyOf(g);
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const r of [...roots].sort()) {
    if (!seen.has(r)) {
      seen.add(r);
      queue.push(r);
    }
  }
  while (queue.length > 0) {
    const cur = queue.shift() as string;
    for (const e of adj.get(cur) ?? []) {
      if (!seen.has(e.to)) {
        seen.add(e.to);
        queue.push(e.to);
      }
    }
  }
  return seen;
}

/**
 * Shortest path (node id list, root first) from any root to `target`, or
 * null when unreachable. Ties break lexicographically (sorted adjacency).
 */
export function shortestPath(g: CallGraph, roots: string[], target: string): string[] | null {
  if (roots.includes(target)) return [target];
  const adj = adjacencyOf(g);
  const parent = new Map<string, { from: string; edge: GraphEdge } | null>();
  const queue = [...roots].sort();
  for (const r of queue) parent.set(r, null);
  while (queue.length > 0) {
    const cur = queue.shift() as string;
    if (cur === target) break;
    for (const e of adj.get(cur) ?? []) {
      if (parent.has(e.to)) continue;
      parent.set(e.to, { from: cur, edge: e });
      queue.push(e.to);
    }
  }
  if (!parent.has(target)) return null;
  const path = [target];
  let cur: string | undefined = target;
  while (cur !== undefined) {
    const p = parent.get(cur);
    if (p === null || p === undefined) break;
    path.push(p.from);
    cur = p.from;
  }
  return path.reverse();
}

/** Whether any edge on the path used a name-based fallback (--cha / --over-approx). */
export function pathHasNameBasedFallback(g: CallGraph, path: string[]): boolean {
  const fallback = new Map<string, boolean>();
  for (const e of g.edges) {
    const key = `${e.from}\u0000${e.to}`;
    if (e.via === "cha" || e.via === "over-approx") fallback.set(key, true);
  }
  for (let i = 0; i + 1 < path.length; i++) {
    if (fallback.get(`${path[i] as string}\u0000${path[i + 1] as string}`) === true) return true;
  }
  return false;
}
