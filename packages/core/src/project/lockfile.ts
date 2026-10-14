// Lockfile tie graphs (plan section 5.3 v3.5 item 7, ADR 0014).
//
// The tie graph is the SBOM dependencies[] when present, else the lockfile's
// resolved graph, else absent. This module builds the lockfile side:
// npm package-lock.json (v1 nested + v3 packages map) and the pnpm virtual
// store's on-disk structure. bun.lock is not parsed in v1 — its graph is
// "absent" and the gap is recorded, not guessed.

import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { join, posix, sep } from "node:path";
import { decodePnpmId } from "./scan.js";
import type { TieGraph, TieNode } from "./types.js";

/**
 * npm package-lock.json / npm-shrinkwrap.json at the given root -> lockfile
 * tie graph, or null when no parseable lockfile is present.
 *
 * v3 ("packages"): keys are install paths; the parent of
 * `node_modules/a/node_modules/b` is `node_modules/a` (nesting is the graph).
 * v1 ("dependencies"): nested objects; nesting is the graph the same way.
 */
export function npmLockfileGraph(installRoot: string): TieGraph | null {
  for (const name of ["package-lock.json", "npm-shrinkwrap.json"]) {
    const file = join(installRoot, name);
    if (!existsSync(file)) continue;
    let doc: unknown;
    try {
      doc = JSON.parse(readFileSync(file, "utf8"));
    } catch {
      return null;
    }
    if (typeof doc !== "object" || doc === null) return null;
    const d = doc as { packages?: Record<string, { name?: string; version?: string }>; dependencies?: unknown };
    const nodes = new Map<string, TieNode>();
    const edges: Array<[string, string]> = [];

    if (d.packages !== undefined) {
      const rootEntry = d.packages[""];
      nodes.set("", { key: "", name: typeof rootEntry?.name === "string" ? rootEntry.name : "" });
      for (const [path, entry] of Object.entries(d.packages)) {
        if (path === "") continue;
        const name = typeof entry.name === "string" ? entry.name : lastPathSegment(path);
        const node: TieNode = { key: path, name, path };
        if (typeof entry.version === "string" && entry.version.length > 0) node.version = entry.version;
        nodes.set(path, node);
        edges.push([parentOfLockPath(path), path]);
      }
      return { source: "lockfile", nodes, edges };
    }
    if (d.dependencies !== undefined) {
      const walk = (deps: Record<string, { version?: string; dependencies?: unknown }>, prefix: string): void => {
        for (const [name, entry] of Object.entries(deps)) {
          const key = `${prefix}${name}`;
          const node: TieNode = { key, name, path: `${prefix === "" ? "" : `${prefix}node_modules/`}${name}` };
          if (typeof entry.version === "string" && entry.version.length > 0) node.version = entry.version;
          nodes.set(key, node);
          edges.push([prefix === "" ? "" : prefix, key]);
          const sub = entry.dependencies;
          if (sub !== undefined && typeof sub === "object" && sub !== null) {
            walk(sub as Record<string, { version?: string; dependencies?: unknown }>, `${key}/`);
          }
        }
      };
      walk(d.dependencies as Record<string, { version?: string; dependencies?: unknown }>, "");
      return { source: "lockfile", nodes, edges };
    }
    return null;
  }
  return null;
}

function lastPathSegment(path: string): string {
  const parts = path.split("/");
  return parts[parts.length - 1] ?? "";
}

/** `node_modules/a/node_modules/b` -> `node_modules/a`; top level -> "". */
function parentOfLockPath(path: string): string {
  const idx = path.lastIndexOf("/node_modules/");
  if (idx > 0) return path.slice(0, idx);
  return "";
}

/**
 * pnpm tie graph from the on-disk virtual store:
 * `node_modules/.pnpm/<id>/node_modules/<dep>` symlinks are edges
 * `<id> -> <dep>`, and top-level `node_modules/<name>` links are root edges.
 */
export function pnpmLockfileGraph(projectRoot: string): TieGraph | null {
  const nm = join(projectRoot, "node_modules");
  const store = join(nm, ".pnpm");
  if (!existsSync(store)) return null;
  const nodes = new Map<string, TieNode>();
  const edges: Array<[string, string]> = [];
  const rootKey = "root";
  nodes.set(rootKey, { key: rootKey, name: "" });

  const storeEntries = safeReaddir(store);
  for (const entry of storeEntries) {
    if (!entry.isDirectory()) continue;
    const id = entry.name;
    const decoded = decodePnpmId(id);
    if (decoded === null) continue;
    const nodeKey = `store/${id}`;
    nodes.set(nodeKey, {
      key: nodeKey,
      name: decoded.name,
      version: decoded.version,
      path: `node_modules/.pnpm/${id}/node_modules/${decoded.name}`,
    });
    const inner = join(store, id, "node_modules");
    for (const dep of safeReaddir(inner)) {
      if (dep.name.startsWith("@")) {
        for (const sub of safeReaddir(join(inner, dep.name))) {
          pushStoreEdge(join(inner, dep.name, sub.name), nodeKey, nodes, edges);
        }
        continue;
      }
      pushStoreEdge(join(inner, dep.name), nodeKey, nodes, edges);
    }
  }
  for (const entry of safeReaddir(nm)) {
    if (entry.name === ".pnpm" || entry.name === ".modules.yaml" || entry.name.startsWith(".")) continue;
    const link = join(nm, entry.name);
    if (!statIfExists(link)) continue;
    const targetId = storeIdOfLink(link);
    if (targetId === null) continue;
    if (!nodes.has(`store/${targetId}`)) continue;
    edges.push([rootKey, `store/${targetId}`]);
  }
  if (nodes.size <= 1) return null;
  return { source: "lockfile", nodes, edges };
}

/** Record an edge from the store entry to the symlink target's store entry. */
function pushStoreEdge(
  linkPath: string,
  fromKey: string,
  nodes: Map<string, TieNode>,
  edges: Array<[string, string]>,
): void {
  if (!statIfExists(linkPath)) return;
  const targetId = storeIdOfLink(linkPath);
  if (targetId === null) return;
  const targetKey = `store/${targetId}`;
  if (!nodes.has(targetKey)) {
    const decoded = decodePnpmId(targetId);
    if (decoded === null) return;
    nodes.set(targetKey, {
      key: targetKey,
      name: decoded.name,
      version: decoded.version,
      path: `node_modules/.pnpm/${targetId}/node_modules/${decoded.name}`,
    });
  }
  edges.push([fromKey, targetKey]);
}

/** The `.pnpm/<id>` store id a symlink targets (realpath, last segment before /node_modules/). */
function storeIdOfLink(linkPath: string): string | null {
  let real: string;
  try {
    real = realpathSync(linkPath);
  } catch {
    return null;
  }
  const marker = `${sep}.pnpm${sep}`;
  const idx = real.lastIndexOf(marker);
  if (idx < 0) return null;
  const after = real.slice(idx + marker.length);
  const first = after.split(sep)[0];
  if (first === undefined || first.length === 0) return null;
  return first;
}

function safeReaddir(dir: string): { name: string; isDirectory(): boolean }[] {
  try {
    return readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

function statIfExists(path: string): boolean {
  try {
    statSync(path);
    return true;
  } catch {
    return false;
  }
}
