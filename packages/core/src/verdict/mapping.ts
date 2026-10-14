// vuln-mappings.json (plan section 5.6, ADR 0013).
//
// Keyed by canonical advisory id, targets expressed against the package's
// PUBLIC surface (internal file names change between versions):
//   { "CVE-2021-23337": [ {"package":"lodash","export":"template"} ] }
// `export` resolves through the package's exported functions to a graph node;
// `file` + `function` address internals. Malformed document => exit 2
// (JVM parity: the JVM schema is strict too). A mapping id matching no
// candidate is a warning, never fatal.

import { join } from "node:path";
import type { CallGraph } from "../callgraph/types.js";
import type { PackageRecord } from "../osv/normalize.js";
import { UsageError } from "../util/errors.js";
import { reachableFrom } from "./reach.js";

/** One target entry of one mapping. */
export interface MappingEntry {
  package: string;
  /** Public-surface target (resolves through the export table). */
  export?: string;
  /** Internal target (file relative to the package root). */
  file?: string;
  /** Internal target function (requires `file`). */
  function?: string;
  line: number;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/**
 * Parse and validate the mapping document. Throws UsageError (exit 2) on
 * anything malformed — the mapping is part of the soundness contract.
 */
export function parseMappings(doc: unknown): Map<string, MappingEntry[]> {
  if (!isRecord(doc)) throw new UsageError("vuln-mappings: the document must be a JSON object of id -> entries");
  const out = new Map<string, MappingEntry[]>();
  for (const [id, value] of Object.entries(doc)) {
    if (!Array.isArray(value)) throw new UsageError(`vuln-mappings: ${id} must map to an array of targets`);
    const entries: MappingEntry[] = [];
    for (const [i, v] of value.entries()) {
      if (!isRecord(v)) throw new UsageError(`vuln-mappings: ${id}[${i}] must be an object`);
      if (typeof v.package !== "string" || v.package.length === 0)
        throw new UsageError(`vuln-mappings: ${id}[${i}] needs a "package" string`);
      const entry: MappingEntry = { package: v.package, line: 0 };
      if (v.export !== undefined) {
        if (typeof v.export !== "string") throw new UsageError(`vuln-mappings: ${id}[${i}].export must be a string`);
        entry.export = v.export;
      }
      if (v.file !== undefined) {
        if (typeof v.file !== "string" || v.file.startsWith("/") || v.file.includes(".."))
          throw new UsageError(`vuln-mappings: ${id}[${i}].file must be a package-relative path`);
        entry.file = v.file;
        if (typeof v.function !== "string" || v.function.length === 0)
          throw new UsageError(`vuln-mappings: ${id}[${i}] with "file" needs a "function" string`);
        entry.function = v.function;
      }
      if (entry.export === undefined && entry.file === undefined)
        throw new UsageError(`vuln-mappings: ${id}[${i}] needs "export" or "file"+"function"`);
      entries.push(entry);
    }
    out.set(id, entries);
  }
  return out;
}

/** A resolved mapping target: the graph node it addresses (null: absent). */
export interface ResolvedTarget {
  entry: MappingEntry;
  /** Null when the target file/function is not in the graph. */
  nodeId: string | null;
  /** True when the target executes at import time (module-init reaches it). */
  importTime: boolean;
}

/**
 * Resolve the mapping entries of one advisory against the graph of one
 * instance directory. `export` matches loaded function nodes of the instance
 * named by the export; `file`+`function` addresses the node directly.
 */
export function resolveMappingTargets(
  record: PackageRecord,
  mappings: Map<string, MappingEntry[]>,
  graph: CallGraph,
  instanceDir: string,
): ResolvedTarget[] {
  const entries = mappings.get(record.canonicalId) ?? [];
  const byName = new Map<string, string[]>();
  for (const n of graph.nodes) {
    if (n.kind !== "function") continue;
    if (!n.file.startsWith(`${instanceDir}/`)) continue;
    const list = byName.get(n.name) ?? [];
    list.push(n.id);
    byName.set(n.name, list);
  }
  // Import-time execution: any module-init node of the instance reaches the
  // target (importing the package runs its import-time code).
  const inits = graph.nodes
    .filter((n) => n.kind === "module-init" && n.file.startsWith(`${instanceDir}/`))
    .map((n) => n.id);
  const initReachable = inits.length > 0 ? reachableFrom(graph, inits) : new Set<string>();

  const out: ResolvedTarget[] = [];
  for (const entry of entries) {
    if (entry.package !== record.packageName) continue;
    if (entry.export !== undefined) {
      const ids = byName.get(entry.export) ?? [];
      for (const id of [...ids].sort()) {
        out.push({ entry, nodeId: id, importTime: initReachable.has(id) });
      }
      continue;
    }
    if (entry.file !== undefined && entry.function !== undefined) {
      const nodeId = `${join(instanceDir, entry.file)}#${entry.function}`;
      const exists = graph.nodes.some((n) => n.id === nodeId);
      out.push({ entry, nodeId: exists ? nodeId : null, importTime: exists && initReachable.has(nodeId) });
    }
  }
  return out;
}
