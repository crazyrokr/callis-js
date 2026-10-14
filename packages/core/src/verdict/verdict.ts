// Verdict decision (plan section 5.6, ADRs 0012-0013).
//
// Precedence (v3.4 item 11):
//   1. MALICIOUS_PACKAGE — a MAL-* record fails regardless of dev scope
//      (install scripts run on the CI machine at `npm ci` time).
//   2. DEV_ONLY — dev component without --include-dev (reachability analysis
//      only; the malware gate above is unaffected).
//   3. NO_SOURCE — the component has no instance on disk.
//   4. Reachability — REACHABLE whenever the evidence tier is met (a call
//      into a covered addon's JS wrapper satisfies the `call` tier);
//      NATIVE_OPAQUE only when the path ends at a .node/WASM boundary and
//      the tier is not otherwise met (the boundary crossing is the only
//      evidence); UNREACHABLE otherwise (mapping present but not reached,
//      or loaded-but-below-tier).
//   5. --sbom-only: APPLICABLE / MALICIOUS_PACKAGE / DEV_ONLY only — no
//      REACHABLE/UNREACHABLE without a call graph, NO_SOURCE dropped.

import type { CallGraph } from "../callgraph/types.js";
import type { PackageRecord } from "../osv/normalize.js";
import type { PackageInstance } from "../project/types.js";
import { UsageError } from "../util/errors.js";
import { type MappingEntry, parseMappings, resolveMappingTargets } from "./mapping.js";
import { pathHasNameBasedFallback, reachableFrom, shortestPath } from "./reach.js";
import type { Candidate, Confidence, Evidence, Finding, MatchLevel, Verdict } from "./types.js";

export interface VerdictOptions {
  /** Artifact-level evidence tier (default call). */
  packageEvidence: "call" | "load";
  /** Which evidence satisfies the call tier (default any). */
  callEvidence: "any" | "direct";
  includeDev: boolean;
  /** sbom-only: no call graph, no filesystem — APPLICABLE etc. only. */
  sbomOnly: boolean;
  /** Advisory id -> mapping entries (validated at startup). */
  mappings: Map<string, MappingEntry[]>;
  /** Entry node ids (module-init + named entries of every entry point). */
  entryRoots: string[];
  graph: CallGraph | null;
  /** Instance dirs the graph loaded (module-init nodes present). */
  loadedRealDirs: Set<string>;
  /** Instances whose directory contains a native (.node/WASM) artifact. */
  nativeRealDirs: Set<string>;
}

function emptyEvidence(): Evidence {
  return { loaded: false, called: false, callbackRegistered: false };
}

/** Evidence of one instance: which of its functions the graph touched. */
function evidenceOf(graph: CallGraph, instance: PackageInstance | null, loadedRealDirs: Set<string>): Evidence {
  const ev = emptyEvidence();
  if (instance === null) return ev;
  ev.loaded = loadedRealDirs.has(instance.realDir);
  if (!ev.loaded) return ev;
  const prefix = `${instance.realDir}/`;
  const inside = (nodeId: string): boolean => (nodeId.split("#")[0] as string).startsWith(prefix);
  // A call edge into the instance counts only when it comes from OUTSIDE the
  // instance (application/library code reaches the package): a package calling
  // its own functions (e.g. its module-init bootstrapping internals) is not
  // evidence that the application calls it. Model registration edges
  // (`model:emit`/`model:on`) are callback registrations, not calls.
  for (const e of graph.edges) {
    if (!inside(e.to)) continue;
    if (e.kind !== "call" || inside(e.from)) continue;
    if (e.via !== undefined && (e.via.startsWith("model:emit") || e.via === "model:on")) ev.callbackRegistered = true;
    else ev.called = true;
    if (ev.called && ev.callbackRegistered) break;
  }
  return ev;
}

/**
 * Decide the verdict for one candidate. `relatedIds` come from the M1
 * normalization (unmerged sibling findings, plan section 5.6).
 */
export function decideVerdict(
  candidate: Candidate,
  relatedIds: string[],
  options: VerdictOptions,
  supplyPath: string[] = [],
): Finding {
  const { record } = candidate;
  const ev =
    options.graph !== null ? evidenceOf(options.graph, candidate.instance, options.loadedRealDirs) : emptyEvidence();
  const base: Finding = {
    id: record.canonicalId,
    aliases: [...record.aliases].sort(),
    purl: candidate.purl,
    component: candidate.component,
    ...(candidate.componentVersion !== undefined ? { componentVersion: candidate.componentVersion } : {}),
    verdict: "UNREACHABLE",
    installed: candidate.instance !== null,
    evidence: ev,
    resolutionState: candidate.resolution === null ? "NOT_CHECKED" : candidate.resolution.state,
    ...(candidate.instance !== null ? { installedVersion: candidate.instance.version } : {}),
    matchedOn: candidate.matchedOn,
    source: candidate.source,
    relatedIds,
    matchLevel: "artifact",
    summary: record.summary,
    severity: record.severity,
    affectedRange: candidate.affectedRange,
    path: [],
    supplyPath,
  };

  // 1. Malicious: regardless of dev scope (plan 5.6, v3.1).
  if (record.malicious) {
    base.verdict = "MALICIOUS_PACKAGE";
    return base;
  }

  // --sbom-only: no call graph, no filesystem reconciliation.
  if (options.sbomOnly || options.graph === null) {
    base.verdict = candidate.devOnly && !options.includeDev ? "DEV_ONLY" : "APPLICABLE";
    return base;
  }

  // 2. Dev-only without --include-dev: reachability analysis is skipped.
  if (candidate.devOnly && !options.includeDev) {
    base.verdict = "DEV_ONLY";
    return base;
  }

  // 3. No source on disk.
  if (candidate.instance === null || candidate.resolution?.state === "MISSING") {
    base.verdict = "NO_SOURCE";
    return base;
  }

  const graph = options.graph;
  const instance = candidate.instance;
  const prefix = `${instance.realDir}/`;
  const inside = (nodeId: string): boolean => (nodeId.split("#")[0] as string).startsWith(prefix);
  const roots = options.entryRoots;
  const reachSet = reachableFrom(graph, roots);

  const tierMet = (e: Evidence): boolean =>
    options.packageEvidence === "load"
      ? e.loaded
      : options.callEvidence === "any"
        ? e.called || e.callbackRegistered
        : e.called;

  // 4a. Mapping-level precision (plan 5.6): the mapping resolves through the
  //     public surface to a node; import-time targets are REACHABLE below
  //     the tier (absence of a call edge is not evidence of non-execution);
  //     a mapping entry absent from the graph is UNREACHABLE, not an error.
  const targets =
    options.mappings.size > 0 ? resolveMappingTargets(record, options.mappings, graph, instance.realDir) : [];
  if (targets.length > 0) {
    base.matchLevel = "method";
    for (const t of targets) {
      if (t.nodeId === null) continue;
      const reachable = reachSet.has(t.nodeId);
      if (reachable || t.importTime) {
        const path = reachable ? (shortestPath(graph, roots, t.nodeId) ?? [t.nodeId]) : [t.nodeId];
        const confidence: Confidence = pathHasNameBasedFallback(graph, path) ? "NAME_BASED" : "PRECISE";
        base.verdict = "REACHABLE";
        base.confidence = confidence;
        base.path = path;
        // The most precise target wins: the first reachable one (sorted).
        return base;
      }
    }
    // Mapped, but no target is reachable nor import-time: UNREACHABLE.
    base.verdict = "UNREACHABLE";
    return base;
  }

  // 4b. Artifact-level tier.
  if (tierMet(ev)) {
    // The evidence node: the first called/registered function of the
    // instance (sorted for determinism).
    let evidenceNode: string | null = null;
    const candidates = graph.nodes
      .filter((n) => n.kind === "function" && inside(n.id))
      .map((n) => n.id)
      .sort();
    for (const id of candidates) {
      const touched =
        graph.edges.some((e) => e.to === id && e.kind === "call" && !inside(e.from)) ||
        graph.edges.some((e) => e.to === id && !inside(e.from) && (e.via === "model:emit" || e.via === "model:on"));
      if (touched) {
        evidenceNode = id;
        break;
      }
    }
    if (evidenceNode !== null) {
      base.path = shortestPath(graph, roots, evidenceNode) ?? [];
      base.confidence = pathHasNameBasedFallback(graph, base.path) ? "NAME_BASED" : "PRECISE";
    } else {
      // `load` tier: the package is imported but no function was called —
      // the module-init node of the instance is the evidence.
      const initNode = graph.nodes.find((n) => n.kind === "module-init" && inside(n.id));
      base.path = initNode !== undefined ? (shortestPath(graph, roots, initNode.id) ?? []) : [];
      base.confidence = "PRECISE";
    }
    base.verdict = "REACHABLE";
    return base;
  }

  // 4c. Below the tier. Native boundary beyond which the vulnerable code
  //     cannot be seen: NATIVE_OPAQUE (the boundary crossing is the only
  //     evidence, v3.4 item 11); otherwise UNREACHABLE.
  if (ev.loaded && options.nativeRealDirs.has(instance.realDir)) {
    base.verdict = "NATIVE_OPAQUE";
    base.nativeBoundary = ev.loaded ? "reached" : "unresolved";
    base.opaque = true;
    return base;
  }
  base.verdict = "UNREACHABLE";
  return base;
}

/**
 * Validate mapping ids against the candidate set (plan 5.6): a mapping id
 * matching no SBOM candidate is a WARNING, never fatal. Returns warnings.
 */
export function unmappedIds(mappings: Map<string, MappingEntry[]>, records: PackageRecord[]): string[] {
  const known = new Set(records.map((r) => r.canonicalId));
  const warnings: string[] = [];
  for (const id of [...mappings.keys()].sort()) {
    if (!known.has(id)) warnings.push(`mapping id ${id} matches no SBOM candidate (ignored)`);
  }
  return warnings;
}

/** Parse a mappings FILE (malformed => UsageError => exit 2; null => empty). */
export function parseMappingsFile(json: string | null): Map<string, MappingEntry[]> {
  if (json === null) return new Map();
  let doc: unknown;
  try {
    doc = JSON.parse(json);
  } catch (e) {
    throw new UsageError(`vuln-mappings: not a JSON document: ${(e as Error).message}`);
  }
  return parseMappings(doc);
}
