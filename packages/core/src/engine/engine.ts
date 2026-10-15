// AnalyzerEngine (plan section 5.6, ADR 0016).
//
// The facade over the whole pipeline: SBOM + OSV snapshot -> project model
// -> call graph -> candidates -> verdicts -> structured result -> reports.
// Usage errors (exit 2) throw UsageError BEFORE analysis; guard failures
// (exit 3) still write a minimal report so the CI artifact explains the
// run. The policy layer (engine/policy) maps the finished result to the
// exit code — independently tested for every flag combination.

import { existsSync, readFileSync } from "node:fs";
import { mkdir, readdir, rm } from "node:fs/promises";
import { dirname } from "node:path";
import {
  type CallGraph,
  appFilesOf,
  buildGraph,
  detectEntryPoints,
  loadModels,
  makeLinker,
} from "../callgraph/index.js";
import { parseFile } from "../frontend/cache.js";
import { parseModule } from "../frontend/parse.js";
import type { ModuleIR } from "../frontend/types.js";
import { SCHEMA_VERSION, TOOL_VERSION } from "../index.js";
import { loadSnapshot } from "../osv/loader.js";
import { normalizeRecords, relatedIds } from "../osv/normalize.js";
import { allDevNotice, emptySbomGuard, totalResolutionGuard } from "../project/guards.js";
import { npmLockfileGraph, pnpmLockfileGraph } from "../project/lockfile.js";
import { unlistedInstalled } from "../project/reconcile.js";
import { buildProjectModel } from "../project/scan.js";
import { type ComponentResolution, allComponentResolutions, tieGraphFor } from "../project/tie.js";
import type { TieGraph } from "../project/types.js";
import type { PackageInstance, ProjectModel, ResolutionState } from "../project/types.js";
import {
  type AnalysisResult,
  type Completeness,
  type ComponentState,
  type GuardStates,
  type NodeLocation,
  type ReportMeta,
  type UnresolvedImport,
  assembleResult,
  computeExposure,
  computeLimitations,
  writeJUnitReport,
  writeJsonReport,
  writeSarifReport,
} from "../report/index.js";
import { readSbom, supplyPath as sbomSupplyPath } from "../sbom/index.js";
import { type Notice, UsageError } from "../util/errors.js";
import { buildCandidates, supplyRoot } from "../verdict/candidate.js";
import { resolveMappingTargets } from "../verdict/mapping.js";
import type { MappingEntry } from "../verdict/mapping.js";
import type { Finding } from "../verdict/types.js";
import { decideVerdict, parseMappingsFile, unmappedIds } from "../verdict/verdict.js";
import { decideExitCode } from "./policy.js";

export interface EngineOptions {
  project: string;
  sbom: string;
  osvDir: string;
  osvChecksum?: string;
  mappings?: string;
  /** `--entry-points` tokens (extend the curated detection). */
  entryPoints: string[];
  /** `--entry-points-only` tokens (replace; non-empty = replace mode). */
  entryPointsOnly: string[];
  callbackInterfaces: string[];
  cha: boolean;
  pointerAnalysis: boolean;
  packageEvidence: "call" | "load";
  callEvidence: "any" | "direct";
  includeDev: boolean;
  includeTests: boolean;
  malware: "fail" | "warn" | "ignore";
  failOnApplicable: boolean;
  strictSources: boolean;
  requireComplete: boolean;
  allowEmptySbom: boolean;
  matchInstalled: boolean;
  opaqueNative: "fail" | "warn" | "ignore";
  sbomOnly: boolean;
  overApproximateDynamic: boolean;
  cacheDir: string;
  formats: string[];
  output: string;
  verbose: boolean;
  dryRunSbom?: boolean;
  dryRunMatch?: boolean;
  dryRunGraph?: boolean;
}

export interface Console {
  out: (s: string) => void;
  err: (s: string) => void;
}

const DEFAULT_CONSOLE: Console = { out: (s) => console.log(s), err: (s) => console.error(s) };

/** Flag validation (exit 2 conditions; JVM parity). */
export function validateFlags(opts: EngineOptions): void {
  if (opts.cha && opts.pointerAnalysis)
    throw new UsageError("--cha and --pointer-analysis are mutually exclusive precision modes");
  if (opts.failOnApplicable && !opts.sbomOnly)
    throw new UsageError("--fail-on-applicable is only meaningful in --sbom-only mode (v3.5 item 6)");
  for (const f of new Set(opts.formats)) {
    if (f !== "json" && f !== "junitxml" && f !== "sarif") throw new UsageError(`unknown --format token: ${f}`);
  }
  if (!opts.sbomOnly && !existsSync(opts.project)) throw new UsageError(`project directory not found: ${opts.project}`);
}

function builderName(opts: EngineOptions): string {
  let name = "demand-0cfa";
  if (opts.cha) name += "+cha";
  if (opts.overApproximateDynamic) name += "+over-approx";
  if (opts.pointerAnalysis) name += "+pointer";
  return name;
}

/** Report file names for the requested formats (stale cleanup + writing). */
export function reportFiles(output: string, formats: string[]): Record<string, string> {
  const files: Record<string, string> = {};
  for (const f of [...new Set(formats)].sort()) {
    if (f === "json") files.json = `${output}.json`;
    if (f === "junitxml") files.junitxml = `${output}.junit.xml`;
    if (f === "sarif") files.sarif = `${output}.sarif`;
  }
  return files;
}

/** Stale-report deletion (JVM parity): previous reports of this run die first. */
async function deleteStaleReports(output: string, formats: string[]): Promise<void> {
  for (const file of Object.values(reportFiles(output, formats))) {
    try {
      await rm(file, { force: true });
    } catch {
      // an unwritable target is surfaced at write time, not here
    }
  }
}

async function writeReports(
  result: AnalysisResult,
  opts: EngineOptions,
  console: Console,
  nodeLocations?: Record<string, NodeLocation>,
): Promise<void> {
  // A missing output parent is created (a fresh CI workspace); a destination
  // that CANNOT be created or written is the exit-3 condition (plan section 6).
  const dir = dirname(opts.output);
  if (dir !== "" && dir !== ".") await mkdir(dir, { recursive: true });
  await deleteStaleReports(opts.output, opts.formats);
  const files = reportFiles(opts.output, opts.formats);
  if (files.json !== undefined) await writeJsonReport(result, files.json);
  if (files.junitxml !== undefined) await writeJUnitReport(result, files.junitxml);
  if (files.sarif !== undefined) await writeSarifReport(result, files.sarif, nodeLocations);
  if (opts.verbose) {
    for (const f of Object.values(files)) console.out(`report written: ${f}`);
  }
}

/** Node ids to source locations (M7b: the SARIF codeFlow physical anchors).
 *  Undefined when no graph was built (sbom-only / guard failure): the hops
 *  then stay logical node ids. */
function nodeLocationsOf(graph: CallGraph | null): Record<string, NodeLocation> | undefined {
  if (graph === null) return undefined;
  const map: Record<string, NodeLocation> = {};
  for (const n of graph.nodes) map[n.id] = { file: n.file, line: n.line };
  return map;
}

/** The console summary (analysisStatus next to the verdict summary, v3.3). */
function printSummary(result: AnalysisResult, console: Console): void {
  const f = result.findings;
  const reachable = f.filter((x) => x.verdict === "REACHABLE").length;
  console.out(
    `analysisStatus: ${result.analysisStatus} — ${f.length} findings (${reachable} reachable, ${result.exposure.noSource} no-source, ${result.exposure.nativeOpaque} native-opaque)`,
  );
  const e = result.exposure;
  console.out(
    `exposure: ${e.dynamicRisk} dynamic-risk, ${e.noSource} no-source, ${e.nativeOpaque} native-opaque, ${e.dynamicUnscoped} unscoped, ${e.loadedNotCalled} loaded-not-called`,
  );
  for (const w of result.warnings) console.err(`warning: ${w}`);
  for (const n of result.notices) console.out(`notice: ${n.message}`);
}

/** The instance dir that encloses a file (longest match). */
function enclosingInstance(file: string, model: ProjectModel): string | null {
  let best: string | null = null;
  for (const i of model.instances) {
    if (file.startsWith(`${i.realDir}/`) && (best === null || i.realDir.length > best.length)) best = i.realDir;
  }
  return best;
}

interface GraphBundle {
  graph: CallGraph;
  entryPointCount: number;
  loadedRealDirs: Set<string>;
  loadedIrs: Map<string, ModuleIR>;
  warnings: string[];
}

/**
 * Build the call graph (full mode only). Entry detection fills `irs` with
 * sync parses (detection is sync); the graph loader reuses them or falls
 * back to the content-addressed cache.
 */
async function buildGraphOrNull(opts: EngineOptions, model: ProjectModel, console: Console): Promise<GraphBundle> {
  const catalog = await loadModels();
  const irs = new Map<string, ModuleIR>();
  const irOf = (file: string): ModuleIR | null => {
    const hit = irs.get(file);
    if (hit !== undefined) return hit;
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      irs.set(file, null as unknown as ModuleIR);
      return null;
    }
    try {
      const ir = parseModule(file, text, {});
      irs.set(file, ir);
      return ir;
    } catch {
      irs.set(file, null as unknown as ModuleIR);
      return null;
    }
  };
  const detection = await detectEntryPoints(
    { model, irOf, annotations: catalog.annotations, callbackInterfaces: catalog.callbackInterfaces },
    {
      includeTests: opts.includeTests,
      ...(opts.entryPoints.length > 0 ? { extra: opts.entryPoints } : {}),
      ...(opts.entryPointsOnly.length > 0 ? { extraOnly: opts.entryPointsOnly } : {}),
      ...(opts.callbackInterfaces.length > 0 ? { callbackInterfaces: opts.callbackInterfaces } : {}),
    },
  );
  if (opts.verbose) {
    for (const e of detection.entries) console.out(`entry: ${e.source} ${e.file}#${e.name}`);
  }
  const ir = async (file: string): Promise<ModuleIR | null> => {
    const hit = irs.get(file);
    if (hit !== undefined) return hit === null ? null : hit;
    try {
      const r = await parseFile(file, opts.cacheDir, {}, parseModule);
      irs.set(file, r.ir);
      return r.ir;
    } catch {
      irs.set(file, null as unknown as ModuleIR);
      return null;
    }
  };
  const input = {
    ir,
    linker: makeLinker(model),
    entryPoints: detection.entries,
    models: catalog.models,
    ...(opts.cha || opts.overApproximateDynamic || opts.pointerAnalysis
      ? {
          options: {
            ...(opts.cha ? { cha: true } : {}),
            ...(opts.overApproximateDynamic ? { overApproximateDynamic: true } : {}),
            ...(opts.pointerAnalysis ? { pointerAnalysis: true } : {}),
          },
        }
      : {}),
  };
  const built = await buildGraph(input);
  const loadedRealDirs = new Set<string>();
  for (const n of built.graph.nodes) {
    const dir = enclosingInstance(n.file, model);
    if (dir !== null) loadedRealDirs.add(dir);
  }
  const loaded = [...irs.values()].filter((x): x is ModuleIR => x !== null);
  return {
    graph: built.graph,
    entryPointCount: detection.entries.length,
    loadedRealDirs,
    loadedIrs: new Map(loaded.map((x) => [x.file, x])),
    warnings: detection.warnings,
  };
}

/** A native instance: its directory contains a .node/WASM artifact. */
async function nativeRealDirs(instances: PackageInstance[]): Promise<Set<string>> {
  const out = new Set<string>();
  for (const i of instances) {
    try {
      const names = await readdir(i.realDir);
      if (names.some((n) => n.endsWith(".node") || n.endsWith(".wasm"))) out.add(i.realDir);
    } catch {
      // unreadable instance: not native by evidence
    }
  }
  return out;
}

/**
 * Unresolved imports of the loaded modules with their location class
 * (v3.5 item 2): app code and candidate-carrying packages COUNT;
 * library-optional does not (builtins are resolved upstream).
 */
function unresolvedImportRows(
  loadedIrs: Map<string, ModuleIR>,
  model: ProjectModel,
  candidateDirs: Set<string>,
): UnresolvedImport[] {
  const out: UnresolvedImport[] = [];
  const workspacePrefixes = model.workspaces.map((w) => `${w.dir}/`);
  for (const [file, ir] of [...loadedIrs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    for (const text of ir.unresolvedImports) {
      const isApp = workspacePrefixes.some((p) => file.startsWith(p));
      const instDir = enclosingInstance(file, model);
      const isCandidate = instDir !== null && candidateDirs.has(instDir);
      const cls: UnresolvedImport["cls"] = isApp ? "app" : isCandidate ? "candidate" : "library-optional";
      out.push({ location: `${file} (${text})`, cls, counts: isApp || isCandidate });
    }
  }
  return out;
}

/** Tie-graph dependency: does the instance at aDir depend on the one at bDir? */
function dependsOn(graph: TieGraph | null, aDir: string, bDir: string, model: ProjectModel): boolean {
  if (graph === null || graph.source === "absent") return false;
  const a = model.instances.find((i) => i.realDir === aDir);
  const b = model.instances.find((i) => i.realDir === bDir);
  if (a === undefined || b === undefined) return false;
  const keyOf = (i: PackageInstance): string[] =>
    [...graph.nodes.values()]
      .filter((n) => n.name === i.name && (n.version === undefined || n.version === i.version))
      .map((n) => n.key);
  const from = keyOf(a);
  const to = new Set(keyOf(b));
  if (from.length === 0 || to.size === 0) return false;
  const adjacency = new Map<string, string[]>();
  for (const [x, y] of graph.edges) {
    const list = adjacency.get(x) ?? [];
    list.push(y);
    adjacency.set(x, list);
  }
  const seen = new Set(from);
  const queue = [...from];
  while (queue.length > 0) {
    const cur = queue.shift() as string;
    if (to.has(cur)) return true;
    for (const next of adjacency.get(cur) ?? []) {
      if (!seen.has(next)) {
        seen.add(next);
        queue.push(next);
      }
    }
  }
  return false;
}

/**
 * UNREACHABLE findings whose package could PLAUSIBLY be loaded by an
 * unresolved dynamic construct (plan section 5.6): a marker in app code
 * (could load any package), or a marker in a library whose dependency graph
 * reaches the candidate package. A marker in an unrelated library does not
 * count (one global eval must not flag every installed package).
 */
function dynamicRiskCount(
  findings: Finding[],
  graph: CallGraph | null,
  model: ProjectModel | null,
  tieGraph: TieGraph | null,
  purlDirs: Map<string, string>,
): number {
  if (graph === null || model === null) return 0;
  const scoped = graph.markers.filter((m) => m.scopedTo !== null);
  if (scoped.length === 0) return 0;
  const appPrefixes = model.workspaces.map((w) => `${w.dir}/`);
  const markerInfo = scoped.map((m) => {
    const file = (m.scopedTo as string).split("#")[0] as string;
    const instDir = enclosingInstance(file, model);
    return { instDir, isApp: appPrefixes.some((p) => file.startsWith(p)) };
  });
  let n = 0;
  const seen = new Set<string>();
  for (const f of findings) {
    if (f.verdict !== "UNREACHABLE" || seen.has(f.id)) continue;
    const targetDir = purlDirs.get(f.purl);
    if (targetDir === undefined) continue;
    let plausible = false;
    for (const mi of markerInfo) {
      if (mi.isApp) {
        plausible = true;
        break;
      }
      if (mi.instDir !== null && mi.instDir !== targetDir && dependsOn(tieGraph, mi.instDir, targetDir, model)) {
        plausible = true;
        break;
      }
    }
    if (plausible) {
      seen.add(f.id);
      n += 1;
    }
  }
  return n;
}

/**
 * The engine entry point. Returns the exit code. UsageError (exit 2) is
 * thrown by validateFlags before any analysis; guard failures (exit 3)
 * write a minimal report first.
 */
export async function runAnalysis(optsIn: EngineOptions, console: Console = DEFAULT_CONSOLE): Promise<number> {
  const opts = {
    ...optsIn,
    entryPoints: [...optsIn.entryPoints],
    callbackInterfaces: [...optsIn.callbackInterfaces],
    formats: [...optsIn.formats],
  };
  validateFlags(opts);
  const start = Date.now();

  const baseMeta = (noCallGraph: boolean): ReportMeta => ({
    toolVersion: TOOL_VERSION,
    schemaVersion: SCHEMA_VERSION,
    callGraphBuilder: opts.sbomOnly ? "none" : builderName(opts),
    entryPointCount: 0,
    callGraphNodes: 0,
    callGraphCalls: 0,
    osvSnapshotSha256: "",
    osvSkippedRecords: 0,
    sbomFile: opts.sbom,
    durationMillis: Date.now() - start,
    ...(noCallGraph ? { noCallGraph: true } : {}),
    exitReasons: [],
  });

  // Minimal report for guard failures: the CI artifact still explains the
  // run — every unresolved component (purl + directories tried) is listed
  // with the guard reason as a warning (plan section 6, JVM parity).
  const minimalReport = (
    components: { purl: string; state: ResolutionState; triedDirs?: string[] }[],
    message: string,
    guards: GuardStates,
  ): AnalysisResult =>
    assembleResult({
      meta: baseMeta(opts.sbomOnly),
      findings: [],
      completeness: {
        components: components.map(
          (c): ComponentState => ({
            purl: c.purl,
            state: c.state,
            ...(c.triedDirs !== undefined && c.triedDirs.length > 0 ? { triedDirs: c.triedDirs } : {}),
          }),
        ),
        unresolvedImports: [],
        dynamicUnscoped: 0,
        opaqueBoundaries: 0,
        graphBuilt: false,
        unlistedInstalled: [],
        dependencyGraph: "absent",
      },
      limitations: [],
      exposure: computeExposure([], 0, 0),
      guards,
      warnings: [message],
      notices: [],
    });

  // 1. SBOM input (UsageError => exit 2).
  const sbom = readSbom(opts.sbom);
  for (const w of sbom.warnings) console.err(`warning: ${w}`);
  console.err(`sbom: ${sbom.file} (${sbom.components.length} npm components)`);

  const empty = emptySbomGuard(sbom.components, opts.allowEmptySbom);
  if (empty.fail) {
    console.err(`error: ${empty.message}`);
    const report = minimalReport(
      sbom.components.map((c) => ({ purl: c.purl, state: "NOT_CHECKED" as const })),
      empty.message as string,
      { totalResolution: false, emptySbom: true, strictSources: false, requireComplete: false, analysisFailed: false },
    );
    report.meta.exitReasons = ["EMPTY_SBOM_GUARD"];
    await writeReports(report, opts, console);
    return 3;
  }

  // 2. Project model + resolutions (full mode only).
  let model: ProjectModel | null = null;
  const resolutions = new Map<string, ComponentResolution>();
  let tieGraph: TieGraph | null = null;
  if (!opts.sbomOnly) {
    model = buildProjectModel(opts.project);
    const lockGraph = model.layout === "pnpm" ? pnpmLockfileGraph(model.root) : npmLockfileGraph(model.installRoot);
    tieGraph = tieGraphFor(sbom, lockGraph);
    const all = allComponentResolutions(
      sbom.components.map((c) => ({
        purl: c.purl,
        name: c.name,
        ...(c.version !== undefined ? { version: c.version } : {}),
        ref: c.ref,
      })),
      model,
      tieGraph,
      false,
    );
    for (const r of all) resolutions.set(r.component.purl, r);
  }

  // 3. OSV snapshot (UsageError => exit 2; zero valid records => exit 3).
  // --match-installed also queries the snapshot for the names of the INSTALLED
  // instances: an unlisted-but-affected package still yields a candidate
  // (v3.5 item 1), and the snapshot index reads only the requested names.
  const names = new Set<string>(sbom.components.map((c) => c.name));
  if (opts.matchInstalled && model !== null) {
    for (const i of model.instances) names.add(i.name);
  }
  const snapshot = await loadSnapshot(opts.osvDir, [...names].sort(), opts.cacheDir, opts.osvChecksum);
  if (snapshot.zeroValidRecords) {
    console.err("error: OSV snapshot contains files but zero valid records");
    const report = minimalReport(
      sbom.components.map((c) => ({ purl: c.purl, state: "NOT_CHECKED" as const })),
      "OSV snapshot contains files but zero valid records",
      { totalResolution: false, emptySbom: false, strictSources: false, requireComplete: false, analysisFailed: true },
    );
    report.meta.osvSnapshotSha256 = snapshot.pin;
    report.meta.exitReasons = ["ANALYSIS_FAILURE"];
    await writeReports(report, opts, console);
    return 3;
  }
  const { records, skipped } = normalizeRecords(snapshot.records);

  // 4. Mappings (UsageError => exit 2).
  let mappings = new Map<string, MappingEntry[]>();
  if (opts.mappings !== undefined) {
    let raw: string;
    try {
      raw = readFileSync(opts.mappings, "utf8");
    } catch (e) {
      throw new UsageError(`mappings file not readable: ${opts.mappings}: ${(e as Error).message}`);
    }
    mappings = parseMappingsFile(raw);
  }

  // 5. Call graph (full mode only; construction failure => INCOMPLETE).
  let bundle: GraphBundle | null = null;
  let graphFailed = false;
  if (!opts.sbomOnly && model !== null) {
    try {
      bundle = await buildGraphOrNull(opts, model, console);
      for (const w of bundle.warnings) console.err(`warning: ${w}`);
    } catch (e) {
      graphFailed = true;
      console.err(`error: graph construction failed: ${(e as Error).message}`);
    }
  }
  const graph = bundle?.graph ?? null;

  // --dry-run trio (hidden debugging; print and stop, no reports).
  if (opts.dryRunSbom === true) {
    for (const c of sbom.components) console.out(`sbom: ${c.purl} dev=${c.devOnly} ref=${c.ref}`);
    return 0;
  }
  if (opts.dryRunMatch === true) {
    const provisional =
      model !== null
        ? buildCandidates(sbom, records, resolutions, {
            matchInstalled: opts.matchInstalled,
            loadedRealDirs: bundle?.loadedRealDirs ?? new Set(),
            instances: model.instances,
          })
        : [];
    for (const c of provisional) console.out(`match: ${c.record.canonicalId} ${c.purl} [${c.affectedRange}]`);
    return 0;
  }
  if (opts.dryRunGraph === true && graph !== null) {
    console.out(`graph: ${graph.nodes.length} nodes, ${graph.edges.length} edges, ${graph.entryPoints.length} entries`);
    return 0;
  }

  // Zero entry points from all sources ⇒ analysis failure, not a clean run
  // (plan section 5.5, JVM ADR 0009 parity): nothing can be reached.
  let zeroEntries = false;
  if (!opts.sbomOnly && bundle !== null && bundle.entryPointCount === 0) {
    zeroEntries = true;
    console.err(
      `error: zero entry points detected (tried: package.json main/exports/bin, scripts, framework routes, --entry-points${opts.entryPoints.length > 0 ? ` [${opts.entryPoints.join(",")}]` : ""}): a run without entry points cannot reach anything — analysis failure`,
    );
  }

  // 6. Candidates (+ --match-installed). Under --sbom-only there is no model
  //    (no disk reconciliation): the SBOM x OSV match still runs (instance
  //    evidence is simply absent — APPLICABLE / MALICIOUS / DEV_ONLY only).
  const candidates = buildCandidates(sbom, records, resolutions, {
    matchInstalled: opts.matchInstalled,
    loadedRealDirs: bundle?.loadedRealDirs ?? new Set(),
    instances: model?.instances ?? [],
  });
  for (const w of unmappedIds(mappings, records)) console.err(`warning: ${w}`);

  // 7. Verdicts.
  const native = await nativeRealDirs(model?.instances ?? []);
  const entryRoots = graph !== null ? graph.entryPoints.map((e) => `${e.file}#${e.name}`) : [];
  const findings: Finding[] = [];
  for (const c of candidates) {
    const sp =
      c.ref !== "" && sbom.dependencies.length > 0
        ? sbomSupplyPath(sbom.dependencies, supplyRoot(sbom.dependencies, c.ref) ?? c.ref, c.ref)
        : [];
    findings.push(
      decideVerdict(
        c,
        relatedIds(records, c.record),
        {
          packageEvidence: opts.packageEvidence,
          callEvidence: opts.callEvidence,
          includeDev: opts.includeDev,
          sbomOnly: opts.sbomOnly,
          mappings,
          entryRoots,
          graph,
          loadedRealDirs: bundle?.loadedRealDirs ?? new Set(),
          nativeRealDirs: native,
        },
        sp,
      ),
    );
  }

  // The instance dir behind each finding purl (verdicts carry no instance).
  const purlDirs = new Map<string, string>();
  for (const c of candidates) {
    if (c.instance !== null) purlDirs.set(c.purl, c.instance.realDir);
  }

  // 8. Guards (the policy layer turns these into exit 3). Pre-filter (guard
  //    contract): components whose verdict is DEV_ONLY without --include-dev
  //    do not count — an all-dev SBOM with a broken tree is exit 0 + NOTICE,
  //    not a broken-environment failure (v3.4).
  const devPurls = new Set(sbom.components.filter((c) => c.devOnly).map((c) => c.purl));
  const guardInputs = opts.includeDev
    ? [...resolutions.values()]
    : [...resolutions.values()].filter((r) => !devPurls.has(r.component.purl));
  const guard =
    model !== null && !opts.sbomOnly ? totalResolutionGuard(guardInputs, opts.strictSources) : { fail: false };
  if (guard.fail && guard.message !== undefined) console.err(`error: ${guard.message}`);

  // Notices (never fatal, always visible): all-dev SBOM, stale-SBOM range
  // drift (the finding is based on the installed version), unlisted loaded
  // instances (v3.5 item 1).
  const notices: Notice[] = [];
  const devNotice = allDevNotice(sbom.components);
  if (devNotice !== null) notices.push({ code: "DEV_ONLY", message: devNotice });
  for (const c of candidates) {
    // SBOM-sourced only: an installed-source candidate's componentVersion is
    // the instance's own version, not an SBOM version (no drift to report).
    if (c.source === "sbom" && c.matchedOn === "installed" && c.componentVersion !== undefined && c.instance !== null) {
      notices.push({
        code: "SBOM_DRIFT",
        purl: c.purl,
        message: `component ${c.component}: SBOM version ${c.componentVersion} is outside every affected range; the finding is based on the installed version ${c.instance.version}`,
      });
    }
  }

  // 9. Completeness + exposure + limitations.
  const candidateDirs = new Set(candidates.map((c) => c.instance?.realDir).filter((d): d is string => d !== undefined));
  const completeness: Completeness = {
    components: (model !== null
      ? [...resolutions.values()].map((r): ComponentState => {
          const iv = r.state === "VERSION_MISMATCH" ? r.instances[0]?.version : undefined;
          return { purl: r.component.purl, state: r.state, ...(iv !== undefined ? { installedVersion: iv } : {}) };
        })
      : sbom.components.map((c): ComponentState => ({ purl: c.purl, state: "NOT_CHECKED" as const }))
    ).sort((a, b) => (a.purl < b.purl ? -1 : 1)),
    unresolvedImports:
      model !== null && bundle !== null ? unresolvedImportRows(bundle.loadedIrs, model, candidateDirs) : [],
    dynamicUnscoped: graph?.stats.unscopedMarkers ?? 0,
    opaqueBoundaries: findings.filter((f) => f.verdict === "NATIVE_OPAQUE").length,
    graphBuilt: graph !== null && !graphFailed,
    unlistedInstalled:
      model !== null ? unlistedInstalled(model.instances, sbom.components, bundle?.loadedRealDirs ?? null) : [],
    dependencyGraph: tieGraph === null || tieGraph.source === "absent" ? "absent" : "present",
  };

  for (const u of completeness.unlistedInstalled) {
    notices.push({
      code: "UNLISTED_INSTALLED",
      purl: `pkg:npm/${u.name.toLowerCase()}@${u.version}`,
      message: `installed instance not listed in the SBOM: ${u.name}@${u.version} (${u.relPath})`,
    });
  }

  // The import-time caveat applies when some method-level REACHABLE was
  // justified by import-time execution of a mapping target (below the tier).
  let importTimeReachable = false;
  if (graph !== null && mappings.size > 0) {
    for (const f of findings) {
      if (f.verdict !== "REACHABLE" || f.matchLevel !== "method") continue;
      const rec = records.find((r) => r.canonicalId === f.id);
      const dir = purlDirs.get(f.purl);
      if (rec === undefined || dir === undefined) continue;
      const targets = resolveMappingTargets(rec, mappings, graph, dir);
      if (targets.some((t) => t.importTime)) importTimeReachable = true;
    }
  }
  const callbackRegisteredUsed = findings.some((f) => f.verdict === "REACHABLE" && f.evidence.callbackRegistered);
  const exposure = computeExposure(
    findings,
    dynamicRiskCount(findings, graph, model, tieGraph, purlDirs),
    graph?.stats.unscopedMarkers ?? 0,
  );
  if (exposure.dynamicRisk > 0) {
    notices.push({
      code: "DYNAMIC_RISK",
      message: `${exposure.dynamicRisk} UNREACHABLE finding(s) of installed packages could plausibly be loaded by a dynamic construct in application code (dynamic require/import/eval)`,
    });
  }
  const limitations = computeLimitations({
    dynamicMarkers: graph?.stats.dynamicMarkers ?? 0,
    importTimeReachable,
    callbackRegisteredUsed,
    nativeOpaque: exposure.nativeOpaque,
    overApproximateDynamic: opts.overApproximateDynamic,
    cha: opts.cha,
    ...(opts.pointerAnalysis
      ? {
          pointer: true,
          pointerStats: graph?.stats.pointer,
        }
      : {}),
  });

  const meta = baseMeta(opts.sbomOnly);
  meta.osvSnapshotSha256 = snapshot.pin;
  meta.osvSkippedRecords = snapshot.skippedRecords + skipped;
  meta.entryPointCount = bundle?.entryPointCount ?? 0;
  meta.callGraphNodes = graph?.nodes.length ?? 0;
  meta.callGraphCalls = graph?.edges.filter((e) => e.kind === "call").length ?? 0;
  meta.durationMillis = Date.now() - start;

  let result = assembleResult({
    meta,
    findings,
    completeness,
    limitations,
    exposure,
    guards: {
      totalResolution: guard.fail && !opts.strictSources,
      emptySbom: false,
      strictSources: guard.fail && opts.strictSources,
      requireComplete: false,
      analysisFailed: graphFailed || zeroEntries,
    },
    warnings: [],
    notices,
  });

  // 10. Policy: the exit code and every triggered reason (independent of the
  //     precedence winner, v3.5).
  const decision = decideExitCode(result, {
    malware: opts.malware,
    opaqueNative: opts.opaqueNative,
    sbomOnly: opts.sbomOnly,
    failOnApplicable: opts.failOnApplicable,
    requireComplete: opts.requireComplete,
  });
  result.meta.exitReasons = decision.reasons;
  if (decision.reasons.length > 0) console.err(`exitReasons: ${decision.reasons.join(", ")}`);

  // Guard failure with no findings to retain: the minimal report is the CI
  // artifact (plan section 6) — it lists each unresolved component (purl +
  // directories tried). Findings, when present, stay in the full report.
  if ((guard.fail || graphFailed || zeroEntries) && result.findings.length === 0 && model !== null) {
    const message =
      guard.fail && guard.message !== undefined
        ? guard.message
        : zeroEntries
          ? "zero entry points from all sources: the analysis cannot reach anything"
          : "call-graph construction failed";
    const minimal = minimalReport(
      [...resolutions.values()].map((r) => ({ purl: r.component.purl, state: r.state, triedDirs: r.triedDirs })),
      message,
      {
        totalResolution: guard.fail && !opts.strictSources,
        emptySbom: false,
        strictSources: guard.fail && opts.strictSources,
        requireComplete: false,
        analysisFailed: graphFailed || zeroEntries,
      },
    );
    minimal.meta.osvSnapshotSha256 = snapshot.pin;
    minimal.meta.osvSkippedRecords = snapshot.skippedRecords + skipped;
    minimal.meta.exitReasons = decision.reasons;
    result = minimal;
  }

  // 11. Reports (stale cleanup first) + console summary.
  try {
    await writeReports(result, opts, console, nodeLocationsOf(graph));
  } catch (e) {
    console.err(`error: cannot write reports: ${(e as Error).message}`);
    return 3;
  }
  printSummary(result, console);
  return decision.code;
}
