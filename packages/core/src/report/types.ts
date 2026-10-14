// M5: report types (plan section 5.6, ADR 0012).
//
// The report carries schemaVersion INDEPENDENT of toolVersion (a tool
// release does not necessarily change the schema). Field classes:
//   mandatory  — always present
//   optional   — present when the condition holds
//   extensible — arrays/objects consumers must tolerate unknown members.
// Unknown verdicts and properties stay forward-compatible.

import type { UnlistedInstance } from "../project/reconcile.js";
import type { ResolutionState } from "../project/types.js";
import type { Notice } from "../util/errors.js";
import type { Finding } from "../verdict/types.js";

export type AnalysisStatus = "COMPLETE" | "PARTIAL" | "INCOMPLETE" | "NOT_PERFORMED";

export type ExitReason =
  | "REACHABLE_FINDINGS"
  | "MALWARE_FAIL"
  | "OPAQUE_NATIVE_FAIL"
  | "TOTAL_RESOLUTION_GUARD"
  | "EMPTY_SBOM_GUARD"
  | "STRICT_SOURCES"
  | "REQUIRE_COMPLETE"
  | "ANALYSIS_FAILURE";

export const EXIT_REASONS: ExitReason[] = [
  "REACHABLE_FINDINGS",
  "MALWARE_FAIL",
  "OPAQUE_NATIVE_FAIL",
  "TOTAL_RESOLUTION_GUARD",
  "EMPTY_SBOM_GUARD",
  "STRICT_SOURCES",
  "REQUIRE_COMPLETE",
  "ANALYSIS_FAILURE",
];

/** Per-component resolution states (the completeness block input). */
export interface ComponentState {
  purl: string;
  state: ResolutionState;
  /** On VERSION_MISMATCH: the version actually on disk. */
  installedVersion?: string;
  /** Minimal report (guard failure): the directories the resolver tried. */
  triedDirs?: string[];
}

/**
 * One unresolved import (v3.5 item 2): only the first two location classes
 * COUNT toward the status (builtins are resolved; library-optional imports
 * of a package that does not exist are a normal npm pattern).
 */
export interface UnresolvedImport {
  location: string;
  cls: "app" | "candidate" | "library-optional";
  counts: boolean;
}

export interface Completeness {
  components: ComponentState[];
  unresolvedImports: UnresolvedImport[];
  dynamicUnscoped: number;
  /** Findings ending at a .node/WASM boundary. */
  opaqueBoundaries: number;
  graphBuilt: boolean;
  unlistedInstalled: UnlistedInstance[];
  dependencyGraph: "present" | "absent";
}

/** All false-negative exposure of the run (plan section 5.6). */
export interface Exposure {
  /** UNREACHABLE findings whose package a dynamic construct could load. */
  dynamicRisk: number;
  /** NO_SOURCE findings. */
  noSource: number;
  /** NATIVE_OPAQUE findings. */
  nativeOpaque: number;
  /** Dynamic constructs not attributable to any package. */
  dynamicUnscoped: number;
  /** Packages loaded but below the configured evidence tier. */
  loadedNotCalled: number;
}

/** Guard states of the run (the policy layer input, v3.5 exitReasons). */
export interface GuardStates {
  totalResolution: boolean;
  emptySbom: boolean;
  strictSources: boolean;
  requireComplete: boolean;
  analysisFailed: boolean;
}

export interface ReportMeta {
  toolVersion: string;
  schemaVersion: string;
  /** The graph policy: demand-0cfa (+ +cha / +over-approx when set). */
  callGraphBuilder: string;
  entryPointCount: number;
  callGraphNodes: number;
  callGraphCalls: number;
  osvSnapshotSha256: string;
  osvSkippedRecords: number;
  sbomFile: string;
  /** Excluded from cache keys and binary-parity comparison (plan section 6). */
  durationMillis: number;
  /** --sbom-only: no call graph was built. */
  noCallGraph?: boolean;
  /** M8 fills input/memo keys; absent until then (optional). */
  keys?: { input?: string; memo?: string };
  /** Every condition triggered — independent of the precedence winner. */
  exitReasons: ExitReason[];
}

/** The structured analysis result (v3.3: policy layer input, ADR 0016). */
export interface AnalysisResult {
  meta: ReportMeta;
  analysisStatus: AnalysisStatus;
  findings: Finding[];
  completeness: Completeness;
  /** Material limitations of THIS run (soundness-contract forms met, ...). */
  limitations: string[];
  exposure: Exposure;
  guards: GuardStates;
  warnings: string[];
  notices: Notice[];
}

export type ReportFormat = "json" | "junitxml" | "sarif";

export const REPORT_FORMATS: ReportFormat[] = ["json", "junitxml", "sarif"];
