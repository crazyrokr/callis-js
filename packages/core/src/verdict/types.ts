// M5: verdict types (plan section 5.6, ADRs 0012-0013).
//
// One Finding per candidate (advisory x installed instance). The verdict
// vocabulary is closed and forward-compatible: unknown values added later
// must not break consumers (schemaVersion is independent of toolVersion).

import type { PackageRecord } from "../osv/normalize.js";
import type { ComponentResolution } from "../project/tie.js";
import type { PackageInstance } from "../project/types.js";

export type Verdict =
  | "REACHABLE"
  | "UNREACHABLE"
  | "NO_SOURCE"
  | "DEV_ONLY"
  | "MALICIOUS_PACKAGE"
  | "NATIVE_OPAQUE"
  /** `--sbom-only` only: advisory applies, no call graph was built. */
  | "APPLICABLE";

/** REACHABLE carries PRECISE (all hops direct/flow) or NAME_BASED (a
 *  name-based fallback hop: --cha / --over-approximate-dynamic). */
export type Confidence = "PRECISE" | "NAME_BASED";

/** method = mapping resolved to a function node; artifact = tier only. */
export type MatchLevel = "method" | "artifact";

export type NativeBoundaryState = "reached" | "unresolved";

export type ResolutionStateOf = "RESOLVED" | "MISSING" | "VERSION_MISMATCH" | "AMBIGUOUS" | "NOT_CHECKED";

export interface Evidence {
  /** The package instance was loaded into the graph (import edge). */
  loaded: boolean;
  /** A function of the package is called (any evidence kind per --call-evidence). */
  called: boolean;
  /** A handler of the package was registered (model emitter on/addListener). */
  callbackRegistered: boolean;
}

/** SBOM x OSV match (+ `--match-installed` additions), pre-verdict. */
export interface Candidate {
  record: PackageRecord;
  /** Canonical purl of the SBOM component (installed-source: the instance purl). */
  purl: string;
  component: string;
  componentVersion?: string;
  devOnly: boolean;
  /** SBOM component ref (supplyPath root anchor); "" for installed-source. */
  ref: string;
  /** Which version evidence the range match used (v3.5 item 8). */
  matchedOn: "installed" | "sbom" | "both";
  /** sbom = the SBOM listed the instance; installed = the SBOM never did. */
  source: "sbom" | "installed";
  /** Matcher evidence string (the range(s) that matched, normalized). */
  affectedRange: string;
  /** null under --sbom-only (NOT_CHECKED, no filesystem reconciliation). */
  resolution: ComponentResolution | null;
  /** The resolved installed instance (null when not RESOLVED / sbom-only). */
  instance: PackageInstance | null;
}

/** One report entry (the JSON `findings[]` element, plan section 5.6). */
export interface Finding {
  id: string;
  aliases: string[];
  purl: string;
  component: string;
  componentVersion?: string;
  verdict: Verdict;
  installed: boolean;
  evidence: Evidence;
  resolutionState: ResolutionStateOf;
  /** On VERSION_MISMATCH: the version actually on disk. */
  installedVersion?: string;
  matchedOn: "installed" | "sbom" | "both";
  source: "sbom" | "installed";
  /** On NATIVE_OPAQUE: reached | unresolved. */
  nativeBoundary?: NativeBoundaryState;
  /** v3.4: NATIVE_OPAQUE findings carry opaque: true. */
  opaque?: boolean;
  relatedIds: string[];
  matchLevel: MatchLevel;
  /** REACHABLE only. */
  confidence?: Confidence;
  summary: string;
  severity: string;
  affectedRange: string;
  /** Shortest entry -> evidence node path ([] when not reachable). */
  path: string[];
  /** SBOM dependencies[] chain (app -> ... -> component). */
  supplyPath: string[];
}

export const VERDICTS: Verdict[] = [
  "REACHABLE",
  "UNREACHABLE",
  "NO_SOURCE",
  "DEV_ONLY",
  "MALICIOUS_PACKAGE",
  "NATIVE_OPAQUE",
  "APPLICABLE",
];
