// Fail-visibly guards (plan sections 1, 5.3; ADR 0014).
//
// Two JS-specific exit-3 conditions (neither in the JVM list):
//  - total-resolution guard: every analyzable component non-RESOLVED
//    (broken environment — absent node_modules, wrong lockfile, unreadable
//    mount — is never a clean run);
//  - empty-SBOM guard: zero npm components before dev filtering
//    (a run that analyzes nothing is broken input).
// Exit-code precedence 2 > 3 > 1 > 0 is applied by the engine (M5).

import type { NpmComponent } from "../sbom/types.js";
import type { ComponentResolution } from "./tie.js";
import type { ResolutionState } from "./types.js";

export interface GuardResult {
  /** True when the guard fires (exit 3 unless explicitly opted out). */
  fail: boolean;
  /** Console message naming the likely cause (the CI artifact explains it). */
  message?: string;
  /** The components the guard was evaluated over (minimal report input). */
  components?: { purl: string; state: ResolutionState; triedDirs: string[] }[];
}

/**
 * Empty-SBOM guard: zero npm components before dev filtering ⇒ exit 3.
 * Applies under --sbom-only too; `--allow-empty-sbom` opts out.
 * An all-dev SBOM is NOT empty (exit 0 with the notice below).
 */
export function emptySbomGuard(components: NpmComponent[], allowEmptySbom: boolean): GuardResult {
  if (components.length > 0) return { fail: false };
  if (allowEmptySbom) return { fail: false };
  return {
    fail: true,
    message:
      "SBOM contains no npm components (wrong producer or all non-npm purls): a run that analyzes nothing is broken input; use --allow-empty-sbom to opt out",
  };
}

/**
 * Total-resolution guard: at least one analyzable component exists and every
 * analyzable one is non-RESOLVED (missing, version-mismatched, or ambiguous).
 * Evaluated over components with verdicts DEV_ONLY / MALICIOUS_PACKAGE
 * already excluded from the analyzable set (callers pre-filter).
 * `strictSources` extends the failure to ANY non-RESOLVED component.
 */
export function totalResolutionGuard(resolutions: ComponentResolution[], strictSources: boolean): GuardResult {
  const states = resolutions.map((r) => r.state);
  const analyzable = states.filter((s) => s !== "NOT_CHECKED");
  if (analyzable.length === 0) return { fail: false };
  const noneResolved = analyzable.every((s) => s !== "RESOLVED");
  if (strictSources) {
    const anyNonResolved = analyzable.some((s) => s !== "RESOLVED");
    if (anyNonResolved) {
      return {
        fail: true,
        message:
          "--strict-sources: at least one analyzable component is not RESOLVED (absent node_modules, wrong lockfile, or unreadable mount); nothing that did not resolve is analyzed",
        components: resolutions.map((r) => ({ purl: r.component.purl, state: r.state, triedDirs: r.triedDirs })),
      };
    }
    return { fail: false };
  }
  if (!noneResolved) return { fail: false };
  return {
    fail: true,
    message:
      "no analyzable component resolved (absent node_modules, wrong lockfile, or unreadable mount): a run in which nothing resolved is a broken environment, never a clean one",
    components: resolutions.map((r) => ({ purl: r.component.purl, state: r.state, triedDirs: r.triedDirs })),
  };
}

/**
 * All-dev notice: an all-dev SBOM is not empty — exit 0 with the DEV_ONLY
 * verdicts listed plus this notice (v3.4 wording fix).
 */
export function allDevNotice(components: NpmComponent[]): string | null {
  if (components.length === 0) return null;
  if (!components.every((c) => c.devOnly)) return null;
  return "all components dev-only — use --include-dev to analyze them";
}
