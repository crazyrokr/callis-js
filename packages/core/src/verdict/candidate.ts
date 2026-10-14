// Candidate generation (plan section 5.6 "Per candidate", v3.5 items 1/8).
//
// A candidate is an advisory x SBOM component (or, with --match-installed,
// advisory x installed instance the SBOM never listed). Matching uses the
// M1 boundary semantics (introduced inclusive, fixed EXCLUSIVE). `matchedOn`
// records which version evidence the match used; `source` distinguishes
// SBOM-listed from installed-only findings.

import { rangeSatisfied } from "../osv/matcher.js";
import type { PackageRecord } from "../osv/normalize.js";
import type { ComponentResolution } from "../project/tie.js";
import type { PackageInstance } from "../project/types.js";
import type { DependencyEdge, NpmComponent, SbomParseResult } from "../sbom/types.js";
import type { Candidate } from "./types.js";

export interface CandidateOptions {
  /** Also generate candidates from installed instances (v3.5 item 1). */
  matchInstalled: boolean;
  /** Instances the graph actually loaded (matchInstalled gating). */
  loadedRealDirs: Set<string>;
  instances: PackageInstance[];
}

/** Evidence string for the matched range(s) / versions (matcher evidence). */
function evidenceString(record: PackageRecord, versions: string[]): string {
  const parts: string[] = [];
  for (const version of versions) {
    for (const r of record.ranges) {
      if (r.kind !== "SEMVER") continue;
      if (rangeSatisfied(version, r) === true) {
        const ev = r.events
          .map((e) =>
            e.introduced !== undefined
              ? `introduced:${e.introduced}`
              : e.fixed !== undefined
                ? `fixed:${e.fixed}`
                : `last_affected:${e.last_affected ?? "?"}`,
          )
          .sort()
          .join(",");
        parts.push(`[${ev}]`);
      }
    }
    const exact = record.versions.filter((v) => v === version);
    if (exact.length > 0) parts.push(`versions:{${[...exact].sort().join(",")}}`);
  }
  if (parts.length === 0) return "range-or-version match";
  return [...new Set(parts)].sort().join(" ");
}

function versionMatches(record: PackageRecord, version: string | undefined): boolean {
  if (version === undefined) return record.versions.length > 0;
  if (record.versions.includes(version)) return true;
  return record.ranges.some((r) => rangeSatisfied(version, r) === true);
}

/**
 * SBOM x OSV candidates. `resolutions` maps purl -> ComponentResolution
 * (NOT_CHECKED under --sbom-only). Dev components stay candidates (the
 * verdict decides DEV_ONLY) UNLESS --include-dev is off and they are the
 * only evidence — they are kept: the DEV_ONLY NOTICE needs them.
 */
export function buildCandidates(
  sbom: SbomParseResult,
  records: PackageRecord[],
  resolutions: Map<string, ComponentResolution>,
  options: CandidateOptions,
): Candidate[] {
  const out: Candidate[] = [];
  const sbomNames = new Set(sbom.components.map((c) => c.name));
  const sbomKey = new Map<string, NpmComponent>();
  for (const c of sbom.components) sbomKey.set(`${c.name}@${c.version ?? ""}`, c);

  for (const record of records) {
    if (record.ecosystem !== "npm") continue;
    for (const c of sbom.components) {
      if (c.name !== record.packageName) continue;
      const resolution = resolutions.get(c.purl) ?? null;
      // The first tied instance (RESOLVED) or same-name instance (MISMATCH /
      // AMBIGUOUS — the on-disk version is reported as installedVersion).
      const instance =
        resolution !== null && resolution.instances.length > 0 ? (resolution.instances[0] as PackageInstance) : null;
      const installedVersion = instance !== null ? instance.version : undefined;
      // Both versions evaluated (v3.5 item 8): a finding is kept if EITHER
      // the SBOM version or the installed one is in range — the stale-SBOM
      // case (the tree drifted past the SBOM) still produces a candidate.
      const sbomIn = c.version !== undefined && versionMatches(record, c.version);
      const instIn =
        installedVersion !== undefined && installedVersion !== c.version && versionMatches(record, installedVersion);
      if (!sbomIn && !instIn) continue;
      let matchedOn: Candidate["matchedOn"] = "sbom";
      if (!sbomIn && instIn) matchedOn = "installed";
      else if (sbomIn && instIn) matchedOn = "both";
      const matched: string[] = [];
      if (sbomIn) matched.push(c.version as string);
      if (instIn) matched.push(installedVersion as string);
      out.push({
        record,
        purl: c.purl,
        component: c.name,
        ...(c.version !== undefined ? { componentVersion: c.version } : {}),
        devOnly: c.devOnly,
        ref: c.ref,
        matchedOn,
        source: "sbom",
        affectedRange: evidenceString(record, matched),
        resolution,
        instance,
      });
    }

    if (!options.matchInstalled) continue;
    // Installed instances the SBOM never listed (v3.5 item 1): the SBOM is
    // stale, the instance is real. Only LOADED instances produce findings —
    // an unlisted package that is never imported cannot reach anything.
    for (const i of options.instances) {
      if (i.name !== record.packageName) continue;
      if (sbomNames.has(i.name) || sbomKey.has(`${i.name}@${i.version}`)) continue;
      if (!options.loadedRealDirs.has(i.realDir)) continue;
      if (!versionMatches(record, i.version)) continue;
      const resolution = resolutions.get(`pkg:npm/${i.name.toLowerCase()}@${i.version}`) ?? null;
      out.push({
        record,
        purl: `pkg:npm/${i.name.toLowerCase()}@${i.version}`,
        component: i.name,
        componentVersion: i.version,
        devOnly: false,
        ref: "",
        matchedOn: "installed",
        source: "installed",
        affectedRange: evidenceString(record, [i.version]),
        resolution,
        instance: i,
      });
    }
  }

  const byKey = new Map<string, Candidate>();
  const sorted = [...out].sort((a, b) => (a.record.canonicalId + a.purl < b.record.canonicalId + b.purl ? -1 : 1));
  for (const c of sorted) {
    const key = `${c.record.canonicalId}\u0000${c.purl}\u0000${c.source}`;
    if (!byKey.has(key)) byKey.set(key, c);
  }
  return [...byKey.values()];
}

/** The supply-path root: the lexicographically-first ref that reaches `ref`. */
export function supplyRoot(deps: DependencyEdge[], ref: string): string | null {
  const edges = new Map(deps.map((d) => [d.ref, d.dependsOn]));
  const reach = (from: string, to: string): boolean => {
    if (from === to) return true;
    const seen = new Set([from]);
    const queue = [from];
    while (queue.length > 0) {
      const cur = queue.shift() as string;
      for (const n of edges.get(cur) ?? []) {
        if (seen.has(n)) continue;
        if (n === to) return true;
        seen.add(n);
        queue.push(n);
      }
    }
    return false;
  };
  const roots = [...new Set(deps.map((d) => d.ref))].sort();
  for (const r of roots) {
    if (r === ref || reach(r, ref)) return r;
  }
  return null;
}
