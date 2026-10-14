// Reverse reconciliation (plan section 5.3 v3.5 item 1, ADR 0014).
//
// SBOM -> disk runs in the state computation; this checks the other
// direction: an instance the call graph loaded that has NO matching SBOM
// component goes into completeness.unlistedInstalled and demotes
// analysisStatus to PARTIAL (an SBOM from a stale lockfile or a different tree
// cannot silently omit a package the application actually loads).

import type { NpmComponent } from "../sbom/types.js";
import type { PackageInstance } from "./types.js";

export interface UnlistedInstance {
  name: string;
  version: string;
  realDir: string;
  relPath: string;
}

/**
 * Instances (loaded by the graph, or all when no load set is given) with no
 * matching SBOM component (name+version). Sorted, deduplicated by realpath.
 */
export function unlistedInstalled(
  instances: PackageInstance[],
  components: NpmComponent[],
  loadedRealDirs: Set<string> | null,
): UnlistedInstance[] {
  const known = new Map<string, string>();
  for (const c of components) {
    if (c.version !== undefined) known.set(`${c.name}@${c.version}`, c.purl);
  }
  const seen = new Map<string, UnlistedInstance>();
  for (const i of instances) {
    if (loadedRealDirs !== null && !loadedRealDirs.has(i.realDir)) continue;
    if (known.has(`${i.name}@${i.version}`)) continue;
    if (seen.has(i.realDir)) continue;
    seen.set(i.realDir, { name: i.name, version: i.version, realDir: i.realDir, relPath: i.relPath });
  }
  const out = [...seen.values()];
  out.sort((a, b) => {
    const byName = a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
    if (byName !== 0) return byName;
    return a.realDir < b.realDir ? -1 : a.realDir > b.realDir ? 1 : 0;
  });
  return out;
}
