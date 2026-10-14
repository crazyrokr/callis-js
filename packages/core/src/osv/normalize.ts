// Advisory normalization and dedup (plan section 5.2, v3.3/v3.4, ADR 0013).
//
// The same issue can exist as several bucket files, so identity is
// established explicitly: every record normalizes into per-package internal
// records. Records merge only when ecosystem + package identity match AND
// the affected ranges are equal after normalization — merging keeps the
// union of source record ids and aliases. Records with differing ranges
// remain separate findings, linked by `relatedIds` and grouped in the
// report. Alias-set overlap is never the dedup rule, and the canonical id
// is a presentation field, not a dedup key.

import { type NormalizedRange, normalizeRange } from "./matcher.js";
import { type OsRecord, isMalicious, maxSeverity, packageIdentity } from "./record.js";

export interface PackageRecord {
  /** Union of the source record ids that were merged (stable-sorted). */
  sourceIds: string[];
  /** Union of all aliases of the merged records (stable-sorted). */
  aliases: string[];
  packageName: string;
  ecosystem: string;
  /** Normalized affected ranges across the merged source entries. */
  ranges: NormalizedRange[];
  /** Explicit versions, normalized (ecosystem suffixes stripped). */
  versions: string[];
  malicious: boolean;
  severity: string;
  summary: string;
  /** Canonical id of the merged record (presentation field). */
  canonicalId: string;
}

/** One affected entry of one record, with its normalized identity. */
interface Contribution {
  record: OsRecord;
  packageName: string;
  ranges: NormalizedRange[];
  versions: string[];
  /** Stable signature of (ranges, versions) — the merge key (v3.4). */
  signature: string;
}

function stableSort(values: string[]): string[] {
  return [...new Set(values)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function signatureOf(ranges: NormalizedRange[], versions: string[]): string {
  const r = ranges
    .map((x) => JSON.stringify(x))
    .sort()
    .join("|");
  const v = stableSort(versions).join("|");
  return `${r}#${v}`;
}

/**
 * Normalize records into per-package internal records with the merge rule of
 * plan section 5.2. `skipped` counts records with no usable id or no
 * package-identifiable entries (never downgraded into vulnerabilities).
 */
export function normalizeRecords(records: OsRecord[]): { records: PackageRecord[]; skipped: number } {
  const contributions = new Map<string, Map<string, Contribution[]>>();
  let skipped = 0;

  for (const record of records) {
    if (record.id.length === 0) {
      skipped += 1;
      continue;
    }
    // Malformed event (not exactly one of introduced/fixed/last_affected):
    // the whole record is skipped + counted (plan section 5.2).
    let malformed = false;
    for (const entry of record.affected ?? []) {
      for (const r of entry.ranges ?? []) {
        if (normalizeRange(r)?.malformed === true) malformed = true;
      }
    }
    if (malformed) {
      skipped += 1;
      continue;
    }
    let anyEntry = false;
    for (const entry of record.affected ?? []) {
      const identity = packageIdentity(entry);
      if (identity === null) {
        continue; // no determinable package identity: never matches (v3.3)
      }
      anyEntry = true;
      const ranges: NormalizedRange[] = [];
      for (const r of entry.ranges ?? []) {
        const normalized = normalizeRange(r);
        if (normalized !== null) ranges.push(normalized);
      }
      const versions = stableSort(
        (entry.versions ?? []).map((v) => v.replace(/-npm$/, "")).filter((v) => v.length > 0),
      );
      const c: Contribution = {
        record,
        packageName: identity,
        ranges,
        versions,
        signature: signatureOf(ranges, versions),
      };
      let perPackage = contributions.get(identity);
      if (perPackage === undefined) {
        perPackage = new Map();
        contributions.set(identity, perPackage);
      }
      const list = perPackage.get(c.signature) ?? [];
      list.push(c);
      perPackage.set(c.signature, list);
    }
    if (!anyEntry) skipped += 1;
  }

  const out: PackageRecord[] = [];
  for (const pkg of stableSort([...contributions.keys()])) {
    const perPackage = contributions.get(pkg) as Map<string, Contribution[]>;
    for (const sig of stableSort([...perPackage.keys()])) {
      const list = perPackage.get(sig) as Contribution[];
      const sourceIds: string[] = [];
      const aliases: string[] = [];
      let malicious = false;
      let severity = "UNKNOWN";
      let summary = "";
      const sevOrder = ["UNKNOWN", "NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
      for (const c of list) {
        if (!sourceIds.includes(c.record.id)) sourceIds.push(c.record.id);
        aliases.push(c.record.id, ...c.record.aliases);
        if (isMalicious(c.record)) malicious = true;
        const sev = maxSeverity(c.record);
        if (sevOrder.indexOf(sev) > sevOrder.indexOf(severity)) severity = sev;
        if (summary.length === 0 && c.record.summary !== undefined) summary = c.record.summary;
      }
      const mergedAliases = stableSort(aliases);
      const mergedSourceIds = stableSort(sourceIds);
      // Canonical id for the merged record (plan section 5.2): the
      // lexicographically smallest CVE-* alias when one or more exist (the
      // CVE id is the human-facing identifier — the two-GHSA-file lodash
      // case merges to its CVE), else the smallest source id, else the
      // smallest alias. A presentation field, never a dedup key.
      const cveAliases = mergedAliases.filter((a) => a.startsWith("CVE-"));
      const canonical =
        cveAliases.length > 0
          ? (cveAliases[0] as string)
          : mergedSourceIds.length > 0
            ? (mergedSourceIds[0] as string)
            : (mergedAliases[0] ?? pkg);
      out.push({
        sourceIds: mergedSourceIds,
        aliases: mergedAliases,
        packageName: pkg,
        ecosystem: "npm",
        ranges: list[0] ? (list[0] as Contribution).ranges : [],
        versions: list[0] ? (list[0] as Contribution).versions : [],
        malicious,
        severity,
        summary,
        canonicalId: canonical,
      });
    }
  }
  return { records: out, skipped };
}

/** Sibling findings for the same package, linked by relatedIds (v3.4). */
export function relatedIds(records: PackageRecord[], rec: PackageRecord): string[] {
  return stableSort(
    records
      .filter((r) => r.packageName === rec.packageName && r.sourceIds.join("\n") !== rec.sourceIds.join("\n"))
      .map((r) => r.canonicalId),
  );
}
