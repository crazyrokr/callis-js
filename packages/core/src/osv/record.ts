// OSV record parsing (plan section 5.2).
//
// Records are stored under database-specific ids, not every alias — one
// issue can appear as several bucket files. Upstream data is inconsistent,
// so parsing is lenient about shape but strict about identity: entries
// without a determinable package identity never match (v3.3).

import { readFile } from "node:fs/promises";
import { z } from "zod";
import { parsePurl } from "../sbom/purl.js";

const rangeEvent = z.object({
  introduced: z.union([z.string(), z.number()]).optional(),
  fixed: z.union([z.string(), z.number()]).optional(),
  last_affected: z.union([z.string(), z.number()]).optional(),
});

const affectedRange = z.object({
  type: z.string(),
  events: z.array(rangeEvent).default([]),
  range: z.string().optional(),
});

const affectedPackage = z.object({
  name: z.string().optional(),
  ecosystem: z.string().optional(),
  purl: z.string().optional(),
});

const affectedEntry = z.object({
  package: affectedPackage.optional(),
  ranges: z.array(affectedRange).default([]),
  versions: z.array(z.string()).optional(),
});

const osvRecord = z.object({
  id: z.string(),
  aliases: z.array(z.string()).default([]),
  summary: z.string().optional(),
  details: z.string().optional(),
  severity: z
    .array(
      z.object({
        type: z.string(),
        data: z.object({ CVE: z.string().optional(), score: z.string().optional() }).partial(),
      }),
    )
    .default([]),
  affected: z.array(affectedEntry).default([]),
  schema_version: z.string().optional(),
  published: z.string().optional(),
  modified: z.string().optional(),
});

export type OsRecordEvent = z.infer<typeof rangeEvent>;
export type OsAffectedRange = z.infer<typeof affectedRange>;
export type OsAffectedEntry = z.infer<typeof affectedEntry>;
export type OsRecord = z.infer<typeof osvRecord>;

/** Parse one OSV record file. Returns null for unreadable/malformed JSON. */
export function parseRecord(json: string): OsRecord | null {
  let doc: unknown;
  try {
    doc = JSON.parse(json);
  } catch {
    return null;
  }
  try {
    return osvRecord.parse(doc) as OsRecord;
  } catch {
    return null;
  }
}

/** Injectable record read (test seam; default is a plain file read). */
export type ReadRecordFn = (path: string) => Promise<string>;

export async function defaultReadRecord(path: string): Promise<string> {
  return readFile(path, "utf8");
}

/**
 * Read + parse one record file. An unreadable file (vanished, permissions)
 * is skipped + counted by the caller — never a silent gap.
 */
export async function readRecordFile(path: string, read: ReadRecordFn = defaultReadRecord): Promise<OsRecord | null> {
  try {
    return parseRecord(await read(path));
  } catch {
    return null;
  }
}

/** MAL-* records are malicious-package advisories (plan section 5.2). */
export function isMalicious(record: OsRecord): boolean {
  return record.id.startsWith("MAL-") || record.aliases.some((a) => a.startsWith("MAL-"));
}

/**
 * Package identity of an affected entry (name or npm purl). Returns null
 * when no identity is determinable — such entries never match (v3.3): the
 * record's ecosystem only filters which records are read.
 */
export function packageIdentity(entry: OsAffectedEntry): string | null {
  const pkg = entry.package;
  if (pkg !== undefined) {
    if (pkg.name !== undefined && pkg.name.length > 0) return pkg.name;
    if (pkg.purl !== undefined) {
      try {
        const p = parsePurl(pkg.purl);
        if (p.type === "npm" && p.name.length > 0) return p.name;
      } catch {
        // malformed purl: no identity from this entry
      }
    }
  }
  return null;
}

/**
 * Canonical advisory id for presentation (plan section 5.2, v3.1): prefer
 * the lexicographically smallest CVE-* alias when several exist, else the
 * record's own id, else the lexicographically smallest alias.
 */
export function canonicalId(record: OsRecord): string {
  const all = new Set<string>([record.id, ...record.aliases]);
  const cves = [...all].filter((id) => id.startsWith("CVE-")).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  if (cves.length >= 2) return cves[0] as string;
  if (record.id.length > 0 && record.id !== "UNKNOWN") return record.id;
  if (cves.length === 1) return cves[0] as string;
  const smallest = [...all].filter((id) => id.length > 0).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))[0];
  return smallest ?? record.id;
}

/** Highest severity across the record's severity entries. */
export function maxSeverity(record: OsRecord): string {
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"];
  let best = "UNKNOWN";
  for (const s of record.severity) {
    if (s.type !== "CVSS_V3" && s.type !== "CVSS_V4") continue;
    const score = s.data?.score;
    if (score === undefined) continue;
    const level = scoreToLevel(score);
    if (order.indexOf(level) < order.indexOf(best) || best === "UNKNOWN") best = level;
  }
  return best;
}

function scoreToLevel(score: string): string {
  const n = Number.parseFloat(score);
  if (Number.isNaN(n)) return "UNKNOWN";
  if (n >= 9) return "CRITICAL";
  if (n >= 7) return "HIGH";
  if (n >= 4) return "MEDIUM";
  if (n >= 0.1) return "LOW";
  return "NONE";
}

/**
 * A record fails schema validation when its id is missing/empty — such a
 * record is skipped + counted, never downgraded into a normal vulnerability
 * (plan section 5.2, v3.3).
 */
export function recordIsUsable(record: OsRecord): boolean {
  return record.id.length > 0;
}

export { osvRecord };
