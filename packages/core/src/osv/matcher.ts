// OSV version matching (plan section 5.2).
//
// Boundary semantics pinned (JVM ADR 0015 parity): `introduced` is an
// inclusive lower bound, `fixed` is EXCLUSIVE (v == fixed is not affected —
// the false-positive guard), `last_affected` is an inclusive upper bound.
// An event must carry exactly one of the three keys or the record is
// malformed (skipped + counted). An empty event list matches nothing.
// Multiple events within a range AND; multiple ranges OR. ECOSYSTEM ranges
// are treated as semver for npm. GIT ranges are skipped with a warning —
// but only when no SEMVER/versions evidence remains for that affected entry.

import { coerce, gte, lt, lte, valid as semverValid } from "semver";
import type { OsAffectedRange } from "./record.js";

export interface NormalizedRange {
  /** SEMVER/ECOSYSTEM (treated as semver for npm), GIT, or OTHER. */
  kind: "SEMVER" | "GIT" | "OTHER";
  /** Parsed events; [] when the range has no usable events. */
  events: { introduced?: string; fixed?: string; last_affected?: string }[];
  /** True when at least one event was malformed (not exactly one key). */
  malformed: boolean;
  /** Raw range string (GIT), for diagnostics. */
  raw?: string;
}

/** Normalize one OSV range; null when the whole record is malformed. */
export function normalizeRange(range: OsAffectedRange): NormalizedRange | null {
  const events = (range.events ?? []).map((e) => {
    const keys = [e.introduced !== undefined, e.fixed !== undefined, e.last_affected !== undefined].filter(
      Boolean,
    ).length;
    if (keys !== 1)
      return { malformed: true as const, ev: {} as { introduced?: string; fixed?: string; last_affected?: string } };
    const ev: { introduced?: string; fixed?: string; last_affected?: string } = {};
    if (e.introduced !== undefined) ev.introduced = String(e.introduced);
    if (e.fixed !== undefined) ev.fixed = String(e.fixed);
    if (e.last_affected !== undefined) ev.last_affected = String(e.last_affected);
    return { malformed: false as const, ev };
  });
  const malformed = events.some((e) => e.malformed);
  const usable = events.filter((e) => !e.malformed).map((e) => e.ev);
  const type = range.type?.toUpperCase() ?? "";
  if (type === "GIT") {
    return { kind: "GIT", events: [], malformed, ...(range.range !== undefined ? { raw: range.range } : {}) };
  }
  if (type !== "SEMVER" && type !== "ECOSYSTEM") {
    return { kind: "OTHER", events: [], malformed };
  }
  // ECOSYSTEM ranges are treated as semver for npm (plan section 5.2).
  return { kind: "SEMVER", events: usable, malformed };
}

function asVersion(v: string): string | null {
  if (v === "" || v === "*" || v === "0") return null;
  const exact = semverValid(v);
  if (exact !== null) return exact;
  const coerced = coerce(v);
  return coerced === null ? null : coerced.version;
}

/**
 * Does `version` satisfy one normalized range? Multiple events AND; the
 * boundary semantics above apply. Returns null for versions that are not
 * semver-comparable.
 */
export function rangeSatisfied(version: string, range: NormalizedRange): boolean | null {
  if (range.kind !== "SEMVER") return null;
  const v = asVersion(version);
  if (v === null) return null;
  let lower: string | null = null;
  let fixedUpper: string | null = null;
  let lastUpper: string | null = null;
  for (const ev of range.events) {
    if (ev.introduced !== undefined) {
      const n = asVersion(ev.introduced);
      if (n !== null && (lower === null || gte(n, lower))) lower = n;
    }
    if (ev.fixed !== undefined) {
      const n = asVersion(ev.fixed);
      if (n !== null && (fixedUpper === null || lt(n, fixedUpper))) fixedUpper = n;
    }
    if (ev.last_affected !== undefined) {
      const n = asVersion(ev.last_affected);
      if (n !== null && (lastUpper === null || lt(n, lastUpper))) lastUpper = n;
    }
  }
  // No usable events: the range matches nothing (empty event list rule).
  if (range.events.length === 0) return false;
  if (lower !== null && !gte(v, lower)) return false;
  if (fixedUpper !== null && !lt(v, fixedUpper)) return false; // v == fixed: NOT affected
  if (lastUpper !== null && !lte(v, lastUpper)) return false; // v == last_affected: affected
  return true;
}

/** Match evidence string in the JVM affectedRange shape (plan section 5.2). */
export function rangeEvidence(version: string, range: NormalizedRange, index: number): string {
  const evs = range.events.map((e) =>
    Object.entries(e)
      .map(([k, val]) => `${k}=${val === "0" ? "0" : val}`)
      .join(", "),
  );
  const parts = evs.filter((s) => s.length > 0);
  return `range#${index} (${parts.join("; ")})`;
}

export interface MatchResult {
  affected: boolean;
  /** Evidence string for the satisfied range/version list, or null. */
  evidence: string | null;
  /** True when the entry had no semver/versions evidence at all. */
  evidenceless: boolean;
}

/**
 * Is `version` affected by the normalized package record? Multiple ranges
 * OR; explicit versions are exact matches (ecosystem suffixes stripped by
 * the normalizer). `matchedOn`-style version choice (installed vs SBOM) is
 * applied by the caller by invoking this with each version (v3.5 item 8).
 */
export function isAffected(version: string, ranges: NormalizedRange[], versions: string[]): MatchResult {
  if (versions.length > 0) {
    // Explicit versions are exact matches; ecosystem suffixes (-npm) are
    // normalized on both sides (plan section 5.2).
    const normalizedList = versions.map((v) => normalizeExactVersion(v));
    if (normalizedList.includes(normalizeExactVersion(version))) {
      return { affected: true, evidence: `versions (${versions.join(", ")})`, evidenceless: false };
    }
  }
  const semverRanges = ranges.filter((r) => r.kind === "SEMVER");
  let evidence: string | null = null;
  for (let i = 0; i < semverRanges.length; i += 1) {
    const r = semverRanges[i];
    if (r === undefined) continue;
    const satisfied = rangeSatisfied(version, r);
    if (satisfied === true && evidence === null) evidence = rangeEvidence(version, r, i);
  }
  if (evidence !== null) return { affected: true, evidence, evidenceless: false };
  const gitOnly = ranges.every((r) => r.kind !== "SEMVER");
  return { affected: false, evidence: null, evidenceless: gitOnly && versions.length === 0 };
}

/** Normalize an installed/SBOM version for exact-list comparison. */
export function normalizeExactVersion(v: string): string {
  const plain = v.replace(/-npm$/, "");
  const exact = semverValid(plain);
  if (exact !== null) return exact;
  const coerced = coerce(plain);
  return coerced === null ? plain : coerced.version;
}
