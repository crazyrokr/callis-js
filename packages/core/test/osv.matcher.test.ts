import { describe, expect, test } from "bun:test";
import { coerce, gte, lt, lte, valid } from "semver";
import {
  type NormalizedRange,
  isAffected,
  normalizeExactVersion,
  normalizeRange,
  rangeSatisfied,
} from "../src/osv/matcher.js";

/** Normalize a bound; the OSV "0" sentinel means unbounded. */
function asBound(v: string | undefined): string | null {
  if (v === undefined || v === "" || v === "0") return null;
  const exact = valid(v);
  if (exact !== null) return exact;
  const c = coerce(v);
  return c === null ? null : c.version;
}

/** Oracle: the pinned boundary semantics, stated directly with semver. */
function oracle(version: string, events: { introduced?: string; fixed?: string; last_affected?: string }[]): boolean {
  if (events.length === 0) return false;
  for (const ev of events) {
    const lo = asBound(ev.introduced);
    if (lo !== null && !gte(version, lo)) return false;
    const hi = asBound(ev.fixed);
    if (hi !== null && !lt(version, hi)) return false;
    const la = asBound(ev.last_affected);
    if (la !== null && !lte(version, la)) return false;
  }
  return true;
}

function mkRange(
  events: { introduced?: string; fixed?: string; last_affected?: string }[],
  type = "SEMVER",
): NormalizedRange {
  const r = normalizeRange({ type, events });
  if (r === null) throw new Error("unnormalized range");
  return r;
}

describe("OSV matcher boundary semantics (plan 5.2, JVM ADR 0015 parity)", () => {
  test("given a range with introduced and fixed, when matched, then v==introduced is affected and v==fixed is NOT (the false-positive guard)", () => {
    const r = mkRange([{ introduced: "0" }, { fixed: "4.17.21" }]);
    expect(rangeSatisfied("4.17.20", r)).toBe(true); // the lodash CVE-2021-23337 case
    expect(rangeSatisfied("4.17.21", r)).toBe(false); // v == fixed: excluded
    expect(rangeSatisfied("4.17.22", r)).toBe(false);
  });

  test("given a last_affected-only entry, when matched, then v==last_affected is affected (inclusive upper bound)", () => {
    const r = mkRange([{ last_affected: "2.2.3" }]);
    expect(rangeSatisfied("2.2.3", r)).toBe(true);
    expect(rangeSatisfied("2.2.4", r)).toBe(false);
    expect(rangeSatisfied("0.0.1", r)).toBe(true);
  });

  test("given an introduced-only range, when matched, then everything from the bound up is affected", () => {
    const r = mkRange([{ introduced: "1.0.0" }]);
    expect(rangeSatisfied("0.9.0", r)).toBe(false);
    expect(rangeSatisfied("1.0.0", r)).toBe(true);
    expect(rangeSatisfied("99.0.0", r)).toBe(true);
  });

  test("given multiple events within a range, when matched, then they AND", () => {
    const r = mkRange([{ introduced: "1.0.0" }, { fixed: "2.0.0" }]);
    expect(rangeSatisfied("1.5.0", r)).toBe(true);
    expect(rangeSatisfied("0.5.0", r)).toBe(false);
    expect(rangeSatisfied("2.0.0", r)).toBe(false);
    expect(rangeSatisfied("3.0.0", r)).toBe(false);
  });

  test("given multiple ranges, when matched, then they OR", () => {
    const a = mkRange([{ introduced: "0" }, { fixed: "1.0.0" }]);
    const b = mkRange([{ introduced: "2.0.0" }]);
    // 1.5.0 is in neither range: the OR of two misses is a miss.
    expect(isAffected("1.5.0", [a, b], []).affected).toBe(false);
    expect(isAffected("0.5.0", [a, b], []).affected).toBe(true);
    expect(isAffected("3.0.0", [a, b], []).affected).toBe(true);
  });

  test("given an empty event list, when matched, then the range matches nothing", () => {
    expect(rangeSatisfied("1.0.0", mkRange([]))).toBe(false);
  });

  test("given an ECOSYSTEM range, when matched, then it is treated as semver", () => {
    const r = normalizeRange({ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "3.0.0" }] });
    expect(r?.kind).toBe("SEMVER");
    expect(rangeSatisfied("2.9.9", r as NormalizedRange)).toBe(true);
    expect(rangeSatisfied("3.0.0", r as NormalizedRange)).toBe(false);
  });

  test("given a GIT range with no other evidence, when matched, then the entry is evidenceless (no match)", () => {
    const r = normalizeRange({ type: "GIT", range: "https://x@v1.0...v2.0", events: [] });
    const result = isAffected("1.5.0", [r as NormalizedRange], []);
    expect(result.affected).toBe(false);
    expect(result.evidenceless).toBe(true);
  });

  test("given a GIT range with explicit versions, when matched, then the versions still match (warning only)", () => {
    const r = normalizeRange({ type: "GIT", range: "https://x@v1.0...v2.0", events: [] });
    const result = isAffected("1.5.0", [r as NormalizedRange], ["1.5.0"]);
    expect(result.affected).toBe(true);
    expect(result.evidenceless).toBe(false);
  });

  test("given explicit versions with an ecosystem suffix, when matched, then the -npm suffix is normalized", () => {
    expect(normalizeExactVersion("4.17.20-npm")).toBe("4.17.20");
    const result = isAffected("4.17.20", [], ["4.17.20-npm"]);
    expect(result.affected).toBe(true);
    expect(result.evidence).toContain("versions");
  });

  test("given a version that is not semver, when matched, then it is not affected", () => {
    const r = mkRange([{ introduced: "0" }]);
    expect(isAffected("not-a-version", [r], []).affected).toBe(false);
  });

  test("given a range, when evidence is requested, then it uses the affectedRange string shape", () => {
    const r = mkRange([{ introduced: "0" }, { fixed: "4.17.21" }]);
    const result = isAffected("4.17.20", [r], []);
    expect(result.affected).toBe(true);
    expect(result.evidence).toBe("range#0 (introduced=0; fixed=4.17.21)");
  });
});

describe("OSV matcher property tests against the semver package (plan 9)", () => {
  function mulberry32(seed: number): () => number {
    let a = seed;
    return () => {
      a |= 0;
      a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  test("given generated introduced/fixed pairs and versions, when matched, then the matcher agrees with the semver oracle", () => {
    const rand = mulberry32(20261013);
    for (let i = 0; i < 500; i += 1) {
      const intro = `${Math.floor(rand() * 5)}.${Math.floor(rand() * 10)}.${Math.floor(rand() * 10)}`;
      const fixed = `${Math.floor(rand() * 6)}.${Math.floor(rand() * 10)}.${Math.floor(rand() * 10)}`;
      const version = `${Math.floor(rand() * 6)}.${Math.floor(rand() * 10)}.${Math.floor(rand() * 10)}`;
      const events = [{ introduced: intro }, { fixed }];
      const r = mkRange(events);
      const actual = rangeSatisfied(version, r);
      const expected = oracle(version, events);
      expect(actual).toBe(expected);
    }
  });

  test("given generated last_affected-only ranges, when matched, then the inclusive upper bound holds", () => {
    const rand = mulberry32(42);
    for (let i = 0; i < 300; i += 1) {
      const last = `${Math.floor(rand() * 5)}.${Math.floor(rand() * 10)}.${Math.floor(rand() * 10)}`;
      const version = `${Math.floor(rand() * 6)}.${Math.floor(rand() * 10)}.${Math.floor(rand() * 10)}`;
      const events = [{ last_affected: last }];
      const r = mkRange(events);
      expect(rangeSatisfied(version, r)).toBe(oracle(version, events));
    }
  });

  test("given generated multi-event ranges, when matched, then the AND semantics hold", () => {
    const rand = mulberry32(7);
    for (let i = 0; i < 200; i += 1) {
      const a = `${Math.floor(rand() * 4)}.${Math.floor(rand() * 10)}.0`;
      const b = `${Math.floor(rand() * 6)}.${Math.floor(rand() * 10)}.0`;
      const version = `${Math.floor(rand() * 7)}.${Math.floor(rand() * 10)}.0`;
      const events = [{ introduced: a }, { fixed: b }];
      const r = mkRange(events);
      expect(rangeSatisfied(version, r)).toBe(oracle(version, events));
    }
  });
});
