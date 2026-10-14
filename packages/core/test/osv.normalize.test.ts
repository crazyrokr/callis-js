import { describe, expect, test } from "bun:test";
import { type PackageRecord, normalizeRecords, relatedIds } from "../src/osv/normalize.js";
import { type OsRecord, canonicalId, isMalicious, parseRecord } from "../src/osv/record.js";

function record(id: string, aliases: string[], affected: unknown[]): OsRecord {
  const r = parseRecord(JSON.stringify({ id, aliases, affected }));
  if (r === null) throw new Error(`record ${id} failed to parse`);
  return r;
}

function semverEntry(name: string, introduced: string, fixed?: string) {
  const events: { introduced?: string; fixed?: string }[] = [{ introduced }];
  if (fixed !== undefined) events.push({ fixed });
  return { package: { name, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events }] };
}

describe("advisory normalization and dedup (plan 5.2, v3.3/v3.4)", () => {
  test("given two records of the same issue in two bucket files, when normalized, then they merge with the union of source ids and aliases", () => {
    const a = record("GHSA-aaaa-1111-2222", ["CVE-2021-23337"], [semverEntry("lodash", "0", "4.17.21")]);
    const b = record("GHSA-bbbb-3333-4444", ["CVE-2021-23337"], [semverEntry("lodash", "0", "4.17.21")]);
    const { records, skipped } = normalizeRecords([a, b]);
    expect(skipped).toBe(0);
    expect(records.length).toBe(1);
    const merged = records[0] as PackageRecord;
    expect(merged.packageName).toBe("lodash");
    expect(merged.sourceIds).toEqual(["GHSA-aaaa-1111-2222", "GHSA-bbbb-3333-4444"]);
    expect(merged.aliases).toContain("CVE-2021-23337");
    expect(merged.canonicalId).toBe("CVE-2021-23337");
  });

  test("given one record with several CVE aliases, when the canonical id is chosen, then the lexicographically smallest CVE wins", () => {
    const r = record(
      "GHSA-1",
      ["CVE-2023-22222", "CVE-2021-11111", "CVE-2022-33333"],
      [semverEntry("lodash", "0", "9.9.9")],
    );
    expect(canonicalId(r)).toBe("CVE-2021-11111");
  });

  test("given one record with no CVE alias, when the canonical id is chosen, then the record's own id wins", () => {
    const r = record("GHSA-xyz-1", ["PYSEC-123"], [semverEntry("lodash", "0", "9.9.9")]);
    expect(canonicalId(r)).toBe("GHSA-xyz-1");
  });

  test("given records with differing ranges for the same package, when normalized, then they stay separate findings linked by relatedIds", () => {
    const a = record("GHSA-a", [], [semverEntry("lodash", "0", "4.17.21")]);
    const b = record("GHSA-b", [], [semverEntry("lodash", "0", "4.17.20")]);
    const { records } = normalizeRecords([a, b]);
    expect(records.length).toBe(2);
    expect(relatedIds(records, records[0] as PackageRecord)).toEqual([(records[1] as PackageRecord).canonicalId]);
    expect(relatedIds(records, records[1] as PackageRecord)).toEqual([(records[0] as PackageRecord).canonicalId]);
  });

  test("given records with partially overlapping alias sets, when normalized, then no merge happens (alias overlap is never the dedup rule)", () => {
    const a = record("GHSA-a", ["CVE-1-1-1"], [semverEntry("lodash", "0", "4.17.21")]);
    const b = record("GHSA-b", ["CVE-1-1-1", "CVE-2-2-2"], [semverEntry("lodash", "0", "4.17.22")]);
    const { records } = normalizeRecords([a, b]);
    expect(records.length).toBe(2);
  });

  test("given an affected entry without a package identity, when normalized, then it matches nothing", () => {
    const a = record("GHSA-noid", [], [{ ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }]);
    const { records, skipped } = normalizeRecords([a]);
    expect(records.length).toBe(0);
    expect(skipped).toBe(1);
  });

  test("given an affected entry whose package identity comes from an npm purl, when normalized, then the package is matched", () => {
    const a = record(
      "GHSA-purl",
      [],
      [
        {
          package: { purl: "pkg:npm/%40babel/core@7.20.0" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "7.21.0" }] }],
        },
      ],
    );
    const { records } = normalizeRecords([a]);
    expect(records.length).toBe(1);
    expect((records[0] as PackageRecord).packageName).toBe("@babel/core");
  });

  test("given a record with a malformed event (two keys), when normalized, then the record is skipped + counted, never downgraded", () => {
    const a = record(
      "GHSA-bad",
      [],
      [
        {
          package: { name: "lodash", ecosystem: "npm" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0", fixed: "4.17.21" }] }],
        },
      ],
    );
    const { records, skipped } = normalizeRecords([a]);
    expect(records.length).toBe(0);
    expect(skipped).toBe(1);
  });

  test("given explicit versions with -npm suffixes, when normalized, then the suffixes are stripped", () => {
    const a = record(
      "GHSA-ver",
      [],
      [{ package: { name: "pkg", ecosystem: "npm" }, versions: ["1.0.0-npm", "2.0.0-npm"] }],
    );
    const { records } = normalizeRecords([a]);
    expect((records[0] as PackageRecord).versions).toEqual(["1.0.0", "2.0.0"]);
  });

  test("given a record with multi-package affected entries, when normalized, then each package produces its own record", () => {
    const a = record(
      "GHSA-multi",
      [],
      [
        semverEntry("lodash", "0", "4.17.21"),
        semverEntry("lodash-es", "0", "4.17.21"),
        {
          package: { name: "ruby-gem", ecosystem: "RubyGems" },
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }] }],
        },
      ],
    );
    const { records } = normalizeRecords([a]);
    const names = records.map((r) => (r as PackageRecord).packageName).sort();
    expect(names).toEqual(["lodash", "lodash-es", "ruby-gem"]);
  });

  test("given a MAL-* record, when classified, then it is malicious", () => {
    const a = record("MAL-2025-1234", [], [semverEntry("evil-pkg", "0", "99.99.99")]);
    expect(isMalicious(a)).toBe(true);
    const { records } = normalizeRecords([a]);
    expect((records[0] as PackageRecord).malicious).toBe(true);
  });
});
