// Edge-case coverage for the M1 data layer (plan section 9: 100% line
// coverage on sbom/ and osv/).

import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { computePin } from "../src/osv/checksum.js";
import { buildIndex, loadIndex } from "../src/osv/index-store.js";
import { loadSnapshot } from "../src/osv/loader.js";
import { isAffected, normalizeExactVersion, normalizeRange } from "../src/osv/matcher.js";
import { normalizeRecords } from "../src/osv/normalize.js";
import type { PackageRecord } from "../src/osv/normalize.js";
import {
  type OsRecord,
  canonicalId,
  isMalicious,
  maxSeverity,
  packageIdentity,
  parseRecord,
  recordIsUsable,
} from "../src/osv/record.js";
import { parseCycloneDx } from "../src/sbom/cyclonedx.js";
import { readSbom, supplyPath } from "../src/sbom/index.js";
import { isNpmPurl, parsePurl } from "../src/sbom/purl.js";
import { parseSpdx } from "../src/sbom/spdx.js";
import { UsageError } from "../src/util/errors.js";

async function tmp(files: Record<string, string> = {}): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "callis-fill-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel);
    await mkdir(join(full, ".."), { recursive: true });
    await writeFile(full, content);
  }
  return dir;
}

describe("readSbom dispatch (plan 5.1)", () => {
  test("given a CycloneDX file, when read, then the CycloneDX reader is used", async () => {
    const dir = await tmp({
      "bom.json": JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.5",
        components: [{ name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20" }],
      }),
    });
    const r = readSbom(join(dir, "bom.json"));
    expect(r.format).toBe("cyclonedx-1.5");
    expect(r.components.length).toBe(1);
    expect(r.fileSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  test("given an SPDX 2.x file, when read, then the SPDX reader is used", async () => {
    const dir = await tmp({
      "bom.json": JSON.stringify({
        spdxVersion: "SPDX-2.3",
        packages: [{ spdxId: "P1", name: "lodash", purl: "pkg:npm/lodash@4.17.20" }],
        relationships: [],
      }),
    });
    expect(readSbom(join(dir, "bom.json")).format).toBe("spdx-2.3");
  });

  test("given a document with neither marker, when read, then a UsageError is thrown (exit 2)", async () => {
    const dir = await tmp({ "bom.json": JSON.stringify({ name: "nope" }) });
    expect(() => readSbom(join(dir, "bom.json"))).toThrow(UsageError);
  });

  test("given a non-JSON file, when read, then a UsageError is thrown (exit 2)", async () => {
    const dir = await tmp({ "bom.json": "definitely not json" });
    expect(() => readSbom(join(dir, "bom.json"))).toThrow(UsageError);
  });

  test("given a nonexistent file, when read, then a UsageError is thrown (exit 2)", async () => {
    expect(() => readSbom("/nonexistent-bom-file-xyz.json")).toThrow(UsageError);
  });
});

describe("supplyPath (plan 5.1)", () => {
  const deps = [
    { ref: "app", dependsOn: ["express", "lodash"] },
    { ref: "express", dependsOn: ["qs"] },
  ];

  test("given a two-hop chain, when walked, then the path is returned", () => {
    expect(supplyPath(deps, "app", "qs")).toEqual(["app", "express", "qs"]);
  });

  test("given from === to, when walked, then the single-element path is returned", () => {
    expect(supplyPath(deps, "app", "app")).toEqual(["app"]);
  });

  test("given an unknown target, when walked, then no path is returned", () => {
    expect(supplyPath(deps, "app", "unknown-pkg")).toEqual([]);
  });
});

describe("purl edge cases (plan 5.1)", () => {
  test("given a purl with an empty name part, when parsed, then a UsageError is thrown", () => {
    expect(() => parsePurl("pkg:npm/")).toThrow(UsageError);
  });

  test("given a malformed purl, when classified as npm, then the catch returns false", () => {
    expect(isNpmPurl("not-a-purl")).toBe(false);
  });
});

describe("CycloneDX component edge cases (plan 5.1)", () => {
  test("given a component with a malformed purl, when parsed, then it is skipped with a warning", () => {
    const r = parseCycloneDx(
      JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.5",
        components: [{ name: "x", version: "1.0.0", purl: "not-a-purl" }],
      }),
      "bom.json",
      "sha",
    );
    expect(r.components.length).toBe(0);
    expect(r.warnings[0]).toContain("not-a-purl");
  });
});

describe("SPDX package edge cases (plan 5.1)", () => {
  test("given a package without a purl, when parsed, then it is skipped with a warning", () => {
    const r = parseSpdx(
      JSON.stringify({
        spdxVersion: "SPDX-2.3",
        packages: [{ spdxId: "P1", name: "no-purl" }],
        relationships: [],
      }),
      "bom.json",
      "sha",
    );
    expect(r.components.length).toBe(0);
    expect(r.warnings[0]).toContain("no-purl");
  });

  test("given a package with a malformed purl, when parsed, then it is skipped with a warning", () => {
    const r = parseSpdx(
      JSON.stringify({
        spdxVersion: "SPDX-2.3",
        packages: [{ spdxId: "P1", name: "x", purl: "bad-purl" }],
        relationships: [],
      }),
      "bom.json",
      "sha",
    );
    expect(r.components.length).toBe(0);
    expect(r.warnings[0]).toContain("bad-purl");
  });

  test("given a package whose version comes from versionInfo, when parsed, then the version is carried", () => {
    const r = parseSpdx(
      JSON.stringify({
        spdxVersion: "SPDX-2.3",
        packages: [{ spdxId: "P1", name: "lodash", versionInfo: "4.17.20", purl: "pkg:npm/lodash" }],
        relationships: [],
      }),
      "bom.json",
      "sha",
    );
    expect(r.components[0]?.version).toBe("4.17.20");
  });

  test("given valid JSON that fails the SPDX 2.x schema, when parsed, then a UsageError is thrown", () => {
    expect(() =>
      parseSpdx(
        JSON.stringify({ spdxVersion: "SPDX-2.3", packages: "not-an-array", relationships: [] }),
        "bom.json",
        "sha",
      ),
    ).toThrow(UsageError);
  });

  test("given a pre-2.x spdxVersion, when parsed, then it is refused with a UsageError", () => {
    expect(() =>
      parseSpdx(JSON.stringify({ spdxVersion: "SPDX-1.0", packages: [], relationships: [] }), "bom.json", "sha"),
    ).toThrow(UsageError);
  });
});

describe("OSV record edge cases (plan 5.2)", () => {
  test("given unparseable JSON, when parsed, then null is returned", () => {
    expect(parseRecord("{not json")).toBeNull();
  });

  test("given an entry with a malformed purl, when its identity is resolved, then null is returned", () => {
    const r = parseRecord(JSON.stringify({ id: "GHSA-x", affected: [{ package: { purl: "bad" } }] }));
    expect(r).not.toBeNull();
    const entry = (r as OsRecord).affected[0];
    expect(entry).toBeDefined();
    if (entry === undefined) throw new Error("missing entry");
    expect(packageIdentity(entry)).toBeNull();
  });

  test("given CVSS scores, when the max severity is computed, then each band maps to its level", () => {
    const mk = (score: string) =>
      parseRecord(JSON.stringify({ id: "GHSA-s", severity: [{ type: "CVSS_V3", data: { score } }] }));
    expect(maxSeverity(mk("9.8") as OsRecord)).toBe("CRITICAL");
    expect(maxSeverity(mk("7.5") as OsRecord)).toBe("HIGH");
    expect(maxSeverity(mk("4.3") as OsRecord)).toBe("MEDIUM");
    expect(maxSeverity(mk("0.5") as OsRecord)).toBe("LOW");
    expect(maxSeverity(mk("0") as OsRecord)).toBe("NONE");
    expect(maxSeverity(mk("not-a-score") as OsRecord)).toBe("UNKNOWN");
  });

  test("given a non-CVSS severity entry, when the max severity is computed, then it is ignored", () => {
    const r = parseRecord(JSON.stringify({ id: "GHSA-n", severity: [{ type: "OTHER", data: { score: "9.9" } }] }));
    expect(maxSeverity(r as OsRecord)).toBe("UNKNOWN");
  });

  test("given a record whose id is a MAL alias, when classified, then it is malicious", () => {
    const r = parseRecord(JSON.stringify({ id: "GHSA-m", aliases: ["MAL-2025-1"], affected: [] }));
    expect(isMalicious(r as OsRecord)).toBe(true);
  });

  test("given a record with an empty id, when checked, then it is not usable", () => {
    const r = parseRecord(JSON.stringify({ id: "", affected: [] }));
    expect(recordIsUsable(r as OsRecord)).toBe(false);
  });
});

describe("matcher edge cases (plan 5.2)", () => {
  test("given a non-semver range type, when normalized, then it is OTHER and evidenceless", () => {
    const r = normalizeRange({ type: "SOMETHING-ELSE", events: [{ introduced: "0" }] });
    expect(r?.kind).toBe("OTHER");
    expect(normalizeExactVersion("not-a-version")).toBe("not-a-version");
  });

  test("given a record with an empty id, when normalized, then it is skipped + counted", () => {
    const r = parseRecord(JSON.stringify({ id: "", affected: [{ package: { name: "x", ecosystem: "npm" } }] }));
    const { records, skipped } = normalizeRecords([r as OsRecord]);
    expect(records.length).toBe(0);
    expect(skipped).toBe(1);
  });
});

describe("loader edge cases (plan 5.2/6)", () => {
  test("given a record that vanished between index and read, when loaded, then it is skipped and counted", async () => {
    const dir = await tmp({
      "npm/GHSA-a.json": JSON.stringify({
        id: "GHSA-A",
        affected: [
          {
            package: { name: "lodash", ecosystem: "npm" },
            ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
          },
        ],
      }),
    });
    const cacheDir = await tmp();
    const pin = await computePin(dir);
    await buildIndex(dir, pin);
    // A record that vanished (or became unreadable) between index and read
    // is skipped + counted, never a silent gap.
    const failingRead = async (_p: string): Promise<string> => {
      throw new Error("vanished");
    };
    const snapshot = await loadSnapshot(dir, ["lodash"], cacheDir, pin, failingRead);
    expect(snapshot.records.length).toBe(0);
    expect(snapshot.skippedRecords).toBe(1);
  });

  test("given a valid snapshot for the requested package, when loaded, then zeroValidRecords is false", async () => {
    const dir = await tmp({
      "npm/GHSA-b.json": JSON.stringify({
        id: "GHSA-B",
        affected: [
          {
            package: { name: "qs", ecosystem: "npm" },
            ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "6.7.0" }] }],
          },
        ],
      }),
    });
    const cacheDir = await tmp();
    const snapshot = await loadSnapshot(dir, ["qs"], cacheDir);
    expect(snapshot.zeroValidRecords).toBe(false);
    expect(snapshot.records.length).toBe(1);
    expect(snapshot.skippedRecords).toBe(0);
  });

  test("given an empty directory, when loaded, then there are no records and no zero-valid-records failure", async () => {
    const dir = await tmp();
    const cacheDir = await tmp();
    const snapshot = await loadSnapshot(dir, ["lodash"], cacheDir);
    expect(snapshot.records.length).toBe(0);
    expect(snapshot.zeroValidRecords).toBe(false);
  });
});

describe("advisory identity edge cases (plan 5.2)", () => {
  test("given a record with the UNKNOWN id and one CVE alias, when the canonical id is chosen, then the CVE alias wins", () => {
    const r = parseRecord(JSON.stringify({ id: "UNKNOWN", aliases: ["CVE-1-1-1"], affected: [] }));
    expect(r !== null && canonicalId(r as OsRecord)).toBe("CVE-1-1-1");
  });

  test("given a record with an empty id and no aliases, when the canonical id is chosen, then the empty id is returned", () => {
    const r = parseRecord(JSON.stringify({ id: "", aliases: [], affected: [] }));
    expect(r !== null && canonicalId(r as OsRecord)).toBe("");
  });

  test("given valid JSON that is not an object, when parsed, then null is returned", () => {
    expect(parseRecord(JSON.stringify([]))).toBeNull();
  });

  test("given a CVSS entry without a score, when the max severity is computed, then the entry is ignored", () => {
    const r = parseRecord(
      JSON.stringify({ id: "GHSA-noscore", severity: [{ type: "CVSS_V3", data: { CVE: "CVE-1-1-1" } }] }),
    );
    expect(maxSeverity(r as OsRecord)).toBe("UNKNOWN");
  });

  test("given explicit versions that do not match the installed version, when matched, then the record is not affected", () => {
    const r = parseRecord(
      JSON.stringify({
        id: "GHSA-ver",
        affected: [{ package: { name: "pkg", ecosystem: "npm" }, versions: ["1.0.0", "2.0.0"] }],
      }),
    );
    const { records } = normalizeRecords([r as OsRecord]);
    const rec = records[0] as PackageRecord;
    expect(isAffected("9.9.9", rec.ranges, rec.versions).affected).toBe(false);
  });
});

describe("index-store edge cases (plan 5.2)", () => {
  test("given a directory whose file list is empty, when the index is built, then it has no entries", async () => {
    const dir = await tmp();
    const pin = await computePin(dir);
    const index = await buildIndex(dir, pin);
    expect(Object.keys(index.packages).length).toBe(0);
    expect(index.validRecords).toBe(0);
    const loaded = await loadIndex(dir, pin, await tmp());
    expect(loaded.pin).toBe(pin);
  });
});
