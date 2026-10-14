import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { computePin } from "../src/osv/checksum.js";
import { buildIndex, filesForAliases, filesForPackages, loadIndex } from "../src/osv/index-store.js";
import { loadSnapshot } from "../src/osv/loader.js";
import { UsageError } from "../src/util/errors.js";

async function fixtureDir(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "callis-osv-idx-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel);
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content);
  }
  return dir;
}

const Lodash = {
  "npm/GHSA-aaaa-1111-2222.json": JSON.stringify({
    id: "GHSA-AAAA-1111-2222",
    aliases: ["CVE-2021-23337"],
    affected: [
      {
        package: { name: "lodash", ecosystem: "npm" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
      },
    ],
  }),
  "npm/GHSA-bbbb-3333-4444.json": JSON.stringify({
    id: "GHSA-BBBB-3333-4444",
    aliases: ["CVE-2021-23337"],
    affected: [
      {
        package: { name: "lodash", ecosystem: "npm" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
      },
    ],
  }),
  "npm/GHSA-cccc-5555-6666.json": JSON.stringify({
    id: "GHSA-CCCC-5555-6666",
    aliases: [],
    affected: [
      {
        package: { name: "express", ecosystem: "npm" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.18.0" }] }],
      },
    ],
  }),
  "npm/broken.json": "{not json",
};

describe("OSV index (plan 5.2: index, do not scan)", () => {
  test("given a snapshot, when the index is built, then packages and aliases key to record files", async () => {
    const dir = await fixtureDir(Lodash);
    const pin = await computePin(dir);
    const index = await buildIndex(dir, pin);
    expect(index.packages.lodash).toEqual(["npm/GHSA-aaaa-1111-2222.json", "npm/GHSA-bbbb-3333-4444.json"]);
    expect(index.packages.express).toEqual(["npm/GHSA-cccc-5555-6666.json"]);
    expect((index.aliases["CVE-2021-23337"] ?? []).sort()).toEqual([
      "npm/GHSA-aaaa-1111-2222.json",
      "npm/GHSA-bbbb-3333-4444.json",
    ]);
    expect(index.skippedRecords).toBe(1);
  });

  test("given SBOM package names, when the index is read, then only those record files are returned", async () => {
    const dir = await fixtureDir(Lodash);
    const pin = await computePin(dir);
    const index = await buildIndex(dir, pin);
    expect(filesForPackages(index, ["lodash", "qs"])).toEqual([
      "npm/GHSA-aaaa-1111-2222.json",
      "npm/GHSA-bbbb-3333-4444.json",
    ]);
    expect(filesForPackages(index, ["no-such-pkg"])).toEqual([]);
    expect(filesForAliases(index, ["CVE-2021-23337"]).length).toBe(2);
  });

  test("given a pin mismatch, when the index is loaded, then it is rebuilt", async () => {
    const dir = await fixtureDir(Lodash);
    const cacheDir = await mkdtemp(join(tmpdir(), "callis-cache-"));
    const pin = await computePin(dir);
    const first = await loadIndex(dir, pin, cacheDir);
    expect(first.pin).toBe(pin);
    const second = await loadIndex(dir, "deadbeef".repeat(8), cacheDir);
    expect(second.pin).toBe("deadbeef".repeat(8));
    // A matching pin read does not rebuild: the stored index is returned.
    const third = await loadIndex(dir, pin, cacheDir);
    expect(third.packages.lodash).toEqual(first.packages.lodash);
  });

  test("given a snapshot with files but zero valid records for the SBOM set, when loaded, then zeroValidRecords is set (the exit-3 condition)", async () => {
    const dir = await fixtureDir({ "npm/only-malformed.json": "{not json" });
    const snapshot = await loadSnapshot(dir, ["lodash"], await mkdtemp(join(tmpdir(), "callis-cache-")));
    expect(snapshot.records.length).toBe(0);
    expect(snapshot.zeroValidRecords).toBe(true);
  });

  test("given an expected pin, when the computed pin differs, then a UsageError is thrown (exit 2)", async () => {
    const dir = await fixtureDir(Lodash);
    await expect(
      loadSnapshot(dir, ["lodash"], await mkdtemp(join(tmpdir(), "callis-cache-")), "0".repeat(64)),
    ).rejects.toThrow(UsageError);
  });

  test("given a nonexistent directory, when loaded, then a UsageError is thrown (exit 2)", async () => {
    await expect(
      loadSnapshot("/nonexistent-osv-dir-xyz", ["lodash"], await mkdtemp(join(tmpdir(), "callis-cache-"))),
    ).rejects.toThrow(UsageError);
  });
});
