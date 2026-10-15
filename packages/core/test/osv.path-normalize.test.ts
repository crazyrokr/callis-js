// M6 — path normalization regression: the e2e harness passed the OSV dir as
// `<demo>//osv` (glob trailing slash), and the redundant slash made the pin
// and the index keys depend on the path spelling instead of the directory
// contents. The pin contract (plan section 5.2, shell-script parity) is a
// function of the directory alone.

import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { computePin, hashAllFiles } from "../src/osv/checksum.js";
import { buildIndex, listRecordFiles } from "../src/osv/index-store.js";

async function makeSnapshot(): Promise<string> {
  // Absolute /tmp anchor: every pin/index function normalizes its argument
  // with path.resolve, so a CWD-relative fixture path would resolve
  // differently for whoever runs the suite (bun test workers, CI, local).
  const dir = await mkdtemp(join("/tmp", "callis-pinnorm-"));
  await writeFile(
    join(dir, "GHSA-0001-aaaa-bbbb.json"),
    JSON.stringify({
      id: "GHSA-0001-AAAA-BBBB",
      affected: [
        {
          package: { name: "p", ecosystem: "npm" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.0" }] }],
        },
      ],
    }),
  );
  await writeFile(join(dir, "broken.json"), "{not json");
  return dir;
}

describe("OSV path normalization (redundant slashes in the directory argument)", () => {
  test("given a snapshot dir, when the pin is computed with single vs doubled vs trailing slashes, then the pins are identical", async () => {
    const dir = await makeSnapshot();
    try {
      // Redundant-slash spellings of the SAME directory must give the same
      // pin. (A "./" + absolutePath spelling is NOT the same directory —
      // path.join/resolve normalize it to a CWD-relative path — so it is
      // deliberately not part of this contract.)
      const single = await computePin(dir);
      expect(await computePin(`${dir}/`)).toBe(single);
      expect(await computePin(`${dir}//`)).toBe(single);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("given a snapshot dir, when all files are hashed with redundant slashes, then the keys are the same relative paths", async () => {
    const dir = await makeSnapshot();
    try {
      const a = [...(await hashAllFiles(dir)).entries()].sort();
      const b = [...(await hashAllFiles(`${dir}//`)).entries()].sort();
      expect(b).toEqual(a);
      // Byte order: "GHSA-..." (0x47) sorts before "broken.json" (0x62).
      expect(a.map(([k]) => k)).toEqual(["GHSA-0001-aaaa-bbbb.json", "broken.json"]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("given a snapshot dir, when record files are listed with redundant slashes, then the relative names are unchanged", async () => {
    const dir = await makeSnapshot();
    try {
      expect(await listRecordFiles(`${dir}//`)).toEqual(await listRecordFiles(dir));
      expect(await listRecordFiles(dir)).toEqual(["GHSA-0001-aaaa-bbbb.json", "broken.json"]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("given a snapshot dir, when an index is built through a doubled-slash path, then every record is valid and the package key resolves", async () => {
    const dir = await makeSnapshot();
    try {
      const pin = await computePin(dir);
      const index = await buildIndex(`${dir}//`, pin);
      expect(index.validRecords).toBe(1);
      expect(index.skippedRecords).toBe(1);
      expect(index.packages.p).toEqual(["GHSA-0001-aaaa-bbbb.json"]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
