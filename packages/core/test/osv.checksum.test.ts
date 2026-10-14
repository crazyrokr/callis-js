import { describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { computePin, hashAllFiles } from "../src/osv/checksum.js";
import { byteOrderSort, sha256Hex } from "../src/util/hash.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..");

async function fixtureDir(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "callis-osv-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel);
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content);
  }
  return dir;
}

describe("OSV snapshot pin (plan 5.2: script/TS parity)", () => {
  test("given a small snapshot, when the pin is computed in TS and in shell, then they are identical", async () => {
    const dir = await fixtureDir({
      "npm/GHSA-aaaa-1111-2222.json": '{"id":"GHSA-AAAA-1111-2222"}',
      "npm/GHSA-bbbb-3333-4444.json": '{"id":"GHSA-BBBB-3333-4444"}',
      "npm/GHSA-cccc-5555-6666.json": '{"id":"GHSA-CCCC-5555-6666"}',
    });
    const tsPin = await computePin(dir);
    const shellPin = execFileSync("bash", [join(repoRoot, "scripts/compute-pin.sh"), dir], { encoding: "utf8" }).trim();
    expect(tsPin).toBe(shellPin);
    expect(tsPin).toMatch(/^[0-9a-f]{64}$/);
  });

  test("given a nested layout with non-ASCII file names, when hashed, then the byte-order sort is stable", async () => {
    const dir = await fixtureDir({
      "npm/a.json": "one",
      "npm/b.json": "two",
      "deep/nested/c.json": "three",
      "npm/züst.json": "four",
    });
    const files = await hashAllFiles(dir);
    expect(files.size).toBe(4);
    const lines = byteOrderSort([...files.entries()].map(([n, s]) => `${n}:${s}`));
    const pin = sha256Hex(Buffer.from(`${lines.join("\n")}\n`, "utf8"));
    const shellPin = execFileSync("bash", [join(repoRoot, "scripts/compute-pin.sh"), dir], { encoding: "utf8" }).trim();
    expect(pin).toBe(shellPin);
  });

  test("given a changed file, when the pin is recomputed, then it changes (invalidation)", async () => {
    const dir = await fixtureDir({ "npm/a.json": "one" });
    const before = await computePin(dir);
    await writeFile(join(dir, "npm/a.json"), "one-patched");
    const after = await computePin(dir);
    expect(before).not.toBe(after);
  });
});
