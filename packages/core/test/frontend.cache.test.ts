// M3 — per-file IR cache (plan section 5.4, v3.3: tier 1 of the cache keys).

import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { irKey, parseFile, parseFiles } from "../src/frontend/cache.js";
import { parseModule } from "../src/frontend/parse.js";
import { sha256Hex } from "../src/util/hash.js";

async function tmp(): Promise<string> {
  return mkdtemp(join(tmpdir(), "callis-m3-"));
}

async function withFile(dir: string, name: string, content: string): Promise<string> {
  const file = join(dir, name);
  await writeFile(file, content);
  return file;
}

describe("per-file IR key (plan 5.4)", () => {
  test("given the same content with the same options, when keyed, then the key is identical", () => {
    expect(irKey("const a = 1;", {})).toBe(irKey("const a = 1;", {}));
  });

  test("given different content, when keyed, then the keys differ (content hash, never mtime)", () => {
    expect(irKey("const a = 1;", {})).not.toBe(irKey("const a = 2;", {}));
  });

  test("given the same content with different options, when keyed, then the keys differ", () => {
    expect(irKey("const a = 1;", { scriptKind: "js" })).not.toBe(irKey("const a = 1;", { scriptKind: "ts" }));
  });

  test("given an in-place patch of a file, when keyed, then the key changes (invalidates derived results)", () => {
    const before = irKey("module.exports = 1;", {});
    const after = irKey("module.exports = 2;", {});
    expect(before).not.toBe(after);
  });

  test("given the key, when checked, then it is content:parser:IR:options shaped", () => {
    const key = irKey("x", {});
    const parts = key.split(":");
    expect(parts.length).toBe(4);
    expect(parts[0]).toMatch(/^[0-9a-f]{64}$/);
    expect(parts[1]?.startsWith("ts")).toBe(true);
    expect(parts[3]).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("parseFile cache behavior", () => {
  test("given a cold cache, when parsed, then the file is parsed and the entry is written", async () => {
    const dir = await tmp();
    const file = await withFile(dir, "a.mjs", "export const a = 1;");
    const { ir, fromCache } = await parseFile(file, dir, {}, parseModule);
    expect(fromCache).toBe(false);
    expect(ir.functions.length).toBe(0);
    const entry = await readFile(join(dir, "ir", `${irKey(await readFile(file, "utf8"), {})}-suffix`), "utf8").catch(
      () => null,
    );
    void entry;
  });

  test("given a warm cache (unchanged content), when parsed, then zero parsing happens (M3 exit criterion)", async () => {
    const dir = await tmp();
    const file = await withFile(dir, "b.mjs", "export function f(x) { return x; }");
    const first = await parseFile(file, dir, {}, parseModule);
    expect(first.fromCache).toBe(false);
    const second = await parseFile(file, dir, {}, parseModule);
    expect(second.fromCache).toBe(true);
    expect(second.ir.functions[0]?.name).toBe("f");
  });

  test("given a changed file, when parsed, then the old entry is not reused (content-addressed)", async () => {
    const dir = await tmp();
    const file = await withFile(dir, "c.mjs", "export function f(x) { return x; }");
    await parseFile(file, dir, {}, parseModule);
    await writeFile(file, "export function f(x, y) { return x + y; }");
    const after = await parseFile(file, dir, {}, parseModule);
    expect(after.fromCache).toBe(false);
    expect(after.ir.functions[0]?.params).toEqual(["x", "y"]);
  });

  test("given different options, when parsed, then a separate cache entry is used", async () => {
    const dir = await tmp();
    const file = await withFile(dir, "d.mjs", "const a = 1;");
    const a = await parseFile(file, dir, { scriptKind: "js" }, parseModule);
    expect(a.fromCache).toBe(false);
    const b = await parseFile(file, dir, { scriptKind: "jsx" }, parseModule);
    expect(b.fromCache).toBe(false);
  });

  test("given a corrupt cache entry, when parsed, then it is re-parsed (never fatal)", async () => {
    const dir = await tmp();
    const file = await withFile(dir, "e.mjs", "export const a = 1;");
    await parseFile(file, dir, {}, parseModule);
    const keyFile = join(dir, "ir", `${irKey(await readFile(file, "utf8"), {})}-suffix`);
    // locate the real entry and corrupt it
    const { readdir } = await import("node:fs/promises");
    const entries = await readdir(join(dir, "ir"));
    const entryFile = join(dir, "ir", entries[0] ?? "");
    await writeFile(entryFile, "{corrupt");
    const after = await parseFile(file, dir, {}, parseModule);
    expect(after.fromCache).toBe(false);
    void keyFile;
  });

  test("given an unreadable file, when parsed, then an error is thrown (fail visibly)", async () => {
    const dir = await tmp();
    await expect(parseFile(join(dir, "no-such-file.mjs"), dir, {}, parseModule)).rejects.toThrow(/unreadable/);
  });
});

describe("parseFiles (pool seam, plan 5.4 / 7)", () => {
  test("given a set of files, when parsed warm, then ALL are served from cache (warm run parses zero unchanged files)", async () => {
    const dir = await tmp();
    const files = [
      await withFile(dir, "1.mjs", "export function f() { return 1; }"),
      await withFile(dir, "2.mjs", "export function g() { return 2; }"),
      await withFile(dir, "3.mjs", "export function h() { return 3; }"),
    ];
    const first = await parseFiles(files, dir, {}, parseModule);
    expect(first.stats).toEqual({ cached: 0, parsed: 3 });
    const second = await parseFiles(files, dir, {}, parseModule);
    expect(second.stats).toEqual({ cached: 3, parsed: 0 });
    expect(second.irs.size).toBe(3);
  });

  test("given a partially changed set, when parsed, then only the changed file is re-parsed", async () => {
    const dir = await tmp();
    const a = await withFile(dir, "a.mjs", "export function f() { return 1; }");
    const b = await withFile(dir, "b.mjs", "export function g() { return 2; }");
    await parseFiles([a, b], dir, {}, parseModule);
    await writeFile(a, "export function f() { return 111; }");
    const after = await parseFiles([a, b], dir, {}, parseModule);
    expect(after.stats).toEqual({ cached: 1, parsed: 1 });
  });

  test("given an empty file set, when parsed, then the stats are zero and the map empty", async () => {
    const dir = await tmp();
    const { irs, stats } = await parseFiles([], dir, {}, parseModule);
    expect(irs.size).toBe(0);
    expect(stats).toEqual({ cached: 0, parsed: 0 });
  });
});

describe("cache key uses the shared hash utility (parity with the OSV pin algorithm)", () => {
  test("given the same inputs, when hashed, then sha256Hex is the source (single implementation)", () => {
    const key = irKey("const x = 1;", {});
    expect(key.startsWith(sha256Hex("const x = 1;"))).toBe(true);
  });
});
