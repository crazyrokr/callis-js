// M7c — PnP install-state reader + content-addressed zip extraction
// (project/pnp.ts): GWT over the record shapes, the corrupted-file contract
// (UsageError), zip lookup (local → global cache), and the extract-once
// rule (reuse by content, crash-safe, traversal rejected).

import { describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  writeFileSync as writeFileSyncSync,
} from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync, gzipSync } from "node:zlib";
import {
  type PnpPackageLocator,
  defaultGlobalCacheDir,
  ensurePnpExtracted,
  findPnpZip,
  readInstallState,
} from "../src/project/pnp.js";
import { UsageError } from "../src/util/errors.js";
import { sha256Hex } from "../src/util/hash.js";
import { ZipError } from "../src/util/zip.js";

interface FixtureEntry {
  name: string;
  data: Buffer;
  method?: 0 | 8;
}

/** Minimal ZIP writer for fixtures (same contract as util.zip.test.ts). */
function makeZip(entries: FixtureEntry[]): Buffer {
  const CRC_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c >>> 0;
    }
    return t;
  })();
  const crc = (b: Buffer): number => {
    let c = 0xffffffff;
    for (let i = 0; i < b.length; i++) {
      const idx = (c ^ (b[i] ?? 0)) & 0xff;
      c = (CRC_TABLE[idx] ?? 0) ^ (c >>> 8);
    }
    return (c ^ 0xffffffff) >>> 0;
  };
  const locals: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const method = e.method ?? 8;
    const name = Buffer.from(e.name, "utf8");
    const comp = method === 8 ? deflateRawSync(e.data) : e.data;
    const c = crc(e.data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(c, 14);
    local.writeUInt32LE(comp.length, 18);
    local.writeUInt32LE(e.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(local, name, comp);
    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(20, 4);
    cen.writeUInt16LE(20, 6);
    cen.writeUInt16LE(0, 8);
    cen.writeUInt16LE(method, 10);
    cen.writeUInt32LE(c, 16);
    cen.writeUInt32LE(comp.length, 20);
    cen.writeUInt32LE(e.data.length, 24);
    cen.writeUInt16LE(name.length, 28);
    cen.writeUInt32LE(offset, 42);
    central.push(cen, name);
    offset += local.length + name.length + comp.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

function tmpSync(prefix: string): string {
  return mkdtempSync(join(tmpdir(), `callis-pnp-${prefix}-`));
}

async function tmpAsync(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), `callis-pnp-${prefix}-`));
}

function writeGz(root: string, content: Buffer): void {
  const dir = join(root, ".yarn");
  mkdirSync(dir, { recursive: true });
  writeFileSyncSync(join(dir, "install-state.gz"), content);
}

function writeGzJson(root: string, json: unknown): void {
  writeGz(root, gzipSync(JSON.stringify(json)));
}

describe("readInstallState", () => {
  test("given v5-style records (packageManifest), when read, then each entry yields name/version/folderName and the checksum is the raw sha256", () => {
    const root = tmpSync("v5");
    try {
      const records = [
        {
          version: 5,
          folderName: "lodash-npm-4.17.21-abc123.zip",
          checksum: "deadbeef",
          packageManifest: { name: "lodash", version: "4.17.21", resolution: "lodash@npm:4.17.21" },
        },
        {
          version: 5,
          folderName: "ms-npm-2.1.3-def456.zip",
          packageManifest: { name: "ms", version: "2.1.3" },
        },
      ];
      const raw = gzipSync(JSON.stringify(records));
      writeGz(root, raw);
      const st = readInstallState(root);
      expect(st).not.toBe(null);
      expect(st?.entries).toEqual([
        { name: "lodash", version: "4.17.21", folderName: "lodash-npm-4.17.21-abc123.zip", checksum: "deadbeef" },
        { name: "ms", version: "2.1.3", folderName: "ms-npm-2.1.3-def456.zip", checksum: undefined },
      ]);
      expect(st?.checksum).toBe(sha256Hex(raw));
    } finally {
      void rm(root, { recursive: true, force: true });
    }
  });

  test("given records that carry the identity in `pattern` instead, when read, then the identity comes from pattern (format-drift tolerance)", () => {
    const root = tmpSync("pattern");
    try {
      writeGzJson(root, [
        { version: 3, folderName: "is-odd-npm-3.0.1-xyz.zip", pattern: { name: "is-odd", version: "3.0.1" } },
      ]);
      expect(readInstallState(root)?.entries).toEqual([
        { name: "is-odd", version: "3.0.1", folderName: "is-odd-npm-3.0.1-xyz.zip", checksum: undefined },
      ]);
    } finally {
      void rm(root, { recursive: true, force: true });
    }
  });

  test("given a record without any usable identity, when read, then it is skipped (tolerant, not an error)", () => {
    const root = tmpSync("skip");
    try {
      writeGzJson(root, [
        { version: 5, folderName: "no-identity.zip" },
        { version: 5, folderName: "ok-npm-1.0.0.zip", packageManifest: { name: "ok", version: "1.0.0" } },
      ]);
      expect(readInstallState(root)?.entries).toEqual([
        { name: "ok", version: "1.0.0", folderName: "ok-npm-1.0.0.zip", checksum: undefined },
      ]);
    } finally {
      void rm(root, { recursive: true, force: true });
    }
  });

  test("given a project WITHOUT install-state.gz, when read, then null (the caller refuses with a hint)", () => {
    const root = tmpSync("absent");
    try {
      expect(readInstallState(root)).toBeNull();
    } finally {
      void rm(root, { recursive: true, force: true });
    }
  });

  test("given a corrupt gzip, when read, then a UsageError with a re-install hint", () => {
    const root = tmpSync("corrupt-gz");
    try {
      writeGz(root, Buffer.from("this is not gzip"));
      expect(() => readInstallState(root)).toThrow(UsageError);
      expect(() => readInstallState(root)).toThrow(/not a valid gzip/);
    } finally {
      void rm(root, { recursive: true, force: true });
    }
  });

  test("given valid gzip but non-JSON content, when read, then a UsageError", () => {
    const root = tmpSync("corrupt-json");
    try {
      writeGz(root, gzipSync("not json at all"));
      expect(() => readInstallState(root)).toThrow(/not valid JSON/);
    } finally {
      void rm(root, { recursive: true, force: true });
    }
  });

  test("given a JSON object (not an array), when read, then a UsageError", () => {
    const root = tmpSync("not-array");
    try {
      writeGz(root, gzipSync(JSON.stringify({ nope: true })));
      expect(() => readInstallState(root)).toThrow(/expected a JSON array/);
    } finally {
      void rm(root, { recursive: true, force: true });
    }
  });
});

describe("findPnpZip", () => {
  test("given a zip in the project-local cache, when looked up, then the local path wins", () => {
    const root = tmpSync("local");
    try {
      const cacheDir = join(root, ".yarn", "cache");
      mkdirSync(cacheDir, { recursive: true });
      writeFileSyncSync(join(cacheDir, "lodash-npm-4.17.21-abc.zip"), Buffer.from("zip"));
      expect(findPnpZip(root, "lodash-npm-4.17.21-abc.zip", { globalCacheDir: join(root, "global") })).toBe(
        join(cacheDir, "lodash-npm-4.17.21-abc.zip"),
      );
    } finally {
      void rm(root, { recursive: true, force: true });
    }
  });

  test("given a zip ONLY in the global cache, when looked up, then the global path is returned", () => {
    const root = tmpSync("global");
    const globalCache = tmpSync("global-cache");
    try {
      writeFileSyncSync(join(globalCache, "ms-npm-2.1.3-def.zip"), Buffer.from("zip"));
      expect(findPnpZip(root, "ms-npm-2.1.3-def.zip", { globalCacheDir: globalCache })).toBe(
        join(globalCache, "ms-npm-2.1.3-def.zip"),
      );
    } finally {
      void rm(root, { recursive: true, force: true });
      void rm(globalCache, { recursive: true, force: true });
    }
  });

  test("given a folderName absent from both caches, when looked up, then null (MISSING-eligible, not an error)", () => {
    const root = tmpSync("absent-zip");
    try {
      expect(findPnpZip(root, "ghost-npm-9.9.9-000.zip", { globalCacheDir: join(root, "no-such-global") })).toBeNull();
    } finally {
      void rm(root, { recursive: true, force: true });
    }
  });

  test("given the default global cache dir, when computed, then it is ~/.yarn/berry/cache (and YARN_GLOBAL_FOLDER wins)", () => {
    const saved = process.env.YARN_GLOBAL_FOLDER;
    try {
      Reflect.deleteProperty(process.env, "YARN_GLOBAL_FOLDER");
      expect(defaultGlobalCacheDir()).toBe(join(homedir(), ".yarn", "berry", "cache"));
      process.env.YARN_GLOBAL_FOLDER = "/opt/yarn-cache";
      expect(defaultGlobalCacheDir()).toBe("/opt/yarn-cache/cache");
    } finally {
      if (saved === undefined) Reflect.deleteProperty(process.env, "YARN_GLOBAL_FOLDER");
      else process.env.YARN_GLOBAL_FOLDER = saved;
    }
  });
});

describe("ensurePnpExtracted (extract fully, once, content-addressed)", () => {
  const locator: PnpPackageLocator = { name: "lodash", version: "4.17.21", folderName: "lodash-npm-4.17.21-abc.zip" };

  test("given a yarn cache zip, when extracted, then the package files land at the content-addressed dest with a manifest", async () => {
    const base = await tmpAsync("extract");
    const cache = join(base, "cache");
    const zip = join(base, "zip");
    writeFileSyncSync(
      zip,
      makeZip([
        { name: "package.json", data: Buffer.from('{"name":"lodash"}') },
        { name: "index.js", data: Buffer.from("module.exports = {}") },
      ]),
    );
    try {
      const dest = ensurePnpExtracted(zip, locator, cache);
      expect(readFileSync(join(dest, "package.json"), "utf8")).toBe('{"name":"lodash"}');
      expect(readFileSync(join(dest, "index.js"), "utf8")).toBe("module.exports = {}");
      expect(existsSync(join(dest, ".callis-extracted.json"))).toBe(true);
      expect(dest.endsWith("lodash@4.17.21")).toBe(true);
    } finally {
      await rm(base, { recursive: true, force: true });
    }
  });

  test("given the SAME zip requested again, when re-extracted, then the existing tree is reused verbatim (no re-extraction: a sentinel survives)", async () => {
    const base = await tmpAsync("reuse");
    const cache = join(base, "cache");
    const zip = join(base, "zip");
    writeFileSyncSync(zip, makeZip([{ name: "package.json", data: Buffer.from("{}") }]));
    try {
      const first = ensurePnpExtracted(zip, locator, cache);
      writeFileSyncSync(join(first, "sentinel.txt"), "survives");
      const second = ensurePnpExtracted(zip, locator, cache);
      expect(second).toBe(first);
      expect(readFileSync(join(second, "sentinel.txt"), "utf8")).toBe("survives");
    } finally {
      await rm(base, { recursive: true, force: true });
    }
  });

  test("given DIFFERENT content under the same name@version, when extracted, then a distinct content-addressed dir is created and the old tree is untouched", async () => {
    const base = await tmpAsync("drift");
    const cache = join(base, "cache");
    const zip = join(base, "zip");
    await writeFile(zip, makeZip([{ name: "package.json", data: Buffer.from('{"v":1}') }]));
    const first = ensurePnpExtracted(zip, locator, cache);
    await writeFile(zip, makeZip([{ name: "package.json", data: Buffer.from('{"v":2}') }]));
    const second = ensurePnpExtracted(zip, locator, cache);
    try {
      expect(second).not.toBe(first);
      expect(readFileSync(join(first, "package.json"), "utf8")).toBe('{"v":1}');
      expect(readFileSync(join(second, "package.json"), "utf8")).toBe('{"v":2}');
    } finally {
      await rm(base, { recursive: true, force: true });
    }
  });

  test("given a zip with a traversal entry, when extracted, then a ZipError is thrown and NO cache tree is left behind", async () => {
    const base = await tmpAsync("traversal");
    const cache = join(base, "cache");
    const zip = join(base, "zip");
    await writeFile(zip, makeZip([{ name: "../evil.js", data: Buffer.from("x"), method: 0 }]));
    try {
      expect(() => ensurePnpExtracted(zip, locator, cache)).toThrow(ZipError);
      const pnp = join(cache, "pnp");
      const leftovers = existsSync(pnp) ? readdirSync(pnp) : [];
      expect(leftovers).toEqual([]); // no half-built extraction survives
    } finally {
      await rm(base, { recursive: true, force: true });
    }
  });
});
