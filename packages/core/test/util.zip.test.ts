// M7c — zip reader (util/zip.ts): GWT over STORED/DEFLATE round-trips,
// safety rejections (zip-slip traversal, encryption, zip64, caps), and
// extraction (files land below destDir, traversal writes nothing).

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync } from "node:zlib";
import { ZIP_LIMITS, ZipError, crc32Of, extractZip, isSafeZipPath, unzipZip } from "../src/util/zip.js";

interface FixtureEntry {
  name: string;
  data: Buffer;
  /** 0 stored / 8 deflate — other values exercise the method rejection. */
  method?: number;
  /** set bit 0 of the general-purpose flags (encrypted). */
  encrypted?: boolean;
}

/** A minimal ZIP writer for fixtures (local headers + central directory + EOCD). */
function makeZip(entries: FixtureEntry[]): Buffer {
  const locals: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const method = e.method ?? 8;
    const name = Buffer.from(e.name, "utf8");
    const comp = method === 8 ? deflateRawSync(e.data) : e.data;
    const crc = crc32Of(e.data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(e.encrypted ? 0x1 : 0, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(comp.length, 18);
    local.writeUInt32LE(e.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, name, comp);

    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(20, 4);
    cen.writeUInt16LE(20, 6);
    cen.writeUInt16LE(e.encrypted ? 0x1 : 0, 8);
    cen.writeUInt16LE(method, 10);
    cen.writeUInt32LE(crc, 16);
    cen.writeUInt32LE(comp.length, 20);
    cen.writeUInt32LE(e.data.length, 24);
    cen.writeUInt16LE(name.length, 28);
    cen.writeUInt16LE(0, 30);
    cen.writeUInt16LE(0, 32);
    cen.writeUInt32LE(0, 36);
    cen.writeUInt32LE(offset, 42);
    central.push(cen, name);
    offset += local.length + name.length + comp.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...locals, cd, eocd]);
}

function makeZip64Eocd(): Buffer {
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0xffff, 8); // total entries = zip64 marker
  eocd.writeUInt32LE(0xffffffff, 12);
  eocd.writeUInt32LE(0xffffffff, 16);
  eocd.writeUInt16LE(0, 20);
  return eocd;
}

describe("unzipZip: round-trips", () => {
  test("given a single DEFLATE entry, when parsed, then the decompressed data matches", () => {
    const payload = Buffer.from("hello zip ".repeat(50));
    const zip = makeZip([{ name: "a.txt", data: payload }]);
    const entries = unzipZip(zip);
    expect(entries.map((e) => e.name)).toEqual(["a.txt"]);
    expect(entries[0]?.data.equals(payload)).toBe(true);
  });

  test("given multiple STORED entries, when parsed, then every entry round-trips in order", () => {
    const a = Buffer.from("stored-alpha");
    const b = Buffer.alloc(0); // empty entry
    const c = Buffer.from("stored-gamma");
    const zip = makeZip([
      { name: "dir/a", data: a, method: 0 },
      { name: "empty", data: b, method: 0 },
      { name: "deep/nested/c", data: c, method: 0 },
    ]);
    const entries = unzipZip(zip);
    expect(entries.map((e) => e.name)).toEqual(["dir/a", "empty", "deep/nested/c"]);
    expect(entries[0]?.data.equals(a)).toBe(true);
    expect(entries[1]?.data.length).toBe(0);
    expect(entries[2]?.data.equals(c)).toBe(true);
  });

  test("given an empty archive, when parsed, then zero entries (no error)", () => {
    expect(unzipZip(makeZip([]))).toEqual([]);
  });

  test("given a directory entry (trailing slash), when parsed, then it is returned like any entry", () => {
    const zip = makeZip([{ name: "somedir/", data: Buffer.alloc(0), method: 0 }]);
    expect(unzipZip(zip).map((e) => e.name)).toEqual(["somedir/"]);
  });
});

describe("unzipZip: structural rejections", () => {
  test("given a non-zip buffer, when parsed, then a ZipError names the missing EOCD", () => {
    expect(() => unzipZip(Buffer.from("definitely not a zip, just text"))).toThrow(ZipError);
    expect(() => unzipZip(Buffer.from("definitely not a zip, just text"))).toThrow(/end-of-central-directory/);
  });

  test("given an empty buffer, when parsed, then a ZipError (no EOCD to find)", () => {
    expect(() => unzipZip(Buffer.alloc(0))).toThrow(ZipError);
  });

  test("given a ZIP64 EOCD, when parsed, then zip64 is rejected", () => {
    expect(() => unzipZip(makeZip64Eocd())).toThrow(/zip64/);
  });

  test("given an encrypted entry, when parsed, then encryption is rejected by name", () => {
    const zip = makeZip([{ name: "secret.txt", data: Buffer.from("x"), method: 0, encrypted: true }]);
    expect(() => unzipZip(zip)).toThrow(/encrypted.*secret\.txt/s);
  });

  test("given an unknown compression method, when parsed, then the method is rejected", () => {
    const zip = makeZip([{ name: "b.txt", data: Buffer.from("x"), method: 12 }]);
    expect(() => unzipZip(zip)).toThrow(/compression method 12/);
  });

  test("given a CRC-corrupted entry, when parsed, then the mismatch is rejected", () => {
    const zip = makeZip([{ name: "a", data: Buffer.from("original") }]);
    const corrupted = Buffer.from(zip);
    // Corrupt one payload byte (DEFLATE stream of the first entry).
    const byte = corrupted[31] ?? 0;
    corrupted[31] = byte ^ 0xff;
    expect(() => unzipZip(corrupted)).toThrow(ZipError);
  });

  test("given an archive with more entries than the cap, when parsed, then the cap is enforced", () => {
    const many: FixtureEntry[] = [];
    // Cap is 20k; build just over it with cheap 1-byte STORED entries.
    const n = ZIP_LIMITS.maxEntries + 1;
    for (let i = 0; i < n; i++) many.push({ name: `f${i}`, data: Buffer.from("x"), method: 0 });
    expect(() => unzipZip(makeZip(many))).toThrow(/entry cap/);
  });
});

describe("isSafeZipPath: zip-slip defense", () => {
  test("given relative paths, when checked, then they are safe (incl. ./ prefixes and backslashes)", () => {
    expect(isSafeZipPath("a/b/c.js")).toBe(true);
    expect(isSafeZipPath("./a/b.js")).toBe(true);
    expect(isSafeZipPath("dir\\sub\\file.js")).toBe(true);
  });

  test("given traversal or absolute paths, when checked, then they are unsafe", () => {
    expect(isSafeZipPath("../evil.js")).toBe(false);
    expect(isSafeZipPath("a/../../evil.js")).toBe(false);
    expect(isSafeZipPath("/etc/passwd")).toBe(false);
    expect(isSafeZipPath("C:\\windows\\system32")).toBe(false);
    expect(isSafeZipPath("")).toBe(false);
    expect(isSafeZipPath("a\0b")).toBe(false);
  });
});

describe("extractZip", () => {
  test("given a zip with nested entries, when extracted, then the files land below destDir with intact content", async () => {
    const dest = await mkdtemp(join(tmpdir(), "callis-zip-"));
    try {
      const a = Buffer.from("alpha");
      const b = Buffer.from("beta");
      extractZip(
        makeZip([
          { name: "pkg/package.json", data: a },
          { name: "pkg/index.js", data: b },
        ]),
        dest,
      );
      expect(readFileSync(join(dest, "pkg", "package.json")).equals(a)).toBe(true);
      expect(readFileSync(join(dest, "pkg", "index.js")).equals(b)).toBe(true);
    } finally {
      await rm(dest, { recursive: true, force: true });
    }
  });

  test("given a zip with a directory entry, when extracted, then no file is written for the directory (parents are created)", async () => {
    const dest = await mkdtemp(join(tmpdir(), "callis-zip-"));
    try {
      extractZip(
        makeZip([
          { name: "d/", data: Buffer.alloc(0), method: 0 },
          { name: "d/file.txt", data: Buffer.from("x") },
        ]),
        dest,
      );
      expect(readFileSync(join(dest, "d", "file.txt"), "utf8")).toBe("x");
    } finally {
      await rm(dest, { recursive: true, force: true });
    }
  });

  test("given a zip with a traversal entry, when extracted, then a ZipError is thrown and NO file escapes destDir", async () => {
    const base = await mkdtemp(join(tmpdir(), "callis-zip-"));
    const dest = join(base, "dest");
    try {
      const zip = makeZip([
        { name: "safe.txt", data: Buffer.from("safe"), method: 0 },
        { name: "../evil.txt", data: Buffer.from("escape"), method: 0 },
      ]);
      expect(() => extractZip(zip, dest)).toThrow(/unsafe entry path/);
      expect(() => readFileSync(join(base, "evil.txt"), "utf8")).toThrow(); // never written
    } finally {
      await rm(base, { recursive: true, force: true });
    }
  });

  test("given a zip with an absolute entry path, when extracted, then it is rejected before any write", async () => {
    const base = await mkdtemp(join(tmpdir(), "callis-zip-"));
    const dest = join(base, "dest");
    const planted = join(base, "planted.txt");
    try {
      const zip = makeZip([{ name: "/etc/callis-escape", data: Buffer.from("x"), method: 0 }]);
      expect(() => extractZip(zip, dest)).toThrow(/unsafe entry path/);
      expect(() => readFileSync(planted, "utf8")).toThrow();
    } finally {
      await rm(base, { recursive: true, force: true });
    }
  });
});

describe("crc32Of", () => {
  test("given known vectors, when hashed, then the standard CRC-32 values are produced", () => {
    expect(crc32Of(Buffer.from(""))).toBe(0);
    expect(crc32Of(Buffer.from("123456789")).toString(16)).toBe("cbf43926");
  });
});
