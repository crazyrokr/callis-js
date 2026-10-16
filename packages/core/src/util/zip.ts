// Minimal pure-JS ZIP reader (M7c, ADR 0017): archives from the analyzed
// tree (Yarn PnP `.yarn/cache` zips) are PARSED, never executed — and every
// entry path is validated before extraction (zip-slip defense, the M9
// "archive path-traversal validation" hardening applied at the reader).
//
// Scope: non-ZIP64 archives, STORED (method 0) and DEFLATE (method 8)
// entries only. Encrypted entries, ZIP64 records, and unknown methods are
// rejected with a ZipError (clear diagnostic, no partial state).

import { mkdirSync, writeFileSync } from "node:fs";
import { isAbsolute, join, resolve, sep } from "node:path";
import { inflateRawSync } from "node:zlib";

export interface ZipEntry {
  name: string;
  data: Buffer;
}

/** Hard caps on untrusted archives (ADR 0017 resource limits). */
export const ZIP_LIMITS = {
  maxEntries: 20_000,
  maxUncompressedBytes: 512 * 1024 * 1024,
  maxNameBytes: 512,
} as const;

/** Thrown on any structural or safety violation in an archive. */
export class ZipError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ZipError";
  }
}

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;
const ZIP64 = 0xffffffff;
/** EOCD may sit up to 64 KiB (max comment length) from the end of the file. */
const EOCD_MAX_SCAN = 22 + 0xffff;

/** True when the entry name is safe to extract below `destDir`. */
export function isSafeZipPath(name: string): boolean {
  if (name === "" || name.includes("\0")) return false;
  const norm = name.replace(/\\/g, "/");
  if (isAbsolute(norm) || /^[A-Za-z]:/.test(norm)) return false;
  if (norm.split("/").some((p) => p === "..")) return false;
  return true;
}

interface CentralEntry {
  name: string;
  method: number;
  flags: number;
  compressedSize: number;
  uncompressedSize: number;
  crc32: number;
  localOffset: number;
}

function findEocd(buf: Buffer): { offset: number; entries: number; cdSize: number; cdOffset: number } {
  const floor = Math.max(0, buf.length - EOCD_MAX_SCAN);
  for (let i = buf.length - 22; i >= floor; i--) {
    if (i < 0) break;
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      const entries = buf.readUInt16LE(i + 10);
      const cdSize = buf.readUInt32LE(i + 12);
      const cdOffset = buf.readUInt32LE(i + 16);
      if (entries === 0xffff || cdSize === ZIP64 || cdOffset === ZIP64) {
        throw new ZipError("zip64 archives are not supported");
      }
      return { offset: i, entries, cdSize, cdOffset };
    }
  }
  throw new ZipError("not a zip archive (end-of-central-directory record not found)");
}

/** Parse and decompress every entry (caps and method validation included). */
export function unzipZip(buf: Buffer): ZipEntry[] {
  const eocd = findEocd(buf);
  const cdEnd = eocd.cdOffset + eocd.cdSize;
  if (cdEnd > buf.length) throw new ZipError("central directory extends past end of archive");

  const entries: ZipEntry[] = [];
  if (eocd.entries > ZIP_LIMITS.maxEntries) {
    throw new ZipError(`archive exceeds the entry cap (${eocd.entries} > ${ZIP_LIMITS.maxEntries})`);
  }
  let totalUncompressed = 0;

  let p = eocd.cdOffset;
  for (let n = 0; n < eocd.entries; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== CD_SIG) {
      throw new ZipError("corrupt central directory");
    }
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const compSize = buf.readUInt32LE(p + 20);
    const uncompSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString("utf8");

    if (nameLen > ZIP_LIMITS.maxNameBytes) throw new ZipError(`entry name exceeds the name cap: ${name}`);
    if (compSize === ZIP64 || uncompSize === ZIP64) {
      throw new ZipError(`zip64 sizes are not supported (entry ${name})`);
    }
    if (flags & 0x1) throw new ZipError(`encrypted entry is not supported: ${name}`);
    if (method !== 0 && method !== 8) {
      throw new ZipError(`unsupported compression method ${method} (entry ${name})`);
    }
    totalUncompressed += uncompSize;
    if (totalUncompressed > ZIP_LIMITS.maxUncompressedBytes) {
      throw new ZipError(`archive exceeds the size cap (${totalUncompressed} bytes uncompressed)`);
    }

    if (localOffset + 30 > buf.length || buf.readUInt32LE(localOffset) !== LOCAL_SIG) {
      throw new ZipError(`corrupt local header (entry ${name})`);
    }
    const localNameLen = buf.readUInt16LE(localOffset + 26);
    const localExtraLen = buf.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
    const raw = buf.subarray(dataStart, dataStart + compSize);
    if (dataStart + compSize > buf.length) {
      throw new ZipError(`truncated entry data (entry ${name})`);
    }
    let data: Buffer;
    try {
      data = method === 8 ? inflateRawSync(raw) : Buffer.from(raw);
    } catch {
      throw new ZipError(`corrupt deflate stream (entry ${name})`);
    }
    if (method === 8 && data.length !== uncompSize) {
      throw new ZipError(`deflate size mismatch (entry ${name})`);
    }
    if (crc32Of(data) !== crc) {
      throw new ZipError(`crc mismatch (entry ${name})`);
    }
    entries.push({ name, data });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

/**
 * Extract an archive below `destDir` (created as needed). Every entry is
 * path-validated (zip-slip: no absolute paths, no `..` segments) and the
 * resolved target is re-checked against `destDir` before writing.
 */
export function extractZip(buf: Buffer, destDir: string): void {
  const base = resolve(destDir);
  const entries = unzipZip(buf);
  for (const entry of entries) {
    const norm = entry.name.replace(/\\/g, "/");
    if (norm.endsWith("/") || norm === "") continue; // directory entries
    if (!isSafeZipPath(entry.name)) {
      throw new ZipError(`unsafe entry path (traversal or absolute): ${entry.name}`);
    }
    const target = join(base, norm);
    if (target !== base && !target.startsWith(base + sep)) {
      throw new ZipError(`entry escapes the extraction directory: ${entry.name}`);
    }
    mkdirSync(resolve(target, ".."), { recursive: true });
    writeFileSync(target, entry.data);
  }
}

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32Of(data: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    const idx = (c ^ (data[i] ?? 0)) & 0xff;
    c = (CRC_TABLE[idx] ?? 0) ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}
