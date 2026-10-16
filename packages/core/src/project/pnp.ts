// M7c — Yarn PnP layout adapter (ADR 0005 profile (c), ADRs 0014/0017).
//
// Data-driven, NO EXECUTION: a project's `.pnp.cjs` is a generated artifact
// of the analyzed tree and a layout MARKER ONLY (ADR 0017: node_modules and
// its siblings are parsed, never executed). The sources of truth are:
//   - `.yarn/install-state.gz`  — name@version → cache zip folderName
//   - `yarn.lock`               — the resolved dependency graph (1b)
//   - `.yarn/cache/*.zip`       — package sources (extracted once, below)
//
// Zip extraction follows the archive rule: each archive is extracted FULLY,
// ONCE, content-addressed (the extraction path is a deterministic function
// of the zip content); the recorded path is reused for all later needs —
// never re-extracted.

import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { UsageError } from "../util/errors.js";
import { sha256File, sha256Hex } from "../util/hash.js";
import { ZipError, extractZip } from "../util/zip.js";

export interface PnpPackageLocator {
  name: string;
  version: string;
  /** Basename of the package archive inside a yarn cache. */
  folderName: string;
  checksum?: string | undefined;
}

export interface InstallState {
  entries: PnpPackageLocator[];
  /** sha256 of the raw install-state.gz bytes (fingerprint input). */
  checksum: string;
}

/** Default global yarn cache (Yarn 3/4 default; `YARN_GLOBAL_FOLDER` overrides). */
export function defaultGlobalCacheDir(): string {
  const env = process.env.YARN_GLOBAL_FOLDER;
  if (env !== undefined && env.length > 0) return join(env, "cache");
  return join(homedir(), ".yarn", "berry", "cache");
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

/**
 * Read `.yarn/install-state.gz` (a gzipped JSON array of per-package
 * records). Returns null when the file is absent (a degraded PnP install —
 * the caller refuses with a `yarn install` hint). Tolerant to format drift:
 * the package identity comes from `packageManifest` or `pattern`, and
 * records without a usable identity are skipped. A CORRUPT file is a
 * UsageError (exit 2): the install state is environment configuration, and
 * a broken install cannot be analyzed soundly.
 */
export function readInstallState(root: string): InstallState | null {
  const file = join(root, ".yarn", "install-state.gz");
  let raw: Buffer;
  try {
    raw = readFileSync(file);
  } catch {
    return null;
  }
  let text: string;
  try {
    text = gunzipSync(raw).toString("utf8");
  } catch {
    throw new UsageError(
      "yarn install state is corrupt (.yarn/install-state.gz is not a valid gzip) — re-run `yarn install`",
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new UsageError(
      "yarn install state is corrupt (.yarn/install-state.gz is not valid JSON) — re-run `yarn install`",
    );
  }
  if (!Array.isArray(parsed)) {
    throw new UsageError("yarn install state is malformed (expected a JSON array) — re-run `yarn install`");
  }
  const entries: PnpPackageLocator[] = [];
  for (const record of parsed) {
    if (!isObj(record)) continue;
    const folderName = str(record.folderName);
    if (folderName === null) continue;
    const manifest = isObj(record.packageManifest) ? record.packageManifest : null;
    const pattern = isObj(record.pattern) ? record.pattern : null;
    const name = str(manifest?.name) ?? str(pattern?.name);
    const version = str(manifest?.version) ?? str(pattern?.version);
    if (name === null || version === null) continue;
    entries.push({ name, version, folderName, checksum: str(record.checksum) ?? undefined });
  }
  return { entries, checksum: sha256Hex(raw) };
}

/**
 * Locate a locator's archive: the project-local cache first, then the global
 * cache. null when absent from both (the instance then resolves as MISSING —
 * an honest gap, not an error).
 */
export function findPnpZip(root: string, folderName: string, opts: { globalCacheDir?: string } = {}): string | null {
  const dirs = [join(root, ".yarn", "cache"), opts.globalCacheDir ?? defaultGlobalCacheDir()];
  for (const dir of dirs) {
    const candidate = join(dir, folderName);
    try {
      if (existsSync(candidate)) return candidate;
    } catch {
      // Unreadable cache directory — try the next candidate.
    }
  }
  return null;
}

/**
 * Extract a yarn cache zip fully and once, content-addressed:
 * `<cacheDir>/pnp/<sha256(zip)>/<name>@<version>/…`. The tree is built in a
 * sibling temp dir and renamed into place with a manifest written LAST, so a
 * crashed extraction never leaves a partial tree that could be reused. An
 * existing extraction with a matching manifest is reused as-is (no
 * re-extraction, even if the zip file moved or changed mtime — content
 * decides).
 */
export function ensurePnpExtracted(zipPath: string, locator: PnpPackageLocator, cacheDir: string): string {
  const zipHash = sha256File(zipPath);
  const bucket = join(cacheDir, "pnp", zipHash);
  const dest = join(bucket, `${locator.name}@${locator.version}`);
  const manifestPath = join(dest, ".callis-extracted.json");
  if (existsSync(manifestPath)) {
    try {
      const m = JSON.parse(readFileSync(manifestPath, "utf8")) as { zipHash?: string };
      if (m.zipHash === zipHash) return dest;
    } catch {
      // Stale or corrupt manifest — re-extract below.
    }
  }
  const zipContent = readFileSync(zipPath);
  const tmp = join(bucket, `.extracting-${locator.name}@${locator.version}`);
  rmSync(tmp, { recursive: true, force: true });
  mkdirSync(bucket, { recursive: true });
  try {
    extractZip(zipContent, tmp);
    writeJson(manifestAt(tmp), { zipHash, name: locator.name, version: locator.version });
  } catch (e) {
    // No half-built state may survive a failed extraction (the bucket holds
    // only this temp tree at this point — the content-addressed dir of a
    // different zip cannot share it).
    rmSync(bucket, { recursive: true, force: true });
    throw e instanceof ZipError ? e : new ZipError(`failed to extract ${locator.folderName}`);
  }
  rmSync(dest, { recursive: true, force: true });
  renameSync(tmp, dest);
  return dest;
}

function manifestAt(extractRoot: string): string {
  return join(extractRoot, ".callis-extracted.json");
}

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, JSON.stringify(value));
}
