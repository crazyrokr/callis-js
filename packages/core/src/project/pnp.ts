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

import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, relative, resolve } from "node:path";
import { gunzipSync } from "node:zlib";
import { UsageError } from "../util/errors.js";
import { sha256File, sha256Hex } from "../util/hash.js";
import { type ZipEntry, ZipError, extractZip, unzipZip } from "../util/zip.js";
import { type PkgJson, detectWorkspaces, findInstallRoot, readPkgJson } from "./scan.js";
import type { PackageInstance, PnpContext, ProjectModel } from "./types.js";
import { normalizeDescriptor, parseYarnLockFile } from "./yarnlock.js";

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
 * Read `.yarn/install-state.gz`. Returns null when the file is absent OR in
 * a format we do not decode (the caller then falls back to the cache zips;
 * with neither, it refuses with a `yarn install` hint).
 *
 * Format drift is real: Yarn 2/3 wrote a gzipped JSON array of per-package
 * records (decoded here; identity from `packageManifest` or `pattern`,
 * records without a usable identity skipped). Yarn 4.x (observed 4.18)
 * writes a BINARY serialization instead — content that does not look like
 * JSON is treated as "present but undecodable" (null), not corrupt. A
 * CORRUPT file (broken gzip, or JSON-looking content that fails to parse)
 * is a UsageError (exit 2): the install state is environment configuration,
 * and a broken install cannot be analyzed soundly.
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
  // Not JSON-shaped: a non-JSON format (e.g. the Yarn 4.x binary
  // serialization) — present, but undecodable here.
  if (!text.startsWith("[") && !text.startsWith("{")) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new UsageError(
      "yarn install state is corrupt (.yarn/install-state.gz is not valid JSON) — re-run `yarn install`",
    );
  }
  if (!Array.isArray(parsed)) {
    // JSON, but not the array-of-records shape: a format we do not decode.
    return null;
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

export interface PnpModelOptions {
  /** Content-addressed extraction root (the callis cache dir). */
  cacheDir: string;
  /** Global yarn cache override (defaults to `defaultGlobalCacheDir()`). */
  globalCacheDir?: string;
}

/**
 * Build the project model for a Yarn PnP install (M7c, ADR 0005 profile (c)):
 * zip packages from the install state — extracted fully, once,
 * content-addressed — as library instances, plus the workspace projects as
 * application instances. `scannedDirs` is just the root (there is no
 * node_modules to walk). A degraded install (no install state AND no zips)
 * is a UsageError with a `yarn install` hint (exit 2).
 *
 * (Imports `detectWorkspaces`/`readPkgJson`/`findInstallRoot` from scan.ts,
 * which imports this module's `buildPnpModel` back — a cycle that is safe
 * because both sides only use the other's hoisted function declarations at
 * call time, never at module load.)
 *
 * The extraction dir becomes `instance.realDir`, so the cache dirs are made
 * ABSOLUTE here: the `--project` and `--cache-dir` arguments may be relative
 * (the e2e gate passes both relative, with the cache dir INSIDE the project
 * tree), and downstream path comparisons (the tie graph, instance
 * attribution of loaded files) must not depend on that shape.
 */
export function buildPnpModel(root: string, opts: PnpModelOptions): ProjectModel {
  const cacheDir = resolve(opts.cacheDir);
  const globalCacheDir = opts.globalCacheDir !== undefined ? resolve(opts.globalCacheDir) : defaultGlobalCacheDir();
  const state = readInstallState(root);
  let locators: PnpPackageLocator[];
  if (state !== null) {
    locators = state.entries;
  } else {
    // Degraded install: no install state, but the cache zips still name
    // their packages (each zip carries its own package.json).
    locators = locatorsFromCacheZips(root, { cacheDir, globalCacheDir });
    if (locators.length === 0) {
      throw new UsageError(
        "Yarn PnP install state not found (.yarn/install-state.gz is missing and .yarn/cache holds no zips) — run `yarn install`",
      );
    }
  }

  const entries = parseYarnLockFile(root) ?? [];
  const canonical = new Map<string, string>();
  for (const e of entries) {
    if (e.protocol === "workspace" || e.version === "") continue;
    const key = `${e.name}@${e.version}`;
    for (const d of e.descriptors) {
      const n = normalizeDescriptor(d);
      if (!canonical.has(n)) canonical.set(n, key);
    }
  }

  const byLocator = new Map<string, string>();
  const instances: PackageInstance[] = [];
  const seen = new Set<string>();
  for (const loc of locators) {
    const key = `${loc.name}@${loc.version}`;
    if (seen.has(key)) continue; // one instance per name@version (first record wins)
    seen.add(key);
    const zip = findPnpZip(root, loc.folderName, { globalCacheDir });
    if (zip === null) continue; // no source anywhere: the component is MISSING, not an error
    let entries: ZipEntry[];
    try {
      entries = unzipZip(readFileSync(zip));
    } catch {
      continue; // unreadable or corrupt archive: missing-eligible
    }
    const dir = ensurePnpExtracted(zip, loc, cacheDir);
    const pkgDir = packageRootOf(entries, dir);
    if (pkgDir === null) continue;
    const pkg = readPkgJson(pkgDir);
    if (pkg === null || typeof pkg.name !== "string" || pkg.name.length === 0) continue;
    byLocator.set(key, pkgDir);
    const instance: PackageInstance = {
      name: pkg.name,
      version: typeof pkg.version === "string" && pkg.version.length > 0 ? pkg.version : loc.version,
      realDir: pkgDir,
      relPath: relative(root, pkgDir),
      library: true,
      parent: null,
      pkgType: pkg.type === "module" ? "module" : "commonjs",
    };
    if (typeof pkg.main === "string") instance.main = pkg.main;
    if (pkg.bin !== undefined) instance.bin = pkg.bin;
    instances.push(instance);
  }
  // Deterministic order (the extraction dir is content-addressed, so path
  // order would be hash order): by name@version, then by dir.
  instances.sort((a, b) => {
    const ka = `${a.name}@${a.version}`;
    const kb = `${b.name}@${b.version}`;
    if (ka !== kb) return ka < kb ? -1 : 1;
    return a.realDir < b.realDir ? -1 : a.realDir > b.realDir ? 1 : 0;
  });

  const workspaces = detectWorkspaces(root, "pnp");
  const pnp: PnpContext = {
    byLocator,
    canonical,
    workspaceDirs: workspaces.map((w) => w.dir),
  };
  return {
    root,
    layout: "pnp",
    workspaces,
    instances,
    scannedDirs: [root],
    installRoot: findInstallRoot(root),
    pnp,
  };
}

/**
 * The package directory inside an extracted yarn cache zip:
 * - a flat archive (package.json at the root) → the root itself;
 * - the yarn layout (the package stored at `node_modules/<name>/…`) → that
 *   package dir (exactly one level under node_modules).
 * null when no manifest is found (the locator is then skipped).
 */
function packageRootOf(entries: ZipEntry[], dest: string): string | null {
  const names = entries.map((e) => (e.name.startsWith("./") ? e.name.slice(2) : e.name));
  if (names.includes("package.json")) return dest;
  const dirs = new Set<string>();
  for (const n of names) {
    const parts = n.split("/");
    if (parts.length === 3 && parts[0] === "node_modules" && parts[2] === "package.json") {
      const name = parts[1];
      if (name !== undefined && name.length > 0) dirs.add(join(dest, "node_modules", name));
    }
  }
  for (const dir of [...dirs].sort()) {
    const pkg = readPkgJson(dir);
    if (pkg !== null && typeof pkg.name === "string" && pkg.name.length > 0) return dir;
  }
  return null;
}

/**
 * Zip-derived locators (the path for installs whose install state is absent
 * or in a format we do not decode — e.g. the Yarn 4.x binary form): each
 * cache zip's top-level package.json names the package. Zips without a
 * parseable identity (or unreadable archives) are skipped; the folderName is
 * the cache basename. When a yarn.lock is present, only zips whose
 * name@version the lockfile lists are kept (a cache may hold STALE zips from
 * earlier installs — the lockfile is the source of truth for the installed
 * set). The project-local cache is scanned before the global one: this
 * project's own zips win, and the global cache (which holds zips of other
 * projects) only fills gaps. Deterministic (folderNames sorted per cache).
 */
function locatorsFromCacheZips(root: string, opts: PnpModelOptions): PnpPackageLocator[] {
  const entries = parseYarnLockFile(root);
  const lockVersions = new Set<string>();
  for (const e of entries ?? []) {
    if (e.protocol === "workspace" || e.version === "") continue;
    lockVersions.add(`${e.name}@${e.version}`);
  }
  const hasLock = (entries ?? []).length > 0;
  const out: PnpPackageLocator[] = [];
  const covered = new Set<string>();
  // Two passes: the project-local cache FIRST (this project's own install
  // wins), then the global cache (the fallback for installs that stored
  // their zips there). A global zip never covers a name@version the local
  // cache already provides — the global cache holds zips of OTHER projects.
  const cacheDirs = [join(root, ".yarn", "cache"), opts.globalCacheDir ?? defaultGlobalCacheDir()];
  for (const cacheDir of cacheDirs) {
    let names: string[];
    try {
      names = readdirSync(cacheDir);
    } catch {
      continue;
    }
    const folderNames = names.filter((n) => n.endsWith(".zip")).sort();
    for (const folderName of folderNames) {
      const identity = zipIdentity(join(cacheDir, folderName));
      if (identity === null) continue;
      const key = `${identity.name}@${identity.version}`;
      if (hasLock && !lockVersions.has(key)) continue; // stale zip: not in the lockfile
      if (covered.has(key)) continue;
      covered.add(key);
      out.push({ name: identity.name, version: identity.version, folderName });
    }
  }
  return out;
}

/** A zip's package identity from its top-level (or yarn-layout) package.json; null if unreadable. */
function zipIdentity(zipPath: string): { name: string; version: string } | null {
  try {
    const entries = unzipZip(readFileSync(zipPath));
    const manifest =
      entries.find((e) => e.name === "package.json") ??
      entries.find((e) => {
        const parts = e.name.split("/");
        return parts.length === 3 && parts[0] === "node_modules" && parts[2] === "package.json";
      });
    if (manifest === undefined) return null;
    const doc = JSON.parse(manifest.data.toString("utf8")) as { name?: unknown; version?: unknown };
    const name = typeof doc.name === "string" && doc.name.length > 0 ? doc.name : null;
    const version = typeof doc.version === "string" && doc.version.length > 0 ? doc.version : null;
    if (name === null || version === null) return null;
    return { name, version };
  } catch {
    return null; // unreadable or not a zip
  }
}
