// Project scan: install layout, package instances, app-vs-library, workspaces
// (plan section 5.3, ADR 0005, ADR 0014).
//
// npm / Bun / Yarn(node-modules) share the node_modules walk; pnpm adds the
// .pnpm virtual store (symlinked); Yarn PnP (M7c) builds a data-driven model
// from install-state + yarn.lock + cache zips — never executing `.pnp.cjs`
// (ADR 0017).

import { lstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { join, relative } from "node:path";
import { UsageError } from "../util/errors.js";
import { buildPnpModel } from "./pnp.js";
import type { Layout, PackageInstance, ProjectModel, Workspace } from "./types.js";

export interface PkgJson {
  name?: string;
  version?: string;
  type?: string;
  main?: string;
  bin?: string;
  exports?: unknown;
  imports?: unknown;
  workspaces?: unknown;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
  [key: string]: unknown;
}

/** Read + parse a package.json; null when absent or unparseable. */
export function readPkgJson(dir: string): PkgJson | null {
  try {
    return JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as PkgJson;
  } catch {
    return null;
  }
}

function isDirectory(path: string): boolean {
  try {
    return lstatSync(path).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Detect the install layout from the project root: pnp (`.pnp.cjs` marker, or
 * a berry yarn.lock with a .yarn/ dir), pnpm (.pnpm store), or npm-style
 * node_modules. Like `findInstallRoot`, the check walks up (bounded, 4
 * levels) so a monorepo subpackage finds the install at its repo root.
 */
export function detectLayout(root: string): Layout {
  let dir = root;
  for (let depth = 0; depth <= 4; depth += 1) {
    if (isDirectory(join(dir, "node_modules", ".pnpm"))) return "pnpm";
    if (exists(join(dir, ".pnp.cjs")) || exists(join(dir, ".pnp.js"))) return "pnp";
    if (isDirectory(join(dir, "node_modules"))) return "npm";
    // Secondary PnP marker: a berry lockfile next to a .yarn/ dir, with no
    // node_modules here (a `nodeLinker: node-modules` install scans npm).
    if (exists(join(dir, "yarn.lock")) && isDirectory(join(dir, ".yarn"))) return "pnp";
    const parent = join(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  // A lockfile alone still tells us which layout to expect.
  const lock = lockfileNameAt(root);
  if (lock === "pnpm-lock.yaml") return "pnpm";
  if (lock === "bun.lock" || lock === "bun.lockb") return "npm";
  return "unknown";
}

function exists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

function lockfileNameAt(root: string): string | null {
  for (const name of ["package-lock.json", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "yarn.lock"]) {
    if (exists(join(root, name))) return name;
  }
  return null;
}

/**
 * The install root: the nearest ancestor of the project root (the root itself
 * included) that carries a lockfile or a node_modules directory. Monorepo
 * subfolders find their hoisted dependencies there; the walk is bounded so an
 * unrelated node_modules higher up the tree is never picked up.
 */
export function findInstallRoot(root: string): string {
  let dir = root;
  for (let depth = 0; depth <= 4; depth += 1) {
    if (lockfileNameAt(dir) !== null || isDirectory(join(dir, "node_modules"))) return dir;
    const parent = join(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  return root;
}

/**
 * The node_modules directories to scan: one per level from the project root up
 * to (and including) the install root — npm hoisting (a monorepo subfolder
 * resolves dependencies at the repo root).
 */
export function scanLevels(root: string, installRoot: string): string[] {
  const levels: string[] = [];
  let dir = root;
  for (;;) {
    const nm = join(dir, "node_modules");
    if (isDirectory(nm)) levels.push(nm);
    if (dir === installRoot) break;
    const parent = join(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  return levels;
}

/**
 * App-vs-library rule (plan v2): a file is *library* when its realpath is under
 * a node_modules/ directory or the pnpm store; symlinks resolve first, so
 * pnpm's top-level links classify correctly with no special case.
 */
export function isLibraryPath(realPath: string): boolean {
  const parts = realPath.split(/[/\\]/);
  return parts.includes("node_modules") || parts.includes(".pnpm");
}

interface RawInstance {
  dir: string;
  realDir: string;
  relPath: string;
  name: string;
  version: string;
  parent: { name: string; version: string } | null;
  pkgJson: PkgJson;
}

function realPathSafe(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

/** One node_modules level -> raw instances (deduplicated by realpath below). */
function scanLevel(nmDir: string, root: string): RawInstance[] {
  const out: RawInstance[] = [];
  const walk = (dir: string, parent: { name: string; version: string } | null): void => {
    let entries: { name: string; isDirectory(): boolean; isSymbolicLink(): boolean }[] = [];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
      if (entry.name === ".pnpm" || entry.name === ".cache" || entry.name === ".vite") continue;
      const full = join(dir, entry.name);
      let pkg = readPkgJson(full);
      if (pkg === null && entry.isSymbolicLink()) {
        // pnpm top-level link: the package.json may only exist at the target.
        const resolved = realPathSafe(full);
        pkg = readPkgJson(resolved);
        if (pkg !== null) {
          const raw = toRaw(full, resolved, root, pkg, parent);
          if (raw !== null) out.push(raw);
          continue;
        }
        continue;
      }
      if (pkg === null) {
        if (entry.name.startsWith("@") && entry.isDirectory()) {
          walk(full, parent);
        }
        continue;
      }
      const raw = toRaw(full, realPathSafe(full), root, pkg, parent);
      if (raw !== null) out.push(raw);
      // A package can host its own nested node_modules (a's private copy of a
      // dependency): recurse with this package as the parent. Symlinked
      // entries are not walked — their store targets are scanned separately.
      if (!entry.isSymbolicLink() && isDirectory(join(full, "node_modules"))) {
        walk(join(full, "node_modules"), raw !== null ? { name: raw.name, version: raw.version } : parent);
      }
    }
  };
  walk(nmDir, null);

  function toRaw(
    dir: string,
    realDir: string,
    root: string,
    pkg: PkgJson,
    parent: { name: string; version: string } | null,
  ): RawInstance | null {
    if (typeof pkg.name !== "string" || pkg.name.length === 0) return null;
    const version = typeof pkg.version === "string" && pkg.version.length > 0 ? pkg.version : "";
    if (version.length === 0) return null;
    return { dir, realDir, relPath: relative(root, realDir), name: pkg.name, version, parent, pkgJson: pkg };
  }

  return out;
}

/** pnpm virtual store: .pnpm/<id>/node_modules/<name> (symlinked entries). */
function scanPnpmStore(nmDir: string, root: string): RawInstance[] {
  const out: RawInstance[] = [];
  const store = join(nmDir, ".pnpm");
  let entries: { name: string; isDirectory(): boolean; isSymbolicLink(): boolean }[] = [];
  try {
    entries = readdirSync(store, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const idDir = join(store, entry.name);
    const inner = join(idDir, "node_modules");
    const innerEntries = safeReaddir(inner);
    for (const innerEntry of innerEntries) {
      if (innerEntry.name.startsWith("@") && innerEntry.isDirectory()) {
        for (const sub of safeReaddir(join(inner, innerEntry.name))) {
          pushStoreEntry(join(inner, innerEntry.name, sub.name), root, out);
        }
      } else {
        pushStoreEntry(join(inner, innerEntry.name), root, out);
      }
    }
  }
  return out;

  function pushStoreEntry(dir: string, root: string, out: RawInstance[]): void {
    const resolved = realPathSafe(dir);
    const pkg = readPkgJson(resolved);
    if (pkg === null || typeof pkg.name !== "string" || typeof pkg.version !== "string" || pkg.version.length === 0)
      return;
    // Store entries are virtual-store roots; the dependency graph between them
    // comes from the lockfile graph, not a parent pointer.
    out.push({
      dir,
      realDir: resolved,
      relPath: relative(root, resolved),
      name: pkg.name,
      version: pkg.version,
      parent: null,
      pkgJson: pkg,
    });
  }
}

/**
 * .pnpm id -> {name, version}. `@scope+name@1.2.3` (scoped: + becomes /) and
 * the peer-suffix form `name@ver_peer@peerver` (the suffix after the first `_`
 * is dropped).
 */
export function decodePnpmId(id: string): { name: string; version: string } | null {
  const head = id.split("_")[0] ?? id;
  const at = head.lastIndexOf("@");
  if (at <= 0) return null;
  const name = head.slice(0, at).replace("+", "/");
  const version = head.slice(at + 1);
  if (name.length === 0 || version.length === 0) return null;
  return { name, version };
}

function safeReaddir(dir: string): { name: string; isDirectory(): boolean }[] {
  try {
    return readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

function dedupeByRealDir(raw: RawInstance[]): PackageInstance[] {
  const seen = new Map<string, PackageInstance>();
  for (const r of raw) {
    if (seen.has(r.realDir)) continue;
    const parent = r.parent === null ? null : { name: r.parent.name, version: r.parent.version };
    const instance: PackageInstance = {
      name: r.name,
      version: r.version,
      realDir: r.realDir,
      relPath: r.relPath,
      library: isLibraryPath(r.realDir),
      parent,
      pkgType: r.pkgJson.type === "module" ? "module" : "commonjs",
    };
    if (typeof r.pkgJson.main === "string") instance.main = r.pkgJson.main;
    if (r.pkgJson.bin !== undefined) instance.bin = r.pkgJson.bin;
    seen.set(r.realDir, instance);
  }
  const out = [...seen.values()];
  out.sort((a, b) => (a.relPath < b.relPath ? -1 : a.relPath > b.relPath ? 1 : 0));
  return out;
}

/** Workspace packages (application code): npm/Bun workspaces, pnpm-workspace.yaml. */
export function detectWorkspaces(root: string, layout: Layout): Workspace[] {
  const out: Workspace[] = [];
  const add = (dir: string): void => {
    const full = join(root, dir);
    const pkg = readPkgJson(full);
    if (pkg !== null && typeof pkg.name === "string" && pkg.name.length > 0) {
      out.push({ dir: full, name: pkg.name });
    }
  };
  const rootPkg = readPkgJson(root);
  if (rootPkg !== null && Array.isArray(rootPkg.workspaces)) {
    for (const pattern of rootPkg.workspaces) {
      if (typeof pattern === "string") for (const dir of expandGlob(pattern, root)) add(dir);
      else if (
        typeof pattern === "object" &&
        pattern !== null &&
        Array.isArray((pattern as { packages?: unknown }).packages)
      ) {
        for (const p of (pattern as { packages: unknown[] }).packages) {
          if (typeof p === "string") for (const dir of expandGlob(p, root)) add(dir);
        }
      }
    }
  }
  if (layout === "pnpm") {
    for (const pattern of pnpmWorkspaceDirs(root)) {
      for (const dir of expandGlob(pattern, root)) add(dir);
    }
  }
  // The root package itself is application code (even with workspaces);
  // deduplicated by directory.
  if (rootPkg !== null) {
    const name = typeof rootPkg.name === "string" ? rootPkg.name : "";
    if (name.length > 0 && !out.some((w) => w.dir === root)) out.unshift({ dir: root, name });
  }
  return out;
}

/** `packages/*` style glob (one `*` segment only — the common shape). */
function expandGlob(pattern: string, root: string): string[] {
  const star = pattern.indexOf("*");
  if (star < 0) return [pattern];
  const base = join(root, pattern.slice(0, star));
  const suffix = pattern.slice(star + 1).replace(/^\//, "");
  let entries: string[];
  try {
    entries = readdirSync(base);
  } catch {
    return [];
  }
  const out: string[] = [];
  const baseRel = pattern.slice(0, star);
  for (const entry of entries) {
    const candidate = suffix === "" ? join(base, entry) : join(base, entry, suffix);
    if (readPkgJson(candidate) !== null) out.push(join(baseRel, entry, suffix));
  }
  return out;
}

/** Minimal pnpm-workspace.yaml reader: the `packages:` list (no anchors). */
function pnpmWorkspaceDirs(root: string): string[] {
  const file = join(root, "pnpm-workspace.yaml");
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    return [];
  }
  const dirs: string[] = [];
  let inPackages = false;
  for (const line of text.split("\n")) {
    const trimmed = line.replace(/\r$/, "");
    if (/^packages:\s*$/.test(trimmed)) {
      inPackages = true;
      continue;
    }
    if (inPackages) {
      const m = /^(\s+)-\s+(.+?)\s*$/.exec(trimmed);
      if (m !== null) {
        const value = (m[2] ?? "").replace(/^["']|["']$/g, "");
        if (value.length > 0) dirs.push(value);
        continue;
      }
      if (trimmed.length > 0 && !/^\s*-/.test(trimmed)) inPackages = false;
    }
  }
  return dirs;
}

export interface ProjectModelOptions {
  /** Callis cache dir (PnP zip extraction root; defaults to the CLI default). */
  cacheDir?: string;
  /** Global yarn cache override (PnP only). */
  globalCacheDir?: string;
}

/** Default callis cache dir (CLI parity: `$XDG_CACHE_HOME/callis`, else `~/.cache/callis`). */
function defaultCacheDir(): string {
  const xdg = process.env.XDG_CACHE_HOME;
  const base = xdg !== undefined && xdg.length > 0 ? xdg : join(homedir(), ".cache");
  return join(base, "callis");
}

/**
 * Build the project model. Yarn PnP (M7c) builds the data-driven model from
 * install-state + yarn.lock + cache zips (a degraded install without either
 * install state AND zips is a UsageError with a `yarn install` hint).
 */
export function buildProjectModel(root: string, opts: ProjectModelOptions = {}): ProjectModel {
  const layout = detectLayout(root);
  if (layout === "pnp") {
    return buildPnpModel(root, {
      cacheDir: opts.cacheDir ?? defaultCacheDir(),
      ...(opts.globalCacheDir !== undefined ? { globalCacheDir: opts.globalCacheDir } : {}),
    });
  }
  const installRoot = findInstallRoot(root);
  const scannedDirs = scanLevels(root, installRoot);
  const raw: RawInstance[] = [];
  for (const nmDir of scannedDirs) {
    raw.push(...scanLevel(nmDir, root));
    if (layout === "pnpm") raw.push(...scanPnpmStore(nmDir, root));
  }
  return {
    root,
    layout: layout === "unknown" ? "npm" : layout,
    workspaces: detectWorkspaces(root, layout),
    instances: dedupeByRealDir(raw),
    scannedDirs,
    installRoot,
  };
}
