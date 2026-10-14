// Runtime module resolution profile (plan section 5.3 item 4, ADR 0005).
//
// Own resolver, not Bun.resolveSync: verdicts must be deterministic and
// runtime-independent. Node semantics — conditional exports (condition
// ordering matters, nested conditions), package self-references, `#` imports,
// main/index, extension probing with the type field, workspaces, symlink
// realpaths — and NO tsconfig paths at runtime: a TS alias that does not
// runtime-resolve must not invent a production call edge. Profile b2 (app-code
// aliases with a detected runtime mechanism) is a separate, marked profile.

import { readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, posix, resolve as resolvePath, sep } from "node:path";
import { type PkgJson, readPkgJson } from "./scan.js";
import type { ProjectModel, ResolutionDecision } from "./types.js";

const PROBE_EXTENSIONS = [".mjs", ".cjs", ".mts", ".cts", ".js", ".ts"] as const;

/** Node core modules (v3.5 item 2): resolved as builtin, never "unresolved". */
export const BUILTIN_MODULES = [
  "assert",
  "async_hooks",
  "buffer",
  "child_process",
  "cluster",
  "console",
  "constants",
  "crypto",
  "dgram",
  "diagnostics_channel",
  "dns",
  "domain",
  "events",
  "fs",
  "http",
  "http2",
  "https",
  "inspector",
  "module",
  "net",
  "os",
  "path",
  "path/posix",
  "path/win32",
  "perf_hooks",
  "process",
  "punycode",
  "querystring",
  "readline",
  "repl",
  "stream",
  "string_decoder",
  "sys",
  "timers",
  "tls",
  "trace_events",
  "tty",
  "url",
  "util",
  "v8",
  "vm",
  "wasi",
  "worker_threads",
  "zlib",
] as const;

function isBuiltin(spec: string): boolean {
  if (spec.startsWith("node:")) return true;
  const bare = spec.replace(/^node:/, "");
  return (BUILTIN_MODULES as readonly string[]).includes(bare);
}

/** The nearest package root at or above dir (its package.json). */
export function nearestPackageDir(dir: string, limit: string): { dir: string; pkg: PkgJson } | null {
  let cur = dir;
  for (;;) {
    const pkg = readPkgJson(cur);
    if (pkg !== null && typeof pkg.name === "string" && pkg.name.length > 0) {
      return { dir: cur, pkg };
    }
    if (cur === limit) break;
    const parent = join(cur, "..");
    if (parent === cur) break;
    cur = parent;
  }
  return null;
}

function fileExists(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function dirExists(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Extension probing for a module specifier that is a file path:
 * try the exact path, then each extension, then directory index files.
 * Returns the resolved file or null.
 */
export function probeFile(base: string): string | null {
  if (fileExists(base)) return base;
  for (const ext of PROBE_EXTENSIONS) {
    const candidate = base + ext;
    if (fileExists(candidate)) return candidate;
  }
  for (const ext of PROBE_EXTENSIONS) {
    const candidate = join(base, `index${ext}`);
    if (fileExists(candidate)) return candidate;
  }
  return null;
}

/** Module format from file extension + nearest package "type" field. */
export function moduleFormatOf(file: string): "cjs" | "esm" | "unknown" {
  if (file.endsWith(".mjs") || file.endsWith(".mts")) return "esm";
  if (file.endsWith(".cjs") || file.endsWith(".cts")) return "cjs";
  if (file.endsWith(".js")) {
    const pkgDir = nearestPackageDir(dirOf(file), dirOf(file));
    if (pkgDir !== null && pkgDir.pkg.type === "module") return "esm";
    return "cjs";
  }
  if (file.endsWith(".ts")) return "esm";
  return "unknown";
}

function dirOf(file: string): string {
  const i = file.lastIndexOf(sep);
  return i > 0 ? file.slice(0, i) : ".";
}

interface Ctx {
  model: ProjectModel;
  /** require or import (the "require"/"import" export conditions). */
  format: "require" | "import";
  /** Profile b2: tsconfig aliases for app code with a detected mechanism. */
  allowTsconfigAliases: boolean;
}

/**
 * Resolve a module specifier from a directory. The decision records the
 * candidates tried and the reason (ADR 0005); unresolved stays unresolved —
 * never a silent fallback to a convenient file.
 */
export function resolveSpecifier(
  spec: string,
  fromDir: string,
  model: ProjectModel,
  options: { format?: "require" | "import"; allowTsconfigAliases?: boolean } = {},
): ResolutionDecision {
  const ctx: Ctx = {
    model,
    format: options.format ?? "require",
    allowTsconfigAliases: options.allowTsconfigAliases ?? false,
  };
  const base = { spec, fromDir, candidates: [] as string[] };

  if (isBuiltin(spec)) {
    return { ...base, status: "builtin", moduleFormat: "unknown", reason: "node builtin" };
  }

  if (spec.startsWith("./") || spec.startsWith("../") || isAbsolute(spec)) {
    const resolved = resolveRelative(spec, fromDir, ctx, base);
    if (resolved !== null) return resolved;
    return { ...base, status: "unresolved", moduleFormat: "unknown", reason: "relative path not found" };
  }

  // Bare specifier: `#` subpath imports, self-references, node_modules.
  if (spec.startsWith("#")) {
    const fromPkg = nearestPackageDir(fromDir, model.root);
    if (fromPkg !== null && fromPkg.pkg.imports !== undefined) {
      const target = resolveExportsTarget(fromPkg.pkg.imports, spec, fromPkg.dir, ctx.format);
      if (target !== null) {
        const file = probeFile(target);
        if (file !== null) {
          return {
            ...base,
            status: "resolved",
            target: file,
            instanceDir: fromPkg.dir,
            moduleFormat: moduleFormatOf(file),
            candidates: [file],
            reason: `# import via package "imports"`,
          };
        }
      }
    }
    return {
      ...base,
      status: "unresolved",
      moduleFormat: "unknown",
      reason: "# import without a package-level imports mapping",
    };
  }

  // Self-reference: a package importing its own name (npm feature).
  const ownPkg = nearestPackageDir(fromDir, model.root);
  const ownName = ownPkg === null ? null : ownPkg.pkg.name;
  if (
    ownPkg !== null &&
    ownName !== null &&
    ownName !== undefined &&
    ownName.length > 0 &&
    (spec === ownName || spec.startsWith(`${ownName}/`))
  ) {
    const resolved = resolveWithinPackage(
      ownPkg.dir,
      ownPkg.pkg,
      spec === ownName ? "." : spec.slice(ownName.length + 1),
      ctx,
      base,
    );
    if (resolved !== null) return resolved;
  }

  // node_modules walk from fromDir up through the project (hoisting).
  // "p/lib/x" resolves the package "p" then subpath "./lib/x" (scoped:
  // "@s/p/x" -> package "@s/p", subpath "./x").
  const slash = spec.startsWith("@") ? spec.indexOf("/", spec.indexOf("/") + 1) : spec.indexOf("/");
  const pkgName = slash < 0 ? spec : spec.slice(0, slash);
  const subpath = slash < 0 ? "." : `./${spec.slice(slash + 1)}`;
  let dir = fromDir;
  for (;;) {
    const candidateDir = join(dir, "node_modules", pkgName);
    base.candidates.push(candidateDir);
    const pkg = readPkgJson(candidateDir);
    if (pkg !== null && typeof pkg.name === "string") {
      const resolved = resolveWithinPackage(candidateDir, pkg, subpath, ctx, base);
      if (resolved !== null) return resolved;
    }
    // Hoisting: keep walking up to the install root (a monorepo subfolder
    // finds its dependencies at the repo root), then stop.
    if (dir === model.installRoot) break;
    const parent = join(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  // Profile b2: application-code tsconfig alias with a detected mechanism.
  if (ctx.allowTsconfigAliases && isAppCode(fromDir, model)) {
    const alias = resolveTsconfigAlias(spec, fromDir, model);
    if (alias !== null) {
      return {
        ...base,
        status: "tsconfig-alias",
        target: alias.target,
        moduleFormat: moduleFormatOf(alias.target),
        reason: alias.reason,
      };
    }
  }
  return { ...base, status: "unresolved", moduleFormat: "unknown", reason: "no candidate matched" };
}

function resolveRelative(
  spec: string,
  fromDir: string,
  ctx: Ctx,
  base: { spec: string; fromDir: string; candidates: string[] },
): ResolutionDecision | null {
  const basePath = isAbsolute(spec) ? spec : resolvePath(fromDir, spec);
  const file = probeFile(basePath);
  base.candidates.push(basePath);
  if (file !== null) {
    const target = realTarget(file);
    const instanceDir = instanceDirOf(target, ctx.model);
    const result: ResolutionDecision = {
      ...base,
      status: "resolved",
      target,
      moduleFormat: moduleFormatOf(target),
      reason: "relative path",
    };
    if (instanceDir !== null) result.instanceDir = instanceDir;
    return result;
  }
  // TS source mapping only (profile b): a relative alias target with no
  // runtime file does NOT create an edge here — the runtime profile is
  // authoritative for call edges.
  if (ctx.allowTsconfigAliases && isAppCode(fromDir, ctx.model)) {
    const alias = resolveTsconfigAlias(spec, fromDir, ctx.model);
    if (alias !== null) {
      return {
        ...base,
        status: "tsconfig-alias",
        target: alias.target,
        moduleFormat: moduleFormatOf(alias.target),
        reason: alias.reason,
      };
    }
  }
  return null;
}

/** The package instance directory a file lives in, when under node_modules. */
export function instanceDirOf(file: string, model: ProjectModel): string | null {
  const marker = `${sep}node_modules${sep}`;
  const idx = file.lastIndexOf(marker);
  if (idx < 0) return null;
  const after = file.slice(idx + marker.length);
  const parts = after.split(sep);
  const depth = (parts[0] ?? "").startsWith("@") ? 2 : 1;
  if (parts.length < depth) return null;
  const dir = join(file.slice(0, idx), "node_modules", ...parts.slice(0, depth));
  for (const instance of model.instances) {
    if (instance.realDir === dir || file.startsWith(`${instance.realDir}${sep}`)) return instance.realDir;
  }
  return dirExists(dir) ? dir : null;
}

function isAppCode(dir: string, model: ProjectModel): boolean {
  if (dir !== model.root && !dir.startsWith(`${model.root}${sep}`)) return false;
  const marker = `${sep}node_modules${sep}`;
  return !dir.includes(marker);
}

// --- package-internal resolution (exports / main / index) -------------------

type ExportsValue = string | Record<string, unknown>;

function isConditionObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Conditional exports resolution (Node semantics, ADR 0005): condition
 * ordering matters (first match wins, "default" last), nested conditions.
 * Returns the resolved file path or null.
 */
export function resolveExportsTarget(
  exports: unknown,
  subpath: string,
  pkgDir: string,
  format: "require" | "import",
): string | null {
  const target = matchExports(exports, subpath, format);
  if (typeof target === "string") {
    const base = target.startsWith("./") ? resolvePath(pkgDir, target.slice(2)) : join(pkgDir, target);
    return probeFile(base);
  }
  if (typeof target === "object" && target !== null) {
    // A nested condition object as the final value: pick the first condition.
    const file = pickCondition(target, format, pkgDir);
    return file;
  }
  return null;
}

function matchExports(exports: unknown, subpath: string, format: "require" | "import"): ExportsValue | null {
  if (typeof exports === "string") {
    return subpath === "." ? exports : null;
  }
  if (!isConditionObject(exports)) return null;
  // 1) Subpath object: keys are exact, "..." patterns, or "." (root).
  if (subpath === "." || !subpath.startsWith("./")) {
    const exact = exports[subpath === "." ? "." : subpath];
    if (exact !== undefined) return matchCondition(exact, format);
    const pattern = matchPatternKey(exports, subpath === "." ? "." : `./${subpath}`);
    if (pattern !== null) return matchCondition(pattern.value, format, pattern.mid);
    const root = exports["."];
    if (root !== undefined) return matchCondition(root, format);
    return null;
  }
  // subpath "./x"
  const key = subpath;
  const exact = exports[key];
  if (exact !== undefined) return matchCondition(exact, format);
  const pattern = matchPatternKey(exports, key);
  if (pattern !== null) return matchCondition(pattern.value, format, pattern.mid);
  return null;
}

/** `./lib/*` style pattern matching; the most specific (longest static part) wins. */
function matchPatternKey(exports: Record<string, unknown>, subpath: string): { value: unknown; mid: string } | null {
  let best: { value: unknown; mid: string; specificity: number } | null = null;
  for (const [key, value] of Object.entries(exports)) {
    if (!key.includes("*")) continue;
    const star = key.indexOf("*");
    const prefix = key.slice(0, star);
    const suffix = key.slice(star + 1);
    if (!subpath.startsWith(prefix) || !subpath.endsWith(suffix)) continue;
    const mid = subpath.slice(prefix.length, subpath.length - suffix.length);
    if (mid.length === 0) continue;
    const specificity = prefix.length + suffix.length;
    if (best === null || specificity > best.specificity) {
      best = { value, mid, specificity };
    }
  }
  return best === null ? null : best;
}

function matchCondition(value: unknown, format: "require" | "import", mid: string | null = null): ExportsValue | null {
  if (typeof value === "string") return mid === null || !value.includes("*") ? value : value.replace("*", mid);
  if (!isConditionObject(value)) return null;
  const picked = pickConditionKeys(value, format);
  if (picked === null) return null;
  return matchCondition(picked, format, mid);
}

function pickConditionKeys(obj: Record<string, unknown>, format: "require" | "import"): unknown {
  const conditions = ["node", format, "default"];
  for (const cond of conditions) {
    if (obj[cond] !== undefined) return obj[cond];
  }
  return null;
}

function pickCondition(obj: Record<string, unknown>, format: "require" | "import", pkgDir: string): string | null {
  const picked = pickConditionKeys(obj, format);
  if (typeof picked !== "string") return null;
  const base = picked.startsWith("./")
    ? resolvePath(pkgDir, picked.slice(2))
    : join(pkgDir, picked.replace(/^\.\//, ""));
  return probeFile(base);
}

function resolveWithinPackage(
  pkgDir: string,
  pkg: PkgJson,
  subpath: string,
  ctx: Ctx,
  base: { spec: string; fromDir: string; candidates: string[] },
): ResolutionDecision | null {
  const norm = subpath === "." ? "." : subpath.startsWith("./") ? subpath : `./${subpath}`;
  if (pkg.exports !== undefined) {
    const file = resolveExportsTarget(pkg.exports, norm, pkgDir, ctx.format);
    base.candidates.push(`${pkgDir} (exports)`);
    if (file !== null) {
      return {
        ...base,
        status: "resolved",
        target: realTarget(file),
        instanceDir: pkgDir,
        moduleFormat: moduleFormatOf(realTarget(file)),
        reason: "package exports",
      };
    }
    // exports present but no match: no main/index fallback (Node semantics).
    return null;
  }
  const mainOrSub = norm === "." ? (pkg.main ?? "index") : norm;
  const targetPath =
    mainOrSub.startsWith(".") && mainOrSub !== "index"
      ? resolvePath(pkgDir, mainOrSub)
      : join(pkgDir, mainOrSub === "index" ? "index" : mainOrSub);
  const file = probeFile(targetPath);
  base.candidates.push(targetPath);
  if (file === null) return null;
  const target = realTarget(file);
  return {
    ...base,
    status: "resolved",
    target,
    instanceDir: pkgDir,
    moduleFormat: moduleFormatOf(target),
    reason: pkg.main !== undefined && norm === "." ? "package main" : "package index",
  };
}

/** The realpath of a resolved file (symlinked package dirs resolve to their store/origin). */
function realTarget(file: string): string {
  try {
    return realpathSync(file);
  } catch {
    return file;
  }
}

// --- tsconfig alias profile (b: source mapping; b2: app-code with mechanism) -

interface TsAliasConfig {
  baseUrl: string;
  paths: Record<string, string[]>;
}

/** Read the nearest tsconfig.json (within the project) with paths/baseUrl. */
export function tsconfigOf(fromDir: string, projectRoot: string): TsAliasConfig | null {
  let cur = fromDir;
  for (;;) {
    const file = join(cur, "tsconfig.json");
    if (fileExists(file)) {
      try {
        const doc = JSON.parse(readFileSync(file, "utf8").replace(/^﻿/, "")) as {
          compilerOptions?: { baseUrl?: string; paths?: Record<string, unknown>; extends?: unknown };
        };
        const options = doc.compilerOptions ?? {};
        const baseUrl = typeof options.baseUrl === "string" ? resolvePath(cur, options.baseUrl) : cur;
        const paths: Record<string, string[]> = {};
        if (isConditionObject(options.paths)) {
          for (const [pattern, targets] of Object.entries(options.paths)) {
            if (Array.isArray(targets)) {
              paths[pattern] = targets.filter((t): t is string => typeof t === "string");
            }
          }
        }
        return { baseUrl, paths };
      } catch {
        return null;
      }
    }
    if (cur === projectRoot) break;
    const parent = join(cur, "..");
    if (parent === cur) break;
    cur = parent;
  }
  return null;
}

/**
 * Detect the b2 runtime-resolution mechanism (plan v3.4 item 1): a Next.js
 * config, a Nest build config, or a tsconfig-paths/tsc-alias/module-alias
 * dependency. Without one, a tsconfig alias stays UNRESOLVED at runtime.
 */
export function detectAliasMechanism(projectRoot: string): boolean {
  const pkg = readPkgJson(projectRoot);
  if (pkg !== null) {
    const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    for (const tool of ["tsconfig-paths", "tsc-alias", "module-alias"]) {
      if (deps[tool] !== undefined) return true;
    }
  }
  for (const name of ["next.config.js", "next.config.ts", "next.config.mjs", "next.config.cjs", "next.config.json"]) {
    if (fileExists(join(projectRoot, name))) return true;
  }
  if (fileExists(join(projectRoot, "nest-cli.json"))) return true;
  return false;
}

/**
 * Profile b/b2: map a specifier through tsconfig paths/baseUrl. App code only;
 * the caller must have detected a runtime mechanism to mark the edge
 * "tsconfig-alias" (otherwise the specifier stays unresolved).
 */
export function resolveTsconfigAlias(
  spec: string,
  fromDir: string,
  model: ProjectModel,
): { target: string; reason: string } | null {
  const config = tsconfigOf(fromDir, model.root);
  if (config === null) return null;
  if (spec.startsWith("./") || spec.startsWith("../") || isAbsolute(spec) || spec.startsWith("#") || isBuiltin(spec)) {
    const direct = probeFile(isAbsolute(spec) ? spec : resolvePath(fromDir, spec));
    if (direct !== null) return { target: direct, reason: "relative path" };
    return null;
  }
  const patterns = Object.entries(config.paths);
  let best: { pattern: string; target: string } | null = null;
  for (const [pattern, targets] of patterns) {
    const star = pattern.indexOf("*");
    let candidatePath: string | null = null;
    if (star < 0) {
      if (pattern === spec) {
        candidatePath = null; // resolved below via baseUrl
        if (targets.length > 0) {
          const t = firstExisting(resolvePath(config.baseUrl, targets[0] ?? ""));
          if (t !== null) candidatePath = t;
        }
        if (candidatePath === null) {
          const t = firstExisting(resolvePath(config.baseUrl, spec));
          if (t !== null) return { target: t, reason: `tsconfig paths "${pattern}" (baseUrl)` };
        }
        if (candidatePath !== null) return { target: candidatePath, reason: `tsconfig paths "${pattern}"` };
      }
      continue;
    }
    const prefix = pattern.slice(0, star);
    const suffix = pattern.slice(star + 1);
    if (!spec.startsWith(prefix) || !spec.endsWith(suffix)) continue;
    const mid = spec.slice(prefix.length, spec.length - suffix.length);
    if (mid.length === 0) continue;
    for (const target of targets) {
      const expanded = target.replace("*", mid);
      const t = firstExisting(resolvePath(config.baseUrl, expanded));
      if (t !== null) {
        if (best === null || prefix.length > best.pattern.length) {
          best = { pattern, target: t };
        }
      }
    }
  }
  return best === null ? null : { target: best.target, reason: `tsconfig paths "${best.pattern}"` };
}

/** First candidate path (with extension probing) that exists. */
function firstExisting(base: string): string | null {
  return probeFile(base);
}

/**
 * Whether any file under the project root is application code (it is, if the
 * project has sources outside node_modules). Used by entry-point detection.
 */
export function hasAppCode(model: ProjectModel): boolean {
  const { root } = model;
  let entries: string[];
  try {
    entries = readdirSync(root);
  } catch {
    return false;
  }
  for (const entry of entries) {
    if (entry === "node_modules" || entry.startsWith(".")) continue;
    const full = join(root, entry);
    try {
      const st = statSync(full);
      if (st.isFile() && /\.(ts|tsx|js|mjs|cjs|jsx|mts|cts)$/.test(entry)) return true;
      if (st.isDirectory()) {
        for (const sub of readdirSync(full)) {
          if (/\.(ts|tsx|js|mjs|cjs|jsx|mts|cts)$/.test(sub)) return true;
        }
      }
    } catch {
      // unreadable entry: skip
    }
  }
  return false;
}
