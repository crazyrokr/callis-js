// Curated entry-point detection (plan section 5.5 "Entry points").
//
// Sources: the application package's main/module/exports/bin, package.json
// scripts (at least `start` — a plain `node scripts/x.js` app must not
// analyze to zero entry points silently), server-framework route
// registration (curated constructor + verb tables from @callis/models),
// Next.js-style route files, and the callback-interface catalogue
// (module#handler, ...). Test files are excluded unless --include-tests.
//
// User tokens: `--entry-points` EXTENDS curated detection,
// `--entry-points-only` REPLACES it (JVM replace contract). Malformed or
// unknown tokens WARN, they never fail the run (JVM resolveOverrides parity).
// Zero entry points from all sources ⇒ the CLI exits 3 (plan 5.5).

import { readFileSync } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import type { Assignment, ModuleIR } from "../frontend/index.js";
import type { ProjectModel } from "../project/types.js";
import type { CallbackInterfaceCatalog, EntryPointAnnotations } from "./models.js";
import type { EntryPoint } from "./types.js";
import { MODULE_INIT_NAME } from "./types.js";

export interface DetectOptions {
  includeTests?: boolean;
  /** `--entry-points` tokens: `<file>#<function|<module-init>>` (extend). */
  extra?: string[];
  /** `--entry-points-only` tokens: replace curated detection (JVM contract). */
  extraOnly?: string[];
  /** `--callback-interfaces` tokens: `<file>#<export>` (extend the catalogue). */
  callbackInterfaces?: string[];
}

export interface DetectionResult {
  entries: EntryPoint[];
  warnings: string[];
}

export interface DetectContext {
  model: ProjectModel;
  irOf: (file: string) => ModuleIR | null;
  annotations: EntryPointAnnotations;
  callbackInterfaces: CallbackInterfaceCatalog;
}

const SOURCE_EXTS = new Set([".js", ".cjs", ".mjs", ".ts", ".mts", ".jsx", ".tsx"]);
const SKIP_DIRS = new Set(["node_modules", "dist", "build", "coverage", ".git"]);

/** Parse `<file>#<name>` tokens; returns entries + warnings for bad tokens. */
export function parseEntryTokens(
  tokens: string[],
  projectRoot: string,
  knownFiles: Set<string>,
): { entries: EntryPoint[]; warnings: string[] } {
  const entries: EntryPoint[] = [];
  const warnings: string[] = [];
  for (const token of tokens) {
    const hash = token.indexOf("#");
    if (hash <= 0 || hash === token.length - 1) {
      warnings.push(`entry token "${token}" is malformed (expected <file>#<name>)`);
      continue;
    }
    const file = token.slice(0, hash).startsWith("/") ? token.slice(0, hash) : join(projectRoot, token.slice(0, hash));
    const name = token.slice(hash + 1);
    if (!knownFiles.has(file)) {
      warnings.push(`entry token "${token}" names an unknown file`);
      continue;
    }
    entries.push({ file, name, source: "user", line: 0 });
  }
  return { entries, warnings };
}

/** Collect application source files of a workspace (tests excluded by default). */
export async function appFilesOf(
  workspaceDir: string,
  testPatterns: string[],
  includeTests: boolean,
): Promise<string[]> {
  const out: string[] = [];
  const isTest = (rel: string): boolean => !includeTests && testPatterns.some((p) => globMatch(p, rel));
  const walk = async (dir: string): Promise<void> => {
    let names: string[];
    try {
      names = await readdir(dir);
    } catch {
      return;
    }
    for (const n of names.sort()) {
      if (n.startsWith(".") || SKIP_DIRS.has(n)) continue;
      const full = join(dir, n);
      let st: Awaited<ReturnType<typeof stat>>;
      try {
        st = await stat(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        await walk(full);
        continue;
      }
      const ext = full.slice(full.lastIndexOf("."));
      if (!SOURCE_EXTS.has(ext)) continue;
      const rel = relative(workspaceDir, full).split(sep).join("/");
      if (isTest(rel)) continue;
      out.push(full);
    }
  };
  await walk(workspaceDir);
  return out;
}

/** Detect entry points from the curated sources of a resolved project. */
export async function detectEntryPoints(ctx: DetectContext, options: DetectOptions = {}): Promise<DetectionResult> {
  const { model, annotations } = ctx;
  const warnings: string[] = [];
  const includeTests = options.includeTests ?? false;

  const fileSet = new Set<string>();
  for (const ws of model.workspaces) {
    for (const f of await appFilesOf(ws.dir, annotations.testPatterns, includeTests)) fileSet.add(f);
  }

  const entries: EntryPoint[] = [];
  const addEntry = (ep: EntryPoint): void => {
    if (!entries.some((e) => e.file === ep.file && e.name === ep.name)) entries.push(ep);
  };

  const extraOnly = options.extraOnly !== undefined;

  if (!extraOnly) {
    const irCache = new Map<string, ModuleIR | null>();
    const irOf = (file: string): ModuleIR | null => {
      if (!irCache.has(file)) irCache.set(file, ctx.irOf(file));
      return irCache.get(file) ?? null;
    };

    for (const ws of model.workspaces) {
      for (const ep of pkgEntriesSync(ws.dir)) {
        if (fileSet.has(ep.file)) addEntry(ep);
      }
      for (const ep of scriptEntriesSync(ws.dir)) {
        if (fileSet.has(ep.file)) addEntry(ep);
      }
    }

    // Framework route registration + callback interfaces need the IR.
    const interfaces = [...ctx.callbackInterfaces.interfaces, ...(options.callbackInterfaces ?? [])];
    for (const file of [...fileSet].sort()) {
      const ir = irOf(file);
      if (ir === null) continue;

      const rel = relative(model.root, file).split(sep).join("/");
      if (annotations.nextRoutePatterns.some((p) => globMatch(p, rel))) {
        addEntry({ file, name: MODULE_INIT_NAME, source: "framework", line: 1, framework: "next" });
      }
      for (const ep of frameworkRouteEntries(file, ir, annotations)) addEntry(ep);

      for (const iface of interfaces) {
        const hash = iface.indexOf("#");
        if (hash <= 0) continue;
        const wanted = iface.slice(hash + 1);
        const exp = ir.exports.find((e) => e.name === wanted);
        if (exp !== undefined && exp.local !== undefined) {
          addEntry({
            file,
            name: exp.local,
            source: "callback-interface",
            line: exp.line,
            framework: iface.slice(0, hash),
          });
        }
      }
    }
  }

  const tokenSources = [...(options.extra ?? []), ...(options.extraOnly ?? [])];
  if (tokenSources.length > 0) {
    const parsed = parseEntryTokens(tokenSources, model.root, fileSet);
    warnings.push(...parsed.warnings);
    for (const ep of parsed.entries) addEntry(ep);
  }

  return { entries, warnings };
}

interface PkgJsonLike {
  main?: unknown;
  module?: unknown;
  exports?: unknown;
  bin?: unknown;
  scripts?: Record<string, unknown>;
}

function readJsonSync(dir: string): PkgJsonLike | null {
  try {
    // sync read: entry detection runs before any parsing (one small file)
    return JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as PkgJsonLike;
  } catch {
    return null;
  }
}

/** Entry points from a workspace package.json (main/module/exports/bin). */
function pkgEntriesSync(wsDir: string): EntryPoint[] {
  const pkg = readJsonSync(wsDir);
  if (pkg === null) return [];
  const out: EntryPoint[] = [];
  const add = (spec: unknown, source: EntryPoint["source"]): void => {
    if (typeof spec !== "string" || spec.length === 0) return;
    const file = join(wsDir, spec);
    if (!SOURCE_EXTS.has(extOf(file)) && !isIndexFile(file)) return;
    out.push({ file, name: MODULE_INIT_NAME, source, line: 0 });
  };
  add(pkg.main, "main");
  add(pkg.module, "module");
  add(exportTargetOf(pkg.exports), "exports");
  addBin(pkg.bin, wsDir, out);
  return out;
}

function extOf(file: string): string {
  const i = file.lastIndexOf(".");
  return i > 0 ? file.slice(i) : "";
}

function isIndexFile(file: string): boolean {
  return /\/index\.(js|cjs|mjs|ts|mts)$/.test(file);
}

function exportTargetOf(exports: unknown): string | null {
  if (exports === undefined || exports === null) return null;
  if (typeof exports === "string") return exports;
  if (Array.isArray(exports)) return null;
  if (typeof exports === "object") {
    const rec = exports as Record<string, unknown>;
    const pick = (v: unknown): string | null => {
      if (typeof v === "string") return v;
      if (v !== null && typeof v === "object") {
        const inner = v as Record<string, unknown>;
        const d = inner.default ?? inner.require ?? inner.import ?? inner.node;
        if (typeof d === "string") return d;
      }
      return null;
    };
    return pick(rec["."]) ?? pick(rec.default) ?? pick(rec.require) ?? pick(rec.import) ?? pick(rec.node);
  }
  return null;
}

function addBin(bin: unknown, wsDir: string, out: EntryPoint[]): void {
  if (typeof bin === "string") {
    const file = join(wsDir, bin);
    if (SOURCE_EXTS.has(extOf(file))) out.push({ file, name: MODULE_INIT_NAME, source: "bin", line: 0 });
    return;
  }
  if (bin !== null && typeof bin === "object") {
    for (const value of Object.values(bin)) {
      if (typeof value !== "string") continue;
      const file = join(wsDir, value);
      if (SOURCE_EXTS.has(extOf(file))) out.push({ file, name: MODULE_INIT_NAME, source: "bin", line: 0 });
    }
  }
}

/**
 * Entry points from package.json scripts: every script that is a plain
 * `node <file>` (or `bun <file>`) invocation. At minimum `start` is
 * resolved (plan 5.5) — a no-framework app must not analyze to zero.
 */
function scriptEntriesSync(wsDir: string): EntryPoint[] {
  const pkg = readJsonSync(wsDir);
  if (pkg === null || pkg.scripts === undefined) return [];
  const out: EntryPoint[] = [];
  for (const [name, script] of Object.entries(pkg.scripts)) {
    if (name.startsWith("@") || name.startsWith("pre") || name.startsWith("post")) continue;
    if (typeof script !== "string") continue;
    const m = /^(?:node|bun)\s+([^\s&|;]+)(\s|$)/.exec(script.trim());
    if (m === null || m[1] === undefined) continue;
    const spec = m[1];
    if (SOURCE_EXTS.has(extOf(spec))) {
      const file = join(wsDir, spec);
      if (SOURCE_EXTS.has(extOf(file))) out.push({ file, name: MODULE_INIT_NAME, source: "script", line: 0 });
    }
  }
  return out;
}

/**
 * Framework route registration: `app.<verb>(path, handler)` where `app` is
 * created by a curated framework constructor (`express()`, `new Koa()`, ...).
 * Identifier handlers become function entries; anonymous handlers are not
 * recorded (a documented precision limit, ADR 0011) — the module-init entry
 * of the file still covers the import-time registration side effects.
 */
export function frameworkRouteEntries(file: string, ir: ModuleIR, annotations: EntryPointAnnotations): EntryPoint[] {
  const out: EntryPoint[] = [];
  const appVars = new Map<string, string>();

  const ctorsByFramework = new Map<string, Set<string>>();
  const verbsByFramework = new Map<string, Set<string>>();
  for (const [framework, ctors] of Object.entries(annotations.constructors)) {
    ctorsByFramework.set(framework, new Set(ctors));
    verbsByFramework.set(framework, new Set(annotations.routes[framework] ?? []));
  }

  // Module scope: `const app = express()` / `const app = new Koa()` —
  // module-scope assignments (M3 moduleAssignments) plus assignments inside
  // top-level (non-exported-body) functions.
  const scopeAssignments: Assignment[] = [
    ...ir.moduleAssignments,
    ...ir.functions.filter((f) => f.top).flatMap((f) => f.assignments),
  ];
  for (const a of scopeAssignments) {
    if (a.kind !== "identifier") continue;
    // `new Koa()` first (constructor call), then a bare creator call
    // (`express()` — the text may carry arguments, so prefix-match only).
    const m = /^new\s+([A-Za-z_$][\w$]*)\(/.exec(a.value) ?? /^([A-Za-z_$][\w$]*)\(/.exec(a.value);
    if (m === null || m[1] === undefined) continue;
    for (const [framework, ctors] of ctorsByFramework) {
      if (ctors.has(m[1])) appVars.set(a.target, framework);
    }
  }

  // Route registrations are MEMBER calls (`app.get(path, handler)`) — their
  // topLevel entries carry no functionName (that is set for identifier
  // callees only), so match on the call shape alone.
  const handlerPattern = /^([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\(\s*(['"])(.+)\3\s*,\s*([A-Za-z_$][\w$]*)\)\s*$/;
  for (const t of ir.topLevel) {
    if (t.kind !== "call") continue;
    const m = handlerPattern.exec(t.shape);
    if (m === null || m[1] === undefined || m[2] === undefined || m[5] === undefined) continue;
    const framework = appVars.get(m[1]);
    if (framework === undefined) continue;
    const verbs = verbsByFramework.get(framework) ?? new Set();
    if (!verbs.has(m[2])) continue;
    const fn = ir.functions.find((f) => f.name === m[5] && f.top);
    if (fn !== undefined) {
      out.push({ file, name: fn.name, source: "framework", line: fn.line, framework });
    }
  }
  return out;
}

/**
 * Minimal glob for the annotation data (plan 5.5): `**`, `*`, `?`,
 * `?(a|b)` and `(a|b)` groups. Matches workspace-relative POSIX paths.
 */
export function globMatch(pattern: string, path: string): boolean {
  return new RegExp(`^${globToRegex(pattern)}$`).test(path);
}

export function globToRegex(pattern: string): string {
  let out = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i] as string;
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        out += ".*";
        i++;
        if (pattern[i + 1] === "/") i++;
      } else {
        out += "[^/]*";
      }
    } else if (c === "?") {
      if (pattern[i + 1] === "(") {
        const close = pattern.indexOf(")", i + 2);
        if (close < 0) {
          out += "[^/]";
        } else {
          const inner = pattern
            .slice(i + 2, close)
            .split("|")
            .map((s) => s.replace(/\./g, "\\."));
          out += `(${inner.join("|")})?`;
          i = close;
        }
      } else {
        out += "[^/]";
      }
    } else if (c === "(") {
      const close = pattern.indexOf(")", i + 1);
      if (close < 0) {
        out += "\\(";
      } else {
        const inner = pattern
          .slice(i + 1, close)
          .split("|")
          .map((s) => globToRegex(s));
        out += `(${inner.join("|")})`;
        i = close;
      }
    } else if (c === "." || c === "+" || c === "$" || c === "^" || c === "{" || c === "}" || c === "|" || c === "[") {
      out += `\\${c}`;
    } else {
      out += c;
    }
  }
  return out;
}
