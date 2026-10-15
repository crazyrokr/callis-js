// Declarative library models and annotation data (plan section 5.5 item 4,
// ADR 0011 "modeled" classification). The data lives in @callis/models (JSON);
// the compiled binary embeds it via --asset, source checkouts read from the
// workspace. The format is declarative on purpose: contributors extend the
// catalogue without touching the engine.

import { readFile } from "node:fs/promises";
import { join } from "node:path";

/** One library-model entry (packages/models/data/library-models.json). */
export interface LibraryModel {
  /** Method or function name (map, setTimeout, ...). */
  name: string;
  /** Global owner (timers, process, global); absent for prototype methods. */
  module?: string;
  /** true: `x.<name>(...)`; absent: global call. */
  method?: boolean;
  /** Callback argument positions (map: [0], then: [0,1]). */
  callbackArgs?: number[];
  /** Single callback position (timers); sugar for callbackArgs. */
  callbackArg?: number;
  /** callback | emitter (on/once registration) | emitter-emit | alias (bind). */
  kind: "callback" | "emitter" | "emitter-emit" | "alias";
  /** Event-name argument position for emitter kinds. */
  eventArg?: number;
}

export interface EntryPointAnnotations {
  /** Framework route verbs: express -> [get, post, ...]. */
  routes: Record<string, string[]>;
  /** Framework constructor/creator names: express -> [express, createServer]. */
  constructors: Record<string, string[]>;
  /** Next.js-style route file globs (app route files, pages/api tree). */
  nextRoutePatterns: string[];
  /** Test-file globs (excluded from analysis unless --include-tests). */
  testPatterns: string[];
}

/** Callback-interface catalogue (module#handler, module#process, ...). */
export interface CallbackInterfaceCatalog {
  interfaces: string[];
}

export interface ModelCatalog {
  models: LibraryModel[];
  annotations: EntryPointAnnotations;
  callbackInterfaces: CallbackInterfaceCatalog;
}

function modelArgPositions(m: LibraryModel): number[] {
  if (m.callbackArgs !== undefined) return m.callbackArgs;
  if (m.callbackArg !== undefined) return [m.callbackArg];
  return [];
}

const EMPTY_CATALOG: ModelCatalog = {
  models: [],
  annotations: { routes: {}, constructors: {}, nextRoutePatterns: [], testPatterns: [] },
  callbackInterfaces: { interfaces: [] },
};

async function readJson(file: string): Promise<unknown> {
  return JSON.parse(await readFile(file, "utf8")) as unknown;
}

/**
 * Candidate URLs for one catalogue file. The first is the compiled-binary
 * shape: bun --asset embeds the file FLAT next to the entry, and Bun serves
 * it at the URL import.meta.url resolves to (measured: /$bunfs/root/<name>,
 * Bun 1.4.2). The second is the workspace @callis/models copy (source
 * checkout, bun run / bun test).
 */
export function modelFileCandidates(file: string): URL[] {
  return [new URL(file, import.meta.url), new URL(`../../../models/data/${file}`, import.meta.url)];
}

async function readAsset(file: string): Promise<unknown> {
  let lastError: Error | null = null;
  for (const url of modelFileCandidates(file)) {
    try {
      const res = await fetch(url);
      if (res.ok) return await res.json();
      lastError = new Error(`HTTP ${res.status} for ${url.href}`);
    } catch (e) {
      lastError = e as Error;
    }
  }
  throw new Error(`models: cannot load ${file} (embedded asset or workspace copy): ${lastError?.message ?? "unknown"}`);
}

/**
 * Load the model catalogue (default: embedded assets in the compiled binary,
 * the workspace @callis/models data in a source checkout). An explicit
 * directory is read from disk. A missing source is a hard error — the models
 * are part of the soundness contract, not an optional extra.
 */
export async function loadModels(dataDir?: string): Promise<ModelCatalog> {
  const files = ["library-models.json", "entry-point-annotations.json", "callback-interfaces.json"] as const;
  const docs =
    dataDir !== undefined
      ? await Promise.all(
          files.map((f) =>
            readJson(join(dataDir, f)).catch((e: Error) => {
              throw new Error(`models: cannot read ${f} from ${dataDir}: ${e.message}`);
            }),
          ),
        )
      : await Promise.all(files.map((f) => readAsset(f)));
  return validateCatalog(docs[0] as unknown, docs[1] as unknown, docs[2] as unknown);
}

/** Validate + normalize the three catalogue documents (untrusted shape check). */
export function validateCatalog(rawModels: unknown, rawAnnotations: unknown, rawInterfaces: unknown): ModelCatalog {
  const models = parseModels(rawModels);
  const annotations = parseAnnotations(rawAnnotations);
  const callbackInterfaces = parseCallbackInterfaces(rawInterfaces);
  return { models, annotations, callbackInterfaces };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function parseModels(raw: unknown): LibraryModel[] {
  if (!isRecord(raw) || !Array.isArray(raw.models)) throw new Error("models: missing models array");
  const out: LibraryModel[] = [];
  for (const entry of raw.models) {
    if (!isRecord(entry) || typeof entry.name !== "string" || typeof entry.kind !== "string") {
      throw new Error("models: malformed entry");
    }
    const kind = entry.kind;
    if (kind !== "callback" && kind !== "emitter" && kind !== "emitter-emit" && kind !== "alias") {
      throw new Error(`models: unknown kind ${String(kind)}`);
    }
    const m: LibraryModel = { name: entry.name, kind };
    if (typeof entry.module === "string") m.module = entry.module;
    if (typeof entry.method === "boolean") m.method = entry.method;
    if (Array.isArray(entry.callbackArgs)) m.callbackArgs = entry.callbackArgs.filter((n) => typeof n === "number");
    if (typeof entry.callbackArg === "number") m.callbackArg = entry.callbackArg;
    if (typeof entry.eventArg === "number") m.eventArg = entry.eventArg;
    out.push(m);
  }
  return out;
}

function parseAnnotations(raw: unknown): EntryPointAnnotations {
  if (!isRecord(raw)) throw new Error("annotations: not an object");
  const routes: Record<string, string[]> = {};
  const constructors: Record<string, string[]> = {};
  // A non-string ROW inside a framework list is dropped; a non-array list
  // drops the whole framework (untrusted rows never reach detection).
  if (isRecord(raw.routes)) {
    for (const [framework, verbs] of Object.entries(raw.routes)) {
      if (Array.isArray(verbs)) {
        const ok = verbs.filter((v) => typeof v === "string");
        if (ok.length > 0) routes[framework] = ok;
      }
    }
  }
  if (isRecord(raw.constructors)) {
    for (const [framework, ctors] of Object.entries(raw.constructors)) {
      if (Array.isArray(ctors)) {
        const ok = ctors.filter((c) => typeof c === "string");
        if (ok.length > 0) constructors[framework] = ok;
      }
    }
  }
  const nextRoutePatterns = Array.isArray(raw.nextRoutePatterns)
    ? raw.nextRoutePatterns.filter((p) => typeof p === "string")
    : [];
  const testPatterns = Array.isArray(raw.testPatterns) ? rawPatterns(raw.testPatterns) : [];
  return { routes, constructors, nextRoutePatterns, testPatterns };
}

function rawPatterns(list: unknown[]): string[] {
  return list.filter((p): p is string => typeof p === "string");
}

function parseCallbackInterfaces(raw: unknown): CallbackInterfaceCatalog {
  if (!isRecord(raw) || !Array.isArray(raw.interfaces)) throw new Error("interfaces: missing array");
  return { interfaces: rawInterfaces(raw.interfaces) };
}

function rawInterfaces(list: unknown[]): string[] {
  return list.filter((i): i is string => typeof i === "string" && i.includes("#"));
}

/** Look up the model matching a call (name + method/global shape). */
export function modelForCall(name: string, method: boolean, models: LibraryModel[]): LibraryModel | null {
  for (const m of models) {
    if (m.name !== name) continue;
    if (method && m.method !== true) continue;
    if (!method && m.method === true) continue;
    return m;
  }
  return null;
}

export function callbackArgsOf(m: LibraryModel): number[] {
  return modelArgPositions(m);
}

export const emptyCatalog = (): ModelCatalog => ({ ...EMPTY_CATALOG, annotations: { ...EMPTY_CATALOG.annotations } });
