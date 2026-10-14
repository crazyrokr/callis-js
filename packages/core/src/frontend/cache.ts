// Per-file IR cache (plan section 5.4, v3.3: tier 1 of the cache keys).
//
// Key = sha256(file contents) + parser version + IR_VERSION + parse options.
// The key hashes CONTENT (never mtime): an in-place patch of a loaded package
// changes its IR key and invalidates every derived result (P0.4/P0.7).
// node_modules rarely changes, so warm runs skip almost all parsing.
//
// Parsing itself runs in a pool of Bun Workers in the COMPILED binary
// (plan section 7, worker-entry compile constraint); in source checkouts the
// pool is a sequential loop over the same parseOne entry point.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { IR_VERSION } from "../index.js";
import { sha256Hex } from "../util/hash.js";
import { parserVersion } from "./parse.js";
import type { ModuleIR, ParseOptions } from "./types.js";

export interface CacheStats {
  /** Files served from the on-disk cache (zero parsing). */
  cached: number;
  /** Files parsed from source (and written back). */
  parsed: number;
}

/** The per-file IR key (plan 5.4). */
export function irKey(content: string, options: ParseOptions): string {
  const optionsKey = sha256Hex(JSON.stringify(options ?? {}));
  return `${sha256Hex(content)}:${parserVersion()}:${IR_VERSION}:${optionsKey}`;
}

function cacheFileOf(cacheDir: string, key: string): string {
  return join(cacheDir, "ir", `${key}.json`);
}

/**
 * Parse one file (cache hit when possible). Returns the IR + where it came
 * from; the cache is best-effort (a corrupt entry is re-parsed, never fatal).
 */
export async function parseFile(
  file: string,
  cacheDir: string,
  options: ParseOptions,
  parse: (file: string, content: string, options: ParseOptions) => ModuleIR,
): Promise<{ ir: ModuleIR; fromCache: boolean }> {
  let content: string;
  try {
    content = await readFile(file, "utf8");
  } catch {
    throw new Error(`IR cache: unreadable file: ${file}`);
  }
  const key = irKey(content, options);
  const path = cacheFileOf(cacheDir, key);
  try {
    const raw = await readFile(path, "utf8");
    const ir = JSON.parse(raw) as ModuleIR;
    if (ir !== null && typeof ir === "object" && ir.file === file) {
      return { ir, fromCache: true };
    }
  } catch {
    // no cache entry (or corrupt): fall through to a fresh parse
  }
  const ir = parse(file, content, options);
  try {
    await mkdir(join(cacheDir, "ir"), { recursive: true });
    await writeFile(path, JSON.stringify(ir));
  } catch {
    // cache write failures are not analysis failures
  }
  return { ir, fromCache: false };
}

/**
 * Parse a set of files with the shared cache. Source checkouts: sequential
// (the compiled-binary worker pool, plan section 7, swaps the loop for a
 * Bun Worker pool over the same parseFile entry).
 */
export async function parseFiles(
  files: string[],
  cacheDir: string,
  options: ParseOptions,
  parse: (file: string, content: string, options: ParseOptions) => ModuleIR,
): Promise<{ irs: Map<string, ModuleIR>; stats: CacheStats }> {
  const irs = new Map<string, ModuleIR>();
  const stats: CacheStats = { cached: 0, parsed: 0 };
  for (const file of [...files].sort()) {
    const { ir, fromCache } = await parseFile(file, cacheDir, options, parse);
    irs.set(file, ir);
    if (fromCache) stats.cached += 1;
    else stats.parsed += 1;
  }
  return { irs, stats };
}
