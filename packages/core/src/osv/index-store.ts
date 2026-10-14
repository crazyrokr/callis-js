// OSV index: package name / alias -> record files (plan section 5.2).
//
// OSV files are named by advisory id, not package. A full scan per run would
// be too slow on 230k records, so the first run builds osv-index.json in
// --cache-dir (default $XDG_CACHE_HOME/callis) — NEVER inside --osv-dir (it
// may be read-only or shared). The index header stores the snapshot pin; a
// pin mismatch rebuilds it. Later runs read only records for packages in
// the SBOM.

import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { type OsRecord, type ReadRecordFn, defaultReadRecord, packageIdentity, readRecordFile } from "./record.js";

export interface OsvIndex {
  version: 1;
  /** Snapshot pin the index was built for. */
  pin: string;
  /** Package name -> record file paths (relative to the OSV dir). */
  packages: Record<string, string[]>;
  /** Record alias -> record file paths (secondary key, R11). */
  aliases: Record<string, string[]>;
  /** Records that failed schema validation (skipped + counted). */
  skippedRecords: number;
  /** Records that parsed and carry a usable id (the whole-directory count). */
  validRecords: number;
}

export async function buildIndex(
  osvDir: string,
  pin: string,
  read: ReadRecordFn = defaultReadRecord,
): Promise<OsvIndex> {
  const index: OsvIndex = {
    version: 1,
    pin,
    packages: {},
    aliases: {},
    skippedRecords: 0,
    validRecords: 0,
  };
  const files = await listRecordFiles(osvDir);
  const concurrency = 32;
  for (let i = 0; i < files.length; i += concurrency) {
    const batch = files.slice(i, i + concurrency);
    const parsed: (OsRecord | null)[] = await Promise.all(
      batch.map(async (f) => readRecordFile(join(osvDir, f), read)),
    );
    batch.forEach((f, j) => {
      const record = parsed[j] ?? null;
      if (record === null || record.id.length === 0) {
        index.skippedRecords += 1;
        return;
      }
      index.validRecords += 1;
      const identities = new Set<string>();
      for (const entry of record.affected ?? []) {
        const id = packageIdentity(entry);
        if (id !== null) identities.add(id);
      }
      for (const name of identities) {
        const list = index.packages[name] ?? [];
        if (!list.includes(f)) list.push(f);
        index.packages[name] = list;
      }
      for (const alias of new Set([record.id, ...record.aliases])) {
        const list = index.aliases[alias] ?? [];
        if (!list.includes(f)) list.push(f);
        index.aliases[alias] = list;
      }
    });
  }
  for (const key of Object.keys(index.packages)) {
    index.packages[key] = [...(index.packages[key] ?? [])].sort();
  }
  for (const key of Object.keys(index.aliases)) {
    index.aliases[key] = [...(index.aliases[key] ?? [])].sort();
  }
  return index;
}

/** Read the index if its pin matches; rebuild otherwise. */
export async function loadIndex(
  osvDir: string,
  pin: string,
  cacheDir: string,
  read: ReadRecordFn = defaultReadRecord,
): Promise<OsvIndex> {
  const indexPath = join(cacheDir, "osv-index.json");
  try {
    const parsed = JSON.parse(await readFile(indexPath, "utf8")) as OsvIndex;
    if (parsed.version === 1 && parsed.pin === pin) return parsed;
  } catch {
    // no index yet (or unreadable): fall through to a rebuild
  }
  const rebuilt = await buildIndex(osvDir, pin, read);
  await mkdir(dirname(indexPath), { recursive: true });
  await writeFile(indexPath, JSON.stringify(rebuilt));
  return rebuilt;
}

/** Record file paths (relative) for the given package names. */
export function filesForPackages(index: OsvIndex, names: string[]): string[] {
  const out = new Set<string>();
  for (const name of names) {
    for (const f of index.packages[name] ?? []) out.add(f);
  }
  return [...out].sort();
}

/** Record file paths (relative) that reference any of these aliases. */
export function filesForAliases(index: OsvIndex, aliases: string[]): string[] {
  const out = new Set<string>();
  for (const a of aliases) {
    for (const f of index.aliases[a] ?? []) out.add(f);
  }
  return [...out].sort();
}

export async function listRecordFiles(osvDir: string): Promise<string[]> {
  const out: string[] = [];
  const queue: string[] = [osvDir];
  while (queue.length > 0) {
    const current = queue.pop() as string;
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) queue.push(full);
      else if (entry.isFile() && entry.name.endsWith(".json")) {
        out.push(full.startsWith(`${osvDir}/`) ? full.slice(osvDir.length + 1) : full);
      }
    }
  }
  return out.sort();
}
