// OSV snapshot pin (plan section 5.2).
//
// The pin is sha256 over the "name:filesha256" lines, sorted in BYTE order
// (LC_ALL=C in the shell script; UTF-8 byte comparison here — never
// localeCompare), so the pin is identical between the script and the
// analyzer. At 230k files per-file hashing is the slow step, so it is
// parallelized in chunks.

import { promises as fs } from "node:fs";
import { join, resolve } from "node:path";
import { byteOrderSort, sha256Hex as hashHex, sha256File } from "../util/hash.js";

/** sha256 of every file under dir (recursively), keyed by relative path. */
export async function hashAllFiles(dir: string): Promise<Map<string, string>> {
  // Normalize first: redundant slashes in the argument must not change the
  // relative keys (the pin is a function of the directory contents only).
  const root = resolve(dir);
  const out = new Map<string, string>();
  const queue: string[] = [root];
  while (queue.length > 0) {
    const current = queue.pop() as string;
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        queue.push(full);
      } else if (entry.isFile()) {
        const rel = full.startsWith(`${root}/`) ? full.slice(root.length + 1) : full;
        out.set(rel, await sha256File(full));
      }
    }
  }
  return out;
}

/**
 * The snapshot pin: sha256 over the byte-order-sorted
 * "name:filesha256" lines (trailing newline included, matching the shell
 * `LC_ALL=C sort > lines; sha256sum lines` pipeline).
 */
export async function computePin(dir: string, concurrency = 32): Promise<string> {
  const files = await hashAllFiles(dir);
  const lines = byteOrderSort([...files.entries()].map(([name, sum]) => `${name}:${sum}`));
  return hashHex(Buffer.from(`${lines.join("\n")}\n`, "utf8"));
}
