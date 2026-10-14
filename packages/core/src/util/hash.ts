// Hashing helpers shared by checksum pinning, cache keys, and the
// normalization contract (plan sections 5.2, 6, 9).

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

/** SHA-256 of a string, hex. */
export function sha256Hex(text: string | Uint8Array): string {
  return createHash("sha256").update(text).digest("hex");
}

/** SHA-256 of a file, hex. */
export function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/**
 * UTF-8 *byte-order* sort (plan section 5.2: never localeCompare — the shell
 * pin uses LC_ALL=C byte comparison, and the two must agree).
 */
export function byteOrderSort(lines: string[]): string[] {
  const out = [...lines];
  out.sort((a, b) => Buffer.from(a, "utf8").compare(Buffer.from(b, "utf8")));
  return out;
}
