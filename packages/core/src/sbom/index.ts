// SBOM input entry point: auto-detect CycloneDX vs SPDX 2.x (plan section
// 5.1). SPDX 3.x, unknown bomFormat, or neither marker: explicit error,
// exit 2 (UsageError, JVM ADR 0016 parity).

import { readFileSync } from "node:fs";
import { UsageError } from "../util/errors.js";
import { sha256Hex } from "../util/hash.js";
import { parseCycloneDx } from "./cyclonedx.js";
import { parseSpdx } from "./spdx.js";
import type { NpmComponent, SbomParseResult } from "./types.js";

export * from "./purl.js";
export * from "./types.js";

export function readSbom(file: string): SbomParseResult {
  let json: string;
  try {
    json = readFileSync(file, "utf8");
  } catch (e) {
    throw new UsageError(`SBOM file not readable: ${file}: ${(e as Error).message}`);
  }
  const fileSha256 = sha256Hex(json);
  const doc = json.trim().startsWith("{") ? (JSON.parse(json) as Record<string, unknown>) : null;
  if (doc === null) {
    throw new UsageError(`SBOM is not a JSON document: ${file}`);
  }
  if (doc.bomFormat === "CycloneDX") {
    return parseCycloneDx(json, file, fileSha256);
  }
  if (typeof doc.spdxVersion === "string") {
    return parseSpdx(json, file, fileSha256);
  }
  throw new UsageError(`SBOM format not recognized: neither CycloneDX nor SPDX 2.x marker in ${file}`);
}

/**
 * Supply path from the SBOM dependencies graph (plan section 5.1): the
 * human-readable chain app -> express -> qs shown alongside the code-level
 * trace. Walks from the application ref toward the component ref.
 */
export function supplyPath(deps: { ref: string; dependsOn: string[] }[], from: string, to: string): string[] {
  const edges = new Map(deps.map((d) => [d.ref, d.dependsOn]));
  if (from === to) return [to];
  // BFS from `from` following dependsOn; the shortest path wins and ties
  // break lexicographically (sorted neighbor lists, normalization contract).
  const queue: string[][] = [[from]];
  const seen = new Set([from]);
  while (queue.length > 0) {
    const path = queue.shift() as string[];
    const last = path[path.length - 1] as string;
    const next = [...(edges.get(last) ?? [])].sort();
    for (const n of next) {
      if (seen.has(n)) continue;
      const extended = [...path, n];
      if (n === to) return extended;
      seen.add(n);
      queue.push(extended);
    }
  }
  return [];
}

export type { NpmComponent, SbomParseResult };
