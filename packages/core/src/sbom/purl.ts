// Package URL (purl) parsing for the npm ecosystem (plan section 5.1).
//
// Shape: pkg:npm/%40scope/name@1.2.3 — scoped names are percent-encoded
// (the @ becomes %40). Components without an npm purl are skipped with a
// warning (same contract as the JVM tool).

import { UsageError } from "../util/errors.js";

export interface Purl {
  type: string;
  name: string;
  version?: string;
  /** Percent-encoded form exactly as it appeared (round-trip stable). */
  rawName: string;
}

const PURL_RE = /^pkg:([a-z0-9-]+)\/(.+)$/;

/** Parse a purl string; throws UsageError on malformed input (exit 2). */
export function parsePurl(purl: string): Purl {
  const m = PURL_RE.exec(purl.trim());
  if (m === null) {
    throw new UsageError(`malformed purl: ${purl}`);
  }
  const type = m[1] ?? "";
  const rest = m[2] ?? "";
  // Qualifiers/subpaths are not part of the npm purl shape: be strict.
  const queryOrSub = rest.search(/[?#]/);
  if (queryOrSub >= 0) {
    throw new UsageError(`malformed purl (unexpected qualifiers): ${purl}`);
  }
  // The version follows the last '@' (purl spec).
  let namePart = rest;
  let version: string | undefined;
  const at = rest.lastIndexOf("@");
  if (at > 0) {
    version = decodeURIComponent(rest.slice(at + 1));
    namePart = rest.slice(0, at);
  }
  const name = decodeURIComponent(namePart);
  const result: Purl = { type, name, rawName: namePart };
  if (version !== undefined) result.version = version;
  return result;
}

/** True when the purl names an npm package (pkg:npm/...). */
export function isNpmPurl(purl: string): boolean {
  try {
    return parsePurl(purl).type === "npm";
  } catch {
    return false;
  }
}
