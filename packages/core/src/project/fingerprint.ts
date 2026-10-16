// Deterministic install fingerprint (plan section 5.3, ADR 0014/0015).
//
// Instance identities + realpaths + install-state file contents (npm
// node_modules/.package-lock.json, pnpm .modules.yaml, PnP
// .yarn/install-state.gz — each when present). Joining
// the cache keys makes locally patched packages, lockfile/tree drift, and
// unreadable directories visible instead of silently changing verdicts.
// Same byte-order pin algorithm as the OSV checksum (never localeCompare).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { byteOrderSort, sha256Hex } from "../util/hash.js";
import type { PackageInstance } from "./types.js";

export interface StateFile {
  path: string;
  /** sha256 of the file content (content, not mtime — deterministic). */
  sha256: string;
}

/** Read the install-state files present at the install root (may be none). */
export function readStateFiles(installRoot: string, layout: string): StateFile[] {
  const out: StateFile[] = [];
  const candidates =
    layout === "pnpm"
      ? [join(installRoot, "node_modules", ".modules.yaml")]
      : layout === "pnp"
        ? [join(installRoot, ".yarn", "install-state.gz")]
        : [join(installRoot, "node_modules", ".package-lock.json")];
  for (const path of candidates) {
    try {
      out.push({ path, sha256: sha256Hex(readFileSync(path)) });
    } catch {
      // absent or unreadable: the absence is part of the fingerprint (below)
    }
  }
  return out;
}

/**
 * The fingerprint: sha256 over byte-order-sorted lines
 * `inst <name>@<version> <realDir> <relPath>` + `state <path> <sha256>`
 * (missing state files contribute a `state <path> -` line, so absence is
 * visible), plus a trailing newline.
 */
export function installFingerprint(
  instances: PackageInstance[],
  stateFiles: StateFile[],
  expectedStatePaths: string[],
): string {
  const lines: string[] = [];
  const seen = new Set<string>();
  for (const i of instances) {
    lines.push(`inst ${i.name}@${i.version} ${i.realDir} ${i.relPath}`);
    seen.add(i.realDir);
  }
  const present = new Map(stateFiles.map((s) => [s.path, s.sha256] as const));
  for (const path of expectedStatePaths) {
    const sha = present.get(path);
    lines.push(`state ${path} ${sha ?? "-"}`);
  }
  for (const s of stateFiles) {
    if (!expectedStatePaths.includes(s.path)) lines.push(`state ${s.path} ${s.sha256}`);
  }
  return sha256Hex(`${byteOrderSort(lines).join("\n")}\n`);
}
