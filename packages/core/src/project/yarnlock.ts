// M7c — Yarn berry lockfile parser (ADR 0005 profile (c), ADR 0014).
//
// A strict-subset parser for the MACHINE-GENERATED berry format
// (`__metadata.version >= 2`, as written by Yarn 2/3/4): entry keys are
// comma-separated descriptor lists (`"name@range, name@npm:range, …"`),
// bodies are two-level maps. No YAML dependency is added — the berry output
// is a fixed 2-space/4-space layout, and a line that does not fit the shape
// is a UsageError (record the gap, don't guess: the same discipline as the
// unparsed bun.lock). Yarn 1.x classic lockfiles (no `__metadata`) are
// REFUSED explicitly — such projects use node_modules and are already
// supported as the npm layout.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { UsageError } from "../util/errors.js";

export interface YarnDescriptor {
  name: string;
  /** `npm` (default), `workspace`, `portal`, … */
  protocol: string;
  /** The range without the peer suffix (`^1.2.3`, `4.17.21`, `workspace:^` …). */
  range: string;
  /** The peer suffix `(...)` verbatim, or "". */
  peers: string;
}

export interface YarnLockEntry {
  name: string;
  /** The entry's resolved version ("" for workspace entries). */
  version: string;
  protocol: string;
  /** Every descriptor that keys this entry (range aliases included). */
  descriptors: string[];
  /** dep name → descriptor (dependencies + optionalDependencies merged). */
  dependencies: Map<string, string>;
  /** dep name → descriptor (peerDependencies — kept separate: they are
   *  conditional and must not become unconditional graph edges). */
  peerDependencies: Map<string, string>;
  checksum?: string;
}

/**
 * A dependency-map value is usually a bare range (`ms: 2.1.3` →
 * `ms@2.1.3`) or a protocol-prefixed range (`myapp: workspace:^` →
 * `myapp@workspace:^`); a value whose part before the `@` is a valid
 * package name is already a full descriptor (alias `realpkg@^1.0.0`,
 * workspace `myapp@workspace:^`) and is kept as-is.
 */
export function toDescriptor(depName: string, raw: string): string {
  const at = raw.indexOf("@", raw.startsWith("@") ? 1 : 0);
  if (at > 0) {
    const namePart = raw.slice(0, at);
    if (/^(@[A-Za-z0-9._~-]+\/)?[A-Za-z0-9._~-]+$/.test(namePart)) return raw;
  }
  return `${depName}@${raw}`;
}

/** Split one descriptor (`name[@protocol:range[(peers)]`) into its parts. */
export function parseDescriptor(desc: string): YarnDescriptor {
  let name: string;
  let rest: string;
  if (desc.startsWith("@")) {
    const i = desc.indexOf("@", 1);
    if (i < 0) return { name: desc, protocol: "", range: "", peers: "" };
    name = desc.slice(0, i);
    rest = desc.slice(i + 1);
  } else {
    const i = desc.indexOf("@");
    if (i < 0) return { name: desc, protocol: "", range: "", peers: "" };
    name = desc.slice(0, i);
    rest = desc.slice(i + 1);
  }
  let protocol = "npm";
  let body = rest;
  if (rest.startsWith("@")) {
    const ci = rest.indexOf(":");
    if (ci < 0) {
      protocol = rest.slice(1);
      body = "";
    } else {
      protocol = rest.slice(1, ci);
      body = rest.slice(ci + 1);
    }
  } else {
    // `npm:1.0.0` / `workspace:^` / bare `^1.0.0`
    const ci = rest.indexOf(":");
    if (ci > 0) {
      protocol = rest.slice(0, ci);
      body = rest.slice(ci + 1);
    }
  }
  let range = body;
  let peers = "";
  const pi = body.indexOf("(");
  if (pi >= 0 && body.endsWith(")")) {
    range = body.slice(0, pi);
    peers = body.slice(pi);
  }
  return { name, protocol, range, peers };
}

/**
 * Parse berry lockfile text. UsageError on any line outside the strict
 * subset (including a non-berry / yarn 1.x classic file).
 */
export function parseYarnLock(text: string): YarnLockEntry[] {
  const lines = text.split(/\r?\n/);
  let i = 0;

  // __metadata header (required — its absence means a non-berry lockfile).
  // Skip blank/comment lines; the FIRST column-0 content must be the header.
  let berryVersion: number | null = null;
  while (i < lines.length) {
    const line = lines[i] ?? "";
    const trimmed = line.trim();
    if (trimmed === "" || line.startsWith("#")) {
      i += 1;
      continue;
    }
    if (line.startsWith(" ")) {
      throw new UsageError(`yarn.lock line ${i + 1}: unexpected indented content before __metadata: ${trimmed}`);
    }
    const m = /^(\w+):\s*(.*)$/.exec(line);
    if (m !== null && m[1] === "__metadata") {
      i += 1;
      while (i < lines.length) {
        const l2 = lines[i] ?? "";
        if (l2.trim() === "" || l2.startsWith("#")) {
          i += 1;
          continue;
        }
        if (!/^ {2}\S/.test(l2)) break;
        const mv = /^ {2}version:\s*(\d+)\s*$/.exec(l2);
        if (mv !== null && mv[1] !== undefined) berryVersion = Number(mv[1]);
        i += 1;
      }
      break;
    }
    throw new UsageError(`yarn.lock line ${i + 1} is not a berry lockfile (entry before __metadata): ${trimmed}`);
  }
  if (berryVersion === null) {
    throw new UsageError(
      "yarn.lock is not a berry (Yarn 2/3/4) lockfile (no __metadata header) — yarn 1.x classic lockfiles are not supported; such projects use node_modules and are supported as the npm layout",
    );
  }
  if (berryVersion < 2) {
    throw new UsageError(`yarn.lock __metadata version ${berryVersion} is not supported (need >= 2)`);
  }

  const entries: YarnLockEntry[] = [];
  while (i < lines.length) {
    const line = lines[i] ?? "";
    if (line.trim() === "" || line.startsWith("#")) {
      i += 1;
      continue;
    }
    if (line.startsWith(" ")) {
      throw new UsageError(`yarn.lock line ${i + 1}: unexpected indentation outside an entry: ${line.trim()}`);
    }

    // Entry key: quoted `"d1, d2":` or unquoted `d1:`.
    let key: string;
    if (line.startsWith('"')) {
      const end = line.indexOf('":');
      if (end < 0) throw new UsageError(`yarn.lock line ${i + 1}: unterminated entry key: ${line.trim()}`);
      key = line.slice(1, end);
    } else {
      const ci = line.indexOf(":");
      if (ci < 0) throw new UsageError(`yarn.lock line ${i + 1}: not an entry key: ${line.trim()}`);
      key = line.slice(0, ci).trim();
    }
    i += 1;
    const descriptors = key
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    const first = parseDescriptor(descriptors[0] ?? "");
    const entry: YarnLockEntry = {
      name: first.name,
      version: "",
      protocol: first.protocol,
      descriptors,
      dependencies: new Map(),
      peerDependencies: new Map(),
    };

    let section: "none" | "deps" | "peers" | "optional" = "none";
    while (i < lines.length) {
      const l = lines[i] ?? "";
      if (l.trim() === "" || l.startsWith("#")) {
        i += 1;
        continue;
      }
      if (!l.startsWith(" ")) break; // next entry key
      if (/^ {2}[A-Za-z_]+\s*:/.test(l) && !/^ {4}/.test(l)) {
        const m = /^ {2}([A-Za-z_]+):\s*(.*)$/.exec(l);
        if (m === null || m[1] === undefined) {
          throw new UsageError(`yarn.lock line ${i + 1}: not parseable: ${l.trim()}`);
        }
        const k = m[1];
        const v = m[2] ?? "";
        if (v === "") {
          section =
            k === "dependencies" || k === "optionalDependencies" ? "deps" : k === "peerDependencies" ? "peers" : "none";
        } else {
          section = "none";
          const unquoted = v.startsWith('"') && v.endsWith('"') ? v.slice(1, -1) : v;
          if (k === "version") entry.version = unquoted;
          else if (k === "checksum") entry.checksum = unquoted;
          // other scalars (resolution, languageName, engines, …) are ignored
        }
        i += 1;
        continue;
      }
      if (/^ {4}[A-Za-z@][^:]*:\s*\S.*$/.test(l) || /^ {4}[^:]+:\s*$/u.test(l)) {
        const m = /^ {4}([^:]+):\s*(.*)$/.exec(l);
        if (m === null || m[1] === undefined || m[2] === undefined) {
          throw new UsageError(`yarn.lock line ${i + 1}: not parseable: ${l.trim()}`);
        }
        const depName = m[1].trim();
        const depDesc = m[2].trim();
        if (section === "deps") entry.dependencies.set(depName, toDescriptor(depName, depDesc));
        else if (section === "peers") entry.peerDependencies.set(depName, toDescriptor(depName, depDesc));
        i += 1;
        continue;
      }
      throw new UsageError(`yarn.lock line ${i + 1} is not parseable berry format: ${l.trim()}`);
    }
    entries.push(entry);
  }
  return entries;
}

/** Parse `<root>/yarn.lock`; null when the file is absent. */
export function parseYarnLockFile(root: string): YarnLockEntry[] | null {
  const file = join(root, "yarn.lock");
  if (!existsSync(file)) return null;
  return parseYarnLock(readFileSync(file, "utf8"));
}
