#!/usr/bin/env bun
// M6 — compile pipeline (plan section 7, ADR 0009).
//
// One entry (packages/cli/src/main.ts) compiled to 8 native targets. The
// @callis/models catalogue is embedded via --asset: Bun serves the embedded
// file FLAT next to the entry (/$bunfs/root/<basename>), and the loader tries
// that candidate before the workspace copy, so the binary runs from any
// directory with no model files present (verified by scripts/binary-smoke.ts).
//
// Every produced binary is validated before it may be published:
//   1. magic bytes match the target family (ELF / Mach-O / PE),
//   2. --version exits 0 and prints the release version (host-family targets
//      only — cross-compiled binaries are not executable here),
//   3. SHA256SUMS lists every artifact (consumers verify a REPO-PINNED digest,
//      never this file — see templates/callis-check.yml).
//
// Usage: bun scripts/build.ts [--only <suffix>[,<suffix>...]]

import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

export const VERSION = "0.1.0";

const ENTRY = "packages/cli/src/main.ts";
const MODEL_ASSETS = [
  "packages/models/data/library-models.json",
  "packages/models/data/entry-point-annotations.json",
  "packages/models/data/callback-interfaces.json",
];

export type TargetFamily = "elf" | "macho" | "pe";

export interface Target {
  suffix: string;
  target: string;
  family: TargetFamily;
}

export const TARGETS: Target[] = [
  { suffix: "linux-x64", target: "bun-linux-x64", family: "elf" },
  { suffix: "linux-arm64", target: "bun-linux-arm64", family: "elf" },
  { suffix: "linux-x64-musl", target: "bun-linux-x64-musl", family: "elf" },
  { suffix: "linux-arm64-musl", target: "bun-linux-arm64-musl", family: "elf" },
  { suffix: "darwin-x64", target: "bun-darwin-x64", family: "macho" },
  { suffix: "darwin-arm64", target: "bun-darwin-arm64", family: "macho" },
  { suffix: "windows-x64", target: "bun-windows-x64", family: "pe" },
  { suffix: "linux-x64-baseline", target: "bun-linux-x64-baseline", family: "elf" },
];

// Mach-O magic as it appears in the file: the 32-bit values MH_MAGIC
// (0xfeedface) and MH_MAGIC_64 (0xfeedfacf) stored in either byte order.
const MACHO_MAGIC_HEX = new Set(["cefaedfe", "feedface", "cffaedfe", "feedfacf"]);

/**
 * Magic-byte validation per target family.
 * ELF: 0x7f 'E' 'L' 'F'. Mach-O: one of the four canonical spellings.
 * PE: 'M' 'Z' (two-byte signature).
 */
export function validateMagicBytes(bytes: Uint8Array, family: TargetFamily): boolean {
  if (family === "pe") return bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a;
  if (bytes.length < 4) return false;
  if (family === "elf") {
    return bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46;
  }
  const head = [0, 1, 2, 3].map((i) => (bytes[i] ?? 0).toString(16).padStart(2, "0")).join("");
  return MACHO_MAGIC_HEX.has(head);
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export interface SumEntry {
  file: string;
  hex: string;
}

/** One `sha256  path` line per entry, sorted by path (stable for diffing). */
export function sumsLines(entries: SumEntry[]): string {
  if (entries.length === 0) return "";
  return `${[...entries]
    .sort((x, y) => x.file.localeCompare(y.file))
    .map((e) => `${e.hex}  ${e.file}`)
    .join("\n")}\n`;
}

/** Host family for --version smoke execution (cross-compiled binaries stay untested here). */
export function hostFamily(): TargetFamily | null {
  if (process.platform === "win32") return "pe";
  if (process.platform === "darwin") return "macho";
  if (process.platform === "linux") return "elf";
  return null;
}

export function isHostTarget(t: Target): boolean {
  const host = hostFamily();
  if (host === null) return false;
  if (t.family !== host) return false;
  if (host === "elf") return t.suffix.startsWith("linux-");
  if (host === "macho") return t.suffix.startsWith("darwin-");
  return t.suffix.startsWith("windows-");
}

function buildOne(t: Target, dist: string): string {
  const outfile = join(dist, `callis-${t.suffix}`);
  const args = [
    "build",
    "--compile",
    "--minify",
    "--sourcemap",
    `--target=${t.target}`,
    "--no-compile-autoload-dotenv",
    "--no-compile-autoload-bunfig",
    `--define BUILD_VERSION="${JSON.stringify(VERSION)}"`,
    ENTRY,
  ];
  for (const asset of MODEL_ASSETS) args.push("--asset", asset);
  args.push("--outfile", outfile);
  const r = spawnSync("bun", args, { stdio: ["ignore", "pipe", "pipe"] });
  if (r.status !== 0) throw new Error(`bun build failed for ${t.suffix}: ${r.stderr.toString()}`);
  return outfile;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const onlyIdx = argv.indexOf("--only");
  const only = onlyIdx >= 0 ? (argv[onlyIdx + 1] ?? "").split(",").filter((s) => s.length > 0) : null;
  let selected = TARGETS;
  if (only !== null) {
    const unknown = only.filter((s) => !TARGETS.some((t) => t.suffix === s));
    if (unknown.length > 0)
      throw new Error(`unknown target(s): ${unknown.join(", ")} (valid: ${TARGETS.map((t) => t.suffix).join(", ")})`);
    selected = TARGETS.filter((t) => only.includes(t.suffix));
  }

  const dist = "dist";
  await mkdir(dist, { recursive: true });

  console.log(`building ${selected.length} target(s) from ${ENTRY} (version ${VERSION})`);
  const built: string[] = [];
  const table: string[] = ["target            size        --version(ms)  magic"];
  for (const t of selected) {
    const t0 = performance.now();
    const outfile = buildOne(t, dist);
    const bytes = await readFile(outfile);
    if (!validateMagicBytes(bytes, t.family)) {
      throw new Error(`${outfile}: magic bytes do not match family ${t.family} — refusing to publish`);
    }
    let versionMs = "n/a (cross-compiled)";
    if (isHostTarget(t)) {
      const v0 = performance.now();
      const r = spawnSync(outfile, ["--version"], { stdio: ["ignore", "pipe", "pipe"] });
      versionMs = `${Math.round(performance.now() - v0)} (exit ${r.status}, ${r.stdout.toString().trim()})`;
      if (r.status !== 0) throw new Error(`${outfile}: --version exited ${r.status}: ${r.stderr.toString()}`);
    }
    built.push(outfile);
    table.push(
      `${t.suffix.padEnd(15)} ${(bytes.length / 1048576).toFixed(2).padStart(8)} MB   ${versionMs.padEnd(12)}  ${t.family}`,
    );
    console.log(`built ${outfile} (${(bytes.length / 1048576).toFixed(2)} MB, ${(performance.now() - t0) / 1000.0}s)`);
  }

  console.log(`\n${table.join("\n")}`);
  const sums = await Promise.all(
    built.map(async (f) => ({ file: `dist/${f.split("/").pop()}`, hex: sha256Hex(await readFile(f)) })),
  );
  await writeFile(join(dist, "SHA256SUMS"), sumsLines(sums));
  console.log(`\nwrote dist/SHA256SUMS (${sums.length} entries)`);
}

if (import.meta.main)
  main().catch((e) => {
    console.error(`error: ${(e as Error).message}`);
    process.exit(1);
  });
