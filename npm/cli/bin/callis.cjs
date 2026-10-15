#!/usr/bin/env node
// @callis/cli shim (M7d, the esbuild/Biome pattern): no build step and no
// native dependencies in the main package. The platform binary comes from
// the @callis/cli-<platform> optional dependencies (each carries os/cpu/
// libc fields, so only the matching ones install); this shim locates the
// right one and execs it with all arguments.
//
// Selection (see selectPackage): the runner OS/arch plus two host probes —
// a musl loader present -> the -musl asset; an x64 host without the AVX2
// CPU flag -> the -baseline asset (when it is installed).
//
// Probe paths are overridable for tests / unusual hosts:
//   CALLIS_CLI_PLATFORM   process.platform override (linux/darwin/win32)
//   CALLIS_CLI_ARCH       process.arch override (x64/arm64/...)
//   CALLIS_CLI_MUSL       1/0 — the musl probe result
//   CALLIS_CLI_AVX2       1/0 — the AVX2 probe result
//   CALLIS_CLI_NODE_MODULES  an extra node_modules root to search first
//   CALLIS_CLI_BIN        run this binary instead of resolving (air-gapped)

"use strict";

const { existsSync, readFileSync } = require("node:fs");
const { spawnSync } = require("node:child_process");
const { arch, platform } = require("node:os");
const { createRequire } = require("node:module");
const { dirname, join } = require("node:path");

/** Asset file inside each platform package (the publish workflow stages
 *  the built binary under this name). */
const BINARY_BY_PACKAGE = {
  "cli-linux-x64": "callis-linux-x64",
  "cli-linux-x64-musl": "callis-linux-x64-musl",
  "cli-linux-x64-baseline": "callis-linux-x64-baseline",
  "cli-linux-arm64": "callis-linux-arm64",
  "cli-linux-arm64-musl": "callis-linux-arm64-musl",
  "cli-darwin-x64": "callis-darwin-x64",
  "cli-darwin-arm64": "callis-darwin-arm64",
  "cli-windows-x64": "callis-windows-x64.exe",
};

const MUSL_LIBS = [
  "/lib64/ld-musl-x86-64.so.3",
  "/lib/ld-musl-x86-64.so.7",
  "/lib64/ld-musl-aarch64.so.1",
  "/lib/ld-musl-aarch64.so.1",
];

function detectMusl() {
  const override = process.env.CALLIS_CLI_MUSL;
  if (override !== undefined) return override === "1";
  return MUSL_LIBS.some((p) => existsSync(p));
}

function detectAvx2() {
  const override = process.env.CALLIS_CLI_AVX2;
  if (override !== undefined) return override === "1";
  try {
    return /\bavx2\b/.test(readFileSync("/proc/cpuinfo", "utf8"));
  } catch {
    return true; // unprobeable host: assume a modern CPU
  }
}

/** The @callis/cli-<platform> package for this host, or null (not
 *  published here). Pure: takes the probes as data (the install-matrix
 *  test drives it directly). */
function selectPackage({ platformName, archName, musl, avx2, installed }) {
  const have = (name) => installed.includes(name);
  if (platformName === "win32") {
    return archName === "x64" && have("cli-windows-x64") ? "cli-windows-x64" : null;
  }
  if (platformName === "darwin") {
    const a = archName === "arm64" ? "cli-darwin-arm64" : archName === "x64" ? "cli-darwin-x64" : null;
    return a !== null && have(a) ? a : null;
  }
  if (platformName === "linux") {
    if (archName === "arm64") {
      const a = musl ? "cli-linux-arm64-musl" : "cli-linux-arm64";
      return have(a) ? a : null;
    }
    if (archName === "x64") {
      if (musl) return have("cli-linux-x64-musl") ? "cli-linux-x64-musl" : null;
      // glibc x64: the no-AVX2 baseline wins when it is installed AND the
      // host lacks AVX2 (it is a plain glibc build, so musl never gets it).
      if (!avx2 && have("cli-linux-x64-baseline")) return "cli-linux-x64-baseline";
      return have("cli-linux-x64") ? "cli-linux-x64" : null;
    }
    return null; // 32-bit / riscv64 linux: no asset published
  }
  return null;
}

/** The directory of one installed @callis package (null when absent). */
function platformPackageDir(name) {
  const roots = [];
  if (process.env.CALLIS_CLI_NODE_MODULES !== undefined) roots.push(process.env.CALLIS_CLI_NODE_MODULES);
  try {
    roots.push(dirname(createRequire(__filename).resolve(`@callis/${name}/package.json`)));
  } catch {
    // not installed from this shim's location
  }
  roots.push(join(__dirname, "..", "..", "node_modules"));
  for (const root of roots) {
    const dir = join(root, "@callis", name);
    if (existsSync(join(dir, "package.json"))) return dir;
  }
  return null;
}

/** The executable to run (null + the reason when nothing fits). */
function resolveBinary() {
  const platformName = process.env.CALLIS_CLI_PLATFORM ?? platform();
  const archName = process.env.CALLIS_CLI_ARCH ?? arch();
  const names = Object.keys(BINARY_BY_PACKAGE);
  const installed = names.filter((n) => platformPackageDir(n) !== null);
  const name = selectPackage({ platformName, archName, musl: detectMusl(), avx2: detectAvx2(), installed });
  if (name === null) {
    return {
      bin: null,
      reason: `no @callis/${name ?? "cli-<platform>"} package is installed for ${platformName}/${archName}`,
    };
  }
  const dir = platformPackageDir(name);
  const bin = join(dir, BINARY_BY_PACKAGE[name]);
  if (dir === null || !existsSync(bin))
    return { bin: null, reason: `@callis/${name} is present but ${BINARY_BY_PACKAGE[name]} is missing` };
  if (platformName !== "win32") {
    try {
      const { chmodSync } = require("node:fs");
      chmodSync(bin, 0o755);
    } catch {
      // not the owner: spawn surfaces the real error
    }
  }
  return { bin, reason: "" };
}

function main() {
  if (process.argv.includes("--print-selection")) {
    const r =
      process.env.CALLIS_CLI_BIN !== undefined ? { bin: process.env.CALLIS_CLI_BIN, reason: "" } : resolveBinary();
    process.stdout.write(r.bin !== null ? r.bin : `none: ${r.reason}\n`);
    process.exit(r.bin === null ? 1 : 0);
  }

  const bin = process.env.CALLIS_CLI_BIN !== undefined ? process.env.CALLIS_CLI_BIN : null;
  const resolved = bin === null ? resolveBinary() : { bin, reason: "" };
  if (resolved.bin === null) {
    process.stderr.write(`callis: ${resolved.reason}\n`);
    process.stderr.write(
      "callis: reinstall @callis/cli (the platform package is an optionalDependency), or set CALLIS_CLI_BIN to a local binary.\n",
    );
    process.exit(2);
  }

  const r = spawnSync(resolved.bin, process.argv.slice(2), { stdio: "inherit" });
  if (r.error !== undefined) {
    process.stderr.write(`callis: cannot run ${resolved.bin}: ${r.error.message}\n`);
    process.exit(3);
  }
  process.exit(r.status ?? 3);
}

if (require.main === module) main();

module.exports = { selectPackage, BINARY_BY_PACKAGE };
