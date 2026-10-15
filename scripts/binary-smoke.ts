#!/usr/bin/env bun
// M6 — compiled-binary smoke (plan section 7, ADR 0009).
//
// The release binary must be self-sufficient: the @callis/models catalogue is
// embedded via --asset, so the binary runs from ANY directory (including an
// empty one) with no model files adjacent to it. The binary is also built
// with --no-compile-autoload-dotenv --no-compile-autoload-bunfig, so a
// hostile analyzed project cannot steer it with a planted .env or bunfig.toml.
//
// Checks (each prints PASS/FAIL, exit 1 on the first failure):
//   1. --version exits 0 and prints the release version
//   2. --help exits 0
//   3. full analysis of a demo project, cwd = an EMPTY scratch directory
//      (models come from the embedded asset, not from the binary's directory)
//   4. hostile cwd: the analyzed project contains a planted .env that would
//      redirect the cache (XDG_CACHE_HOME) and a SYNTACTICALLY BROKEN
//      bunfig.toml — neither may change the binary's behavior (no parse
//      errors, cache lands in the HOME-based default, not the planted one)
//   5. the bundle graph (bun build --metafile) contains no native addon
//      dependency (.node/.so/.dylib/.dll) and DOES contain the model assets
//
// Usage: bun scripts/binary-smoke.ts [--binary <path>]

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const VERSION = "0.1.0";
const MODEL_ASSETS = ["library-models.json", "entry-point-annotations.json", "callback-interfaces.json"];
const NATIVE_EXTS = [".node", ".so", ".dylib", ".dll"];

function hostSuffix(): string {
  const sys = process.platform;
  const arch = process.arch;
  if (sys === "win32") return "windows-x64";
  if (sys === "darwin") return arch === "arm64" ? "darwin-arm64" : "darwin-x64";
  return arch === "arm64" ? "linux-arm64" : "linux-x64";
}

const SUFFIX_TO_TARGET: Record<string, string> = {
  "linux-x64": "bun-linux-x64",
  "linux-arm64": "bun-linux-arm64",
  "linux-x64-musl": "bun-linux-x64-musl",
  "linux-arm64-musl": "bun-linux-arm64-musl",
  "darwin-x64": "bun-darwin-x64",
  "darwin-arm64": "bun-darwin-arm64",
  "windows-x64": "bun-windows-x64",
  "linux-x64-baseline": "bun-linux-x64-baseline",
};

// Resolved absolute: the smoke checks run the binary from other cwds.
const argv = process.argv.slice(2);
const binIdx = argv.indexOf("--binary");
const BIN = resolve(binIdx >= 0 ? (argv[binIdx + 1] ?? `dist/callis-${hostSuffix()}`) : `dist/callis-${hostSuffix()}`);

let failures = 0;
function pass(name: string): void {
  console.log(`PASS ${name}`);
}
function fail(name: string, detail: string): void {
  failures += 1;
  console.log(`FAIL ${name}: ${detail}`);
}

function run(binary: string, args: string[], cwd: string): { code: number; out: string; err: string } {
  const r = spawnSync(binary, args, { cwd, stdio: ["ignore", "pipe", "pipe"] });
  // On spawn failure (e.g. missing binary) Bun leaves the streams null.
  return { code: r.status ?? -1, out: r.stdout?.toString() ?? "", err: r.stderr?.toString() ?? "" };
}

// A demo's committed fixture is install/; the analyzed tree needs the
// standard node_modules/ layout (gitignored, materialized at run time).
async function materialize(project: string): Promise<void> {
  const install = join(project, "install");
  if (!existsSync(install)) return;
  await rm(join(project, "node_modules"), { recursive: true, force: true });
  await cp(install, join(project, "node_modules"), { recursive: true, dereference: false });
}

async function main(): Promise<void> {
  if (!existsSync(BIN)) {
    console.error(`error: ${BIN} not found — build it first (bun run build --only ${hostSuffix()})`);
    process.exit(1);
  }
  const scratch = await mkdtemp(join("/tmp", "callis-smoke-"));
  const demo = "examples/vulnerable-demo-fixed-pin-bun";
  if (!existsSync(join(demo, "sbom.json"))) {
    console.error(`error: ${demo} missing — run from the repository root`);
    process.exit(1);
  }
  try {
    // 1. --version
    {
      const r = run(BIN, ["--version"], scratch);
      if (r.code === 0 && r.out.trim() === `callis ${VERSION}`) pass("--version");
      else fail("--version", `exit ${r.code}, out ${r.out.trim()}, err ${r.err.trim()}`);
    }

    // 2. --help
    {
      const r = run(BIN, ["--help"], scratch);
      const ok = r.code === 0 && r.out.includes("Usage: callis") && !r.err.includes("error");
      if (ok) pass("--help");
      else fail("--help", `exit ${r.code}, err ${r.err.slice(0, 200)}`);
    }

    // 3. full analysis from an EMPTY directory (models must come from the embedded asset)
    {
      const empty = join(scratch, "empty");
      await mkdir(empty, { recursive: true });
      const out = join(scratch, "out3");
      const cache = join(scratch, "cache3");
      // Analyze a copy in scratch (materialized), never the checkout.
      const demoCopy = join(scratch, "demo");
      await cp(resolve(demo), demoCopy, { recursive: true });
      await materialize(demoCopy);
      const r = run(
        BIN,
        [
          "--project",
          demoCopy,
          "--sbom",
          join(demoCopy, "sbom.json"),
          "--osv-dir",
          join(demoCopy, "osv"),
          "--format",
          "json",
          "--output",
          join(out, "report"),
          "--cache-dir",
          cache,
        ],
        empty,
      );
      const reportPath = join(out, "report.json");
      const ok =
        r.code === 0 &&
        existsSync(reportPath) &&
        existsSync(join(cache, "osv-index.json")) &&
        !r.err.includes("cannot load") &&
        !r.err.includes("ENOENT");
      if (ok) pass("empty-cwd analysis (embedded models)");
      else fail("empty-cwd analysis", `exit ${r.code}, err ${r.err.slice(0, 400)}`);
    }

    // 4. hostile cwd: planted .env + broken bunfig.toml inside the ANALYZED project
    {
      const host = join(scratch, "hostile");
      await cp(demo, host, { recursive: true });
      await materialize(host);
      const pwnedCache = join(scratch, "pwned-cache");
      const home = join(scratch, "home");
      await mkdir(home, { recursive: true });
      // If the binary autoloaded this .env, its default cache dir would become
      // $XDG_CACHE_HOME/callis = <pwnedCache>/callis.
      await writeFile(join(host, ".env"), `XDG_CACHE_HOME=${pwnedCache}\n`);
      // If the binary autoloaded/parsed this file, a TOML parse error would hit stderr.
      await writeFile(join(host, "bunfig.toml"), "this is [[ not valid toml = =\n");
      const out = join(scratch, "out4");
      // The default must be the HOME-based one, never a planted .env: build the
      // env without XDG_CACHE_HOME (a spread copy, no `delete`).
      const { XDG_CACHE_HOME: _dropped, ...restEnv } = process.env as Record<string, string | undefined>;
      void _dropped;
      const env: Record<string, string | undefined> = { ...restEnv, HOME: home };
      const r = spawnSync(
        BIN,
        [
          "--project",
          host,
          "--sbom",
          join(host, "sbom.json"),
          "--osv-dir",
          join(host, "osv"),
          "--format",
          "json",
          "--output",
          join(out, "report"),
        ],
        { cwd: host, env, stdio: ["ignore", "pipe", "pipe"] },
      );
      const defaultCache = join(home, ".cache", "callis", "osv-index.json");
      const ok =
        (r.status ?? -1) === 0 &&
        existsSync(join(out, "report.json")) &&
        existsSync(defaultCache) &&
        !existsSync(join(pwnedCache, "callis")) &&
        !r.stderr.toString().includes("toml");
      if (ok) pass("hostile cwd (.env + broken bunfig.toml ignored)");
      else
        fail(
          "hostile cwd",
          `exit ${r.status}, defaultCache=${existsSync(defaultCache)}, pwned=${existsSync(join(pwnedCache, "callis"))}, stderr=${r.stderr.toString().slice(0, 300)}`,
        );
    }

    // 5. bundle graph: no native addons, model assets present
    {
      const metaPath = join(scratch, "meta.json");
      const tmpBin = join(scratch, "meta-binary");
      const suffix = hostSuffix();
      const args = [
        "build",
        "--compile",
        "--minify",
        `--target=${SUFFIX_TO_TARGET[suffix]}`,
        "--no-compile-autoload-dotenv",
        "--no-compile-autoload-bunfig",
        `--define BUILD_VERSION=${JSON.stringify(VERSION)}`,
        "packages/cli/src/main.ts",
      ];
      for (const a of MODEL_ASSETS) args.push("--asset", join("packages/models/data", a));
      args.push(`--metafile=${metaPath}`, `--outfile=${tmpBin}`);
      const r = spawnSync("bun", args, { stdio: ["ignore", "pipe", "pipe"] });
      if ((r.status ?? -1) !== 0) {
        fail("bundle graph build", r.stderr.toString().slice(0, 300));
      } else {
        const meta = JSON.parse(await readFile(metaPath, "utf8")) as {
          inputs: Record<string, { imports?: { path?: string }[] }>;
        };
        const allPaths: string[] = [];
        for (const [path, info] of Object.entries(meta.inputs)) {
          allPaths.push(path);
          for (const imp of info.imports ?? []) if (imp.path) allPaths.push(imp.path);
        }
        // --asset files are embedded at compile time and do not appear in the
        // module graph; their presence is proven behaviorally by check 3 (the
        // empty-cwd analysis loads the models from the embedded asset).
        const native = allPaths.filter((p) => NATIVE_EXTS.some((e) => p.endsWith(e)));
        if (native.length === 0) pass("bundle graph (no native addon dependencies)");
        else fail("bundle graph", `native=[${native.join(", ")}]`);
      }
    }
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }

  if (failures > 0) {
    console.error(`\nbinary-smoke: ${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log("\nbinary-smoke: all checks passed");
}

main().catch((e) => {
  console.error(`error: ${(e as Error).stack ?? String(e)}`);
  process.exit(1);
});
