#!/usr/bin/env bun
// M6 — binary parity (plan section 7): the compiled binary and the
// interpreted core must produce the SAME reports for every golden demo.
//
// For each examples/vulnerable-demo-* the demo is copied once, then BOTH
// runners are invoked against that copy with identical arguments (same
// --project/--sbom/--osv-dir paths, same extra flags), so the report text is
// directly comparable:
//   interpreted: bun run packages/cli/src/main.ts
//   compiled:    dist/callis-<host>
// Reports are compared per format:
//   JSON  — identical after stripping every durationMillis field
//           (the only non-deterministic field; toolVersion matches by the
//           --define BUILD_VERSION contract, so it is compared as-is)
//   JUnit — identical after redacting the time="..." attributes
//   SARIF — byte-identical (no timing in the document)
//
// Usage: bun scripts/binary-parity.ts [--demo <name>]

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

const argv = process.argv.slice(2);
const demoIdx = argv.indexOf("--demo");
const onlyDemo = demoIdx >= 0 ? argv[demoIdx + 1] : null;

function hostSuffix(): string {
  const sys = process.platform;
  const arch = process.arch;
  if (sys === "win32") return "windows-x64";
  if (sys === "darwin") return arch === "arm64" ? "darwin-arm64" : "darwin-x64";
  return arch === "arm64" ? "linux-arm64" : "linux-x64";
}

const BIN = `dist/callis-${hostSuffix()}`;
if (!existsSync(BIN)) {
  console.error(`error: ${BIN} not found — build it first (bun run build --only ${hostSuffix()})`);
  process.exit(1);
}

/** Strip every durationMillis field (the only non-deterministic JSON field). */
function stripDuration(o: unknown): unknown {
  if (Array.isArray(o)) return o.map(stripDuration);
  if (o !== null && typeof o === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(o as Record<string, unknown>)) {
      if (k === "durationMillis") continue;
      out[k] = stripDuration(v);
    }
    return out;
  }
  return o;
}

function redactJUnit(xml: string): string {
  return xml.replace(/\s*time="[^"]*"/g, "");
}

// A demo's committed fixture is install/; the analyzed tree needs the
// standard node_modules/ layout (gitignored, materialized at run time).
async function materialize(project: string): Promise<void> {
  const install = join(project, "install");
  if (!existsSync(install)) return;
  await rm(join(project, "node_modules"), { recursive: true, force: true });
  await cp(install, join(project, "node_modules"), { recursive: true, dereference: false });
}

function diffFirst(a: string, b: string): string {
  const la = a.split("\n");
  const lb = b.split("\n");
  const n = Math.max(la.length, lb.length);
  for (let i = 0; i < n; i += 1) {
    if (la[i] !== lb[i]) {
      return `line ${i + 1}:\n  interpreted: ${JSON.stringify(la[i])}\n  compiled:    ${JSON.stringify(lb[i])}`;
    }
  }
  return "length mismatch";
}

/** Copy the demo, run ONE runner against it, normalize the reports. */
async function runRunner(cmd: string, cmdArgs: string[], work: string): Promise<{ ok: boolean; detail: string }> {
  const out = join(work, "out");
  const cache = join(work, "cache");
  await mkdir(out, { recursive: true });
  await mkdir(cache, { recursive: true });
  const args = ["--project", work, "--sbom", join(work, "sbom.json"), "--osv-dir", join(work, "osv")];
  if (existsSync(join(work, "vuln-mappings.json"))) args.push("--mappings", join(work, "vuln-mappings.json"));
  if (existsSync(join(work, "extra-flags.txt"))) {
    for (const line of (await readFile(join(work, "extra-flags.txt"), "utf8")).split("\n")) {
      const t = line.trim();
      if (t.length === 0 || t.startsWith("#")) continue;
      args.push(...t.split(/\s+/));
    }
  }
  args.push("--format", "json,junitxml,sarif", "--output", join(out, "report"), "--cache-dir", cache);
  const r = spawnSync(cmd, [...cmdArgs, ...args], { stdio: ["ignore", "pipe", "pipe"] });
  const reportJson = join(out, "report.json");
  if (r.status === null || !existsSync(reportJson)) {
    return { ok: false, detail: `exit ${r.status}, stderr: ${r.stderr.toString().slice(0, 300)}` };
  }
  const norm = join(out, "normalized");
  await mkdir(norm, { recursive: true });
  const json = JSON.stringify(stripDuration(JSON.parse(await readFile(reportJson, "utf8")) as unknown));
  const junit = redactJUnit(await readFile(join(out, "report.junit.xml"), "utf8"));
  const sarif = await readFile(join(out, "report.sarif"), "utf8");
  await writeFile(join(norm, "json"), json);
  await writeFile(join(norm, "junit"), junit);
  await writeFile(join(norm, "sarif"), sarif);
  return { ok: true, detail: "" };
}

async function runDemo(demo: string, scratch: string): Promise<boolean> {
  const name = demo.split("/").pop() as string;
  const work = join(scratch, name);
  await cp(demo, work, { recursive: true });
  await materialize(work);
  let ok = true;
  const results: Record<string, { ok: boolean; detail: string }> = {};
  const normInterpreted = join(work, "normalized-interpreted");
  const runners: [string, string, string[]][] = [
    ["interpreted", "bun", ["run", "packages/cli/src/main.ts"]],
    ["compiled", BIN, []],
  ];
  for (let i = 0; i < runners.length; i += 1) {
    const [runnerName, cmd, cmdArgs] = runners[i] as [string, string, string[]];
    await rm(join(work, "out"), { recursive: true, force: true }).catch(() => {});
    results[runnerName] = await runRunner(cmd, cmdArgs, work);
    if (!results[runnerName].ok) {
      console.log(`FAIL ${name} [${runnerName}]: ${results[runnerName].detail}`);
      ok = false;
    }
    if (i === 0 && ok) {
      await cp(join(work, "out", "normalized"), normInterpreted, { recursive: true });
    }
  }
  if (!ok) return false;

  // The interpreted run's normalized reports were saved before the compiled
  // run overwrote out/; compare them with the compiled run's.
  let failed = false;
  for (const f of ["json", "junit", "sarif"]) {
    const a = await readFile(join(work, "normalized-interpreted", f), "utf8");
    const b = await readFile(join(work, "out", "normalized", f), "utf8");
    if (a !== b) {
      console.log(`FAIL ${name} [${f}]:\n${diffFirst(a, b)}`);
      failed = true;
    }
  }
  if (!failed) console.log(`PASS ${name} (json/junit/sarif identical modulo timing)`);
  return !failed;
}

async function main(): Promise<void> {
  const demos: string[] = (await readdir("examples").catch(() => []))
    .filter((d) => d.startsWith("vulnerable-demo-"))
    .filter((d) => onlyDemo === null || d === onlyDemo)
    .map((d) => join("examples", d))
    .sort();
  if (demos.length === 0) {
    console.error("error: no demos found under examples/");
    process.exit(1);
  }
  const scratch = await mkdtemp(join("/tmp", "callis-parity-"));
  let failures = 0;
  try {
    for (const demo of demos) {
      if (!(await runDemo(demo, scratch))) failures += 1;
    }
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
  if (failures > 0) {
    console.error(`\nbinary-parity: ${failures} demo(s) diverge between interpreted and compiled`);
    process.exit(1);
  }
  console.log(`\nbinary-parity: all ${demos.length} demos identical between interpreted and compiled`);
}

main().catch((e) => {
  console.error(`error: ${(e as Error).stack ?? String(e)}`);
  process.exit(1);
});
