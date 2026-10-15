// M5 — end-to-end exit-code matrix (plan section 9): the REAL CLI, spawned
// in throwaway project trees. Every 0/1/2/3 condition of the plan matrix:
// usage errors (2), guard failures with minimal reports (3), reachable /
// malicious / opaque-native / fail-on-applicable / match-installed (1),
// clean / unreachable / all-dev / sbom-only (0), exitReasons co-occurrence,
// stale-report deletion, and the --dry-run trio.

import { afterAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkFixture, pkg } from "./project.fixtures.js";

const CLI = join(import.meta.dir, "..", "..", "cli", "src", "main.ts");

function run(args: string[]): { code: number; out: string; err: string } {
  const r = Bun.spawnSync(["bun", CLI, ...args], { stdout: "pipe", stderr: "pipe" });
  return { code: r.exitCode, out: r.stdout.toString(), err: r.stderr.toString() };
}

/** Spawn with a controlled environment (values: set, undefined: remove). */
function runWithEnv(
  args: string[],
  env: Record<string, string | undefined>,
): { code: number; out: string; err: string } {
  const allEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined) allEnv[k] = v;
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) delete allEnv[k];
    else allEnv[k] = v;
  }
  const r = Bun.spawnSync(["bun", CLI, ...args], { stdout: "pipe", stderr: "pipe", env: allEnv });
  return { code: r.exitCode, out: r.stdout.toString(), err: r.stderr.toString() };
}

// One app that CALLS the vulnerable package (the REACHABLE fixture).
async function callTree(extra: Record<string, string> = {}): Promise<string> {
  return mkFixture({
    files: {
      "package.json": pkg("app", "1.0.0", { main: "src/main.js" }),
      "src/main.js": `const pkg = require("vulnpkg");\npkg.vuln();\n`,
      "node_modules/vulnpkg/package.json": pkg("vulnpkg", "1.0.0"),
      "node_modules/vulnpkg/index.js": "module.exports = { vuln: function vuln() { return 1; } };\n",
      ...extra,
    },
  });
}

// The app only IMPORTS the package (loaded, never called).
async function importTree(extra: Record<string, string> = {}): Promise<string> {
  return mkFixture({
    files: {
      "package.json": pkg("app", "1.0.0", { main: "src/main.js" }),
      "src/main.js": `require("vulnpkg");\n`,
      "node_modules/vulnpkg/package.json": pkg("vulnpkg", "1.0.0"),
      "node_modules/vulnpkg/index.js": "module.exports = { vuln: function vuln() { return 1; } };\n",
      ...extra,
    },
  });
}

function recordFile(id: string, name: string, fixed?: string, versions: string[] = []): string {
  const entry: Record<string, unknown> = { package: { name, ecosystem: "npm" } };
  const ranges: unknown[] = [];
  if (fixed !== undefined) ranges.push({ type: "SEMVER", events: [{ introduced: "0" }, { fixed }] });
  if (ranges.length > 0) entry.ranges = ranges;
  if (versions.length > 0) entry.versions = versions;
  return JSON.stringify({ id, affected: [entry] });
}

function sbomDoc(
  components: { name: string; version?: string; dev?: boolean }[],
  deps: Record<string, string[]> = {},
): string {
  return JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    components: components.map((c) => ({
      type: "library",
      name: c.name,
      ...(c.version !== undefined ? { version: c.version } : {}),
      purl: `pkg:npm/${c.name.toLowerCase()}${c.version !== undefined ? `@${c.version}` : ""}`,
      ref: c.name,
      ...(c.dev ? { scope: "excluded" } : {}),
    })),
    dependencies: Object.entries(deps).map(([ref, dependsOn]) => ({ ref, dependsOn })),
  });
}

interface Case {
  project: string;
  osvDir: string;
  cacheDir: string;
  outDir: string;
  sbom: string;
}

const cleanup: string[] = [];
function track(dir: string): string {
  cleanup.push(dir);
  return dir;
}

afterAll(async () => {
  for (const d of cleanup) await rm(d, { recursive: true, force: true });
});

// A fresh throwaway run environment (project + OSV snapshot + SBOM + isolated
// cache/output dirs). Every artifact is tracked for afterAll cleanup.
async function env(project: string, osvFiles: Record<string, string>, sbom: string): Promise<Case> {
  const osvDir = track(await mkFixture({ files: osvFiles }));
  const root = track(await mkdtemp(join(tmpdir(), "callis-e2e-")));
  const sbomFile = join(root, "sbom.json");
  await writeFile(sbomFile, sbom);
  await mkdir(join(root, "out"), { recursive: true });
  return {
    project: track(project),
    osvDir,
    cacheDir: join(root, "cache"),
    outDir: join(root, "out"),
    sbom: sbomFile,
  };
}

const args = (c: Case, extra: string[] = []): string[] => [
  "--project",
  c.project,
  "--sbom",
  c.sbom,
  "--osv-dir",
  c.osvDir,
  "--cache-dir",
  c.cacheDir,
  "--output",
  join(c.outDir, "callis-report"),
  ...extra,
];

async function reportOf(c: Case): Promise<Record<string, unknown> | null> {
  try {
    return JSON.parse(await readFile(join(c.outDir, "callis-report.json"), "utf8"));
  } catch {
    return null;
  }
}

const CVE = { id: "CVE-2024-1234", fixed: "2.0.0" };
const OTHER = recordFile("CVE-2024-9999", "otherpkg", "1.1.0");

describe("exit 2 — usage/config errors", () => {
  test("given no --sbom, when run, then exit 2", async () => {
    const project = track(await callTree());
    const osvDir = track(await mkFixture({ files: { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) } }));
    const r = run([
      "--project",
      project,
      "--osv-dir",
      osvDir,
      "--cache-dir",
      join(project, "cache"),
      "--output",
      join(project, "out", "r"),
    ]);
    expect(r.code).toBe(2);
  });

  test("given a malformed mappings file, when run, then exit 2 (the mapping contract)", async () => {
    const c = await env(
      await callTree(),
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const bad = join(c.outDir, "mappings.json");
    await writeFile(bad, "{not json", "utf8");
    const r = run(args(c, ["--mappings", bad]));
    expect(r.code).toBe(2);
    expect(r.err).toContain("vuln-mappings");
  });

  test("given --cha and --pointer-analysis together, when run, then exit 2 (mutually exclusive precision modes)", async () => {
    const c = await env(
      await callTree(),
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const r = run(args(c, ["--cha", "--pointer-analysis"]));
    expect(r.code).toBe(2);
    expect(r.err).toContain("mutually exclusive");
  });

  test("given --fail-on-applicable WITHOUT --sbom-only, when run, then exit 2 (v3.5 item 6)", async () => {
    const c = await env(
      await callTree(),
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const r = run(args(c, ["--fail-on-applicable"]));
    expect(r.code).toBe(2);
    expect(r.err).toContain("--fail-on-applicable");
  });

  test("given an unknown --format token, when run, then exit 2", async () => {
    const c = await env(
      await callTree(),
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const r = run(args(c, ["--format=json,bogus"]));
    expect(r.code).toBe(2);
    expect(r.err).toContain("unknown --format token");
  });

  test("given a missing project directory, when run, then exit 2", async () => {
    const osvDir = track(await mkFixture({ files: { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) } }));
    const r = run([
      "--project",
      "/definitely-missing-dir-xyz-12345",
      "--sbom",
      "/definitely-missing-dir-xyz-12345/sbom.json",
      "--osv-dir",
      osvDir,
      "--cache-dir",
      "/definitely-missing-dir-xyz-12345/cache",
      "--output",
      "/definitely-missing-dir-xyz-12345/out/r",
    ]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("project directory not found");
  });
});

describe("exit 3 — analysis failures", () => {
  test("given a zero-valid-records OSV directory, when run, then exit 3 with a minimal report (ANALYSIS_FAILURE)", async () => {
    const c = await env(
      await callTree(),
      { "broken.json": "{not json" },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const r = run(args(c));
    expect(r.code).toBe(3);
    const rep = await reportOf(c);
    expect(rep).not.toBeNull();
    expect(rep?.meta).toHaveProperty("exitReasons", ["ANALYSIS_FAILURE"]);
    expect(rep?.analysisStatus).toBe("INCOMPLETE");
  });

  test("given the total-resolution guard (every component non-RESOLVED, no findings to retain), when run, then exit 3 with the minimal report (purl + tried dirs)", async () => {
    const project = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0", { main: "src/main.js" }),
        "src/main.js": `const pkg = require("vulnpkg");\npkg.vuln();\n`,
        "node_modules/unrelated/package.json": pkg("unrelated", "1.0.0"),
      },
    });
    // A valid record for ANOTHER package: the snapshot is fine, but nothing
    // for vulnpkg — nothing resolved, nothing to retain as a finding.
    const c = await env(project, { "CVE-9.json": OTHER }, sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]));
    const r = run(args(c));
    expect(r.code).toBe(3);
    const rep = await reportOf(c);
    expect(rep?.meta).toHaveProperty("exitReasons", ["TOTAL_RESOLUTION_GUARD"]);
    expect(rep?.analysisStatus).toBe("INCOMPLETE");
    const completeness = rep?.completeness as
      | { components: { purl: string; state: string; triedDirs?: string[] }[] }
      | undefined;
    const comps = completeness?.components ?? [];
    expect(comps).toHaveLength(1);
    expect(comps[0]?.state).toBe("MISSING");
    expect(comps[0]?.triedDirs?.length ?? 0).toBeGreaterThan(0);
  });

  test("given an empty SBOM, when run, then exit 3 (EMPTY_SBOM_GUARD); with --allow-empty-sbom then exit 0", async () => {
    const c = await env(await callTree(), { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) }, sbomDoc([]));
    const r = run(args(c));
    expect(r.code).toBe(3);
    expect((await reportOf(c))?.meta).toHaveProperty("exitReasons", ["EMPTY_SBOM_GUARD"]);
    const r2 = run(args(c, ["--allow-empty-sbom"]));
    expect(r2.code).toBe(0);
  });

  test("given --require-complete on a PARTIAL run (one non-RESOLVED component), when run, then exit 3 (REQUIRE_COMPLETE)", async () => {
    const c = await env(
      await importTree(),
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([
        { name: "vulnpkg", version: "1.0.0" },
        { name: "ghost", version: "1.0.0" },
      ]),
    );
    const r = run(args(c, ["--require-complete"]));
    expect(r.code).toBe(3);
    const rep = await reportOf(c);
    expect(rep?.meta).toHaveProperty("exitReasons", ["REQUIRE_COMPLETE"]);
    expect(rep?.analysisStatus).toBe("PARTIAL");
  });

  test("given zero entry points from all sources, when run, then exit 3 (the finding is retained, INCOMPLETE)", async () => {
    const project = await mkFixture({
      files: {
        // No main, no scripts, no framework: zero curated entry points.
        "package.json": pkg("app", "1.0.0"),
        "node_modules/vulnpkg/package.json": pkg("vulnpkg", "1.0.0"),
        "node_modules/vulnpkg/index.js": "module.exports = { vuln: function vuln() { return 1; } };\n",
      },
    });
    const c = await env(
      project,
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const r = run(args(c));
    expect(r.code).toBe(3);
    const rep = await reportOf(c);
    expect(rep?.meta).toHaveProperty("exitReasons", ["ANALYSIS_FAILURE"]);
    expect(rep?.analysisStatus).toBe("INCOMPLETE");
    expect((rep?.findings as { verdict: string }[])[0]?.verdict).toBe("UNREACHABLE");
    expect((rep?.meta as { entryPointCount: number }).entryPointCount).toBe(0);
  });

  test("given a non-writable --output destination, when run, then exit 3 (the write is the failure, never silent)", async () => {
    const c = await env(
      await callTree(),
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    // A regular FILE as the parent directory: the destination cannot be
    // created or written (ENOTDIR) — a genuine non-writable destination.
    const r = run(args(c, ["--output", `${c.sbom}/r`]));
    expect(r.code).toBe(3);
    expect(r.err).toContain("cannot write reports");
  });
});

describe("exit 1 — the failure family", () => {
  test("given a called vulnerable package, when run, then exit 1 with REACHABLE_FINDINGS and the trace in the report", async () => {
    const c = await env(
      await callTree(),
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }], { app: ["vulnpkg"] }),
    );
    const r = run(args(c));
    expect(r.code).toBe(1);
    const rep = await reportOf(c);
    expect(rep?.meta).toHaveProperty("exitReasons", ["REACHABLE_FINDINGS"]);
    const f = (rep?.findings as { verdict: string; path: string[]; supplyPath: string[] }[])[0];
    expect(f?.verdict).toBe("REACHABLE");
    expect(f?.path.length).toBeGreaterThan(1);
    expect(f?.supplyPath).toEqual(["app", "vulnpkg"]);
  });

  test("given a MAL-* record with --malware=fail, when run, then exit 1 with MALWARE_FAIL", async () => {
    const c = await env(
      await callTree(),
      { "MAL-1.json": recordFile("MAL-2024-0001", "vulnpkg", undefined, ["1.0.0"]) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const r = run(args(c, ["--malware=fail"]));
    expect(r.code).toBe(1);
    const rep = await reportOf(c);
    expect(rep?.meta).toHaveProperty("exitReasons", ["MALWARE_FAIL"]);
    expect((rep?.findings as { verdict: string }[])[0]?.verdict).toBe("MALICIOUS_PACKAGE");
  });

  test("given a MAL-* record, when run with the default --malware=warn, then the finding is listed but the exit is 0", async () => {
    const c = await env(
      await callTree(),
      { "MAL-1.json": recordFile("MAL-2024-0001", "vulnpkg", undefined, ["1.0.0"]) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const r = run(args(c));
    expect(r.code).toBe(0);
    const rep = await reportOf(c);
    expect((rep?.findings as { verdict: string }[])[0]?.verdict).toBe("MALICIOUS_PACKAGE");
  });

  test("given a reached native boundary with --opaque-native=fail, when run, then exit 1 with OPAQUE_NATIVE_FAIL", async () => {
    const tree = await importTree({ "node_modules/vulnpkg/binding.node": "native" });
    const c = await env(
      tree,
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const r = run(args(c, ["--opaque-native=fail"]));
    expect(r.code).toBe(1);
    const rep = await reportOf(c);
    expect(rep?.meta).toHaveProperty("exitReasons", ["OPAQUE_NATIVE_FAIL"]);
    const f = (rep?.findings as { verdict: string; nativeBoundary?: string }[])[0];
    expect(f?.verdict).toBe("NATIVE_OPAQUE");
    expect(f?.nativeBoundary).toBe("reached");
  });

  test("given --sbom-only --fail-on-applicable with an applicable advisory, when run, then exit 1 (v3.4 item 9)", async () => {
    const c = await env(
      await callTree(),
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const r = run(args(c, ["--sbom-only", "--fail-on-applicable"]));
    expect(r.code).toBe(1);
    const rep = await reportOf(c);
    expect(rep?.meta).toHaveProperty("exitReasons", ["REACHABLE_FINDINGS"]);
    expect((rep?.findings as { verdict: string }[])[0]?.verdict).toBe("APPLICABLE");
    expect(rep?.analysisStatus).toBe("NOT_PERFORMED");
  });

  test("given an unlisted-but-loaded instance with --match-installed, when run, then exit 1 (the finding carries source: installed)", async () => {
    // "other" resolves (the SBOM is not broken); vulnpkg is loaded but
    // UNLISTED — the v3.5 item 1 hole.
    const tree = await callTree({ "node_modules/other/package.json": pkg("other", "1.0.0") });
    const c = await env(
      tree,
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "other", version: "1.0.0" }]),
    );
    const r = run(args(c, ["--match-installed"]));
    expect(r.code).toBe(1);
    const rep = await reportOf(c);
    const f = (rep?.findings as { verdict: string; source: string }[])[0];
    expect(f?.verdict).toBe("REACHABLE");
    expect(f?.source).toBe("installed");
    expect(rep?.analysisStatus).toBe("PARTIAL");
    expect((rep?.notices as { code: string }[]).some((n) => n.code === "UNLISTED_INSTALLED")).toBe(true);
  });
});

describe("exit 0 — the clean family", () => {
  test("given no applicable advisory, when run, then exit 0 with no findings", async () => {
    const c = await env(await callTree(), { "CVE-1.json": OTHER }, sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]));
    const r = run(args(c));
    expect(r.code).toBe(0);
    const rep = await reportOf(c);
    expect(rep?.findings).toEqual([]);
    expect(rep?.meta).toHaveProperty("exitReasons", []);
    expect(rep?.analysisStatus).toBe("COMPLETE");
  });

  test("given an imported-but-never-called vulnerable package, when run, then exit 0 with UNREACHABLE (the loadedNotCalled exposure)", async () => {
    const c = await env(
      await importTree(),
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const r = run(args(c));
    expect(r.code).toBe(0);
    const rep = await reportOf(c);
    const f = (rep?.findings as { verdict: string; evidence: { loaded: boolean; called: boolean } }[])[0];
    expect(f?.verdict).toBe("UNREACHABLE");
    expect(f?.evidence.loaded).toBe(true);
    expect(f?.evidence.called).toBe(false);
    expect((rep?.exposure as { loadedNotCalled: number }).loadedNotCalled).toBe(1);
  });

  test("given an all-dev SBOM with a broken tree, when run, then exit 0 with DEV_ONLY + NOTICE (no guard: v3.4)", async () => {
    const project = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0", { main: "src/main.js" }),
        "src/main.js": `require("vulnpkg");\n`,
      },
    });
    const c = await env(
      project,
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0", dev: true }]),
    );
    const r = run(args(c));
    expect(r.code).toBe(0);
    const rep = await reportOf(c);
    expect((rep?.findings as { verdict: string }[])[0]?.verdict).toBe("DEV_ONLY");
    expect(rep?.meta).toHaveProperty("exitReasons", []);
    expect((rep?.notices as { code: string }[]).some((n) => n.code === "DEV_ONLY")).toBe(true);
  });

  test("given --sbom-only with an applicable advisory, when run, then exit 0 with APPLICABLE (default: no fail-on-applicable)", async () => {
    const c = await env(
      await callTree(),
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const r = run(args(c, ["--sbom-only"]));
    expect(r.code).toBe(0);
    const rep = await reportOf(c);
    expect((rep?.findings as { verdict: string }[])[0]?.verdict).toBe("APPLICABLE");
    expect(rep?.analysisStatus).toBe("NOT_PERFORMED");
  });
});

describe("exitReasons co-occurrence + report mechanics", () => {
  test("given a REACHABLE finding AND a strict-sources failure, when run, then exit 3 with BOTH reasons (v3.5)", async () => {
    const project = await callTree({ "node_modules/ghost/package.json": pkg("ghost", "1.0.0") });
    const c = await env(
      project,
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([
        { name: "vulnpkg", version: "1.0.0" },
        { name: "ghost", version: "9.9.9" },
      ]),
    );
    const r = run(args(c, ["--strict-sources"]));
    expect(r.code).toBe(3);
    const rep = await reportOf(c);
    expect(rep?.meta).toHaveProperty("exitReasons", ["REACHABLE_FINDINGS", "STRICT_SOURCES"]);
    expect((rep?.findings as { verdict: string }[]).some((f) => f.verdict === "REACHABLE")).toBe(true);
  });

  test("given a previous run's stale report, when the next run writes, then the stale bytes are replaced (stale-report deletion)", async () => {
    const c = await env(
      await callTree(),
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const stale = join(c.outDir, "callis-report.json");
    await writeFile(stale, `{"stale":true}\n`, "utf8");
    const r = run(args(c));
    expect(r.code).toBe(1);
    const rep = JSON.parse(await readFile(stale, "utf8"));
    expect(rep.stale).toBeUndefined();
    expect(rep.analysisStatus).toBeDefined();
  });

  test("given an EMPTY XDG_CACHE_HOME and no --cache-dir, when run, then the default cache is $HOME/.cache/callis (never the filesystem root)", async () => {
    const c = await env(
      await callTree(),
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const home = track(await mkdtemp(join("/tmp", "callis-xdg-")));
    // No --cache-dir flag: the default must honor a set XDG_CACHE_HOME...
    const withXdg = runWithEnv(
      [
        "--project",
        c.project,
        "--sbom",
        c.sbom,
        "--osv-dir",
        c.osvDir,
        "--output",
        join(c.outDir, "x"),
        "--format",
        "json",
      ],
      { XDG_CACHE_HOME: home },
    );
    expect(withXdg.code).toBe(1);
    expect(existsSync(join(home, "callis", "osv-index.json"))).toBe(true);
    // ...and an EMPTY XDG_CACHE_HOME must fall through to $HOME/.cache, not "/callis".
    const r = runWithEnv(
      [
        "--project",
        c.project,
        "--sbom",
        c.sbom,
        "--osv-dir",
        c.osvDir,
        "--output",
        join(c.outDir, "y"),
        "--format",
        "json",
      ],
      { HOME: home, XDG_CACHE_HOME: "" },
    );
    expect(r.err, r.err).not.toContain("EACCES");
    expect(r.code).toBe(1);
    expect(existsSync(join(home, ".cache", "callis", "osv-index.json"))).toBe(true);
  });

  test("given the --dry-run trio, when run, then exit 0 with the debug output and NO report", async () => {
    const c = await env(
      await callTree(),
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const r1 = run(args(c, ["--dry-run-sbom"]));
    expect(r1.code).toBe(0);
    expect(r1.out).toContain("sbom: pkg:npm/vulnpkg@1.0.0");
    const r2 = run(args(c, ["--dry-run-match"]));
    expect(r2.code).toBe(0);
    expect(r2.out).toContain("match: CVE-2024-1234 pkg:npm/vulnpkg@1.0.0");
    const r3 = run(args(c, ["--dry-run-graph"]));
    expect(r3.code).toBe(0);
    expect(r3.out).toContain("graph: ");
    expect(await reportOf(c)).toBeNull(); // no report was written
  });

  test("given a stale-SBOM drift (SBOM version out of range, installed in range), when run, then the finding is kept (matchedOn: installed) with the NOTICE", async () => {
    // A second component resolves, so the total-resolution guard (every
    // component non-RESOLVED) stays quiet while the drift is visible.
    const tree = await callTree({ "node_modules/other/package.json": pkg("other", "1.0.0") });
    const c = await env(
      tree,
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([
        { name: "vulnpkg", version: "3.0.0" },
        { name: "other", version: "1.0.0" },
      ]),
    );
    const r = run(args(c));
    expect(r.code).toBe(1);
    const rep = await reportOf(c);
    const f = (
      rep?.findings as { verdict: string; matchedOn: string; componentVersion?: string; installedVersion?: string }[]
    )[0];
    expect(f?.verdict).toBe("REACHABLE");
    expect(f?.matchedOn).toBe("installed");
    expect(f?.componentVersion).toBe("3.0.0");
    expect(f?.installedVersion).toBe("1.0.0");
    expect((rep?.notices as { code: string }[]).some((n) => n.code === "SBOM_DRIFT")).toBe(true);
  });
});
