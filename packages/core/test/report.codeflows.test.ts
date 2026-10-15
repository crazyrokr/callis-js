// M7b — SARIF codeFlows end-to-end (plan M7 item 7b): a full engine run
// writes a SARIF whose findings with a call path carry codeFlows, and every
// hop is a PHYSICAL location at a real source file on disk (file + line),
// cross-checked against the JSON report's path and the filesystem.

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

const cleanup: string[] = [];
function track(dir: string): string {
  cleanup.push(dir);
  return dir;
}

afterAll(async () => {
  for (const d of cleanup) await rm(d, { recursive: true, force: true });
});

function recordFile(id: string, name: string, fixed: string): string {
  return JSON.stringify({
    id,
    affected: [
      {
        package: { name, ecosystem: "npm" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed }] }],
      },
    ],
  });
}

function sbomDoc(components: { name: string; version?: string }[]): string {
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
    })),
    dependencies: [{ ref: "app", dependsOn: components.map((c) => c.name) }],
  });
}

async function env(
  project: string,
  osvFiles: Record<string, string>,
  sbom: string,
): Promise<{
  osvDir: string;
  sbom: string;
  outDir: string;
  cacheDir: string;
}> {
  const osvDir = track(await mkFixture({ files: osvFiles }));
  const root = track(await mkdtemp(join(tmpdir(), "callis-cf-")));
  const sbomFile = join(root, "sbom.json");
  await writeFile(sbomFile, sbom);
  await mkdir(join(root, "out"), { recursive: true });
  return { osvDir, sbom: sbomFile, outDir: join(root, "out"), cacheDir: join(root, "cache") };
}

const CVE = { id: "CVE-2024-1234", fixed: "2.0.0" };

describe("SARIF codeFlows (M7b) — engine-level", () => {
  test("given a full run of an app that calls the vulnerable package, when written, then the SARIF finding carries codeFlows whose hops are real, on-disk source locations matching the JSON path", async () => {
    const project = track(
      await mkFixture({
        files: {
          "package.json": pkg("app", "1.0.0", { main: "src/main.js" }),
          "src/main.js": `const pkg = require("vulnpkg");\npkg.vuln();\n`,
          "node_modules/vulnpkg/package.json": pkg("vulnpkg", "1.0.0"),
          "node_modules/vulnpkg/index.js": "module.exports = { vuln: function vuln() { return 1; } };\n",
        },
      }),
    );
    const c = await env(
      project,
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const r = run([
      "--project",
      project,
      "--sbom",
      c.sbom,
      "--osv-dir",
      c.osvDir,
      "--cache-dir",
      c.cacheDir,
      "--output",
      join(c.outDir, "callis-report"),
      "--format",
      "json,sarif",
    ]);
    expect(r.code).toBe(1); // a REACHABLE finding

    const json = JSON.parse(await readFile(join(c.outDir, "callis-report.json"), "utf8"));
    const sarif = JSON.parse(await readFile(join(c.outDir, "callis-report.sarif"), "utf8"));
    const f = (json.findings as { id: string; verdict: string; path: string[] }[]).find((x) => x.id === CVE.id);
    expect(f?.verdict).toBe("REACHABLE");
    expect((f?.path ?? []).length).toBeGreaterThan(1);

    const res = (
      sarif.runs[0].results as {
        ruleId: string;
        codeFlows?: {
          threadFlows: {
            locations: { physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } } }[];
          }[];
        }[];
      }[]
    ).find((x) => x.ruleId === CVE.id);
    expect(res?.codeFlows).toHaveLength(1);
    const hops = res?.codeFlows?.[0]?.threadFlows[0]?.locations ?? [];
    const path = f?.path ?? [];
    expect(hops).toHaveLength(path.length);

    for (let i = 0; i < hops.length; i++) {
      const nodeId = path[i];
      if (nodeId === undefined) throw new Error("path shorter than the codeFlow");
      const file = nodeId.slice(0, nodeId.indexOf("#"));
      const hop = hops[i];
      if (hop === undefined) throw new Error("codeFlow shorter than the path");
      // Every hop of a real run is a PHYSICAL location at a file on disk.
      expect(hop.physicalLocation.artifactLocation.uri).toBe(file);
      expect(hop.physicalLocation.region.startLine).toBeGreaterThanOrEqual(1);
      expect(existsSync(file)).toBe(true);
    }

    // First hop is the app's entry file; the last hop is inside the
    // vulnerable package.
    expect(hops[0]?.physicalLocation.artifactLocation.uri.endsWith("src/main.js")).toBe(true);
    expect(hops[hops.length - 1]?.physicalLocation.artifactLocation.uri).toContain("vulnpkg");
  });

  test("given a full run whose finding has no path, when written, then no codeFlows property (UNREACHABLE keeps the SBOM anchor only)", async () => {
    const project = track(
      await mkFixture({
        files: {
          "package.json": pkg("app", "1.0.0", { main: "src/main.js" }),
          "src/main.js": "// the package is never required\n",
          "node_modules/vulnpkg/package.json": pkg("vulnpkg", "1.0.0"),
          "node_modules/vulnpkg/index.js": "module.exports = { vuln: function vuln() { return 1; } };\n",
        },
      }),
    );
    const c = await env(
      project,
      { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) },
      sbomDoc([{ name: "vulnpkg", version: "1.0.0" }]),
    );
    const r = run([
      "--project",
      project,
      "--sbom",
      c.sbom,
      "--osv-dir",
      c.osvDir,
      "--cache-dir",
      c.cacheDir,
      "--output",
      join(c.outDir, "callis-report"),
      "--format",
      "json,sarif",
    ]);
    expect(r.code).toBe(0);

    const json = JSON.parse(await readFile(join(c.outDir, "callis-report.json"), "utf8"));
    const sarif = JSON.parse(await readFile(join(c.outDir, "callis-report.sarif"), "utf8"));
    const f = (json.findings as { id: string; verdict: string; path: string[] }[]).find((x) => x.id === CVE.id);
    expect(f?.verdict).toBe("UNREACHABLE");
    expect(f?.path).toEqual([]);

    const res = (sarif.runs[0].results as Record<string, unknown>[]).find((x) => x.ruleId === CVE.id);
    expect(res?.codeFlows).toBeUndefined();
    expect(res?.locations).toHaveLength(1); // the SBOM anchor only
  });
});
