// M7e — the callis GitHub Action runner (action/dist/index.js): runs the
// pinned binary against a fixture project, verifies the REPO-PINNED digest
// (never the release's own), cross-checks expected-reachable, maps the
// exit code, and picks the right release asset per platform.

import { afterAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkFixture, pkg } from "../packages/core/test/project.fixtures.js";

const ACTION = join(import.meta.dir, "..", "action", "dist", "index.cjs");
const CLI = join(import.meta.dir, "..", "packages", "cli", "src", "main.ts");
const CVE = { id: "CVE-2024-1234", fixed: "2.0.0" };

const cleanup: string[] = [];
function track(dir: string): string {
  cleanup.push(dir);
  return dir;
}

afterAll(async () => {
  for (const d of cleanup) await rm(d, { recursive: true, force: true });
});

function sha256OfFile(file: string): string {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

/** A local executable that behaves like the compiled binary: the same CLI
 *  contract, interpreted (the action only needs a file to verify and run). */
async function shimBinary(): Promise<string> {
  const dir = track(await mkdtemp(join(tmpdir(), "callis-action-")));
  const shim = join(dir, "callis");
  await writeFile(shim, `#!/bin/sh\nexec bun ${CLI} "$@"\n`, "utf8");
  await chmod(shim, 0o755);
  return shim;
}

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

function sbomDoc(): string {
  return JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    components: [{ type: "library", name: "vulnpkg", version: "1.0.0", purl: "pkg:npm/vulnpkg@1.0.0", ref: "vulnpkg" }],
    dependencies: [{ ref: "app", dependsOn: ["vulnpkg"] }],
  });
}

/** The REACHABLE fixture: an app that calls the vulnerable package. */
async function reachableEnv(): Promise<{ project: string; osvDir: string; sbom: string }> {
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
  const osvDir = track(await mkFixture({ files: { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) } }));
  const sbomDir = track(await mkdtemp(join(tmpdir(), "callis-action-")));
  const sbom = join(sbomDir, "sbom.json");
  await writeFile(sbom, sbomDoc());
  return { project, osvDir, sbom };
}

interface ActionRun {
  code: number;
  out: string;
  err: string;
  outputs: Record<string, string>;
}

/** Spawn the action with controlled INPUT_* env (undefined: removed). */
async function runAction(env: Record<string, string | undefined>, cwd: string): Promise<ActionRun> {
  const allEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && k !== "RUNNER_OS" && k !== "RUNNER_ARCH" && k !== "GITHUB_OUTPUT") allEnv[k] = v;
  }
  const cacheHome = track(await mkdtemp(join(tmpdir(), "callis-action-cache-")));
  allEnv.XDG_CACHE_HOME = cacheHome;
  const outputFile = join(cacheHome, "github-output");
  await writeFile(outputFile, "", "utf8");
  allEnv.GITHUB_OUTPUT = outputFile;
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) delete allEnv[k];
    else allEnv[k] = v;
  }
  const r = Bun.spawnSync(["node", ACTION], { stdout: "pipe", stderr: "pipe", env: allEnv, cwd });
  const outputs: Record<string, string> = {};
  for (const line of readFileSync(outputFile, "utf8").split("\n")) {
    const i = line.indexOf("=");
    if (i > 0) outputs[line.slice(0, i)] = line.slice(i + 1);
  }
  return {
    code: r.exitCode ?? -1,
    out: r.stdout?.toString() ?? "",
    err: r.stderr?.toString() ?? "",
    outputs,
  };
}

/**
 * A local HTTP server serving one file (a spawned NODE process — the
 * action's node fetch client and the node server are a proven pair; the
 * Bun server implementation is not).
 */
async function serveLocal(file: string): Promise<{ port: number; stop: () => void }> {
  const dir = track(await mkdtemp(join(tmpdir(), "callis-action-")));
  const script = join(dir, "serve.cjs");
  const portFile = join(dir, "port");
  await writeFile(
    script,
    `const { readFileSync, writeFileSync } = require("node:fs");
const http = require("node:http");
const bytes = readFileSync(process.argv[2]);
const s = http.createServer((req, res) => {
  res.writeHead(200, { "content-type": "application/octet-stream" });
  res.end(bytes);
});
s.listen(0, "127.0.0.1", () => writeFileSync(process.argv[3], String(s.address().port)));
`,
    "utf8",
  );
  const proc = Bun.spawn(["node", script, file, portFile], { stdout: "ignore", stderr: "ignore" });
  for (let i = 0; i < 200; i++) {
    if (existsSync(portFile)) break;
    await Bun.sleep(50);
  }
  if (!existsSync(portFile)) throw new Error("server did not start");
  const port = Number(readFileSync(portFile, "utf8").trim());
  if (!Number.isFinite(port) || port <= 0) throw new Error(`server port unreadable: ${port}`);
  return { port, stop: () => proc.kill() };
}

/** The resolved release asset suffix for a runner environment. */
function printTarget(env: Record<string, string>): string {
  const allEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && k !== "RUNNER_OS" && k !== "RUNNER_ARCH") allEnv[k] = v;
  }
  Object.assign(allEnv, env);
  const r = Bun.spawnSync(["node", ACTION, "--print-target"], { stdout: "pipe", stderr: "pipe", env: allEnv });
  return (r.stdout?.toString() ?? "").trim();
}

describe("the action runner (M7e)", () => {
  test("given a REACHABLE project and a local binary with a matching pinned digest, when run, then the action exits 1, writes the report, and exposes the outputs", async () => {
    const env = await reachableEnv();
    const binary = await shimBinary();
    const r = await runAction(
      {
        INPUT_BINARY: binary,
        INPUT_SHA256: sha256OfFile(binary),
        INPUT_VERSION: "0.1.0",
        INPUT_SBOM: env.sbom,
        INPUT_OSV_DIR: env.osvDir,
      },
      env.project,
    );
    expect(r.code).toBe(1);
    expect(r.err).toContain("digest verified");
    expect(r.outputs["exit-code"]).toBe("1");
    expect(r.outputs["report-json"]).toBe("callis-report.json");
    const report = JSON.parse(readFileSync(join(env.project, "callis-report.json"), "utf8"));
    const f = report.findings.find((x: { id: string }) => x.id === CVE.id);
    expect(f?.verdict).toBe("REACHABLE");
  });

  test("given a binary whose actual digest differs from the pin, when run, then the action refuses to run it (exit 2, no report)", async () => {
    const env = await reachableEnv();
    const binary = await shimBinary();
    const r = await runAction(
      {
        INPUT_BINARY: binary,
        INPUT_SHA256: "0".repeat(64),
        INPUT_VERSION: "0.1.0",
        INPUT_SBOM: env.sbom,
        INPUT_OSV_DIR: env.osvDir,
      },
      env.project,
    );
    expect(r.code).toBe(2);
    expect(r.err).toContain("SHA256 MISMATCH");
    expect(existsSync(join(env.project, "callis-report.json"))).toBe(false);
  });

  test("given a matching expected-reachable pin, when run, then no cross-check problem is reported and the callis exit code passes through", async () => {
    const env = await reachableEnv();
    const binary = await shimBinary();
    const expected = join(env.project, "expected-reachable.txt");
    await writeFile(expected, `REACHABLE ${CVE.id}\n`, "utf8");
    const r = await runAction(
      {
        INPUT_BINARY: binary,
        INPUT_SHA256: sha256OfFile(binary),
        INPUT_VERSION: "0.1.0",
        INPUT_SBOM: env.sbom,
        INPUT_OSV_DIR: env.osvDir,
        INPUT_EXPECTED_REACHABLE: expected,
      },
      env.project,
    );
    expect(r.code).toBe(1);
    expect(r.err).not.toContain("callis-action: expected");
    expect(r.err).not.toContain("callis-action: unexpected");
    expect(r.err).not.toContain("callis-action: bad expected");
  });

  test("given a stale expected-reachable pin (verdict mismatch), when run, then the action exits 2 with the problem", async () => {
    const env = await reachableEnv();
    const binary = await shimBinary();
    const expected = join(env.project, "expected-reachable.txt");
    await writeFile(expected, `UNREACHABLE ${CVE.id}\n`, "utf8");
    const r = await runAction(
      {
        INPUT_BINARY: binary,
        INPUT_SHA256: sha256OfFile(binary),
        INPUT_VERSION: "0.1.0",
        INPUT_SBOM: env.sbom,
        INPUT_OSV_DIR: env.osvDir,
        INPUT_EXPECTED_REACHABLE: expected,
      },
      env.project,
    );
    expect(r.code).toBe(2);
    expect(r.err).toContain(`expected UNREACHABLE ${CVE.id}, got REACHABLE`);
  });

  test("given an ABSENT expectation for a finding that exists, when run, then the action exits 2", async () => {
    const env = await reachableEnv();
    const binary = await shimBinary();
    const expected = join(env.project, "expected-reachable.txt");
    await writeFile(expected, `ABSENT ${CVE.id}\n`, "utf8");
    const r = await runAction(
      {
        INPUT_BINARY: binary,
        INPUT_SHA256: sha256OfFile(binary),
        INPUT_VERSION: "0.1.0",
        INPUT_SBOM: env.sbom,
        INPUT_OSV_DIR: env.osvDir,
        INPUT_EXPECTED_REACHABLE: expected,
      },
      env.project,
    );
    expect(r.code).toBe(2);
    expect(r.err).toContain(`expected no finding for ${CVE.id}, got REACHABLE`);
  });

  test("given a clean project (the package is installed but never called) with an UNREACHABLE pin, when run, then the action exits 0", async () => {
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
    const osvDir = track(await mkFixture({ files: { "CVE-1.json": recordFile(CVE.id, "vulnpkg", CVE.fixed) } }));
    const sbomDir = track(await mkdtemp(join(tmpdir(), "callis-action-")));
    const sbom = join(sbomDir, "sbom.json");
    await writeFile(sbom, sbomDoc());
    const binary = await shimBinary();
    const expected = join(project, "expected-reachable.txt");
    await writeFile(expected, `UNREACHABLE ${CVE.id}\n`, "utf8");
    const r = await runAction(
      {
        INPUT_BINARY: binary,
        INPUT_SHA256: sha256OfFile(binary),
        INPUT_VERSION: "0.1.0",
        INPUT_SBOM: sbom,
        INPUT_OSV_DIR: osvDir,
        INPUT_EXPECTED_REACHABLE: expected,
      },
      project,
    );
    expect(r.code).toBe(0);
    expect(r.outputs["exit-code"]).toBe("0");
  });

  test("given a release-url served over local HTTP, when run, then the action downloads, verifies, and runs the binary", async () => {
    const env = await reachableEnv();
    const binary = await shimBinary();
    const bytes = readFileSync(binary);
    const server = await serveLocal(binary);
    try {
      const runnerTemp = track(await mkdtemp(join(tmpdir(), "callis-action-")));
      const r = await runAction(
        {
          INPUT_VERSION: "0.1.0",
          INPUT_SHA256: createHash("sha256").update(bytes).digest("hex"),
          INPUT_RELEASE_URL: `http://127.0.0.1:${server.port}/callis-linux-x64`,
          INPUT_SBOM: env.sbom,
          INPUT_OSV_DIR: env.osvDir,
          RUNNER_OS: "Linux",
          RUNNER_ARCH: "x64",
          RUNNER_TEMP: runnerTemp,
        },
        env.project,
      );
      expect(r.code).toBe(1);
      expect(r.err).toContain("digest verified");
      expect(existsSync(join(runnerTemp, "callis-linux-x64"))).toBe(true);
      expect(existsSync(join(env.project, "callis-report.json"))).toBe(true);
    } finally {
      server.stop();
    }
  });
});

describe("release asset selection (M7e)", () => {
  test("given the runner matrix, when resolved, then the correct asset suffix is picked", async () => {
    const probeDir = track(await mkdtemp(join(tmpdir(), "callis-action-")));
    const existingFile = join(probeDir, "ld-musl-x86-64.so.3");
    await writeFile(existingFile, "musl\n", "utf8");
    const missingFile = join(probeDir, `callis-action-missing-${process.pid}`);
    const cpuinfoAvx2 = join(probeDir, "cpuinfo-avx2");
    await writeFile(cpuinfoAvx2, "processor\t: 0\nflags\t: fpu vme sse2 sse4_1 avx2 fma\n", "utf8");
    const cpuinfoNoAvx2 = join(probeDir, "cpuinfo-no-avx2");
    await writeFile(cpuinfoNoAvx2, "processor\t: 0\nflags\t: fpu vme sse2\n", "utf8");

    expect(printTarget({ RUNNER_OS: "Windows" })).toBe("windows-x64");
    expect(printTarget({ RUNNER_OS: "macOS", RUNNER_ARCH: "arm64" })).toBe("darwin-arm64");
    expect(printTarget({ RUNNER_OS: "macOS", RUNNER_ARCH: "x64" })).toBe("darwin-x64");
    expect(printTarget({ RUNNER_OS: "Linux", RUNNER_ARCH: "x64", CALLIS_ACTION_MUSL_LIB: existingFile })).toBe(
      "linux-x64-musl",
    );
    expect(
      printTarget({
        RUNNER_OS: "Linux",
        RUNNER_ARCH: "x64",
        CALLIS_ACTION_MUSL_LIB: missingFile,
        CALLIS_ACTION_CPUINFO: cpuinfoNoAvx2,
      }),
    ).toBe("linux-x64-baseline");
    expect(
      printTarget({
        RUNNER_OS: "Linux",
        RUNNER_ARCH: "x64",
        CALLIS_ACTION_MUSL_LIB: missingFile,
        CALLIS_ACTION_CPUINFO: cpuinfoAvx2,
      }),
    ).toBe("linux-x64");
    expect(printTarget({ RUNNER_OS: "Linux", RUNNER_ARCH: "arm64", CALLIS_ACTION_MUSL_LIB: missingFile })).toBe(
      "linux-arm64",
    );
    expect(printTarget({ RUNNER_OS: "Linux", RUNNER_ARCH: "arm64", CALLIS_ACTION_MUSL_LIB: existingFile })).toBe(
      "linux-arm64-musl",
    );
  });
});
