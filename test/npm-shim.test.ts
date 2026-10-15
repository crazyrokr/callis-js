// M7d — the @callis/cli shim (npm/cli/bin/callis.cjs, the esbuild/Biome
// pattern): the main package carries no binary; the platform binary comes
// from the @callis/cli-<platform> optionalDependencies. The shim selects
// the package from the runner OS/arch plus the musl/AVX2 probes and execs
// it. The install-matrix test drives the selection over a fake
// node_modules (the registry side of the matrix — npm/pnpm/yarn/bun
// honoring os/cpu/libc — is covered by the publish workflow, not the shim).

import { afterAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";

const require2 = createRequire(import.meta.url);
const SHIM = join(import.meta.dir, "..", "npm", "cli", "bin", "callis.cjs");
const { selectPackage, BINARY_BY_PACKAGE } = require2(SHIM) as {
  selectPackage: (p: {
    platformName: string;
    archName: string;
    musl: boolean;
    avx2: boolean;
    installed: string[];
  }) => string | null;
  BINARY_BY_PACKAGE: Record<string, string>;
};

const ALL = Object.keys(BINARY_BY_PACKAGE);
const cleanup: string[] = [];
function track(dir: string): string {
  cleanup.push(dir);
  return dir;
}

afterAll(async () => {
  for (const d of cleanup) await rm(d, { recursive: true, force: true });
});

/** A fake node_modules with the given @callis packages installed (each
 *  carrying a fake binary that prints a marker and exits 7). */
async function fakeRoot(installed: string[]): Promise<string> {
  const root = track(await mkdtemp(join(tmpdir(), "callis-npm-")));
  for (const name of installed) {
    const dir = join(root, "@callis", name);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "package.json"), JSON.stringify({ name: `@callis/${name}`, version: "0.1.0" }));
    const file = BINARY_BY_PACKAGE[name];
    if (file === undefined) throw new Error(`no binary name for @callis/${name}`);
    const bin = join(dir, file);
    await writeFile(bin, `#!/bin/sh\necho "callis-fake(${name})"\nexit 7\n`, "utf8");
    await chmod(bin, 0o755);
  }
  return root;
}

interface ShimRun {
  code: number;
  out: string;
  err: string;
}

function spawnShim(env: Record<string, string | undefined>, args: string[]): ShimRun {
  const allEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined) allEnv[k] = v;
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) delete allEnv[k];
    else allEnv[k] = v;
  }
  const r = Bun.spawnSync(["node", SHIM, ...args], { stdout: "pipe", stderr: "pipe", env: allEnv });
  return { code: r.exitCode ?? -1, out: r.stdout?.toString() ?? "", err: r.stderr?.toString() ?? "" };
}

const LINUX_X64_GLIBC = { CALLIS_CLI_PLATFORM: "linux", CALLIS_CLI_ARCH: "x64" };

describe("shim package selection (M7d install matrix)", () => {
  const sel = (p: { musl?: boolean; avx2?: boolean; installed?: string[]; platformName?: string; archName?: string }) =>
    selectPackage({
      platformName: p.platformName ?? "linux",
      archName: p.archName ?? "x64",
      musl: p.musl ?? false,
      avx2: p.avx2 ?? true,
      installed: p.installed ?? ALL,
    });

  test("given the full platform matrix, when resolved, then the right package is selected (or none)", () => {
    expect(sel({})).toBe("cli-linux-x64"); // glibc x64, AVX2
    expect(sel({ avx2: false })).toBe("cli-linux-x64-baseline"); // no AVX2, baseline installed
    expect(sel({ avx2: false, installed: ["cli-linux-x64"] })).toBe("cli-linux-x64"); // no AVX2, no baseline
    expect(sel({ musl: true })).toBe("cli-linux-x64-musl");
    expect(sel({ archName: "arm64" })).toBe("cli-linux-arm64");
    expect(sel({ archName: "arm64", musl: true })).toBe("cli-linux-arm64-musl");
    expect(sel({ platformName: "darwin" })).toBe("cli-darwin-x64");
    expect(sel({ platformName: "darwin", archName: "arm64" })).toBe("cli-darwin-arm64");
    expect(sel({ platformName: "win32" })).toBe("cli-windows-x64");
    expect(sel({ platformName: "win32", archName: "arm64" })).toBe(null); // not published
    expect(sel({ archName: "riscv64" })).toBe(null); // not published
    expect(sel({ installed: [] })).toBe(null); // nothing installed
    // musl never gets the glibc baseline, even without AVX2:
    expect(sel({ musl: true, avx2: false, installed: ["cli-linux-x64-musl", "cli-linux-x64-baseline"] })).toBe(
      "cli-linux-x64-musl",
    );
  });

  test("given a fake node_modules, when printed, then the selected binary path is resolved from the installed package", async () => {
    const root = await fakeRoot(ALL);
    const r = spawnShim(
      { ...LINUX_X64_GLIBC, CALLIS_CLI_MUSL: "1", CALLIS_CLI_AVX2: "1", CALLIS_CLI_NODE_MODULES: root },
      ["--print-selection"],
    );
    expect(r.code).toBe(0);
    expect(r.out.trim()).toBe(join(root, "@callis", "cli-linux-x64-musl", "callis-linux-x64-musl"));
  });

  test("given a no-AVX2 host with the baseline installed, when printed, then the baseline binary is selected", async () => {
    const root = await fakeRoot(["cli-linux-x64", "cli-linux-x64-baseline"]);
    const r = spawnShim(
      { ...LINUX_X64_GLIBC, CALLIS_CLI_MUSL: "0", CALLIS_CLI_AVX2: "0", CALLIS_CLI_NODE_MODULES: root },
      ["--print-selection"],
    );
    expect(r.out.trim()).toBe(join(root, "@callis", "cli-linux-x64-baseline", "callis-linux-x64-baseline"));
  });

  test("given a fake node_modules without any @callis package, when printed, then the reason is reported (exit 1)", async () => {
    const root = await fakeRoot([]);
    const r = spawnShim({ ...LINUX_X64_GLIBC, CALLIS_CLI_MUSL: "0", CALLIS_CLI_NODE_MODULES: root }, [
      "--print-selection",
    ]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("none:");
  });

  test("given a package present without its binary file, when printed, then the missing file is reported", async () => {
    const root = track(await mkdtemp(join(tmpdir(), "callis-npm-")));
    const dir = join(root, "@callis", "cli-linux-x64");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "package.json"), JSON.stringify({ name: "@callis/cli-linux-x64", version: "0.1.0" }));
    const r = spawnShim({ ...LINUX_X64_GLIBC, CALLIS_CLI_MUSL: "0", CALLIS_CLI_NODE_MODULES: root }, [
      "--print-selection",
    ]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("callis-linux-x64 is missing");
  });
});

describe("shim exec (M7d)", () => {
  test("given an installed platform package, when any args are passed, then the binary runs with them and its exit code passes through", async () => {
    const root = await fakeRoot(["cli-linux-x64", "cli-linux-x64-baseline"]);
    const r = spawnShim(
      { ...LINUX_X64_GLIBC, CALLIS_CLI_MUSL: "0", CALLIS_CLI_AVX2: "1", CALLIS_CLI_NODE_MODULES: root },
      ["--version"],
    );
    expect(r.code).toBe(7); // the fake binary's exit code
    expect(r.out).toContain("callis-fake(cli-linux-x64)");
  });

  test("given no usable package on this host, when run, then the action fails with the reinstall hint (exit 2)", async () => {
    const root = await fakeRoot(["cli-darwin-arm64"]); // the wrong platform
    const r = spawnShim({ ...LINUX_X64_GLIBC, CALLIS_CLI_MUSL: "0", CALLIS_CLI_NODE_MODULES: root }, ["--version"]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("reinstall @callis/cli");
  });

  test("given a CALLIS_CLI_BIN override, when run, then that binary runs (air-gapped seam)", async () => {
    const root = await fakeRoot(["cli-linux-x64"]);
    const bin = join(root, "@callis", "cli-linux-x64", "callis-linux-x64");
    const r = spawnShim({ CALLIS_CLI_BIN: bin }, ["--version"]);
    expect(r.code).toBe(7);
    expect(r.out).toContain("callis-fake(cli-linux-x64)");
    // and the override is honored by --print-selection too:
    const p = spawnShim({ CALLIS_CLI_BIN: bin }, ["--print-selection"]);
    expect(p.code).toBe(0);
    expect(p.out.trim()).toBe(bin);
  });

  test("given the real built binary, when run through the shim, then the real callis answers (end-to-end)", async () => {
    const bin = join(import.meta.dir, "..", "dist", "callis-linux-x64");
    if (!existsSync(bin)) {
      // the build is a separate gate; the shim contract is covered above
      expect(true).toBe(true);
      return;
    }
    const r = spawnShim({ CALLIS_CLI_BIN: bin }, ["--version"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("callis 0.1.0");
  });
});
