import { describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { IR_VERSION, SCHEMA_VERSION, TOOL_VERSION } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..");

function runCli(args: string[]): { code: number; out: string; err: string } {
  try {
    const out = execFileSync("bun", ["packages/cli/src/main.ts", ...args], {
      cwd: repoRoot,
      encoding: "utf8",
    });
    return { code: 0, out, err: "" };
  } catch (e) {
    const err = e as { status?: number; stderr?: string };
    return { code: err.status ?? 1, out: "", err: err.stderr ?? String(e) };
  }
}

describe("bootstrap", () => {
  test("given the core version pins, when read, then all three constants are set", () => {
    expect(TOOL_VERSION).toBe("0.1.0");
    // IR_VERSION is "2" since M4 (ModuleIR gained classBases; older cache entries
    // are never reused — the key embeds the version).
    expect(IR_VERSION).toBe("2");
    expect(SCHEMA_VERSION).toBe("1");
  });

  test("given the workspace, when checked, then the MIT license exists from the first commit", () => {
    expect(existsSync(join(repoRoot, "LICENSE"))).toBe(true);
  });

  test("given the CLI, when run with --version, then it prints the brand version and exits 0", () => {
    const r = runCli(["--version"]);
    expect(r.code).toBe(0);
    expect(r.out.trim()).toBe(`callis ${TOOL_VERSION}`);
  });

  test("given no --sbom, when the CLI is run, then it is a usage error (exit 2), never green", () => {
    const r = runCli(["--osv-dir", "/nonexistent"]);
    expect(r.code).toBe(2);
  });

  test("given a run without the pipeline, when the CLI is run, then it fails visibly (exit 2)", () => {
    const r = runCli(["--sbom", "/nonexistent.json", "--osv-dir", "/nonexistent"]);
    expect(r.code).toBe(2);
  });
});
