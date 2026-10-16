// Golden demos in the test suite (plan section 9): every examples/vulnerable-demo-*
// runs through the REAL CLI (interpreted core) with the exact e2e argument
// shapes, and the report + console + exit code are checked against
// scripts/golden-expected.ts — the same table scripts/e2e.sh checks the
// COMPILED binary against. This keeps the expectation content in the tests
// (no per-demo expected-*.txt files) while the binary gate stays a separate
// script.

import { describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, readFileSync, readdirSync } from "node:fs";
import { cp, rm } from "node:fs/promises";
import { join } from "node:path";
import { checkGoldenReport, goldenExpectations } from "../../../scripts/golden-expected.js";

const CLI = join(import.meta.dir, "..", "..", "cli", "src", "main.ts");
const EXAMPLES = join(import.meta.dir, "..", "..", "..", "examples");

function demoDirs(): string[] {
  return readdirSync(EXAMPLES)
    .filter((d) => d.startsWith("vulnerable-demo-"))
    .map((d) => join(EXAMPLES, d));
}

/** Per-demo extra flags (one per line, comments skipped) — the only
 * per-demo input file left on disk. */
function extraFlags(demo: string): string[] {
  const file = join(demo, "extra-flags.txt");
  if (!existsSync(file)) return [];
  return readFileSync(file, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"));
}

/** Materialize the committed install/ fixture as node_modules (e2e contract). */
async function materialize(demo: string): Promise<void> {
  const install = join(demo, "install");
  if (!existsSync(install)) return;
  await rm(join(demo, "node_modules"), { recursive: true, force: true });
  await cp(install, join(demo, "node_modules"), { recursive: true, dereference: false });
}

function run(demo: string, args: string[]): { code: number; log: string } {
  const r = Bun.spawnSync(["bun", CLI, ...args], { stdout: "pipe", stderr: "pipe" });
  return {
    code: r.exitCode ?? -1,
    log: r.stdout.toString() + r.stderr.toString(),
  };
}

describe("golden demos (interpreted core, expectations from scripts/golden-expected.ts)", () => {
  test("given the examples directory and the expectation table, when compared, then they name exactly the same demos", () => {
    const dirs = demoDirs()
      .map((d) => d.split("/").pop() as string)
      .sort();
    const keys = Object.keys(goldenExpectations).sort();
    expect(dirs).toEqual(keys);
  });

  for (const demo of demoDirs()) {
    const name = demo.split("/").pop() as string;
    test(`given the ${name} demo, when analyzed, then exit, verdicts, and notices match the expectation`, async () => {
      await materialize(demo);
      mkdirSync(join(demo, "out"), { recursive: true });
      const args = ["--project", demo, "--sbom", join(demo, "sbom.json"), "--osv-dir", join(demo, "osv")];
      if (existsSync(join(demo, "vuln-mappings.json"))) args.push("--mappings", join(demo, "vuln-mappings.json"));
      args.push(...extraFlags(demo));
      args.push(
        "--format",
        "json",
        "--output",
        join(demo, "out", "callis-report"),
        "--cache-dir",
        join(demo, "out", "cache"),
      );

      const { code, log } = run(demo, args);
      const report = JSON.parse(readFileSync(join(demo, "out", "callis-report.json"), "utf8")) as {
        findings: { id: string; verdict: string }[];
      };

      const errors = checkGoldenReport(name, report, log);
      const exp = goldenExpectations[name];
      if (exp !== undefined && code !== exp.exit) errors.push(`${name}: exit ${code} != expected ${exp.exit}`);
      expect(errors).toEqual([]);
    });
  }
});
