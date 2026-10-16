#!/usr/bin/env bun
// Golden-demo expectation checker (plan section 9, JVM expected-reachable.txt
// parity).
//
// Usage: bun scripts/check-expected.ts <report.json> <console.log> <demo-name> <exit-code>
//
// Checks the report's findings against the demo's expectation in
// scripts/golden-expected.ts (the single source of truth, shared with
// packages/core/test/e2e.demos.test.ts): every expected finding must exist
// with exactly its verdict, every report finding must be accounted for,
// every expected console notice must appear verbatim, and the process exit
// code must match.

import { readFileSync } from "node:fs";
import { checkGoldenReport, goldenExpectations } from "./golden-expected.js";

const [reportPath, consolePath, demoName, exitCodeArg] = process.argv.slice(2);
if (reportPath === undefined || consolePath === undefined || demoName === undefined || exitCodeArg === undefined) {
  console.error("usage: check-expected.ts <report.json> <console.log> <demo-name> <exit-code>");
  process.exit(2);
}

const exp = goldenExpectations[demoName];
if (exp === undefined) {
  console.error(`${demoName}: no expectation defined (add it to scripts/golden-expected.ts)`);
  process.exit(2);
}

const report = JSON.parse(readFileSync(reportPath, "utf8")) as { findings: { id: string; verdict: string }[] };
const consoleLog = readFileSync(consolePath, "utf8");

const errors: string[] = [];
if (Number(exitCodeArg) !== exp.exit) errors.push(`${demoName}: exit ${exitCodeArg} != expected ${exp.exit}`);
errors.push(...checkGoldenReport(demoName, report, consoleLog));

if (errors.length > 0) {
  for (const e of errors) console.error(e);
  process.exit(1);
}
console.log(`${demoName}: expected exit ${exp.exit} + verdicts OK (${report.findings.length} findings)`);
