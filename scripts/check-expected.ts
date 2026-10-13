#!/usr/bin/env bun
// Golden-demo verdict checker (plan section 9, JVM expected-reachable.txt
// parity).
//
// Usage: bun scripts/check-expected.ts <report.json> <expected-reachable.txt> <demo-name>
//
// expected-reachable.txt format:
//   REACHABLE  <canonical-id>     — finding must have verdict REACHABLE
//   UNREACHABLE <canonical-id>    — finding must exist with verdict UNREACHABLE
//   ABSENT     <canonical-id>     — no finding for this id may exist
// Lines starting with # are comments. Every finding in the report must be
// accounted for by some expected line (a surprise verdict fails the demo).

import { existsSync, readFileSync } from "node:fs";

interface Finding {
  id: string;
  verdict: string;
}

const [reportPath, expectedPath, demoName] = process.argv.slice(2);
if (reportPath === undefined || expectedPath === undefined) {
  console.error("usage: check-expected.ts <report.json> <expected-reachable.txt> <demo-name>");
  process.exit(2);
}

const report = JSON.parse(readFileSync(reportPath, "utf8")) as { findings: Finding[] };
const expected = readFileSync(expectedPath, "utf8")
  .split("\n")
  .map((l) => l.trim())
  .filter((l) => l.length > 0 && !l.startsWith("#"));

interface Expectation {
  op: "REACHABLE" | "UNREACHABLE" | "ABSENT";
  id: string;
}

const expectations: Expectation[] = [];
for (const line of expected) {
  const [op, id] = line.split(/\s+/);
  if ((op !== "REACHABLE" && op !== "UNREACHABLE" && op !== "ABSENT") || id === undefined) {
    console.error(`${demoName}: bad expected line: ${line}`);
    process.exit(2);
  }
  expectations.push({ op: op as Expectation["op"], id });
}

let failed = false;
const seen = new Set<string>();
for (const exp of expectations) {
  const finding = report.findings.find((f) => f.id === exp.id);
  if (exp.op === "REACHABLE" && finding?.verdict !== "REACHABLE") {
    console.error(`${demoName}: expected REACHABLE ${exp.id}, got ${finding?.verdict ?? "no finding"}`);
    failed = true;
  }
  if (exp.op === "UNREACHABLE" && finding?.verdict !== "UNREACHABLE") {
    console.error(`${demoName}: expected UNREACHABLE ${exp.id}, got ${finding?.verdict ?? "no finding"}`);
    failed = true;
  }
  if (exp.op === "ABSENT" && finding !== undefined) {
    console.error(`${demoName}: expected no finding for ${exp.id}, got ${finding.verdict}`);
    failed = true;
  }
  if (finding !== undefined) seen.add(exp.id);
}
for (const f of report.findings) {
  if (!expectations.some((e) => e.id === f.id)) {
    console.error(`${demoName}: unexpected finding ${f.id} (${f.verdict}) — add it to expected-reachable.txt`);
    failed = true;
  }
}
if (failed) process.exit(1);
console.log(`${demoName}: expected verdicts OK (${report.findings.length} findings)`);
if (existsSync(expectedPath)) void expectedPath;
