#!/usr/bin/env bun
// Golden-demo verdict checker (plan section 9, JVM expected-reachable.txt
// parity).
//
// Usage: bun scripts/check-expected.ts <report.json> <expected-reachable.txt> <demo-name>
//
// expected-reachable.txt format:
//   <VERDICT> <canonical-id>      — a finding for this id must exist with
//                                   exactly this verdict. VERDICT is any
//                                   value of the Verdict union (REACHABLE,
//                                   UNREACHABLE, APPLICABLE, DEV_ONLY,
//                                   NO_SOURCE, NATIVE_OPAQUE,
//                                   MALICIOUS_PACKAGE)
//   ABSENT    <canonical-id>      — no finding for this id may exist
// Lines starting with # are comments. Every finding in the report must be
// accounted for by some expected line (a surprise verdict fails the demo).

import { readFileSync } from "node:fs";
const VERDICTS = [
  "REACHABLE",
  "UNREACHABLE",
  "APPLICABLE",
  "DEV_ONLY",
  "NO_SOURCE",
  "NATIVE_OPAQUE",
  "MALICIOUS_PACKAGE",
] as const;

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
  /** A Verdict value, or ABSENT. */
  op: string;
  id: string;
}

const expectations: Expectation[] = [];
for (const line of expected) {
  const [op, id] = line.split(/\s+/);
  if (op === undefined || id === undefined || (op !== "ABSENT" && !(VERDICTS as readonly string[]).includes(op))) {
    console.error(`${demoName}: bad expected line: ${line}`);
    process.exit(2);
  }
  expectations.push({ op, id });
}

let failed = false;
const seen = new Set<string>();
for (const exp of expectations) {
  const finding = report.findings.find((f) => f.id === exp.id);
  if (exp.op === "ABSENT") {
    if (finding !== undefined) {
      console.error(`${demoName}: expected no finding for ${exp.id}, got ${finding.verdict}`);
      failed = true;
    }
  } else if (finding === undefined || finding.verdict !== exp.op) {
    console.error(`${demoName}: expected ${exp.op} ${exp.id}, got ${finding?.verdict ?? "no finding"}`);
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
