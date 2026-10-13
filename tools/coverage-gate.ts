#!/usr/bin/env bun
// Per-directory line-coverage gates over the lcov output of
// `bun test --coverage --coverage-reporter=lcov` (plan section 9).
//
// Gates (JVM coverageGate parity):
//   packages/core/src/sbom    100% line
//   packages/core/src/osv     100% line
//   packages/core/src/report  100% line
//   packages/core/src/callgraph >= 90% line
//   packages/core/src/verdict >= 90% line
//
// Branch coverage is not reported by Bun; the branch gate for
// callgraph/verdict runs nightly under Node + c8 (plan section 9, R8).

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

interface Gate {
  dir: string;
  min: number;
}

const GATES: Gate[] = [
  { dir: "packages/core/src/sbom", min: 100 },
  { dir: "packages/core/src/osv", min: 100 },
  { dir: "packages/core/src/report", min: 100 },
  { dir: "packages/core/src/callgraph", min: 90 },
  { dir: "packages/core/src/verdict", min: 90 },
];

const lcovPath = process.argv[2] ?? join("coverage", "lcov.info");

if (!existsSync(lcovPath)) {
  console.error(`coverage-gate: ${lcovPath} not found; run bun test --coverage --coverage-reporter=lcov`);
  process.exit(2);
}

interface FileRecord {
  file: string;
  lines: number;
  hit: number;
}

const records: FileRecord[] = [];
let currentFile: string | null = null;
for (const raw of readFileSync(lcovPath, "utf8").split("\n")) {
  const line = raw.trimEnd();
  if (line.startsWith("SF:")) {
    currentFile = line.slice(3);
  } else if (line.startsWith("DA:")) {
    // DA:<line>,<hit>[,<checksum>]
    const parts = line.slice(3).split(",");
    const hit = Number(parts[1] ?? "0");
    if (hit >= 0 && currentFile !== null) {
      const rec = records.find((r) => r.file === currentFile);
      if (rec !== undefined) {
        rec.lines += 1;
        rec.hit += hit > 0 ? 1 : 0;
      } else {
        records.push({ file: currentFile, lines: 1, hit: hit > 0 ? 1 : 0 });
      }
    }
  } else if (line === "end_of_record") {
    currentFile = null;
  }
}

let failed = false;
for (const gate of GATES) {
  const dirExists = existsSync(join("packages", ...gate.dir.split("/")));
  const files = records.filter((r) => r.file.startsWith(`${gate.dir}/`));
  if (!dirExists) {
    console.log(`coverage-gate: ${gate.dir} absent in this checkout; gate deferred`);
    continue;
  }
  if (files.length === 0) {
    console.error(`coverage-gate: no lcov records for ${gate.dir}; the gate cannot be evaluated`);
    failed = true;
    continue;
  }
  const lines = files.reduce((n, r) => n + r.lines, 0);
  const hit = files.reduce((n, r) => n + r.hit, 0);
  const pct = lines === 0 ? 100 : (100 * hit) / lines;
  const ok = pct >= gate.min;
  console.log(
    `coverage-gate: ${gate.dir}: ${pct.toFixed(2)}% (hit ${hit}/${lines}, required ${gate.min}%) ${ok ? "OK" : "FAIL"}`,
  );
  if (!ok) failed = true;
}
process.exit(failed ? 1 : 0);
