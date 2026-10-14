// JUnit XML writer (plan section 5.6, JVM ADR 0010 parity).
//
// One <testcase> per finding. REACHABLE findings FAIL (the message carries
// the call trace); everything else passes. The purl rides in <properties>
// (JVM parity), so CI can filter by component.

import { writeFile } from "node:fs/promises";
import type { Finding } from "../verdict/types.js";
import type { AnalysisResult } from "./types.js";

function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** The call-trace message of a finding (empty path: no trace). */
export function traceMessage(f: Finding): string {
  if (f.path.length > 1) return `reachable: ${f.path.join(" -> ")} (confidence: ${f.confidence ?? "PRECISE"})`;
  return `${f.verdict}: ${f.component}@${f.componentVersion ?? "?"} via ${f.affectedRange}`;
}

function testcaseOf(f: Finding): string {
  const failing = f.verdict === "REACHABLE";
  const name = `${f.component}@${f.componentVersion ?? "?"} ${f.id}`;
  if (failing) {
    return `    <testcase name="${escapeXml(name)}">\n      <failure message="${escapeXml(traceMessage(f))}"/>\n    </testcase>`;
  }
  return `    <testcase name="${escapeXml(name)}"/>`;
}

/** The exact XML document (stable order: findings pre-sorted). */
export function junitDocument(result: AnalysisResult): string {
  const failures = result.findings.filter((f) => f.verdict === "REACHABLE").length;
  const cases = result.findings.map(testcaseOf).join("\n");
  const props = result.findings
    .map((f) => `      <property name="${escapeXml(f.purl)}" value="${escapeXml(f.verdict)}"/>`)
    .join("\n");
  const meta = `  <properties>\n    <property name="analysisStatus" value="${result.analysisStatus}"/>\n    <property name="schemaVersion" value="${result.meta.schemaVersion}"/>\n${props ? `${props}\n` : ""}  </properties>\n`;
  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="callis" tests="${result.findings.length}" failures="${failures}">\n${meta}${cases ? `${cases}\n` : ""}</testsuite>\n`;
}

export async function writeJUnitReport(result: AnalysisResult, file: string): Promise<void> {
  await writeFile(file, junitDocument(result), "utf8");
}
