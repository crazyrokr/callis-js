// SARIF 2.1.0 writer (plan section 5.6, JVM ADR 0010 parity).
//
// One result per finding: ruleId = canonical advisory id, message carries
// the call trace, the PHYSICAL location is the SBOM file (so GitHub
// code-scanning has an anchor), and each trace hop is a logical location
// `file#name` (stable node identity). Unknown verdicts/properties stay
// forward-compatible (schema 2.1.0, schemaVersion independent).

import { writeFile } from "node:fs/promises";
import type { Finding } from "../verdict/types.js";
import { traceMessage } from "./junit.js";
import type { AnalysisResult } from "./types.js";

const SEVERITY_TO_LEVEL: Record<string, string> = {
  CRITICAL: "error",
  HIGH: "error",
  MEDIUM: "warning",
  LOW: "note",
};

function levelOf(severity: string): string {
  return SEVERITY_TO_LEVEL[severity.toUpperCase()] ?? "note";
}

/** One SARIF result (stable field order). */
function resultOf(f: Finding, sbomFile: string): Record<string, unknown> {
  // Physical location at the SBOM file (GitHub code-scanning anchor); each
  // trace hop is a logical location with the stable node identity.
  const locations: Record<string, unknown>[] = [
    {
      physicalLocation: {
        artifactLocation: { uri: sbomFile, index: 0 },
      },
    },
  ];
  for (const node of f.path) {
    locations.push({
      logicalLocations: [{ name: node, kind: node.endsWith("#<module-init>") ? "module" : "function" }],
    });
  }
  const properties: Record<string, unknown> = {
    purl: f.purl,
    verdict: f.verdict,
    matchLevel: f.matchLevel,
    matchedOn: f.matchedOn,
    source: f.source,
    resolutionState: f.resolutionState,
  };
  if (f.confidence !== undefined) properties.confidence = f.confidence;
  if (f.nativeBoundary !== undefined) properties.nativeBoundary = f.nativeBoundary;
  if (f.opaque === true) properties.opaque = true;
  if (f.aliases.length > 0) properties.aliases = f.aliases;
  if (f.relatedIds.length > 0) properties.relatedIds = f.relatedIds;
  if (f.supplyPath.length > 0) properties.supplyPath = f.supplyPath;

  return {
    ruleId: f.id,
    level: levelOf(f.severity),
    message: { text: traceMessage(f) },
    locations,
    properties,
  };
}

function ruleOf(f: Finding): Record<string, unknown> {
  return {
    id: f.id,
    name: f.id,
    shortDescription: { text: f.summary },
    ...(f.aliases.length > 0 ? { fullDescription: { text: f.aliases.join(", ") } } : {}),
  };
}

/** The exact SARIF 2.1.0 document (stable order: findings pre-sorted). */
export function sarifDocument(result: AnalysisResult): string {
  const rules = new Map<string, Record<string, unknown>>();
  const results: Record<string, unknown>[] = [];
  for (const f of result.findings) {
    if (!rules.has(f.id)) rules.set(f.id, ruleOf(f));
    results.push(resultOf(f, result.meta.sbomFile));
  }
  const doc = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "callis",
            version: result.meta.toolVersion,
            informationUri: "https://github.com/callis-js",
            rules: [...rules.values()],
          },
        },
        results,
        properties: {
          analysisStatus: result.analysisStatus,
          schemaVersion: result.meta.schemaVersion,
          exposure: result.exposure,
        },
      },
    ],
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}

export async function writeSarifReport(result: AnalysisResult, file: string): Promise<void> {
  await writeFile(file, sarifDocument(result), "utf8");
}
