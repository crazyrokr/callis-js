// SARIF 2.1.0 writer (plan section 5.6, JVM ADR 0010 parity).
//
// One result per finding: ruleId = canonical advisory id, message carries
// the call trace, and the PHYSICAL location is the SBOM file (so GitHub
// code-scanning has an anchor). M7b: findings with a call path also carry
// `codeFlows` — one threadFlow per path, each hop a PHYSICAL location
// (file + line) from the graph's node locations; a hop without a known
// node falls back to a logical location `file#name` (stable node
// identity). Unknown verdicts/properties stay forward-compatible (schema
// 2.1.0, schemaVersion independent).

import { writeFile } from "node:fs/promises";
import type { Finding } from "../verdict/types.js";
import { traceMessage } from "./junit.js";
import type { AnalysisResult } from "./types.js";

/** The source location of one graph node (the codeFlow physical anchor). */
export interface NodeLocation {
  file: string;
  line: number;
}

const SEVERITY_TO_LEVEL: Record<string, string> = {
  CRITICAL: "error",
  HIGH: "error",
  MEDIUM: "warning",
  LOW: "note",
};

function levelOf(severity: string): string {
  return SEVERITY_TO_LEVEL[severity.toUpperCase()] ?? "note";
}

/** One codeFlow location for a path node: physical (file + line) when the
 *  node is in the location map, logical (stable node id) when it is not. */
function hopOf(node: string, nodeLocations: Record<string, NodeLocation> | undefined): Record<string, unknown> {
  const loc = nodeLocations?.[node];
  if (loc !== undefined) {
    return {
      physicalLocation: {
        artifactLocation: { uri: loc.file },
        region: { startLine: loc.line },
      },
    };
  }
  return {
    logicalLocations: [{ name: node, kind: node.endsWith("#<module-init>") ? "module" : "function" }],
  };
}

/** One SARIF result (stable field order). */
function resultOf(
  f: Finding,
  sbomFile: string,
  nodeLocations: Record<string, NodeLocation> | undefined,
): Record<string, unknown> {
  // The result-level physical location is the SBOM file (GitHub
  // code-scanning anchor). The call path rides in codeFlows (M7b).
  const locations: Record<string, unknown>[] = [
    {
      physicalLocation: {
        artifactLocation: { uri: sbomFile, index: 0 },
      },
    },
  ];
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
    ...(f.path.length > 0
      ? {
          codeFlows: [
            {
              id: 1,
              message: { text: traceMessage(f) },
              threadFlows: [{ locations: f.path.map((node) => hopOf(node, nodeLocations)) }],
            },
          ],
        }
      : {}),
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

/** The exact SARIF 2.1.0 document (stable order: findings pre-sorted).
 *  `nodeLocations` (optional, from the built graph) turns codeFlow hops
 *  into physical locations; without it the hops stay logical node ids. */
export function sarifDocument(result: AnalysisResult, nodeLocations?: Record<string, NodeLocation>): string {
  const rules = new Map<string, Record<string, unknown>>();
  const results: Record<string, unknown>[] = [];
  for (const f of result.findings) {
    if (!rules.has(f.id)) rules.set(f.id, ruleOf(f));
    results.push(resultOf(f, result.meta.sbomFile, nodeLocations));
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

export async function writeSarifReport(
  result: AnalysisResult,
  file: string,
  nodeLocations?: Record<string, NodeLocation>,
): Promise<void> {
  await writeFile(file, sarifDocument(result, nodeLocations), "utf8");
}
