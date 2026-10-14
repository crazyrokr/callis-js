// JSON report writer (plan section 5.6, normalization contract P1.7).
//
// Deterministic: findings sorted (report/status), findings carry a fixed
// field order, no wall-clock timestamps anywhere.

import { writeFile } from "node:fs/promises";
import type { AnalysisResult } from "./types.js";

/** The exact JSON document (stable field order, stable finding order). */
export function jsonDocument(result: AnalysisResult): string {
  return `${JSON.stringify(result, null, 2)}\n`;
}

export async function writeJsonReport(result: AnalysisResult, file: string): Promise<void> {
  await writeFile(file, jsonDocument(result), "utf8");
}
