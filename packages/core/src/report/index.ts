// M5: reports (plan section 5.6, ADR 0012).

export * from "./types.js";
export {
  assembleResult,
  computeAnalysisStatus,
  computeExposure,
  computeLimitations,
  sortFindings,
  type ResultParts,
  type StatusInput,
} from "./status.js";
export { jsonDocument, writeJsonReport } from "./json.js";
export { junitDocument, traceMessage, writeJUnitReport } from "./junit.js";
export { sarifDocument, writeSarifReport } from "./sarif.js";
