// M5: verdicts (plan section 5.6, ADRs 0012-0013).

export * from "./types.js";
export * from "./reach.js";
export * from "./mapping.js";
export * from "./candidate.js";
export { decideVerdict, parseMappingsFile, unmappedIds, type VerdictOptions } from "./verdict.js";
