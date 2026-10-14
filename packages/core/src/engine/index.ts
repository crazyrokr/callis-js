// M5: engine facade + policy layer (plan section 5.6, ADR 0016).

export { decideExitCode, reachableFindings, type PolicyDecision, type PolicyFlags } from "./policy.js";
export {
  reportFiles,
  runAnalysis,
  validateFlags,
  type Console,
  type EngineOptions,
} from "./engine.js";
