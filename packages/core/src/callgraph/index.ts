// M4: call graph and entry points (plan section 5.5).

export * from "./types.js";
export * from "./models.js";
export { CallGraphBuilder, buildGraph, type BuildResult } from "./builder.js";
export { dispatchClosure, supertypeClosures, type ExtendsMap } from "./pointer.js";
export { makeLinker, type LinkerOptions } from "./linker.js";
export {
  appFilesOf,
  detectEntryPoints,
  frameworkRouteEntries,
  globMatch,
  globToRegex,
  parseEntryTokens,
  type DetectContext,
  type DetectOptions,
  type DetectionResult,
} from "./entrypoints.js";
