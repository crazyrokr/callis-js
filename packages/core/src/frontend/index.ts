// M3: front end and IR (plan section 5.4).

export * from "./types.js";
export { parseModule, parserVersion } from "./parse.js";
export { parseFile, parseFiles, irKey, type CacheStats } from "./cache.js";
