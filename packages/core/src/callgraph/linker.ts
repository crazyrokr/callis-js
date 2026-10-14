// M2-resolver → call-graph linker adapter (plan sections 5.3 / 5.5).
//
// The builder never touches the resolver directly; it receives a Linker so
// tests can inject stubs and the CLI can wire the real M2 resolution
// (profiles a/b2, the type field, tsconfig aliases) in one place.

import { dirname } from "node:path";
import { resolveSpecifier } from "../project/resolver.js";
import type { ProjectModel } from "../project/types.js";
import type { Linker } from "./types.js";

export interface LinkerOptions {
  /** Allow tsconfig-path aliases for app code (profile b2, plan 5.3). */
  allowTsconfigAliases?: boolean;
}

/** Build a Linker over the M2 resolver for a resolved project model. */
export function makeLinker(model: ProjectModel, options: LinkerOptions = {}): Linker {
  const allowTsconfigAliases = options.allowTsconfigAliases ?? true;
  return {
    resolve(fromFile: string, specifier: string, format: "import" | "require"): string | null {
      const decision = resolveSpecifier(specifier, dirname(fromFile), model, {
        format,
        allowTsconfigAliases,
      });
      if (decision.status === "resolved" || decision.status === "tsconfig-alias") {
        return decision.target ?? null;
      }
      return null;
    },
  };
}
