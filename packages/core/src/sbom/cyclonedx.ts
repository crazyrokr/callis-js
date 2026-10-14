// CycloneDX 1.4-1.6 (JSON) reader (plan section 5.1).
//
// Dev-marker rules: CycloneDX `scope` ("excluded" / "optional") and the
// `cdx:npm:is-dev` property mark dev-only components. An SBOM without any
// dev markers analyzes every component (no DEV_ONLY verdicts) — the safe
// default. Recommended producers: npm sbom, @cyclonedx/cyclonedx-npm, cdxgen.

import { z } from "zod";
import { UsageError } from "../util/errors.js";
import type { Purl } from "./purl.js";
import { parsePurl } from "./purl.js";
import type { DependencyEdge, NpmComponent, SbomParseResult } from "./types.js";

const cdxComponent = z.object({
  ref: z.string().optional(),
  name: z.string(),
  version: z.string().optional(),
  purl: z.string().optional(),
  type: z.string().optional(),
  scope: z.string().optional(),
  properties: z.array(z.object({ name: z.string(), value: z.string() })).default([]),
});

const cycloneDx = z.object({
  bomFormat: z.literal("CycloneDX"),
  specVersion: z.enum(["1.4", "1.5", "1.6"]),
  serialNumber: z.string().optional(),
  version: z.number().default(1),
  components: z.array(cdxComponent).default([]),
  dependencies: z.array(z.object({ ref: z.string(), dependsOn: z.array(z.string()).default([]) })).default([]),
});

export function parseCycloneDx(json: string, file: string, fileSha256: string): SbomParseResult {
  let doc: unknown;
  try {
    doc = JSON.parse(json);
  } catch (e) {
    throw new UsageError(`SBOM is not valid JSON: ${file}: ${(e as Error).message}`);
  }
  let parsed: CycloneDxDoc;
  try {
    parsed = cycloneDx.parse(doc);
  } catch {
    throw new UsageError(`SBOM is not a CycloneDX 1.4-1.6 document: ${file}`);
  }
  return cdxToResult(parsed, file, fileSha256);
}

type CycloneDxDoc = z.infer<typeof cycloneDx>;

function cdxToResult(doc: CycloneDxDoc, file: string, fileSha256: string): SbomParseResult {
  const components: NpmComponent[] = [];
  const warnings: string[] = [];
  let hasDevMarkers = false;

  for (const c of doc.components) {
    if (c.purl === undefined) {
      warnings.push(`component without purl skipped: ${c.name}@${c.version ?? "unknown"}`);
      continue;
    }
    let p: Purl;
    try {
      p = parsePurl(c.purl);
    } catch {
      warnings.push(`component with malformed purl skipped: ${c.purl}`);
      continue;
    }
    if (p.type !== "npm") {
      warnings.push(`non-npm component skipped: ${c.purl}`);
      continue;
    }
    const isDev =
      c.scope === "excluded" ||
      c.scope === "optional" ||
      c.properties.some((prop) => prop.name === "cdx:npm:is-dev" && prop.value === "true");
    if (isDev) hasDevMarkers = true;
    const version = p.version ?? c.version;
    components.push({
      purl: c.purl,
      name: p.name,
      ...(version !== undefined ? { version } : {}),
      devOnly: isDev,
      ref: c.ref ?? c.purl,
    });
  }

  const dependencies: DependencyEdge[] = doc.dependencies.map((d) => ({
    ref: d.ref,
    dependsOn: [...d.dependsOn],
  }));
  return {
    format: `cyclonedx-${doc.specVersion}`,
    components,
    dependencies,
    hasDevMarkers,
    warnings,
    fileSha256,
    file,
  };
}
