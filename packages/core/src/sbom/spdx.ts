// SPDX 2.x (JSON) reader (plan section 5.1). SPDX 3.x is refused explicitly
// (exit 2, UsageError) — v1 reads SPDX 2.3 documents only.
//
// Dev-marker rules: SPDX 2.x has no scope field; `DEV_DEPENDENCY_OF`
// relationships mark dev-only components. An SBOM without such relationships
// analyzes every component (no DEV_ONLY verdicts) — the safe default.

import { z } from "zod";
import { UsageError } from "../util/errors.js";
import type { Purl } from "./purl.js";
import { parsePurl } from "./purl.js";
import type { NpmComponent, SbomParseResult } from "./types.js";

const spdxPackage = z.object({
  spdxId: z.string().optional(),
  name: z.string().optional(),
  versionInfo: z.string().optional(),
  purl: z.string().optional(),
});

const spdxRelationship = z.object({
  spdxElementId: z.string(),
  relatedSpdxElement: z.string(),
  relationshipType: z.string(),
});

const spdx2 = z.object({
  spdxVersion: z.string(),
  name: z.string().optional(),
  packages: z.array(spdxPackage).default([]),
  relationships: z.array(spdxRelationship).default([]),
});

export function parseSpdx(json: string, file: string, fileSha256: string): SbomParseResult {
  let doc: unknown;
  try {
    doc = JSON.parse(json);
  } catch (e) {
    throw new UsageError(`SBOM is not valid JSON: ${file}: ${(e as Error).message}`);
  }
  const spdxVersion = (doc as { spdxVersion?: string }).spdxVersion;
  if (spdxVersion !== undefined && !spdxVersion.startsWith("SPDX-2")) {
    // SPDX 3.x (or any other major) — refused explicitly, plan section 5.1.
    throw new UsageError(`SBOM format not supported: ${spdxVersion} (SPDX 3.x is refused in v1): ${file}`);
  }
  let parsed: Spdx2Doc;
  try {
    parsed = spdx2.parse(doc);
  } catch {
    throw new UsageError(`SBOM is not a valid SPDX 2.x document: ${file}`);
  }
  return spdxToResult(parsed, file, fileSha256);
}

type Spdx2Doc = z.infer<typeof spdx2>;

function spdxToResult(doc: Spdx2Doc, file: string, fileSha256: string): SbomParseResult {
  const components: NpmComponent[] = [];
  const warnings: string[] = [];
  const devRefs = new Set<string>();
  let hasDevMarkers = false;

  for (const rel of doc.relationships) {
    if (rel.relationshipType === "DEV_DEPENDENCY_OF") {
      devRefs.add(rel.spdxElementId);
    }
  }
  if (devRefs.size > 0) hasDevMarkers = true;

  const ids = new Set(
    doc.relationships.map((r) => r.spdxElementId).concat(doc.relationships.map((r) => r.relatedSpdxElement)),
  );
  for (const pkg of doc.packages) {
    if (pkg.purl === undefined) {
      warnings.push(`package without purl skipped: ${pkg.name ?? pkg.spdxId ?? "unknown"}`);
      continue;
    }
    let p: Purl;
    try {
      p = parsePurl(pkg.purl);
    } catch {
      warnings.push(`package with malformed purl skipped: ${pkg.purl}`);
      continue;
    }
    if (p.type !== "npm") {
      warnings.push(`non-npm package skipped: ${pkg.purl}`);
      continue;
    }
    const ref = pkg.spdxId ?? `SPDXRef-Package:${pkg.purl}`;
    const isDev = hasDevMarkers && devRefs.has(ref);
    const version = p.version ?? pkg.versionInfo;
    components.push({
      purl: pkg.purl,
      name: p.name,
      ...(version !== undefined ? { version } : {}),
      devOnly: isDev,
      ref,
    });
  }

  // SPDX 2.x dependencies come from DEPENDS_ON / DEPENDENCY_OF relationships.
  const dependencies = doc.relationships
    .filter((r) => r.relationshipType === "DEPENDS_ON" || r.relationshipType === "DEPENDENCY_OF")
    .map((r) => ({
      ref: r.spdxElementId,
      dependsOn: [r.relatedSpdxElement],
    }))
    .filter((d) => ids.has(d.ref));

  return {
    format: `spdx-${doc.spdxVersion.replace("SPDX-", "")}`,
    components,
    dependencies,
    hasDevMarkers,
    warnings,
    fileSha256,
    file,
  };
}
