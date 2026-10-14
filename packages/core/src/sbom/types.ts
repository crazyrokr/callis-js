// SBOM model shared by the CycloneDX and SPDX readers (plan section 5.1).

export interface NpmComponent {
  /** Canonical purl (pkg:npm/<name>@<version>, percent-encoded scope). */
  purl: string;
  name: string;
  /** Version from the purl; absent when the purl carries none. */
  version?: string;
  /** True when the SBOM marks the component dev-only (see marker rules). */
  devOnly: boolean;
  /** Component reference id (CDX ref / SPDX package id) for the supply path. */
  ref: string;
}

export interface DependencyEdge {
  ref: string;
  dependsOn: string[];
}

export interface SbomParseResult {
  format: string;
  /** Every component with an npm purl. */
  components: NpmComponent[];
  /** SBOM dependencies[] graph (may be absent — SPDX 2.x often lacks one). */
  dependencies: DependencyEdge[];
  /** True when the SBOM carries at least one dev marker of any kind. */
  hasDevMarkers: boolean;
  /** Warnings: skipped non-npm components, malformed entries, ... */
  warnings: string[];
  /** sha256 of the SBOM file (part of the input cache key, plan section 6). */
  fileSha256: string;
  /** Absolute path of the SBOM file (report metadata sbomFile). */
  file: string;
}
