// M2 fixture builders: small on-disk project trees (npm/pnpm layouts,
// lockfiles, symlinks) for the resolver and state fixture matrix.

import { existsSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface FixtureOpts {
  /** rel path -> file content. */
  files: Record<string, string>;
  /** [link rel, target rel or absolute] — directory symlinks. */
  symlinks?: [string, string][];
}

/** Create a throwaway project tree under the system temp dir. */
export async function mkFixture(opts: FixtureOpts): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "callis-m2-"));
  for (const [rel, content] of Object.entries(opts.files)) {
    const full = join(root, rel);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, content);
  }
  for (const [link, target] of opts.symlinks ?? []) {
    const linkPath = join(root, link);
    const targetPath = target.startsWith("/") ? target : join(root, target);
    mkdirSync(join(linkPath, ".."), { recursive: true });
    if (!existsSync(targetPath)) writeFileSync(targetPath, "");
    // A link replaces whatever placeholder the file map left at that path.
    rmSync(linkPath, { recursive: true, force: true });
    symlinkSync(targetPath, linkPath, "dir");
  }
  return root;
}

/** A package.json body (name/version + optional extra fields). */
export function pkg(name: string, version: string, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ name, version, ...extra });
}

/** A minimal SBOM-shaped component list (the M2 tie/state input). */
export function sbomComponents(
  specs: { ref: string; name: string; version?: string; devOnly?: boolean; purl?: string }[],
  dependencies: { ref: string; dependsOn: string[] }[] = [],
) {
  return {
    format: "cyclonedx-1.5",
    components: specs.map((s) => {
      const c: { purl: string; name: string; version?: string; devOnly: boolean; ref: string } = {
        purl: s.purl ?? `pkg:npm/${s.name}${s.version !== undefined ? `@${s.version}` : ""}`,
        name: s.name,
        devOnly: s.devOnly ?? false,
        ref: s.ref,
      };
      if (s.version !== undefined) c.version = s.version;
      return c;
    }),
    dependencies,
    hasDevMarkers: false,
    warnings: [],
    fileSha256: "0".repeat(64),
    file: "/dev/null",
  };
}
