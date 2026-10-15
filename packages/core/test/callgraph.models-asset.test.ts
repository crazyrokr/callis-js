// M6 — asset-embedding contract (plan section 7, ADR 0009): the compiled
// binary embeds the @callis/models catalogue via --asset, and Bun serves
// the embedded file FLAT next to the entry (/$bunfs/root/<basename>), while
// a source checkout resolves the workspace copy instead. This test pins the
// source-side half (the flat candidate must be absent so the workspace copy
// wins; the binary-side half is verified in CI by running the compiled
// binary from an empty directory — scripts/binary-smoke.ts).

import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { loadModels, modelFileCandidates } from "../src/callgraph/models.js";
import { TOOL_VERSION } from "../src/index.js";

describe("model asset candidates (dual-mode loading)", () => {
  test("given a source checkout, when resolving a catalogue file, then the flat binary-asset candidate is absent and the workspace copy exists", () => {
    for (const file of ["library-models.json", "entry-point-annotations.json", "callback-interfaces.json"]) {
      const [flat, workspace] = modelFileCandidates(file) as [URL, URL];
      // No stray copy of the catalogue next to the module in a checkout.
      expect(existsSync(flat.pathname), `flat candidate for ${file} must not exist in source`).toBe(false);
      // The workspace @callis/models data resolves from this module.
      expect(existsSync(workspace.pathname), `workspace copy of ${file} must exist`).toBe(true);
    }
  });

  test("given a source checkout, when loadModels() is called without a directory, then the workspace copy is loaded (flat candidate misses, workspace candidate hits)", async () => {
    const cat = await loadModels();
    expect(cat.models.length).toBeGreaterThan(0);
    expect(Object.keys(cat.annotations.routes).length).toBeGreaterThan(0);
    expect(cat.callbackInterfaces.interfaces.length).toBeGreaterThan(0);
  });

  test("given a data directory with a missing catalogue file, when loaded, then it rejects (models are part of the soundness contract, no silent empty)", async () => {
    await expect(loadModels("/nonexistent/callis-models-data-m6")).rejects.toThrow(/models/);
  });
});

describe("tool version (compiled binary --define, plan section 7)", () => {
  test("given no BUILD_VERSION define (source checkout), when TOOL_VERSION is read, then it falls back to the release literal", () => {
    expect(TOOL_VERSION).toBe("0.1.0");
  });
});
