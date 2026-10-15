// M6 — pure-part contract of the compile pipeline: magic-byte validation,
// SHA256SUMS formatting, host-target selection. (The real compile + --version
// smoke is exercised in CI by scripts/binary-smoke.ts on native runners.)

import { describe, expect, test } from "bun:test";
import {
  type HostProbe,
  TARGETS,
  hostFamily,
  isHostTarget,
  readHostProbe,
  sha256Hex,
  sumsLines,
  targetArch,
  validateMagicBytes,
} from "./build.js";

const ELF = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01]);
// The four canonical Mach-O spellings (MH_MAGIC / MH_MAGIC_64 in either byte order).
const MACHO_LE64 = new Uint8Array([0xcf, 0xfa, 0xed, 0xfe]); // 0xfeedfacf, little-endian
const MACHO_BE32 = new Uint8Array([0xfe, 0xed, 0xfa, 0xce]); // 0xfeedface, big-endian
const MACHO_BE64 = new Uint8Array([0xfe, 0xed, 0xfa, 0xcf]); // 0xfeedfacf, big-endian
const MACHO_LE32 = new Uint8Array([0xce, 0xfa, 0xed, 0xfe]); // 0xfeedface, little-endian
const PE = new Uint8Array([0x4d, 0x5a, 0x90, 0x00]);

describe("validateMagicBytes", () => {
  test("given ELF bytes, when checked against the elf family, then it is accepted", () => {
    expect(validateMagicBytes(ELF, "elf")).toBe(true);
  });

  test("given Mach-O bytes in every canonical spelling, when checked against macho, then each is accepted", () => {
    expect(validateMagicBytes(MACHO_LE64, "macho")).toBe(true);
    expect(validateMagicBytes(MACHO_BE32, "macho")).toBe(true);
    expect(validateMagicBytes(MACHO_BE64, "macho")).toBe(true);
    expect(validateMagicBytes(MACHO_LE32, "macho")).toBe(true);
  });

  test("given PE bytes, when checked against the pe family, then it is accepted", () => {
    expect(validateMagicBytes(PE, "pe")).toBe(true);
  });

  test("given bytes of one family, when checked against a DIFFERENT family, then it is rejected (false-positive guard)", () => {
    expect(validateMagicBytes(ELF, "pe")).toBe(false);
    expect(validateMagicBytes(ELF, "macho")).toBe(false);
    expect(validateMagicBytes(MACHO_LE64, "elf")).toBe(false);
    expect(validateMagicBytes(PE, "elf")).toBe(false);
  });

  test("given a truncated buffer (fewer than 4 bytes), when checked, then it is rejected without throwing", () => {
    expect(validateMagicBytes(new Uint8Array([0x7f, 0x45]), "elf")).toBe(false);
    expect(validateMagicBytes(new Uint8Array([0x4d]), "pe")).toBe(false);
    expect(validateMagicBytes(new Uint8Array(), "macho")).toBe(false);
  });

  test("given near-miss magic bytes (one byte off), when checked, then they are rejected", () => {
    const nearMissElf = new Uint8Array([0x7f, 0x45, 0x4c, 0x50]); // 'P' not 'F'
    const nearMissMacho = new Uint8Array([0xcf, 0xfb, 0xed, 0xfe]); // fb not fa
    expect(validateMagicBytes(nearMissElf, "elf")).toBe(false);
    expect(validateMagicBytes(nearMissMacho, "macho")).toBe(false);
  });

  test("given the eight release targets, when each is validated against its own family, then the family table is well-formed", () => {
    expect(TARGETS.length).toBe(8);
    const suffixes = TARGETS.map((t) => t.suffix);
    expect(new Set(suffixes).size).toBe(8);
  });
});

describe("sha256Hex / sumsLines", () => {
  test("given the empty-string vector, when hashed, then the known SHA-256 constant is produced", () => {
    expect(sha256Hex(new Uint8Array([]))).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  test("given entries in arbitrary order, when rendered, then lines are sorted by path with the sha256 two-space format", () => {
    const out = sumsLines([
      { file: "dist/callis-linux-x64", hex: "a".repeat(64) },
      { file: "dist/callis-darwin-arm64", hex: "b".repeat(64) },
      { file: "dist/callis-linux-x64-musl", hex: "c".repeat(64) },
    ]);
    const lines = [
      `${"b".repeat(64)}  dist/callis-darwin-arm64`,
      `${"a".repeat(64)}  dist/callis-linux-x64`,
      `${"c".repeat(64)}  dist/callis-linux-x64-musl`,
    ];
    expect(out).toBe(`${lines.join("\n")}\n`);
  });

  test("given an empty entry list, when rendered, then the result is the empty string (no header, no trailing newline)", () => {
    expect(sumsLines([])).toBe("");
  });

  test("given duplicate paths, when rendered, then both lines are kept (one line per artifact)", () => {
    const out = sumsLines([
      { file: "dist/callis-linux-x64", hex: "a".repeat(64) },
      { file: "dist/callis-linux-x64", hex: "b".repeat(64) },
    ]);
    expect(out.split("\n")).toHaveLength(3); // two lines + trailing newline
  });
});

describe("isHostTarget", () => {
  test("given the current host, when every target is tested, then exactly the executable targets are selected (and at most one per architecture)", () => {
    const host = hostFamily();
    if (host === null) {
      expect(TARGETS.some((t) => isHostTarget(t))).toBe(false);
      return;
    }
    const executable = TARGETS.filter((t) => isHostTarget(t));
    expect(executable.length).toBeGreaterThan(0);
    // No target from another family is ever executable here.
    for (const t of TARGETS) {
      if (t.family !== host) expect(isHostTarget(t)).toBe(false);
    }
  });

  test("given a non-host family target, when tested, then it is rejected (cross-compiled binaries are not run in this pipeline)", () => {
    const foreign = TARGETS.filter((t) => t.family !== hostFamily());
    for (const t of foreign) expect(isHostTarget(t)).toBe(false);
  });
});

describe("targetArch", () => {
  test("given every target, when the arch is derived, then arm64 suffixes are arm64 and everything else x64 (musl/baseline keep the base arch)", () => {
    for (const t of TARGETS) {
      const expected = t.suffix.includes("arm64") ? "arm64" : "x64";
      expect(targetArch(t)).toBe(expected);
    }
  });
});

describe("isHostTarget (probe)", () => {
  const glibcX64: HostProbe = { family: "elf", arch: "x64", musl: false, glibc: true };
  const muslArm64: HostProbe = { family: "elf", arch: "arm64", musl: true, glibc: false };
  const mixedX64: HostProbe = { family: "elf", arch: "x64", musl: true, glibc: true };
  const bareX64: HostProbe = { family: "elf", arch: "x64", musl: false, glibc: false };
  const darwinX64: HostProbe = { family: "macho", arch: "x64", musl: false, glibc: false };
  const darwinArm64: HostProbe = { family: "macho", arch: "arm64", musl: false, glibc: false };
  const windowsX64: HostProbe = { family: "pe", arch: "x64", musl: false, glibc: false };
  const unknown: HostProbe = { family: null, arch: "x64", musl: false, glibc: false };

  function executableOn(probe: HostProbe): string[] {
    return TARGETS.filter((t) => isHostTarget(t, probe)).map((t) => t.suffix);
  }

  test("given a glibc x64 host, when every target is tested, then only the glibc x64 variants run (musl and arm64 are not spawnable here)", () => {
    expect(executableOn(glibcX64)).toEqual(["linux-x64", "linux-x64-baseline"]);
  });

  test("given a glibc x64 host, when the musl target is tested, then it is rejected (its interpreter is absent — the ENOENT trap)", () => {
    const muslX64 = TARGETS.find((t) => t.suffix === "linux-x64-musl");
    if (muslX64 === undefined) throw new Error("fixture: linux-x64-musl missing from TARGETS");
    expect(isHostTarget(muslX64, glibcX64)).toBe(false);
  });

  test("given a musl arm64 host, when every target is tested, then only the arm64 musl variant runs", () => {
    expect(executableOn(muslArm64)).toEqual(["linux-arm64-musl"]);
  });

  test("given a host with BOTH loaders, when every target is tested, then the glibc and musl x64 variants all run (false-positive guard: no family/arch mismatch sneaks in)", () => {
    expect(executableOn(mixedX64).sort()).toEqual(["linux-x64", "linux-x64-baseline", "linux-x64-musl"]);
  });

  test("given a stripped chroot with no known loader, when every target is tested, then nothing runs (a missing loader is not a spawnable host)", () => {
    expect(executableOn(bareX64)).toEqual([]);
  });

  test("given a darwin x64 host, when the Mach-O targets are tested, then the x64 binary runs and the arm64 one does not", () => {
    expect(executableOn(darwinX64)).toEqual(["darwin-x64"]);
  });

  test("given a darwin arm64 host, when the Mach-O targets are tested, then both run (x64 under Rosetta, arm64 natively)", () => {
    expect(executableOn(darwinArm64).sort()).toEqual(["darwin-arm64", "darwin-x64"]);
  });

  test("given a windows x64 host, when every target is tested, then only windows-x64 runs", () => {
    expect(executableOn(windowsX64)).toEqual(["windows-x64"]);
  });

  test("given an unknown platform family, when every target is tested, then nothing runs", () => {
    expect(executableOn(unknown)).toEqual([]);
  });

  test("given the real host, when readHostProbe is used, then family matches hostFamily and the probe-based selection equals the default-argument selection", () => {
    const probe = readHostProbe();
    expect(probe.family).toBe(hostFamily());
    for (const t of TARGETS) expect(isHostTarget(t, probe)).toBe(isHostTarget(t));
  });
});
