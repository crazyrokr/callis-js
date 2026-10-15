# Build-tool integration: Turborepo and Nx

`callis` answers a content-sensitive question (is this SBOM
vulnerability reachable FROM THIS SOURCE TREE with THIS install state?),
so task runners that cache by input files fit it exactly: the same
content-aware cacheability the JVM tool gets from the Gradle/Maven
plugins. This page is the M7e/M8 recipe (plan v3.3 C3).

## The contract

A `callis` task declares as **inputs** everything the input key is
computed from (plan §6 `--print-cache-key`, the canonical definition the
M8 flag prints):

- application sources (the whole tree, default exclusions
  `node_modules/`, `.git/`, `dist/`, `build/`, `.next/`, `coverage/`,
  `.turbo/`, the cache dir; `--source-exclude`/`--source-include`
  override),
- every lockfile variant present (`package-lock.json`,
  `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`,
  `bun.lock`/`bun.lockb`),
- the SBOM file, the OSV snapshot pin, the mappings file,
- the effective flag set.

and as **outputs** the reports (`callis-report.json`,
`callis-report.junit.xml`, `callis-report.sarif`). Deterministic report
bytes (sorted findings, no wall-clock in the cache-relevant part —
`durationMillis` is excluded from keys and from the binary-parity
comparison) make caching safe: unchanged inputs yield byte-identical
reports.

**Until M8** (the `--print-cache-key` flag) the recipes below declare the
inputs EXPLICITLY so the task runner hashes exactly the right files.
**From M8** the canonical task hash is `callis --print-cache-key`
(computable before the run); the explicit lists above mirror that
definition, and `--hash-installed` extends the key with content hashes
of every installed file (without it, task-level caching cannot see an
in-place patch of a package — a documented caveat, not a default).

## Turborepo

`turbo.json`:

```json
{
  "tasks": {
    "callis:check": {
      "inputs": [
        "src/**",
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lock",
        "sbom.json",
        "vuln-mappings.json"
      ],
      "outputFiles": [
        "callis-report.json",
        "callis-report.junit.xml",
        "callis-report.sarif"
      ]
    }
  }
}
```

`package.json` (the npm package exposes the `callis` bin, M7d):

```json
{
  "scripts": {
    "callis:check": "callis --project . --sbom sbom.json --osv-dir osv-npm --mappings vuln-mappings.json --output callis-report"
  },
  "devDependencies": {
    "@callis/cli": "^0.1.0"
  }
}
```

`bun run turbo callis:check` then runs callis only when an input
changed; the cached reports are reused otherwise. (The task must run
where `osv-npm/` exists — the snapshot is an input file like any
other; keep it in the repo or restore it from a cache keyed on its pin.)

## Nx

`nx.json`:

```json
{
  "targetDefaults": {
    "callis:check": {
      "inputs": [
        "{workspaceProject}#sources",
        "project.json"
      ]
    }
  }
}
```

with the same file set declared as the project's `sources` (application
sources + the lockfile variants + `sbom.json` + `vuln-mappings.json`),
or, from M8, `computeHash` over `callis --print-cache-key` output.
`project.json`:

```json
{
  "targets": {
    "callis:check": {
      "executor": "nx:run-commands",
      "options": {
        "command": "callis --project . --sbom sbom.json --osv-dir osv-npm --mappings vuln-mappings.json --output callis-report"
      },
      "outputs": ["{projectRoot}/callis-report.{json,junit.xml,sarif}"]
    }
  }
}
```

## Caveats (same in both)

- **No lockfile and no install-state file** → full-result caching is
  disabled for the run (callis prints a warning; per-file IR caching
  still applies). Task-level caching then re-runs on every change of any
  declared input, which is the safe direction.
- **In-place patches** of installed packages are invisible to the
  default key; use `--hash-installed` (M8) if you patch packages by
  hand.
- The OSV snapshot pin is part of the key: bumping the snapshot
  re-runs the analysis even when nothing else changed.
