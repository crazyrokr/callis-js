# callis GitHub Action

Answers **is this vulnerability in the SBOM actually reachable from
application code?** in GitHub Actions: downloads the pinned `callis`
release binary, verifies it, runs the analysis, and fails the step on
`REACHABLE` findings (or on a stale `expected-reachable` pin).

## Usage

```yaml
jobs:
  callis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # The OSV snapshot lives in your repo or a cache; it is an INPUT to
      # the analysis (callis never downloads advisories at run time).
      - uses: callis-js/callis-js@main
        with:
          version: 0.1.0
          # REPO-PINNED digest of the binary for this runner (Renovate
          # bumps it with the version). Never fetched from the release:
          # the release's own SHA256SUMS is not independent evidence.
          sha256: <pinned-sha256>
          sbom: sbom.json
          osv-dir: osv-npm
          mappings: vuln-mappings.json
          expected-reachable: expected-reachable.txt
      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: callis-report
          path: callis-report.json
```

Optional: verify the signature too (install cosign first):

```yaml
      - uses: sigstore/cosign-installer@v3
        with:
          version: 2.5.3
      - uses: callis-js/callis-js@main
        with:
          # ... plus:
          cosign-identity: "<repo-owner>+callis-js@github.com"
```

## Verification contract (ADR 0017)

1. **The SHA256 digest is always checked** against the REPO-PINNED value
   before the binary runs. A mismatch fails the step and the binary is
   never executed.
2. **The cosign signature is optional** (skipped with a warning when
   cosign is not on PATH) — it is independent evidence, but the digest
   pin is the hard gate.

## Platform target selection

The release asset is chosen from the runner OS/arch plus two host
probes: a musl loader present → the `-musl` asset; an x64 host without
the `AVX2` CPU flag → the `-baseline` asset. (A musl host without AVX2
is unsupported: no musl-baseline asset exists.)

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `version` | — | The callis release version to run. |
| `sha256` | — | The REPO-PINNED digest of the binary for this platform. |
| `cosign-identity` | — | Optional certificate identity (cosign on PATH). |
| `cosign-issuer` | `https://token.actions.githubusercontent.com` | The certificate OIDC issuer. |
| `release-repo` | `callis-js/callis-js` | The repository that publishes the releases. |
| `release-url` | — | Optional full download-URL override (mirrors). |
| `binary` | — | Optional local binary (air-gapped CI); the digest is still verified. |
| `project` | `.` | The project directory to analyze. |
| `sbom` | — | The SBOM file (CycloneDX / SPDX 2.x). |
| `osv-dir` | — | The local OSV npm snapshot directory. |
| `mappings` | — | Optional `vuln-mappings.json`. |
| `output` | `callis-report` | Report base name (`.json` / `.junit.xml` / `.sarif`). |
| `formats` | `json,junitxml,sarif` | Comma-separated report formats. |
| `extra-args` | — | Extra callis flags, space separated (e.g. `--cha --include-dev`). |
| `expected-reachable` | — | Optional repo-pinned `expected-reachable.txt` (a living integration test). |

## Outputs

- `exit-code` — the callis exit code (`0` clean, `1` REACHABLE / MAL /
  OPAQUE, `2` usage/config, `3` analysis failure).
- `report-json` — the path of the JSON report.

## `expected-reachable.txt`

The same format as the golden demos: lines `<VERDICT> <id>` (a finding
must exist with exactly that verdict) or `ABSENT <id>` (no finding may
exist); every finding must be accounted for. A stale or malformed pin
fails the step with exit `2` — independent of the callis exit code — so
a dependency change that alters the verdicts is caught in CI.
