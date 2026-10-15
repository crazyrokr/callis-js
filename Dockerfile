# callis-js glibc container image (plan section 7, per-platform M7d).
#
# One image per linux glibc variant; the musl variants live in
# Dockerfile.musl (alpine base). The binary carries the @callis/models
# catalogue embedded via --asset, so NO model files are needed in the image
# or at runtime.
#
# VARIANT selects the binary (buildx provides TARGETARCH per platform):
#   ""          arch default: amd64 -> callis-linux-x64, arm64 -> callis-linux-arm64
#   "baseline"  callis-linux-x64-baseline (amd64 only, AVX2-less CPUs)
#
# Usage (project mounted at /workspace, the default --project):
#   docker run -v $(pwd):/workspace ghcr.io/<org>/callis-js:<variant> \
#     --sbom sbom.json --osv-dir osv
#
# The binary is built with --no-compile-autoload-dotenv and
# --no-compile-autoload-bunfig: a mounted project's .env / bunfig.toml can
# NOT steer the analysis (verified by scripts/binary-smoke.ts).
FROM debian:bookworm-slim

ARG TARGETARCH
ARG VARIANT=""

COPY dist/callis-linux-x64 /tmp/bin/callis-linux-x64
COPY dist/callis-linux-x64-baseline /tmp/bin/callis-linux-x64-baseline
COPY dist/callis-linux-arm64 /tmp/bin/callis-linux-arm64

RUN set -eux; \
    if [ "$VARIANT" = "baseline" ]; then BIN=callis-linux-x64-baseline; \
    elif [ "$TARGETARCH" = "amd64" ]; then BIN=callis-linux-x64; \
    elif [ "$TARGETARCH" = "arm64" ]; then BIN=callis-linux-arm64; \
    else echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1; fi; \
    install -m 0755 /tmp/bin/$BIN /usr/local/bin/callis; \
    rm -rf /tmp/bin; \
    # No shell user assumptions: run as the invoking uid, read-only by default.
    callis --version

ENV XDG_CACHE_HOME=/var/cache/callis
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/callis"]
CMD ["--help"]
