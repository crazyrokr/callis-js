# callis-js container image (plan section 7).
#
# Multi-arch (linux/amd64 + linux/arm64 via buildx). The image carries the
# prebuilt static glibc binary — the models catalogue is embedded in the
# binary (--asset), so NO model files are needed in the image or at runtime.
#
# Usage (project mounted at /workspace, the default --project):
#   docker run -v $(pwd):/workspace -v $(pwd):/workspace \
#     ghcr.io/<org>/callis-js:latest \
#     --sbom sbom.json --osv-dir osv
#
# The binary is built with --no-compile-autoload-dotenv and
# --no-compile-autoload-bunfig: a mounted project's .env / bunfig.toml can
# NOT steer the analysis (verified by scripts/binary-smoke.ts).
FROM debian:bookworm-slim

# TARGETARCH is provided by buildx per platform (amd64 | arm64).
ARG TARGETARCH

COPY dist/callis-linux-x64 /tmp/bin/callis-linux-x64
COPY dist/callis-linux-arm64 /tmp/bin/callis-linux-arm64

RUN set -eux; \
    if [ "$TARGETARCH" = "amd64" ]; then BIN=callis-linux-x64; \
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
