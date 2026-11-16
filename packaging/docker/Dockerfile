# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
#
# Rustegon server image (docker.md, FR-INS-003, ADR-030, PD-150). Build from the repository
# root: `packaging/docker/build.sh` (or `docker buildx build -f packaging/docker/Dockerfile .`).
# Base images are pinned by multi-arch index digest; bump them deliberately.

# GUI first: its output is embedded into rustegond at compile time (ADR-027, PD-130). The
# assets do not depend on the target architecture, so this stage runs on the build platform.
FROM --platform=$BUILDPLATFORM node:24.21.0-bookworm-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20 AS gui
WORKDIR /src/gui
COPY gui/package.json gui/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY gui/ ./
RUN npm run build

# Release binaries, cross-compiled on the build platform for the target platform (build.sh).
FROM --platform=$BUILDPLATFORM rust:1-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS build
ARG TARGETPLATFORM
# Optional parallelism cap of the Rust build (hosts with little memory).
ARG CARGO_BUILD_JOBS=
WORKDIR /src
COPY . .
COPY --from=gui /src/gui/dist gui/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=rustegon-target-$TARGETPLATFORM \
    ./packaging/docker/build.sh "$TARGETPLATFORM" /out

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /out/rustegond /out/rustegon /usr/bin/
# The data volume must exist owned by the server user: a named volume copies it on first use.
COPY --from=build --chown=10001:10001 /out/data /var/lib/rustegon
USER 10001:10001
VOLUME ["/var/lib/rustegon"]
EXPOSE 7700 7710 7780
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=6 CMD ["/usr/bin/rustegon","health","--ready"]
ENTRYPOINT ["/usr/bin/rustegond"]
CMD ["--config-from-env"]
