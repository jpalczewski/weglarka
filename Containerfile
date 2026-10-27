# Węglarka image: static binaries (musl) on `scratch` — no shell, no libc, no system CA store
# (the daemon talks only to the Podman socket; Podman pulls the images). The one outbound HTTPS
# client — notifications to ntfy — trusts the roots bundled by `webpki-roots`, not `/etc/ssl`.
# Decisions: docs/decisions/0006 (packaging), docs/decisions/0021 (notifications).
#
#   podman build -t weglarka -f Containerfile .                                  # from source (local)
#   podman build -t weglarka -f Containerfile --build-arg BIN_SOURCE=prebuilt .  # CI/release: bin/{weglarka-daemon,weglarka}
#
# `prebuilt` copies already-built static binaries from ./bin instead of compiling them, so the image CI and
# release publish contains exactly the binaries that were tested (docs/decisions/0008). The unused `build`
# stage is skipped by BuildKit and by Buildah.
#
# No `USER`: in rootless Podman the container's root is the host's runtime user, and only that user
# has access to the mounted sockets and the state directory (0005: paths mounted 1:1).

ARG RUST_IMAGE=docker.io/library/rust:1.99.1-alpine
ARG BIN_SOURCE=build

FROM ${RUST_IMAGE} AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates ./crates
# The base image is Alpine (musl), so a build without --target is static for the build architecture.
# The registry and target caches speed up subsequent builds; the binaries are copied out of the cache.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
        -p weglarka-daemon -p weglarka-cli \
 && install -D -t /out target/release/weglarka-daemon \
        target/release/weglarka

FROM scratch AS prebuilt
COPY --chmod=0755 bin/weglarka-daemon bin/weglarka /out/

FROM ${BIN_SOURCE} AS bin

FROM scratch
ARG VERSION=dev
ARG REVISION=unknown
# The state schema this image writes (crates/weglarka-model/src/state.rs). The self-updater compares
# the label with the running daemon's schema before replacing the image (docs/decisions/0023).
ARG STATE_SCHEMA=14
LABEL org.opencontainers.image.title="weglarka" \
      org.opencontainers.image.description="Węglarka — deploy-tool dla rootless Podmana" \
      org.opencontainers.image.source="https://github.com/jpalczewski/weglarka" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      io.weglarka.state-schema="${STATE_SCHEMA}"
COPY --from=bin /out/weglarka-daemon /out/weglarka /usr/local/bin/
ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/weglarka-daemon"]
CMD ["run"]
