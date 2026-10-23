# Węglarka image: static binaries (musl) on `scratch` — no shell, no libc, no CA
# (the daemon talks only to the Podman socket; Podman pulls the images). Decisions: docs/decisions/0006.
#
#   podman build -t weglarka -f Containerfile .
#
# No `USER`: in rootless Podman the container's root is the host's runtime user, and only that user
# has access to the mounted sockets and the state directory (0005: paths mounted 1:1).

ARG RUST_IMAGE=docker.io/library/rust:1.99.1-alpine

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

FROM scratch
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="weglarka" \
      org.opencontainers.image.description="Węglarka — deploy-tool dla rootless Podmana" \
      org.opencontainers.image.source="https://github.com/jpalczewski/weglarka" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build /out/weglarka-daemon /out/weglarka /usr/local/bin/
ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/weglarka-daemon"]
CMD ["run"]
