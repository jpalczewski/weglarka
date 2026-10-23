# Obraz Węglarki: statyczne binarki (musl) na `scratch` — bez shella, bez libc, bez CA
# (demon rozmawia tylko z socketem Podmana; obrazy ściąga Podman). Decyzje: docs/decisions/0006.
#
#   podman build -t weglarka -f Containerfile .
#
# Bez `USER`: w rootless Podmanie root kontenera to użytkownik runtime'u z hosta, a tylko on
# ma dostęp do zamontowanych socketów i katalogu stanu (0005: ścieżki montowane 1:1).

ARG RUST_IMAGE=docker.io/library/rust:1.99.1-alpine

FROM ${RUST_IMAGE} AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates ./crates
# Obraz bazowy to Alpine (musl), więc build bez --target jest statyczny dla architektury buildu.
# Cache rejestru i katalogu target przyspiesza kolejne budowy; binarki kopiujemy poza cache.
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
