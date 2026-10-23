# 0008 — CI speed: prebuilt binaries, `ci` profile, no regex stack

Status: accepted (2026-10-23). Supplements 0006 (packaging); the "CI" paragraph there is superseded by this note.

**Problem.** The critical path of CI was `image` (a full `cargo build --release` inside the `Containerfile`,
~4 min on a cold runner: `COPY crates` busts the layer on every change and BuildKit cache mounts do not
survive between GitHub runners) → `integration-podman` (~3 min). Everything else ran in parallel but each job paid
for its own toolchain install and cache.

**Decisions.**

1. **Build the binaries once, assemble the image from them.** The `musl` job builds `weglarka-daemon` + `weglarka`
   (`x86_64-unknown-linux-musl`, `rust-cache`) and uploads them as the `musl-bin` artifact. The `Containerfile` has a
   build-arg `BIN_SOURCE`: the default `build` compiles from source (local `podman build -t weglarka .` keeps
   working, no setup needed); `BIN_SOURCE=prebuilt` copies `bin/weglarka-daemon` and `bin/weglarka` onto
   `scratch` (same labels, `ENTRYPOINT`, `CMD`). Unused stages are skipped by BuildKit and Buildah.
   - CI: `integration-podman` (needs `musl`) downloads the artifact, builds the image with `podman build` in seconds and
     runs the smoke tests with those very binaries (also as the host CLI/daemon — they are static). The separate
     `image` job and the image-tar artifact are gone: they only added a runner start-up and an upload/download.
   - `release.yml`: the `binaries` matrix is now the only compilation. The linux/musl leg runs on every push to
     `main` (macOS only for tags) and its binaries feed both the image (`BIN_SOURCE=prebuilt`) and the release
     tarball. The image job no longer builds, so the GHA layer cache is dropped. cosign signature, SBOM
     and attestation are unchanged.
2. **`[profile.ci]`** (`inherits = "release"`, `lto = "thin"`, `codegen-units = 16`) for pull requests; `main`
   and tags use the full `release` profile. Trade-off: an image from a PR is **not bit-for-bit the production
   binary** (different LTO/codegen, a bit larger and a bit slower), so PR smoke tests prove behaviour, not the final
   artifact. Smoke tests on `main` run on the full `release` profile before anything is published. `main`
   additionally seeds the `ci`-profile cache (`seed-ci-cache` job) because a `release` cache is useless to PRs
   (caches are only written on `main`, `save-if`).
   Note: the `release.yml` binaries are built separately from CI's `release` build of the same commit
   (same toolchain and flags, but not guaranteed bit-identical); making publication wait for the CI run on that
   commit is a possible follow-up.
3. **Smoke test waits.** The 96 s of the acceptance run was almost entirely sleeping: the canary has no
   healthcheck, so the default gate (30 s window) waits it out; the duplicate-delivery check watched for 25 s.
   `acceptance.sh` gained `--health-window` and `--dup-wait`; CI passes `4` and `5`. Production defaults and
   the script's defaults are unchanged.
4. **Jobs and caches.** `shellcheck`, `fmt`, `clippy`, `test` and `nginx -t` are one `check` job (fmt → clippy →
   test → nginx), sharing one toolchain install and one debug `target/` (`shared-key: check`). `rust-cache` writes
   only on `main`; PRs restore read-only. `musl` uses separate keys per profile. Podman `.deb`s are cached
   (`actions/cache`, key = candidate versions of `podman`, `netavark`, `passt`); an empty cache is a normal install.
5. **Fewer dependencies.** `tracing-subscriber` without `env-filter` (removes `regex`, `regex-automata`,
   `regex-syntax`, `matchers`, … — 39 crates from `Cargo.lock`). **Behaviour change:** `RUST_LOG` is now a plain
   level (`error|warn|info|debug|trace|off`); per-target directives (`weglarka=debug,hyper=warn`) are no longer
   parsed, and an unparsable value means `info`. The quadlet and image only ever set `RUST_LOG=info`.
   `clap` stays (large share of the build, but derive use is everywhere; replacing it is not a small change).
