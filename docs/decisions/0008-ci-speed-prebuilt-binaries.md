# 0008 — CI speed: prebuilt binaries, `ci` profile, no regex stack

Status: accepted (2026-10-23). Supplements 0006 (packaging); the "CI" paragraph there is superseded by this note.
Amended by the addendum below (2026-11-05, #578): the `ci` profile no longer inherits `release`'s LTO and
`opt-level = "z"`.

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
2. **`[profile.ci]`** (`inherits = "release"`, initially `lto = "thin"`, `codegen-units = 16`; lighter since the
   addendum below) for pull requests; `main` and tags use the full `release` profile. Trade-off: an image from a PR
   is **not bit-for-bit the production binary** (different LTO/codegen, a bit larger and a bit slower), so PR smoke
   tests prove behaviour, not the final artifact. Smoke tests on `main` run on the full `release` profile before
   anything is published. `main`
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
   (`actions/cache/restore`, key = the versions pinned in the action); a hit installs them with `dpkg -i` and no
   OBS request, and only `main` fills the cache (`actions/cache/save`) — a miss is a normal install from OBS (#579).
5. **Fewer dependencies.** `tracing-subscriber` without `env-filter` (removes `regex`, `regex-automata`,
   `regex-syntax`, `matchers`, … — 39 crates from `Cargo.lock`). **Behaviour change:** `RUST_LOG` is now a plain
   level (`error|warn|info|debug|trace|off`); per-target directives (`weglarka=debug,hyper=warn`) are no longer
   parsed, and an unparsable value means `info`. The quadlet and image only ever set `RUST_LOG=info`.
   `clap` stays (large share of the build, but derive use is everywhere; replacing it is not a small change).

## Addendum (2026-11-05): a cheaper `ci` profile (#578)

**Problem.** `[profile.ci]` inherited `release` (`opt-level = "z"`, `codegen-units = 1`) and only replaced the link
step (`lto = "thin"`, `codegen-units = 16`). That is the wrong half to optimize: PR smoke binaries are not the
production artifact (point 2 above), yet `cargo build --profile ci` was 115 s of the `musl` job on the PR critical
path (`musl` 165 s → `smoke-behind` 117 s), most of it spent in optimization passes and the LTO link of three
binaries.

**Decision.** The `ci` profile keeps `panic = "abort"` and a stripped binary but drops what costs time and buys
nothing for a smoke run:

```toml
[profile.ci]
inherits = "release"
lto = false
opt-level = 1
codegen-units = 256
debug = 0
strip = "symbols"
panic = "abort"
```

`debug = 0` and `strip = "symbols"` are what `release` already resolves to; they are written out so the profile
reads as a whole. Deliberately **not** `inherits = "dev"`: the smoke and acceptance windows (`--health-window 4`,
`--dup-wait 5`, point 3 above) were tuned on optimized binaries and unoptimized ones change deploy and health-check
latency. `release` is untouched — `main`, tags, the published image and the release tarball are unchanged.

**Measurements.** Local host, 8 logical CPUs, shared with other agent sessions (load average 2–13 during the runs),
sccache (`RUSTC_WRAPPER`) unset so every crate really compiled, `rm -rf target/x86_64-unknown-linux-musl` before
each cold run. Command, exactly as in `ci.yml`:

```
cargo build --profile ci --locked --target x86_64-unknown-linux-musl -p weglarka-daemon -p weglarka-cli -p weglarka-panel
```

Six interleaved rounds, before (`lto = "thin"`, `codegen-units = 16`, `opt-level = "z"`) and after alternating:

| scenario | before | after | |
|---|---|---|---|
| cold — empty `target/x86_64-unknown-linux-musl`, 175 crates | 43.5–98.1 s, median **56.9 s** | 36.4–72.8 s, median **37.1 s** | −35 % |
| warm — `touch crates/weglarka-model/src/lib.rs`, 14 crates + 3 links | 39.6–74.2 s, median **40.4 s** | 27.8–72.3 s, median **28.5 s** | −29 % |

The warm case is the shape of a normal PR (the `musl-ci` cache restored, only changed crates rebuilt); the cold case
is what *this* PR itself sees, because the changed profile invalidates the whole restored cache. The spread is the
shared host, not the profile: in 11 of the 12 paired runs the after build was faster, the exception being one round
where both runs sat in the same load spike (72.0 s vs 72.3 s). A one-run sweep of the individual keys, same host:

| profile | cold | warm |
|---|---|---|
| `lto = false`, `opt-level = "z"`, `codegen-units = 16` | 41.7 s | 36.7 s |
| `lto = false`, `opt-level = 1`, `codegen-units = 16` | 50.8 s | 49.5 s |
| `lto = false`, `opt-level = "z"`, `codegen-units = 256` | 34.6 s | 32.1 s |
| `lto = false`, `opt-level = 1`, `codegen-units = 256` (chosen) | 37.1 s | 28.5 s |

So the win is the dropped LTO link plus the many codegen units; `opt-level = 1` versus `"z"` is inside the noise
here, and `1` is the better of the two for a binary that must behave like production under a timing window.

**Consequences.**

- The smoke binaries are bigger — stripped and static: `weglarka` 6.7 → 8.8 MB, `weglarka-daemon` 12.2 → 15.8 MB
  (+30 %), `weglarka-panel` 5.1 → 6.1 MB (+19 %) — so the `musl-bin` artifact and the throwaway
  `--build-arg BIN_SOURCE=prebuilt` image grow by the sum of the two binaries (~5.7 MB). Nothing published changes —
  `release` builds the real artifact.
- Speed, not size: the runtime cost is a slower daemon than `release`, which is why `main` and tags still build
  `release` and the pre-merge smoke tests on `main` run on the production profile.
- Caches: `seed-ci-cache` keeps writing the single `musl-ci` target cache, now with the new flags; a PR that changes
  this profile pays one cold build, later PRs restore it.
- This is a floor, not a target: going further (unoptimized dependencies, `opt-level = 0` anywhere) turns the smoke
  binaries into `dev` binaries and invalidates the timing assumptions above.
