---
paths:
  - "**/tests/**"
  - "crates/weglarka-engine/src/engine_tests.rs"
  - "crates/weglarka-cli/src/tests.rs"
  - "**/*.snap"
  - ".github/scripts/*.sh"
  - "scripts/acceptance.sh"
  - ".github/workflows/ci.yml"
  - "crates/weglarka-panel/e2e/**"
  - "crates/weglarka-panel/assets/app.js"
---

# Testing

- `cargo test --workspace` — unit tests + snapshots, no Podman. Snapshots use `insta`: commit the `.snap` files; update
  with `INSTA_UPDATE=always cargo test`, then review the diff.
- The daemon's integration tests are **one binary** (`crates/weglarka-daemon/tests/it/main.rs`); a new area = a new `mod`,
  not a new `tests/*.rs` (every binary rebuilds `Daemon<FakePodman>` from scratch). One area:
  `cargo test -p weglarka-daemon --test it -- sites::`. The panel follows the same pattern
  (`crates/weglarka-panel/tests/it/main.rs`: a module per area).
- Sandboxed environments (agent / CI in a container): the committed `.cargo/config.toml` already builds into the
  checkout's own `target/`. If cargo still writes elsewhere (`Operation not permitted`), something exported
  `CARGO_TARGET_DIR` — unset it, or pass `--target-dir "$(scripts/worktree.sh target)"`; never point at another
  checkout's `target/` (see `.claude/rules/worktrees.md`).
- **A shared build directory can lie** (measured 2026-10-24 and 2026-10-27): when two checkouts write to one `target/`
  (or `build.build-dir`), cargo may link an **old or foreign** `libweglarka_{core,api}` — either reporting errors that
  are not in the code (`unresolved import weglarka_core::images`, `no field repo_digests on type ImageInfo`,
  `ContainerSpec has no field command`), or, worse, building without error and without recompiling (0 crates) a binary
  from the other worktree's code. Do not "fix" the code then: repeat on a private directory
  `cargo test --workspace --target-dir "$PWD/target"` (a full rebuild, minutes, but trustworthy). Do not hide the
  verdict in a pipe either: `cargo test … > /tmp/log 2>&1; echo "EXIT: $?"` — `| tail` masks the exit code.
- Fake: `weglarka-engine` with `features = ["testing"]` provides `FakePodman` (scriptable pull digests, errors in the
  middle of a pull, a queue of healthcheck results, a call log). The former `weglarka-core` crate (`weglarka_core::testing::FakePodman`)
  was split into `weglarka-model` (traits) and `weglarka-engine` (the fake).
- Integration tests with real Podman 6.1 (`crates/weglarka-podman/tests/`): need `WEGLARKA_PODMAN_SOCKET` (CI sets it in
  the `podman-tests` job); without the variable the tests are skipped (`docs/decisions/0002-podman-in-ci.md`). The job
  raises the subuid pool to ~1 M (an instance range is 65 536 UIDs, ADR 0009);
  `engine_ranges_volumes_secrets_import_migration_and_purge` goes through the whole engine on real Podman.
  The subuid pool comes from the server (`PodmanClient::subuid_pool`), and `version_is_podman_6` is only enforced with
  `WEGLARKA_PODMAN_EXPECT_V6=1` (CI sets it), so the suite can run against a remote libpod socket; tests that read a
  volume mountpoint on the runner's filesystem still need the Podman host to be local.
- **Browser tests of the panel** (`crates/weglarka-panel/e2e/`, CI job `panel-e2e`): Playwright on the **Bun** runtime,
  versions pinned exactly (`package.json`, `bun.lock`). Run `bun install && bun run test` there; the script is
  `bun --bun playwright test` because without `--bun` Playwright's shebang silently runs on Node (a test asserts the
  runtime). `fixture.ts` serves the real template section, `assets/app.js`, the vendored htmx and the panel's CSP, so
  a change to `app.js` or the polled markup needs a browser test there; the Rust side of a fragment stays in
  `tests/it/`. In agent containers the preinstalled Chromium is found through `PLAYWRIGHT_BROWSERS_PATH`; this is the
  only JavaScript tooling in the repo (Cargo's `[workspace.dependencies]` rule is about Rust crates).
  CI runs the job in the official `mcr.microsoft.com/playwright` image pinned by digest; its tag must equal the
  `playwright` version in `bun.lock` (`.github/scripts/check-playwright-image.sh`), so a bump moves both.
- Static build: `cargo build --release --target x86_64-unknown-linux-musl` (CI: job `musl`).
- **Tests run in CI the way production does:** the smoke test starts the daemon from the quadlet's arguments (no
  `/etc/passwd`, no `/etc/subuid` in the `scratch` image).
- Acceptance on a host / in CI: `scripts/acceptance.sh` (canary, traffic, webhook 202/401/204, cleanup;
  `--with-local-registry` adds a deploy from a webhook and a forced rollback — CI only). Image smoke tests:
  `.github/scripts/smoke-image.sh` and `smoke-quadlet.sh` (arguments from `platform install`).
- PRs build with the `ci` profile (no LTO, `opt-level = 1`, `codegen-units = 256`, still `panic = "abort"`);
  `main` and tags with the full `release` (`docs/decisions/0008`, addendum of 2026-11-05). A PR
  changing only documentation (`docs/**`, `*.md`, `.gitignore`) runs no builds — the job `changes` skips
  `check`/`nginx-e2e`/`musl`/`podman-tests`/`smoke-behind`/`smoke-edge`/`panel-e2e`; `changes` and `pr-title` always run. A push to
  `main` with documentation only runs neither CI nor Release (`paths-ignore`) — the image is not rebuilt then; `v*` tags
  always build.

## Entry points

| Area | Files |
|---|---|
| engine tests | `crates/weglarka-engine/src/engine_tests.rs` (scenarios on `FakePodman`), module tests in `crates/weglarka-engine/src/volumes.rs` |
| daemon/API tests | `crates/weglarka-daemon/tests/it/*.rs` — one test binary (`it/main.rs`, a module per area, a new file = a new `mod`), real unix socket + `FakePodman` |
