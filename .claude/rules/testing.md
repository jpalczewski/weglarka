---
paths:
  - "**/tests/**"
  - "crates/weglarka-engine/src/engine_tests.rs"
  - "crates/weglarka-cli/src/tests.rs"
  - "**/*.snap"
  - ".github/scripts/*.sh"
  - "scripts/acceptance.sh"
  - ".github/workflows/ci.yml"
---

# Testing

- `cargo test --workspace` — unit tests + snapshots, no Podman. Snapshots use `insta`: commit the `.snap` files; update
  with `INSTA_UPDATE=always cargo test`, then review the diff.
- The daemon's integration tests are **one binary** (`crates/weglarka-daemon/tests/it/main.rs`); a new area = a new `mod`,
  not a new `tests/*.rs` (every binary rebuilds `Daemon<FakePodman>` from scratch). One area:
  `cargo test -p weglarka-daemon --test it -- sites::`. The panel follows the same pattern
  (`crates/weglarka-panel/tests/it/main.rs`: a module per area).
- Sandboxed environments (agent / CI in a container): if cargo cannot write to the global `target-dir`
  (`Operation not permitted`), set `CARGO_TARGET_DIR` to a directory writable in the sandbox — for a worktree its own
  `target/` (`CARGO_TARGET_DIR="$(scripts/worktree.sh target)"`); never point at another checkout's `target/` (see
  `.claude/rules/worktrees.md`).
- **A shared build directory can lie** (measured 2026-10-24 and 2026-10-27): when two checkouts write to one `target/`
  (or `build.build-dir`), cargo may link an **old or foreign** `libweglarka_{core,api}` — either reporting errors that
  are not in the code (`unresolved import weglarka_core::images`, `no field repo_digests on type ImageInfo`,
  `ContainerSpec has no field command`), or, worse, building without error and without recompiling (0 crates) a binary
  from the other worktree's code. Do not "fix" the code then: repeat on a private directory
  `CARGO_TARGET_DIR="$PWD/target" cargo test --workspace` (a full rebuild, minutes, but trustworthy). Do not hide the
  verdict in a pipe either: `cargo test … > /tmp/log 2>&1; echo "EXIT: $?"` — `| tail` masks the exit code.
- Fake: `weglarka-engine` with `features = ["testing"]` provides `FakePodman` (scriptable pull digests, errors in the
  middle of a pull, a queue of healthcheck results, a call log). The former `weglarka-core` crate (`weglarka_core::testing::FakePodman`)
  was split into `weglarka-model` (traits) and `weglarka-engine` (the fake).
- Integration tests with real Podman 6.1 (`crates/weglarka-podman/tests/`): need `WEGLARKA_PODMAN_SOCKET` (CI sets it in
  the `podman-tests` job); without the variable the tests are skipped (`docs/decisions/0002-podman-in-ci.md`). The job
  raises the subuid pool to ~1 M (an instance range is 65 536 UIDs, ADR 0009);
  `engine_ranges_volumes_secrets_import_migration_and_purge` goes through the whole engine on real Podman.
- Static build: `cargo build --release --target x86_64-unknown-linux-musl` (CI: job `musl`).
- **Tests run in CI the way production does:** the smoke test starts the daemon from the quadlet's arguments (no
  `/etc/passwd`, no `/etc/subuid` in the `scratch` image).
- Acceptance on a host / in CI: `scripts/acceptance.sh` (canary, traffic, webhook 202/401/204, cleanup;
  `--with-local-registry` adds a deploy from a webhook and a forced rollback — CI only). Image smoke tests:
  `.github/scripts/smoke-image.sh` and `smoke-quadlet.sh` (arguments from `platform install`).
- PRs build with the `ci` profile (thin LTO); `main` and tags with the full `release` (`docs/decisions/0008`). A PR
  changing only documentation (`docs/**`, `*.md`, `.gitignore`) runs no builds — the job `changes` skips
  `check`/`nginx-e2e`/`musl`/`podman-tests`/`smoke-behind`/`smoke-edge`; `changes` and `pr-title` always run. A push to
  `main` with documentation only runs neither CI nor Release (`paths-ignore`) — the image is not rebuilt then; `v*` tags
  always build.

## Entry points

| Area | Files |
|---|---|
| engine tests | `crates/weglarka-engine/src/engine_tests.rs` (scenarios on `FakePodman`), module tests in `crates/weglarka-engine/src/volumes.rs` |
| daemon/API tests | `crates/weglarka-daemon/tests/it/*.rs` — one test binary (`it/main.rs`, a module per area, a new file = a new `mod`), real unix socket + `FakePodman` |
