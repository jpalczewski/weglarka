# Worktrees (parallel work)

One task = one checkout: the branch lives in its own worktree, so two sessions never edit the same files, and a failed
experiment is removed together with its directory. In DSH the **Git Worktrees** bundle does this: from the **main
checkout** call `create_worktree({ name })` — it creates `.agents/worktrees/<name>` on a new branch of that name from
`HEAD`, enters it and returns `path`/`branch`/`baseCommit`. It does not copy uncommitted files and does not `fetch`, so
create the worktree **before** the first edit.

- **Start from the main checkout, not from inside a worktree.** The `workspace-write` boundary is the directory the
  session started in, not the one it enters later (`create_worktree`, `working_directory`). From the main checkout,
  `.agents/worktrees/*`, the shared `.git` and `target/` are inside the write boundary; a session started inside a
  worktree has the main `.git` and `target/` outside it (git writes need escalation).
- **Every checkout builds in its own `target/`** — do not share a build directory between worktrees (neither through a
  shared `CARGO_TARGET_DIR` nor a shared `build.build-dir`; measured 2026-10-27, #223). Workspace crate paths are hashed
  relative to the workspace root, so identical layouts produce identical artifact names, and freshness is mtime: if your
  edit is older than another worktree's build, cargo rebuilds nothing and links **that** checkout's code. crates.io
  dependencies are compiled once by sccache anyway (`RUSTC_WRAPPER=sccache`), so a private `target/` costs disk, not
  time. `~/.cargo/config.toml` may set a global `target-dir` — pin it:
  `export CARGO_TARGET_DIR="$(scripts/worktree.sh target)"`. Size: about 1.1 GB after `cargo build --workspace`, ≥2 GB
  with tests (`scripts/worktree.sh usage` shows all of them plus free space).
- Leaving: `cd` back to the checkout (the worktree and branch stay). After the PR merges, remove the worktree **together
  with its `target/`**: `scripts/worktree.sh remove .agents/worktrees/<name> --delete-branch` (that is `rm -rf target`,
  `git worktree remove`, `git worktree prune`, `git branch -D`). Stale `target/` directories are also cleaned
  periodically by `scripts/worktree.sh sweep [days]` (`cargo sweep --time 14` in every worktree; needs
  `cargo install cargo-sweep`). `.agents/worktrees/.gitignore` (`*`) keeps the pool out of `git status`.
- Agent Teams: the tool changes the directory of the calling session only. One writer = one worktree: either the Lead
  creates it before spawning teammates, or each member creates its own and lists it in the task's `write_scopes`; a
  teammate never works in the Lead's checkout.
- Without the bundle (`create_worktree` unavailable): `git worktree add .agents/worktrees/<name> -b <name> origin/main`
  and enter it — the other rules stay the same.
- The old `.claude/worktrees/` (Claude Code sessions) are excluded from searches (gitignored); do not use them for new
  work.
