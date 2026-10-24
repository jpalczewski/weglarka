#!/bin/sh
# One cargo target directory shared by the main checkout and every git worktree of it, so the
# dependencies from crates.io are compiled once instead of once per worktree. A sandboxed agent
# (or CI in a container) cannot write the machine-wide target dir from `~/.cargo/config.toml`;
# this path lives inside the checkout and resolves to the same directory from a linked worktree,
# which is what makes the reuse work:
#
#   CARGO_TARGET_DIR="$(scripts/shared-target.sh)" cargo test --workspace
#
# Cargo serializes concurrent builds of one target dir (the second one waits for the lock), so
# parallel sessions share the artifacts instead of compiling the same crates again.
set -eu

common=$(git rev-parse --path-format=absolute --git-common-dir)
printf '%s/target\n' "$(dirname "$common")"
