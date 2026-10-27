#!/bin/sh
# Build-directory helper for parallel git worktrees. Every checkout builds into its OWN `target/`:
# a directory shared between worktrees (a shared CARGO_TARGET_DIR, or a shared `build.build-dir`)
# makes cargo reuse an artifact built from another worktree's sources whenever your edit is older
# than that build, and it does so silently (0 crates recompiled, wrong binary). Dependencies from
# crates.io are still compiled once across worktrees by sccache (RUSTC_WRAPPER=sccache).
#
#   export CARGO_TARGET_DIR="$(scripts/worktree.sh target)"   # pin cargo to this checkout's target/
#   scripts/worktree.sh usage                                 # target/ size of every worktree + free disk
#   scripts/worktree.sh remove <worktree path> [--delete-branch]
#   scripts/worktree.sh sweep [days]                          # cargo sweep --time <days> (default 14)
#
# The pin is needed because a machine-wide `target-dir` in ~/.cargo/config.toml would otherwise send
# every worktree to the same directory.
set -eu

top=$(git rev-parse --show-toplevel)

# `git worktree list --porcelain` prints "worktree <path>" blocks; paths may contain spaces.
worktrees() {
    git worktree list --porcelain | sed -n 's/^worktree //p'
}

free_disk() {
    df -h "$top" | awk 'NR==2 { print $4 " free" }'
}

case "${1:-}" in
target)
    printf '%s/target\n' "$top"
    ;;
usage)
    worktrees | while IFS= read -r wt; do
        if [ -d "$wt/target" ]; then
            size=$(du -sh "$wt/target" | cut -f1)
        else
            size=-
        fi
        printf '%8s  %s\n' "$size" "$wt"
    done
    free_disk
    ;;
remove)
    [ $# -ge 2 ] || { echo "usage: $0 remove <worktree path> [--delete-branch]" >&2; exit 2; }
    wt=$(cd "$2" && pwd -P)
    main=$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")
    [ "$wt" != "$main" ] || { echo "refusing to remove the main checkout" >&2; exit 1; }
    branch=$(git -C "$wt" symbolic-ref --quiet --short HEAD || true)
    # target/ is untracked, so `git worktree remove` would not need it gone; dropping it first is what frees the disk.
    rm -rf "$wt/target"
    git worktree remove "$wt"
    git worktree prune
    if [ "${3:-}" = "--delete-branch" ] && [ -n "$branch" ]; then
        git branch -D "$branch"
    fi
    free_disk
    ;;
sweep)
    command -v cargo-sweep >/dev/null || { echo "needs: cargo install cargo-sweep" >&2; exit 1; }
    days=${2:-14}
    worktrees | while IFS= read -r wt; do
        [ -d "$wt/target" ] || continue
        CARGO_TARGET_DIR="$wt/target" cargo sweep --time "$days" "$wt"
    done
    free_disk
    ;;
*)
    echo "usage: $0 target | usage | remove <worktree path> [--delete-branch] | sweep [days]" >&2
    exit 2
    ;;
esac
