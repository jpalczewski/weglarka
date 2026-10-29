# Agent workflow

How larger changes are split across parallel agent sessions (cloud and local) and reviewed before they merge. The
admin panel series ([ADR 0057](../decisions/0057-admin-panel-architecture.md)) was built this way. Conventions that
apply to every change (checks, Conventional Commits, language) stay in [CLAUDE.md](../../CLAUDE.md) and [commits and PRs](../../.claude/rules/commits-and-prs.md); issue labels and
the roadmap project are in [issues and project](issues-and-project.md).

## Stages

1. **Issue.** Every unit of work starts as a GitHub issue; see [issues and project](issues-and-project.md).
2. **ADR or plan.** A design question that has rejected alternatives gets an ADR (template:
   [`0000-template.md`](../decisions/0000-template.md)), merged before the code that depends on it. Smaller work gets a
   short plan in the issue itself.
3. **Briefs.** The plan is cut into tasks, each with a brief (template below) that is complete enough to be read cold.
4. **Parallel sessions.** Each brief goes to one session that works on its own branch and opens its own PR.
5. **Review.** Every PR is read before merge; security-relevant ones get a dedicated review (see below).
6. **Merge.** Squash after CI is green; the PR title becomes the commit on `main`.

## Cloud or local

| Run as a cloud session | Run locally |
|---|---|
| Additive API, test or documentation work | Security-sensitive code (auth, sessions, redaction) |
| Clear file list, no shared tooling needed | Iterative work where the next step depends on what you see |
| Result is checkable from the PR and CI alone | Work that needs shared tooling, a real Podman socket or an identity provider |

A cloud session does not report back when it finishes. Check the PR (and its CI) yourself instead of waiting for a
message, and read the diff before you trust the summary.

## One writer per file set

Two sessions never edit the same files at the same time. Split work by crate or directory, and when two PRs must touch
the same file, order them and merge the first before the second starts (or rebase the second onto it).

Files that tend to collide, and so need an explicit order in the plan:

- `crates/weglarka-api/src/endpoints.rs` (every new endpoint starts here)
- `crates/weglarka-daemon/src/admin.rs` (the routes for those endpoints)
- `Cargo.lock` (regenerate after a rebase with cargo; never merge it by hand)
- `CLAUDE.md` and `.claude/rules/` (one PR at a time, and only for a real convention change)

Rules for branches:

- Start from a fresh `origin/main` (`git fetch origin && git rebase origin/main`); the PR must be on the current `main`.
- Do not rewrite a branch someone else pushes to; merge `main` into it instead.
- One task, one checkout. Never share a `target/` between checkouts: a shared build directory can link another
  checkout's code without rebuilding. See [worktrees](../../.claude/rules/worktrees.md) for the commands.

## Brief template

```markdown
## Goal and context
What the change achieves and why; link the ADR or parent issue.

## Files and symbols
The files to edit and the types or functions to extend, with paths.

## Do not touch
Files and behaviour that belong to other sessions or that must stay stable
(for example `crates/weglarka-daemon/src/admin.rs` while another PR owns it).

## Issues
Closes #NN

## Checks
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/adr.sh lint        # when docs changed

## Definition of done
Observable results (tests that exist and pass, docs updated), PR title in
Conventional Commits format, PR body linking the issue.
```

Name the exact checks; "make sure it works" is not a definition of done. State what is out of scope as clearly as
what is in scope, because a session that finds an adjacent problem should file an issue, not fix it in the same PR.

## Review before merge

A security-relevant PR (label `🛡️ security`, or anything touching authentication, sessions, redaction or the token
listener) is reviewed before it merges, by someone who did not write it. The review looks at:

- **Redirects.** Open redirects, and redirect targets built from user input.
- **State binding.** `state`, PKCE verifier and nonce are bound to the browser that started the login.
- **Session fixation.** The session id is regenerated at login.
- **Token leakage.** Tokens and credentials in logs, `Debug` output, error text, URLs or responses.
- **CSRF.** Every state-changing route checks a token, and none of them answers `GET`.
- **Resource exhaustion.** Unbounded maps, queues, request bodies and streams, especially for anonymous callers.

CI must report before you squash-merge. If no checks are required on the branch, auto-merge merges immediately, so
do not enable it on a PR whose CI has not finished; wait for green first.

## Lessons

- **Changing the options of a GitHub Projects single-select field wipes the value on every item.** Back the values up
  first (item, field, value) and restore them afterwards; see [issues and project](issues-and-project.md).
- **Prefer an allowlist projection to a blocklist.** Agents tend to blank known-sensitive fields. A projection that
  rebuilds a type by destructuring every field (no `..`) stops compiling when a field is added, so someone has to
  classify it. The read view of an app (ADR 0057, decision 8) works this way.
- **`Closes #NN` is mandatory in the PR body.** It is what closes the issue on merge; without it the board drifts.
- **Review large PRs even when local checks are green.** Reviews of the panel PRs found real issues (leaked values,
  unbounded state, unchecked claims) that formatting, clippy and tests did not.
