# 0058 — Test coverage reporting on GitHub Pages

Status: accepted (2026-10-29).

## Problem

We want a visible, honest figure for how much of the workspace the tests exercise, and a per-file report to find
untested code. Constraints: the repository is public, CI runs on GitHub Actions, and priorities are security first
(no third-party service receiving our sources or holding a token), then simple code, then RAM.

## Decision

- A separate workflow, `.github/workflows/coverage.yml`, runs `cargo llvm-cov nextest --workspace` on every push to
  `main` that changes code (same `paths-ignore` rule as `ci.yml`) and on manual dispatch. Pull requests do not run it.
- The HTML report and a shields.io endpoint file (`badge.json`) are deployed to GitHub Pages with the official
  `deploy-pages` action; only the deploy job holds `pages: write` and `id-token: write`.
- The README badge reads `badge.json` through shields.io's endpoint badge. The metric is **line coverage**.
- The figure is informational: nothing gates on it. Tests that need a real Podman skip themselves without
  `WEGLARKA_PODMAN_SOCKET`, so the reported number is a floor.

## Consequences

- One-time setup by a repository admin: Settings → Pages → Source = "GitHub Actions". Until then the deploy job fails
  and nothing else is affected.
- No state files, API or runtime behaviour change; no rollback concerns.
- The badge and report appear only after the first run on `main`.

## Rejected alternatives

- **Codecov / Coveralls**: PR comments and diff coverage, but an external service gets the coverage data and a token
  lives in repository secrets.
- **Only a number in the CI job summary**: not visible from the README and no per-file view.
- **Gating PRs on a threshold**: a ratchet invites tests written for the metric; revisit when the number is stable.
