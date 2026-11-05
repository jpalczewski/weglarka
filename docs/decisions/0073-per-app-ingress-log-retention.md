# 0073 — Per-app ingress log files and retention

Status: proposed (2026-11-05, issue #553)

## Problem

ADR 0070 keeps one shared access log and one host-wide `[logs] retention`, and lists per-app retention as a rejected
alternative. Sites on one host now promise different periods in their privacy policies (e.g. 30 days for one site,
90 or 180 for others), while `weglarka access` should keep the long history of the sites that allow it.

## Decision

Stub — reserved number. To be written with the implementation of #553; this ADR supersedes the "per-app retention"
rejection of ADR 0070. Already decided:

- One directory per app (`ingress-logs/apps/<app>/`) with a `.retention` sidecar; static per-`server` `access_log` and
  `error_log` paths.
- Optional app field `log_retention` (same values as `[logs] retention`), outside `spec_hash`, `apps.toml` schema 21.
  It may be longer or shorter than the host default; there is no host cap.
- Files shared by several apps use the shortest period of all apps.

## Consequences

To be written.

## Rejected alternatives

To be written (one shared file at the shortest period, retention only in Loki, a host cap on per-app periods).
