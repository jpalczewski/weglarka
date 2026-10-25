# Crash loop and unhealthy detection

An app that keeps crashing used to go unnoticed: every container runs with `restart = always`, so Podman brings it back before the next reconcile pass notices anything wrong, and the health gate checks the healthcheck only at deploy time. The reconcile loop now detects two conditions and emits them as **engine events**: with notifications configured they go to ntfy (see [notifications](notifications.md)), without them they stay in the daemon log. Decision and rejected alternatives: [ADR 0022](../decisions/0022-crash-loop-detection.md). Configuration snippet: [`monitor.toml`](../examples/monitor.toml).

**What is emitted:**

- `crash loop: <app>` (critical): the number of **new** restarts in the window reached the threshold. The counter is libpod's `RestartCount`; recreating the container (deploy, recreate, rollback) starts counting from zero, so a new version does not inherit the old one's alarm.
- `unhealthy: <app>` (warning): the container healthcheck has been failing for `unhealthy_observations` consecutive observations. A container without a healthcheck is never reported this way.
- `running again: <app>` (info): the app is healthy again, either a whole window without a new restart or the healthcheck passing again. One event per recovery, not per observation.

**Configuration** (an optional section; the defaults work without it):

```toml
[monitor]
crash_loop_restarts = 3        # how many new restarts in the window = a loop; 0 disables detection
crash_loop_window_secs = 600   # counter window and the quiet period after which the app counts as recovered
unhealthy_observations = 2     # how many consecutive failing-healthcheck observations = unhealthy; 0 disables
```

- **No extra load:** detection uses the container list that reconcile fetches anyway (`container_list` inspects every container) and writes nothing to disk. Everything happens in memory and under the engine mutex, so an observation never overlaps with a deploy.
- **Daemon restart:** the observation state is in memory. The first observation after startup only sets a baseline, so a loop that is already running raises the alarm after a further `crash_loop_restarts` restarts, not immediately.
- **Apps with `start = false`, apps waiting for secrets, and apps before their first deploy:** they have no container, so they generate no events. Containers that are not in `apps.toml` (being cleaned up) are skipped too.
- **Repeats:** the detector sends one event per loop, not one per restart; the notification dedup windows (see [notifications](notifications.md)) still collect a summary if an app flaps between failing and recovering.

## Rollback

`[monitor]` is a new section in `weglarka.toml`, so an older daemon will not read it. Before a downgrade, remove it together with `[notify]` (see [verify and rollback](verify-and-rollback.md)).
