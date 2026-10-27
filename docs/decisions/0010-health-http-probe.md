# 0010 — `health.http`: probe through nginx, resource limits, `health.command`

Status: accepted (iteration 2, session 2). Amended by [0054](0054-health-probe-socket.md): the probe goes over the ingress probe socket, not `weglarka-nginx:8080`.

## Decision

**Limits.** `resources = { memory = "256m", pids_limit = 200, cpus = 1.5 }`. `memory` is bytes or
`<n>[k|m|g]` (1024-based, case-insensitive, > 0); `pids_limit` is an integer > 0; `cpus` is a number in
(0, 1024]. Parsing and validation live in the contract types (`MemoryLimit`, `CpuLimit`) and in
`state::validate_app`, so `apps add/update` reject bad values with a message naming the field. Mapped to
libpod `resource_limits`: `memory.limit`, `pids.limit`, `cpu.quota = cpus × 100000` with `period = 100000`.
Unset fields are not sent at all (no field → Podman/containers.conf defaults, e.g. a pids limit of 2048).

**`health.command`.** Sent as `healthconfig.Test = ["CMD", …]` (exec form), `Interval 30s`, `Timeout 5s`,
`Retries 3`. It replaces the image's HEALTHCHECK. The deploy gate still calls `healthcheck run` itself.

**`health.http`.** The daemon does `GET path` against `weglarka-nginx:<listen port>` on `net-weglarka`
(it shares that network with nginx; it never joins an app network) with `Host: <first domain of the app>`.
The route is therefore the one real traffic takes (nginx → app network → container). The probe sends no
`X-Forwarded-*`: the daemon's address lies inside the subnet nginx trusts by default (0007), and a probe must
not lean on that trust. No redirects are followed, the body is not read, and `timeout_secs` bounds the whole
request. In one gate attempt **every configured probe must pass** (command and http); the first such attempt
ends the gate, none within `attempts` fails it. An http-only gate never passes on "merely running".
A configured probe that cannot run (no prober, no domain) fails the gate — it never silently passes.

**Apps without a domain.** `health.http` requires at least one domain (validation error, next to the existing
"requires port"). The alternative — an internal `server` per instance for probes — does not work
without more: nginx joins only the networks of apps *with* domains (`IngressManager::apply`), so it would also
need to be attached to every app's network and gain a second, unauthenticated route to the app. Apps
without a domain keep using `health.command` (or the image's HEALTHCHECK).

**`dyn` exception to 0001.** The engine holds the prober as `Arc<dyn HttpProber>` returning a boxed future
(`weglarka_core::limits`). Making `Reconciler` generic over the prober would ripple through every `impl` block
and `IngressManager`, for one small allocation saved per probe.

## Consequences

- Changing `resources` or `health.command` recreates the container (spec hash); `health.http` does not.
- The first deploy of an app can race the ingress apply (nginx not yet on the app's network): the probe
  fails, the attempt is retried, and the window (`attempts`/`window_secs`) absorbs the lag.
- Cgroup enforcement of limits needs controller delegation to the user (cgroup v2). `memory` and `pids` are
  delegated in the usual systemd user slices, `cpu` often is not; libpod records the request either way
  (visible in `inspect`). The integration test asserts `inspect` and, where delegated, the cgroup files.
