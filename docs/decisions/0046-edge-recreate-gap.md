# 0046 — Edge mode: no refused connections while nginx or the forwarder is replaced

Status: accepted (2026-10-25, issue #183). Cause established from the code and the report (a stop that takes the full timeout); the gap itself is measured on a real host, not in CI.

## Problem

On a production edge host every public hostname refused connections for ~15 s, twice a day, while a SIGHUP
reload was seamless. The daemon logged only `ingress applied … Recreated`. Two things add up:

* The forwarder (ADR 0043) owns the public ports and was recreated on every daemon self-update, because its
  identity included the daemon image id. Its process is the container's PID 1 and handled no signal, so
  `podman stop` waited the whole stop timeout (10 s) and then killed it: the ports were closed from the stop
  until the new container started — a refused connection, not a slow one.
* When nginx itself is recreated (image, hardening, hash format, published address), the forwarder dialled the
  unix socket once, failed and dropped the client, for as long as nginx was stopping (up to the SIGQUIT drain),
  being created and started.

## Decision

1. **The forwarder is not recreated by a daemon self-update.** Its identity is `FORWARDER_REVISION` (a constant in
   `daemon/src/ingress.rs`), the publishes and the hardening — not the image id. It is a stateless relay with a
   stable command line; bump the revision when its behaviour must change. It keeps running the daemon image it
   was created from until then.
2. **The forwarder exits on SIGTERM/SIGINT** and is stopped with a 3 s timeout, so the unavoidable recreate (a
   changed `bind`/`https_bind`, a revision bump) closes the ports for about a second instead of ten.
3. **The forwarder holds clients while nginx is away**: connecting to nginx's socket is retried every 100 ms for up
   to 20 s on "missing"/"refused" before the client is dropped. A nginx recreate (stop, create, start) therefore
   shows up as a slow first request, not a failure.
4. **Every recreate says why.** Both containers carry a `weglarka.ingress-spec` label with the canonical JSON the
   hash was computed from; on a mismatch the daemon diffs it with the wanted spec and logs
   `reason = "changed: image, bind"` (or "container predates the recorded spec") and the measured `gap_ms`
   (stop → start) in a `warn` line next to `ingress applied`. The label is informational; only the hash decides.

A blue/green swap of nginx (start the new container before removing the old) is not possible with the current
constraints: both would bind the same unix socket files in the shared directory and the new one would need the
old one's `nginx.conf` mount and networks. Item 3 gives the same client-visible effect.

## Consequences

* Upgrading recreates the forwarder once (new identity format `v2`) and both containers once more to gain the
  spec label (`predates the recorded spec`); later daemon updates leave the forwarder alone.
* No `apps.toml`/`state.toml`/`weglarka.toml` change. Downgrade: an older daemon recreates the forwarder (its hash
  differs) once and ignores the new label.
* A forwarder that never restarts keeps the daemon image of its creation alive on disk; remove the container
  (`podman rm -f weglarka-forwarder`) to move it on, or bump the revision.
* Tests: `edge_self_update_keeps_the_forwarder_and_a_changed_publish_replaces_it`, `recreate_reason_*`,
  `forwarder_identity_*`, and the late-socket connect test in `forwarder.rs`.

## Rejected alternatives

* *Keep the image id in the forwarder hash and only fix the stop.* Still ~1 s of refused connections on every
  update; the relay does not change between releases.
* *Socket activation / passing the listening fds across the swap.* Needs systemd, which ADR 0043 avoids on purpose.
* *Create the new container under a temporary name first.* Saves only the create step (milliseconds); the stop
  was the cost.
