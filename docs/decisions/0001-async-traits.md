# 0001 — Async in traits: native `async fn` + generics

Status: accepted (foundation, 2026-10-23).

**Decision.** Traits with I/O (`PodmanClient`, `Platform`) use native async in traits, written as
`fn … -> impl Future<Output = …> + Send` (streams: `impl Stream + Send`), and the code consuming them
is generic (`struct Reconciler<P: PodmanClient>`). No `async-trait`, no `dyn`.

**Why.** Zero allocation per call (priority: RAM), no dependency on a macro, `Send` explicit in the
signature, so `tokio::spawn` works. There is one production implementation per trait in a given
process (platform/client choice at startup), so static dispatch costs nothing. Implementations can
write plain `async fn` (the compiler checks conformance with `+ Send`).

**Exception.** Traits that must be a heterogeneous collection (`WebhookSource`: GitHub, later
Forgejo) and `SecretStore` are **synchronous and dyn-compatible**: they operate on already-loaded data
(headers+body; a small file), so async is not needed. `SecretStore` is called from async via
`spawn_blocking`.

**Consequences.** `Box<dyn PodmanClient>` is not possible; tests use `FakePodman` as a generic
parameter. If `dyn` were ever needed, a narrow `async-trait` adapter is added without changing the traits.
