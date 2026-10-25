# 0002 — Podman 6.1 in integration tests: install from OBS on the runner

Status: accepted (foundation, 2026-10-23); to be confirmed by the first green run of the job.

**Options.** (A) `apt install` from OBS `home:alvistack` on `ubuntu-24.04` with apt pinning;
(B) Podman in a container (`--privileged`, Podman-in-Podman / Docker).

**Decision: A.**
- The `ubuntu-24.04` runner mirrors the production host (Ubuntu 24.04.4, cgroups v2, systemd 255) —
  the test also exercises the same delivery channel and pinning that will go to production.
- Rootless Podman in a container requires privileged mode and nested user namespaces, which changes
  the semantics of `userns=auto`/subuid — that is exactly what we want to test.
- Cost: installation from an external repo (tens of seconds) and a dependency on OBS availability.
  Mitigation: the `podman-tests` job is separate; if OBS fails it does not block fmt/clippy/test.

**Contract with the tests (session a).** The job starts `podman system service` and exports
`WEGLARKA_PODMAN_SOCKET`. Integration tests read this variable and skip when it is absent
(locally `cargo test` stays fast and without Podman).

**Operational note (measured in CI, 2026-10-23).** `download.opensuse.org` redirects to mirrors that
could serve `.deb` files of a different size than the index (`File has unexpected size`) and
`apt install` failed repeatably. We use `downloadcontent.opensuse.org` (the OBS server without mirrors).
**The same note applies to the Ansible task for the production host.**

**Package conflict (measured in CI).** Ubuntu's `golang-github-containers-common` (a dependency of
Podman 4.9, preinstalled on the runner) has no `Replaces` against `containers-common` from alvistack
— `dpkg` refuses to overwrite `/etc/containers/policy.json`. Before installing, the Ubuntu stack must be
uninstalled (`apt purge podman buildah skopeo crun conmon golang-github-containers-*`).
On the production host there is no Podman, so this does not apply — but the Ansible task should ensure it.
