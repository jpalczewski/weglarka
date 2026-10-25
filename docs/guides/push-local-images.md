# Deploying a locally built image (weglarka push)

`weglarka push <app> …` deploys an image that did not arrive through the webhook: one built on your laptop, or
another tag of the app's image repository. It goes through the same path as every deploy — health gate,
rollback, `current` / `previous` / `failed` in `state.toml`. Decision:
[ADR 0042](../decisions/0042-push-local-images.md).

```sh
# an archive from the laptop (a file or stdin); it travels through the SSH tunnel to the admin socket
podman save --format oci-archive ghcr.io/me/app:dev | weglarka push app -
weglarka push app ./app.tar

# another tag of the same repository: the host pulls it (with `<app>.registry-auth`, if the app has one)
weglarka push app --image ghcr.io/me/app:sha-1f2e3d4     # same as `weglarka deploy app --image …`
```

- **What the daemon does with an archive:** loads it into Podman's image store (`oci-archive` or
  `docker-archive`, a plain tar rather than `.tar.gz`), tags the image `<app's repository>:pushed` and deploys
  its digest. The archive is streamed, never held in the daemon's memory; the limit is 8 GiB and only one
  upload runs at a time (a second one is a 409). An upload does not block other deploys — only the deploy that
  follows takes the engine lock.
- **The digest** is the one of the image *after* loading. A `docker-archive` carries no manifest, so Podman
  computes one and it differs from the registry's digest; the same archive always gives the same digest, so
  pushing an unchanged image again ends in `Unchanged`.
- **`apps.toml` is not touched:** push changes only the pin in `state.toml`. The next webhook (or `apps deploy`)
  for the spec's tag deploys the tag's image and **replaces** the pushed one. Until `weglarka hold` (#107)
  exists, keeping a pushed image means `--no-auto-update` or a fixed tag in `image`.
- **`--image`:** the reference must be in the **same repository** as the app's `image` (otherwise a 400 and
  nothing is pulled): the pin has the form `repo@digest`, and registry credentials are per instance.
- **Errors:** an archive Podman cannot load and a foreign repository are a 400; an unknown app is a 404; a
  second upload is a 409. A failed health gate rolls back to the previous digest (the exit code is the same as
  for `deploy`), and a manual push retries a digest marked bad, like `apps deploy`.
- **A narrow window:** between loading and deploying, a deploy of another app of the same repository could
  take the new image for unused and prune it ([image retention](image-retention.md)); the deploy then fails
  on pulling `repo@digest` and the push has to be repeated.
- **Security:** whoever holds the admin socket can already run arbitrary code (`weglarka run`), so push does not
  widen trust; pushed images are not signature-verified (cosign covers only Węglarka's own
  [self-update](self-update.md)).
- **Not available (yet):** `weglarka push --static` (a static site) — waits for #48.

## Rollback

Nothing to do — push adds no field to `apps.toml` or `state.toml` (no schema version bump). An older daemon has
no `PUT /v1/apps/{name}/image` route and still rejects `deploy --image` ("not supported yet"); an older CLI has
no such command.
