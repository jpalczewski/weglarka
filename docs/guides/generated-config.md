# Generated config files

Some infrastructure apps read configuration that Węglarka computes from `apps.toml` instead of from files you write — the identity provider's access rules and OIDC clients are the first. Węglarka renders the files, checks them with the app's own validator, switches to them atomically, and goes back if the app does not survive them. Decision: [ADR 0055](../decisions/0055-generated-config-pipeline.md).

> **Status.** The pipeline is in place, but no generator is registered yet: nothing is generated, mounted or reported until the identity provider integration is enabled ([ADR 0051](../decisions/0051-identity-provider-integration.md)). This guide describes what you will see then.

## Where the files are

```
<state dir>/generated/<app>/
  current -> v-3f9a1c0b7d42      # relative symlink to the live version
  v-3f9a1c0b7d42/rules.yml       # the live version
  v-81c2e07a55ad/rules.yml       # the previous one (kept for the way back)
```

The app gets the whole `<app>` directory **read-only** at `/weglarka/generated`, so its config points at `/weglarka/generated/current/…`. A version name is the first 12 characters of a fingerprint of its files: equal names mean equal bytes. Files are `0644`, directories `0755`; the generated files never contain a secret value — only references, and the digests the provider stores.

The mount is part of the app's container, so the first time a generator is registered for a running app, that app is **recreated once** to gain it. Apps without a generator keep exactly the spec hash they had.

## What happens on a change

Whenever `apps.toml` changes (and once when the daemon starts), after a 2 second pause so that a burst of edits counts once:

1. The files are rendered. If they equal the applied version, nothing happens.
2. The new version is written next to the live one.
3. The app's validator runs in a one-off container of the app against the new version (skipped when the app was never deployed). If it rejects the files, the live version stays and you get a `GeneratedConfigInvalid` notification with the end of its output (secret values masked).
4. `current` is switched to the new version in one step.
5. A **running** app is reloaded — with its `reload_signal`, otherwise restarted — and must pass its health gate. A stopped or never-deployed app simply reads the files on its next start. An app that re-reads its files by itself (the Prometheus scraper's [scrape targets](metrics.md)) is neither signalled nor restarted, and has no health gate to fail, so step 6 does not apply to it ([ADR 0064](../decisions/0064-consumer-watched-generated-config.md)).
6. If the health gate fails, `current` goes back to the previous version once, the app is reloaded again and you get `GeneratedConfigRolledBack`. There is no retry loop: the same rejected render is not tried again until the render changes.

The first launch of an app whose generator has not run yet writes its files **before** the container is created (the identity provider will not start without its access rules). That version cannot be validated; the app's own start is the validation, and a bad render shows up as a failed deploy with the app's logs.

## When the app or the role goes

**The app is removed from `apps.toml`.** The next reconcile pass after its containers are gone (the app's own, and any `weglarka run` or `weglarka forward` container of it) deletes `<state dir>/generated/<app>/` and the app's tables in `generated.toml`. This is deliberate: the identity provider's files hold credential digests, and nothing else would ever remove them. It happens with or without `--purge-volumes`, and whether or not a generator is still registered. Back up the directory first if you want the files.

**The app stays but loses the role** (`[identity]` or `[metrics] scraper` removed from `weglarka.toml`, or the scraper role moved to another app). Nothing is deleted: the setting may be coming back, and the app still exists. The container is recreated without the mount, and the files and the record wait on disk. When the role returns, the files are mounted again and the next pass renders as usual. If you drop the role for good and want the files gone, delete `<state dir>/generated/<app>/` by hand, or they go when the app does.

**An app of the same name is added later.** It starts clean: its first launch renders new files instead of using an old `current`, and a failure remembered for the old app does not make the same render skip its validator. A `current` is only trusted for an app with a deployed image.

If you remove an app without purging and add it back before the next pass, it is the same app to Węglarka (its state and pinned image are still there), so it keeps its files.

## Checking

`weglarka doctor` has one check per generator, `generated.<id>`: the live and the applied version, `unvalidated` for a version applied without the validator, and — after a failure — what the validator or the health gate said. A live version that differs from the applied one means a restart interrupted a switch; the next pass finishes it.

## Rollback

There are no new `apps.toml` or `state.toml` fields and no `schema_version` bump, so nothing has to be removed before downgrading Węglarka. The bookkeeping lives in `generated.toml` in the state directory (0600); an older daemon ignores it, including the `consumer` key of its tables, and drops that key when it next writes the file. A table without `consumer` still works after upgrading again: it stays as long as a directory holds the version it names.

An older daemon does not know about the extra mount, so it recreates a generated-config app without it, and an app that depends on the files will then fail to start. Before downgrading, either keep the app stopped, or put the files it needs where the older version expects them (for example under `config_root`, see [host config files](host-configs.md)). The `generated/` directory stays on disk, and an older daemon does not clean up after a removed app: remove `<state dir>/generated/<app>/` by hand if the app is gone.
