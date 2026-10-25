# Importing data: Coolify migration and SQLite

Importing a volume from a tar (for example from Coolify), exporting your own backups, and lessons from a real SQLite migration. Volume basics are in [volumes.md](volumes.md); provisioning an app without starting it is in [stopped-apps.md](stopped-apps.md) ([ADR 0011](../decisions/0011-start-false-provisioning.md)). Shared-volume specifics (an import requires all members to be stopped; SQLite with several writers) are in [shared-volumes.md](shared-volumes.md).

## Importing data from Coolify

Import the tar from Coolify in the default mode (a **foreign** tar): libpod gives the extracted files the owner from the container configuration (the image `USER`, root when absent) regardless of the UIDs in the tar, so a tree with many owners is flattened to one (for SQLite under a single user, that is exactly what you want).

```sh
# On the Coolify host: just the volume's files, an uncompressed tar (unpack a .tar.gz with gunzip)
tar -cf weather-data.tar -C /var/lib/docker/volumes/<volume>/_data .
```

You do not need to start the app first: `start = false` **provisions** it (image pull and digest pin, network, UID range and volumes) but creates no container. Import does not need one, because the tar is extracted by a helper, never-started container from the same image. The whole order is: provisioning, import, secrets, first start:

```toml
# weather.toml: the app is prepared but not running yet
image = "ghcr.io/example/weather:latest"
start = false
volumes = [{ name = "data", target = "/data" }]
```

```sh
# On the Węglarka side:
weglarka apps add weather --spec weather.toml                    # image, UID range, volume; no container
weglarka volumes import weather data --from weather-data.tar     # or: < weather-data.tar
weglarka secrets set weather config < config.json                # if the app has secrets
weglarka apps start weather                                      # pull, health gate, container and router
```

Only `apps start` clears `start = false`: pull of the latest tag, health gate (rollback on failure), container and router in the ingress. The imported data waits in the volume with the correct owner (UID range), so the app starts with it from the first request. The flag equivalent of the file is `apps add ... --no-start` (but volumes require `--spec`).

Import stops the app's running container, extracts the tar (Podman does it in a helper, never-started container from the same image; Węglarka unpacks nothing itself) and starts the app again. For an app with `start = false` there is nothing to stop or start: import only extracts the data. Files with the same path are overwritten, the others stay; an interrupted import leaves some of the files. Limit of a single import: 8 GiB.

**`--replace`: import into an empty volume.** Without it, files that are not in the tar stay in the volume. With SQLite in **WAL** mode that is a trap: if the app started before the import, its `*.db-wal`/`*.db-shm` files are in the volume, and after the start SQLite replays that old WAL onto the imported database, so the data "disappears" although the `.db` file is correct (this happened on a real migration; verification with `?immutable=1` does not see it, because it ignores the WAL). `weglarka volumes import <app> <volume> --from backup.tar --replace` removes the volume and creates it anew (the app's container is recreated in the process). Back up a WAL database with `.backup` (or `PRAGMA wal_checkpoint(TRUNCATE)` on the copy), and verify the copy together with the `-wal`/`-shm` files, not the `.db` alone.

**Your own backups** (`volumes export`) come back **only** with `--own` and only to an app with the same UID range:

```sh
weglarka volumes export weather data --out backup.tar
weglarka volumes import weather data --from backup.tar --own
```

Do not mix up the modes: a foreign tar imported with `--own` lands **silently** on the wrong UIDs; a Węglarka export imported without `--own` loses its owners (everything gets the container user).

## Migrating a SQLite app

Lessons from a real SQLite app migration from Coolify (downtime ≈ 46 s, of which ~25 s was avoidable):

1. **Dry run without downtime:** run the app in Węglarka **without a domain**, with a volume and `auto_update = false`, if the app migrates its schema on start (an image rollback does not undo the schema). Copy from the running app **only through SQLite** (`sqlite3 -readonly <db> ".backup /tmp/copy.db"` or `VACUUM INTO`), never the raw file of a database someone is writing to right now. Import with a foreign tar, deploy, and compare table row counts with the old app.
2. **Cutover:** stop the old app in Coolify; through its API that is `POST /api/v1/applications/{uuid}/stop` (`GET` returns 405), and the stop itself takes up to ~30 s. Disable its auto-deploy in Coolify so a push to `main` does not bring it back up. Take the final `.backup` copy from the **stopped** database, import it again, then `apps update --domain …`.
3. **Verify after the cutover, not in the downtime window:** run `PRAGMA integrity_check` on the database in the volume and the row-count comparison **after** adding the domain (on the final copy you can run them in parallel, outside the window). On that migration, checking inside the window extended the downtime by ~25 s.
4. **Behind a proxy:** the app sees traffic from Węglarka's nginx coming from the subnet of its network (`net-<instance>`); if the app itself trusts proxy headers, give it that subnet (for example `TRUSTED_PROXIES=10.89.5.0/24`; check with `podman network inspect net-<instance>`). Set the public origin if the app has one (a `Secure` cookie).
5. **Rollback:** `apps update --remove-domain …` and start the old app. Data written after the cutover is lost: before going back under real traffic, run `weglarka volumes export`.
