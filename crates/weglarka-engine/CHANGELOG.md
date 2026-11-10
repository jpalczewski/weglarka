# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.8](https://github.com/jpalczewski/weglarka/compare/weglarka-engine-v0.0.7...weglarka-engine-v0.0.8) - 2026-11-10

### Added

- *(daemon)* platform install --check reports installed-unit drift
- *(engine)* shared service networks and start order through effective_spec
- *(engine)* refuse removing a shared service instance
- *(model)* shared service rules, overlay and per-kind gate (skeleton)
- *(engine)* mount ingress logs read-only into the configured reader ([#587](https://github.com/jpalczewski/weglarka/pull/587))
- *(model)* site-level static options and a robots preset ([#570](https://github.com/jpalczewski/weglarka/pull/570))
- *(engine)* explicit log driver and size bound for containers ([#557](https://github.com/jpalczewski/weglarka/pull/557))

### Fixed

- *(engine)* check shared static options against the served releases on sites declare ([#585](https://github.com/jpalczewski/weglarka/pull/585))
- *(daemon)* report a served static site as serving, not missing ([#569](https://github.com/jpalczewski/weglarka/pull/569))
- *(engine)* refuse kind changes on update and require a served release for static sites ([#549](https://github.com/jpalczewski/weglarka/pull/549))

### Other

- Merge pull request #641 from jpalczewski/refactor/629-mutate-apps-volumes
- *(engine)* use mutate_apps for the volumes.rs writes
- *(engine)* SharedServiceInUse carries member names like SharedVolumeInUse
- *(model)* one private-file check and one header-token validator ([#623](https://github.com/jpalczewski/weglarka/pull/623))
- *(engine)* deduplicate apps.toml writes, the health probe and test helpers ([#627](https://github.com/jpalczewski/weglarka/pull/627))
- *(engine)* dedupe volume refs, uid ranges and name validation ([#626](https://github.com/jpalczewski/weglarka/pull/626))
- *(podman)* deduplicate the Podman client, filters and test helpers ([#625](https://github.com/jpalczewski/weglarka/pull/625))
- *(engine)* check static ingress options against the served release ([#566](https://github.com/jpalczewski/weglarka/pull/566))
- gate tests that read /proc to Linux ([#550](https://github.com/jpalczewski/weglarka/pull/550))

## [0.0.7](https://github.com/jpalczewski/weglarka/compare/weglarka-engine-v0.0.6...weglarka-engine-v0.0.7) - 2026-11-05

### Added

- *(engine)* roll a static site back to its previous release ([#543](https://github.com/jpalczewski/weglarka/pull/543))
- *(engine)* site release store, configurable extraction limits and sites doctor checks ([#541](https://github.com/jpalczewski/weglarka/pull/541))
- *(engine)* internal_hosts maps served domains to Podman's host-gateway ([#532](https://github.com/jpalczewski/weglarka/pull/532))
- *(daemon)* report containers whose conmon died ([#537](https://github.com/jpalczewski/weglarka/pull/537))
- *(cli)* list image reservations and reclaim stale ones at startup ([#531](https://github.com/jpalczewski/weglarka/pull/531))
- static sites — per-site rendering options ([#104](https://github.com/jpalczewski/weglarka/pull/104)) ([#500](https://github.com/jpalczewski/weglarka/pull/500))
- *(engine)* add image provenance and retention ([#471](https://github.com/jpalczewski/weglarka/pull/471))
- *(platform)* add platform update v1 shared contracts and parser ([#465](https://github.com/jpalczewski/weglarka/pull/465))

### Fixed

- *(engine)* roll back to a release on disk without the image or the registry ([#542](https://github.com/jpalczewski/weglarka/pull/542))
- *(engine)* reload restarts a container whose conmon died ([#534](https://github.com/jpalczewski/weglarka/pull/534))
- *(engine)* image retention fails closed on provenance errors ([#528](https://github.com/jpalczewski/weglarka/pull/528))
- *(platform)* OpenRC downgrade and remove clean up the init script and the cron block ([#505](https://github.com/jpalczewski/weglarka/pull/505))

### Other

- *(engine)* one deploy-and-retain path ([#522](https://github.com/jpalczewski/weglarka/pull/522))
- *(podman)* one contract suite for LibpodClient and FakePodman ([#524](https://github.com/jpalczewski/weglarka/pull/524))
- *(launcher)* skip rehashing unchanged generation binaries ([#513](https://github.com/jpalczewski/weglarka/pull/513))
- *(model)* bounded state-file serialization and batched inventory writes ([#507](https://github.com/jpalczewski/weglarka/pull/507))

## [0.0.6](https://github.com/jpalczewski/weglarka/compare/weglarka-engine-v0.0.5...weglarka-engine-v0.0.6) - 2026-10-31

### Added

- *(daemon)* generated Prometheus file_sd targets ([#398](https://github.com/jpalczewski/weglarka/pull/398))
- *(daemon)* doctor warns about orphaned Podman networks ([#388](https://github.com/jpalczewski/weglarka/pull/388))
- *(engine)* connect the metrics scraper to the metrics networks ([#397](https://github.com/jpalczewski/weglarka/pull/397))
- *(cli)* expose a stored secret to one run with run --secret ([#396](https://github.com/jpalczewski/weglarka/pull/396))
- *(cli)* apps update/start/stop --wait for the reconcile ([#395](https://github.com/jpalczewski/weglarka/pull/395))
- *(engine)* metrics_port and a per-app metrics network ([#383](https://github.com/jpalczewski/weglarka/pull/383))
- *(daemon)* host metrics from the daemon without mounts ([#362](https://github.com/jpalczewski/weglarka/pull/362))
- *(daemon)* per-app resource metrics labelled with the instance name ([#357](https://github.com/jpalczewski/weglarka/pull/357))
- *(daemon)* report container memory use in doctor ([#348](https://github.com/jpalczewski/weglarka/pull/348))

### Fixed

- *(engine)* remove generated config of a removed consumer ([#403](https://github.com/jpalczewski/weglarka/pull/403))
- *(daemon)* make OIDC secret rotation atomic ([#389](https://github.com/jpalczewski/weglarka/pull/389))

### Other

- *(model)* add ContainerSpec::new ([#427](https://github.com/jpalczewski/weglarka/pull/427))
- *(engine)* add not-found helpers for libpod results ([#425](https://github.com/jpalczewski/weglarka/pull/425))
- *(daemon)* share one resource snapshot between metrics and the API ([#424](https://github.com/jpalczewski/weglarka/pull/424))
- *(model)* move human_bytes to weglarka-model ([#422](https://github.com/jpalczewski/weglarka/pull/422))
- *(podman)* run the real-Podman suite against a remote libpod socket ([#378](https://github.com/jpalczewski/weglarka/pull/378))

## [0.0.5](https://github.com/jpalczewski/weglarka/compare/weglarka-engine-v0.0.4...weglarka-engine-v0.0.5) - 2026-10-29

### Added

- *(daemon)* app logs stream ([#287](https://github.com/jpalczewski/weglarka/pull/287))
- *(api)* redacted app view and runtime detail ([#252](https://github.com/jpalczewski/weglarka/pull/252))

## [0.0.4](https://github.com/jpalczewski/weglarka/compare/weglarka-engine-v0.0.3...weglarka-engine-v0.0.4) - 2026-10-29

### Added

- *(daemon)* token admin API with read/admin scopes (ADR 0056) ([#246](https://github.com/jpalczewski/weglarka/pull/246))
- *(identity)* wire OIDC clients and the provider into the daemon ([#239](https://github.com/jpalczewski/weglarka/pull/239))
- *(engine)* generated config pipeline (render, validate, apply) ([#238](https://github.com/jpalczewski/weglarka/pull/238))
- *(model)* SecretOps and OIDC client credentials ([#229](https://github.com/jpalczewski/weglarka/pull/229))

### Fixed

- *(engine)* ingress range read does not wait for the engine lock ([#234](https://github.com/jpalczewski/weglarka/pull/234))
