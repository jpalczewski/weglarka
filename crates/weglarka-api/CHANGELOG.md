# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.7](https://github.com/jpalczewski/weglarka/compare/weglarka-api-v0.0.6...weglarka-api-v0.0.7) - 2026-10-31

### Added

- *(api)* add read-scope container resource stats ([#428](https://github.com/jpalczewski/weglarka/pull/428))
- *(engine)* connect the metrics scraper to the metrics networks ([#397](https://github.com/jpalczewski/weglarka/pull/397))
- *(cli)* expose a stored secret to one run with run --secret ([#396](https://github.com/jpalczewski/weglarka/pull/396))
- *(cli)* apps update/start/stop --wait for the reconcile ([#395](https://github.com/jpalczewski/weglarka/pull/395))
- *(api)* host-wide volume listing and a limit on GET /v1/events ([#384](https://github.com/jpalczewski/weglarka/pull/384))
- *(daemon)* stream an app's access log ([#355](https://github.com/jpalczewski/weglarka/pull/355))
- *(daemon)* optional /metrics listener on a dedicated network ([#354](https://github.com/jpalczewski/weglarka/pull/354))

### Fixed

- *(cli)* keep log history across a token renewal ([#359](https://github.com/jpalczewski/weglarka/pull/359))

### Other

- *(panel)* one resumable driver for daemon streams ([#430](https://github.com/jpalczewski/weglarka/pull/430))
- *(api)* share the unsafe-character set for untrusted stream text ([#429](https://github.com/jpalczewski/weglarka/pull/429))
- *(api)* add DoctorCheck constructors ([#423](https://github.com/jpalczewski/weglarka/pull/423))
- *(api)* stop copying frame payloads in the stream codec ([#376](https://github.com/jpalczewski/weglarka/pull/376))

## [0.0.6](https://github.com/jpalczewski/weglarka/compare/weglarka-api-v0.0.5...weglarka-api-v0.0.6) - 2026-10-30

### Fixed

- *(daemon)* redact all of argv for read tokens ([#319](https://github.com/jpalczewski/weglarka/pull/319))

## [0.0.5](https://github.com/jpalczewski/weglarka/compare/weglarka-api-v0.0.4...weglarka-api-v0.0.5) - 2026-10-29

### Added

- *(daemon)* certificates and host config view ([#286](https://github.com/jpalczewski/weglarka/pull/286))
- *(daemon)* app logs stream ([#287](https://github.com/jpalczewski/weglarka/pull/287))
- *(daemon)* recent events ([#256](https://github.com/jpalczewski/weglarka/pull/256))
- *(api)* redacted app view and runtime detail ([#252](https://github.com/jpalczewski/weglarka/pull/252))

### Fixed

- *(daemon)* read view as an exhaustive projection ([#280](https://github.com/jpalczewski/weglarka/pull/280))
- *(daemon)* redact argv and failure text for read tokens

## [0.0.4](https://github.com/jpalczewski/weglarka/compare/weglarka-api-v0.0.3...weglarka-api-v0.0.4) - 2026-10-29

### Added

- *(daemon)* token admin API with read/admin scopes (ADR 0056) ([#246](https://github.com/jpalczewski/weglarka/pull/246))
- *(identity)* wire OIDC clients and the provider into the daemon ([#239](https://github.com/jpalczewski/weglarka/pull/239))

### Other

- split weglarka-core into weglarka-model and weglarka-engine ([#228](https://github.com/jpalczewski/weglarka/pull/228))

## [0.0.3](https://github.com/jpalczewski/weglarka/compare/weglarka-api-v0.0.2...weglarka-api-v0.0.3) - 2026-10-26

### Added

- *(core)* sites with environments and promotion ([#206](https://github.com/jpalczewski/weglarka/pull/206))
- *(core)* allowlisted host mounts and group_add for log collectors ([#185](https://github.com/jpalczewski/weglarka/pull/185))
- *(cli)* deploy a locally built image with weglarka push ([#163](https://github.com/jpalczewski/weglarka/pull/163))
- *(cli)* weglarka forward, a temporary port forward ([#165](https://github.com/jpalczewski/weglarka/pull/165))
- one-off containers with `weglarka run` ([#157](https://github.com/jpalczewski/weglarka/pull/157))

## [0.0.2](https://github.com/jpalczewski/weglarka/compare/weglarka-api-v0.0.1...weglarka-api-v0.0.2) - 2026-10-24

### Added

- *(daemon)* automatic fallback to the previous daemon image ([#144](https://github.com/jpalczewski/weglarka/pull/144))
- *(core)* shared networks between instances ([#137](https://github.com/jpalczewski/weglarka/pull/137))
- *(core)* more than one shared volume per app via volume groups ([#135](https://github.com/jpalczewski/weglarka/pull/135))
- config_root mounts and apps reload ([#121](https://github.com/jpalczewski/weglarka/pull/121))
- *(cli)* secrets remove and apps remove --purge-secrets ([#122](https://github.com/jpalczewski/weglarka/pull/122))
- notify deploys and rollbacks through ntfy ([#115](https://github.com/jpalczewski/weglarka/pull/115))
- *(core)* keep only the current and previous image per app ([#116](https://github.com/jpalczewski/weglarka/pull/116))
- share volumes between instances ([#66](https://github.com/jpalczewski/weglarka/pull/66))

### Other

- version and changelog each crate independently with release-plz ([#68](https://github.com/jpalczewski/weglarka/pull/68))
