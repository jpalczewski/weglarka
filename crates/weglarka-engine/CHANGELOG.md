# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
