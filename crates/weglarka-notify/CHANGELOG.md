# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.6](https://github.com/jpalczewski/weglarka/compare/weglarka-notify-v0.0.5...weglarka-notify-v0.0.6) - 2026-11-07

### Added

- *(notify)* read the ntfy token on use, from a file or a host secret
- *(model)* host credential sources and a host-scoped secret store

### Fixed

- *(model)* a host secret that is not set yet does not stop the startup

### Other

- renumber the host credentials ADR to 0080 after the 0079 collision
- *(model)* one private-file check and one header-token validator ([#623](https://github.com/jpalczewski/weglarka/pull/623))

## [0.0.5](https://github.com/jpalczewski/weglarka/compare/weglarka-notify-v0.0.4...weglarka-notify-v0.0.5) - 2026-10-29

### Added

- *(daemon)* recent events ([#256](https://github.com/jpalczewski/weglarka/pull/256))

## [0.0.4](https://github.com/jpalczewski/weglarka/compare/weglarka-notify-v0.0.3...weglarka-notify-v0.0.4) - 2026-10-29

### Added

- *(engine)* generated config pipeline (render, validate, apply) ([#238](https://github.com/jpalczewski/weglarka/pull/238))
- *(http)* [**breaking**] shared HTTP client crate on reqwest; move notify onto it ([#230](https://github.com/jpalczewski/weglarka/pull/230))

### Other

- split weglarka-core into weglarka-model and weglarka-engine ([#228](https://github.com/jpalczewski/weglarka/pull/228))

## [0.0.3](https://github.com/jpalczewski/weglarka/compare/weglarka-notify-v0.0.2...weglarka-notify-v0.0.3) - 2026-10-26

### Added

- *(daemon)* run an ACME worker for edge certificates ([#154](https://github.com/jpalczewski/weglarka/pull/154))

## [0.0.2](https://github.com/jpalczewski/weglarka/compare/weglarka-notify-v0.0.1...weglarka-notify-v0.0.2) - 2026-10-24

### Added

- *(daemon)* automatic fallback to the previous daemon image ([#144](https://github.com/jpalczewski/weglarka/pull/144))
- self-update Węglarka's own image with a verified digest ([#133](https://github.com/jpalczewski/weglarka/pull/133))
- *(core)* detect crash-looping and unhealthy apps ([#120](https://github.com/jpalczewski/weglarka/pull/120))
