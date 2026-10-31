# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/jpalczewski/weglarka/compare/weglarka-panel-v0.1.0...weglarka-panel-v0.1.1) - 2026-10-31

### Added

- *(panel)* show container resource usage ([#434](https://github.com/jpalczewski/weglarka/pull/434))
- *(panel)* live access log per app ([#433](https://github.com/jpalczewski/weglarka/pull/433))
- *(panel)* warn once when an unlisted reverse proxy forwards requests ([#394](https://github.com/jpalczewski/weglarka/pull/394))
- *(cli)* sign in to a remote host with the device grant and reach it through the panel relay ([#335](https://github.com/jpalczewski/weglarka/pull/335))

### Fixed

- *(panel)* back off token refresh after a transient provider failure ([#381](https://github.com/jpalczewski/weglarka/pull/381))
- *(panel)* charge the relay rate limit after the bearer check ([#379](https://github.com/jpalczewski/weglarka/pull/379))
- *(panel)* rate-limit login callbacks per client address ([#332](https://github.com/jpalczewski/weglarka/pull/332))

### Other

- *(panel)* one resumable driver for daemon streams ([#430](https://github.com/jpalczewski/weglarka/pull/430))
- *(api)* share the unsafe-character set for untrusted stream text ([#429](https://github.com/jpalczewski/weglarka/pull/429))
- *(model)* take an id token's audience from the client id in verify ([#382](https://github.com/jpalczewski/weglarka/pull/382))
- *(panel)* make the in-flight shutdown test deterministic ([#373](https://github.com/jpalczewski/weglarka/pull/373))
- *(panel)* drain the spawned panel's stdout/stderr in the test harness ([#371](https://github.com/jpalczewski/weglarka/pull/371))
- release ([#320](https://github.com/jpalczewski/weglarka/pull/320))

## [0.1.0](https://github.com/jpalczewski/weglarka/compare/weglarka-panel-v0.0.1...weglarka-panel-v0.1.0) - 2026-10-30

### Other

- first minor release of the panel (version set by hand, see #328); updated the following local packages: weglarka-api

## [0.0.1](https://github.com/jpalczewski/weglarka/compare/weglarka-panel-v0.0.0...weglarka-panel-v0.0.1) - 2026-10-29

### Added

- *(panel)* read-mostly pages ([#305](https://github.com/jpalczewski/weglarka/pull/305))
- *(panel)* OIDC login and sessions ([#288](https://github.com/jpalczewski/weglarka/pull/288))

### Fixed

- *(panel)* login and session hardening ([#302](https://github.com/jpalczewski/weglarka/pull/302))

### Other

- split CLAUDE.md into scoped rules ([#311](https://github.com/jpalczewski/weglarka/pull/311))
- *(panel)* cover binary startup, flags and graceful shutdown ([#268](https://github.com/jpalczewski/weglarka/pull/268))
