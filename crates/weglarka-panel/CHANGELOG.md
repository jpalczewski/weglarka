# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/jpalczewski/weglarka/compare/weglarka-panel-v0.1.0...weglarka-panel-v0.1.1) - 2026-10-30

### Added

- *(cli)* sign in to a remote host with the device grant and reach it through the panel relay ([#335](https://github.com/jpalczewski/weglarka/pull/335))

### Fixed

- *(panel)* rate-limit login callbacks per client address ([#332](https://github.com/jpalczewski/weglarka/pull/332))

### Other

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
