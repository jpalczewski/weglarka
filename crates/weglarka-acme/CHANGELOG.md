# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.4](https://github.com/jpalczewski/weglarka/compare/weglarka-acme-v0.0.3...weglarka-acme-v0.0.4) - 2026-10-27

### Other

- split weglarka-core into weglarka-model and weglarka-engine ([#228](https://github.com/jpalczewski/weglarka/pull/228))

## [0.0.3](https://github.com/jpalczewski/weglarka/compare/weglarka-acme-v0.0.2...weglarka-acme-v0.0.3) - 2026-10-26

### Added

- *(daemon)* wildcard certificates over DNS-01 ([acme.dns]) ([#160](https://github.com/jpalczewski/weglarka/pull/160))
- *(dns)* ACME DNS-01 provider adapter (Cloudflare) and DnsSolver ([#155](https://github.com/jpalczewski/weglarka/pull/155))
- *(daemon)* run an ACME worker for edge certificates ([#154](https://github.com/jpalczewski/weglarka/pull/154))
- *(acme)* order certificates through instant-acme ([#153](https://github.com/jpalczewski/weglarka/pull/153))

### Fixed

- *(acme)* wait for DNS-01 records before asking the CA to validate ([#202](https://github.com/jpalczewski/weglarka/pull/202))
- *(acme)* report why the CA rejected a challenge ([#201](https://github.com/jpalczewski/weglarka/pull/201))
- *(acme)* publish wildcard DNS-01 challenges at the base name ([#196](https://github.com/jpalczewski/weglarka/pull/196))

### Other

- *(acme)* make Challenge own the wildcard-to-base-name rule ([#198](https://github.com/jpalczewski/weglarka/pull/198))
