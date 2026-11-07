# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.5](https://github.com/jpalczewski/weglarka/compare/weglarka-dns-v0.0.4...weglarka-dns-v0.0.5) - 2026-11-07

### Added

- *(dns)* read the DNS-01 token on use, from a file or a host secret

### Other

- renumber the host credentials ADR to 0080 after the 0079 collision

## [0.0.4](https://github.com/jpalczewski/weglarka/compare/weglarka-dns-v0.0.3...weglarka-dns-v0.0.4) - 2026-10-29

### Other

- *(http)* move the registry and Cloudflare clients onto weglarka-http ([#235](https://github.com/jpalczewski/weglarka/pull/235))
- split weglarka-core into weglarka-model and weglarka-engine ([#228](https://github.com/jpalczewski/weglarka/pull/228))

## [0.0.3](https://github.com/jpalczewski/weglarka/compare/weglarka-dns-v0.0.2...weglarka-dns-v0.0.3) - 2026-10-26

### Added

- *(daemon)* refresh the Cloudflare ranges from the API ([#172](https://github.com/jpalczewski/weglarka/pull/172))
