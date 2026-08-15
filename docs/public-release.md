# Public Release Policy

This document defines the minimum gate for making Commeatus public and, later, for declaring a release usable.

## Repository publication gate

Before changing repository visibility to public:

- [ ] Repository name is `commeatus`.
- [ ] Default branch is `main`.
- [ ] `LICENSE` contains the Apache License 2.0 text.
- [ ] Cargo metadata uses SPDX identifier `Apache-2.0`.
- [ ] README, crate names and documentation contain no temporary `agent-*` project identity.
- [ ] Full Git history has been reviewed for secrets, credentials, private keys, tokens, cookies and private user data.
- [ ] No proprietary or third-party source was copied into the repository without compatible licensing and attribution.
- [ ] `SECURITY.md` explains non-public vulnerability disclosure.
- [ ] `CONTRIBUTING.md` states the license applied to contributions.
- [ ] The project is clearly marked bootstrap / not production-ready.

Changing visibility to public is considered irreversible disclosure of every reachable commit in repository history. Secret material must be removed from history before publication, not merely deleted in a later commit.

## Source and dependency policy

- Every dependency must have a known source and compatible license.
- Git dependencies should not enter stable release builds without an explicit reason and pinned revision.
- New protocol implementations should be based on public specifications or clean, license-compatible references.
- Compatibility code must not copy incompatible implementation code from mihomo, sing-box, Xray or other projects.
- Third-party notices must be tracked when required by upstream licenses.

## Pre-release engineering gate

Before any build is described as usable or recommended:

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo check --workspace`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] dependency advisory and license audit
- [ ] fuzzing coverage for network-facing parsers
- [ ] malformed configuration and subscription regression tests
- [ ] crash recovery / failure-domain tests
- [ ] DNS failure and route fallback tests
- [ ] Android Root clean-uninstall / network-recovery tests
- [ ] measured idle CPU, memory and wakeup baseline
- [ ] measured throughput and latency baseline

## Release artifacts

Stable distribution is expected to provide, at minimum:

- source tag
- reproducible build instructions
- target architecture and minimum Android/Linux requirements
- SHA-256 checksums for binaries
- dependency/license inventory
- release notes describing compatibility and known limitations

SBOM generation, signed provenance/attestations and reproducible-build verification should be added before the project is treated as mature infrastructure.

## Visibility and naming

The canonical repository is intended to be:

`Zhanfg/commeatus`

The canonical core/binary name is:

`commeatus`

Compatibility names such as mihomo, sing-box and Clash are interoperability targets only and are not part of the native project identity.
