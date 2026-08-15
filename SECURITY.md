# Security Policy

Commeatus is currently in architecture/bootstrap stage and is **not production-ready**.

## Security principles

- Rust safe-first: business/runtime code defaults to `#![forbid(unsafe_code)]`.
- `unsafe` code, when later required, must remain inside narrowly scoped platform/FFI boundaries with documented SAFETY invariants.
- Do not implement cryptographic primitives from scratch; use established, reviewed libraries.
- Treat network packets, DNS data, subscriptions, configuration files, compatibility formats and control APIs as untrusted input.
- Root integration must use privilege separation and a minimal trusted computing base.
- External input must have explicit limits for size, nesting, decompression, rate, memory use and execution time.
- A malformed flow must not crash the global runtime.
- Fuzzing and property-based testing are required before network-facing parsers are considered production-capable.
- Secrets, tokens, passwords, cookies, API keys and private keys must never be committed to the repository.

## Reporting a vulnerability

Do **not** publish exploit details, credentials, private user data or a working proof of concept in a public GitHub issue.

When GitHub private vulnerability reporting is enabled for the public repository, use that channel. If it is unavailable, open only a minimal public issue requesting a private contact channel and omit technical exploit details until a private channel is established.

Please include, privately where appropriate:

- affected revision/version
- affected platform
- impact
- minimal reproduction conditions
- whether exploitation requires Root, local access or remote network access
- suggested mitigation, if known

## Supported versions

No version is currently designated production-supported. Security support policy will be versioned before the first stable release.
