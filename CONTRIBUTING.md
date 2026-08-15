# Contributing to Commeatus

Commeatus is still in architecture bootstrap. Contributions should preserve the project boundaries before expanding feature count.

## Engineering rules

- Do not introduce large dependencies unrelated to the architecture.
- New modules must document their responsibility boundary.
- Compatibility hacks must terminate inside the compatibility layer and must not leak into the native core model.
- Network-facing input must not rely on unguarded `unwrap()` / `expect()`.
- `unsafe` code is disallowed by default and, when a narrowly scoped platform/FFI exception is introduced, requires a documented SAFETY invariant.
- Stability and regression fixes take priority over performance gains.
- Avoid custom cryptographic primitives; use established reviewed implementations.
- Keep `cargo fmt`, `cargo check`, tests and `cargo clippy -- -D warnings` green.
- Architecture-changing work should include or update an ADR.

## Change process

1. Keep changes scoped and reviewable.
2. Explain the failure domain and compatibility impact of new runtime behavior.
3. Add regression coverage for bug fixes.
4. Do not claim performance, power or compatibility improvements without measurements.
5. Do not commit credentials, tokens, private keys, cookies or other sensitive data.

## Licensing of contributions

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in Commeatus is submitted under the Apache License 2.0, without additional terms or conditions.

See `LICENSE` for the complete license text.
