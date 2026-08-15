# Contributing

Short and sharp rules for this repository.

## Rules

- Do not introduce large dependencies unrelated to the architecture.
- New modules must document their responsibility boundary.
- Compatibility hacks must not leak into the core crate.
- Network input must not use unguarded `unwrap()` / `expect()`.
- `unsafe` code requires an explicit SAFETY invariant comment.
- Stability and regression fixes take priority over performance gains.
- Keep `cargo fmt` and `cargo clippy -D warnings` green.

## Process

- Bootstrap stage: coordinate with the architecture docs
  (`docs/architecture/` and `docs/adr/`) before opening large changes.
