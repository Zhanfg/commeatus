# Security

Security posture of the project at bootstrap stage.

## Principles

- Rust safe-first: business code defaults to `#![forbid(unsafe_code)]`.
- `unsafe` code, when introduced later, exists only at strictly scoped
  platform/FFI boundaries with documented SAFETY invariants.
- Do not implement cryptographic primitives from scratch; use reviewed,
  established libraries.
- Never commit secrets: keys, tokens, passwords, cookies, SSH private
  keys or API keys. See `.gitignore`.
- Treat all network input as untrusted data.
- Root components require privilege separation by design.
- External configuration and subscriptions require strict resource
  limits (size, depth, rate).
- Fuzzing and property-based testing must be introduced before any
  network-facing parser reaches production.
