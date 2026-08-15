# Changelog

All notable changes to Commeatus are documented here.

The project is pre-1.0. Native configuration and internal APIs may change between alpha releases.

## 0.1.0-alpha.1 — 2026-08-15

First runnable public alpha.

### Added

- flow-centric Rust core with canonical `FlowContext`, typed `Matcher`, `PolicyEngine`, `PolicyDecision` and immutable `ExecutionPlan`
- policy authority ordering: `UserHard > Safety > Compatibility > Adaptive > Default`
- explicit separation between actions and endpoints
- `DIRECT` endpoint and typed `REJECT` action
- exact domain, suffix-domain, exact-IP, IPv4/IPv6 CIDR and destination-port matching
- `commeatus` executable and strict native alpha configuration
- SOCKS5 no-auth TCP CONNECT inbound with IPv4, domain and IPv6 targets
- HTTP/1.x CONNECT inbound with domain, IPv4 and bracketed IPv6 targets
- system resolver use for direct domain connections
- bidirectional TCP relay with half-close handling
- configuration limits and parse/validate/compile-before-swap `ConfigStore`
- all-listeners-bind-before-start startup semantics
- handshake timeouts, outbound TCP connect deadline and bounded resolved-address candidates
- 256 active-session cap before handler creation
- loopback-only unauthenticated listeners by default, with explicit `allow-public-listen true` opt-in
- CLI commands: `run`, `check`, `version`
- real loopback end-to-end tests for SOCKS5 and HTTP CONNECT
- explicit Rust 1.85 MSRV CI
- Linux release build and Android arm64 cross-build CI

### Security and stability

- malformed single connections are isolated from listener lifetime
- policy rejection occurs before outbound connect
- listener startup is transactional with respect to bind failures
- configuration candidates cannot partially mutate active state on parse/compile failure
- external configuration size, rule count and listener count are bounded
- GitHub Actions dependencies are pinned to reviewed commits for the first-alpha build path

### Known limitations

- no inbound authentication
- no UDP, TUN, TProxy or eBPF interception
- no proxy-protocol outbounds yet
- no secure DNS subsystem or Fake-IP
- no live process-level configuration reload despite transactional config-state primitives
- CIDR rules do not currently apply to addresses resolved later from a canonical domain destination
- synchronous operating-system DNS can still block according to resolver behavior
- execution backend is bounded thread-per-session and is not the final low-power Android runtime
