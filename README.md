# Commeatus

Commeatus is a new-generation proxy core for Android (Root-first) and Linux, written in Rust.

The name comes from Latin *commeatus*: passage, free movement, traffic, and a route through which movement can occur.

> **Status:** early architecture / V0.1 core-model stage. Not production-ready. No production proxy protocols are implemented yet.

## Project priorities

In order of precedence:

1. Stability
2. Security
3. Low idle power
4. Performance
5. Extensibility
6. Compatibility
7. Feature coverage

A feature must not weaken the higher-priority properties above.

## Design goals

Planned goals include:

- flow-centric runtime and typed internal IR
- Rust safe-first implementation
- Android Root-first integration with Linux portability
- modern eBPF / BTF / CO-RE fast paths where supported
- TProxy / TUN compatibility fallbacks
- TCP / UDP / QUIC support
- policy-based routing, allow/deny lists and ad blocking
- independent DNS policy and resolver subsystem
- long-term adaptive routing based primarily on real traffic telemetry
- low-power, event-driven background behavior
- protocol and transport extensibility without a monolithic configuration model
- compatibility importers for mihomo, sing-box and Clash ecosystems without making those formats the native runtime model

## Current implementation

The first V0.1 vertical slice is under active development:

```text
FlowContext
    ↓
Matcher
    ↓
PolicyEngine
    ↓
PolicyDecision
    ↓
ExecutionPlan
```

Implemented in the current V0.1 work:

- canonical flow/source/destination/network/transport types
- typed policy matchers for UID, package, domain, IP, port, TCP/UDP and network kind
- composed `All`, `AnyOf` and `Not` matchers
- fixed policy authority: `UserHard > Safety > Compatibility > Adaptive > Default`
- native separation between actions and endpoints
- `Direct` endpoint and typed `Reject` action
- deterministic plan generation
- unit tests for key policy invariants

This is a core-model implementation, not yet a functioning network proxy.

See `docs/architecture/v0.1-flow-policy-runtime.md`.

## Not implemented yet

The repository intentionally does **not** yet implement SOCKS5, HTTP proxy, VLESS, VMess, Trojan, Shadowsocks, Hysteria, TUIC, WireGuard, TUN, TProxy, eBPF programs, DNS resolvers, Fake-IP, ad-blocking engines, smart routing, Clash API or subscription parsers.

Architecture comes before protocol count.

## Repository layout

```text
.
├── Cargo.toml
├── crates/
│   ├── core/       # native Flow / Policy / Routing runtime
│   ├── platform/   # Linux / Android platform boundary
│   └── compat/     # ecosystem compatibility boundary
├── ebpf/           # eBPF / BTF / CO-RE programs (planned)
├── docs/
│   ├── architecture/
│   └── adr/
├── tests/
└── scripts/
```

## Architecture invariants

- Flow is the first-class runtime object.
- Compatibility formats terminate at the compatibility boundary.
- Actions, endpoints, transports, resolvers and policies remain distinct concepts.
- One state has one authoritative owner.
- Failures should remain local; a single flow or subsystem failure must not imply global network failure.
- Configuration changes are expected to become transactional, validated and rollback-capable.
- Direct traffic should avoid unnecessary userspace traversal when the platform supports it.
- User hard policy and safety constraints outrank adaptive decisions.

Accepted architecture decisions live in `docs/adr/`.

## Public project policy

Before a release is considered usable, the project will require reproducible builds, dependency and license auditing, fuzzing of network-facing parsers, regression tests, stability tests and measured power/performance baselines.

The public-release checklist is maintained in `docs/public-release.md`.

## Security

Do not report vulnerabilities with exploit details in public issues. See `SECURITY.md`.

## Contributing

The project is still in early architecture development. Read `CONTRIBUTING.md` before proposing large changes.

## License

Licensed under the **Apache License 2.0**. See `LICENSE`.
