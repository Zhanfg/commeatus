# agent

A new-generation proxy core for Android (Root-first) and Linux, written in
Rust. This repository is at the very first bootstrap stage.

## Status

Early architecture / bootstrap stage.

Nothing below is implemented. Everything is `Planned` unless stated
otherwise.

## Goals

- stability first
- memory safety
- low idle power
- high performance
- extensibility
- Android Root first
- Linux portability
- modern eBPF integration
- compatibility without internal architectural pollution

## Non-goals for bootstrap

No production proxy protocols are implemented yet. This includes (but is
not limited to) SOCKS5, HTTP proxy, VLESS, VMess, Trojan, Shadowsocks,
Hysteria, TUIC, WireGuard, TUN, TProxy, eBPF programs, DNS resolvers,
Fake-IP, ad-blocking engines, smart routing, Clash API and subscription
parsers.

## Planned

- Flow-centric runtime (see `docs/adr/0001-flow-centric-architecture.md`)
- Policy engine and execution plans
- Routing, DNS, ad blocking, allow/deny lists
- Smart / adaptive long-term learning
- TCP / UDP / QUIC
- TProxy / TUN fallback
- eBPF / BTF / CO-RE integration
- Multi-protocol support with ecosystem compatibility (mihomo,
  sing-box, Clash)

## Experimental

None yet.

## Implemented

None yet.

## Repository layout

```text
.
├── Cargo.toml              # Rust workspace manifest
├── crates/
│   ├── core/               # native runtime core (Flow, Policy, Routing, ...)
│   ├── platform/           # Linux/Android platform layer (Root, TProxy, TUN, eBPF)
│   └── compat/             # ecosystem compatibility boundary (mihomo, sing-box, Clash)
├── ebpf/                   # eBPF / BTF / CO-RE programs (planned)
├── docs/
│   ├── architecture/       # architecture documentation
│   └── adr/                # architecture decision records
├── tests/                  # compatibility / regression / stability / benchmark
└── scripts/                # development and tooling scripts
```

## Development status

Bootstrap only.
