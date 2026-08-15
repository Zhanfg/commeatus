# Commeatus

Commeatus is a Rust proxy core and runtime built around a flow-centric policy model. Android Root is the first-priority platform, with Linux kept as a portable development and deployment target.

The name comes from Latin *commeatus*: passage, free movement, traffic, and a route through which movement can occur.

> **Status:** `0.1.0-alpha.1` release candidate. The current build is experimental and not production-ready, but it is a functioning TCP proxy rather than an architecture-only skeleton.

## Project priorities

In order of precedence:

1. Stability
2. Security
3. Low idle power
4. Performance
5. Extensibility
6. Compatibility
7. Feature coverage

A feature must not weaken a higher-priority property without an explicit architecture decision.

## What works in 0.1.0-alpha.1

The first runnable slice includes:

- `commeatus` executable for Linux and Android arm64 builds
- SOCKS5 no-auth TCP `CONNECT`
- HTTP/1.x `CONNECT`
- IPv4 and IPv6 destination handling
- domain destinations resolved by the operating system resolver for `DIRECT`
- `DIRECT` and `REJECT` policy actions
- exact domain, domain suffix, exact IP, CIDR and destination-port rules
- flow-centric `FlowContext → PolicyEngine → ExecutionPlan` core
- fixed authority ordering: `UserHard > Safety > Compatibility > Adaptive > Default`
- transactional parse/validate/compile configuration snapshots
- configuration, listener and rule-count resource limits
- 10-second outbound TCP connect deadline after address resolution
- bounded resolved-address candidates
- 10-second inbound handshake timeout
- 256 active-session cap before handler threads are created
- transactional listener startup: every configured socket must bind before service starts
- per-connection failure isolation
- loopback-by-default safety for unauthenticated listeners
- `check`, `run` and `version` CLI commands
- zero third-party Rust runtime dependencies in this alpha

The execution path is:

```text
SOCKS5 / HTTP CONNECT
        ↓
   canonical Target
        ↓
    FlowContext
        ↓
   PolicyEngine
        ↓
  ExecutionPlan
        ↓
 DIRECT or REJECT
        ↓
 TCP relay
```

## Quick start

Build the daemon:

```bash
cargo build --release --locked -p commeatus
```

Validate the example configuration:

```bash
./target/release/commeatus check --config examples/commeatus.conf
```

Run it:

```bash
./target/release/commeatus run --config examples/commeatus.conf
```

The example listens only on loopback:

```text
SOCKS5: 127.0.0.1:1080
HTTP CONNECT: 127.0.0.1:8080
```

Use those addresses as the SOCKS5 or HTTP proxy in a local client.

## Native alpha configuration

The bootstrap native syntax is deliberately small:

```text
version 1

listen socks5 127.0.0.1:1080
listen http 127.0.0.1:8080

default direct

rule reject domain-suffix ads.example
rule reject domain-exact blocked.example
rule reject ip 203.0.113.8
rule reject cidr 10.0.0.0/8
rule reject port 25
```

`#` begins a comment. The native syntax is not stable API before 1.0.

### Public-listen safety

SOCKS5 and HTTP CONNECT authentication are **not implemented in this alpha**. Commeatus therefore rejects non-loopback listener addresses by default.

To deliberately expose an unauthenticated listener, the configuration must contain:

```text
allow-public-listen true
```

Do not enable this on an untrusted network unless another trusted access-control layer protects the listener.

## Policy semantics worth knowing

- `Reject` is an action, not an outbound endpoint.
- `Direct` is an endpoint selected by a route action.
- User hard policy outranks safety-compatible lower authority, compatibility rules, adaptive decisions and defaults.
- Domain identity is preserved as a domain through policy evaluation.
- A CIDR rule currently matches only a flow whose canonical destination was already an IP address. It does **not** retroactively match IPs obtained later by system DNS for a domain destination.

That last behavior is intentional for now: DNS resolution state is not allowed to silently replace canonical destination identity.

## Current limitations

`0.1.0-alpha.1` deliberately does not include:

- SOCKS5 username/password authentication
- HTTP proxy authentication
- UDP forwarding
- SOCKS5 `UDP ASSOCIATE`
- ordinary forward-HTTP requests; HTTP inbound is CONNECT-only
- TUN or TProxy interception
- eBPF/BTF/CO-RE fast paths
- Android Root integration/module packaging
- native proxy outbounds such as Shadowsocks, VLESS, Trojan, Hysteria2 or TUIC
- DoH/DoT/DoQ or Fake-IP
- ad-block rule providers
- Clash/mihomo/sing-box configuration import
- adaptive/Smart routing
- live process-level hot reload
- a final low-power event-driven executor

The current executor uses blocking `std` sockets and bounded thread-per-session handling. It exists to establish a small, auditable, end-to-end-correct execution backend. It is not the final Android power/performance architecture.

System DNS resolution itself is currently synchronous and can still be subject to operating-system resolver delays even though outbound TCP connects are deadline-bounded afterward.

## Verification

GitHub Actions on Ubuntu validates:

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets --locked`
- `cargo clippy --workspace --all-targets --locked -- -D warnings`
- `cargo test --workspace --locked`
- release build
- CLI smoke tests
- explicit Rust 1.85 MSRV check
- Android `aarch64-linux-android` release cross-build with the Android NDK

The test suite includes real loopback TCP end-to-end tests. It starts an echo server and verifies bytes passing through both SOCKS5 and HTTP CONNECT, policy rejection before outbound connect, and listener survival after a malformed client.

## Repository layout

```text
.
├── Cargo.toml
├── crates/
│   ├── core/       # Flow / Policy / ExecutionPlan runtime core
│   ├── daemon/     # runnable TCP proxy and native alpha config
│   ├── platform/   # Linux / Android platform boundary
│   └── compat/     # ecosystem compatibility boundary
├── ebpf/           # eBPF / BTF / CO-RE work (planned)
├── examples/
├── docs/
└── tests/
```

## Architecture invariants

- Flow is the first-class runtime object.
- Compatibility formats terminate at the compatibility boundary.
- Actions, endpoints, transports, resolvers and policies remain distinct concepts.
- One state has one authoritative owner.
- Failures should remain local; a single flow or subsystem failure must not imply global network failure.
- Configuration candidates are validated before replacing active state.
- Direct traffic should avoid unnecessary userspace traversal when the future platform backend supports it.
- User hard policy and safety constraints outrank adaptive decisions.

Accepted architecture decisions live in `docs/adr/`.

## Roadmap after the first alpha

The next major slices are expected to cover:

1. endpoint capability registry and native proxy outbounds
2. UDP and QUIC-oriented execution paths
3. DNS subsystem separation and secure resolvers
4. Android Root interception with eBPF/TPROXY/TUN capability fallback
5. rule-provider/ad-block compilation
6. adaptive routing and real-traffic telemetry
7. power/performance baselines against mihomo and sing-box

## Security

Do not report vulnerabilities with exploit details in public issues. See `SECURITY.md`.

## Contributing

Read `CONTRIBUTING.md` and the ADRs before proposing architecture-level changes.

## License

Licensed under the **Apache License 2.0**. See `LICENSE`.
