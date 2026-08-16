# Commeatus

Commeatus is a Rust proxy core and runtime built around a flow-centric policy model. Android Root is the first-priority platform, with Linux kept as a portable development and deployment target.

The name comes from Latin *commeatus*: passage, free movement, traffic, and a route through which movement can occur.

> **Status:** `0.3.0-alpha.1`. This is an experimental alpha, not a production-ready replacement for mihomo or sing-box. It has a real TCP/UDP inbound data plane, native policy, compiled domain filtering, an isolated DNS engine, named native proxy TCP outbounds, Android arm64 builds, and a CI-verified eBPF prototype boundary.

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

## Runtime model

The first-class runtime object is a flow:

```text
DISCOVER → CLASSIFY → POLICY → PLAN → CONNECT → TRANSFER → OBSERVE → COMPLETE
```

Policy produces an immutable execution result instead of invoking a protocol implementation directly:

```text
FlowContext
    ↓
PolicyEngine
    ↓
ExecutionPlan
    ↓
ExecutionAction
   ├─ Reject(reason)
   └─ Route(endpoint)
        ├─ Direct
        └─ Proxy(EndpointId)
```

`Reject` is an action, not a fake outbound. The core knows a proxy endpoint only by its validated opaque `EndpointId`; SOCKS5/HTTP protocol configuration and upstream addresses remain execution-layer data.

## What works in 0.3.0-alpha.1

### Inbounds and direct data plane

- Linux x86_64 and Android arm64 `commeatus` executable
- SOCKS5 no-auth TCP `CONNECT`
- SOCKS5 no-auth `UDP ASSOCIATE`
- HTTP/1.x `CONNECT`
- IPv4, IPv6 and domain destinations
- bidirectional TCP relay with half-close handling
- policy-aware direct UDP relay
- UDP association lifetime bound to its SOCKS5 TCP control connection
- UDP client endpoint locking and remote-reply allowlisting
- explicit rejection of unsupported SOCKS5 UDP fragmentation

### Named proxy TCP outbounds

The daemon owns an execution-layer `OutboundRegistry`:

```text
EndpointId
   ↓
OutboundRegistry
   ├─ protocol capability
   ├─ upstream address
   └─ connector implementation
```

The first native proxy outbounds are:

- upstream SOCKS5 no-auth TCP `CONNECT`
- upstream HTTP/1.x `CONNECT`

A domain selected for a proxy route is preserved to the upstream proxy. It is **not** first resolved through the local DIRECT DNS engine.

Current proxy endpoints advertise TCP capability only. If policy selects one for UDP, the datagram is not silently sent DIRECT.

### Native outbound configuration

```text
version 1

listen socks5 127.0.0.1:1080
listen http 127.0.0.1:8080

endpoint edge-socks socks5 127.0.0.1:1081
endpoint office-http http 127.0.0.1:8081

rule proxy:edge-socks domain-suffix proxied.example
rule proxy:office-http domain-exact office.example

default direct
```

Rules and the default action may reference `proxy:<id>`. Protocol and upstream address remain endpoint-registry data rather than policy/core data.

Current endpoint guards:

- maximum 64 named proxy endpoints
- endpoint IDs are 1–64 ASCII alphanumeric/`._-` characters
- duplicate IDs are rejected
- undefined `proxy:<id>` references are rejected before runtime commit
- upstream endpoint address must currently be a literal IP socket address with a non-zero port

Literal upstream addresses are deliberate for this slice. Proxy-bootstrap DNS will receive explicit semantics later instead of being smuggled into the config parser.

### Flow and policy

TCP and UDP targets use the same native pipeline:

```text
Inbound request/datagram
        ↓
     Target
        ↓
  FlowContext
        ↓
 PolicyEngine
        ↓
ExecutionPlan
```

Available native matchers include:

- exact domain
- domain suffix
- exact IP
- IPv4/IPv6 CIDR
- destination port
- transport (`tcp` / `udp`)
- compiled domain filter

Policy authority remains:

```text
UserHard > Safety > Compatibility > Adaptive > Default
```

### Compiled blocklists

Large domain policy assets compile once into immutable native domain sets instead of becoming one linear runtime rule per source line.

Accepted alpha forms include:

```text
0.0.0.0 ads.example
tracker.example
||telemetry.example^
@@||api.telemetry.example^
```

Supported semantics:

- hosts-style blocking entries
- plain exact domains
- AdBlock-style domain suffix rules
- AdBlock-style allow exceptions
- DNS-label-boundary suffix matching
- normalization and deduplication

Allow exceptions are **filter exceptions only**. They do not force `DIRECT` and therefore cannot override unrelated routing policy.

Configuration:

```text
blocklist ./rules/ads.txt
```

Resource guards:

- maximum 8 blocklist files
- maximum 8 MiB per blocklist source
- maximum 250,000 accepted entries per source compile

### DNS failure domain

Direct domain resolution lives in `commeatus-dns`, not in SOCKS5 or HTTP handlers:

```text
Domain
  ↓
Hosts override
  ↓ miss
Bounded cache
  ↓ miss
Ordered Resolver chain
  ↓
System Resolver   (current network resolver)
```

The DNS engine provides:

- typed errors and statistics
- DNS hosts overrides
- ordered resolver fallback abstraction
- bounded 4,096-entry cache
- 60-second default synthetic cache TTL
- hard maximum cache TTL of 300 seconds
- at most 16 returned addresses per resolution
- resolver failure isolation

System DNS is still the only network resolver in `0.3.0-alpha.1`. DoH, DoT, DoQ and Fake-IP are future implementations behind the resolver boundary.

DNS hosts assets are separate from blocklists:

```text
hosts ./dns/hosts.txt       # name → IP resolution override
blocklist ./rules/ads.txt   # policy rejection source
```

### Platform capability boundary

`commeatus platform` performs non-destructive probes and reports:

- platform kind
- TUN evidence
- TPROXY evidence
- eBPF evidence
- BTF availability
- bpffs availability

A result can be `available`, `unavailable`, or `unknown`. `unknown` is never silently treated as supported.

### eBPF prototype

The repository contains CI-compiled programs for:

- `cgroup/connect4`
- `cgroup/connect6`

They deliberately return allow and perform no redirect, block, mark or rewrite. There is no live loader in this release.

## Quick start

Build:

```bash
cargo build --release --locked -p commeatus
```

Inspect platform evidence:

```bash
./target/release/commeatus platform
```

Validate the normal example:

```bash
./target/release/commeatus check --config examples/commeatus.conf
```

Validate named proxy endpoint syntax:

```bash
./target/release/commeatus check --config examples/proxy-outbound.conf
```

Run:

```bash
./target/release/commeatus run --config examples/commeatus.conf
```

The bundled normal example listens only on loopback.

## Transactional configuration

Configuration and referenced assets follow candidate-then-swap semantics:

```text
source
  ↓
parse
  ↓
validate
  ↓
load referenced assets
  ↓
compile Policy + DNS + OutboundRegistry candidate
  ↓
atomic snapshot replacement
```

Malformed configuration, dangling endpoint references, missing/oversized blocklists, or invalid hosts files fail the candidate. The Last Known Good snapshot remains active.

## Public-listen safety

Inbound SOCKS5 and HTTP authentication are still **not implemented**. Non-loopback listener addresses are rejected by default.

Explicit opt-out:

```text
allow-public-listen true
```

Do not use this on an untrusted network without another access-control layer.

## Stability and resource guards

Current guards include:

- configuration: 1 MiB
- native policy rules: 4,096
- listeners: 16
- named proxy endpoints: 64
- blocklists: 8
- hosts files: 4
- hosts source: 4 MiB
- parsed hosts names: 100,000
- active TCP sessions: 256
- remembered UDP remote endpoints per association: 256
- SOCKS5/HTTP inbound handshake timeout: 10 seconds
- direct outbound TCP connect deadline: 10 seconds after resolution
- proxy upstream TCP connect timeout: 10 seconds
- proxy handshake timeout: 10 seconds
- resolved-address candidate cap: 16
- UDP idle timeout: 120 seconds
- upstream HTTP response-header cap: 16 KiB

All configured listener sockets must bind before service starts. Per-flow/session errors remain local. Thread creation is fallible rather than panic-based, and relay I/O errors shut down both directions to avoid stranded sessions.

## Current limitations

`0.3.0-alpha.1` does **not** include:

- inbound SOCKS5/HTTP authentication
- upstream SOCKS5/HTTP authentication
- ordinary forward-HTTP proxying
- SOCKS5 UDP fragmentation/reassembly
- proxy UDP execution
- endpoint groups, health selection or load balancing
- TLS transport provider
- Shadowsocks, Trojan, VLESS, Hysteria2 or TUIC
- TUN interception
- live TPROXY installation
- live eBPF loading, policy maps or redirection
- Android KernelSU/Magisk module packaging
- DoH, DoT, DoQ or Fake-IP
- remote rule-provider refresh
- Clash/mihomo/sing-box configuration import or compatible API
- adaptive/Smart routing
- process-level live reload watcher
- final low-power event-driven execution backend

The current blocking `std` socket / bounded thread-per-session executor remains transitional. It keeps the execution path small and auditable while protocol, policy, DNS and platform boundaries stabilize.

A CIDR rule still matches only a canonical IP destination. It does not retroactively replace domain identity with DNS results; this is intentional until DNS-derived matching is explicitly modeled.

## Verification

GitHub Actions on Ubuntu validates:

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets --locked`
- `cargo clippy --workspace --all-targets --locked -- -D warnings`
- full workspace tests
- release build
- CLI `version`, `platform`, and config-check smoke
- explicit Rust 1.85 MSRV
- Android `aarch64-linux-android` NDK/API-29 release build and ELF verification
- eBPF Clang build and `cgroup/connect4`, `cgroup/connect6`, `license` section verification
- Linux + Android release-package dry run with SHA-256 verification

The E2E suite includes real loopback coverage for:

- SOCKS5 TCP `CONNECT`
- HTTP `CONNECT`, including buffered tunnel bytes
- SOCKS5 UDP `ASSOCIATE`
- TCP/UDP domain routing through a hosts-only DNS override
- policy rejection before outbound connect
- listener survival after malformed input
- SOCKS5 inbound → named upstream SOCKS5 proxy → echo
- HTTP CONNECT inbound → named upstream HTTP proxy → echo
- `.invalid` target-domain preservation to the selected upstream proxy without local destination DNS

## Repository layout

```text
.
├── Cargo.toml
├── crates/
│   ├── core/       # Flow / Policy / ExecutionPlan / endpoint identity
│   ├── dns/        # DNS engine, hosts, cache and resolver boundary
│   ├── daemon/     # inbound handlers, outbound registry and execution
│   ├── platform/   # Linux / Android capability boundary
│   └── compat/     # external-format compilers such as blocklists
├── ebpf/           # compile-verified eBPF prototypes
├── examples/
├── docs/
└── tests/
```

## Architecture invariants

- Flow is the first-class runtime object.
- Compatibility formats terminate at the compatibility boundary.
- Actions, endpoints, transports, resolvers and policies remain distinct concepts.
- Proxy protocol configuration does not leak into the core endpoint identity.
- One state has one authoritative owner.
- A subsystem failure must not automatically become a global network outage.
- Configuration candidates and referenced assets are validated before replacing active state.
- Root/eBPF behavior is capability-gated platform logic, not a core assumption.
- Direct traffic should eventually avoid unnecessary userspace traversal where the platform safely supports it.
- User hard policy and safety constraints outrank adaptive decisions.
- Unsupported endpoint capability must fail locally; it must not mutate policy into a fallback route.

Accepted architecture decisions live in `docs/adr/`.

## Next development slices

After this release line, the highest-value work is:

1. reusable transport-session boundary, starting with TLS as a transport capability rather than protocol-owned security
2. first encrypted native proxy protocol on that transport boundary
3. proxy UDP execution and a capability-safe datagram abstraction
4. secure DNS resolvers behind `commeatus-dns`
5. TPROXY backend and safe attach/cleanup lifecycle
6. eBPF loader, read-only policy maps, atomic generations and fallback behavior
7. compatibility importers/API facade
8. adaptive routing and real-traffic telemetry
9. low-power executor and comparative power/performance benchmarks

## Security

Do not report vulnerabilities with exploit details in public issues. See `SECURITY.md`.

## Contributing

Read `CONTRIBUTING.md` and the ADRs before proposing architecture-level changes.

## License

Licensed under the **Apache License 2.0**. See `LICENSE`.
