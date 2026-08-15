# Commeatus

Commeatus is a Rust proxy core and runtime built around a flow-centric policy model. Android Root is the first-priority platform, with Linux kept as a portable development and deployment target.

The name comes from Latin *commeatus*: passage, free movement, traffic, and a route through which movement can occur.

> **Status:** `0.2.0-alpha.1`. This is an experimental alpha, not a production-ready replacement for mihomo or sing-box. It is, however, a real TCP/UDP proxy runtime with native policy, compiled domain filtering, an isolated DNS engine, Android arm64 builds, and a CI-verified eBPF prototype boundary.

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

## What works in 0.2.0-alpha.1

### Proxy data plane

- Linux x86_64 and Android arm64 `commeatus` executable
- SOCKS5 no-auth TCP `CONNECT`
- SOCKS5 no-auth `UDP ASSOCIATE`
- HTTP/1.x `CONNECT`
- IPv4, IPv6 and domain destinations
- bidirectional TCP relay with half-close handling
- UDP association lifetime bound to its SOCKS5 TCP control connection
- UDP client endpoint locking and remote-reply allowlisting
- 256 active TCP-session cap and 256 remembered remote UDP endpoints per association
- explicit rejection of unsupported SOCKS5 UDP fragmentation

### Flow and policy

Every TCP and UDP target continues through the same native pipeline:

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
    ↙       ↘
 DIRECT    REJECT
```

Available native matchers include:

- exact domain
- domain suffix
- exact IP
- IPv4/IPv6 CIDR
- destination port
- transport (`tcp` / `udp`)

Policy authority remains:

```text
UserHard > Safety > Compatibility > Adaptive > Default
```

`Reject` is an action, not an outbound endpoint. `Direct` is an endpoint selected by a route action.

### Compiled blocklists

Large domain policy assets compile once into immutable native domain sets instead of becoming one linear runtime rule per source line.

Accepted source forms in this alpha:

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
- deduplication and normalization

Allow exceptions are **filter exceptions only**. They do not silently force `DIRECT` and therefore cannot override an unrelated user routing policy.

Resource guards:

- maximum 8 blocklist files
- maximum 8 MiB per blocklist source
- maximum 250,000 accepted entries per source compile

### DNS failure domain

Domain resolution is no longer performed inside SOCKS5 or HTTP protocol handlers. All direct domain destinations go through `commeatus-dns`:

```text
Domain
  ↓
Hosts override
  ↓ miss
Bounded cache
  ↓ miss
Ordered Resolver chain
  ↓
System Resolver   (v0.2 network resolver)
```

The DNS engine currently provides:

- separate typed errors and statistics
- DNS hosts overrides
- ordered resolver fallback abstraction
- bounded 4,096-entry cache
- 60-second default synthetic cache TTL
- hard maximum cache TTL of 300 seconds
- at most 16 returned addresses per resolution
- resolver failure isolation rather than process-wide failure

System DNS is the only network resolver in `0.2.0-alpha.1`. DoH, DoT, DoQ and Fake-IP are future resolver/backend work behind this boundary.

DNS hosts assets are distinct from blocklists:

```text
hosts <path>      # name → IP resolution override
blocklist <path>  # policy rejection source
```

These two concepts intentionally do not share semantics.

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

The repository now contains CI-compiled eBPF programs for:

- `cgroup/connect4`
- `cgroup/connect6`

The current programs deliberately return allow and perform **no redirect, block, mark or rewrite**. GitHub Actions compiles the BPF ELF and verifies the expected sections. There is no userspace loader or live Android interception in this release.

This establishes the attach-point/toolchain boundary before introducing privileged live behavior.

## Quick start

Build:

```bash
cargo build --release --locked -p commeatus
```

Inspect platform capabilities:

```bash
./target/release/commeatus platform
```

Validate configuration:

```bash
./target/release/commeatus check --config examples/commeatus.conf
```

Run:

```bash
./target/release/commeatus run --config examples/commeatus.conf
```

The bundled example listens only on loopback.

## Native alpha configuration

The native syntax is deliberately small and remains unstable before 1.0:

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
rule reject transport udp
```

Optional external policy/DNS assets:

```text
blocklist ./rules/ads.txt
hosts ./dns/hosts.txt
```

Relative asset paths are resolved relative to the configuration file directory, not the daemon working directory. Assets are fully read and compiled as part of the candidate configuration before the active runtime is replaced.

### Transactional configuration

The intended lifecycle is:

```text
source
  ↓
parse
  ↓
validate
  ↓
load referenced assets
  ↓
compile Policy + DNS candidate
  ↓
atomic snapshot replacement
```

If a config, blocklist or hosts file is malformed, missing or over its resource limit, the candidate fails and the Last Known Good snapshot remains active.

### Public-listen safety

SOCKS5 and HTTP authentication are still **not implemented**. Non-loopback listener addresses are therefore rejected by default.

Intentional opt-out:

```text
allow-public-listen true
```

Do not use this on an untrusted network without another access-control layer.

## Stability/resource guards

Current alpha guards include:

- configuration: 1 MiB
- native policy rules: 4,096
- listeners: 16
- blocklists: 8
- hosts files: 4
- hosts source: 4 MiB
- parsed hosts names: 100,000
- active TCP sessions: 256
- remembered UDP remote endpoints per association: 256
- SOCKS5/HTTP handshake timeout: 10 seconds
- outbound TCP connect deadline: 10 seconds after resolution
- resolved-address candidate cap: 16
- UDP idle timeout: 120 seconds

All configured listener sockets must bind before service starts. Per-flow/session errors remain local. Thread creation is fallible rather than panic-based, and relay I/O errors shut down both directions to avoid stranded sessions.

## Current limitations

`0.2.0-alpha.1` does **not** include:

- SOCKS5 username/password authentication
- HTTP proxy authentication
- ordinary forward-HTTP requests
- SOCKS5 UDP fragmentation/reassembly
- TUN interception
- live TPROXY installation
- live eBPF loading, policy maps or redirection
- Android KernelSU/Magisk module packaging
- native proxy outbounds such as Shadowsocks, Trojan, VLESS, Hysteria2 or TUIC
- DoH, DoT, DoQ or Fake-IP
- remote rule-provider refresh
- Clash/mihomo/sing-box configuration import or compatible API
- adaptive/Smart routing
- process-level live reload watcher
- final low-power event-driven execution backend

The current blocking `std` socket / bounded thread-per-session executor remains transitional. It exists to keep the execution path small and auditable while protocol, policy, DNS and platform boundaries stabilize.

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

The test suite includes real loopback E2E for:

- SOCKS5 TCP CONNECT
- HTTP CONNECT, including buffered tunnel bytes
- SOCKS5 UDP ASSOCIATE
- TCP domain routing through a hosts-only DNS override
- UDP domain routing through a hosts-only DNS override
- policy rejection before outbound connect
- listener survival after a malformed client

## Repository layout

```text
.
├── Cargo.toml
├── crates/
│   ├── core/       # Flow / Policy / ExecutionPlan / compiled domain sets
│   ├── dns/        # DNS engine, hosts, cache and resolver boundary
│   ├── daemon/     # runnable proxy and native alpha config
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
- One state has one authoritative owner.
- A subsystem failure must not automatically become a global network outage.
- Configuration candidates and referenced assets are validated before replacing active state.
- Root/eBPF behavior is capability-gated platform logic, not a core assumption.
- Direct traffic should eventually avoid unnecessary userspace traversal where the platform safely supports it.
- User hard policy and safety constraints outrank adaptive decisions.

Accepted architecture decisions live in `docs/adr/`.

## Next development slices

After this release line, the highest-value work is:

1. protocol/transport capability registry and first native encrypted proxy outbounds
2. secure DNS resolvers behind the isolated DNS engine
3. TPROXY backend and safe attach/cleanup lifecycle
4. eBPF loader, read-only policy maps, atomic generations and fallback behavior
5. compatibility importers/API facade
6. adaptive routing and real-traffic telemetry
7. low-power executor and comparative power/performance benchmarks

## Security

Do not report vulnerabilities with exploit details in public issues. See `SECURITY.md`.

## Contributing

Read `CONTRIBUTING.md` and the ADRs before proposing architecture-level changes.

## License

Licensed under the **Apache License 2.0**. See `LICENSE`.
