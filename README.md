# Commeatus

Commeatus is a Rust proxy core and runtime built around a flow-centric policy model. Android Root is the first-priority platform, with Linux kept as a portable development and deployment target.

The name comes from Latin *commeatus*: passage, free movement, traffic, and a route through which movement can occur.

> **Status:** current `main` is **v0.6 development**; the latest public prerelease is `v0.5.0-alpha.1`. The tree remains experimental, not a production-ready replacement for mihomo or sing-box. Current main adds explicit verified DNS-over-TLS resolver chains on top of the v0.5 TCP/UDP, policy, Trojan, Android arm64, and eBPF prototype baseline.

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

## What works on current main

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

### Named proxy outbounds

The daemon owns the execution-layer `OutboundRegistry`, but protocol and datagram lifecycle are attached through providers rather than encoded as a central protocol enum:

```text
EndpointId
   ↓
ProxyEndpointConfig
   ├─ stream protocol provider + transport
   └─ optional datagram provider
```

Native stream outbounds currently include:

- upstream SOCKS5 no-auth TCP `CONNECT`
- upstream HTTP/1.x `CONNECT`
- Trojan `CONNECT` over verified TLS

Native datagram execution currently includes:

- policy-aware DIRECT UDP
- Trojan UDP `ASSOCIATE` over verified TLS

A domain selected for any proxy route is preserved to the upstream proxy. It is **not** first resolved through the local DIRECT DNS engine.

UDP capability comes from a real datagram-provider attachment. If policy selects an endpoint that lacks one, the datagram fails locally and is never silently sent DIRECT.

### Native outbound configuration

```text
version 1

listen socks5 127.0.0.1:1080
listen http 127.0.0.1:8080

endpoint edge-socks socks5 127.0.0.1:1081
endpoint office-http http 127.0.0.1:8081
endpoint secure-trojan trojan tls 203.0.113.10:443 trojan.example change-me

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

### Verified TLS transport

TLS is a transport/security capability below the proxy-protocol handshake. Existing SOCKS5 and HTTP CONNECT outbounds can run over plain TCP or verified TLS without TLS-specific branches in their protocol code.

Native forms:

```text
# v0.3-compatible implicit TCP
endpoint edge socks5 127.0.0.1:1081

# explicit TCP
endpoint edge-tcp socks5 tcp 127.0.0.1:1081

# TLS: connection address and certificate identity are separate
endpoint secure socks5 tls 203.0.113.7:443 proxy.example
```

The native TLS path:

- uses rustls 0.23 with the ring crypto provider;
- validates the configured `ServerName` / SNI against the peer certificate;
- trusts the embedded WebPKI server-root set;
- keeps `SocketAddr` separate from TLS identity;
- applies bounded connect and handshake timeouts;
- bounds rustls plaintext buffering;
- exposes no native `insecure` / `skip-verify` switch.

After the proxy-protocol handshake, `TlsTransportSession` owns the TLS state and drives the tunnel with readiness notifications rather than a fixed periodic timer. Clean `close_notify` shutdown is preserved; an unclean network EOF is not silently reclassified as a valid TLS close.

Android cross-builds configure Cargo, `cc-rs`, and ring against the same NDK/API-29 toolchain through `scripts/android-ndk-env.sh`.

### Native Trojan TCP and UDP

Trojan is the first encrypted native proxy protocol. The same native endpoint attaches an independent stream provider and datagram provider above verified TLS:

```text
endpoint secure trojan tls 203.0.113.10:443 trojan.example change-me
```

The raw password is transformed into the Trojan verifier while compiling the configuration candidate. The active protocol objects do not retain the raw source password.

Stream CONNECT uses the ordinary verified `TransportSession`. UDP uses a dedicated `TrojanDatagramProvider` over a readiness-driven framed TLS session. The UDP ASSOCIATE preface uses a normalized `0.0.0.0:0` initial target; each following Trojan UDP frame carries its own IPv4, IPv6 or domain destination.

The datagram path is event driven. It does not use the previous fixed 500 ms SOCKS5 UDP poll timeout, does not register permanent writable interest, and does not start a background Trojan worker.

Trojan UDP state is bounded to 64 pending frames, 512 KiB of pending protocol bytes and 128 KiB of decrypted receive buffering. Partial TLS plaintext, multiple coalesced frames and zero-length UDP payloads are covered by native tests and full SOCKS5-to-Trojan TLS E2E.

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

### DNS failure domain and explicit secure resolver chains

Direct domain resolution lives in `commeatus-dns`, not in SOCKS5, HTTP, Trojan, or policy handlers:

```text
Domain
  ↓
Hosts override
  ↓ miss
Bounded cache
  ↓ miss
Ordered Resolver chain
  ├─ SystemResolver
  └─ DotResolver → verified TlsTransport
```

Resolvers return a typed `DnsAnswer` internally so protocol-owned TTL metadata can reach cache policy without changing daemon callers. The public daemon-facing engine API still returns bounded IP address lists.

The DNS engine currently provides:

- typed errors, answer metadata, and statistics
- DNS hosts overrides
- bounded 4,096-entry cache
- configured cache TTL as a hard maximum (300-second hard cap)
- resolver-provided positive TTL handling
- authoritative TTL=0 results that are usable but not cached
- at most 16 returned addresses per resolution
- ordered resolver fallback
- bounded A/AAAA DNS wire parsing with transaction/question validation
- bounded compression-pointer and CNAME-chain handling
- verified persistent DNS-over-TLS using the existing rustls transport boundary
- one local reconnect/retry after a dead DoT session
- resolver failure isolation

Native resolver declarations are themselves the fallback chain:

```text
# Secure-only: no hidden system fallback exists.
resolver dot 1.1.1.1:853 cloudflare-dns.com

# Optional explicit fallback, only if the user writes it:
resolver system
```

Rules:

- with **no** `resolver` directives, legacy configurations keep exactly one system resolver;
- once any resolver directive exists, the daemon adds **nothing** implicitly;
- a DoT-only chain is therefore secure-only;
- `resolver system` enables system fallback only at its declared position;
- DoT bootstrap must be a literal `IP:port`; the TLS server name is separate and verified through WebPKI;
- at most 8 resolvers may be configured;
- duplicate effective resolver declarations are rejected before candidate commit.

This means a secure-resolver outage is visible unless the configuration explicitly authorizes another resolver. Availability does not silently override DNS privacy policy.

DNS hosts assets remain separate from blocklists:

```text
hosts ./dns/hosts.txt       # name → IP resolution override
blocklist ./rules/ads.txt   # policy rejection source
```

See `examples/dot-resolver.conf`, ADR-0013, and ADR-0014.

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

Validate verified TLS endpoint syntax:

```bash
./target/release/commeatus check --config examples/tls-proxy-outbound.conf
./target/release/commeatus check --config examples/trojan-outbound.conf
./target/release/commeatus check --config examples/dot-resolver.conf
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
- configured DNS resolvers: 8
- hosts source: 4 MiB
- parsed hosts names: 100,000
- active TCP sessions: 256
- remembered UDP remote endpoints per association: 256
- SOCKS5/HTTP inbound handshake timeout: 10 seconds
- direct outbound TCP connect deadline: 10 seconds after resolution
- proxy upstream TCP connect timeout: 10 seconds
- proxy handshake timeout: 10 seconds
- TLS transport buffer limit: 64 KiB
- resolved-address candidate cap: 16
- UDP idle timeout: 120 seconds
- upstream HTTP response-header cap: 16 KiB

All configured listener sockets must bind before service starts. Per-flow/session errors remain local. Thread creation is fallible rather than panic-based, and relay I/O errors shut down both directions to avoid stranded sessions.

## Current limitations

`0.5.0-alpha.1` does **not** include:

- inbound SOCKS5/HTTP authentication
- upstream SOCKS5/HTTP authentication
- ordinary forward-HTTP proxying
- SOCKS5 UDP fragmentation/reassembly
- endpoint groups, health selection or load balancing
- Shadowsocks, VLESS, Hysteria2 or TUIC
- TUN interception
- live TPROXY installation
- live eBPF loading, policy maps or redirection
- Android KernelSU/Magisk module packaging
- DoH, DoQ or Fake-IP
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
- HTTP inbound → SOCKS5 outbound protocol → verified TLS transport → TLS SOCKS5 mock → echo, with `.invalid` target preservation
- trusted test CA + matching TLS identity succeeds; wrong TLS identity fails
- clean TLS full-duplex relay / `close_notify` shutdown
- HTTP inbound → native Trojan CONNECT → verified TLS mock, with `.invalid` target preservation
- SOCKS5 UDP inbound → native Trojan UDP provider → verified framed TLS mock
- Trojan UDP partial/coalesced frame handling and zero-length datagram delivery
- verified DoT A+AAAA reuse over one real TLS connection and local reconnect after server close
- native resolver-chain config tests proving DoT-only secure-only semantics and explicit ordered system fallback

## Repository layout

```text
.
├── Cargo.toml
├── crates/
│   ├── core/       # Flow / Policy / ExecutionPlan / endpoint identity
│   ├── dns/        # DNS engine, hosts, cache and resolver boundary
│   ├── transport/  # TCP/TLS transport sessions and carrier-owned relay
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

After v0.5, the highest-value work is:

1. DoH behind the same typed resolver boundary, then DoQ/Fake-IP semantics without weakening explicit fallback policy
2. TPROXY backend with transactional attach/cleanup and safe fallback
3. eBPF loader, read-only policy maps, atomic generations and fallback behavior
4. additional native protocols behind the established provider boundaries (VLESS/Shadowsocks before QUIC-heavy transports)
5. compatibility importers and a compatibility API facade that terminate at native IR
6. endpoint groups, health selection and real-traffic telemetry
7. adaptive/Smart routing constrained by hard policy
8. low-power global executor plus comparative power/performance benchmarks
9. Android Root packaging and supervisor/cleanup integration once interception lifecycle is proven

## Security

Do not report vulnerabilities with exploit details in public issues. See `SECURITY.md`.

## Contributing

Read `CONTRIBUTING.md` and the ADRs before proposing architecture-level changes.

## License

Licensed under the **Apache License 2.0**. See `LICENSE`.
