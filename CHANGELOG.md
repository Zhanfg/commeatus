# Changelog

All notable changes to Commeatus are documented here.

The project is pre-1.0. Native configuration and internal APIs may change between alpha releases.

## 0.4.0-alpha.1 — 2026-08-16

Fourth public alpha. This release establishes a reusable transport-session layer and adds verified native TLS beneath existing outbound proxy protocols.

### Added

- `commeatus-transport` ownership boundary with `TransportConnector`, `TransportSession`, and transport capabilities
- `TcpTransport` / `TcpTransportSession`; TCP-specific clone/half-close logic now belongs to the transport
- rustls 0.23 + ring `TlsTransport` / `TlsTransportSession`
- embedded WebPKI root verification on the native TLS path
- independent literal upstream `SocketAddr` and TLS `ServerName` / SNI
- readiness-driven TLS full-duplex relay using `mio::Poll`
- bounded TLS plaintext buffering and bounded connect/handshake timeouts
- explicit native endpoint forms for TCP and TLS while preserving v0.3 implicit-TCP syntax
- `examples/tls-proxy-outbound.conf`
- ADR-0004 `Transport Owns Session Relay`
- ADR-0005 `TLS Is a Verified Transport`
- deterministic local certificate/SNI verification tests
- full-duplex TLS relay + clean `close_notify` test
- cross-layer HTTP inbound → SOCKS5 protocol → TLS transport → TLS SOCKS5 mock → echo E2E
- Android NDK environment helper for Cargo linker plus target-specific `cc-rs` CC/AR

### Changed

- outbound protocols now perform handshakes over `TransportSession` rather than returning raw `TcpStream`
- carrier relay behavior has one authoritative transport owner
- endpoint encrypted capability is derived from transport metadata
- native TLS configuration separates network connection address from certificate identity
- Android CI/package builds configure native C/assembly dependencies against the same NDK/API-29 toolchain as Rust

### Security and stability

- native TLS certificate/server-name verification is enabled by default
- no native insecure/skip-verification switch is provided
- wrong TLS server identity fails even when the issuing test CA is trusted
- unclean network EOF is not silently accepted as TLS `close_notify`
- TLS readiness interests are registered only while useful I/O work exists; there is no fixed periodic relay timer
- proxy-routed `.invalid` destination identity remains preserved through SOCKS5-over-TLS without local destination DNS
- Rust 1.85 all-targets, Android arm64/ring, eBPF and release packaging remain gated in CI

### Known limitations

- no Trojan, VLESS, Shadowsocks, Hysteria2 or TUIC yet
- no proxy UDP execution
- no Android/Linux user-added enterprise trust-store import
- no client certificates / mTLS, pinning, explicit ALPN policy or ECH
- no endpoint groups / health selection / adaptive routing
- no live TUN/TPROXY/eBPF interception
- no KernelSU/Magisk packaging
- no DoH/DoT/DoQ/Fake-IP
- no Clash/mihomo/sing-box import or compatible API

## 0.3.0-alpha.1 — 2026-08-16

Third public alpha. This release turns policy-selected proxy endpoint identities into a real native TCP execution path while preserving the boundary between core routing decisions and protocol implementation.

### Added

- validated opaque `EndpointId` and `Endpoint::Proxy(EndpointId)` in the native core
- execution-layer `OutboundRegistry` with per-endpoint capability metadata
- native upstream SOCKS5 no-auth TCP `CONNECT` connector
- native upstream HTTP/1.x `CONNECT` connector
- native `endpoint <id> <socks5|http> <ip:port>` configuration
- `proxy:<id>` route actions for rules and the default action
- maximum 64 named proxy endpoints
- candidate validation for duplicate or undefined proxy endpoint references
- outbound endpoint count in CLI configuration diagnostics
- `examples/proxy-outbound.conf`
- real SOCKS5-inbound → named SOCKS5-outbound → echo E2E
- real HTTP-inbound → named HTTP-outbound → echo E2E
- `.invalid` destination E2E proving proxy-routed domains are preserved to the selected upstream proxy rather than resolved locally first

### Changed

- SOCKS5 and HTTP inbound handlers now consume the complete `ExecutionAction` instead of reducing every route to DIRECT
- TCP route execution dispatches through the outbound registry
- endpoint protocol/address/capability data remains outside `commeatus-core`
- TCP capability is checked before connector dispatch
- named proxy endpoint addresses are currently literal `SocketAddr` values so bootstrap-DNS semantics are not introduced implicitly
- workspace and internal crate versions advance to `0.3.0-alpha.1`

### Security and stability

- a proxy endpoint that does not advertise UDP capability never silently degrades to DIRECT
- undefined `proxy:<id>` references fail candidate configuration before active-state replacement
- upstream proxy TCP connect and handshake operations have bounded 10-second timeouts
- upstream HTTP response parsing stops at the header terminator and does not consume tunnel payload bytes
- SOCKS5 upstream replies validate version, reserved byte, status and bound-address framing
- proxy-routed domain targets remain opaque to the local direct DNS path
- existing listener/session/resource limits remain in force

### Known limitations

- upstream SOCKS5/HTTP authentication is not implemented
- proxy UDP execution is not implemented
- no TLS transport provider yet
- no Shadowsocks, Trojan, VLESS, Hysteria2 or TUIC
- no endpoint groups, health selection or adaptive routing
- no live TUN/TPROXY/eBPF interception
- no Android KernelSU/Magisk module packaging
- system DNS remains the only network resolver; no DoH/DoT/DoQ/Fake-IP
- no Clash/mihomo/sing-box import/API compatibility yet
- bounded thread-per-session remains the transitional executor

## 0.2.0-alpha.1 — 2026-08-15

Second public alpha. This release expands the first TCP slice into a policy-aware TCP/UDP runtime and establishes the DNS, filtering and Android/eBPF platform boundaries required for later interception and encrypted proxy protocols.

### Added

- SOCKS5 `UDP ASSOCIATE` with IPv4, IPv6 and domain targets
- UDP targets use the same `FlowContext → PolicyEngine → ExecutionPlan` path as TCP
- native `transport tcp|udp` matcher
- UDP association lifetime tied to the SOCKS5 TCP control connection
- UDP client endpoint locking and remote-reply allowlisting
- 256 remembered remote UDP endpoints per association and 120-second idle timeout
- explicit rejection of unsupported SOCKS5 UDP fragmentation
- independent `commeatus-dns` crate and DNS failure domain
- DNS hosts overrides, bounded cache, ordered resolver fallback abstraction and independent statistics
- `hosts <path>` transactional configuration assets
- compiled immutable domain sets and `Matcher::DomainFilter`
- hosts-style, plain-domain, `||domain^` and `@@||domain^` blocklist compilation
- `blocklist <path>` transactional policy assets
- blocklist/hosts resource limits and config-relative asset resolution
- `commeatus platform` non-destructive TUN/TPROXY/eBPF/BTF/bpffs capability reporting
- typed platform backend/capability boundary
- compile-only eBPF prototypes for `cgroup/connect4` and `cgroup/connect6`
- GitHub Actions BPF ELF/section verification
- real loopback SOCKS5 UDP end-to-end tests
- real TCP and UDP end-to-end tests that resolve an otherwise unavailable domain exclusively through the Commeatus hosts table

### Changed

- direct domain resolution was removed from protocol handlers and centralized in the DNS engine
- HTTP and SOCKS5 handlers consume one injected DNS engine owned by the compiled runtime configuration
- blocklist allow exceptions are filter exceptions only and never force `DIRECT`
- compatibility source formats compile into native policy structures before runtime use
- platform support probes distinguish `available`, `unavailable` and `unknown` instead of assuming support
- HTTP Proxy-Agent version follows the package version

### Security and stability

- UDP remote replies are accepted only from endpoints previously contacted by that association
- malformed or missing blocklist/hosts assets fail the candidate configuration before active-state replacement
- DNS resolver failure can fall through to a later resolver rather than becoming a process-wide failure
- DNS cache and result counts are bounded
- default DNS-engine construction no longer contains an unnecessary panic path
- invalid hosts names are classified as asset-parse errors rather than runtime query failures
- eBPF code in this release is deliberately side-effect free and performs no redirect, rewrite, mark or block

### Known limitations

- no inbound authentication
- no SOCKS5 UDP fragmentation/reassembly
- no TUN backend or live TPROXY installation
- no live eBPF loader, maps or interception
- no Android KernelSU/Magisk module packaging
- no proxy-protocol outbounds yet
- system DNS is still the only network resolver; no DoH/DoT/DoQ/Fake-IP
- no remote rule-provider refresh
- no Clash/mihomo/sing-box import/API compatibility yet
- no adaptive/Smart routing
- no live configuration file watcher
- bounded thread-per-session remains the transitional executor

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
