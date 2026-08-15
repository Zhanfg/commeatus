# Changelog

All notable changes to Commeatus are documented here.

The project is pre-1.0. Native configuration and internal APIs may change between alpha releases.

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
- HTTP and SOCKS5 handlers now consume one injected DNS engine owned by the compiled runtime configuration
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
