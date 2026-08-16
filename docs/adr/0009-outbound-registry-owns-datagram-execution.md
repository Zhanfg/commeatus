# ADR-0009: Outbound Registry Owns Datagram Execution

- **Status:** Accepted
- **Date:** 2026-08-16

## Context

ADR-0008 introduced logical datagram associations and moved SOCKS5 UDP ASSOCIATE onto a readiness-driven DIRECT executor. That removed the fixed 500 ms polling loop, but one ownership leak remained: the SOCKS5 inbound implementation still constructed `DirectDatagramAssociation` itself.

That made the inbound protocol a second authority for outbound execution. It also encoded an assumption that one inbound UDP association maps to one concrete DIRECT execution path.

The assumption is not valid. A single SOCKS5 UDP ASSOCIATE may carry datagrams for many targets, and policy may route those targets to different endpoints. Future proxy datagram support must therefore allow several outbound datagram sessions to coexist under one inbound association without teaching SOCKS5 how each endpoint is implemented.

## Decision

`OutboundRegistry` is the single factory authority for opening a datagram execution path for an `Endpoint`.

```rust
pub fn open_datagram(
    &self,
    endpoint: &Endpoint,
    direct_dns: Arc<DnsEngine>,
) -> io::Result<Box<dyn DatagramExecution>>;
```

The current implementation opens DIRECT through `DirectDatagramAssociation`. A registered proxy endpoint without a datagram provider returns `io::ErrorKind::Unsupported`. An unknown proxy endpoint returns `NotFound`.

No caller may convert either error into DIRECT execution.

## Logical association versus execution readiness

`DatagramAssociation` remains the carrier-agnostic logical interface:

```rust
pub trait DatagramAssociation: Send {
    fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()>;
    fn receive(&mut self, buffer: &mut [u8])
        -> io::Result<Option<ReceivedDatagram>>;
}
```

Readiness is represented separately:

```rust
pub trait DatagramExecution: DatagramAssociation {
    fn readiness_source_count(&self) -> usize;
    fn register_readiness(
        &mut self,
        registry: &Registry,
        tokens: &[Token],
    ) -> io::Result<()>;
}
```

This second interface belongs to the daemon executor layer. It does not imply that DIRECT, a stream-framed proxy protocol and a QUIC-native protocol have the same carrier shape.

## Per-inbound route set

A SOCKS5 UDP ASSOCIATE owns one `DatagramRouteSet` rather than one concrete outbound association.

The route set is keyed by the policy-selected `Endpoint`. `Endpoint` therefore has stable hash identity in the core model.

For each first use of an endpoint, the route set:

1. asks `OutboundRegistry` to open the endpoint's datagram execution path;
2. asks the execution path how many readiness sources it requires;
3. allocates caller-owned readiness tokens;
4. registers those sources in the shared poll registry;
5. retains that execution path for later datagrams routed to the same endpoint.

Subsequent datagrams to the same endpoint reuse the existing execution object. Datagrams routed to another endpoint may open another execution object in the same inbound SOCKS5 association.

The route set is bounded to 32 endpoint executions per inbound association. Reaching the limit rejects creation of another route rather than evicting an existing route or silently changing policy behavior.

Token allocation is monotonic for the lifetime of the inbound association. Token ownership is used to dispatch readiness back to the correct outbound execution path.

Internal invariant failures are returned as `io::Error`; the route set does not panic because a post-insertion lookup unexpectedly fails.

## SOCKS5 ownership after this decision

The SOCKS5 implementation owns only inbound protocol responsibilities:

- TCP control lifetime;
- SOCKS5 UDP framing and client tuple validation;
- flow construction and policy evaluation;
- the client-facing relay socket;
- scheduling readiness events through the route set.

It does **not** construct `DirectDatagramAssociation`, inspect a concrete outbound carrier, or special-case `Endpoint::Direct` when opening a datagram route.

## Capability behavior

This decision does not make existing proxy endpoints UDP-capable.

Current proxy endpoint capability remains `udp = false`. Therefore policy selecting such an endpoint is rejected before a datagram route is opened.

When a future proxy endpoint receives a real datagram provider, its capability must derive from the presence/capabilities of that provider, and `open_datagram` must return the corresponding `DatagramExecution`. SOCKS5 should not require another concrete-protocol branch.

## Future proxy datagram providers

Stream protocol providers and datagram providers remain separate concerns. ADR-0007's `OutboundProtocol` continues to own stream handshake semantics only.

A future Trojan, VLESS, SOCKS5-upstream, Hysteria2 or TUIC datagram implementation may attach a separate datagram provider/factory to the endpoint runtime. The provider may use a reliable stream, native datagrams or another carrier internally, as long as it exposes the logical datagram and readiness execution contracts required by the daemon.

This avoids reintroducing a central `udp: bool` on the stream protocol interface or forcing all protocols into the same carrier model.

## Validation

The refactor is validated by tests that verify:

- one endpoint is lazily opened once and reused across multiple sends;
- readiness token ownership is retained with the endpoint execution;
- route count is bounded at 32 and does not grow after overflow;
- DIRECT still opens through the registry factory;
- a registered proxy endpoint without a datagram provider returns `Unsupported`;
- existing SOCKS5 UDP round-trip, control-close and no-proxy-to-DIRECT-fallback tests continue to pass;
- stable fmt/check/Clippy/all workspace tests and Rust 1.85 all-targets pass before the migration is committed.

## Non-goals

This ADR does not:

- implement Trojan UDP or VLESS UDP;
- mark any current proxy endpoint UDP-capable;
- add Hysteria2, TUIC or QUIC;
- define the final proxy datagram provider configuration schema;
- define a stable external plugin ABI;
- change route precedence, DNS policy or SOCKS5 UDP fragmentation behavior.

## Consequences

Positive consequences:

- outbound runtime has one authority for datagram execution construction;
- one inbound UDP association can obey per-datagram policy decisions across several endpoints;
- SOCKS5 no longer knows whether an endpoint is DIRECT or a future proxy implementation;
- unsupported proxy datagrams remain explicit rather than falling through to DIRECT;
- future proxy datagram protocols can attach below the registry boundary without rewriting inbound SOCKS5 routing logic;
- route and readiness state are bounded.

Trade-offs:

- endpoint identity must be hashable because it is now a runtime route key;
- one inbound association may retain several outbound execution objects, so a hard per-association route bound is required;
- the registry factory currently accepts DIRECT DNS state even though future proxy providers may not use it; provider-specific construction inputs may be refined when the first real proxy datagram implementation is added.
