# ADR-0008: Datagram Associations Are Logical Sessions

- **Status:** Accepted
- **Date:** 2026-08-16

## Context

The existing SOCKS5 UDP ASSOCIATE path predates the protocol-provider and transport-session boundaries. It currently owns several unrelated responsibilities in one loop: SOCKS5 UDP framing, policy planning, DIRECT DNS resolution, public UDP I/O, a remote-peer allowlist, TCP-control lifetime and a fixed polling timeout.

That implementation is sufficient for DIRECT UDP, but it cannot be extended cleanly to Trojan/VLESS-style UDP framing or QUIC-native protocols. Treating UDP support as a boolean protocol capability would also conflate two different questions:

1. what datagram semantics a protocol exposes;
2. how the selected carrier transports those datagrams.

A logical datagram session therefore needs its own execution boundary before proxy UDP is added.

## Decision

The runtime introduces a `DatagramAssociation` interface:

```rust
pub trait DatagramAssociation: Send {
    fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()>;
    fn receive(
        &mut self,
        buffer: &mut [u8],
    ) -> io::Result<Option<ReceivedDatagram>>;
}
```

The interface represents a long-lived logical datagram path selected by policy/execution planning. It intentionally does not expose an OS socket, epoll token or a particular carrier type.

A received datagram returns a canonical source `Target` plus the number of payload bytes written into the caller-owned buffer.

## DIRECT implementation

`DirectDatagramAssociation` is the first implementation. It owns:

- DIRECT-only DNS resolution;
- dedicated nonblocking outbound UDP sockets;
- IPv4 and on-demand IPv6 execution;
- a bounded set of remote socket addresses previously contacted by this association;
- filtering that prevents unsolicited remote datagrams from being surfaced to the inbound client.

The client-facing SOCKS5 UDP relay socket is not the public-network outbound socket. This prevents SOCKS5 framing/lifetime concerns from becoming the owner of DIRECT network state.

The initial remote-peer bound is 256 addresses per association. Reaching the bound rejects a new remote rather than silently evicting an existing authorization.

Zero-length UDP payloads remain valid datagrams.

## DNS ownership

A domain `Target` is preserved until the chosen association executes it. DIRECT resolves the domain inside `DirectDatagramAssociation`.

A future proxy association must encode the canonical domain into its upstream protocol when that protocol supports remote resolution. It must not resolve the proxy-routed destination locally merely because the DIRECT backend does so.

## Event-loop separation

This ADR does not make `DatagramAssociation` a `mio`/epoll interface. Readiness registration is a separate executor/event-source concern.

This separation is deliberate:

- a DIRECT association can have multiple OS sockets;
- a stream-framed proxy association may have one reliable carrier;
- a QUIC implementation may expose several logical streams/datagram sources;
- platform-specific Android/Linux polling machinery must not become part of protocol semantics.

A subsequent change may add an internal event-source adapter and replace the current SOCKS5 500 ms polling loop with readiness plus a real idle deadline. That change must not alter this logical association contract unless new evidence requires it.

## Security and state bounds

The DIRECT implementation only surfaces datagrams from socket addresses it has successfully sent to. Unsolicited sources are discarded.

All remote state is bounded. The association does not retain per-packet history and does not allocate a new payload buffer for each receive operation; the caller supplies the receive buffer.

## Non-goals

This ADR does not:

- claim proxy UDP support;
- implement Trojan UDP, VLESS UDP, Hysteria2 or TUIC;
- change SOCKS5 UDP ASSOCIATE behavior yet;
- add fragmentation support;
- define a stable plugin ABI;
- select an event-loop library;
- change routing, DNS policy or endpoint precedence.

Until a proxy datagram executor exists, proxy endpoint UDP capability remains false and no proxy UDP route may silently fall through to DIRECT.

## Consequences

Positive consequences:

- datagram execution becomes independent from inbound SOCKS5 framing;
- DIRECT DNS and remote authorization have a single owner;
- future proxy protocols can implement the same logical session semantics without pretending to share a carrier model;
- readiness/low-power work can be layered on the association instead of embedded in protocol code.

Trade-offs:

- the first refactor introduces a dedicated outbound UDP socket instead of reusing the SOCKS5 client relay socket;
- readiness integration requires a separate internal adapter in a later change;
- IPv4 and IPv6 socket lifecycle remains an implementation detail of the DIRECT association.
