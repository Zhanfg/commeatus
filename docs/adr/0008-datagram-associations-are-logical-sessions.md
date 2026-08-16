# ADR-0008: Datagram Associations Are Logical Sessions

- **Status:** Accepted
- **Date:** 2026-08-16

## Context

The original SOCKS5 UDP ASSOCIATE path predated the protocol-provider and transport-session boundaries. It owned several unrelated responsibilities in one loop: SOCKS5 UDP framing, policy planning, DIRECT DNS resolution, public UDP I/O, a remote-peer allowlist, TCP-control lifetime and a fixed 500 ms polling timeout.

That shape was sufficient for early DIRECT UDP, but it could not be extended cleanly to Trojan/VLESS-style UDP framing or QUIC-native protocols. Treating UDP support as a boolean protocol capability would also conflate two different questions:

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
- IPv4 plus an optional IPv6 socket created with the association;
- a bounded set of remote socket addresses previously contacted by this association;
- filtering that prevents unsolicited remote datagrams from being surfaced to the inbound client.

The client-facing SOCKS5 UDP relay socket is not the public-network outbound socket. This prevents SOCKS5 framing/lifetime concerns from becoming the owner of DIRECT network state.

The initial remote-peer bound is 256 addresses per association. Reaching the bound rejects a new remote rather than silently evicting an existing authorization.

Zero-length UDP payloads remain valid datagrams.

## DNS ownership

A domain `Target` is preserved until the chosen association executes it. DIRECT resolves the domain inside `DirectDatagramAssociation`.

A future proxy association must encode the canonical domain into its upstream protocol when that protocol supports remote resolution. It must not resolve the proxy-routed destination locally merely because the DIRECT backend does so.

## Readiness and executor ownership

`DatagramAssociation` itself remains independent from `mio`, epoll and OS descriptors. Readiness registration is an executor/event-source concern rather than part of logical datagram semantics.

The DIRECT implementation exposes an internal `register_readiness(...)` hook because its concrete event sources are two nonblocking UDP sockets. This method is not part of `DatagramAssociation` and must not be used to infer that all future datagram associations share the same carrier shape.

The SOCKS5 UDP executor now uses one `mio::Poll` instance to wait on:

- the TCP control connection that owns UDP ASSOCIATE lifetime;
- the client-facing SOCKS5 UDP relay socket;
- the DIRECT IPv4 outbound socket;
- the DIRECT IPv6 outbound socket when available.

The poll timeout is the actual remaining association idle deadline. There is no fixed periodic 500 ms wake-up. TCP control close/error is processed before datagrams from the same event batch so the control connection remains authoritative for association lifetime.

The executor drains at most 32 datagrams from any readiness burst before returning to the event loop. This prevents one hot source from monopolizing the executor.

Client-directed responses use a bounded queue of at most 64 datagrams when the nonblocking relay socket is temporarily not writable. Writable interest is enabled only while that queue is non-empty, avoiding a permanently writable fd that would make the loop spin.

This separation remains deliberate:

- a DIRECT association has multiple OS sockets;
- a stream-framed proxy association may have one reliable carrier;
- a QUIC implementation may expose several logical streams/datagram sources;
- Android/Linux polling machinery must not become protocol semantics.

Future proxy datagram implementations may therefore provide different internal event-source adapters without changing the logical association contract.

## Security, activity and state bounds

The DIRECT implementation only surfaces datagrams from socket addresses it has successfully sent to. Unsolicited sources are discarded.

All remote state is bounded. The association does not retain per-packet history and does not allocate a new payload buffer for each receive operation; the caller supplies the receive buffer.

The SOCKS5 client address is locked only after a packet from the TCP peer IP is successfully parsed, policy-approved and accepted by the selected datagram executor. Malformed or unsupported packets therefore do not claim the client tuple and do not refresh the association idle timer.

A proxy route without a proxy datagram executor remains unsupported. It is dropped and must never fall through to DIRECT.

## Validation

The implementation is covered by deterministic loopback tests for:

- DIRECT IPv4 datagram round trip and canonical source identity;
- hosts-based domain resolution inside the DIRECT association;
- valid zero-length UDP payloads;
- unsolicited remote filtering;
- the 256-remote state bound;
- IPv6 round trip when loopback IPv6 is available;
- full SOCKS5 UDP ASSOCIATE -> DIRECT association -> UDP echo round trip;
- a proxy-routed UDP target not reaching a DIRECT sink when no proxy UDP executor exists;
- TCP control close waking and terminating the readiness executor without waiting for the 120-second idle deadline.

## Non-goals

This ADR does not:

- claim proxy UDP support;
- implement Trojan UDP, VLESS UDP, Hysteria2 or TUIC;
- add SOCKS5 UDP fragmentation support;
- define a stable plugin ABI;
- change routing, DNS policy or endpoint precedence;
- make `mio` part of the `DatagramAssociation` API.

Until a proxy datagram executor exists, proxy endpoint UDP capability remains false and no proxy UDP route may silently fall through to DIRECT.

## Consequences

Positive consequences:

- datagram execution is independent from inbound SOCKS5 framing;
- DIRECT DNS and remote authorization have a single owner;
- the SOCKS5 UDP path no longer wakes on a fixed 500 ms timer;
- TCP control lifetime is readiness-driven rather than sampled with `peek()`;
- future proxy protocols can implement the same logical session semantics without pretending to share a carrier model;
- direct and future proxy datagram executors can share policy-facing semantics while using different readiness adapters.

Trade-offs:

- DIRECT now uses dedicated outbound UDP sockets instead of reusing the SOCKS5 client relay socket;
- the daemon has a direct `mio` dependency for its UDP executor;
- a small bounded response queue is required to preserve nonblocking client writes;
- IPv4 and IPv6 socket lifecycle remains an implementation detail of the DIRECT association.
