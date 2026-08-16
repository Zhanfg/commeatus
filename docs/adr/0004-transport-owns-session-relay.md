# ADR-0004: Transport Owns Session Relay

- Status: Accepted
- Date: 2026-08-16

## Context

The first native proxy outbounds returned a raw `TcpStream` after their protocol handshake. Inbound handlers then called a daemon-level relay that depended on `TcpStream::try_clone()`.

That works for plain TCP, but it makes a TCP implementation detail part of the protocol execution contract. A TLS carrier, QUIC stream, multiplexed stream, or another future transport may not support the same cloning or half-close mechanism. If protocol code owns those assumptions, every new transport forces protocol-specific branching and recreates a `Protocol × Transport` combination explosion.

## Decision

Transport sessions own carrier-specific connection and relay behavior.

The execution boundary is:

```text
ExecutionPlan
    ↓
EndpointId
    ↓
OutboundRegistry
    ↓
Protocol handshake over Read + Write
    ↓
TransportSession::relay_to_client(...)
```

The core continues to know only endpoint identity. The outbound registry composes a protocol with a transport configuration. A protocol may read and write handshake bytes through `TransportSession`, but it does not own carrier establishment, transport encryption, socket cloning, or full-duplex relay strategy.

`TcpTransport` is the first implementation. Its session may use `TcpStream::try_clone()` internally, because that is a TCP transport detail. That behavior must not leak back into SOCKS5, HTTP CONNECT, or future encrypted proxy protocols.

Transport capabilities are authoritative inputs to endpoint capabilities. In particular, whether a carrier is encrypted is transport metadata, not something inferred from a protocol name.

## Consequences

- SOCKS5 and HTTP CONNECT can remain unchanged when a future TLS transport is added beneath them.
- Future protocols such as Trojan or VLESS can be implemented as protocol handshakes over an existing transport session rather than reimplementing TCP/TLS/DNS/routing.
- Carrier-specific half-close and relay behavior has one owner.
- `TransportSession` currently accepts a local `TcpStream` for relay because current inbounds are TCP socket based. Generalizing the local-side stream is explicitly deferred until a real non-TCP inbound requires it; this ADR does not freeze `TcpStream` as the universal inbound abstraction.
- Datagram transports are not implied by this stream-session interface and require a separate capability-safe datagram abstraction.

## Rejected alternatives

### Keep returning `TcpStream`

Rejected because it prevents non-clonable encrypted or multiplexed carriers from fitting the execution model without protocol-specific exceptions.

### Put TLS inside each proxy protocol

Rejected because TLS is a transport/security capability shared by multiple protocols. Protocol-owned TLS would duplicate certificate, SNI, timeout, relay, and future policy behavior.

### Introduce a universal async transport framework immediately

Rejected for this stage. The project first needs a small, testable ownership boundary that preserves current behavior. Event-driven execution can replace individual transport implementations without changing the protocol/core contract established here.
