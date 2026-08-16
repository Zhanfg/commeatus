# ADR-0007: Protocol Providers Own Handshakes

- **Status:** Accepted
- **Date:** 2026-08-16

## Context

The first native outbound implementations were represented by a central `ProxyProtocol` enum. That was sufficient while the runtime contained only SOCKS5 and HTTP CONNECT, but adding Trojan exposed the scaling problem: every new protocol required the central outbound registry to know another concrete protocol variant and another handshake branch.

That shape would turn protocol growth into a global switch and recreate the same combination debt this project is explicitly trying to avoid. Protocol behavior, transport behavior, routing, DNS and policy must remain separate ownership domains.

The runtime already has a transport boundary. `TransportConnector` establishes a carrier, `TransportSession` exposes handshake-time `Read + Write`, and the transport owns carrier-specific full-duplex relay after the protocol handshake. The protocol boundary should follow the same ownership rule.

## Decision

Outbound stream protocols are represented by providers implementing an internal `OutboundProtocol` interface.

```rust
pub struct ProtocolCapabilities {
    pub stream_connect: bool,
    pub requires_tls: bool,
}

pub trait OutboundProtocol: Debug + Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> ProtocolCapabilities;
    fn handshake_stream(
        &self,
        session: &mut dyn TransportSession,
        target: &Target,
    ) -> io::Result<()>;
}
```

The runtime stores `ProtocolRef = Arc<dyn OutboundProtocol>` in `ProxyEndpointConfig`.

The native parser may recognize textual protocol tokens, but those tokens terminate at the configuration boundary by constructing provider objects:

```text
socks5 -> protocol::socks5()
http   -> protocol::http_connect()
trojan -> protocol::trojan(secret)
```

No parser/runtime protocol enum is carried beyond that boundary.

## Ownership

### Protocol provider owns

- protocol authentication and credentials derived for runtime use;
- protocol request/response framing;
- protocol-specific stream handshake;
- protocol-specific validation that is independent of the carrier;
- generic requirements exposed as capabilities, such as `requires_tls`.

### Transport owns

- carrier establishment;
- TCP/TLS/QUIC-specific connection mechanics;
- TLS certificate and ServerName verification;
- carrier-specific buffering and readiness handling;
- full-duplex relay after the protocol handshake.

### Outbound registry owns

- endpoint identity lookup;
- composition of a protocol provider with a transport;
- validation of provider requirements against transport capabilities;
- intersection of protocol stream capability with transport stream capability;
- dispatch through `protocol.handshake_stream(...)`.

The registry must not contain protocol-name special cases such as `if protocol == Trojan`.

### Policy and DNS ownership remain unchanged

Protocol providers do not choose routes, endpoints, DNS resolvers or policy actions. A proxy-routed destination remains a canonical `Target` until the selected provider encodes it for the upstream protocol.

## Trojan consequence

Trojan declares `requires_tls = true`. The registry therefore rejects Trojan over plain TCP through a generic capability rule rather than by matching the Trojan protocol name.

The active Trojan provider stores the SHA-224 verifier used by the wire protocol rather than retaining the raw source password. Secret-source storage remains a separate future concern.

## Datagram boundary

This ADR deliberately does **not** add a generic `udp: bool` to `OutboundProtocol`.

Protocol datagram semantics and carrier datagram capability are not equivalent:

- SOCKS5 or Trojan can represent UDP through a protocol-level association carried over another transport;
- QUIC-based protocols may expose native stream and datagram carrier capabilities;
- future multiplexed transports may carry multiple logical datagram associations over one reliable session.

A separate datagram association/session boundary must be designed before proxy UDP is claimed. Until then, proxy endpoint UDP capability remains false and the runtime must not silently fall back to DIRECT.

## Extensibility

Adding a new native stream protocol should normally require:

1. a new provider implementation;
2. a provider factory at the native/compatibility boundary;
3. protocol-specific tests;
4. no central `match` over all protocol types.

The standard CI permanently rejects reintroduction of the old `ProxyProtocol` symbol in Rust source.

## Non-goals

This internal provider interface is not a stable dynamic-plugin ABI. This ADR does not define shared-library loading, third-party plugin versioning, FFI stability or an external protocol SDK.

It also does not add VLESS, Shadowsocks, Trojan UDP, Hysteria2, TUIC, QUIC, adaptive routing or new compatibility formats.

## Consequences

Positive consequences:

- protocol growth no longer expands a central runtime switch;
- protocol/transport composition remains explicit;
- transport requirements are machine-checkable capabilities;
- concrete protocol state can remain private to its provider module;
- existing SOCKS5, HTTP CONNECT and Trojan E2E paths exercise the same dispatch boundary.

Trade-offs:

- endpoint configs now contain trait objects, so equality/serialization is intentionally not a runtime concern;
- provider factories remain parser-facing construction functions rather than a dynamic registry;
- datagram protocols require a separate abstraction instead of being approximated with a boolean capability.
