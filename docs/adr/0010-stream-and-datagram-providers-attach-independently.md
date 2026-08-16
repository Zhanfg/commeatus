# ADR-0010: Stream and Datagram Providers Attach Independently

- **Status:** Accepted
- **Date:** 2026-08-16

## Context

ADR-0007 removed the central stream-protocol enum and established `OutboundProtocol` providers for stream handshakes. ADR-0008 introduced logical datagram associations, and ADR-0009 made `OutboundRegistry` the single authority for opening endpoint datagram execution paths.

After ADR-0009, every registered proxy endpoint was still structurally stream-only: the registry had no endpoint-owned object that could open a proxy `DatagramExecution`. Extending `OutboundProtocol` with UDP methods or a generic `udp: bool` would collapse stream-handshake semantics and datagram-session semantics back into one interface, even though the two may use different lifecycles and carriers.

Examples make the mismatch explicit:

- a stream protocol may establish one TCP/TLS tunnel while its datagrams use a separate framed association;
- a QUIC-family protocol may expose native streams and datagrams through one implementation but with different runtime objects;
- a future endpoint may support stream connections before its datagram implementation is available;
- compatibility importers may be able to construct only one side of the endpoint capability set.

The endpoint therefore needs independent attachments for stream and datagram execution.

## Decision

A proxy endpoint composes an existing stream protocol provider with an optional, independent datagram provider:

```rust
pub struct ProxyEndpointConfig {
    pub id: EndpointId,
    pub protocol: ProtocolRef,
    pub datagram: Option<DatagramProviderRef>,
    pub transport: TransportConfig,
}
```

`protocol` continues to describe stream-handshake behavior only. `transport` remains the stream carrier configuration used by the current stream path.

The datagram attachment uses a separate interface:

```rust
pub trait OutboundDatagramProvider: Debug + Send + Sync {
    fn open(&self) -> io::Result<Box<dyn DatagramExecution>>;
}

pub type DatagramProviderRef = Arc<dyn OutboundDatagramProvider>;
```

A datagram provider captures every provider-specific construction input it needs. `OutboundRegistry` does not pass `TransportConfig` into `open()` and does not inspect the concrete provider type.

This permits a future provider to own a TLS-stream carrier, QUIC connection state, multiplexed association factory, authentication material, or another implementation-specific dependency without turning the registry into a protocol/carrier switch.

## Capability derivation

For registered proxy endpoints, UDP capability is derived from attachment presence:

```text
datagram = None           -> supports_udp = false
datagram = Some(provider) -> supports_udp = true
```

The stream capability continues to be derived from the stream protocol and stream transport capabilities.

Presence means the endpoint has a concrete datagram execution factory. It does not guarantee that every future `open()` succeeds at runtime; connection, authentication and resource failures remain operational errors.

Existing native SOCKS5, HTTP CONNECT and Trojan endpoint construction explicitly sets `datagram: None`, so this architectural change does not claim new protocol support.

## Factory delegation

`OutboundRegistry::open_datagram(...)` remains the single endpoint-to-execution authority established by ADR-0009.

For a proxy endpoint:

1. an unknown endpoint returns `NotFound`;
2. an endpoint with `datagram: None` returns `Unsupported`;
3. an endpoint with `Some(provider)` delegates directly to `provider.open()`.

The registry must not branch on protocol names to choose a datagram implementation.

DIRECT remains a platform/runtime-owned execution path and is opened separately through `DirectDatagramAssociation`.

## Stream and datagram state are intentionally separate

This decision does not require a datagram provider to reuse the endpoint's stream `TransportConfig` object. Sharing configuration or underlying connections is an implementation decision made when a concrete provider is constructed.

For example, a future Trojan endpoint parser may derive both:

- a Trojan stream provider plus verified TLS stream transport;
- a Trojan datagram provider that owns the state required to establish its own verified TLS-backed datagram association.

A future QUIC-native endpoint may construct a datagram provider around QUIC-specific state without pretending that it is a `TransportSession` clone.

If later evidence shows that stream and datagram providers should share a pooled carrier, that pool should be an explicit shared runtime object captured by both providers rather than an implicit dependency introduced into the central registry.

## Configuration boundary

Native and compatibility parsers remain responsible for constructing endpoint attachments from external configuration.

The runtime does not carry an external-format enum describing whether a protocol "supports UDP". The parser either constructs a real `DatagramProviderRef` or leaves the attachment absent.

This preserves the boundary rule that external configuration schemas do not become the runtime object model.

## Validation

The refactor is validated in both directions:

- all existing endpoint initializers explicitly use `datagram: None` and retain their previous stream-only behavior;
- a registered proxy endpoint with no provider remains `supports_udp = false` and `open_datagram()` returns `Unsupported`;
- a fake attached provider makes `supports_udp = true`;
- opening that endpoint invokes the fake provider exactly once and returns its `DatagramExecution`;
- stable fmt/check/Clippy/all workspace tests and Rust 1.85 all-targets pass before the migration/test commits are accepted.

## Non-goals

This ADR does not:

- implement Trojan UDP, VLESS UDP or upstream SOCKS5 UDP;
- add Hysteria2, TUIC or another QUIC protocol;
- define datagram wire framing;
- define a stable external plugin ABI;
- change SOCKS5 inbound framing, routing precedence or DNS policy;
- make any current production proxy endpoint UDP-capable;
- require stream and datagram providers to share a connection.

## Consequences

Positive consequences:

- stream protocol growth and datagram protocol growth remain independent;
- UDP capability reflects an executable provider rather than a protocol-name table;
- the outbound registry remains protocol-agnostic;
- SOCKS5 and future inbound protocols continue to dispatch through the same endpoint factory;
- the first real proxy datagram implementation can be added without another SOCKS5 or registry concrete-protocol branch;
- carrier sharing, when useful, can be introduced explicitly rather than as hidden global state.

Trade-offs:

- `ProxyEndpointConfig` gains another provider object and all constructors must state attachment presence explicitly;
- a protocol supporting both streams and datagrams may have two provider objects;
- configuration/compiler code must construct both attachments consistently when real proxy UDP support is introduced;
- a provider being present advertises structural UDP capability even though individual runtime opens may still fail operationally.
