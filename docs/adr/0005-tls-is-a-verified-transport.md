# ADR-0005: TLS Is a Verified Transport

- Status: Accepted
- Date: 2026-08-16

## Context

Multiple proxy protocols can use TLS as their carrier security layer. If each protocol owns TLS configuration, certificate verification, SNI, buffering, timeouts, and relay mechanics, the runtime recreates a `Protocol × Transport` matrix and makes security behavior depend on protocol-specific code paths.

The transport-session boundary in ADR-0004 allows TLS to remain below protocol handshakes.

## Decision

TLS is implemented as a transport/security capability, not as a property of a proxy protocol.

A TLS endpoint therefore composes:

```text
EndpointId
   ↓
ProxyProtocol
   ↓
TlsTransport
   ├─ literal upstream SocketAddr
   ├─ independent TLS ServerName / SNI
   ├─ certificate verification policy
   ├─ handshake/connect timeouts
   └─ carrier-specific relay
```

The core still sees only `Endpoint::Proxy(EndpointId)`.

### Verification is mandatory by default

Native `TlsTransport::webpki` uses the embedded WebPKI server-root set and validates the configured TLS server name. No `insecure`, `skip-verify`, or equivalent native configuration switch is provided in this release line.

A test-only/custom constructor can receive an explicit `ClientConfig` so local deterministic tests and future explicit trust-policy implementations can install a specific trust store without weakening the default path.

### Connect address and certificate identity are distinct

The transport stores the upstream `SocketAddr` separately from `ServerName`.

This prevents three concepts from being collapsed into one string:

- where the TCP connection is made;
- which TLS identity is verified;
- which SNI value is sent.

The first native TLS configuration continues to require a literal upstream socket address. Proxy-bootstrap DNS is therefore not introduced implicitly by the TLS feature.

### TLS owns its full-duplex execution

The TLS connection state remains owned by one `TlsTransportSession`. After the proxy-protocol handshake completes, the session switches the sockets to nonblocking mode and drives rustls through readiness notifications.

The relay does not use a fixed periodic timer. Read/write interest is registered only while useful work exists, and buffered plaintext is bounded. TLS closure remains strict: an unclean network EOF is not silently reclassified as a valid TLS `close_notify`.

## Consequences

- Existing SOCKS5 and HTTP CONNECT outbound protocols can run over either TCP or TLS without TLS-specific branches in their protocol handshake logic.
- Future Trojan/VLESS-like protocols can reuse the same verified transport instead of reimplementing certificate/SNI policy.
- Whether an endpoint has encrypted transport is derived from transport capabilities, not inferred from a protocol name.
- Native TLS currently trusts the embedded WebPKI roots, not Android/Linux user-added enterprise roots. Supporting platform/user trust stores requires an explicit future trust-policy design.
- Client certificates, ALPN policy, certificate pinning, ECH, and custom trust sources are separate future capabilities rather than hidden flags in the first TLS slice.

## Rejected alternatives

### Put rustls directly inside each proxy protocol

Rejected because it duplicates a shared security layer and couples protocol code to certificate, SNI, timeout, and relay decisions.

### Add an insecure certificate-verification toggle immediately

Rejected because the project prioritizes security and stability over compatibility shortcuts. A future exceptional trust mode, if ever accepted, must be an explicit policy decision rather than a default-adjacent boolean.

### Treat the upstream hostname as both network address and TLS identity

Rejected because it hides bootstrap DNS semantics and prevents independent routing to a literal address while validating a certificate identity.
