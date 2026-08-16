# ADR-0006: Trojan Is a Protocol over Verified TLS

- Status: Accepted
- Date: 2026-08-16

## Context

Trojan is the first encrypted native proxy protocol added after the transport-session and verified-TLS boundaries.

The protocol specification requires a real TLS handshake before Trojan request framing. The request then carries a SHA-224 password verifier encoded as 56 lowercase hexadecimal ASCII bytes, CRLF, a command/address/port request, another CRLF, and application payload.

If Trojan owns TLS itself, the project would immediately undo ADR-0004 and ADR-0005 by putting certificate/SNI/relay behavior back into protocol code.

## Decision

Trojan is implemented strictly as a proxy protocol **over** `TlsTransport`.

```text
EndpointId
    ↓
OutboundRegistry
    ↓
TrojanProtocol
    ├─ SHA-224 password verifier framing
    ├─ CONNECT command
    └─ SOCKS5-compatible destination address framing
    ↓
TlsTransport
    ├─ certificate / ServerName verification
    ├─ TLS handshake
    └─ full-duplex relay
```

The core continues to see only `Endpoint::Proxy(EndpointId)`.

### TLS is mandatory

A Trojan endpoint constructed with a plain `TcpTransport` is rejected by `OutboundRegistry::new`.

The native configuration compiler accepts Trojan only in this form:

```text
endpoint <id> trojan tls <ip:port> <server-name> <password>
```

The constraint therefore exists at both the native config boundary and the execution registry boundary.

### Runtime password representation

The native parser receives the plaintext password from the configuration source, computes `hex(SHA224(password))` while compiling the candidate, and stores only the 56-byte verifier in `TrojanProtocol`.

The active runtime does not retain the plaintext password in the protocol object and does not emit it in logs or error messages.

This is **not** a claim that plaintext secrets are solved: the source configuration file still contains the password, and the current alpha parser tokenizes it as one whitespace-free value. A future secret-source design must support environment/file/OS-keystore style references without turning secret retrieval into protocol behavior.

### TCP CONNECT only in the first slice

The official protocol also defines UDP ASSOCIATE, but the first native implementation advertises only TCP stream capability and emits only `CONNECT` (`0x01`).

UDP support must arrive through the separate capability-safe datagram execution boundary rather than being hidden inside the stream connector.

### No protocol-owned destination DNS

Trojan uses the canonical target already selected by the flow/policy layer. A domain target is encoded directly into the Trojan address field and remains opaque to the local DIRECT DNS engine.

### First-packet payload optimization is deferred

The protocol wire format permits payload to follow the request immediately. The first implementation sends the authenticated CONNECT request first and lets the established `TransportSession` relay application payload afterward.

Combining already-buffered inbound data into the first Trojan write is a future latency optimization, not part of the protocol ownership model.

## Consequences

- The first encrypted proxy protocol validates that `Protocol × Transport` composition is real data-plane architecture rather than only type structure.
- Trojan authentication/framing can be tested independently from TLS trust policy.
- Certificate/SNI policy remains identical to SOCKS5-over-TLS and HTTP-CONNECT-over-TLS.
- The runtime has no plaintext Trojan password after candidate compilation, but source-secret management remains explicitly unsolved.
- Trojan UDP cannot accidentally be claimed before a datagram executor exists.

## Rejected alternatives

### Implement Trojan as a special TLS endpoint

Rejected because it conflates proxy protocol semantics with transport security and would make future protocols duplicate TLS behavior.

### Permit Trojan over plain TCP for compatibility/testing

Rejected because it violates the protocol's security model and would create an invalid native configuration state.

### Add UDP ASSOCIATE in the same slice

Rejected because the existing outbound execution contract is stream-oriented. UDP requires its own capability-safe transport/session abstraction and must not silently piggyback on the TCP implementation.
