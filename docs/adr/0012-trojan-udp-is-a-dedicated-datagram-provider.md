# ADR-0012: Trojan UDP Is a Dedicated Datagram Provider

- **Status:** Accepted
- **Date:** 2026-08-16

## Context

ADR-0006 defined Trojan stream CONNECT as a protocol over verified TLS. ADR-0007 moved stream handshakes behind protocol providers. ADR-0010 separated stream and datagram provider attachment so an endpoint can advertise UDP only when it owns a real datagram implementation. ADR-0011 then added a readiness-driven framed TLS carrier without moving rustls or the encrypted TCP socket into daemon protocol code.

Trojan UDP is the first real proxy datagram provider to exercise all of those boundaries together. It must preserve Trojan wire semantics, domain identity, bounded memory and low-idle-wakeup behavior without teaching SOCKS5 or `OutboundRegistry` Trojan-specific lifecycle rules.

## Decision

A native Trojan TLS endpoint attaches two independent providers that share credential material but not execution interfaces:

```text
Trojan endpoint
├─ stream provider   -> CONNECT over TransportSession
└─ datagram provider -> UDP ASSOCIATE over TlsFramedSession
```

The raw password is converted once at the native configuration boundary into `TrojanVerifier`. The stream provider receives a clone of that verifier and the datagram provider receives the same verifier value with its own TLS session construction state.

`OutboundRegistry` continues to know only that `ProxyEndpointConfig.datagram` is present. It does not branch on the Trojan protocol name and does not construct Trojan UDP sessions itself.

## Wire ownership

`trojan.rs` owns shared Trojan wire primitives:

- SHA-224 lowercase-hex verifier creation;
- address encoding and parsing;
- stream CONNECT request encoding;
- UDP ASSOCIATE preface encoding;
- UDP datagram frame encoding and incremental parsing.

`TrojanDatagramProvider` owns UDP session lifecycle and uses those primitives. SOCKS5 never emits or parses Trojan bytes.

The UDP ASSOCIATE preface is normalized to:

```text
<56-byte verifier> CRLF
CMD = 0x03
ATYP = IPv4
ADDR = 0.0.0.0
PORT = 0
CRLF
```

The initial wildcard target does not select a remote destination. Each following Trojan UDP frame carries its own `ATYP + ADDR + PORT`, so one logical association can relay multiple destinations without freezing the first target into provider construction.

## Domain identity

A domain carried by an inbound UDP packet remains a domain in the Trojan UDP frame. The datagram provider does not resolve it through the local `DnsEngine` before sending it upstream.

This preserves proxy-side DNS semantics and avoids leaking a proxy-selected destination to local DNS merely because the inbound happened to be SOCKS5.

DIRECT datagram execution continues to own its own DNS resolution separately.

## Incremental framing

Trojan UDP frames are parsed from a persistent decrypted-byte buffer. The parser distinguishes:

- an incomplete but structurally valid prefix, which remains buffered;
- one complete frame, which is consumed while preserving any following bytes;
- structurally invalid input, which fails the local datagram execution.

The 16-bit payload length is interpreted as big-endian. A zero-length UDP payload is valid. Multiple complete frames may arrive in one TLS plaintext burst, and one frame may be split across multiple TLS records or reads.

## Readiness and transport ownership

`TrojanDatagramExecution` is a `DatagramExecution` with one readiness source. It delegates encrypted socket/TLS service to `TlsFramedSession` and never receives the raw TCP socket or rustls connection.

During registration the execution stores a cloned `mio::Registry` handle and its assigned token. This is used only to ask `TlsFramedSession` to refresh interest after protocol plaintext is queued or TLS I/O changes state.

A UDP send may create TLS ciphertext and therefore require `WRITABLE` readiness before any response is readable. The SOCKS5 datagram reactor consequently forwards **any readiness event belonging to an outbound route token** to that route execution. It does not special-case Trojan or infer carrier type.

DIRECT UDP routes still register only `READABLE`, so their event behavior is unchanged.

No Trojan UDP background worker, periodic poll timer or permanent writable interest is introduced.

## Bounded state

Trojan UDP execution uses explicit hard bounds:

- at most 64 pending protocol frames;
- at most 512 KiB of pending protocol bytes;
- at most 128 KiB of decrypted receive buffering;
- one readiness source per Trojan UDP execution.

The existing per-SOCKS5-association `DatagramRouteSet` bound also remains in force, so a client cannot create an unbounded number of endpoint sessions through one UDP ASSOCIATE.

Limit violations and malformed frames fail the affected datagram path; they do not trigger DIRECT fallback and do not convert a local protocol failure into a process panic.

## Verification

The native Trojan UDP path is verified at three levels.

Unit tests verify:

- the verifier matches a known SHA-224 hex vector and Debug output is redacted;
- the UDP ASSOCIATE preface uses the normalized wildcard target;
- IPv4/domain frame encoding and parsing;
- incomplete-frame retention;
- multiple-frame parsing;
- zero-length payload acceptance;
- malformed CRLF rejection.

Integration gates verify:

- native Trojan config attaches a datagram provider and advertises UDP capability;
- existing TCP Trojan behavior remains valid;
- stable fmt/check/Clippy and the full workspace test suite pass;
- Rust 1.85 all-targets passes.

The end-to-end proof drives the complete path:

```text
SOCKS5 UDP inbound
  -> policy-selected proxy endpoint
  -> DatagramRouteSet
  -> OutboundRegistry datagram factory
  -> TrojanDatagramProvider
  -> verified TlsFramedSession
  -> mock Trojan TLS server
```

It additionally proves:

- an `.invalid` destination domain reaches the mock server unchanged, so local DNS did not resolve it;
- the server observes `CMD=0x03` and the `0.0.0.0:0` preface target;
- a response frame split across separate TLS writes is reconstructed;
- a second complete frame coalesced behind the first is preserved and emitted separately;
- the coalesced second frame may contain a zero-length UDP payload;
- the full workspace still passes after this path is exercised.

## Non-goals

This ADR does not:

- add VLESS, VMess, Shadowsocks, TUIC or Hysteria datagram providers;
- introduce a generic reliable-stream UDP framing protocol;
- pool Trojan TLS datagram sessions across endpoint routes;
- add UDP fragmentation above Trojan;
- resolve proxied domains locally;
- expose Trojan wire types through the native external API;
- move TLS verification or encrypted socket readiness out of the transport crate;
- weaken the rule that unsupported proxy UDP must never fall back to DIRECT.

## Consequences

Positive consequences:

- Trojan becomes the first native proxy endpoint with verified TCP and UDP capability while keeping stream/datagram ownership separate;
- SOCKS5 remains protocol-agnostic and can support later datagram providers without protocol-name branches;
- domain identity is preserved to the upstream proxy;
- partial/coalesced TLS plaintext is handled without assuming TLS record boundaries equal UDP frame boundaries;
- idle behavior remains event-driven with transient writable interest;
- memory growth and route growth remain explicitly bounded.

Trade-offs:

- each currently opened Trojan datagram route owns a dedicated TLS session rather than sharing a multiplexed carrier;
- the datagram execution must retain a registry handle solely to refresh transport readiness after sends;
- future transport/session pooling must preserve the existing provider, ownership and failure-isolation boundaries rather than bypass them.
