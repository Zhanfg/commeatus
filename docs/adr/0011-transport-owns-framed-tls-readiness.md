# ADR-0011: Transport Owns Framed TLS Readiness

- **Status:** Accepted
- **Date:** 2026-08-16

## Context

ADR-0004 established that transport owns carrier relay mechanics. ADR-0005 established that TLS is a verified transport rather than a protocol decoration. The first TLS implementation provided two useful phases for stream protocols: blocking verified handshake through `TransportSession`, followed by a transport-owned readiness relay in `relay_to_client()`.

Proxy datagram protocols such as Trojan UDP need a third shape. Their protocol layer must retain a framed plaintext session after TLS handshake and exchange discrete protocol records over that TLS stream. Reusing `relay_to_client()` is impossible because it assumes opaque bidirectional byte relay. Moving rustls or the raw TCP socket into the daemon/protocol layer would violate the existing TLS ownership boundary.

The transport therefore needs a readiness-driven framed TLS carrier that still keeps TLS state and encrypted socket mechanics inside `commeatus-transport`.

## Decision

`TlsTransport` gains a shared verified handshake implementation and a framed-session constructor:

```rust
pub fn connect_framed(&self) -> io::Result<TlsFramedSession>;
```

Both ordinary `TransportSession` creation and framed-session creation use the same `connect_established()` path. This preserves identical certificate verification, ServerName/SNI validation, connect timeout, handshake timeout, rustls configuration and buffer limits.

`TlsFramedSession` owns:

- `rustls::ClientConnection`;
- the underlying nonblocking `mio::net::TcpStream`;
- dynamic poll registration state;
- encrypted read/write service;
- remote TCP EOF state.

The higher-level protocol never receives the raw TCP socket or the rustls connection.

## Plaintext API

The framed carrier exposes only the operations required by a protocol framing layer:

```rust
write_plaintext(&mut self, bytes: &[u8]) -> io::Result<usize>;
read_plaintext(&mut self, bytes: &mut [u8]) -> io::Result<usize>;
service_io(&mut self) -> io::Result<()>;
register_readiness(&mut self, registry: &mio::Registry, token: Token)
    -> io::Result<()>;
refresh_readiness(&mut self, registry: &mio::Registry, token: Token)
    -> io::Result<()>;
```

`write_plaintext` writes into rustls plaintext buffering. `read_plaintext` consumes decrypted bytes produced by rustls. `service_io` drives the encrypted socket in both directions until nonblocking I/O returns `WouldBlock`.

A higher-level protocol may keep its own bounded protocol-frame queues and parsers, but it must not implement TLS record I/O itself.

## Dynamic readiness

Writable TCP sockets are normally continuously ready. Registering permanent `WRITABLE` interest would therefore wake the event loop continuously and violate the project's idle-power requirements.

`TlsFramedSession` derives poll interest from rustls state:

```text
READABLE  <- !remote_eof && connection.wants_read()
WRITABLE  <- connection.wants_write()
```

`refresh_readiness()` registers, re-registers or de-registers the encrypted socket as these states change.

After queued plaintext has been encrypted and ciphertext drains to the socket, `WRITABLE` interest is removed. The session remains read-waiting without a periodic timer or a permanently writable fd.

A read may generate TLS control output, so `service_io()` attempts encrypted writes both before and after encrypted reads.

## Registration ownership

The caller owns the poll registry and token namespace. The transport owns how its encrypted socket maps those tokens to OS readiness.

A `TlsFramedSession` may be registered once. Re-registering through the initial registration API is rejected; subsequent interest changes use `refresh_readiness()`.

This is an internal crate boundary, not a stable external event-loop ABI.

## Verification and identity

`connect_framed()` does not provide an insecure verification mode. It uses the same `TlsTransport` certificate roots/client config and `ServerName` as stream connections.

A datagram provider must therefore construct a normal verified `TlsTransport`; it cannot bypass hostname verification because it uses framed mode.

## Buffering responsibility

The existing bounded rustls buffer limit remains in effect. `TlsFramedSession` intentionally does not add an unbounded plaintext queue.

When a protocol has framed messages larger than currently available rustls plaintext capacity or needs to absorb bursty sends, that protocol execution layer must use its own explicitly bounded queue and feed it incrementally through `write_plaintext()` as readiness allows.

This keeps protocol framing limits separate from TLS record buffering and prevents one generic transport queue from becoming an implicit unbounded store.

## Validation

The framed carrier is tested with a local trusted test CA and matching ServerName. The test verifies:

- verified TLS handshake succeeds through `connect_framed()`;
- plaintext queued by the caller is delivered to the TLS server;
- the transport enables writable readiness while ciphertext needs flushing;
- after the server has received the plaintext but intentionally sends no response, a timed poll remains quiet, proving writable interest was removed instead of spinning;
- later server plaintext is decrypted and returned through `read_plaintext()`;
- existing TLS stream handshake, hostname-verification and full-duplex relay tests continue to pass;
- stable fmt/check/Clippy/all workspace tests and Rust 1.85 all-targets pass before the carrier commit is accepted.

## Non-goals

This ADR does not:

- implement Trojan UDP framing;
- define a generic multiplexed stream abstraction;
- expose rustls types to daemon protocol code;
- add background TLS worker threads;
- add a permanent writable poll interest;
- change ordinary TCP/TLS `TransportSession` semantics;
- define a stable external transport plugin ABI;
- introduce global TLS carrier pooling.

## Consequences

Positive consequences:

- TLS ownership remains entirely in the transport crate;
- framed proxy protocols can be readiness-driven without copying rustls/socket logic;
- writable readiness is transient, preserving low idle CPU/wakeups;
- stream and framed TLS connections share one verified handshake path;
- future Trojan UDP can compose protocol framing above TLS without weakening certificate/SNI verification.

Trade-offs:

- `commeatus-transport` now exposes an internal `mio`-aware framed-session API in addition to opaque `TransportSession`;
- protocol executors must manage their own bounded frame queues and partial plaintext writes;
- carrier sharing/pooling remains future work and must be explicit if introduced.
