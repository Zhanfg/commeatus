# ADR-0013: Resolvers Own DNS Answer Metadata

- **Status:** Accepted
- **Date:** 2026-08-16

## Context

The original DNS engine treated every resolver result as a bare `Vec<IpAddr>` and applied one fixed cache TTL inside `DnsEngine`.

That shape was sufficient while `SystemResolver` was the only network resolver, because the system API does not expose authoritative DNS TTLs. It is not sufficient for secure DNS protocols. A DoT/DoH/DoQ resolver parses DNS resource records itself and therefore owns information that materially affects correctness and cache lifetime.

Discarding that metadata at the `Resolver` boundary would permanently force secure resolvers into the same synthetic fixed-TTL behavior and would make later negative caching, DNSSEC/validation metadata, resolver provenance or record-family policy harder to add without another interface break.

The first secure resolver also needs an encrypted transport without creating a second TLS stack inside the DNS crate.

## Decision

`Resolver` returns a typed logical answer:

```text
Resolver
   ↓
DnsAnswer
├─ addresses: Vec<IpAddr>
└─ ttl: Option<Duration>
   ↓
DnsEngine
```

`DnsEngine::resolve(&str) -> Result<Vec<IpAddr>, DnsError>` remains unchanged for daemon callers. Typed answer metadata terminates inside the DNS failure domain rather than leaking into proxy protocol handlers.

`DnsAnswer::ttl()` semantics are:

- `Some(ttl)` — the resolver supplied an authoritative lifetime for the returned address set;
- `Some(Duration::ZERO)` — the result is usable for the current lookup but must not be inserted into the cache;
- `None` — the resolver cannot supply a protocol TTL, so the engine uses its configured cache TTL.

The configured engine TTL remains a hard maximum. Effective positive cache lifetime is:

```text
resolver_ttl.unwrap_or(configured_max_ttl).min(configured_max_ttl)
```

This keeps operator policy authoritative while preserving shorter DNS lifetimes.

## Wire ownership

The DNS crate owns a bounded A/AAAA wire codec rather than delegating raw DNS semantics to protocol callers.

The codec validates at least:

- message size bounds;
- transaction ID;
- response bit and truncation bit;
- response code;
- exactly one matching question;
- question type and class;
- bounded answer count;
- DNS label lengths and total decoded-name length;
- compression-pointer bounds, backward direction and hop count;
- CNAME alias-chain bounds;
- A/AAAA RDLENGTH;
- CNAME-target framing;
- query/alias ownership before accepting address records.

The parser distinguishes malformed responses (`InvalidResponse`) from valid no-record outcomes and resolver/transport failures.

Unrelated address records are not accepted merely because they appear in the answer section.

For an address reached through CNAME records, the effective answer TTL is the minimum TTL across the accepted alias chain and selected address records.

## DNS-over-TLS provider

`DotResolver` is the first resolver that consumes the typed-answer boundary.

It reuses the existing verified `TlsTransport` rather than owning rustls, certificate roots, SNI verification or the encrypted socket itself:

```text
DnsEngine
   ↓
DotResolver
   ↓
TransportConnector / TransportSession
   ↓
TlsTransport
   ↓
verified TLS socket
```

DoT messages use the standard two-byte length prefix around one DNS message.

The resolver queries A and AAAA sequentially, combines unique addresses and uses the minimum TTL across successful families.

## Connection lifecycle

A `DotResolver` owns one persistent transport session and serializes exchanges through that session.

This first implementation intentionally does **not** pipeline multiple outstanding DNS queries. The session lock remains held while one request/response exchange completes so response ownership is unambiguous and no transaction-demultiplexing state is required yet.

The same TLS stream is reused for the A and AAAA queries of one resolution and for subsequent resolutions while healthy.

If an I/O operation detects a dead session, only the DoT session is discarded. The resolver may establish one replacement session and retry the same framed request once. Failure remains local to the resolver path.

A structurally invalid DNS response also invalidates the persistent session, because continuing to consume a stream after framing/identity corruption could associate later bytes with the wrong query.

There is no DoT background worker, periodic health timer or polling loop.

## Default and fallback policy

This ADR does not change the daemon's default resolver selection.

`DnsEngine::system(...)` continues to install `SystemResolver`. `DotResolver` is an available provider primitive, not an implicit global replacement for system DNS.

A later configuration decision will define:

- native resolver declarations;
- resolver ordering and fallback policy;
- bootstrap/address semantics;
- whether a secure resolver failure may fall through to another configured resolver;
- how user hard policy distinguishes secure-only from opportunistic fallback.

Those decisions must not be inferred from the existence of `DotResolver` itself.

## Bounded state

The existing DNS cache capacity and maximum TTL bounds remain in force.

The DNS wire layer additionally bounds:

- DNS message size to the protocol's 16-bit message-length space;
- accepted answer records;
- compression-pointer hops;
- CNAME/alias growth;
- decoded hostname length;
- final address count through the existing `MAX_RESOLVED_ADDRESSES` limit.

No untrusted DNS length field is used for an unbounded allocation outside those limits.

## Verification

Unit tests verify:

- query transaction ID/name/family encoding;
- compressed A responses;
- AAAA responses;
- CNAME-chain TTL reduction;
- unrelated answer rejection;
- zero TTL preservation;
- NXDOMAIN classification;
- transaction-ID mismatch rejection;
- compression-pointer loop rejection;
- zero-TTL results bypass the engine cache;
- scripted DoT A+AAAA requests reuse one transport session and combine the minimum TTL.

A real local TLS end-to-end test additionally proves:

- `DotResolver` communicates through `TlsTransport` with a trusted test root and matching server name;
- A and AAAA queries are length-prefixed and reuse one verified TLS connection;
- after the server closes that persistent connection, the next resolution detects the dead stream and reconnects locally;
- two complete resolutions result in two accepted TLS connections and four DNS queries rather than one connection per family.

The feature is also required to pass the full workspace suite and Rust 1.85 all-target checks before merge.

## Non-goals

This ADR does not add:

- daemon/native configuration syntax for selecting DoT;
- DoH, HTTP/2 or HTTP/3 DNS transport;
- DoQ;
- DNS query pipelining or concurrent transaction demultiplexing;
- negative-cache SOA TTL handling;
- EDNS(0), ECS, DNSSEC validation or EDE processing;
- Fake-IP allocation;
- bootstrap-host resolver configuration;
- automatic fallback from secure DNS to system DNS;
- per-domain resolver routing.

## Consequences

Positive consequences:

- authoritative TTL information can reach cache policy without changing daemon callers;
- zero-TTL records are usable without being incorrectly cached;
- future secure resolvers share one typed answer contract;
- the first DoT provider reuses audited/verified TLS ownership rather than duplicating TLS code;
- persistent DoT transport avoids one TLS handshake per A/AAAA query;
- dead or malformed DoT sessions fail locally and can be replaced without restarting the DNS engine;
- future resolver metadata can extend `DnsAnswer` rather than changing every proxy caller.

Trade-offs:

- the first DoT implementation serializes requests and therefore does not yet exploit RFC 7858 pipelining;
- a persistent session is protected by a mutex across network I/O;
- A and AAAA are separate DNS transactions rather than one multi-question query;
- secure resolver selection remains unavailable to native daemon configuration until the next slice defines explicit policy and bootstrap semantics.
