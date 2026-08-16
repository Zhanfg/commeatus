# ADR-0014: Secure DNS Fallback Must Be Explicit

- **Status:** Accepted
- **Date:** 2026-08-16

## Context

ADR-0013 introduced typed resolver answers and the first verified DNS-over-TLS provider, but deliberately left daemon resolver selection undefined.

Secure DNS configuration has a dangerous compatibility trap: a daemon may accept a secure resolver declaration yet silently add the operating-system resolver as a fallback. That behavior appears resilient, but it can leak names to a path the user explicitly tried to avoid and makes policy impossible to audit from the configuration file alone.

The opposite compatibility requirement also matters. Existing native configurations contain no resolver directives and historically use `SystemResolver`. Requiring every old configuration to grow a new line would be unnecessary churn.

DoT bootstrap creates a second ambiguity. If the transport endpoint itself is a hostname, resolving that hostname may require the very resolver being bootstrapped, or may implicitly invoke system DNS before secure DNS exists.

## Decision

Native resolver declarations form one ordered fallback chain.

Supported forms are:

```text
resolver system
resolver dot <ip:port> <server-name>
```

The rules are:

1. **No `resolver` directives means legacy compatibility mode.** The effective chain is exactly one `SystemResolver`.
2. **Once any `resolver` directive is present, the daemon adds nothing implicitly.** The effective chain is exactly the declarations, in source order.
3. **A DoT-only chain is secure-only.** If it fails, resolution fails locally.
4. **System fallback exists only when the configuration explicitly contains `resolver system`.** Its position determines when fallback occurs.
5. **DoT bootstrap is a literal IP socket address.** TLS identity is supplied separately as `server-name` and is verified by the existing WebPKI path.
6. **Resolver declarations are bounded.** A configuration may contain at most eight resolvers.
7. **Duplicate effective resolver declarations are rejected before runtime commit.**

Examples:

Secure-only:

```text
resolver dot 1.1.1.1:853 cloudflare-dns.com
```

Explicit secure-first fallback:

```text
resolver dot 1.1.1.1:853 cloudflare-dns.com
resolver system
```

System-first with secure fallback is syntactically possible because source order is authoritative, although it is not a secure-only configuration:

```text
resolver system
resolver dot 1.1.1.1:853 cloudflare-dns.com
```

No hidden preference or automatic reordering is applied.

## Configuration compilation

Resolver configuration is compiled as part of the existing candidate-then-swap transaction.

Compilation validates:

- directive shape;
- resolver count;
- literal DoT `SocketAddr` and non-zero port;
- TLS server-name validity through `DotResolver::webpki` / `TlsTransport` construction;
- duplicate effective resolver declarations.

Compilation does **not** connect to the resolver. Network reachability is runtime state and must not turn configuration parsing into an availability probe.

If a candidate is invalid, the active `CompiledConfig` remains the Last Known Good snapshot.

`CompiledConfig` records `DnsResolverSummary` entries in effective order so callers can inspect whether the active configuration contains system fallback instead of inferring it from runtime behavior.

## Failure semantics

`DnsEngine` already tries its configured resolver list in order. This ADR gives that existing ordering security meaning.

A resolver failure may fall through only to a resolver that is actually present later in the compiled chain.

Therefore:

```text
DoT only
  DoT failure
      ↓
 local DNS failure
```

while:

```text
DoT
System
  DoT failure
      ↓
 explicit SystemResolver attempt
```

There is no implicit `DoT -> System` edge.

This rule is stronger than convenience fallback. Preserving user-declared authority is more important than hiding a secure-resolver outage.

## Bootstrap ownership

The DoT connection address and TLS identity remain separate:

```text
resolver dot 1.1.1.1:853 cloudflare-dns.com
             └ bootstrap IP       └ verified TLS identity
```

The native parser does not resolve DoT bootstrap hostnames. This prevents a hidden system-DNS dependency and avoids recursive bootstrap semantics in the first secure-DNS configuration slice.

A future explicit bootstrap-resolver feature may add hostname bootstrap, but it must model the dependency directly rather than invoking an ambient resolver.

## Compatibility

Configurations written before this ADR remain valid:

```text
version 1
listen socks5 127.0.0.1:1080
default direct
```

Their effective DNS chain remains `[System]`.

The compatibility behavior applies only when **zero** resolver directives exist. Adding the first resolver declaration switches the configuration into explicit-chain semantics.

## Verification

Tests require:

- no resolver directive produces exactly one `System` summary;
- one DoT declaration produces exactly one DoT summary and no implicit system fallback;
- `DoT -> System` preserves source order;
- duplicate system resolver declarations are rejected;
- duplicate DoT resolver declarations are rejected;
- hostname DoT bootstrap addresses are rejected;
- invalid TLS server names are rejected;
- resolver count is capped at eight;
- an invalid secure-resolver reload leaves the Last Known Good snapshot active;
- existing workspace tests continue to pass;
- Rust 1.85 remains supported.

The normal repository CI must additionally pass Android arm64, eBPF and release-package gates on the exact PR head before merge.

## Non-goals

This ADR does not add:

- DoH or DoQ;
- Fake-IP;
- hostname bootstrap or bootstrap resolver graphs;
- opportunistic automatic system fallback;
- resolver health ranking or adaptive selection;
- per-domain resolver routing;
- resolver groups;
- concurrent DNS transaction pipelining;
- live resolver reachability validation during config compilation.

## Consequences

Positive consequences:

- secure-only intent is representable and cannot be silently weakened;
- fallback behavior is readable directly from the configuration source;
- old configurations remain compatible without new directives;
- secure resolver bootstrap does not depend on ambient DNS;
- resolver ordering remains one authoritative state instead of a parser order plus hidden runtime additions;
- invalid resolver configuration remains transactional and cannot replace Last Known Good state.

Trade-offs:

- a DoT-only outage is visible to the user as DNS failure rather than being masked by system DNS;
- users who want availability fallback must write `resolver system` explicitly;
- literal bootstrap IPs are less convenient than hostname endpoints until bootstrap dependencies are modeled explicitly.
