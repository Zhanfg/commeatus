from pathlib import Path

path = Path("README.md")
text = path.read_text()


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one README match, found {count}: {old!r}")
    text = text.replace(old, new, 1)


replace_once(
    "> **Status:** `0.5.0-alpha.1`. This is an experimental alpha, not a production-ready replacement for mihomo or sing-box. It has real TCP/UDP inbounds, native policy, compiled domain filtering, an isolated DNS engine, named proxy stream outbounds, native Trojan CONNECT and UDP ASSOCIATE over verified rustls TLS, Android arm64 builds, and a CI-verified eBPF prototype boundary.",
    "> **Status:** current `main` is **v0.6 development**; the latest public prerelease is `v0.5.0-alpha.1`. The tree remains experimental, not a production-ready replacement for mihomo or sing-box. Current main adds explicit verified DNS-over-TLS resolver chains on top of the v0.5 TCP/UDP, policy, Trojan, Android arm64, and eBPF prototype baseline.",
)
replace_once("## What works in 0.5.0-alpha.1", "## What works on current main")

old_dns = '''### DNS failure domain

Direct domain resolution lives in `commeatus-dns`, not in SOCKS5 or HTTP handlers:

```text
Domain
  ↓
Hosts override
  ↓ miss
Bounded cache
  ↓ miss
Ordered Resolver chain
  ↓
System Resolver   (current network resolver)
```

The DNS engine provides:

- typed errors and statistics
- DNS hosts overrides
- ordered resolver fallback abstraction
- bounded 4,096-entry cache
- 60-second default synthetic cache TTL
- hard maximum cache TTL of 300 seconds
- at most 16 returned addresses per resolution
- resolver failure isolation

System DNS is still the only network resolver in `0.5.0-alpha.1`. DoH, DoT, DoQ and Fake-IP are future implementations behind the resolver boundary.

DNS hosts assets are separate from blocklists:

```text
hosts ./dns/hosts.txt       # name → IP resolution override
blocklist ./rules/ads.txt   # policy rejection source
```
'''
new_dns = '''### DNS failure domain and explicit secure resolver chains

Direct domain resolution lives in `commeatus-dns`, not in SOCKS5, HTTP, Trojan, or policy handlers:

```text
Domain
  ↓
Hosts override
  ↓ miss
Bounded cache
  ↓ miss
Ordered Resolver chain
  ├─ SystemResolver
  └─ DotResolver → verified TlsTransport
```

Resolvers return a typed `DnsAnswer` internally so protocol-owned TTL metadata can reach cache policy without changing daemon callers. The public daemon-facing engine API still returns bounded IP address lists.

The DNS engine currently provides:

- typed errors, answer metadata, and statistics
- DNS hosts overrides
- bounded 4,096-entry cache
- configured cache TTL as a hard maximum (300-second hard cap)
- resolver-provided positive TTL handling
- authoritative TTL=0 results that are usable but not cached
- at most 16 returned addresses per resolution
- ordered resolver fallback
- bounded A/AAAA DNS wire parsing with transaction/question validation
- bounded compression-pointer and CNAME-chain handling
- verified persistent DNS-over-TLS using the existing rustls transport boundary
- one local reconnect/retry after a dead DoT session
- resolver failure isolation

Native resolver declarations are themselves the fallback chain:

```text
# Secure-only: no hidden system fallback exists.
resolver dot 1.1.1.1:853 cloudflare-dns.com

# Optional explicit fallback, only if the user writes it:
resolver system
```

Rules:

- with **no** `resolver` directives, legacy configurations keep exactly one system resolver;
- once any resolver directive exists, the daemon adds **nothing** implicitly;
- a DoT-only chain is therefore secure-only;
- `resolver system` enables system fallback only at its declared position;
- DoT bootstrap must be a literal `IP:port`; the TLS server name is separate and verified through WebPKI;
- at most 8 resolvers may be configured;
- duplicate effective resolver declarations are rejected before candidate commit.

This means a secure-resolver outage is visible unless the configuration explicitly authorizes another resolver. Availability does not silently override DNS privacy policy.

DNS hosts assets remain separate from blocklists:

```text
hosts ./dns/hosts.txt       # name → IP resolution override
blocklist ./rules/ads.txt   # policy rejection source
```

See `examples/dot-resolver.conf`, ADR-0013, and ADR-0014.
'''
replace_once(old_dns, new_dns)

replace_once(
    "./target/release/commeatus check --config examples/trojan-outbound.conf\n```",
    "./target/release/commeatus check --config examples/trojan-outbound.conf\n./target/release/commeatus check --config examples/dot-resolver.conf\n```",
)

replace_once(
    "- hosts files: 4\n- hosts source: 4 MiB",
    "- hosts files: 4\n- configured DNS resolvers: 8\n- hosts source: 4 MiB",
)
replace_once("- DoH, DoT, DoQ or Fake-IP", "- DoH, DoQ or Fake-IP")

replace_once(
    "- Trojan UDP partial/coalesced frame handling and zero-length datagram delivery\n",
    "- Trojan UDP partial/coalesced frame handling and zero-length datagram delivery\n- verified DoT A+AAAA reuse over one real TLS connection and local reconnect after server close\n- native resolver-chain config tests proving DoT-only secure-only semantics and explicit ordered system fallback\n",
)

replace_once(
    "1. secure DNS resolvers behind `commeatus-dns` (DoH/DoT first, then DoQ/Fake-IP semantics)",
    "1. DoH behind the same typed resolver boundary, then DoQ/Fake-IP semantics without weakening explicit fallback policy",
)

path.write_text(text)

final = path.read_text()
for required in [
    "current `main` is **v0.6 development**",
    "resolver dot 1.1.1.1:853 cloudflare-dns.com",
    "a DoT-only chain is therefore secure-only",
    "examples/dot-resolver.conf",
    "configured DNS resolvers: 8",
    "ADR-0014",
]:
    if required not in final:
        raise SystemExit(f"missing secure DNS README invariant: {required}")
if "System DNS is still the only network resolver" in final:
    raise SystemExit("stale system-only DNS claim remains in README")
if "- DoH, DoT, DoQ or Fake-IP" in final:
    raise SystemExit("stale DoT limitation remains in README")
