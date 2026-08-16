from pathlib import Path

OLD = "0.4.0-alpha.1"
NEW = "0.5.0-alpha.1"


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one match in {path}, found {count}: {old!r}")
    p.write_text(text.replace(old, new, 1))


def replace_section(path: str, start: str, end: str, replacement: str) -> None:
    p = Path(path)
    text = p.read_text()
    start_index = text.find(start)
    if start_index < 0:
        raise SystemExit(f"missing section start in {path}: {start!r}")
    end_index = text.find(end, start_index + len(start))
    if end_index < 0:
        raise SystemExit(f"missing section end in {path}: {end!r}")
    p.write_text(text[:start_index] + replacement.rstrip() + "\n\n" + text[end_index:])


# Bump the workspace package version and every exact internal path dependency.
manifest_replacements = 0
for path in [Path("Cargo.toml"), *sorted(Path("crates").glob("*/Cargo.toml"))]:
    text = path.read_text()
    count = text.count(OLD)
    if count:
        path.write_text(text.replace(OLD, NEW))
        manifest_replacements += count
if manifest_replacements < 6:
    raise SystemExit(f"unexpectedly few manifest version replacements: {manifest_replacements}")
for path in [Path("Cargo.toml"), *sorted(Path("crates").glob("*/Cargo.toml"))]:
    if OLD in path.read_text():
        raise SystemExit(f"old version remains in manifest: {path}")

readme = Path("README.md")
text = readme.read_text()

old_status = (
    "> **Status:** `0.4.0-alpha.1`. This is an experimental alpha, not a production-ready "
    "replacement for mihomo or sing-box. It has a real TCP/UDP inbound data plane, native policy, "
    "compiled domain filtering, an isolated DNS engine, named proxy TCP outbounds, a verified rustls "
    "TLS transport, Android arm64 builds, and a CI-verified eBPF prototype boundary."
)
new_status = (
    "> **Status:** `0.5.0-alpha.1`. This is an experimental alpha, not a production-ready "
    "replacement for mihomo or sing-box. It has real TCP/UDP inbounds, native policy, compiled domain "
    "filtering, an isolated DNS engine, named proxy stream outbounds, native Trojan CONNECT and UDP "
    "ASSOCIATE over verified rustls TLS, Android arm64 builds, and a CI-verified eBPF prototype boundary."
)
if text.count(old_status) != 1:
    raise SystemExit("README status paragraph no longer matches expected v0.4 text")
text = text.replace(old_status, new_status, 1)
text = text.replace("## What works in 0.4.0-alpha.1", "## What works in 0.5.0-alpha.1", 1)
text = text.replace(
    "System DNS is still the only network resolver in `0.4.0-alpha.1`.",
    "System DNS is still the only network resolver in `0.5.0-alpha.1`.",
    1,
)
readme.write_text(text)

replace_section(
    "README.md",
    "### Named proxy TCP outbounds",
    "### Native outbound configuration",
    """### Named proxy outbounds

The daemon owns the execution-layer `OutboundRegistry`, but protocol and datagram lifecycle are attached through providers rather than encoded as a central protocol enum:

```text
EndpointId
   ↓
ProxyEndpointConfig
   ├─ stream protocol provider + transport
   └─ optional datagram provider
```

Native stream outbounds currently include:

- upstream SOCKS5 no-auth TCP `CONNECT`
- upstream HTTP/1.x `CONNECT`
- Trojan `CONNECT` over verified TLS

Native datagram execution currently includes:

- policy-aware DIRECT UDP
- Trojan UDP `ASSOCIATE` over verified TLS

A domain selected for any proxy route is preserved to the upstream proxy. It is **not** first resolved through the local DIRECT DNS engine.

UDP capability comes from a real datagram-provider attachment. If policy selects an endpoint that lacks one, the datagram fails locally and is never silently sent DIRECT.
""",
)

# Extend the native configuration example with the first encrypted protocol.
replace_once(
    "README.md",
    "endpoint office-http http 127.0.0.1:8081\n\nrule proxy:edge-socks domain-suffix proxied.example",
    "endpoint office-http http 127.0.0.1:8081\nendpoint secure-trojan trojan tls 203.0.113.10:443 trojan.example change-me\n\nrule proxy:edge-socks domain-suffix proxied.example",
)

# Add the v0.5 transport/protocol slice before flow/policy documentation.
marker = "### Flow and policy\n"
text = readme.read_text()
if text.count(marker) != 1:
    raise SystemExit("README Flow and policy marker changed unexpectedly")
trojan_section = """### Native Trojan TCP and UDP

Trojan is the first encrypted native proxy protocol. The same native endpoint attaches an independent stream provider and datagram provider above verified TLS:

```text
endpoint secure trojan tls 203.0.113.10:443 trojan.example change-me
```

The raw password is transformed into the Trojan verifier while compiling the configuration candidate. The active protocol objects do not retain the raw source password.

Stream CONNECT uses the ordinary verified `TransportSession`. UDP uses a dedicated `TrojanDatagramProvider` over a readiness-driven framed TLS session. The UDP ASSOCIATE preface uses a normalized `0.0.0.0:0` initial target; each following Trojan UDP frame carries its own IPv4, IPv6 or domain destination.

The datagram path is event driven. It does not use the previous fixed 500 ms SOCKS5 UDP poll timeout, does not register permanent writable interest, and does not start a background Trojan worker.

Trojan UDP state is bounded to 64 pending frames, 512 KiB of pending protocol bytes and 128 KiB of decrypted receive buffering. Partial TLS plaintext, multiple coalesced frames and zero-length UDP payloads are covered by native tests and full SOCKS5-to-Trojan TLS E2E.

"""
readme.write_text(text.replace(marker, trojan_section + marker, 1))

# Quick-start validation should include the v0.5 native Trojan example.
replace_once(
    "README.md",
    "./target/release/commeatus check --config examples/tls-proxy-outbound.conf\n```",
    "./target/release/commeatus check --config examples/tls-proxy-outbound.conf\n./target/release/commeatus check --config examples/trojan-outbound.conf\n```",
)

# Remove capabilities that are no longer limitations while retaining still-missing protocols.
text = readme.read_text()
if text.count("- proxy UDP execution\n") != 1:
    raise SystemExit("README proxy UDP limitation changed unexpectedly")
text = text.replace("- proxy UDP execution\n", "", 1)
if text.count("- Shadowsocks, Trojan, VLESS, Hysteria2 or TUIC") != 1:
    raise SystemExit("README protocol limitation changed unexpectedly")
text = text.replace(
    "- Shadowsocks, Trojan, VLESS, Hysteria2 or TUIC",
    "- Shadowsocks, VLESS, Hysteria2 or TUIC",
    1,
)
readme.write_text(text)

# Add current E2E evidence after the v0.4 TLS proof.
replace_once(
    "README.md",
    "- clean TLS full-duplex relay / `close_notify` shutdown\n",
    "- clean TLS full-duplex relay / `close_notify` shutdown\n"
    "- HTTP inbound → native Trojan CONNECT → verified TLS mock, with `.invalid` target preservation\n"
    "- SOCKS5 UDP inbound → native Trojan UDP provider → verified framed TLS mock\n"
    "- Trojan UDP partial/coalesced frame handling and zero-length datagram delivery\n",
)

replace_section(
    "README.md",
    "## Next development slices",
    "## Security",
    """## Next development slices

After v0.5, the highest-value work is:

1. secure DNS resolvers behind `commeatus-dns` (DoH/DoT first, then DoQ/Fake-IP semantics)
2. TPROXY backend with transactional attach/cleanup and safe fallback
3. eBPF loader, read-only policy maps, atomic generations and fallback behavior
4. additional native protocols behind the established provider boundaries (VLESS/Shadowsocks before QUIC-heavy transports)
5. compatibility importers and a compatibility API facade that terminate at native IR
6. endpoint groups, health selection and real-traffic telemetry
7. adaptive/Smart routing constrained by hard policy
8. low-power global executor plus comparative power/performance benchmarks
9. Android Root packaging and supervisor/cleanup integration once interception lifecycle is proven
""",
)

if OLD in readme.read_text():
    raise SystemExit("stale v0.4 release version remains in README")
if "Current proxy endpoints advertise TCP capability only" in readme.read_text():
    raise SystemExit("stale TCP-only capability claim remains in README")

# Update the shipped Trojan example from development wording to release wording.
replace_once(
    "examples/trojan-outbound.conf",
    "# Commeatus v0.5 development example: native Trojan CONNECT over verified TLS.",
    "# Commeatus v0.5 example: native Trojan TCP/UDP over verified TLS.",
)
replace_once(
    "examples/trojan-outbound.conf",
    "# The active TrojanProtocol retains only hex(SHA224(password)), not this raw\n# password. A future secret-source mechanism is still required for production\n# secret management.",
    "# The compiled native endpoint shares the derived Trojan verifier between its\n# stream and datagram providers; the raw source password is not retained by those\n# active provider objects. A future secret-source mechanism is still required for\n# production secret management.",
)

# Prepend the v0.5 changelog entry before the immutable v0.4 history.
changelog = Path("CHANGELOG.md")
text = changelog.read_text()
marker = "## 0.4.0-alpha.1 — 2026-08-16\n"
if text.count(marker) != 1:
    raise SystemExit("CHANGELOG v0.4 marker changed unexpectedly")
entry = """## 0.5.0-alpha.1 — 2026-08-16

Fifth public alpha. This release establishes provider-owned protocol/datagram execution and ships native Trojan TCP and UDP over verified, readiness-driven TLS.

### Added

- protocol-provider boundary for native stream handshakes and capabilities
- native Trojan CONNECT over verified TLS
- shared, redacted `TrojanVerifier` and Trojan address/wire primitives
- logical `DatagramAssociation` / `DatagramExecution` boundary
- outbound-owned `DatagramRouteSet` with bounded, endpoint-lazy sessions
- independent optional datagram-provider attachment on proxy endpoints
- readiness-driven `TlsFramedSession` for framed protocols over verified TLS
- native Trojan UDP ASSOCIATE and per-datagram IPv4/IPv6/domain framing
- bounded Trojan UDP pending-frame, pending-byte and receive buffers
- ADR-0006 through ADR-0012 covering Trojan, provider, datagram and framed-TLS ownership
- `examples/trojan-outbound.conf`
- full native Trojan TCP E2E
- full SOCKS5 UDP → Trojan UDP → verified TLS E2E, including `.invalid` domain preservation, split/coalesced frames and zero-length UDP

### Changed

- `OutboundRegistry` no longer owns a central stream-protocol enum switch
- native Trojan endpoints advertise UDP only because a real datagram provider is attached
- raw Trojan passwords are converted once at configuration compilation and shared as verifier state between stream/datagram providers
- SOCKS5 UDP no longer hard-codes DIRECT datagram construction
- one UDP ASSOCIATE can lazily maintain multiple policy-selected outbound endpoint routes within a hard route limit
- outbound route readiness dispatch accepts any readiness event owned by the route, allowing TLS ciphertext flush without Trojan-specific SOCKS5 branches
- the previous fixed 500 ms SOCKS5 UDP control polling path is removed

### Security and stability

- proxy-selected UDP domains remain opaque to local DIRECT DNS and are carried to Trojan upstream unchanged
- unsupported proxy UDP continues to fail locally and never falls back to DIRECT
- Trojan verifier Debug output is redacted
- malformed or oversized Trojan UDP state fails the affected path rather than panicking the process
- framed TLS keeps certificate/SNI verification and encrypted-socket ownership inside `commeatus-transport`
- writable readiness is transient instead of permanently registered
- Trojan UDP queues/RX state and per-association route growth are explicitly bounded
- Rust 1.85, Android arm64, eBPF, release packaging and full E2E remain CI gates

### Known limitations

- no Shadowsocks, VLESS, Hysteria2 or TUIC
- no endpoint groups, health selection or adaptive routing
- no DoH/DoT/DoQ/Fake-IP
- no live TUN/TPROXY/eBPF interception
- no KernelSU/Magisk packaging
- no compatibility import/API facade
- no shared/multiplexed Trojan UDP carrier pooling
- bounded thread-per-session remains the transitional global TCP executor

"""
changelog.write_text(text.replace(marker, entry + marker, 1))
