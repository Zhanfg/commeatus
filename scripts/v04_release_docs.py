from pathlib import Path

readme = Path("README.md")
text = readme.read_text()

old_status = "> **Status:** `0.3.0-alpha.1`. This is an experimental alpha, not a production-ready replacement for mihomo or sing-box. It has a real TCP/UDP inbound data plane, native policy, compiled domain filtering, an isolated DNS engine, named native proxy TCP outbounds, Android arm64 builds, and a CI-verified eBPF prototype boundary."
new_status = "> **Status:** `0.4.0-alpha.1`. This is an experimental alpha, not a production-ready replacement for mihomo or sing-box. It has a real TCP/UDP inbound data plane, native policy, compiled domain filtering, an isolated DNS engine, named proxy TCP outbounds, a verified rustls TLS transport, Android arm64 builds, and a CI-verified eBPF prototype boundary."
if old_status not in text:
    raise SystemExit("README status marker missing")
text = text.replace(old_status, new_status, 1)
text = text.replace("## What works in 0.3.0-alpha.1", "## What works in 0.4.0-alpha.1", 1)
text = text.replace(
    "System DNS is still the only network resolver in `0.3.0-alpha.1`.",
    "System DNS is still the only network resolver in `0.4.0-alpha.1`.",
    1,
)

flow_marker = "### Flow and policy\n"
tls_section = """### Verified TLS transport

TLS is a transport/security capability below the proxy-protocol handshake. Existing SOCKS5 and HTTP CONNECT outbounds can run over plain TCP or verified TLS without TLS-specific branches in their protocol code.

Native forms:

```text
# v0.3-compatible implicit TCP
endpoint edge socks5 127.0.0.1:1081

# explicit TCP
endpoint edge-tcp socks5 tcp 127.0.0.1:1081

# TLS: connection address and certificate identity are separate
endpoint secure socks5 tls 203.0.113.7:443 proxy.example
```

The native TLS path:

- uses rustls 0.23 with the ring crypto provider;
- validates the configured `ServerName` / SNI against the peer certificate;
- trusts the embedded WebPKI server-root set;
- keeps `SocketAddr` separate from TLS identity;
- applies bounded connect and handshake timeouts;
- bounds rustls plaintext buffering;
- exposes no native `insecure` / `skip-verify` switch.

After the proxy-protocol handshake, `TlsTransportSession` owns the TLS state and drives the tunnel with readiness notifications rather than a fixed periodic timer. Clean `close_notify` shutdown is preserved; an unclean network EOF is not silently reclassified as a valid TLS close.

Android cross-builds configure Cargo, `cc-rs`, and ring against the same NDK/API-29 toolchain through `scripts/android-ndk-env.sh`.

"""
if tls_section not in text:
    if flow_marker not in text:
        raise SystemExit("README flow marker missing")
    text = text.replace(flow_marker, tls_section + flow_marker, 1)

quick_marker = """Validate named proxy endpoint syntax:

```bash
./target/release/commeatus check --config examples/proxy-outbound.conf
```
"""
quick_tls = quick_marker + """
Validate verified TLS endpoint syntax:

```bash
./target/release/commeatus check --config examples/tls-proxy-outbound.conf
```
"""
if quick_marker not in text:
    raise SystemExit("README quick-start marker missing")
text = text.replace(quick_marker, quick_tls, 1)

text = text.replace(
    "- proxy handshake timeout: 10 seconds\n",
    "- proxy handshake timeout: 10 seconds\n- TLS transport buffer limit: 64 KiB\n",
    1,
)
text = text.replace("`0.3.0-alpha.1` does **not** include:", "`0.4.0-alpha.1` does **not** include:", 1)
text = text.replace("- TLS transport provider\n", "", 1)

verify_marker = "- `.invalid` target-domain preservation to the selected upstream proxy without local destination DNS\n"
verify_tls = verify_marker + "- HTTP inbound → SOCKS5 outbound protocol → verified TLS transport → TLS SOCKS5 mock → echo, with `.invalid` target preservation\n- trusted test CA + matching TLS identity succeeds; wrong TLS identity fails\n- clean TLS full-duplex relay / `close_notify` shutdown\n"
if verify_marker not in text:
    raise SystemExit("README verification marker missing")
text = text.replace(verify_marker, verify_tls, 1)

layout_marker = "│   ├── dns/        # DNS engine, hosts, cache and resolver boundary\n"
if layout_marker not in text:
    raise SystemExit("README layout marker missing")
text = text.replace(
    layout_marker,
    layout_marker + "│   ├── transport/  # TCP/TLS transport sessions and carrier-owned relay\n",
    1,
)

next_start = "## Next development slices\n\nAfter this release line, the highest-value work is:\n\n"
next_end = "\n## Security\n"
start = text.find(next_start)
end = text.find(next_end, start)
if start < 0 or end < 0:
    raise SystemExit("README next-development section markers missing")
next_section = next_start + """1. first encrypted native proxy protocol on the verified transport boundary
2. proxy UDP execution and a capability-safe datagram abstraction
3. secure DNS resolvers behind `commeatus-dns`
4. TPROXY backend and safe attach/cleanup lifecycle
5. eBPF loader, read-only policy maps, atomic generations and fallback behavior
6. compatibility importers/API facade
7. adaptive routing and real-traffic telemetry
8. low-power executor and comparative power/performance benchmarks
"""
text = text[:start] + next_section + text[end:]
readme.write_text(text)

changelog = Path("CHANGELOG.md")
text = changelog.read_text()
marker = "The project is pre-1.0. Native configuration and internal APIs may change between alpha releases.\n\n"
if marker not in text:
    raise SystemExit("CHANGELOG preamble marker missing")
entry = """## 0.4.0-alpha.1 — 2026-08-16

Fourth public alpha. This release establishes a reusable transport-session layer and adds verified native TLS beneath existing outbound proxy protocols.

### Added

- `commeatus-transport` ownership boundary with `TransportConnector`, `TransportSession`, and transport capabilities
- `TcpTransport` / `TcpTransportSession`; TCP-specific clone/half-close logic now belongs to the transport
- rustls 0.23 + ring `TlsTransport` / `TlsTransportSession`
- embedded WebPKI root verification on the native TLS path
- independent literal upstream `SocketAddr` and TLS `ServerName` / SNI
- readiness-driven TLS full-duplex relay using `mio::Poll`
- bounded TLS plaintext buffering and bounded connect/handshake timeouts
- explicit native endpoint forms for TCP and TLS while preserving v0.3 implicit-TCP syntax
- `examples/tls-proxy-outbound.conf`
- ADR-0004 `Transport Owns Session Relay`
- ADR-0005 `TLS Is a Verified Transport`
- deterministic local certificate/SNI verification tests
- full-duplex TLS relay + clean `close_notify` test
- cross-layer HTTP inbound → SOCKS5 protocol → TLS transport → TLS SOCKS5 mock → echo E2E
- Android NDK environment helper for Cargo linker plus target-specific `cc-rs` CC/AR

### Changed

- outbound protocols now perform handshakes over `TransportSession` rather than returning raw `TcpStream`
- carrier relay behavior has one authoritative transport owner
- endpoint encrypted capability is derived from transport metadata
- native TLS configuration separates network connection address from certificate identity
- Android CI/package builds configure native C/assembly dependencies against the same NDK/API-29 toolchain as Rust

### Security and stability

- native TLS certificate/server-name verification is enabled by default
- no native insecure/skip-verification switch is provided
- wrong TLS server identity fails even when the issuing test CA is trusted
- unclean network EOF is not silently accepted as TLS `close_notify`
- TLS readiness interests are registered only while useful I/O work exists; there is no fixed periodic relay timer
- proxy-routed `.invalid` destination identity remains preserved through SOCKS5-over-TLS without local destination DNS
- Rust 1.85 all-targets, Android arm64/ring, eBPF and release packaging remain gated in CI

### Known limitations

- no Trojan, VLESS, Shadowsocks, Hysteria2 or TUIC yet
- no proxy UDP execution
- no Android/Linux user-added enterprise trust-store import
- no client certificates / mTLS, pinning, explicit ALPN policy or ECH
- no endpoint groups / health selection / adaptive routing
- no live TUN/TPROXY/eBPF interception
- no KernelSU/Magisk packaging
- no DoH/DoT/DoQ/Fake-IP
- no Clash/mihomo/sing-box import or compatible API

"""
if "## 0.4.0-alpha.1" not in text:
    text = text.replace(marker, marker + entry, 1)
changelog.write_text(text)
