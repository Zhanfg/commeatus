from pathlib import Path
import re


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one match in {path}, found {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1))


def regex_once(path: str, pattern: str, replacement: str) -> None:
    p = Path(path)
    text = p.read_text()
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise SystemExit(f"expected exactly one regex match in {path}, found {count}: {pattern!r}")
    p.write_text(updated)


# Register the provider module.
replace_once(
    "crates/daemon/src/lib.rs",
    "mod outbound;\nmod proxy;",
    "mod outbound;\nmod protocol;\nmod proxy;",
)

# Native config terminates text syntax in provider factories.
replace_once(
    "crates/daemon/src/config.rs",
    "use crate::outbound::{\n    OutboundRegistry, ProxyEndpointConfig, ProxyProtocol, TransportConfig, TrojanProtocol,\n};",
    "use crate::{\n    outbound::{OutboundRegistry, ProxyEndpointConfig, TransportConfig},\n    protocol,\n};",
)
config = Path("crates/daemon/src/config.rs")
text = config.read_text()
if text.count("ProxyProtocol::Socks5") != 3:
    raise SystemExit("unexpected SOCKS5 enum reference count in config")
if text.count("ProxyProtocol::HttpConnect") != 3:
    raise SystemExit("unexpected HTTP enum reference count in config")
text = text.replace("ProxyProtocol::Socks5", "protocol::socks5()")
text = text.replace("ProxyProtocol::HttpConnect", "protocol::http_connect()")
old_trojan = """                        ProxyProtocol::Trojan(\n                            TrojanProtocol::new(password)\n                                .map_err(|error| ConfigError::at(line_number, error.to_string()))?,\n                        ),"""
new_trojan = """                        protocol::trojan(password)\n                            .map_err(|error| ConfigError::at(line_number, error.to_string()))?,"""
if text.count(old_trojan) != 1:
    raise SystemExit("unexpected Trojan enum construction in config")
config.write_text(text.replace(old_trojan, new_trojan, 1))

# Plain outbound E2E takes a provider reference and uses factories.
replace_once(
    "crates/daemon/src/outbound_e2e.rs",
    "    outbound::{OutboundRegistry, ProxyEndpointConfig, ProxyProtocol, TransportConfig},\n    server::spawn_test_listener_with_runtime,",
    "    outbound::{OutboundRegistry, ProxyEndpointConfig, TransportConfig},\n    protocol::{self, ProtocolRef},\n    server::spawn_test_listener_with_runtime,",
)
regex_once(
    "crates/daemon/src/outbound_e2e.rs",
    r"fn registry\(id: EndpointId, protocol: ProxyProtocol, address: SocketAddr\) -> Arc<OutboundRegistry> \{",
    "fn registry(id: EndpointId, protocol: ProtocolRef, address: SocketAddr) -> Arc<OutboundRegistry> {",
)
outbound_e2e = Path("crates/daemon/src/outbound_e2e.rs")
text = outbound_e2e.read_text()
if text.count("ProxyProtocol::Socks5") != 1 or text.count("ProxyProtocol::HttpConnect") != 1:
    raise SystemExit("unexpected plain outbound E2E enum reference count")
text = text.replace("ProxyProtocol::Socks5", "protocol::socks5()")
text = text.replace("ProxyProtocol::HttpConnect", "protocol::http_connect()")
outbound_e2e.write_text(text)

# SOCKS5-over-TLS E2E uses the same provider factory.
replace_once(
    "crates/daemon/src/tls_outbound_e2e.rs",
    "    outbound::{OutboundRegistry, ProxyEndpointConfig, ProxyProtocol, TransportConfig},\n    server::spawn_test_listener_with_runtime,",
    "    outbound::{OutboundRegistry, ProxyEndpointConfig, TransportConfig},\n    protocol,\n    server::spawn_test_listener_with_runtime,",
)
tls_e2e = Path("crates/daemon/src/tls_outbound_e2e.rs")
text = tls_e2e.read_text()
if text.count("ProxyProtocol::Socks5") != 1:
    raise SystemExit("unexpected TLS outbound E2E enum reference count")
tls_e2e.write_text(text.replace("ProxyProtocol::Socks5", "protocol::socks5()", 1))

# Trojan E2E constructs the private provider through its factory.
replace_once(
    "crates/daemon/src/trojan_outbound_e2e.rs",
    "    outbound::{\n        OutboundRegistry, ProxyEndpointConfig, ProxyProtocol, TransportConfig, TrojanProtocol,\n    },\n    server::spawn_test_listener_with_runtime,",
    "    outbound::{OutboundRegistry, ProxyEndpointConfig, TransportConfig},\n    protocol,\n    server::spawn_test_listener_with_runtime,",
)
replace_once(
    "crates/daemon/src/trojan_outbound_e2e.rs",
    "            protocol: ProxyProtocol::Trojan(TrojanProtocol::new(PASSWORD).unwrap()),",
    "            protocol: protocol::trojan(PASSWORD).unwrap(),",
)

# Hard architecture invariant for this migration.
remaining = []
for path in Path("crates").rglob("*.rs"):
    if "ProxyProtocol" in path.read_text():
        remaining.append(str(path))
if remaining:
    raise SystemExit("ProxyProtocol remains in: " + ", ".join(remaining))
