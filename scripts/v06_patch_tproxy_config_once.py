from pathlib import Path

path = Path("crates/daemon/src/config.rs")
text = path.read_text()

replacements = [
    (
        "pub enum ListenerProtocol {\n    Socks5,\n    HttpConnect,\n}",
        "pub enum ListenerProtocol {\n    Socks5,\n    HttpConnect,\n    TproxyTcp,\n}",
    ),
    (
        '"listen syntax is `listen <socks5|http> <ip:port>`",',
        '"listen syntax is `listen <socks5|http|tproxy-tcp> <ip:port>`",',
    ),
    (
        '                    "socks5" => ListenerProtocol::Socks5,\n                    "http" => ListenerProtocol::HttpConnect,\n                    _ => {\n                        return Err(ConfigError::at(\n                            line_number,\n                            "listener protocol must be `socks5` or `http`",\n                        ));\n                    }',
        '                    "socks5" => ListenerProtocol::Socks5,\n                    "http" => ListenerProtocol::HttpConnect,\n                    "tproxy-tcp" => ListenerProtocol::TproxyTcp,\n                    _ => {\n                        return Err(ConfigError::at(\n                            line_number,\n                            "listener protocol must be `socks5`, `http`, or `tproxy-tcp`",\n                        ));\n                    }',
    ),
]

for old, new in replacements:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one latest-main config match, got {count}: {old!r}")
    text = text.replace(old, new, 1)

# Guard the parallel secure-DNS configuration slice: this patch must extend it,
# never replace or erase it.
for required in ["resolver dot", "resolver system", "DnsResolverSummary"]:
    if required not in text:
        raise SystemExit(f"secure-DNS config marker disappeared: {required}")

path.write_text(text)
