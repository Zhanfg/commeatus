from pathlib import Path

config = Path("crates/daemon/src/config.rs")
text = config.read_text()
text = text.replace(
    "use crate::outbound::{OutboundRegistry, ProxyEndpointConfig, ProxyProtocol, TransportConfig};",
    "use crate::outbound::{\n    OutboundRegistry, ProxyEndpointConfig, ProxyProtocol, TransportConfig, TrojanProtocol,\n};",
    1,
)

start_marker = '            Some("endpoint") => {'
end_marker = '            Some("default") => {'
start = text.find(start_marker)
end = text.find(end_marker, start)
if start < 0 or end < 0:
    raise SystemExit("endpoint config block markers missing")

block = r'''            Some("endpoint") => {
                if endpoint_configs.len() >= MAX_PROXY_ENDPOINTS {
                    return Err(ConfigError::at(
                        line_number,
                        format!("proxy endpoint count exceeds {MAX_PROXY_ENDPOINTS}"),
                    ));
                }
                let id = fields
                    .get(1)
                    .ok_or_else(|| {
                        ConfigError::at(
                            line_number,
                            "endpoint requires an id, protocol and transport configuration",
                        )
                    })?;
                let id = EndpointId::new((*id).to_owned())
                    .map_err(|error| ConfigError::at(line_number, error.to_string()))?;
                if !endpoint_ids.insert(id.clone()) {
                    return Err(ConfigError::at(line_number, "duplicate proxy endpoint id"));
                }

                let (protocol, transport) = match fields.as_slice() {
                    ["endpoint", _, "socks5", address] => (
                        ProxyProtocol::Socks5,
                        TransportConfig::Tcp(TcpTransport::new(parse_proxy_address(
                            address,
                            line_number,
                        )?)),
                    ),
                    ["endpoint", _, "http", address] => (
                        ProxyProtocol::HttpConnect,
                        TransportConfig::Tcp(TcpTransport::new(parse_proxy_address(
                            address,
                            line_number,
                        )?)),
                    ),
                    ["endpoint", _, "socks5", "tcp", address] => (
                        ProxyProtocol::Socks5,
                        TransportConfig::Tcp(TcpTransport::new(parse_proxy_address(
                            address,
                            line_number,
                        )?)),
                    ),
                    ["endpoint", _, "http", "tcp", address] => (
                        ProxyProtocol::HttpConnect,
                        TransportConfig::Tcp(TcpTransport::new(parse_proxy_address(
                            address,
                            line_number,
                        )?)),
                    ),
                    ["endpoint", _, "socks5", "tls", address, server_name] => (
                        ProxyProtocol::Socks5,
                        parse_tls_transport(address, server_name, line_number)?,
                    ),
                    ["endpoint", _, "http", "tls", address, server_name] => (
                        ProxyProtocol::HttpConnect,
                        parse_tls_transport(address, server_name, line_number)?,
                    ),
                    ["endpoint", _, "trojan", "tls", address, server_name, password] => (
                        ProxyProtocol::Trojan(
                            TrojanProtocol::new(password)
                                .map_err(|error| ConfigError::at(line_number, error.to_string()))?,
                        ),
                        parse_tls_transport(address, server_name, line_number)?,
                    ),
                    ["endpoint", _, "trojan", ..] => {
                        return Err(ConfigError::at(
                            line_number,
                            "Trojan endpoint syntax is `endpoint <id> trojan tls <ip:port> <server-name> <password>`; plain TCP is forbidden",
                        ));
                    }
                    _ => {
                        return Err(ConfigError::at(
                            line_number,
                            "endpoint syntax supports SOCKS5/HTTP over implicit TCP, explicit TCP or TLS, and Trojan over TLS only",
                        ));
                    }
                };

                endpoint_configs.push(ProxyEndpointConfig {
                    id,
                    protocol,
                    transport,
                });
            }
'''
text = text[:start] + block + text[end:]

helper_marker = "fn expect_fields(\n"
helper_pos = text.find(helper_marker)
if helper_pos < 0:
    raise SystemExit("helper insertion marker missing")
helpers = r'''fn parse_proxy_address(value: &str, line: usize) -> Result<SocketAddr, ConfigError> {
    let address: SocketAddr = value.parse().map_err(|_| {
        ConfigError::at(
            line,
            "proxy endpoint address must be an IP socket address",
        )
    })?;
    if address.port() == 0 {
        return Err(ConfigError::at(line, "proxy endpoint port must not be zero"));
    }
    Ok(address)
}

fn parse_tls_transport(
    address: &str,
    server_name: &str,
    line: usize,
) -> Result<TransportConfig, ConfigError> {
    let address = parse_proxy_address(address, line)?;
    TlsTransport::webpki(address, server_name)
        .map(TransportConfig::Tls)
        .map_err(|error| ConfigError::at(line, error.to_string()))
}

'''
text = text[:helper_pos] + helpers + text[helper_pos:]

marker = "    #[test]\n    fn config_size_is_bounded()"
pos = text.rfind(marker)
if pos < 0:
    raise SystemExit("config test insertion marker missing")

tests = r'''    #[test]
    fn trojan_tls_endpoint_compiles_as_encrypted_tcp_only() {
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            endpoint secure trojan tls 127.0.0.1:443 trojan.example secret
            default proxy:secure
        "#;
        let compiled = parse_config(config).unwrap();
        assert_eq!(compiled.outbounds().len(), 1);
        let endpoint = Endpoint::Proxy(EndpointId::new("secure").unwrap());
        let capabilities = compiled.outbounds().capabilities(&endpoint).unwrap();
        assert!(capabilities.supports_tcp());
        assert!(!capabilities.supports_udp());
        assert!(capabilities.encrypted_transport());
    }

    #[test]
    fn trojan_plain_tcp_is_rejected_by_candidate_parser() {
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            endpoint insecure trojan tcp 127.0.0.1:443 secret
            default proxy:insecure
        "#;
        assert!(parse_config(config).is_err());
    }

'''
text = text[:pos] + tests + text[pos:]
config.write_text(text)
