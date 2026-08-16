use std::{collections::HashMap, io, net::IpAddr};

use commeatus_core::{DestinationHost, Endpoint, EndpointId};
use commeatus_dns::DnsEngine;
use commeatus_transport::{
    TcpTransport, TcpTransportSession, TlsTransport, TransportCapabilities, TransportConnector,
    TransportSession,
};
use sha2::{Digest, Sha224};

use crate::proxy::{self, Target};

const MAX_HTTP_RESPONSE_HEAD: usize = 16 * 1024;
const MAX_TROJAN_PASSWORD_BYTES: usize = 1024;
const TROJAN_PASSWORD_HASH_BYTES: usize = 56;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanProtocol {
    password_hash: [u8; TROJAN_PASSWORD_HASH_BYTES],
}

impl TrojanProtocol {
    pub fn new(password: &str) -> io::Result<Self> {
        if password.is_empty() || password.len() > MAX_TROJAN_PASSWORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Trojan password must contain 1..={MAX_TROJAN_PASSWORD_BYTES} UTF-8 bytes"),
            ));
        }

        let digest = Sha224::digest(password.as_bytes());
        let mut password_hash = [0_u8; TROJAN_PASSWORD_HASH_BYTES];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (index, byte) in digest.iter().copied().enumerate() {
            password_hash[index * 2] = HEX[usize::from(byte >> 4)];
            password_hash[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
        }
        Ok(Self { password_hash })
    }

    #[cfg(test)]
    fn password_hash(&self) -> &[u8; TROJAN_PASSWORD_HASH_BYTES] {
        &self.password_hash
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyProtocol {
    Socks5,
    HttpConnect,
    Trojan(TrojanProtocol),
}

#[derive(Clone, Debug)]
pub enum TransportConfig {
    Tcp(TcpTransport),
    Tls(TlsTransport),
}

impl TransportConfig {
    #[must_use]
    fn capabilities(&self) -> TransportCapabilities {
        match self {
            Self::Tcp(transport) => transport.capabilities(),
            Self::Tls(transport) => transport.capabilities(),
        }
    }

    #[must_use]
    fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    fn connect(&self) -> io::Result<Box<dyn TransportSession>> {
        match self {
            Self::Tcp(transport) => transport.connect(),
            Self::Tls(transport) => transport.connect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProxyEndpointConfig {
    pub id: EndpointId,
    pub protocol: ProxyProtocol,
    pub transport: TransportConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointCapabilities {
    tcp: bool,
    udp: bool,
    encrypted_transport: bool,
}

impl EndpointCapabilities {
    #[must_use]
    pub const fn supports_tcp(self) -> bool {
        self.tcp
    }

    #[must_use]
    pub const fn supports_udp(self) -> bool {
        self.udp
    }

    #[must_use]
    pub const fn encrypted_transport(self) -> bool {
        self.encrypted_transport
    }
}

#[derive(Clone, Debug, Default)]
pub struct OutboundRegistry {
    endpoints: HashMap<EndpointId, ProxyEndpointConfig>,
}

impl OutboundRegistry {
    pub fn new(endpoints: Vec<ProxyEndpointConfig>) -> Result<Self, io::Error> {
        let mut registry = HashMap::with_capacity(endpoints.len());
        for endpoint in endpoints {
            if matches!(&endpoint.protocol, ProxyProtocol::Trojan(_))
                && !endpoint.transport.is_tls()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Trojan endpoint `{}` requires a TLS transport",
                        endpoint.id.as_str()
                    ),
                ));
            }

            let id = endpoint.id.clone();
            if registry.insert(id.clone(), endpoint).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("duplicate outbound endpoint `{}`", id.as_str()),
                ));
            }
        }
        Ok(Self {
            endpoints: registry,
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    #[must_use]
    pub fn contains(&self, id: &EndpointId) -> bool {
        self.endpoints.contains_key(id)
    }

    #[must_use]
    pub fn capabilities(&self, endpoint: &Endpoint) -> Option<EndpointCapabilities> {
        match endpoint {
            Endpoint::Direct => Some(EndpointCapabilities {
                tcp: true,
                udp: true,
                encrypted_transport: false,
            }),
            Endpoint::Proxy(id) => self.endpoints.get(id).map(|config| {
                let transport = config.transport.capabilities();
                let protocol_supports_stream = matches!(
                    &config.protocol,
                    ProxyProtocol::Socks5 | ProxyProtocol::HttpConnect | ProxyProtocol::Trojan(_)
                );
                EndpointCapabilities {
                    tcp: protocol_supports_stream && transport.reliable_stream,
                    udp: false,
                    encrypted_transport: transport.encrypted,
                }
            }),
        }
    }

    pub fn connect_tcp(
        &self,
        endpoint: &Endpoint,
        target: &Target,
        dns: &DnsEngine,
    ) -> io::Result<Box<dyn TransportSession>> {
        if !self
            .capabilities(endpoint)
            .is_some_and(EndpointCapabilities::supports_tcp)
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "selected outbound endpoint does not support TCP",
            ));
        }

        match endpoint {
            Endpoint::Direct => {
                let stream = proxy::connect_direct(target, dns)?;
                Ok(TcpTransportSession::boxed(stream))
            }
            Endpoint::Proxy(id) => {
                let config = self.endpoints.get(id).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("proxy endpoint `{}` is not registered", id.as_str()),
                    )
                })?;
                let mut session = config.transport.connect()?;
                match &config.protocol {
                    ProxyProtocol::Socks5 => handshake_socks5(session.as_mut(), target)?,
                    ProxyProtocol::HttpConnect => handshake_http(session.as_mut(), target)?,
                    ProxyProtocol::Trojan(protocol) => {
                        handshake_trojan(session.as_mut(), target, protocol)?;
                    }
                }
                Ok(session)
            }
        }
    }
}

fn handshake_trojan(
    session: &mut dyn TransportSession,
    target: &Target,
    protocol: &TrojanProtocol,
) -> io::Result<()> {
    let mut request = Vec::with_capacity(TROJAN_PASSWORD_HASH_BYTES + 2 + 1 + 1 + 253 + 2 + 2);
    request.extend_from_slice(&protocol.password_hash);
    request.extend_from_slice(b"\r\n");
    request.push(0x01); // CONNECT
    encode_socks_address(&mut request, &target.host)?;
    request.extend_from_slice(&target.port.to_be_bytes());
    request.extend_from_slice(b"\r\n");
    session.write_all(&request)?;
    session.flush()
}

fn handshake_socks5(session: &mut dyn TransportSession, target: &Target) -> io::Result<()> {
    session.write_all(&[0x05, 0x01, 0x00])?;
    session.flush()?;
    let mut method = [0_u8; 2];
    session.read_exact(&mut method)?;
    if method != [0x05, 0x00] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "upstream SOCKS5 proxy did not accept no-auth",
        ));
    }

    let mut request = Vec::with_capacity(4 + 1 + 253 + 2);
    request.extend_from_slice(&[0x05, 0x01, 0x00]);
    encode_socks_address(&mut request, &target.host)?;
    request.extend_from_slice(&target.port.to_be_bytes());
    session.write_all(&request)?;
    session.flush()?;

    let mut reply = [0_u8; 4];
    session.read_exact(&mut reply)?;
    if reply[0] != 0x05 || reply[2] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid upstream SOCKS5 CONNECT reply",
        ));
    }
    if reply[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "upstream SOCKS5 CONNECT failed with reply code {}",
                reply[1]
            ),
        ));
    }
    discard_socks_address(session, reply[3])?;
    let mut port = [0_u8; 2];
    session.read_exact(&mut port)?;
    Ok(())
}

fn encode_socks_address(buffer: &mut Vec<u8>, host: &DestinationHost) -> io::Result<()> {
    match host {
        DestinationHost::Ip(IpAddr::V4(address)) => {
            buffer.push(0x01);
            buffer.extend_from_slice(&address.octets());
        }
        DestinationHost::Domain(domain) => {
            let length = u8::try_from(domain.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "SOCKS5 domain is too long")
            })?;
            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS5 domain must not be empty",
                ));
            }
            buffer.push(0x03);
            buffer.push(length);
            buffer.extend_from_slice(domain.as_bytes());
        }
        DestinationHost::Ip(IpAddr::V6(address)) => {
            buffer.push(0x04);
            buffer.extend_from_slice(&address.octets());
        }
    }
    Ok(())
}

fn discard_socks_address(session: &mut dyn TransportSession, address_type: u8) -> io::Result<()> {
    match address_type {
        0x01 => {
            let mut bytes = [0_u8; 4];
            session.read_exact(&mut bytes)
        }
        0x03 => {
            let mut length = [0_u8; 1];
            session.read_exact(&mut length)?;
            let mut bytes = vec![0_u8; usize::from(length[0])];
            session.read_exact(&mut bytes)
        }
        0x04 => {
            let mut bytes = [0_u8; 16];
            session.read_exact(&mut bytes)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported upstream SOCKS5 bound address type",
        )),
    }
}

fn handshake_http(session: &mut dyn TransportSession, target: &Target) -> io::Result<()> {
    let authority = target_authority(target);
    write!(
        session,
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    )?;
    session.flush()?;

    let head = read_http_response_head(session)?;
    let text = std::str::from_utf8(&head).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream HTTP CONNECT response is not UTF-8",
        )
    })?;
    let status_line = text.lines().next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream HTTP CONNECT response has no status line",
        )
    })?;
    let mut fields = status_line.split_whitespace();
    let version = fields.next().unwrap_or_default();
    let status = fields.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream HTTP CONNECT response is not HTTP/1.x",
        ));
    }
    let status: u16 = status.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream HTTP CONNECT status is invalid",
        )
    })?;
    if !(200..300).contains(&status) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("upstream HTTP CONNECT failed with status {status}"),
        ));
    }
    Ok(())
}

fn read_http_response_head(session: &mut dyn TransportSession) -> io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HTTP_RESPONSE_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream HTTP CONNECT response header is too large",
            ));
        }
        session.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    Ok(head)
}

fn target_authority(target: &Target) -> String {
    match &target.host {
        DestinationHost::Ip(IpAddr::V4(address)) => format!("{address}:{}", target.port),
        DestinationHost::Ip(IpAddr::V6(address)) => format!("[{address}]:{}", target.port),
        DestinationHost::Domain(domain) => format!("{domain}:{}", target.port),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn trojan_password_hash_matches_sha224_hex_vector() {
        let protocol = TrojanProtocol::new("password").unwrap();
        assert_eq!(
            protocol.password_hash(),
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[test]
    fn trojan_rejects_plain_tcp_transport() {
        let id = EndpointId::new("trojan").unwrap();
        let result = OutboundRegistry::new(vec![ProxyEndpointConfig {
            id,
            protocol: ProxyProtocol::Trojan(TrojanProtocol::new("secret").unwrap()),
            transport: TransportConfig::Tcp(TcpTransport::new("127.0.0.1:443".parse().unwrap())),
        }]);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_endpoint_capabilities_are_derived_from_transport() {
        let id = EndpointId::new("edge").unwrap();
        let registry = OutboundRegistry::new(vec![ProxyEndpointConfig {
            id: id.clone(),
            protocol: ProxyProtocol::Socks5,
            transport: TransportConfig::Tcp(TcpTransport::new("127.0.0.1:1081".parse().unwrap())),
        }])
        .unwrap();
        let capabilities = registry.capabilities(&Endpoint::Proxy(id)).unwrap();
        assert!(capabilities.supports_tcp());
        assert!(!capabilities.supports_udp());
        assert!(!capabilities.encrypted_transport());
    }

    #[test]
    fn tls_capability_comes_from_transport_not_protocol() {
        let id = EndpointId::new("secure").unwrap();
        let tls = TlsTransport::webpki("127.0.0.1:443".parse().unwrap(), "proxy.example").unwrap();
        let registry = OutboundRegistry::new(vec![ProxyEndpointConfig {
            id: id.clone(),
            protocol: ProxyProtocol::HttpConnect,
            transport: TransportConfig::Tls(tls),
        }])
        .unwrap();
        let capabilities = registry.capabilities(&Endpoint::Proxy(id)).unwrap();
        assert!(capabilities.supports_tcp());
        assert!(!capabilities.supports_udp());
        assert!(capabilities.encrypted_transport());
    }

    #[test]
    fn authority_preserves_domain_and_brackets_ipv6() {
        assert_eq!(
            target_authority(
                &Target::new(DestinationHost::Domain("example.com".to_owned()), 443).unwrap()
            ),
            "example.com:443"
        );
        assert_eq!(
            target_authority(
                &Target::new(DestinationHost::Ip(Ipv6Addr::LOCALHOST.into()), 443).unwrap()
            ),
            "[::1]:443"
        );
        assert_eq!(
            target_authority(
                &Target::new(DestinationHost::Ip(Ipv4Addr::LOCALHOST.into()), 80).unwrap()
            ),
            "127.0.0.1:80"
        );
    }
}
