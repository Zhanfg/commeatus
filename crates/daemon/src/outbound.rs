use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    time::Duration,
};

use commeatus_core::{DestinationHost, Endpoint, EndpointId};
use commeatus_dns::DnsEngine;

use crate::proxy::{self, Target};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HTTP_RESPONSE_HEAD: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyProtocol {
    Socks5,
    HttpConnect,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyEndpointConfig {
    pub id: EndpointId,
    pub protocol: ProxyProtocol,
    pub address: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointCapabilities {
    tcp: bool,
    udp: bool,
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
}

#[derive(Clone, Debug, Default)]
pub struct OutboundRegistry {
    endpoints: HashMap<EndpointId, ProxyEndpointConfig>,
}

impl OutboundRegistry {
    pub fn new(endpoints: Vec<ProxyEndpointConfig>) -> Result<Self, io::Error> {
        let mut registry = HashMap::with_capacity(endpoints.len());
        for endpoint in endpoints {
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
            }),
            Endpoint::Proxy(id) => self.endpoints.get(id).map(|config| match config.protocol {
                ProxyProtocol::Socks5 | ProxyProtocol::HttpConnect => EndpointCapabilities {
                    tcp: true,
                    udp: false,
                },
            }),
        }
    }

    pub fn connect_tcp(
        &self,
        endpoint: &Endpoint,
        target: &Target,
        dns: &DnsEngine,
    ) -> io::Result<TcpStream> {
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
            Endpoint::Direct => proxy::connect_direct(target, dns),
            Endpoint::Proxy(id) => {
                let config = self.endpoints.get(id).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("proxy endpoint `{}` is not registered", id.as_str()),
                    )
                })?;
                match config.protocol {
                    ProxyProtocol::Socks5 => connect_socks5(config.address, target),
                    ProxyProtocol::HttpConnect => connect_http(config.address, target),
                }
            }
        }
    }
}

fn connect_upstream(address: SocketAddr) -> io::Result<TcpStream> {
    let stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    Ok(stream)
}

fn finish_handshake(stream: TcpStream) -> io::Result<TcpStream> {
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok(stream)
}

fn connect_socks5(upstream: SocketAddr, target: &Target) -> io::Result<TcpStream> {
    let mut stream = connect_upstream(upstream)?;
    stream.write_all(&[0x05, 0x01, 0x00])?;
    stream.flush()?;
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method)?;
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
    stream.write_all(&request)?;
    stream.flush()?;

    let mut reply = [0_u8; 4];
    stream.read_exact(&mut reply)?;
    if reply[0] != 0x05 || reply[2] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid upstream SOCKS5 CONNECT reply",
        ));
    }
    if reply[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("upstream SOCKS5 CONNECT failed with reply code {}", reply[1]),
        ));
    }
    discard_socks_address(&mut stream, reply[3])?;
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port)?;
    finish_handshake(stream)
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

fn discard_socks_address(stream: &mut TcpStream, address_type: u8) -> io::Result<()> {
    match address_type {
        0x01 => {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes)
        }
        0x03 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length)?;
            let mut bytes = vec![0_u8; usize::from(length[0])];
            stream.read_exact(&mut bytes)
        }
        0x04 => {
            let mut bytes = [0_u8; 16];
            stream.read_exact(&mut bytes)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported upstream SOCKS5 bound address type",
        )),
    }
}

fn connect_http(upstream: SocketAddr, target: &Target) -> io::Result<TcpStream> {
    let mut stream = connect_upstream(upstream)?;
    let authority = target_authority(target);
    write!(
        stream,
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    )?;
    stream.flush()?;

    let head = read_http_response_head(&mut stream)?;
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
    finish_handshake(stream)
}

fn read_http_response_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HTTP_RESPONSE_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream HTTP CONNECT response header is too large",
            ));
        }
        stream.read_exact(&mut byte)?;
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
    fn proxy_endpoint_capabilities_do_not_claim_udp_yet() {
        let id = EndpointId::new("edge").unwrap();
        let registry = OutboundRegistry::new(vec![ProxyEndpointConfig {
            id: id.clone(),
            protocol: ProxyProtocol::Socks5,
            address: "127.0.0.1:1081".parse().unwrap(),
        }])
        .unwrap();
        let capabilities = registry.capabilities(&Endpoint::Proxy(id)).unwrap();
        assert!(capabilities.supports_tcp());
        assert!(!capabilities.supports_udp());
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
