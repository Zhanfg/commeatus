use std::{fmt, io, net::IpAddr, sync::Arc};

use commeatus_core::DestinationHost;
use commeatus_transport::TransportSession;
use sha2::{Digest, Sha224};

use crate::proxy::Target;

const MAX_HTTP_RESPONSE_HEAD: usize = 16 * 1024;
const MAX_TROJAN_PASSWORD_BYTES: usize = 1024;
const TROJAN_PASSWORD_HASH_BYTES: usize = 56;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolCapabilities {
    pub stream_connect: bool,
    pub requires_tls: bool,
}

pub trait OutboundProtocol: fmt::Debug + Send + Sync {
    fn name(&self) -> &'static str;

    fn capabilities(&self) -> ProtocolCapabilities;

    fn handshake_stream(
        &self,
        session: &mut dyn TransportSession,
        target: &Target,
    ) -> io::Result<()>;
}

pub type ProtocolRef = Arc<dyn OutboundProtocol>;

#[must_use]
pub fn socks5() -> ProtocolRef {
    Arc::new(Socks5Protocol)
}

#[must_use]
pub fn http_connect() -> ProtocolRef {
    Arc::new(HttpConnectProtocol)
}

pub fn trojan(password: &str) -> io::Result<ProtocolRef> {
    Ok(Arc::new(TrojanProtocol::new(password)?))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Socks5Protocol;

impl OutboundProtocol for Socks5Protocol {
    fn name(&self) -> &'static str {
        "socks5"
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities {
            stream_connect: true,
            requires_tls: false,
        }
    }

    fn handshake_stream(
        &self,
        session: &mut dyn TransportSession,
        target: &Target,
    ) -> io::Result<()> {
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
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct HttpConnectProtocol;

impl OutboundProtocol for HttpConnectProtocol {
    fn name(&self) -> &'static str {
        "http-connect"
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities {
            stream_connect: true,
            requires_tls: false,
        }
    }

    fn handshake_stream(
        &self,
        session: &mut dyn TransportSession,
        target: &Target,
    ) -> io::Result<()> {
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TrojanProtocol {
    password_hash: [u8; TROJAN_PASSWORD_HASH_BYTES],
}

impl TrojanProtocol {
    fn new(password: &str) -> io::Result<Self> {
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
}

impl OutboundProtocol for TrojanProtocol {
    fn name(&self) -> &'static str {
        "trojan"
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities {
            stream_connect: true,
            requires_tls: true,
        }
    }

    fn handshake_stream(
        &self,
        session: &mut dyn TransportSession,
        target: &Target,
    ) -> io::Result<()> {
        let mut request = Vec::with_capacity(TROJAN_PASSWORD_HASH_BYTES + 2 + 1 + 1 + 253 + 2 + 2);
        request.extend_from_slice(&self.password_hash);
        request.extend_from_slice(b"\r\n");
        request.push(0x01); // CONNECT
        encode_socks_address(&mut request, &target.host)?;
        request.extend_from_slice(&target.port.to_be_bytes());
        request.extend_from_slice(b"\r\n");
        session.write_all(&request)?;
        session.flush()
    }
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
    fn provider_names_are_stable_native_identifiers() {
        assert_eq!(socks5().name(), "socks5");
        assert_eq!(http_connect().name(), "http-connect");
        assert_eq!(trojan("secret").unwrap().name(), "trojan");
    }

    #[test]
    fn trojan_password_hash_matches_sha224_hex_vector() {
        let protocol = TrojanProtocol::new("password").unwrap();
        assert_eq!(
            &protocol.password_hash,
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[test]
    fn transport_requirements_are_provider_capabilities() {
        assert!(!socks5().capabilities().requires_tls);
        assert!(!http_connect().capabilities().requires_tls);
        assert!(trojan("secret").unwrap().capabilities().requires_tls);
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
