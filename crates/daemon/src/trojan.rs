use std::{fmt, io, net::IpAddr, ops::Range};

use commeatus_core::DestinationHost;
use sha2::{Digest, Sha224};

use crate::proxy::Target;

pub const TROJAN_VERIFIER_BYTES: usize = 56;
const MAX_TROJAN_PASSWORD_BYTES: usize = 1024;
const TROJAN_CONNECT: u8 = 0x01;
const TROJAN_UDP_ASSOCIATE: u8 = 0x03;

/// Runtime Trojan credential material.
///
/// The raw source password is converted once at the configuration boundary.
/// The SHA-224 hex verifier is credential-equivalent for Trojan authentication,
/// so Debug output deliberately never exposes it.
#[derive(Clone, Eq, PartialEq)]
pub struct TrojanVerifier([u8; TROJAN_VERIFIER_BYTES]);

impl TrojanVerifier {
    pub fn new(password: &str) -> io::Result<Self> {
        if password.is_empty() || password.len() > MAX_TROJAN_PASSWORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Trojan password must contain 1..={MAX_TROJAN_PASSWORD_BYTES} UTF-8 bytes"),
            ));
        }

        let digest = Sha224::digest(password.as_bytes());
        let mut verifier = [0_u8; TROJAN_VERIFIER_BYTES];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (index, byte) in digest.iter().copied().enumerate() {
            verifier[index * 2] = HEX[usize::from(byte >> 4)];
            verifier[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
        }
        Ok(Self(verifier))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; TROJAN_VERIFIER_BYTES] {
        &self.0
    }
}

impl fmt::Debug for TrojanVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrojanVerifier([REDACTED])")
    }
}

pub fn encode_connect_request(verifier: &TrojanVerifier, target: &Target) -> io::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(TROJAN_VERIFIER_BYTES + 2 + 1 + 1 + 253 + 2 + 2);
    request.extend_from_slice(verifier.as_bytes());
    request.extend_from_slice(b"\r\n");
    request.push(TROJAN_CONNECT);
    encode_target(&mut request, target)?;
    request.extend_from_slice(b"\r\n");
    Ok(request)
}

/// Trojan UDP ASSOCIATE preface.
///
/// The official server uses the command to enter UDP forwarding and derives
/// each real destination from subsequent UDP frames. A normalized SOCKS5
/// wildcard target therefore avoids freezing the first datagram target into
/// the association lifetime.
#[must_use]
pub fn encode_udp_associate_request(verifier: &TrojanVerifier) -> Vec<u8> {
    let mut request = Vec::with_capacity(TROJAN_VERIFIER_BYTES + 2 + 1 + 1 + 4 + 2 + 2);
    request.extend_from_slice(verifier.as_bytes());
    request.extend_from_slice(b"\r\n");
    request.push(TROJAN_UDP_ASSOCIATE);
    request.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0]); // IPv4 0.0.0.0:0
    request.extend_from_slice(b"\r\n");
    request
}

pub fn encode_udp_frame(target: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
    let length = u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Trojan UDP payload exceeds 65535-byte wire limit",
        )
    })?;
    let mut frame = Vec::with_capacity(1 + 253 + 2 + 2 + 2 + payload.len());
    encode_target(&mut frame, target)?;
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(b"\r\n");
    frame.extend_from_slice(payload);
    Ok(frame)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedUdpFrame {
    pub source: Target,
    pub payload: Range<usize>,
    pub consumed: usize,
}

/// Parse one Trojan UDP frame from the beginning of `data`.
///
/// `Ok(None)` means the bytes are a valid prefix of a possible frame and more
/// TLS plaintext is required. Structural violations return `InvalidData`.
pub fn parse_udp_frame(data: &[u8]) -> io::Result<Option<ParsedUdpFrame>> {
    let Some((source, address_len)) = parse_target(data)? else {
        return Ok(None);
    };
    if data.len() < address_len + 4 {
        return Ok(None);
    }
    let length = usize::from(u16::from_be_bytes([
        data[address_len],
        data[address_len + 1],
    ]));
    if &data[address_len + 2..address_len + 4] != b"\r\n" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Trojan UDP length is not followed by CRLF",
        ));
    }
    let payload_start = address_len + 4;
    let consumed = payload_start.checked_add(length).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Trojan UDP frame length overflow",
        )
    })?;
    if data.len() < consumed {
        return Ok(None);
    }
    Ok(Some(ParsedUdpFrame {
        source,
        payload: payload_start..consumed,
        consumed,
    }))
}

pub fn encode_target(buffer: &mut Vec<u8>, target: &Target) -> io::Result<()> {
    encode_host(buffer, &target.host)?;
    buffer.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

fn encode_host(buffer: &mut Vec<u8>, host: &DestinationHost) -> io::Result<()> {
    match host {
        DestinationHost::Ip(IpAddr::V4(address)) => {
            buffer.push(0x01);
            buffer.extend_from_slice(&address.octets());
        }
        DestinationHost::Domain(domain) => {
            let length = u8::try_from(domain.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "Trojan domain is too long")
            })?;
            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Trojan domain must not be empty",
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

fn parse_target(data: &[u8]) -> io::Result<Option<(Target, usize)>> {
    let Some(&address_type) = data.first() else {
        return Ok(None);
    };

    let (host, host_end) = match address_type {
        0x01 => {
            if data.len() < 5 {
                return Ok(None);
            }
            (
                DestinationHost::Ip(IpAddr::V4([data[1], data[2], data[3], data[4]].into())),
                5,
            )
        }
        0x03 => {
            if data.len() < 2 {
                return Ok(None);
            }
            let length = usize::from(data[1]);
            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Trojan domain address is empty",
                ));
            }
            let end = 2 + length;
            if data.len() < end {
                return Ok(None);
            }
            let domain = std::str::from_utf8(&data[2..end]).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Trojan domain is not UTF-8")
            })?;
            (DestinationHost::Domain(domain.to_owned()), end)
        }
        0x04 => {
            if data.len() < 17 {
                return Ok(None);
            }
            let octets: [u8; 16] = data[1..17]
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid IPv6 length"))?;
            (DestinationHost::Ip(IpAddr::V6(octets.into())), 17)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported Trojan address type {address_type}"),
            ));
        }
    };

    if data.len() < host_end + 2 {
        return Ok(None);
    }
    let port = u16::from_be_bytes([data[host_end], data[host_end + 1]]);
    let target = Target::new(host, port).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Trojan target: {error}"),
        )
    })?;
    Ok(Some((target, host_end + 2)))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn verifier_matches_sha224_hex_vector_without_debug_leak() {
        let verifier = TrojanVerifier::new("password").unwrap();
        assert_eq!(
            verifier.as_bytes(),
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
        assert_eq!(format!("{verifier:?}"), "TrojanVerifier([REDACTED])");
    }

    #[test]
    fn udp_associate_preface_uses_wildcard_target() {
        let verifier = TrojanVerifier::new("secret").unwrap();
        let request = encode_udp_associate_request(&verifier);
        assert_eq!(&request[..TROJAN_VERIFIER_BYTES], verifier.as_bytes());
        assert_eq!(
            &request[TROJAN_VERIFIER_BYTES..TROJAN_VERIFIER_BYTES + 2],
            b"\r\n"
        );
        assert_eq!(request[TROJAN_VERIFIER_BYTES + 2], TROJAN_UDP_ASSOCIATE);
        assert_eq!(
            &request[TROJAN_VERIFIER_BYTES + 3..],
            &[0x01, 0, 0, 0, 0, 0, 0, b'\r', b'\n']
        );
    }

    #[test]
    fn udp_frame_parser_handles_partial_multiple_and_zero_length_frames() {
        let first = Target::new(DestinationHost::Domain("opaque.invalid".to_owned()), 443).unwrap();
        let second = Target::new(DestinationHost::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)), 53).unwrap();
        let first_wire = encode_udp_frame(&first, b"abc").unwrap();
        let second_wire = encode_udp_frame(&second, b"").unwrap();

        assert!(
            parse_udp_frame(&first_wire[..first_wire.len() - 1])
                .unwrap()
                .is_none()
        );
        let mut joined = first_wire.clone();
        joined.extend_from_slice(&second_wire);

        let parsed = parse_udp_frame(&joined).unwrap().unwrap();
        assert_eq!(parsed.source, first);
        assert_eq!(&joined[parsed.payload.clone()], b"abc");
        assert_eq!(parsed.consumed, first_wire.len());

        let parsed_zero = parse_udp_frame(&joined[parsed.consumed..])
            .unwrap()
            .unwrap();
        assert_eq!(parsed_zero.source, second);
        assert!(parsed_zero.payload.is_empty());
        assert_eq!(parsed_zero.consumed, second_wire.len());
    }

    #[test]
    fn udp_frame_rejects_bad_crlf_and_supports_ipv4() {
        let target =
            Target::new(DestinationHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 5353).unwrap();
        let mut frame = encode_udp_frame(&target, b"payload").unwrap();
        let crlf = 1 + 4 + 2 + 2;
        frame[crlf] = b'X';
        assert_eq!(
            parse_udp_frame(&frame).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
