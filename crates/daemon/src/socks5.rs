use std::{
    collections::HashSet,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket},
    sync::Arc,
    time::{Duration, Instant},
};

use commeatus_core::{DestinationHost, Runtime, TransportProtocol};
use commeatus_dns::DnsEngine;

use crate::proxy::{self, Authorization, Target};

const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_UNACCEPTABLE: u8 = 0xff;
const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_UDP_ASSOCIATE: u8 = 0x03;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_POLL_TIMEOUT: Duration = Duration::from_millis(500);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_UDP_PACKET: usize = 65_535;
const MAX_UDP_REMOTE_PEERS: usize = 256;

pub fn handle(mut client: TcpStream, runtime: Arc<Runtime>, dns: Arc<DnsEngine>) -> io::Result<()> {
    client.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    client.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    negotiate_method(&mut client)?;
    match read_request(&mut client)? {
        Request::Connect(target) => handle_connect(client, runtime, dns, target),
        Request::UdpAssociate(hint) => handle_udp_associate(client, runtime, dns, hint),
    }
}

fn handle_connect(
    mut client: TcpStream,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    target: Target,
) -> io::Result<()> {
    if proxy::authorize(&runtime, &target, TransportProtocol::Tcp) == Authorization::Reject {
        write_reply(&mut client, 0x02, None)?;
        return Ok(());
    }

    let remote = match proxy::connect_direct(&target, &dns) {
        Ok(remote) => remote,
        Err(error) => {
            let code = connect_error_code(&error);
            let _ = write_reply(&mut client, code, None);
            return Err(error);
        }
    };

    write_reply(&mut client, 0x00, remote.local_addr().ok())?;
    client.set_read_timeout(None)?;
    client.set_write_timeout(None)?;
    proxy::relay(client, remote)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Request {
    Connect(Target),
    UdpAssociate(UdpClientHint),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct UdpClientHint {
    ip: Option<IpAddr>,
    port: Option<u16>,
}

fn negotiate_method(stream: &mut TcpStream) -> io::Result<()> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header)?;
    if header[0] != VERSION || header[1] == 0 {
        return Err(invalid_data("invalid SOCKS5 greeting"));
    }

    let mut methods = vec![0_u8; usize::from(header[1])];
    stream.read_exact(&mut methods)?;
    if methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[VERSION, METHOD_NO_AUTH])?;
        Ok(())
    } else {
        stream.write_all(&[VERSION, METHOD_UNACCEPTABLE])?;
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 client did not offer no-auth method",
        ))
    }
}

fn read_request(stream: &mut TcpStream) -> io::Result<Request> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != VERSION || header[2] != 0 {
        return Err(invalid_data("invalid SOCKS5 request header"));
    }

    let (host, port) = read_address(stream, header[3])?;
    match header[1] {
        COMMAND_CONNECT => Ok(Request::Connect(Target::new(host, port)?)),
        COMMAND_UDP_ASSOCIATE => Ok(Request::UdpAssociate(UdpClientHint {
            ip: match host {
                DestinationHost::Ip(address) if !address.is_unspecified() => Some(address),
                _ => None,
            },
            port: (port != 0).then_some(port),
        })),
        _ => {
            write_reply(stream, 0x07, None)?;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SOCKS5 command is not CONNECT or UDP ASSOCIATE",
            ))
        }
    }
}

fn read_address(stream: &mut TcpStream, address_type: u8) -> io::Result<(DestinationHost, u16)> {
    let host = match address_type {
        0x01 => {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes)?;
            DestinationHost::Ip(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        0x03 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length)?;
            let length = usize::from(length[0]);
            if length == 0 || length > 253 {
                return Err(invalid_data("invalid SOCKS5 domain length"));
            }
            let mut bytes = vec![0_u8; length];
            stream.read_exact(&mut bytes)?;
            let domain = std::str::from_utf8(&bytes)
                .map_err(|_| invalid_data("SOCKS5 domain is not UTF-8"))?
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if domain.is_empty() {
                return Err(invalid_data("empty SOCKS5 domain"));
            }
            DestinationHost::Domain(domain)
        }
        0x04 => {
            let mut bytes = [0_u8; 16];
            stream.read_exact(&mut bytes)?;
            DestinationHost::Ip(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => return Err(invalid_data("unsupported SOCKS5 address type")),
    };

    let mut port = [0_u8; 2];
    stream.read_exact(&mut port)?;
    Ok((host, u16::from_be_bytes(port)))
}

fn handle_udp_associate(
    mut control: TcpStream,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    hint: UdpClientHint,
) -> io::Result<()> {
    let control_peer = control.peer_addr()?;
    if hint.ip.is_some_and(|address| address != control_peer.ip()) {
        write_reply(&mut control, 0x02, None)?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 UDP client hint does not match TCP control peer",
        ));
    }

    let bind_ip = control.local_addr()?.ip();
    let relay = UdpSocket::bind(SocketAddr::new(bind_ip, 0))?;
    relay.set_read_timeout(Some(UDP_POLL_TIMEOUT))?;
    let relay_address = relay.local_addr()?;
    write_reply(&mut control, 0x00, Some(relay_address))?;

    control.set_read_timeout(None)?;
    control.set_write_timeout(None)?;
    control.set_nonblocking(true)?;

    let mut client_address = hint
        .port
        .map(|port| SocketAddr::new(control_peer.ip(), port));
    let mut remote_peers = HashSet::new();
    let mut packet = vec![0_u8; MAX_UDP_PACKET];
    let mut last_activity = Instant::now();

    loop {
        if control_is_closed(&control)? || last_activity.elapsed() >= UDP_IDLE_TIMEOUT {
            return Ok(());
        }

        match relay.recv_from(&mut packet) {
            Ok((length, source)) => {
                last_activity = Instant::now();
                if is_client_packet(source, control_peer.ip(), client_address) {
                    if client_address.is_none() {
                        client_address = Some(source);
                    }
                    handle_udp_client_packet(
                        &relay,
                        &runtime,
                        &dns,
                        &packet[..length],
                        &mut remote_peers,
                    );
                } else if remote_peers.contains(&source) {
                    if let Some(client) = client_address {
                        let response = encode_udp_response(source, &packet[..length]);
                        let _ = relay.send_to(&response, client);
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn control_is_closed(control: &TcpStream) -> io::Result<bool> {
    let mut byte = [0_u8; 1];
    match control.peek(&mut byte) {
        Ok(0) => Ok(true),
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
        Err(error) => Err(error),
    }
}

fn is_client_packet(source: SocketAddr, control_ip: IpAddr, client: Option<SocketAddr>) -> bool {
    client.map_or(source.ip() == control_ip, |client| source == client)
}

fn handle_udp_client_packet(
    relay: &UdpSocket,
    runtime: &Runtime,
    dns: &DnsEngine,
    packet: &[u8],
    remote_peers: &mut HashSet<SocketAddr>,
) {
    let Ok((target, payload)) = parse_udp_request(packet) else {
        return;
    };
    if proxy::authorize(runtime, &target, TransportProtocol::Udp) == Authorization::Reject {
        return;
    }

    let Ok(addresses) = proxy::resolve_target(&target, dns) else {
        return;
    };
    for address in addresses {
        if !remote_peers.contains(&address) && remote_peers.len() >= MAX_UDP_REMOTE_PEERS {
            return;
        }
        if relay.send_to(payload, address).is_ok() {
            remote_peers.insert(address);
            return;
        }
    }
}

fn parse_udp_request(packet: &[u8]) -> io::Result<(Target, &[u8])> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 {
        return Err(invalid_data("invalid SOCKS5 UDP reserved field"));
    }
    if packet[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SOCKS5 UDP fragmentation is not supported",
        ));
    }

    let address_type = packet[3];
    let mut offset = 4;
    let host = match address_type {
        0x01 => {
            let bytes = packet
                .get(offset..offset + 4)
                .ok_or_else(|| invalid_data("truncated SOCKS5 UDP IPv4 address"))?;
            offset += 4;
            DestinationHost::Ip(IpAddr::V4(Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )))
        }
        0x03 => {
            let length = usize::from(
                *packet
                    .get(offset)
                    .ok_or_else(|| invalid_data("truncated SOCKS5 UDP domain length"))?,
            );
            offset += 1;
            if length == 0 || length > 253 {
                return Err(invalid_data("invalid SOCKS5 UDP domain length"));
            }
            let bytes = packet
                .get(offset..offset + length)
                .ok_or_else(|| invalid_data("truncated SOCKS5 UDP domain"))?;
            offset += length;
            let domain = std::str::from_utf8(bytes)
                .map_err(|_| invalid_data("SOCKS5 UDP domain is not UTF-8"))?
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if domain.is_empty() {
                return Err(invalid_data("empty SOCKS5 UDP domain"));
            }
            DestinationHost::Domain(domain)
        }
        0x04 => {
            let bytes = packet
                .get(offset..offset + 16)
                .ok_or_else(|| invalid_data("truncated SOCKS5 UDP IPv6 address"))?;
            offset += 16;
            let mut address = [0_u8; 16];
            address.copy_from_slice(bytes);
            DestinationHost::Ip(IpAddr::V6(Ipv6Addr::from(address)))
        }
        _ => return Err(invalid_data("unsupported SOCKS5 UDP address type")),
    };

    let port_bytes = packet
        .get(offset..offset + 2)
        .ok_or_else(|| invalid_data("truncated SOCKS5 UDP port"))?;
    offset += 2;
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    let target = Target::new(host, port)?;
    let payload = packet
        .get(offset..)
        .ok_or_else(|| invalid_data("truncated SOCKS5 UDP payload"))?;
    Ok((target, payload))
}

fn encode_udp_response(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(22 + payload.len());
    response.extend_from_slice(&[0x00, 0x00, 0x00]);
    match source {
        SocketAddr::V4(address) => {
            response.push(0x01);
            response.extend_from_slice(&address.ip().octets());
            response.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            response.push(0x04);
            response.extend_from_slice(&address.ip().octets());
            response.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    response.extend_from_slice(payload);
    response
}

fn write_reply(stream: &mut TcpStream, code: u8, address: Option<SocketAddr>) -> io::Result<()> {
    match address.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))) {
        SocketAddr::V4(address) => {
            let mut reply = Vec::with_capacity(10);
            reply.extend_from_slice(&[VERSION, code, 0x00, 0x01]);
            reply.extend_from_slice(&address.ip().octets());
            reply.extend_from_slice(&address.port().to_be_bytes());
            stream.write_all(&reply)
        }
        SocketAddr::V6(address) => {
            let mut reply = Vec::with_capacity(22);
            reply.extend_from_slice(&[VERSION, code, 0x00, 0x04]);
            reply.extend_from_slice(&address.ip().octets());
            reply.extend_from_slice(&address.port().to_be_bytes());
            stream.write_all(&reply)
        }
    }
}

fn connect_error_code(error: &io::Error) -> u8 {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => 0x05,
        io::ErrorKind::TimedOut => 0x04,
        io::ErrorKind::PermissionDenied => 0x02,
        io::ErrorKind::NotFound | io::ErrorKind::AddrNotAvailable => 0x04,
        _ => 0x01,
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_parser_rejects_fragmentation() {
        let packet = [0x00, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0, 53];
        assert_eq!(
            parse_udp_request(&packet).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn udp_parser_preserves_domain_identity() {
        let mut packet = vec![0x00, 0x00, 0x00, 0x03, 11];
        packet.extend_from_slice(b"example.com");
        packet.extend_from_slice(&53_u16.to_be_bytes());
        packet.extend_from_slice(b"dns");
        let (target, payload) = parse_udp_request(&packet).unwrap();
        assert_eq!(
            target.host,
            DestinationHost::Domain("example.com".to_owned())
        );
        assert_eq!(target.port, 53);
        assert_eq!(payload, b"dns");
    }

    #[test]
    fn udp_response_encodes_remote_source() {
        let response = encode_udp_response("127.0.0.1:5353".parse().unwrap(), b"reply");
        assert_eq!(&response[..4], &[0, 0, 0, 1]);
        assert_eq!(&response[4..8], &[127, 0, 0, 1]);
        assert_eq!(&response[8..10], &5353_u16.to_be_bytes());
        assert_eq!(&response[10..], b"reply");
    }
}
