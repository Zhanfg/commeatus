use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket},
    sync::Arc,
    time::{Duration, Instant},
};

use commeatus_core::{DestinationHost, ExecutionAction, Runtime, TransportProtocol};
use commeatus_dns::DnsEngine;
use mio::{
    Events, Interest, Poll, Token,
    event::Event,
    net::{TcpStream as MioTcpStream, UdpSocket as MioUdpSocket},
};

use crate::{
    datagram::DatagramRouteSet,
    outbound::{EndpointCapabilities, OutboundRegistry},
    proxy::{self, Target},
};

const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_UNACCEPTABLE: u8 = 0xff;
const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_UDP_ASSOCIATE: u8 = 0x03;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_UDP_PACKET: usize = 65_535;
const MAX_UDP_EVENT_BURST: usize = 32;
const MAX_PENDING_CLIENT_REPLIES: usize = 64;
const UDP_CONTROL_TOKEN: Token = Token(0);
const UDP_CLIENT_TOKEN: Token = Token(1);
const UDP_OUTBOUND_FIRST_TOKEN: Token = Token(2);

pub fn handle(
    mut client: TcpStream,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
) -> io::Result<()> {
    client.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    client.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    negotiate_method(&mut client)?;
    match read_request(&mut client)? {
        Request::Connect(target) => handle_connect(client, runtime, dns, outbounds, target),
        Request::UdpAssociate(hint) => handle_udp_associate(client, runtime, dns, outbounds, hint),
    }
}

fn handle_connect(
    mut client: TcpStream,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
    target: Target,
) -> io::Result<()> {
    let endpoint = match proxy::plan_action(&runtime, &target, TransportProtocol::Tcp) {
        ExecutionAction::Reject { .. } => {
            write_reply(&mut client, 0x02, None)?;
            return Ok(());
        }
        ExecutionAction::Route { endpoint } => endpoint,
    };

    let remote = match outbounds.connect_tcp(&endpoint, &target, &dns) {
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
    remote.relay_to_client(client)
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
                commeatus_core::DestinationHost::Ip(address) if !address.is_unspecified() => {
                    Some(address)
                }
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

fn read_address(
    stream: &mut TcpStream,
    address_type: u8,
) -> io::Result<(commeatus_core::DestinationHost, u16)> {
    let host = match address_type {
        0x01 => {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes)?;
            commeatus_core::DestinationHost::Ip(IpAddr::V4(Ipv4Addr::from(bytes)))
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
            commeatus_core::DestinationHost::Domain(domain)
        }
        0x04 => {
            let mut bytes = [0_u8; 16];
            stream.read_exact(&mut bytes)?;
            commeatus_core::DestinationHost::Ip(IpAddr::V6(Ipv6Addr::from(bytes)))
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
    outbounds: Arc<OutboundRegistry>,
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
    let relay_address = relay.local_addr()?;
    write_reply(&mut control, 0x00, Some(relay_address))?;

    control.set_read_timeout(None)?;
    control.set_write_timeout(None)?;
    control.set_nonblocking(true)?;
    relay.set_nonblocking(true)?;

    let mut control = MioTcpStream::from_std(control);
    let mut relay = MioUdpSocket::from_std(relay);
    let mut poll = Poll::new()?;
    poll.registry()
        .register(&mut control, UDP_CONTROL_TOKEN, Interest::READABLE)?;
    poll.registry()
        .register(&mut relay, UDP_CLIENT_TOKEN, Interest::READABLE)?;
    let mut routes = DatagramRouteSet::new(UDP_OUTBOUND_FIRST_TOKEN);

    let mut events = Events::with_capacity(16);
    let mut client_address = hint
        .port
        .map(|port| SocketAddr::new(control_peer.ip(), port));
    let mut client_packet = vec![0_u8; MAX_UDP_PACKET];
    let mut remote_packet = vec![0_u8; MAX_UDP_PACKET];
    let mut pending_replies = VecDeque::new();
    let mut relay_writable = false;
    let mut last_activity = Instant::now();

    loop {
        let remaining = UDP_IDLE_TIMEOUT.saturating_sub(last_activity.elapsed());
        if remaining.is_zero() {
            return Ok(());
        }

        match poll.poll(&mut events, Some(remaining)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
        if events.is_empty() {
            return Ok(());
        }

        // The TCP control connection owns SOCKS5 UDP association lifetime.
        // Handle it before any datagram event from the same poll batch.
        for event in events
            .iter()
            .filter(|event| event.token() == UDP_CONTROL_TOKEN)
        {
            if control_event_is_closed(&mut control, event)? {
                return Ok(());
            }
        }

        let client_readable = events
            .iter()
            .any(|event| event.token() == UDP_CLIENT_TOKEN && event.is_readable());
        let client_writable = events
            .iter()
            .any(|event| event.token() == UDP_CLIENT_TOKEN && event.is_writable());
        let outbound_ready = events
            .iter()
            .filter(|event| routes.owns_token(event.token()))
            .map(|event| event.token())
            .collect::<Vec<_>>();

        if client_readable {
            for _ in 0..MAX_UDP_EVENT_BURST {
                match relay.recv_from(&mut client_packet) {
                    Ok((length, source)) => {
                        if !is_client_packet(source, control_peer.ip(), client_address) {
                            continue;
                        }
                        if handle_udp_client_packet(
                            &mut routes,
                            poll.registry(),
                            &runtime,
                            &dns,
                            &outbounds,
                            &client_packet[..length],
                        ) {
                            if client_address.is_none() {
                                client_address = Some(source);
                            }
                            last_activity = Instant::now();
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
        }

        for token in outbound_ready {
            for _ in 0..MAX_UDP_EVENT_BURST {
                let Some(received) = routes.receive_ready(token, &mut remote_packet)? else {
                    break;
                };
                let Some(client) = client_address else {
                    continue;
                };
                let response =
                    encode_udp_response(&received.source, &remote_packet[..received.length])?;
                if send_or_queue_client_reply(&relay, &mut pending_replies, response, client) {
                    last_activity = Instant::now();
                }
            }
        }

        if client_writable && flush_pending_client_replies(&relay, &mut pending_replies) {
            last_activity = Instant::now();
        }

        let wants_writable = !pending_replies.is_empty();
        if wants_writable != relay_writable {
            let interest = if wants_writable {
                Interest::READABLE.add(Interest::WRITABLE)
            } else {
                Interest::READABLE
            };
            poll.registry()
                .reregister(&mut relay, UDP_CLIENT_TOKEN, interest)?;
            relay_writable = wants_writable;
        }
    }
}

fn control_event_is_closed(control: &mut MioTcpStream, event: &Event) -> io::Result<bool> {
    if event.is_read_closed() || event.is_error() {
        return Ok(true);
    }
    if !event.is_readable() {
        return Ok(false);
    }

    let mut scratch = [0_u8; 256];
    for _ in 0..4 {
        match control.read(&mut scratch) {
            Ok(0) => return Ok(true),
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::NotConnected
                ) =>
            {
                return Ok(true);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn is_client_packet(source: SocketAddr, control_ip: IpAddr, client: Option<SocketAddr>) -> bool {
    client.map_or(source.ip() == control_ip, |client| source == client)
}

fn handle_udp_client_packet(
    routes: &mut DatagramRouteSet,
    registry: &mio::Registry,
    runtime: &Runtime,
    dns: &Arc<DnsEngine>,
    outbounds: &OutboundRegistry,
    packet: &[u8],
) -> bool {
    let Ok((target, payload)) = parse_udp_request(packet) else {
        return false;
    };

    let endpoint = match proxy::plan_action(runtime, &target, TransportProtocol::Udp) {
        ExecutionAction::Reject { .. } => return false,
        ExecutionAction::Route { endpoint } => endpoint,
    };

    if !outbounds
        .capabilities(&endpoint)
        .is_some_and(EndpointCapabilities::supports_udp)
    {
        return false;
    }

    routes
        .send_with(endpoint, &target, payload, registry, |endpoint| {
            outbounds.open_datagram(endpoint, Arc::clone(dns))
        })
        .is_ok()
}

fn send_or_queue_client_reply(
    relay: &MioUdpSocket,
    pending: &mut VecDeque<(Vec<u8>, SocketAddr)>,
    packet: Vec<u8>,
    client: SocketAddr,
) -> bool {
    match relay.send_to(&packet, client) {
        Ok(sent) if sent == packet.len() => true,
        Ok(_) => false,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            if pending.len() >= MAX_PENDING_CLIENT_REPLIES {
                return false;
            }
            pending.push_back((packet, client));
            true
        }
        Err(_) => false,
    }
}

fn flush_pending_client_replies(
    relay: &MioUdpSocket,
    pending: &mut VecDeque<(Vec<u8>, SocketAddr)>,
) -> bool {
    let mut sent_any = false;
    while let Some((packet, client)) = pending.front() {
        match relay.send_to(packet, *client) {
            Ok(sent) if sent == packet.len() => {
                pending.pop_front();
                sent_any = true;
            }
            Ok(_) => {
                pending.pop_front();
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                pending.pop_front();
            }
        }
    }
    sent_any
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
            commeatus_core::DestinationHost::Ip(IpAddr::V4(Ipv4Addr::new(
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
            commeatus_core::DestinationHost::Domain(domain)
        }
        0x04 => {
            let bytes = packet
                .get(offset..offset + 16)
                .ok_or_else(|| invalid_data("truncated SOCKS5 UDP IPv6 address"))?;
            offset += 16;
            let mut address = [0_u8; 16];
            address.copy_from_slice(bytes);
            commeatus_core::DestinationHost::Ip(IpAddr::V6(Ipv6Addr::from(address)))
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

fn encode_udp_response(source: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut response = Vec::with_capacity(22 + payload.len());
    response.extend_from_slice(&[0x00, 0x00, 0x00]);
    match &source.host {
        DestinationHost::Ip(IpAddr::V4(address)) => {
            response.push(0x01);
            response.extend_from_slice(&address.octets());
        }
        DestinationHost::Ip(IpAddr::V6(address)) => {
            response.push(0x04);
            response.extend_from_slice(&address.octets());
        }
        DestinationHost::Domain(domain) => {
            let length = u8::try_from(domain.len())
                .map_err(|_| invalid_data("SOCKS5 UDP response domain is too long"))?;
            if length == 0 {
                return Err(invalid_data("SOCKS5 UDP response domain is empty"));
            }
            response.push(0x03);
            response.push(length);
            response.extend_from_slice(domain.as_bytes());
        }
    }
    response.extend_from_slice(&source.port.to_be_bytes());
    response.extend_from_slice(payload);
    Ok(response)
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
        io::ErrorKind::Unsupported => 0x07,
        _ => 0x01,
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use commeatus_core::{DestinationHost, Endpoint};

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
        let source =
            Target::new(DestinationHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 5353).unwrap();
        let response = encode_udp_response(&source, b"reply").unwrap();
        assert_eq!(&response[..4], &[0, 0, 0, 1]);
        assert_eq!(&response[4..8], &[127, 0, 0, 1]);
        assert_eq!(&response[8..10], &5353_u16.to_be_bytes());
        assert_eq!(&response[10..], b"reply");
    }

    fn direct_runtime() -> Arc<Runtime> {
        Arc::new(Runtime::new(commeatus_core::PolicyEngine::new(
            Vec::new(),
            commeatus_core::PolicyAction::Route(Endpoint::Direct),
        )))
    }

    fn test_dns() -> Arc<DnsEngine> {
        Arc::new(DnsEngine::system(commeatus_dns::HostsTable::default()))
    }

    fn spawn_udp_test_server(
        runtime: Arc<Runtime>,
        outbounds: Arc<OutboundRegistry>,
    ) -> (
        SocketAddr,
        std::sync::mpsc::Receiver<io::Result<()>>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let (client, _) = listener.accept().unwrap();
            let result = handle(client, runtime, test_dns(), outbounds);
            let _ = result_tx.send(result);
        });
        (address, result_rx, thread)
    }

    fn establish_udp_association(server: SocketAddr) -> (TcpStream, SocketAddr) {
        let mut control = TcpStream::connect(server).unwrap();
        control
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        control
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        control.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut method = [0_u8; 2];
        control.read_exact(&mut method).unwrap();
        assert_eq!(method, [0x05, 0x00]);

        control
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .unwrap();
        let mut header = [0_u8; 4];
        control.read_exact(&mut header).unwrap();
        assert_eq!(&header[..3], &[0x05, 0x00, 0x00]);
        let relay = match header[3] {
            0x01 => {
                let mut address = [0_u8; 4];
                let mut port = [0_u8; 2];
                control.read_exact(&mut address).unwrap();
                control.read_exact(&mut port).unwrap();
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(address)),
                    u16::from_be_bytes(port),
                )
            }
            0x04 => {
                let mut address = [0_u8; 16];
                let mut port = [0_u8; 2];
                control.read_exact(&mut address).unwrap();
                control.read_exact(&mut port).unwrap();
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(address)),
                    u16::from_be_bytes(port),
                )
            }
            other => panic!("unexpected UDP relay address type {other}"),
        };
        (control, relay)
    }

    #[test]
    fn udp_associate_round_trip_uses_direct_datagram_association() {
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        echo.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let echo_address = echo.local_addr().unwrap();
        let echo_thread = std::thread::spawn(move || {
            let mut packet = [0_u8; 128];
            let (length, client) = echo.recv_from(&mut packet).unwrap();
            assert_eq!(&packet[..length], b"udp-through-association");
            echo.send_to(&packet[..length], client).unwrap();
        });

        let (server, result_rx, server_thread) =
            spawn_udp_test_server(direct_runtime(), Arc::new(OutboundRegistry::default()));
        let (control, relay) = establish_udp_association(server);
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let target =
            Target::new(DestinationHost::Ip(echo_address.ip()), echo_address.port()).unwrap();
        let request = encode_udp_response(&target, b"udp-through-association").unwrap();
        client.send_to(&request, relay).unwrap();

        let mut response = [0_u8; 256];
        let (length, _) = client.recv_from(&mut response).unwrap();
        let (source, payload) = parse_udp_request(&response[..length]).unwrap();
        assert_eq!(source.host, DestinationHost::Ip(echo_address.ip()));
        assert_eq!(source.port, echo_address.port());
        assert_eq!(payload, b"udp-through-association");

        drop(control);
        assert!(
            result_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .is_ok()
        );
        server_thread.join().unwrap();
        echo_thread.join().unwrap();
    }

    #[test]
    fn proxy_udp_route_never_falls_back_to_direct() {
        let sink = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        sink.set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let sink_address = sink.local_addr().unwrap();
        let proxy_id = commeatus_core::EndpointId::new("missing-udp-proxy").unwrap();
        let runtime = Arc::new(Runtime::new(commeatus_core::PolicyEngine::new(
            Vec::new(),
            commeatus_core::PolicyAction::Route(Endpoint::Proxy(proxy_id)),
        )));
        let (server, result_rx, server_thread) =
            spawn_udp_test_server(runtime, Arc::new(OutboundRegistry::default()));
        let (control, relay) = establish_udp_association(server);
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target =
            Target::new(DestinationHost::Ip(sink_address.ip()), sink_address.port()).unwrap();
        let request = encode_udp_response(&target, b"must-not-fall-through").unwrap();
        client.send_to(&request, relay).unwrap();

        let mut packet = [0_u8; 64];
        let error = sink.recv_from(&mut packet).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));

        drop(control);
        assert!(
            result_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .is_ok()
        );
        server_thread.join().unwrap();
    }

    #[test]
    fn closing_udp_control_connection_wakes_executor() {
        let (server, result_rx, server_thread) =
            spawn_udp_test_server(direct_runtime(), Arc::new(OutboundRegistry::default()));
        let (control, _relay) = establish_udp_association(server);
        drop(control);

        assert!(
            result_rx
                .recv_timeout(Duration::from_millis(400))
                .expect("readiness executor did not observe TCP control close")
                .is_ok()
        );
        server_thread.join().unwrap();
    }
}
