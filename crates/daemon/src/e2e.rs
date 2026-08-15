use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::Arc,
    thread,
    time::Duration,
};

use commeatus_core::{
    Endpoint, Matcher, PolicyAction, PolicyEngine, PolicyRule, PolicyTier, RejectReason, RuleId,
    Runtime,
};
use commeatus_dns::{DnsEngine, HostsTable};

use crate::{
    config::ListenerProtocol,
    server::{spawn_test_listener, spawn_test_listener_with_dns},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const HOSTS_ONLY_NAME: &str = "commeatus-dns.test";

fn direct_runtime() -> Arc<Runtime> {
    Arc::new(Runtime::new(PolicyEngine::new(
        Vec::new(),
        PolicyAction::Route(Endpoint::Direct),
    )))
}

fn hosts_dns() -> Arc<DnsEngine> {
    let hosts = HostsTable::parse(&format!("127.0.0.1 {HOSTS_ONLY_NAME}\n")).unwrap();
    Arc::new(DnsEngine::system(hosts))
}

fn spawn_echo_server() -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(TEST_TIMEOUT))?;
        stream.set_write_timeout(Some(TEST_TIMEOUT))?;
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            stream.write_all(&buffer[..read])?;
        }
        Ok(())
    });
    Ok((address, handle))
}

fn spawn_udp_echo_server() -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    socket.set_read_timeout(Some(TEST_TIMEOUT))?;
    socket.set_write_timeout(Some(TEST_TIMEOUT))?;
    let address = socket.local_addr()?;
    let handle = thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        let (length, peer) = socket.recv_from(&mut buffer)?;
        socket.send_to(&buffer[..length], peer)?;
        Ok(())
    });
    Ok((address, handle))
}

fn negotiate_socks5(proxy: SocketAddr) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy)?;
    stream.set_read_timeout(Some(TEST_TIMEOUT))?;
    stream.set_write_timeout(Some(TEST_TIMEOUT))?;
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method)?;
    if method != [0x05, 0x00] {
        return Err(io::Error::other("unexpected SOCKS5 method reply"));
    }
    Ok(stream)
}

fn read_socks5_reply(stream: &mut TcpStream) -> io::Result<(u8, SocketAddr)> {
    let mut head = [0_u8; 4];
    stream.read_exact(&mut head)?;
    let reply_code = head[1];
    let address = match head[3] {
        0x01 => {
            let mut tail = [0_u8; 6];
            stream.read_exact(&mut tail)?;
            SocketAddr::from((
                Ipv4Addr::new(tail[0], tail[1], tail[2], tail[3]),
                u16::from_be_bytes([tail[4], tail[5]]),
            ))
        }
        0x04 => {
            let mut tail = [0_u8; 18];
            stream.read_exact(&mut tail)?;
            let mut address = [0_u8; 16];
            address.copy_from_slice(&tail[..16]);
            SocketAddr::new(
                std::net::Ipv6Addr::from(address).into(),
                u16::from_be_bytes([tail[16], tail[17]]),
            )
        }
        other => {
            return Err(io::Error::other(format!(
                "unexpected SOCKS5 reply address type {other}"
            )));
        }
    };
    Ok((reply_code, address))
}

fn connect_socks5(proxy: SocketAddr, target: SocketAddr) -> io::Result<(TcpStream, u8)> {
    let mut stream = negotiate_socks5(proxy)?;
    let SocketAddr::V4(target) = target else {
        return Err(io::Error::other("test target must be IPv4"));
    };
    let mut request = Vec::with_capacity(10);
    request.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]);
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request)?;
    let (reply, _) = read_socks5_reply(&mut stream)?;
    Ok((stream, reply))
}

fn connect_socks5_domain(
    proxy: SocketAddr,
    domain: &str,
    port: u16,
) -> io::Result<(TcpStream, u8)> {
    if domain.is_empty() || domain.len() > u8::MAX as usize {
        return Err(io::Error::other("test domain length is invalid"));
    }
    let mut stream = negotiate_socks5(proxy)?;
    let mut request = Vec::with_capacity(7 + domain.len());
    request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, domain.len() as u8]);
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request)?;
    let (reply, _) = read_socks5_reply(&mut stream)?;
    Ok((stream, reply))
}

fn associate_socks5_udp(proxy: SocketAddr) -> io::Result<(TcpStream, SocketAddr)> {
    let mut stream = negotiate_socks5(proxy)?;
    stream.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
    let (reply, relay) = read_socks5_reply(&mut stream)?;
    if reply != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS5 UDP ASSOCIATE failed with reply {reply}"
        )));
    }
    Ok((stream, relay))
}

fn read_http_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
        if head.len() > 16 * 1024 {
            return Err(io::Error::other("HTTP response header too large"));
        }
    }
    Ok(head)
}

#[test]
fn socks5_connect_relays_bytes_end_to_end() {
    let (echo_address, echo_thread) = spawn_echo_server().unwrap();
    let (proxy_address, proxy_thread) =
        spawn_test_listener(ListenerProtocol::Socks5, direct_runtime(), 1).unwrap();

    let (mut tunnel, reply) = connect_socks5(proxy_address, echo_address).unwrap();
    assert_eq!(reply, 0x00);
    tunnel.write_all(b"socks-through-commeatus").unwrap();
    let mut echoed = [0_u8; 23];
    tunnel.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"socks-through-commeatus");
    drop(tunnel);

    proxy_thread.join().unwrap().unwrap();
    echo_thread.join().unwrap().unwrap();
}

#[test]
fn socks5_domain_connect_uses_hosts_override_end_to_end() {
    let (echo_address, echo_thread) = spawn_echo_server().unwrap();
    let (proxy_address, proxy_thread) =
        spawn_test_listener_with_dns(ListenerProtocol::Socks5, direct_runtime(), hosts_dns(), 1)
            .unwrap();

    let (mut tunnel, reply) =
        connect_socks5_domain(proxy_address, HOSTS_ONLY_NAME, echo_address.port()).unwrap();
    assert_eq!(reply, 0x00);
    tunnel.write_all(b"hosts-through-dns-engine").unwrap();
    let mut echoed = [0_u8; 24];
    tunnel.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"hosts-through-dns-engine");
    drop(tunnel);

    proxy_thread.join().unwrap().unwrap();
    echo_thread.join().unwrap().unwrap();
}

#[test]
fn socks5_udp_associate_relays_datagram_end_to_end() {
    let (echo_address, echo_thread) = spawn_udp_echo_server().unwrap();
    let (proxy_address, proxy_thread) =
        spawn_test_listener(ListenerProtocol::Socks5, direct_runtime(), 1).unwrap();
    let (control, relay_address) = associate_socks5_udp(proxy_address).unwrap();

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let SocketAddr::V4(echo_address) = echo_address else {
        panic!("UDP echo target must be IPv4");
    };
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    packet.extend_from_slice(&echo_address.ip().octets());
    packet.extend_from_slice(&echo_address.port().to_be_bytes());
    packet.extend_from_slice(b"udp-through-commeatus");
    client.send_to(&packet, relay_address).unwrap();

    let mut response = [0_u8; 4096];
    let (length, source) = client.recv_from(&mut response).unwrap();
    assert_eq!(source, relay_address);
    assert_eq!(&response[10..length], b"udp-through-commeatus");
    drop(client);
    drop(control);

    proxy_thread.join().unwrap().unwrap();
    echo_thread.join().unwrap().unwrap();
}

#[test]
fn socks5_udp_domain_uses_hosts_override_end_to_end() {
    let (echo_address, echo_thread) = spawn_udp_echo_server().unwrap();
    let (proxy_address, proxy_thread) =
        spawn_test_listener_with_dns(ListenerProtocol::Socks5, direct_runtime(), hosts_dns(), 1)
            .unwrap();
    let (control, relay_address) = associate_socks5_udp(proxy_address).unwrap();

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x03, HOSTS_ONLY_NAME.len() as u8]);
    packet.extend_from_slice(HOSTS_ONLY_NAME.as_bytes());
    packet.extend_from_slice(&echo_address.port().to_be_bytes());
    packet.extend_from_slice(b"udp-hosts-dns-engine");
    client.send_to(&packet, relay_address).unwrap();

    let mut response = [0_u8; 4096];
    let (length, source) = client.recv_from(&mut response).unwrap();
    assert_eq!(source, relay_address);
    assert_eq!(&response[10..length], b"udp-hosts-dns-engine");
    drop(client);
    drop(control);

    proxy_thread.join().unwrap().unwrap();
    echo_thread.join().unwrap().unwrap();
}

#[test]
fn http_connect_relays_buffered_and_live_bytes_end_to_end() {
    let (echo_address, echo_thread) = spawn_echo_server().unwrap();
    let (proxy_address, proxy_thread) =
        spawn_test_listener(ListenerProtocol::HttpConnect, direct_runtime(), 1).unwrap();

    let mut tunnel = TcpStream::connect(proxy_address).unwrap();
    tunnel.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    tunnel.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
    let request = format!("CONNECT {echo_address} HTTP/1.1\r\nHost: {echo_address}\r\n\r\nearly");
    tunnel.write_all(request.as_bytes()).unwrap();
    let response = read_http_head(&mut tunnel).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));

    let mut early = [0_u8; 5];
    tunnel.read_exact(&mut early).unwrap();
    assert_eq!(&early, b"early");

    tunnel.write_all(b"live").unwrap();
    let mut live = [0_u8; 4];
    tunnel.read_exact(&mut live).unwrap();
    assert_eq!(&live, b"live");
    drop(tunnel);

    proxy_thread.join().unwrap().unwrap();
    echo_thread.join().unwrap().unwrap();
}

#[test]
fn reject_policy_blocks_before_outbound_connect() {
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    target_listener.set_nonblocking(true).unwrap();
    let target_address = target_listener.local_addr().unwrap();
    let runtime = Arc::new(Runtime::new(PolicyEngine::new(
        vec![PolicyRule {
            id: RuleId::new(1),
            tier: PolicyTier::UserHard,
            matcher: Matcher::Port(target_address.port()),
            action: PolicyAction::Reject(RejectReason::Policy),
        }],
        PolicyAction::Route(Endpoint::Direct),
    )));
    let (proxy_address, proxy_thread) =
        spawn_test_listener(ListenerProtocol::Socks5, runtime, 1).unwrap();

    let (tunnel, reply) = connect_socks5(proxy_address, target_address).unwrap();
    assert_eq!(reply, 0x02);
    drop(tunnel);
    proxy_thread.join().unwrap().unwrap();
    assert!(matches!(
        target_listener.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
}

#[test]
fn malformed_client_does_not_kill_socks_listener() {
    let (echo_address, echo_thread) = spawn_echo_server().unwrap();
    let (proxy_address, proxy_thread) =
        spawn_test_listener(ListenerProtocol::Socks5, direct_runtime(), 2).unwrap();

    let mut malformed = TcpStream::connect(proxy_address).unwrap();
    malformed.write_all(&[0x04, 0x01]).unwrap();
    drop(malformed);

    let (mut tunnel, reply) = connect_socks5(proxy_address, echo_address).unwrap();
    assert_eq!(reply, 0x00);
    tunnel.write_all(b"still-alive").unwrap();
    let mut echoed = [0_u8; 11];
    tunnel.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"still-alive");
    drop(tunnel);

    proxy_thread.join().unwrap().unwrap();
    echo_thread.join().unwrap().unwrap();
}
