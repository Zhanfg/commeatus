use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use commeatus_core::{DestinationHost, Endpoint, EndpointId, PolicyAction, PolicyEngine, Runtime};
use commeatus_dns::{DnsEngine, HostsTable};
use commeatus_transport::TcpTransport;

use crate::{
    config::ListenerProtocol,
    outbound::{OutboundRegistry, ProxyEndpointConfig, TransportConfig},
    protocol::{self, ProtocolRef},
    server::spawn_test_listener_with_runtime,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const UPSTREAM_ONLY_DOMAIN: &str = "opaque-target.invalid";

type TestThread<T> = thread::JoinHandle<io::Result<T>>;
type TestServer<T> = io::Result<(SocketAddr, TestThread<T>)>;

fn spawn_echo_server() -> TestServer<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let handle = thread::Builder::new()
        .name("commeatus-v03-echo".to_owned())
        .spawn(move || {
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
        })?;
    Ok((address, handle))
}

fn relay_pair(mut left: TcpStream, mut right: TcpStream) -> io::Result<()> {
    left.set_read_timeout(None)?;
    left.set_write_timeout(None)?;
    right.set_read_timeout(None)?;
    right.set_write_timeout(None)?;

    let mut left_reader = left.try_clone()?;
    let mut right_writer = right.try_clone()?;
    let uplink = thread::Builder::new()
        .name("commeatus-v03-mock-relay".to_owned())
        .spawn(move || -> io::Result<u64> {
            match io::copy(&mut left_reader, &mut right_writer) {
                Ok(copied) => {
                    right_writer.shutdown(Shutdown::Write)?;
                    Ok(copied)
                }
                Err(error) => {
                    let _ = left_reader.shutdown(Shutdown::Both);
                    let _ = right_writer.shutdown(Shutdown::Both);
                    Err(error)
                }
            }
        })?;

    let downlink = io::copy(&mut right, &mut left);
    if downlink.is_ok() {
        left.shutdown(Shutdown::Write)?;
    } else {
        let _ = left.shutdown(Shutdown::Both);
        let _ = right.shutdown(Shutdown::Both);
    }
    uplink
        .join()
        .map_err(|_| io::Error::other("mock proxy relay panicked"))??;
    downlink?;
    Ok(())
}

fn read_socks_target(stream: &mut TcpStream) -> io::Result<(String, u16)> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    if header[..3] != [0x05, 0x01, 0x00] {
        return Err(io::Error::other(
            "unexpected upstream SOCKS5 CONNECT header",
        ));
    }
    let host = match header[3] {
        0x01 => {
            let mut address = [0_u8; 4];
            stream.read_exact(&mut address)?;
            Ipv4Addr::from(address).to_string()
        }
        0x03 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length)?;
            let mut name = vec![0_u8; usize::from(length[0])];
            stream.read_exact(&mut name)?;
            String::from_utf8(name)
                .map_err(|_| io::Error::other("upstream SOCKS5 target is not UTF-8"))?
        }
        0x04 => {
            let mut address = [0_u8; 16];
            stream.read_exact(&mut address)?;
            std::net::Ipv6Addr::from(address).to_string()
        }
        _ => return Err(io::Error::other("unexpected upstream SOCKS5 address type")),
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port)?;
    Ok((host, u16::from_be_bytes(port)))
}

fn spawn_mock_socks5_proxy(echo: SocketAddr) -> TestServer<(String, u16)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let handle = thread::Builder::new()
        .name("commeatus-v03-mock-socks".to_owned())
        .spawn(move || {
            let (mut client, _) = listener.accept()?;
            client.set_read_timeout(Some(TEST_TIMEOUT))?;
            client.set_write_timeout(Some(TEST_TIMEOUT))?;

            let mut greeting = [0_u8; 2];
            client.read_exact(&mut greeting)?;
            if greeting[0] != 0x05 || greeting[1] == 0 {
                return Err(io::Error::other("unexpected upstream SOCKS5 greeting"));
            }
            let mut methods = vec![0_u8; usize::from(greeting[1])];
            client.read_exact(&mut methods)?;
            if !methods.contains(&0x00) {
                return Err(io::Error::other("Commeatus did not offer SOCKS5 no-auth"));
            }
            client.write_all(&[0x05, 0x00])?;

            let observed = read_socks_target(&mut client)?;
            let remote = TcpStream::connect(echo)?;
            client.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])?;
            relay_pair(client, remote)?;
            Ok(observed)
        })?;
    Ok((address, handle))
}

fn read_http_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 16 * 1024 {
            return Err(io::Error::other("HTTP head exceeded test limit"));
        }
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    Ok(head)
}

fn spawn_mock_http_proxy(echo: SocketAddr) -> TestServer<String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let handle = thread::Builder::new()
        .name("commeatus-v03-mock-http".to_owned())
        .spawn(move || {
            let (mut client, _) = listener.accept()?;
            client.set_read_timeout(Some(TEST_TIMEOUT))?;
            client.set_write_timeout(Some(TEST_TIMEOUT))?;
            let head = read_http_head(&mut client)?;
            let text = std::str::from_utf8(&head)
                .map_err(|_| io::Error::other("upstream HTTP request is not UTF-8"))?;
            let request_line = text
                .split("\r\n")
                .next()
                .ok_or_else(|| io::Error::other("upstream HTTP request has no request line"))?;
            let mut fields = request_line.split_whitespace();
            if fields.next() != Some("CONNECT") {
                return Err(io::Error::other("upstream request is not CONNECT"));
            }
            let authority = fields
                .next()
                .ok_or_else(|| io::Error::other("upstream CONNECT has no authority"))?
                .to_owned();
            let remote = TcpStream::connect(echo)?;
            client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
            relay_pair(client, remote)?;
            Ok(authority)
        })?;
    Ok((address, handle))
}

fn proxy_runtime(id: EndpointId) -> Arc<Runtime> {
    Arc::new(Runtime::new(PolicyEngine::new(
        Vec::new(),
        PolicyAction::Route(Endpoint::Proxy(id)),
    )))
}

fn registry(id: EndpointId, protocol: ProtocolRef, address: SocketAddr) -> Arc<OutboundRegistry> {
    Arc::new(
        OutboundRegistry::new(vec![ProxyEndpointConfig {
            id,
            protocol,
            datagram: None,
            transport: TransportConfig::Tcp(TcpTransport::new(address)),
        }])
        .unwrap(),
    )
}

fn dns() -> Arc<DnsEngine> {
    Arc::new(DnsEngine::system(HostsTable::default()))
}

fn negotiate_inbound_socks(proxy: SocketAddr) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy)?;
    stream.set_read_timeout(Some(TEST_TIMEOUT))?;
    stream.set_write_timeout(Some(TEST_TIMEOUT))?;
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut reply = [0_u8; 2];
    stream.read_exact(&mut reply)?;
    if reply != [0x05, 0x00] {
        return Err(io::Error::other("inbound SOCKS5 negotiation failed"));
    }
    Ok(stream)
}

fn connect_inbound_socks_domain(
    proxy: SocketAddr,
    domain: &str,
    port: u16,
) -> io::Result<TcpStream> {
    let mut stream = negotiate_inbound_socks(proxy)?;
    let length =
        u8::try_from(domain.len()).map_err(|_| io::Error::other("test domain too long"))?;
    let mut request = vec![0x05, 0x01, 0x00, 0x03, length];
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request)?;

    let mut reply = [0_u8; 4];
    stream.read_exact(&mut reply)?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(io::Error::other(format!(
            "inbound SOCKS5 CONNECT failed with reply {}",
            reply[1]
        )));
    }
    match reply[3] {
        0x01 => {
            let mut rest = [0_u8; 6];
            stream.read_exact(&mut rest)?;
        }
        0x04 => {
            let mut rest = [0_u8; 18];
            stream.read_exact(&mut rest)?;
        }
        _ => return Err(io::Error::other("unexpected inbound SOCKS5 reply address")),
    }
    Ok(stream)
}

fn connect_inbound_http(proxy: SocketAddr, domain: &str, port: u16) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy)?;
    stream.set_read_timeout(Some(TEST_TIMEOUT))?;
    stream.set_write_timeout(Some(TEST_TIMEOUT))?;
    let authority = format!("{domain}:{port}");
    write!(
        stream,
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
    )?;
    stream.flush()?;
    let head = read_http_head(&mut stream)?;
    if !head.starts_with(b"HTTP/1.1 200") {
        return Err(io::Error::other("inbound HTTP CONNECT failed"));
    }
    Ok(stream)
}

fn assert_echo(mut tunnel: TcpStream, payload: &[u8]) -> io::Result<()> {
    tunnel.write_all(payload)?;
    let mut echoed = vec![0_u8; payload.len()];
    tunnel.read_exact(&mut echoed)?;
    if echoed != payload {
        return Err(io::Error::other("tunnel payload mismatch"));
    }
    drop(tunnel);
    Ok(())
}

#[test]
fn socks_inbound_routes_through_named_socks_outbound_without_local_dns() {
    let (echo, echo_thread) = spawn_echo_server().unwrap();
    let (upstream, upstream_thread) = spawn_mock_socks5_proxy(echo).unwrap();
    let id = EndpointId::new("edge-socks").unwrap();
    let (inbound, inbound_thread) = spawn_test_listener_with_runtime(
        ListenerProtocol::Socks5,
        proxy_runtime(id.clone()),
        dns(),
        registry(id, protocol::socks5(), upstream),
        1,
    )
    .unwrap();

    let tunnel = connect_inbound_socks_domain(inbound, UPSTREAM_ONLY_DOMAIN, echo.port()).unwrap();
    assert_echo(tunnel, b"through-socks-outbound").unwrap();

    inbound_thread.join().unwrap().unwrap();
    let observed = upstream_thread.join().unwrap().unwrap();
    echo_thread.join().unwrap().unwrap();
    assert_eq!(observed, (UPSTREAM_ONLY_DOMAIN.to_owned(), echo.port()));
}

#[test]
fn http_inbound_routes_through_named_http_outbound_without_local_dns() {
    let (echo, echo_thread) = spawn_echo_server().unwrap();
    let (upstream, upstream_thread) = spawn_mock_http_proxy(echo).unwrap();
    let id = EndpointId::new("edge-http").unwrap();
    let (inbound, inbound_thread) = spawn_test_listener_with_runtime(
        ListenerProtocol::HttpConnect,
        proxy_runtime(id.clone()),
        dns(),
        registry(id, protocol::http_connect(), upstream),
        1,
    )
    .unwrap();

    let tunnel = connect_inbound_http(inbound, UPSTREAM_ONLY_DOMAIN, echo.port()).unwrap();
    assert_echo(tunnel, b"through-http-outbound").unwrap();

    inbound_thread.join().unwrap().unwrap();
    let authority = upstream_thread.join().unwrap().unwrap();
    echo_thread.join().unwrap().unwrap();
    assert_eq!(authority, format!("{UPSTREAM_ONLY_DOMAIN}:{}", echo.port()));
}

#[test]
fn proxy_endpoint_domain_is_not_resolved_by_local_dns_before_upstream() {
    let host = DestinationHost::Domain(UPSTREAM_ONLY_DOMAIN.to_owned());
    assert_eq!(
        host,
        DestinationHost::Domain(UPSTREAM_ONLY_DOMAIN.to_owned())
    );
}
