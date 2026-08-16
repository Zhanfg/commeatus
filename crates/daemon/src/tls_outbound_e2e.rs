use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use commeatus_core::{Endpoint, EndpointId, PolicyAction, PolicyEngine, Runtime};
use commeatus_dns::{DnsEngine, HostsTable};
use commeatus_transport::TlsTransport;
use rcgen::generate_simple_self_signed;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::PrivatePkcs8KeyDer,
};

use crate::{
    config::ListenerProtocol,
    outbound::{OutboundRegistry, ProxyEndpointConfig, TransportConfig},
    protocol,
    server::spawn_test_listener_with_runtime,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_SERVER_NAME: &str = "proxy.test";
const TARGET_DOMAIN: &str = "opaque-tls-target.invalid";
const PAYLOAD: &[u8] = b"protocol-over-tls";

type TestThread<T> = thread::JoinHandle<io::Result<T>>;

fn tls_configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let certified = generate_simple_self_signed(vec![TLS_SERVER_NAME.to_owned()]).unwrap();
    let certificate = certified.cert.der().clone();
    let private_key = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());

    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], private_key.into())
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(certificate).unwrap();
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(client), Arc::new(server))
}

fn spawn_echo_server() -> (SocketAddr, TestThread<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let thread = thread::Builder::new()
        .name("commeatus-v04-echo".to_owned())
        .spawn(move || {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(TEST_TIMEOUT))?;
            stream.set_write_timeout(Some(TEST_TIMEOUT))?;
            let mut payload = vec![0_u8; PAYLOAD.len()];
            stream.read_exact(&mut payload)?;
            stream.write_all(&payload)?;
            stream.shutdown(Shutdown::Write)?;
            Ok(())
        })
        .unwrap();
    (address, thread)
}

fn read_socks_target<R: Read>(stream: &mut R) -> io::Result<(String, u16)> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    if header[..3] != [0x05, 0x01, 0x00] {
        return Err(io::Error::other("unexpected SOCKS5 CONNECT header"));
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
            let mut domain = vec![0_u8; usize::from(length[0])];
            stream.read_exact(&mut domain)?;
            String::from_utf8(domain).map_err(|_| io::Error::other("SOCKS5 domain is not UTF-8"))?
        }
        0x04 => {
            let mut address = [0_u8; 16];
            stream.read_exact(&mut address)?;
            std::net::Ipv6Addr::from(address).to_string()
        }
        _ => return Err(io::Error::other("unexpected SOCKS5 address type")),
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port)?;
    Ok((host, u16::from_be_bytes(port)))
}

fn spawn_tls_socks_proxy(
    echo: SocketAddr,
    server_config: Arc<ServerConfig>,
) -> (SocketAddr, TestThread<(String, u16)>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let thread = thread::Builder::new()
        .name("commeatus-v04-tls-socks".to_owned())
        .spawn(move || {
            let (socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(TEST_TIMEOUT))?;
            socket.set_write_timeout(Some(TEST_TIMEOUT))?;
            let connection = ServerConnection::new(server_config)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let mut tls = StreamOwned::new(connection, socket);

            let mut greeting = [0_u8; 2];
            tls.read_exact(&mut greeting)?;
            if greeting[0] != 0x05 || greeting[1] == 0 {
                return Err(io::Error::other("unexpected SOCKS5 greeting over TLS"));
            }
            let mut methods = vec![0_u8; usize::from(greeting[1])];
            tls.read_exact(&mut methods)?;
            if !methods.contains(&0x00) {
                return Err(io::Error::other("SOCKS5 no-auth was not offered"));
            }
            tls.write_all(&[0x05, 0x00])?;
            tls.flush()?;

            let observed = read_socks_target(&mut tls)?;
            let mut remote = TcpStream::connect(echo)?;
            remote.set_read_timeout(Some(TEST_TIMEOUT))?;
            remote.set_write_timeout(Some(TEST_TIMEOUT))?;
            tls.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])?;
            tls.flush()?;

            let mut payload = vec![0_u8; PAYLOAD.len()];
            tls.read_exact(&mut payload)?;
            remote.write_all(&payload)?;
            let mut echoed = vec![0_u8; PAYLOAD.len()];
            remote.read_exact(&mut echoed)?;
            tls.write_all(&echoed)?;
            tls.flush()?;

            let mut extra = [0_u8; 1];
            if tls.read(&mut extra)? != 0 {
                return Err(io::Error::other(
                    "unexpected plaintext after TLS tunnel payload",
                ));
            }
            tls.conn.send_close_notify();
            tls.flush()?;
            Ok(observed)
        })
        .unwrap();
    (address, thread)
}

fn connect_http_inbound(proxy: SocketAddr, domain: &str, port: u16) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy)?;
    stream.set_read_timeout(Some(TEST_TIMEOUT))?;
    stream.set_write_timeout(Some(TEST_TIMEOUT))?;
    let authority = format!("{domain}:{port}");
    write!(
        stream,
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
    )?;
    stream.flush()?;

    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 16 * 1024 {
            return Err(io::Error::other("HTTP response head exceeded test limit"));
        }
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    if !head.starts_with(b"HTTP/1.1 200") {
        return Err(io::Error::other("HTTP inbound did not establish tunnel"));
    }
    Ok(stream)
}

#[test]
fn http_inbound_routes_socks_protocol_over_tls_without_local_dns() {
    let (echo, echo_thread) = spawn_echo_server();
    let (client_config, server_config) = tls_configs();
    let (tls_proxy, proxy_thread) = spawn_tls_socks_proxy(echo, server_config);

    let id = EndpointId::new("secure-socks").unwrap();
    let runtime = Arc::new(Runtime::new(PolicyEngine::new(
        Vec::new(),
        PolicyAction::Route(Endpoint::Proxy(id.clone())),
    )));
    let transport =
        TlsTransport::with_client_config(tls_proxy, TLS_SERVER_NAME, client_config).unwrap();
    let outbounds = Arc::new(
        OutboundRegistry::new(vec![ProxyEndpointConfig {
            id,
            protocol: protocol::socks5(),
            transport: TransportConfig::Tls(transport),
        }])
        .unwrap(),
    );
    let dns = Arc::new(DnsEngine::system(HostsTable::default()));
    let (inbound, inbound_thread) =
        spawn_test_listener_with_runtime(ListenerProtocol::HttpConnect, runtime, dns, outbounds, 1)
            .unwrap();

    let mut tunnel = connect_http_inbound(inbound, TARGET_DOMAIN, echo.port()).unwrap();
    tunnel.write_all(PAYLOAD).unwrap();
    let mut echoed = vec![0_u8; PAYLOAD.len()];
    tunnel.read_exact(&mut echoed).unwrap();
    assert_eq!(echoed, PAYLOAD);
    tunnel.shutdown(Shutdown::Write).unwrap();
    drop(tunnel);

    inbound_thread.join().unwrap().unwrap();
    let observed = proxy_thread.join().unwrap().unwrap();
    echo_thread.join().unwrap().unwrap();
    assert_eq!(observed, (TARGET_DOMAIN.to_owned(), echo.port()));
}
