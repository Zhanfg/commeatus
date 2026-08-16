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
use sha2::{Digest, Sha224};

use crate::{
    config::ListenerProtocol,
    outbound::{OutboundRegistry, ProxyEndpointConfig, TransportConfig},
    protocol,
    server::spawn_test_listener_with_runtime,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_SERVER_NAME: &str = "trojan.test";
const PASSWORD: &str = "test-trojan-secret";
const TARGET_DOMAIN: &str = "opaque-trojan-target.invalid";
const PAYLOAD: &[u8] = b"through-native-trojan";

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

fn password_hash_hex(password: &str) -> [u8; 56] {
    let digest = Sha224::digest(password.as_bytes());
    let mut output = [0_u8; 56];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in digest.iter().copied().enumerate() {
        output[index * 2] = HEX[usize::from(byte >> 4)];
        output[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    output
}

fn spawn_echo_server() -> (SocketAddr, TestThread<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::Builder::new()
        .name("commeatus-v05-trojan-echo".to_owned())
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
    (address, handle)
}

fn read_trojan_target<R: Read>(stream: &mut R) -> io::Result<(String, u16)> {
    let mut command = [0_u8; 1];
    stream.read_exact(&mut command)?;
    if command[0] != 0x01 {
        return Err(io::Error::other("Trojan request is not CONNECT"));
    }

    let mut address_type = [0_u8; 1];
    stream.read_exact(&mut address_type)?;
    let host = match address_type[0] {
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
            String::from_utf8(domain)
                .map_err(|_| io::Error::other("Trojan target domain is not UTF-8"))?
        }
        0x04 => {
            let mut address = [0_u8; 16];
            stream.read_exact(&mut address)?;
            std::net::Ipv6Addr::from(address).to_string()
        }
        _ => return Err(io::Error::other("unexpected Trojan address type")),
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port)?;
    Ok((host, u16::from_be_bytes(port)))
}

fn spawn_trojan_server(
    echo: SocketAddr,
    server_config: Arc<ServerConfig>,
) -> (SocketAddr, TestThread<(String, u16)>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::Builder::new()
        .name("commeatus-v05-trojan-server".to_owned())
        .spawn(move || {
            let (socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(TEST_TIMEOUT))?;
            socket.set_write_timeout(Some(TEST_TIMEOUT))?;
            let connection = ServerConnection::new(server_config)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let mut tls = StreamOwned::new(connection, socket);

            let mut received_hash = [0_u8; 56];
            tls.read_exact(&mut received_hash)?;
            if received_hash != password_hash_hex(PASSWORD) {
                return Err(io::Error::other("Trojan password verifier mismatch"));
            }
            let mut crlf = [0_u8; 2];
            tls.read_exact(&mut crlf)?;
            if crlf != *b"\r\n" {
                return Err(io::Error::other("Trojan verifier is not followed by CRLF"));
            }

            let observed = read_trojan_target(&mut tls)?;
            tls.read_exact(&mut crlf)?;
            if crlf != *b"\r\n" {
                return Err(io::Error::other("Trojan request is not followed by CRLF"));
            }

            let mut remote = TcpStream::connect(echo)?;
            remote.set_read_timeout(Some(TEST_TIMEOUT))?;
            remote.set_write_timeout(Some(TEST_TIMEOUT))?;

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
                    "unexpected Trojan payload after client half-close",
                ));
            }
            tls.conn.send_close_notify();
            tls.flush()?;
            Ok(observed)
        })
        .unwrap();
    (address, handle)
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
        return Err(io::Error::other(
            "HTTP inbound did not establish Trojan tunnel",
        ));
    }
    Ok(stream)
}

#[test]
fn http_inbound_routes_native_trojan_over_verified_tls_without_local_dns() {
    let (echo, echo_thread) = spawn_echo_server();
    let (client_config, server_config) = tls_configs();
    let (trojan_server, trojan_thread) = spawn_trojan_server(echo, server_config);

    let id = EndpointId::new("trojan-secure").unwrap();
    let runtime = Arc::new(Runtime::new(PolicyEngine::new(
        Vec::new(),
        PolicyAction::Route(Endpoint::Proxy(id.clone())),
    )));
    let transport =
        TlsTransport::with_client_config(trojan_server, TLS_SERVER_NAME, client_config).unwrap();
    let outbounds = Arc::new(
        OutboundRegistry::new(vec![ProxyEndpointConfig {
            id,
            protocol: protocol::trojan(PASSWORD).unwrap(),
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
    let observed = trojan_thread.join().unwrap().unwrap();
    echo_thread.join().unwrap().unwrap();
    assert_eq!(observed, (TARGET_DOMAIN.to_owned(), echo.port()));
}
