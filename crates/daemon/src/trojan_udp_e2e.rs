use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::Arc,
    thread,
    time::Duration,
};

use commeatus_core::{DestinationHost, Endpoint, EndpointId, PolicyAction, PolicyEngine, Runtime};
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
    proxy::Target,
    server::spawn_test_listener_with_runtime,
    trojan::{TROJAN_VERIFIER_BYTES, TrojanVerifier, encode_udp_frame, parse_udp_frame},
    trojan_datagram::TrojanDatagramProvider,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_SERVER_NAME: &str = "trojan-udp.test";
const PASSWORD: &str = "test-trojan-udp-secret";
const TARGET_DOMAIN: &str = "opaque-trojan-udp-target.invalid";
const TARGET_PORT: u16 = 5353;
const PAYLOAD: &[u8] = b"through-native-trojan-udp";
const REPLY: &[u8] = b"trojan-udp-reply";
const ZERO_SOURCE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
const ZERO_PORT: u16 = 9000;

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

fn read_one_trojan_udp_frame<R: Read>(stream: &mut R) -> io::Result<(Target, Vec<u8>)> {
    let mut buffered = Vec::new();
    let mut scratch = [0_u8; 256];
    loop {
        if let Some(frame) = parse_udp_frame(&buffered)? {
            let payload = buffered[frame.payload.clone()].to_vec();
            if frame.consumed != buffered.len() {
                return Err(io::Error::other(
                    "test client unexpectedly sent multiple Trojan UDP frames",
                ));
            }
            return Ok((frame.source, payload));
        }
        if buffered.len() > 70 * 1024 {
            return Err(io::Error::other(
                "Trojan UDP test frame exceeded bounded receive buffer",
            ));
        }
        let read = stream.read(&mut scratch)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Trojan UDP TLS stream closed before a complete frame",
            ));
        }
        buffered.extend_from_slice(&scratch[..read]);
    }
}

fn spawn_trojan_udp_server(
    server_config: Arc<ServerConfig>,
) -> (SocketAddr, TestThread<(Target, Vec<u8>)>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::Builder::new()
        .name("commeatus-v05-trojan-udp-server".to_owned())
        .spawn(move || {
            let (socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(TEST_TIMEOUT))?;
            socket.set_write_timeout(Some(TEST_TIMEOUT))?;
            let connection = ServerConnection::new(server_config)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let mut tls = StreamOwned::new(connection, socket);

            let expected = TrojanVerifier::new(PASSWORD)?;
            let mut verifier = [0_u8; TROJAN_VERIFIER_BYTES];
            tls.read_exact(&mut verifier)?;
            if &verifier != expected.as_bytes() {
                return Err(io::Error::other("Trojan UDP verifier mismatch"));
            }

            let mut crlf = [0_u8; 2];
            tls.read_exact(&mut crlf)?;
            if crlf != *b"\r\n" {
                return Err(io::Error::other(
                    "Trojan UDP verifier is not followed by CRLF",
                ));
            }

            let mut command = [0_u8; 1];
            tls.read_exact(&mut command)?;
            if command != [0x03] {
                return Err(io::Error::other("Trojan request is not UDP ASSOCIATE"));
            }

            let mut wildcard = [0_u8; 7];
            tls.read_exact(&mut wildcard)?;
            if wildcard != [0x01, 0, 0, 0, 0, 0, 0] {
                return Err(io::Error::other(
                    "Trojan UDP ASSOCIATE did not use normalized 0.0.0.0:0 target",
                ));
            }
            tls.read_exact(&mut crlf)?;
            if crlf != *b"\r\n" {
                return Err(io::Error::other(
                    "Trojan UDP ASSOCIATE target is not followed by CRLF",
                ));
            }

            let observed = read_one_trojan_udp_frame(&mut tls)?;

            let first = encode_udp_frame(&observed.0, REPLY)?;
            let zero_source = Target::new(DestinationHost::Ip(ZERO_SOURCE.into()), ZERO_PORT)?;
            let zero = encode_udp_frame(&zero_source, b"")?;

            // Force an incomplete first frame onto the TLS carrier, then send
            // the rest of that frame and a complete zero-length second frame
            // together. The client must preserve both incremental and
            // multi-frame parser semantics through the real readiness loop.
            let split = 3;
            tls.write_all(&first[..split])?;
            tls.flush()?;
            thread::sleep(Duration::from_millis(25));

            let mut tail = first[split..].to_vec();
            tail.extend_from_slice(&zero);
            tls.write_all(&tail)?;
            tls.flush()?;

            // Keep the TLS carrier alive until SOCKS5 control closure tears
            // down the association. Raw TCP EOF without close_notify is an
            // acceptable test shutdown because the daemon owns the client
            // side lifetime.
            let mut drain = [0_u8; 64];
            match tls.read(&mut drain) {
                Ok(0) => {}
                Ok(_) => {
                    return Err(io::Error::other(
                        "unexpected extra Trojan UDP client plaintext",
                    ));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::BrokenPipe
                    ) => {}
                Err(error) => return Err(error),
            }
            Ok(observed)
        })
        .unwrap();
    (address, handle)
}

fn associate_socks5_udp(proxy: SocketAddr) -> io::Result<(TcpStream, SocketAddr)> {
    let mut control = TcpStream::connect(proxy)?;
    control.set_read_timeout(Some(TEST_TIMEOUT))?;
    control.set_write_timeout(Some(TEST_TIMEOUT))?;
    control.write_all(&[0x05, 0x01, 0x00])?;
    let mut method = [0_u8; 2];
    control.read_exact(&mut method)?;
    if method != [0x05, 0x00] {
        return Err(io::Error::other("unexpected SOCKS5 method reply"));
    }

    control.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
    let mut reply = [0_u8; 10];
    control.read_exact(&mut reply)?;
    if reply[..4] != [0x05, 0x00, 0x00, 0x01] {
        return Err(io::Error::other("unexpected SOCKS5 UDP ASSOCIATE reply"));
    }
    let relay = SocketAddr::from((
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    Ok((control, relay))
}

fn encode_socks5_udp_domain_request(domain: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    assert!(!domain.is_empty() && domain.len() <= u8::MAX as usize);
    let mut packet = Vec::with_capacity(7 + domain.len() + payload.len());
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x03, domain.len() as u8]);
    packet.extend_from_slice(domain.as_bytes());
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn decode_socks5_udp_response(packet: &[u8]) -> io::Result<(Target, &[u8])> {
    if packet.len() < 4 || packet[..3] != [0, 0, 0] {
        return Err(io::Error::other("invalid SOCKS5 UDP response header"));
    }
    let mut offset = 4;
    let host = match packet[3] {
        0x01 => {
            let address = packet
                .get(offset..offset + 4)
                .ok_or_else(|| io::Error::other("truncated SOCKS5 UDP IPv4 response"))?;
            offset += 4;
            DestinationHost::Ip(IpAddr::V4(Ipv4Addr::new(
                address[0], address[1], address[2], address[3],
            )))
        }
        0x03 => {
            let length = usize::from(
                *packet
                    .get(offset)
                    .ok_or_else(|| io::Error::other("truncated SOCKS5 UDP domain length"))?,
            );
            offset += 1;
            if length == 0 {
                return Err(io::Error::other("empty SOCKS5 UDP response domain"));
            }
            let domain = packet
                .get(offset..offset + length)
                .ok_or_else(|| io::Error::other("truncated SOCKS5 UDP response domain"))?;
            offset += length;
            DestinationHost::Domain(
                std::str::from_utf8(domain)
                    .map_err(|_| io::Error::other("SOCKS5 UDP response domain is not UTF-8"))?
                    .to_owned(),
            )
        }
        0x04 => {
            let address = packet
                .get(offset..offset + 16)
                .ok_or_else(|| io::Error::other("truncated SOCKS5 UDP IPv6 response"))?;
            offset += 16;
            let octets: [u8; 16] = address
                .try_into()
                .map_err(|_| io::Error::other("invalid SOCKS5 UDP IPv6 response length"))?;
            DestinationHost::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        other => {
            return Err(io::Error::other(format!(
                "unexpected SOCKS5 UDP response address type {other}"
            )));
        }
    };
    let port = packet
        .get(offset..offset + 2)
        .ok_or_else(|| io::Error::other("truncated SOCKS5 UDP response port"))?;
    offset += 2;
    let target = Target::new(host, u16::from_be_bytes([port[0], port[1]]))?;
    Ok((target, &packet[offset..]))
}

#[test]
fn socks5_udp_routes_native_trojan_over_verified_tls_without_local_dns() {
    let (client_config, server_config) = tls_configs();
    let (trojan_server, trojan_thread) = spawn_trojan_udp_server(server_config);

    let id = EndpointId::new("trojan-udp-secure").unwrap();
    let runtime = Arc::new(Runtime::new(PolicyEngine::new(
        Vec::new(),
        PolicyAction::Route(Endpoint::Proxy(id.clone())),
    )));
    let verifier = TrojanVerifier::new(PASSWORD).unwrap();
    let transport =
        TlsTransport::with_client_config(trojan_server, TLS_SERVER_NAME, client_config).unwrap();
    let outbounds = Arc::new(
        OutboundRegistry::new(vec![ProxyEndpointConfig {
            id,
            protocol: protocol::trojan_with_verifier(verifier.clone()),
            datagram: Some(TrojanDatagramProvider::new(verifier, transport.clone()).into_ref()),
            transport: TransportConfig::Tls(transport),
        }])
        .unwrap(),
    );
    let dns = Arc::new(DnsEngine::system(HostsTable::default()));
    let (inbound, inbound_thread) =
        spawn_test_listener_with_runtime(ListenerProtocol::Socks5, runtime, dns, outbounds, 1)
            .unwrap();

    let (control, relay) = associate_socks5_udp(inbound).unwrap();
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    client.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
    let request = encode_socks5_udp_domain_request(TARGET_DOMAIN, TARGET_PORT, PAYLOAD);
    client.send_to(&request, relay).unwrap();

    let mut packet = [0_u8; 4096];
    let (first_len, first_peer) = client.recv_from(&mut packet).unwrap();
    assert_eq!(first_peer, relay);
    let (first_source, first_payload) = decode_socks5_udp_response(&packet[..first_len]).unwrap();
    assert_eq!(
        first_source,
        Target::new(
            DestinationHost::Domain(TARGET_DOMAIN.to_owned()),
            TARGET_PORT,
        )
        .unwrap()
    );
    assert_eq!(first_payload, REPLY);

    let (second_len, second_peer) = client.recv_from(&mut packet).unwrap();
    assert_eq!(second_peer, relay);
    let (second_source, second_payload) =
        decode_socks5_udp_response(&packet[..second_len]).unwrap();
    assert_eq!(
        second_source,
        Target::new(DestinationHost::Ip(ZERO_SOURCE.into()), ZERO_PORT).unwrap()
    );
    assert!(second_payload.is_empty());

    drop(client);
    drop(control);
    inbound_thread.join().unwrap().unwrap();
    let (observed_target, observed_payload) = trojan_thread.join().unwrap().unwrap();
    assert_eq!(
        observed_target,
        Target::new(
            DestinationHost::Domain(TARGET_DOMAIN.to_owned()),
            TARGET_PORT,
        )
        .unwrap()
    );
    assert_eq!(observed_payload, PAYLOAD);
}
