use std::{
    io::{Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use rcgen::generate_simple_self_signed;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::PrivatePkcs8KeyDer,
};

use mio::{Events, Poll, Token};

use crate::{TlsTransport, TransportConnector};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const SERVER_NAME: &str = "proxy.test";

type TestServer = (
    SocketAddr,
    Arc<ClientConfig>,
    thread::JoinHandle<std::io::Result<()>>,
);

fn configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let certified = generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
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

fn spawn_tls_echo() -> TestServer {
    let (client_config, server_config) = configs();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::Builder::new()
        .name("commeatus-test-tls-echo".to_owned())
        .spawn(move || {
            let (socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(TEST_TIMEOUT))?;
            socket.set_write_timeout(Some(TEST_TIMEOUT))?;
            let connection = ServerConnection::new(server_config)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let mut tls = StreamOwned::new(connection, socket);
            let mut buffer = [0_u8; 4096];
            let clean_eof = loop {
                let read = match tls.read(&mut buffer) {
                    Ok(0) => break true,
                    Ok(read) => read,
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break false,
                    Err(error) => return Err(error),
                };
                tls.write_all(&buffer[..read])?;
                tls.flush()?;
            };

            if clean_eof {
                tls.conn.send_close_notify();
                tls.flush()?;
            }
            Ok(())
        })
        .unwrap();
    (address, client_config, handle)
}

#[test]
fn trusted_certificate_and_matching_server_name_handshake() {
    let (address, client_config, server) = spawn_tls_echo();
    let transport = TlsTransport::with_client_config(address, SERVER_NAME, client_config).unwrap();
    let mut session = transport.connect().unwrap();
    session.write_all(b"ping").unwrap();
    session.flush().unwrap();
    let mut reply = [0_u8; 4];
    session.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"ping");
    drop(session);
    server.join().unwrap().unwrap();
}

#[test]
fn trusted_ca_does_not_bypass_server_name_verification() {
    let (address, client_config, server) = spawn_tls_echo();
    let transport = TlsTransport::with_client_config(address, "wrong.test", client_config).unwrap();
    assert!(transport.connect().is_err());
    let _ = server.join();
}

#[test]
fn tls_transport_session_relays_bidirectionally_and_half_closes() {
    let (address, client_config, server) = spawn_tls_echo();
    let transport = TlsTransport::with_client_config(address, SERVER_NAME, client_config).unwrap();
    let session = transport.connect().unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let local_address = listener.local_addr().unwrap();
    let mut application = TcpStream::connect(local_address).unwrap();
    application.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    application.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
    let (relay_side, _) = listener.accept().unwrap();

    let relay = thread::Builder::new()
        .name("commeatus-test-tls-relay".to_owned())
        .spawn(move || session.relay_to_client(relay_side))
        .unwrap();

    application.write_all(b"through-tls-relay").unwrap();
    let mut echoed = [0_u8; 17];
    application.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"through-tls-relay");
    application.shutdown(Shutdown::Write).unwrap();

    relay.join().unwrap().unwrap();
    server.join().unwrap().unwrap();
}

#[test]
fn framed_tls_session_is_readiness_driven_without_writable_spin() {
    let (client_config, server_config) = configs();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let (received_tx, received_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let server = thread::Builder::new()
        .name("commeatus-test-tls-framed".to_owned())
        .spawn(move || -> std::io::Result<()> {
            let (socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(TEST_TIMEOUT))?;
            socket.set_write_timeout(Some(TEST_TIMEOUT))?;
            let connection = ServerConnection::new(server_config)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let mut tls = StreamOwned::new(connection, socket);
            let mut request = [0_u8; 10];
            tls.read_exact(&mut request)?;
            if &request != b"frame-ping" {
                return Err(std::io::Error::other("unexpected framed TLS request"));
            }
            received_tx
                .send(())
                .map_err(|_| std::io::Error::other("test receiver disappeared"))?;
            release_rx
                .recv_timeout(TEST_TIMEOUT)
                .map_err(|_| std::io::Error::other("framed TLS response gate timed out"))?;
            tls.write_all(b"frame-")?;
            tls.flush()?;
            tls.write_all(b"pong")?;
            tls.flush()?;
            let mut eof = [0_u8; 1];
            match tls.read(&mut eof) {
                Ok(0) | Err(_) => {}
                Ok(_) => {
                    return Err(std::io::Error::other(
                        "unexpected framed TLS plaintext after response",
                    ));
                }
            }
            Ok(())
        })
        .unwrap();

    let transport = TlsTransport::with_client_config(address, SERVER_NAME, client_config).unwrap();
    let mut framed = transport.connect_framed().unwrap();
    let mut poll = Poll::new().unwrap();
    let token = Token(7);
    framed.register_readiness(poll.registry(), token).unwrap();
    assert_eq!(framed.write_plaintext(b"frame-ping").unwrap(), 10);
    framed.refresh_readiness(poll.registry(), token).unwrap();

    let mut events = Events::with_capacity(8);
    let deadline = std::time::Instant::now() + TEST_TIMEOUT;
    while received_rx.try_recv().is_err() {
        assert!(std::time::Instant::now() < deadline);
        poll.poll(&mut events, Some(Duration::from_millis(100)))
            .unwrap();
        for event in &events {
            assert_eq!(event.token(), token);
            framed.service_io().unwrap();
            framed.refresh_readiness(poll.registry(), token).unwrap();
        }
    }

    // The server has received all queued plaintext but is intentionally not
    // sending anything. A permanently WRITABLE registration would wake this
    // poll immediately and spin; read-only interest must stay quiet.
    events.clear();
    poll.poll(&mut events, Some(Duration::from_millis(80)))
        .unwrap();
    assert!(events.is_empty());

    release_tx.send(()).unwrap();
    let mut reply = Vec::new();
    while reply.len() < 10 {
        poll.poll(&mut events, Some(Duration::from_millis(200)))
            .unwrap();
        for event in &events {
            assert_eq!(event.token(), token);
            framed.service_io().unwrap();
            loop {
                let mut buffer = [0_u8; 32];
                match framed.read_plaintext(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => reply.extend_from_slice(&buffer[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("framed TLS plaintext read failed: {error}"),
                }
            }
            framed.refresh_readiness(poll.registry(), token).unwrap();
        }
        assert!(std::time::Instant::now() < deadline);
    }
    assert_eq!(&reply, b"frame-pong");
    drop(framed);
    server.join().unwrap().unwrap();
}
