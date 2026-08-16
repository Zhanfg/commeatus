use std::{
    io::{Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use rcgen::generate_simple_self_signed;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::PrivatePkcs8KeyDer,
};

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
            loop {
                let read = match tls.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => read,
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(error) => return Err(error),
                };
                tls.write_all(&buffer[..read])?;
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
