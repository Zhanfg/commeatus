from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match in {path}, found {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1))


# Reuse one verified blocking handshake for both stream relay sessions and
# readiness-driven framed sessions.
replace_once(
    "crates/transport/src/tls.rs",
    '''    #[must_use]
    pub fn server_name(&self) -> &ServerName<'static> {
        &self.server_name
    }
}

impl TransportConnector for TlsTransport {''',
    '''    #[must_use]
    pub fn server_name(&self) -> &ServerName<'static> {
        &self.server_name
    }

    fn connect_established(&self) -> io::Result<(ClientConnection, TcpStream)> {
        let mut socket = TcpStream::connect_timeout(&self.address, self.connect_timeout)?;
        socket.set_nodelay(true)?;
        socket.set_read_timeout(Some(self.handshake_timeout))?;
        socket.set_write_timeout(Some(self.handshake_timeout))?;

        let mut connection = ClientConnection::new(self.config.clone(), self.server_name.clone())
            .map_err(tls_error)?;
        connection.set_buffer_limit(Some(TLS_BUFFER_LIMIT));
        connection.complete_io(&mut socket)?;
        if connection.is_handshaking() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS handshake did not complete",
            ));
        }
        Ok((connection, socket))
    }

    /// Establish a verified TLS carrier that can be driven by an external
    /// readiness loop without exposing rustls or the raw TCP socket.
    pub fn connect_framed(&self) -> io::Result<TlsFramedSession> {
        let (mut connection, socket) = self.connect_established()?;
        socket.set_read_timeout(None)?;
        socket.set_write_timeout(None)?;
        socket.set_nonblocking(true)?;
        connection.set_buffer_limit(Some(TLS_BUFFER_LIMIT));
        Ok(TlsFramedSession {
            connection,
            remote: mio::net::TcpStream::from_std(socket),
            registration: Registration::default(),
            remote_eof: false,
        })
    }
}

impl TransportConnector for TlsTransport {''',
)

replace_once(
    "crates/transport/src/tls.rs",
    '''    fn connect(&self) -> io::Result<Box<dyn TransportSession>> {
        let mut socket = TcpStream::connect_timeout(&self.address, self.connect_timeout)?;
        socket.set_nodelay(true)?;
        socket.set_read_timeout(Some(self.handshake_timeout))?;
        socket.set_write_timeout(Some(self.handshake_timeout))?;

        let mut connection = ClientConnection::new(self.config.clone(), self.server_name.clone())
            .map_err(tls_error)?;
        connection.set_buffer_limit(Some(TLS_BUFFER_LIMIT));
        connection.complete_io(&mut socket)?;
        if connection.is_handshaking() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS handshake did not complete",
            ));
        }

        Ok(Box::new(TlsTransportSession { connection, socket }))
    }''',
    '''    fn connect(&self) -> io::Result<Box<dyn TransportSession>> {
        let (connection, socket) = self.connect_established()?;
        Ok(Box::new(TlsTransportSession { connection, socket }))
    }''',
)

replace_once(
    "crates/transport/src/tls.rs",
    '''pub struct TlsTransportSession {
    connection: ClientConnection,
    socket: TcpStream,
}

impl Read for TlsTransportSession {''',
    '''pub struct TlsTransportSession {
    connection: ClientConnection,
    socket: TcpStream,
}

/// Verified TLS stream whose encrypted socket is owned by the transport while
/// plaintext framing is driven by a higher-level protocol executor.
///
/// The caller may queue/read plaintext and ask the transport to service
/// nonblocking TLS I/O. Dynamic interest is derived from rustls
/// `wants_read`/`wants_write`, so writable readiness is not left enabled after
/// encrypted output drains.
pub struct TlsFramedSession {
    connection: ClientConnection,
    remote: mio::net::TcpStream,
    registration: Registration,
    remote_eof: bool,
}

impl TlsFramedSession {
    pub fn write_plaintext(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.connection.writer().write(buffer)
    }

    pub fn read_plaintext(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.connection.reader().read(buffer)
    }

    /// Register the encrypted socket with the caller's poll registry.
    pub fn register_readiness(
        &mut self,
        registry: &mio::Registry,
        token: Token,
    ) -> io::Result<()> {
        if self.registration.registered {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "framed TLS session is already registered",
            ));
        }
        self.refresh_readiness(registry, token)
    }

    /// Reconcile poll interest with the current rustls state.
    pub fn refresh_readiness(
        &mut self,
        registry: &mio::Registry,
        token: Token,
    ) -> io::Result<()> {
        let readable = !self.remote_eof && self.connection.wants_read();
        let writable = self.connection.wants_write();
        update_registration(
            registry,
            &mut self.remote,
            token,
            readable,
            writable,
            &mut self.registration,
        )
    }

    /// Drive all currently possible encrypted socket I/O without blocking.
    ///
    /// It is safe to call this for either readable or writable readiness: each
    /// direction stops at `WouldBlock`. A read may generate TLS control output,
    /// so encrypted writes are attempted both before and after reads.
    pub fn service_io(&mut self) -> io::Result<()> {
        write_remote_tls(&mut self.connection, &mut self.remote)?;
        if !self.remote_eof {
            read_remote_tls(
                &mut self.connection,
                &mut self.remote,
                &mut self.remote_eof,
            )?;
        }
        write_remote_tls(&mut self.connection, &mut self.remote)
    }

    #[must_use]
    pub const fn remote_eof(&self) -> bool {
        self.remote_eof
    }
}

impl Read for TlsTransportSession {''',
)

# Re-export the new carrier from the transport crate.
replace_once(
    "crates/transport/src/lib.rs",
    "pub use tls::{TlsTransport, TlsTransportSession};",
    "pub use tls::{TlsFramedSession, TlsTransport, TlsTransportSession};",
)

# Add a gated TLS server test proving dynamic writable interest drains and the
# carrier returns to read-only waiting instead of spinning on a writable TCP fd.
tests = Path("crates/transport/src/tls_tests.rs")
text = tests.read_text()
text = text.replace(
    "    sync::Arc,\n    thread,",
    "    sync::{Arc, mpsc},\n    thread,",
    1,
)
text = text.replace(
    "use crate::{TlsTransport, TransportConnector};",
    "use mio::{Events, Poll, Token};\n\nuse crate::{TlsTransport, TransportConnector};",
    1,
)
append = r'''

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
'''
if "framed_tls_session_is_readiness_driven_without_writable_spin" in text:
    raise SystemExit("framed TLS test already exists")
tests.write_text(text.rstrip() + append + "\n")
