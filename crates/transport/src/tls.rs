use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

use mio::{Events, Interest, Poll, Token};
use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};

use crate::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_HANDSHAKE_TIMEOUT, TransportCapabilities, TransportConnector,
    TransportSession,
};

const CLIENT: Token = Token(0);
const REMOTE: Token = Token(1);
const EVENT_CAPACITY: usize = 16;
const IO_CHUNK: usize = 16 * 1024;
const TLS_BUFFER_LIMIT: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct TlsTransport {
    address: SocketAddr,
    server_name: ServerName<'static>,
    config: Arc<ClientConfig>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
}

impl TlsTransport {
    pub fn webpki(address: SocketAddr, server_name: impl Into<String>) -> io::Result<Self> {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self::with_client_config(address, server_name, Arc::new(config))
    }

    pub fn with_client_config(
        address: SocketAddr,
        server_name: impl Into<String>,
        config: Arc<ClientConfig>,
    ) -> io::Result<Self> {
        let server_name = ServerName::try_from(server_name.into()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid TLS server name: {error}"),
            )
        })?;
        Ok(Self {
            address,
            server_name,
            config,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        })
    }

    pub fn with_timeouts(
        address: SocketAddr,
        server_name: impl Into<String>,
        config: Arc<ClientConfig>,
        connect_timeout: Duration,
        handshake_timeout: Duration,
    ) -> io::Result<Self> {
        if connect_timeout.is_zero() || handshake_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transport timeouts must be greater than zero",
            ));
        }
        let mut transport = Self::with_client_config(address, server_name, config)?;
        transport.connect_timeout = connect_timeout;
        transport.handshake_timeout = handshake_timeout;
        Ok(transport)
    }

    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    #[must_use]
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

impl TransportConnector for TlsTransport {
    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            reliable_stream: true,
            datagram: false,
            encrypted: true,
        }
    }

    fn connect(&self) -> io::Result<Box<dyn TransportSession>> {
        let (connection, socket) = self.connect_established()?;
        Ok(Box::new(TlsTransportSession { connection, socket }))
    }
}

pub struct TlsTransportSession {
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
    pub fn register_readiness(&mut self, registry: &mio::Registry, token: Token) -> io::Result<()> {
        if self.registration.registered {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "framed TLS session is already registered",
            ));
        }
        self.refresh_readiness(registry, token)
    }

    /// Reconcile poll interest with the current rustls state.
    pub fn refresh_readiness(&mut self, registry: &mio::Registry, token: Token) -> io::Result<()> {
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
            read_remote_tls(&mut self.connection, &mut self.remote, &mut self.remote_eof)?;
        }
        write_remote_tls(&mut self.connection, &mut self.remote)
    }

    #[must_use]
    pub const fn remote_eof(&self) -> bool {
        self.remote_eof
    }
}

impl Read for TlsTransportSession {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        rustls::Stream::new(&mut self.connection, &mut self.socket).read(buffer)
    }
}

impl Write for TlsTransportSession {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        rustls::Stream::new(&mut self.connection, &mut self.socket).write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        rustls::Stream::new(&mut self.connection, &mut self.socket).flush()
    }
}

impl TransportSession for TlsTransportSession {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn relay_to_client(self: Box<Self>, client: TcpStream) -> io::Result<()> {
        let TlsTransportSession {
            mut connection,
            socket,
        } = *self;

        socket.set_read_timeout(None)?;
        socket.set_write_timeout(None)?;
        socket.set_nonblocking(true)?;
        client.set_read_timeout(None)?;
        client.set_write_timeout(None)?;
        client.set_nodelay(true)?;
        client.set_nonblocking(true)?;
        connection.set_buffer_limit(Some(TLS_BUFFER_LIMIT));

        let mut remote = mio::net::TcpStream::from_std(socket);
        let mut client = mio::net::TcpStream::from_std(client);
        let mut poll = Poll::new()?;
        let mut events = Events::with_capacity(EVENT_CAPACITY);

        let mut client_registration = Registration::default();
        let mut remote_registration = Registration::default();
        let mut client_eof = false;
        let mut remote_eof = false;
        let mut close_notify_sent = false;
        let mut client_write_shutdown = false;
        let mut upstream = Pending::default();
        let mut downstream = Pending::default();

        loop {
            feed_upstream(&mut connection, &mut upstream)?;
            fill_downstream(&mut connection, &mut downstream)?;

            if client_eof && upstream.is_empty() && !close_notify_sent {
                connection.send_close_notify();
                close_notify_sent = true;
            }

            if remote_eof && downstream.is_empty() && !client_write_shutdown {
                client.shutdown(Shutdown::Write)?;
                client_write_shutdown = true;
                client_eof = true;
                if !close_notify_sent {
                    connection.send_close_notify();
                    close_notify_sent = true;
                }
            }

            if client_eof
                && remote_eof
                && upstream.is_empty()
                && downstream.is_empty()
                && !connection.wants_write()
            {
                return Ok(());
            }

            let client_read = !client_eof && upstream.is_empty();
            let client_write = !downstream.is_empty();
            update_registration(
                poll.registry(),
                &mut client,
                CLIENT,
                client_read,
                client_write,
                &mut client_registration,
            )?;

            let remote_read = !remote_eof && connection.wants_read();
            let remote_write = connection.wants_write();
            update_registration(
                poll.registry(),
                &mut remote,
                REMOTE,
                remote_read,
                remote_write,
                &mut remote_registration,
            )?;

            if !client_registration.registered && !remote_registration.registered {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS relay has no remaining I/O interest",
                ));
            }

            poll.poll(&mut events, None)?;
            for event in &events {
                match event.token() {
                    CLIENT => {
                        if event.is_readable() && client_read {
                            read_client(&mut client, &mut upstream, &mut client_eof)?;
                        }
                        if event.is_writable() && client_write {
                            write_pending(&mut client, &mut downstream)?;
                        }
                        if event.is_error() || event.is_read_closed() || event.is_write_closed() {
                            client_eof = true;
                        }
                    }
                    REMOTE => {
                        if event.is_readable() && remote_read {
                            read_remote_tls(&mut connection, &mut remote, &mut remote_eof)?;
                        }
                        if event.is_writable() && remote_write {
                            write_remote_tls(&mut connection, &mut remote)?;
                        }
                        if event.is_error() || event.is_read_closed() || event.is_write_closed() {
                            remote_eof = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[derive(Default)]
struct Pending {
    bytes: Vec<u8>,
    offset: usize,
}

impl Pending {
    fn is_empty(&self) -> bool {
        self.offset >= self.bytes.len()
    }

    fn clear(&mut self) {
        self.bytes.clear();
        self.offset = 0;
    }

    fn remaining(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct Registration {
    registered: bool,
    readable: bool,
    writable: bool,
}

fn update_registration(
    registry: &mio::Registry,
    socket: &mut mio::net::TcpStream,
    token: Token,
    readable: bool,
    writable: bool,
    state: &mut Registration,
) -> io::Result<()> {
    if !readable && !writable {
        if state.registered {
            registry.deregister(socket)?;
            *state = Registration::default();
        }
        return Ok(());
    }

    let interest = match (readable, writable) {
        (true, true) => Interest::READABLE | Interest::WRITABLE,
        (true, false) => Interest::READABLE,
        (false, true) => Interest::WRITABLE,
        (false, false) => unreachable!(),
    };

    if !state.registered {
        registry.register(socket, token, interest)?;
        *state = Registration {
            registered: true,
            readable,
            writable,
        };
    } else if state.readable != readable || state.writable != writable {
        registry.reregister(socket, token, interest)?;
        state.readable = readable;
        state.writable = writable;
    }
    Ok(())
}

fn read_client(
    client: &mut mio::net::TcpStream,
    pending: &mut Pending,
    eof: &mut bool,
) -> io::Result<()> {
    if !pending.is_empty() {
        return Ok(());
    }
    pending.clear();
    let mut buffer = [0_u8; IO_CHUNK];
    match client.read(&mut buffer) {
        Ok(0) => *eof = true,
        Ok(count) => pending.bytes.extend_from_slice(&buffer[..count]),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

fn feed_upstream(connection: &mut ClientConnection, pending: &mut Pending) -> io::Result<()> {
    while !pending.is_empty() {
        match connection.writer().write(pending.remaining()) {
            Ok(0) => break,
            Ok(count) => pending.offset += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    if pending.is_empty() {
        pending.clear();
    }
    Ok(())
}

fn read_remote_tls(
    connection: &mut ClientConnection,
    remote: &mut mio::net::TcpStream,
    eof: &mut bool,
) -> io::Result<()> {
    loop {
        match connection.read_tls(remote) {
            Ok(0) => {
                *eof = true;
                break;
            }
            Ok(_) => {
                connection.process_new_packets().map_err(tls_error)?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_remote_tls(
    connection: &mut ClientConnection,
    remote: &mut mio::net::TcpStream,
) -> io::Result<()> {
    while connection.wants_write() {
        match connection.write_tls(remote) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn fill_downstream(connection: &mut ClientConnection, pending: &mut Pending) -> io::Result<()> {
    if !pending.is_empty() {
        return Ok(());
    }
    pending.clear();
    let mut buffer = [0_u8; IO_CHUNK];
    match connection.reader().read(&mut buffer) {
        Ok(0) => {}
        Ok(count) => pending.bytes.extend_from_slice(&buffer[..count]),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

fn write_pending(socket: &mut mio::net::TcpStream, pending: &mut Pending) -> io::Result<()> {
    while !pending.is_empty() {
        match socket.write(pending.remaining()) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "client closed while TLS plaintext remained buffered",
                ));
            }
            Ok(count) => pending.offset += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    if pending.is_empty() {
        pending.clear();
    }
    Ok(())
}

fn tls_error(error: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
