//! Transport-session boundary for Commeatus outbound execution.
//!
//! Proxy protocols consume `Read + Write` during their handshake and then hand
//! the established carrier back to the transport for full-duplex relay. This
//! prevents protocol implementations from depending on transport-specific
//! details such as `TcpStream::try_clone`.

#![forbid(unsafe_code)]

mod tls;

use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    thread,
    time::Duration,
};

pub use tls::{TlsTransport, TlsTransportSession};

pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportCapabilities {
    pub reliable_stream: bool,
    pub datagram: bool,
    pub encrypted: bool,
}

/// An established carrier consumed by an outbound protocol.
///
/// The protocol may read and write handshake bytes through this trait. After
/// the protocol handshake succeeds, the transport itself owns the relay
/// strategy. A future TLS transport therefore does not need to pretend its
/// session can be cloned like a raw TCP socket.
pub trait TransportSession: Read + Write + Send {
    fn local_addr(&self) -> io::Result<SocketAddr>;

    fn relay_to_client(self: Box<Self>, client: TcpStream) -> io::Result<()>;
}

pub trait TransportConnector: Send + Sync {
    fn capabilities(&self) -> TransportCapabilities;

    fn connect(&self) -> io::Result<Box<dyn TransportSession>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpTransport {
    address: SocketAddr,
    connect_timeout: Duration,
    handshake_timeout: Duration,
}

impl TcpTransport {
    #[must_use]
    pub const fn new(address: SocketAddr) -> Self {
        Self {
            address,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    pub fn with_timeouts(
        address: SocketAddr,
        connect_timeout: Duration,
        handshake_timeout: Duration,
    ) -> io::Result<Self> {
        if connect_timeout.is_zero() || handshake_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transport timeouts must be greater than zero",
            ));
        }
        Ok(Self {
            address,
            connect_timeout,
            handshake_timeout,
        })
    }

    #[must_use]
    pub const fn address(self) -> SocketAddr {
        self.address
    }
}

impl TransportConnector for TcpTransport {
    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            reliable_stream: true,
            datagram: false,
            encrypted: false,
        }
    }

    fn connect(&self) -> io::Result<Box<dyn TransportSession>> {
        let stream = TcpStream::connect_timeout(&self.address, self.connect_timeout)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(self.handshake_timeout))?;
        stream.set_write_timeout(Some(self.handshake_timeout))?;
        Ok(TcpTransportSession::boxed(stream))
    }
}

pub struct TcpTransportSession {
    stream: TcpStream,
}

impl TcpTransportSession {
    #[must_use]
    pub const fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    pub fn boxed(stream: TcpStream) -> Box<dyn TransportSession> {
        Box::new(Self::new(stream))
    }
}

impl Read for TcpTransportSession {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buffer)
    }
}

impl Write for TcpTransportSession {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl TransportSession for TcpTransportSession {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    fn relay_to_client(mut self: Box<Self>, mut client: TcpStream) -> io::Result<()> {
        self.stream.set_read_timeout(None)?;
        self.stream.set_write_timeout(None)?;
        client.set_read_timeout(None)?;
        client.set_write_timeout(None)?;
        client.set_nodelay(true)?;
        self.stream.set_nodelay(true)?;

        let mut client_reader = client.try_clone()?;
        let mut remote_writer = self.stream.try_clone()?;
        let uplink = thread::Builder::new()
            .name("commeatus-transport-tcp-up".to_owned())
            .spawn(move || -> io::Result<u64> {
                match io::copy(&mut client_reader, &mut remote_writer) {
                    Ok(copied) => {
                        remote_writer.shutdown(Shutdown::Write)?;
                        Ok(copied)
                    }
                    Err(error) => {
                        let _ = client_reader.shutdown(Shutdown::Both);
                        let _ = remote_writer.shutdown(Shutdown::Both);
                        Err(error)
                    }
                }
            })?;

        let downlink = io::copy(&mut self.stream, &mut client);
        let shutdown = match &downlink {
            Ok(_) => client.shutdown(Shutdown::Write),
            Err(_) => {
                let _ = client.shutdown(Shutdown::Both);
                let _ = self.stream.shutdown(Shutdown::Both);
                Ok(())
            }
        };
        let uplink = uplink
            .join()
            .map_err(|_| io::Error::other("TCP transport relay worker panicked"))?;

        downlink?;
        shutdown?;
        uplink?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener};

    use super::*;

    #[test]
    fn tcp_transport_declares_plain_reliable_stream_only() {
        let transport = TcpTransport::new("127.0.0.1:443".parse().unwrap());
        assert_eq!(
            transport.capabilities(),
            TransportCapabilities {
                reliable_stream: true,
                datagram: false,
                encrypted: false,
            }
        );
    }

    #[test]
    fn zero_timeout_is_rejected() {
        assert!(
            TcpTransport::with_timeouts(
                "127.0.0.1:443".parse().unwrap(),
                Duration::ZERO,
                Duration::from_secs(1),
            )
            .is_err()
        );
    }

    #[test]
    fn tcp_transport_connects_to_loopback_listener() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let transport = TcpTransport::new(address);
        let session = transport.connect().unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        assert_eq!(session.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
    }
}
