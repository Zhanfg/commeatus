use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::Arc,
};

use commeatus_core::DestinationHost;
use commeatus_dns::DnsEngine;

use crate::proxy::{self, Target};

pub const MAX_DATAGRAM_REMOTE_PEERS: usize = 256;
const MAX_UNTRUSTED_DRAIN_PER_RECEIVE: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedDatagram {
    pub source: Target,
    pub length: usize,
}

/// Long-lived logical datagram path selected by an execution plan.
///
/// This interface deliberately models datagram semantics rather than a
/// particular carrier. A future Trojan/VLESS association may frame datagrams
/// over a reliable stream while a QUIC-native provider may use carrier
/// datagrams. Callers therefore do not receive an OS socket from this trait.
pub trait DatagramAssociation: Send {
    fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()>;

    /// Receive one datagram from a peer previously contacted by this
    /// association. Nonblocking implementations return `Ok(None)` when no
    /// trusted datagram is currently ready.
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<ReceivedDatagram>>;
}

/// DIRECT datagram execution.
///
/// DNS resolution and remote-peer ownership live here rather than in an
/// inbound protocol. The association uses dedicated outbound sockets so the
/// SOCKS5 client-facing relay socket is never also the public-network socket.
pub struct DirectDatagramAssociation {
    dns: Arc<DnsEngine>,
    ipv4: UdpSocket,
    ipv6: Option<UdpSocket>,
    remote_peers: HashSet<SocketAddr>,
}

impl DirectDatagramAssociation {
    pub fn new(dns: Arc<DnsEngine>) -> io::Result<Self> {
        let ipv4 = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
        ipv4.set_nonblocking(true)?;
        Ok(Self {
            dns,
            ipv4,
            ipv6: None,
            remote_peers: HashSet::new(),
        })
    }

    #[must_use]
    pub fn remote_peer_count(&self) -> usize {
        self.remote_peers.len()
    }

    fn ensure_ipv6(&mut self) -> io::Result<&UdpSocket> {
        if self.ipv6.is_none() {
            let socket = UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))?;
            socket.set_nonblocking(true)?;
            self.ipv6 = Some(socket);
        }
        Ok(self
            .ipv6
            .as_ref()
            .expect("IPv6 socket was just initialized"))
    }

    fn send_to_resolved(&mut self, address: SocketAddr, payload: &[u8]) -> io::Result<()> {
        if !self.remote_peers.contains(&address)
            && self.remote_peers.len() >= MAX_DATAGRAM_REMOTE_PEERS
        {
            return Err(io::Error::new(
                io::ErrorKind::QuotaExceeded,
                format!(
                    "datagram association remote peer limit {MAX_DATAGRAM_REMOTE_PEERS} reached"
                ),
            ));
        }

        let sent = match address {
            SocketAddr::V4(_) => self.ipv4.send_to(payload, address),
            SocketAddr::V6(_) => self.ensure_ipv6()?.send_to(payload, address),
        }?;
        if sent != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "UDP socket reported a partial datagram send",
            ));
        }
        self.remote_peers.insert(address);
        Ok(())
    }

    fn receive_from_socket(
        socket: &UdpSocket,
        remote_peers: &HashSet<SocketAddr>,
        buffer: &mut [u8],
    ) -> io::Result<Option<ReceivedDatagram>> {
        for _ in 0..MAX_UNTRUSTED_DRAIN_PER_RECEIVE {
            match socket.recv_from(buffer) {
                Ok((length, source)) => {
                    if !remote_peers.contains(&source) {
                        continue;
                    }
                    let target = Target::new(DestinationHost::Ip(source.ip()), source.port())?;
                    return Ok(Some(ReceivedDatagram {
                        source: target,
                        length,
                    }));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    #[cfg(test)]
    fn ipv4_local_addr(&self) -> io::Result<SocketAddr> {
        self.ipv4.local_addr()
    }
}

impl DatagramAssociation for DirectDatagramAssociation {
    fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        let addresses = proxy::resolve_target(target, &self.dns)?;
        let mut last_error = None;

        for address in addresses {
            match self.send_to_resolved(address, payload) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "datagram target resolved to no usable address",
            )
        }))
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<ReceivedDatagram>> {
        if buffer.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram receive buffer must not be empty",
            ));
        }

        if let Some(received) = Self::receive_from_socket(&self.ipv4, &self.remote_peers, buffer)? {
            return Ok(Some(received));
        }
        if let Some(ipv6) = &self.ipv6 {
            return Self::receive_from_socket(ipv6, &self.remote_peers, buffer);
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::UdpSocket,
        thread,
        time::{Duration, Instant},
    };

    use commeatus_dns::HostsTable;

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(3);

    fn dns(hosts: &str) -> Arc<DnsEngine> {
        Arc::new(DnsEngine::system(HostsTable::parse(hosts).unwrap()))
    }

    fn receive_until(
        association: &mut DirectDatagramAssociation,
        buffer: &mut [u8],
    ) -> io::Result<ReceivedDatagram> {
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            if let Some(received) = association.receive(buffer)? {
                return Ok(received);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "test datagram was not received before deadline",
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn direct_ipv4_round_trip_preserves_source() {
        let remote = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        remote.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let remote_address = remote.local_addr().unwrap();
        let remote_thread = thread::spawn(move || {
            let mut buffer = [0_u8; 64];
            let (length, client) = remote.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], b"ping");
            remote.send_to(b"pong", client).unwrap();
        });

        let mut association = DirectDatagramAssociation::new(dns("")).unwrap();
        let target = Target::new(
            DestinationHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            remote_address.port(),
        )
        .unwrap();
        association.send(&target, b"ping").unwrap();

        let mut buffer = [0_u8; 64];
        let received = receive_until(&mut association, &mut buffer).unwrap();
        assert_eq!(&buffer[..received.length], b"pong");
        assert_eq!(
            received.source.host,
            DestinationHost::Ip(remote_address.ip())
        );
        assert_eq!(received.source.port, remote_address.port());
        remote_thread.join().unwrap();
    }

    #[test]
    fn direct_domain_resolution_is_owned_by_association() {
        let remote = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        remote.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let remote_address = remote.local_addr().unwrap();
        let remote_thread = thread::spawn(move || {
            let mut buffer = [0_u8; 64];
            let (length, _) = remote.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], b"domain-route");
        });

        let mut association = DirectDatagramAssociation::new(dns("127.0.0.1 direct.test")).unwrap();
        let target = Target::new(
            DestinationHost::Domain("direct.test".to_owned()),
            remote_address.port(),
        )
        .unwrap();
        association.send(&target, b"domain-route").unwrap();
        remote_thread.join().unwrap();
        assert_eq!(association.remote_peer_count(), 1);
    }

    #[test]
    fn zero_length_datagram_is_valid() {
        let remote = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        remote.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let remote_address = remote.local_addr().unwrap();
        let mut association = DirectDatagramAssociation::new(dns("")).unwrap();
        let target = Target::new(
            DestinationHost::Ip(remote_address.ip()),
            remote_address.port(),
        )
        .unwrap();

        association.send(&target, &[]).unwrap();
        let mut buffer = [0_u8; 1];
        let (length, _) = remote.recv_from(&mut buffer).unwrap();
        assert_eq!(length, 0);
    }

    #[test]
    fn unsolicited_remote_is_not_exposed() {
        let mut association = DirectDatagramAssociation::new(dns("")).unwrap();
        let attacker = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        attacker
            .send_to(b"unsolicited", association.ipv4_local_addr().unwrap())
            .unwrap();

        let deadline = Instant::now() + TEST_TIMEOUT;
        let mut buffer = [0_u8; 64];
        loop {
            match association.receive(&mut buffer).unwrap() {
                Some(_) => panic!("unsolicited datagram escaped the remote allowlist"),
                None if Instant::now() >= deadline => break,
                None => thread::sleep(Duration::from_millis(1)),
            }
        }
    }

    #[test]
    fn remote_peer_limit_is_bounded() {
        let mut association = DirectDatagramAssociation::new(dns("")).unwrap();
        for port in 10_000_u16..10_000_u16 + MAX_DATAGRAM_REMOTE_PEERS as u16 {
            let target =
                Target::new(DestinationHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), port).unwrap();
            association.send(&target, b"x").unwrap();
        }
        assert_eq!(association.remote_peer_count(), MAX_DATAGRAM_REMOTE_PEERS);

        let overflow =
            Target::new(DestinationHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 20_000).unwrap();
        let error = association.send(&overflow, b"x").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::QuotaExceeded);
    }

    #[test]
    fn direct_ipv6_round_trip_when_loopback_is_available() {
        let Ok(remote) = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) else {
            return;
        };
        remote.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let remote_address = remote.local_addr().unwrap();
        let remote_thread = thread::spawn(move || {
            let mut buffer = [0_u8; 64];
            let (length, client) = remote.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], b"v6-ping");
            remote.send_to(b"v6-pong", client).unwrap();
        });

        let mut association = DirectDatagramAssociation::new(dns("")).unwrap();
        let target = Target::new(
            DestinationHost::Ip(remote_address.ip()),
            remote_address.port(),
        )
        .unwrap();
        association.send(&target, b"v6-ping").unwrap();

        let mut buffer = [0_u8; 64];
        let received = receive_until(&mut association, &mut buffer).unwrap();
        assert_eq!(&buffer[..received.length], b"v6-pong");
        assert_eq!(
            received.source.host,
            DestinationHost::Ip(remote_address.ip())
        );
        remote_thread.join().unwrap();
    }
}
