use std::{
    collections::{HashMap, HashSet},
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
};

use commeatus_core::{DestinationHost, Endpoint};
use commeatus_dns::DnsEngine;
use mio::{Interest, Registry, Token, net::UdpSocket};

use crate::proxy::{self, Target};

pub const MAX_DATAGRAM_REMOTE_PEERS: usize = 256;
pub const MAX_DATAGRAM_ROUTES: usize = 32;
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

/// Executor-facing readiness adapter for a logical datagram association.
///
/// Readiness is deliberately a second trait instead of being part of
/// `DatagramAssociation`: protocol semantics stay carrier-agnostic while the
/// daemon can still drive DIRECT sockets, stream-framed proxy sessions or
/// future QUIC event sources without periodic polling.
pub trait DatagramExecution: DatagramAssociation {
    /// Number of readiness tokens required by this concrete execution path.
    fn readiness_source_count(&self) -> usize;

    /// Register all concrete event sources using exactly `tokens.len()`
    /// caller-owned tokens.
    fn register_readiness(&mut self, registry: &Registry, tokens: &[Token]) -> io::Result<()>;
}

/// Factory owned by a proxy endpoint for opening its logical datagram path.
///
/// The provider captures every implementation-specific construction input.
/// `OutboundRegistry` therefore does not need to know whether the provider
/// uses TLS streams, native QUIC datagrams, multiplexing, or another carrier.
pub trait OutboundDatagramProvider: fmt::Debug + Send + Sync {
    fn open(&self) -> io::Result<Box<dyn DatagramExecution>>;
}

pub type DatagramProviderRef = Arc<dyn OutboundDatagramProvider>;

struct DatagramRoute {
    execution: Box<dyn DatagramExecution>,
    tokens: Vec<Token>,
}

/// Per-inbound-association set of lazily opened outbound datagram routes.
///
/// One SOCKS5 UDP ASSOCIATE may send different targets through different
/// policy-selected endpoints. The route set therefore owns one execution
/// object per endpoint instead of assuming the first datagram fixes the egress
/// for the entire inbound association.
pub struct DatagramRouteSet {
    routes: HashMap<Endpoint, DatagramRoute>,
    next_token: usize,
}

impl DatagramRouteSet {
    #[must_use]
    pub fn new(first_token: Token) -> Self {
        Self {
            routes: HashMap::new(),
            next_token: first_token.0,
        }
    }

    #[cfg(test)]
    #[must_use]
    fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Send through the route selected for `endpoint`, opening and registering
    /// it only on first use.
    pub fn send_with<F>(
        &mut self,
        endpoint: Endpoint,
        target: &Target,
        payload: &[u8],
        registry: &Registry,
        open: F,
    ) -> io::Result<()>
    where
        F: FnOnce(&Endpoint) -> io::Result<Box<dyn DatagramExecution>>,
    {
        if !self.routes.contains_key(&endpoint) {
            if self.routes.len() >= MAX_DATAGRAM_ROUTES {
                return Err(io::Error::new(
                    io::ErrorKind::QuotaExceeded,
                    format!("datagram route limit {MAX_DATAGRAM_ROUTES} reached"),
                ));
            }

            let mut execution = open(&endpoint)?;
            let source_count = execution.readiness_source_count();
            if source_count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "datagram execution path declared zero readiness sources",
                ));
            }
            let end = self.next_token.checked_add(source_count).ok_or_else(|| {
                io::Error::new(io::ErrorKind::OutOfMemory, "datagram token space exhausted")
            })?;
            let tokens = (self.next_token..end).map(Token).collect::<Vec<_>>();
            execution.register_readiness(registry, &tokens)?;
            self.next_token = end;
            self.routes
                .insert(endpoint.clone(), DatagramRoute { execution, tokens });
        }

        let route = self.routes.get_mut(&endpoint).ok_or_else(|| {
            io::Error::other("datagram route disappeared after successful insertion")
        })?;
        route.execution.send(target, payload)
    }

    #[must_use]
    pub fn owns_token(&self, token: Token) -> bool {
        self.routes
            .values()
            .any(|route| route.tokens.contains(&token))
    }

    /// Receive from the route that owns `token`.
    ///
    /// Unknown tokens return `Ok(None)` so the caller can share one poll set
    /// with TCP-control and inbound-relay tokens.
    pub fn receive_ready(
        &mut self,
        token: Token,
        buffer: &mut [u8],
    ) -> io::Result<Option<ReceivedDatagram>> {
        let Some(route) = self
            .routes
            .values_mut()
            .find(|route| route.tokens.contains(&token))
        else {
            return Ok(None);
        };
        route.execution.receive(buffer)
    }
}

/// DIRECT datagram execution.
///
/// DNS resolution and remote-peer ownership live here rather than in an
/// inbound protocol. The association uses dedicated outbound UDP sockets so
/// the SOCKS5 client-facing relay socket is never also the public-network
/// socket.
pub struct DirectDatagramAssociation {
    dns: Arc<DnsEngine>,
    ipv4: UdpSocket,
    ipv6: Option<UdpSocket>,
    remote_peers: HashSet<SocketAddr>,
}

impl DirectDatagramAssociation {
    pub fn new(dns: Arc<DnsEngine>) -> io::Result<Self> {
        let ipv4 = bind_nonblocking(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
        let ipv6 = match bind_nonblocking(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))) {
            Ok(socket) => Some(socket),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
                ) =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        Ok(Self {
            dns,
            ipv4,
            ipv6,
            remote_peers: HashSet::new(),
        })
    }

    #[cfg(test)]
    fn remote_peer_count(&self) -> usize {
        self.remote_peers.len()
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
            SocketAddr::V6(_) => self
                .ipv6
                .as_ref()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "IPv6 datagram socket is unavailable on this platform",
                    )
                })?
                .send_to(payload, address),
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

fn bind_nonblocking(address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = StdUdpSocket::bind(address)?;
    socket.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(socket))
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

impl DatagramExecution for DirectDatagramAssociation {
    fn readiness_source_count(&self) -> usize {
        1 + usize::from(self.ipv6.is_some())
    }

    fn register_readiness(&mut self, registry: &Registry, tokens: &[Token]) -> io::Result<()> {
        let expected = self.readiness_source_count();
        if tokens.len() != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "DIRECT datagram execution requires {expected} readiness tokens, got {}",
                    tokens.len()
                ),
            ));
        }
        registry.register(&mut self.ipv4, tokens[0], Interest::READABLE)?;
        if let Some(ipv6) = &mut self.ipv6 {
            registry.register(ipv6, tokens[1], Interest::READABLE)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, UdpSocket},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    use commeatus_core::EndpointId;
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

    #[derive(Debug)]
    struct FakeExecution {
        sends: Arc<AtomicUsize>,
    }

    impl DatagramAssociation for FakeExecution {
        fn send(&mut self, _target: &Target, _payload: &[u8]) -> io::Result<()> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn receive(&mut self, _buffer: &mut [u8]) -> io::Result<Option<ReceivedDatagram>> {
            Ok(None)
        }
    }

    impl DatagramExecution for FakeExecution {
        fn readiness_source_count(&self) -> usize {
            1
        }

        fn register_readiness(&mut self, _registry: &Registry, tokens: &[Token]) -> io::Result<()> {
            if tokens.len() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "fake execution requires one token",
                ));
            }
            Ok(())
        }
    }

    #[test]
    fn route_set_lazily_opens_once_per_endpoint() {
        let poll = mio::Poll::new().unwrap();
        let mut routes = DatagramRouteSet::new(Token(8));
        let endpoint = Endpoint::Proxy(EndpointId::new("proxy-a").unwrap());
        let target = Target::new(DestinationHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53).unwrap();
        let opens = Arc::new(AtomicUsize::new(0));
        let sends = Arc::new(AtomicUsize::new(0));

        for _ in 0..2 {
            let opens = Arc::clone(&opens);
            let sends = Arc::clone(&sends);
            routes
                .send_with(
                    endpoint.clone(),
                    &target,
                    b"x",
                    poll.registry(),
                    move |_| {
                        opens.fetch_add(1, Ordering::SeqCst);
                        Ok(Box::new(FakeExecution { sends }))
                    },
                )
                .unwrap();
        }

        assert_eq!(opens.load(Ordering::SeqCst), 1);
        assert_eq!(sends.load(Ordering::SeqCst), 2);
        assert_eq!(routes.route_count(), 1);
        assert!(routes.owns_token(Token(8)));
        assert!(!routes.owns_token(Token(9)));
    }

    #[test]
    fn route_set_rejects_unbounded_endpoint_growth() {
        let poll = mio::Poll::new().unwrap();
        let mut routes = DatagramRouteSet::new(Token(32));
        let target = Target::new(DestinationHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53).unwrap();

        for index in 0..MAX_DATAGRAM_ROUTES {
            let endpoint = Endpoint::Proxy(EndpointId::new(format!("proxy-{index}")).unwrap());
            routes
                .send_with(endpoint, &target, b"x", poll.registry(), |_| {
                    Ok(Box::new(FakeExecution {
                        sends: Arc::new(AtomicUsize::new(0)),
                    }))
                })
                .unwrap();
        }
        assert_eq!(routes.route_count(), MAX_DATAGRAM_ROUTES);

        let overflow = Endpoint::Proxy(EndpointId::new("proxy-overflow").unwrap());
        let error = routes
            .send_with(overflow, &target, b"x", poll.registry(), |_| {
                Ok(Box::new(FakeExecution {
                    sends: Arc::new(AtomicUsize::new(0)),
                }))
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::QuotaExceeded);
        assert_eq!(routes.route_count(), MAX_DATAGRAM_ROUTES);
    }
}
