from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one match in {path}, found {count}: {old!r}")
    p.write_text(text.replace(old, new, 1))


# Safe ancillary-data wrappers for ORIGDSTADDR on Linux/Android.
replace_once(
    "crates/daemon/Cargo.toml",
    'socket2 = { version = "=0.6.5", features = ["all"] }\n',
    'socket2 = { version = "=0.6.5", features = ["all"] }\nnix = { version = "=0.31.3", features = ["socket", "uio", "net"] }\n',
)

# A token allocator can now be shared by many inbound logical associations.
replace_once(
    "crates/daemon/src/datagram.rs",
    '''pub struct DatagramRouteSet {
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
''',
    '''#[derive(Clone, Debug)]
pub struct DatagramTokenAllocator {
    next_token: usize,
}

impl DatagramTokenAllocator {
    #[must_use]
    pub const fn new(first_token: Token) -> Self {
        Self {
            next_token: first_token.0,
        }
    }

    fn allocate(&mut self, count: usize) -> io::Result<Vec<Token>> {
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram execution path declared zero readiness sources",
            ));
        }
        let end = self.next_token.checked_add(count).ok_or_else(|| {
            io::Error::new(io::ErrorKind::OutOfMemory, "datagram token space exhausted")
        })?;
        let tokens = (self.next_token..end).map(Token).collect::<Vec<_>>();
        self.next_token = end;
        Ok(tokens)
    }
}

pub struct DatagramRouteSet {
    routes: HashMap<Endpoint, DatagramRoute>,
}

impl DatagramRouteSet {
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }
''',
)
replace_once(
    "crates/daemon/src/datagram.rs",
    '''        registry: &Registry,
        open: F,
''',
    '''        registry: &Registry,
        token_allocator: &mut DatagramTokenAllocator,
        open: F,
''',
)
replace_once(
    "crates/daemon/src/datagram.rs",
    '''            let source_count = execution.readiness_source_count();
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
''',
    '''            let source_count = execution.readiness_source_count();
            let tokens = token_allocator.allocate(source_count)?;
            execution.register_readiness(registry, &tokens)?;
''',
)
replace_once(
    "crates/daemon/src/datagram.rs",
    '''    #[must_use]
    pub fn owns_token(&self, token: Token) -> bool {
''',
    '''    #[must_use]
    pub fn owned_tokens(&self) -> Vec<Token> {
        self.routes
            .values()
            .flat_map(|route| route.tokens.iter().copied())
            .collect()
    }

    #[must_use]
    pub fn owns_token(&self, token: Token) -> bool {
''',
)

# Update SOCKS5 to use the reusable allocator. Semantics stay otherwise identical.
replace_once(
    "crates/daemon/src/socks5.rs",
    "    datagram::DatagramRouteSet,\n",
    "    datagram::{DatagramRouteSet, DatagramTokenAllocator},\n",
)
replace_once(
    "crates/daemon/src/socks5.rs",
    "    let mut routes = DatagramRouteSet::new(UDP_OUTBOUND_FIRST_TOKEN);\n",
    "    let mut route_tokens = DatagramTokenAllocator::new(UDP_OUTBOUND_FIRST_TOKEN);\n    let mut routes = DatagramRouteSet::new();\n",
)
replace_once(
    "crates/daemon/src/socks5.rs",
    '''                            &mut routes,
                            poll.registry(),
''',
    '''                            &mut routes,
                            &mut route_tokens,
                            poll.registry(),
''',
)
replace_once(
    "crates/daemon/src/socks5.rs",
    '''fn handle_udp_client_packet(
    routes: &mut DatagramRouteSet,
    registry: &mio::Registry,
''',
    '''fn handle_udp_client_packet(
    routes: &mut DatagramRouteSet,
    token_allocator: &mut DatagramTokenAllocator,
    registry: &mio::Registry,
''',
)
replace_once(
    "crates/daemon/src/socks5.rs",
    '''        .send_with(endpoint, &target, payload, registry, |endpoint| {
            outbounds.open_datagram(endpoint, Arc::clone(dns))
        })
''',
    '''        .send_with(
            endpoint,
            &target,
            payload,
            registry,
            token_allocator,
            |endpoint| outbounds.open_datagram(endpoint, Arc::clone(dns)),
        )
''',
)

# Route-set tests: constructor and shared allocator.
p = Path("crates/daemon/src/datagram.rs")
text = p.read_text()
text = text.replace(
    "let mut routes = DatagramRouteSet::new(Token(8));",
    "let mut allocator = DatagramTokenAllocator::new(Token(8));\n        let mut routes = DatagramRouteSet::new();",
)
text = text.replace(
    "let mut routes = DatagramRouteSet::new(Token(32));",
    "let mut allocator = DatagramTokenAllocator::new(Token(32));\n        let mut routes = DatagramRouteSet::new();",
)
# Exactly four sends exist in these two route-set tests.
text = text.replace(
    "                    poll.registry(),\n                    move |_| {",
    "                    poll.registry(),\n                    &mut allocator,\n                    move |_| {",
)
text = text.replace(
    "routes\n                .send_with(endpoint, &target, b\"x\", poll.registry(), |_| {",
    "routes\n                .send_with(endpoint, &target, b\"x\", poll.registry(), &mut allocator, |_| {",
)
text = text.replace(
    ".send_with(overflow, &target, b\"x\", poll.registry(), |_| {",
    ".send_with(overflow, &target, b\"x\", poll.registry(), &mut allocator, |_| {",
)
p.write_text(text)

# Listener config: TCP and UDP occupy separate socket namespaces, so the same numeric port is valid.
replace_once(
    "crates/daemon/src/config.rs",
    '''pub enum ListenerProtocol {
    Socks5,
    HttpConnect,
    TproxyTcp,
}''',
    '''pub enum ListenerProtocol {
    Socks5,
    HttpConnect,
    TproxyTcp,
    TproxyUdp,
}

impl ListenerProtocol {
    const fn is_udp(self) -> bool {
        matches!(self, Self::TproxyUdp)
    }
}''',
)
replace_once(
    "crates/daemon/src/config.rs",
    '"listen syntax is `listen <socks5|http|tproxy-tcp> <ip:port>`",',
    '"listen syntax is `listen <socks5|http|tproxy-tcp|tproxy-udp> <ip:port>`",',
)
replace_once(
    "crates/daemon/src/config.rs",
    '''                    "socks5" => ListenerProtocol::Socks5,
                    "http" => ListenerProtocol::HttpConnect,
                    "tproxy-tcp" => ListenerProtocol::TproxyTcp,
                    _ => {
                        return Err(ConfigError::at(
                            line_number,
                            "listener protocol must be `socks5`, `http`, or `tproxy-tcp`",
                        ));
                    }''',
    '''                    "socks5" => ListenerProtocol::Socks5,
                    "http" => ListenerProtocol::HttpConnect,
                    "tproxy-tcp" => ListenerProtocol::TproxyTcp,
                    "tproxy-udp" => ListenerProtocol::TproxyUdp,
                    _ => {
                        return Err(ConfigError::at(
                            line_number,
                            "listener protocol must be `socks5`, `http`, `tproxy-tcp`, or `tproxy-udp`",
                        ));
                    }''',
)
replace_once(
    "crates/daemon/src/config.rs",
    '''                if !listener_addresses.insert(address) {
                    return Err(ConfigError::at(
                        line_number,
                        "two listeners cannot bind the same socket address",
                    ));
                }
''',
    '''                if !listener_addresses.insert((protocol.is_udp(), address)) {
                    return Err(ConfigError::at(
                        line_number,
                        "two listeners cannot bind the same transport/socket address",
                    ));
                }
''',
)

# Module graph.
replace_once(
    "crates/daemon/src/lib.rs",
    "mod transparent_tcp;\n",
    "mod transparent_tcp;\nmod transparent_udp;\n",
)

Path("crates/daemon/src/transparent_udp.rs").write_text(r'''use std::{
    collections::HashMap,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
    os::fd::AsRawFd,
    sync::Arc,
    time::{Duration, Instant},
};

use commeatus_core::{DestinationHost, ExecutionAction, Runtime, TransportProtocol};
use commeatus_dns::DnsEngine;
use mio::{Events, Interest, Poll, Token, net::UdpSocket as MioUdpSocket};
use nix::{
    cmsg_space,
    errno::Errno,
    libc::{sockaddr_in, sockaddr_in6},
    sys::socket::{
        ControlMessageOwned, MsgFlags, SockaddrIn, SockaddrIn6, SockaddrStorage, recvmsg,
        setsockopt, sockopt,
    },
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::{
    datagram::{DatagramRouteSet, DatagramTokenAllocator},
    outbound::{EndpointCapabilities, OutboundRegistry},
    proxy::{self, Target},
};

const INBOUND_TOKEN: Token = Token(0);
const OUTBOUND_FIRST_TOKEN: Token = Token(1);
const MAX_PACKET: usize = 65_535;
const MAX_EVENT_BURST: usize = 32;
const MAX_CLIENTS: usize = 512;
const MAX_REPLY_SOCKETS: usize = 256;
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const REPLY_SOCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

pub struct TransparentUdpListener {
    socket: MioUdpSocket,
}

struct ReceivedTransparentDatagram {
    client: SocketAddr,
    target: Target,
    length: usize,
}

struct ClientState {
    routes: DatagramRouteSet,
    last_activity: Instant,
}

struct ReplySocket {
    socket: StdUdpSocket,
    last_used: Instant,
}

struct ReplySocketCache {
    sockets: HashMap<SocketAddr, ReplySocket>,
}

impl ReplySocketCache {
    fn new() -> Self {
        Self {
            sockets: HashMap::new(),
        }
    }

    fn cleanup_expired(&mut self, now: Instant) {
        self.sockets.retain(|_, reply| {
            now.saturating_duration_since(reply.last_used) < REPLY_SOCKET_IDLE_TIMEOUT
        });
    }

    fn send(&mut self, source: &Target, client: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let source = target_socket_addr(source)?;
        if source.is_ipv4() != client.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transparent UDP reply source/client address families differ",
            ));
        }

        if !self.sockets.contains_key(&source) {
            self.cleanup_expired(Instant::now());
            if self.sockets.len() >= MAX_REPLY_SOCKETS {
                if let Some(oldest) = self
                    .sockets
                    .iter()
                    .min_by_key(|(_, reply)| reply.last_used)
                    .map(|(source, _)| *source)
                {
                    self.sockets.remove(&oldest);
                }
            }
            let socket = bind_transparent_reply_socket(source)?;
            self.sockets.insert(
                source,
                ReplySocket {
                    socket,
                    last_used: Instant::now(),
                },
            );
        }

        let reply = self.sockets.get_mut(&source).ok_or_else(|| {
            io::Error::other("transparent UDP reply socket disappeared after insertion")
        })?;
        let sent = reply.socket.send_to(payload, client)?;
        if sent != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "transparent UDP reply reported a partial datagram send",
            ));
        }
        reply.last_used = Instant::now();
        Ok(())
    }
}

pub fn bind_listener(address: SocketAddr) -> io::Result<TransparentUdpListener> {
    let socket = Socket::new(Domain::for_address(address), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    match address {
        SocketAddr::V4(_) => {
            socket.set_ip_transparent_v4(true)?;
            setsockopt(&socket, sockopt::Ipv4OrigDstAddr, &true).map_err(nix_to_io)?;
        }
        SocketAddr::V6(_) => {
            socket.set_only_v6(true)?;
            socket.set_ip_transparent_v6(true)?;
            setsockopt(&socket, sockopt::Ipv6OrigDstAddr, &true).map_err(nix_to_io)?;
        }
    }
    socket.bind(&SockAddr::from(address))?;
    socket.set_nonblocking(true)?;
    let socket: StdUdpSocket = socket.into();
    Ok(TransparentUdpListener {
        socket: MioUdpSocket::from_std(socket),
    })
}

pub fn serve_forever(
    mut listener: TransparentUdpListener,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
) -> io::Result<()> {
    let mut poll = Poll::new()?;
    poll.registry()
        .register(&mut listener.socket, INBOUND_TOKEN, Interest::READABLE)?;

    let mut events = Events::with_capacity(64);
    let mut clients: HashMap<SocketAddr, ClientState> = HashMap::new();
    let mut token_clients: HashMap<Token, SocketAddr> = HashMap::new();
    let mut tokens = DatagramTokenAllocator::new(OUTBOUND_FIRST_TOKEN);
    let mut reply_sockets = ReplySocketCache::new();
    let mut inbound_buffer = vec![0_u8; MAX_PACKET];
    let mut outbound_buffer = vec![0_u8; MAX_PACKET];

    loop {
        let timeout = next_client_timeout(&clients, Instant::now());
        match poll.poll(&mut events, timeout) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }

        let now = Instant::now();
        cleanup_idle_clients(&mut clients, &mut token_clients, now);
        reply_sockets.cleanup_expired(now);

        let inbound_ready = events
            .iter()
            .any(|event| event.token() == INBOUND_TOKEN && event.is_readable());
        if inbound_ready {
            for _ in 0..MAX_EVENT_BURST {
                let Some(received) = recv_original_datagram(&listener.socket, &mut inbound_buffer)?
                else {
                    break;
                };
                if handle_inbound(
                    received.client,
                    &received.target,
                    &inbound_buffer[..received.length],
                    &mut clients,
                    &mut token_clients,
                    &mut tokens,
                    poll.registry(),
                    &runtime,
                    &dns,
                    &outbounds,
                ) {
                    if let Some(state) = clients.get_mut(&received.client) {
                        state.last_activity = Instant::now();
                    }
                }
            }
        }

        let outbound_ready = events
            .iter()
            .filter_map(|event| {
                let token = event.token();
                token_clients.get(&token).copied().map(|client| (token, client))
            })
            .collect::<Vec<_>>();

        for (token, client) in outbound_ready {
            for _ in 0..MAX_EVENT_BURST {
                let received = {
                    let Some(state) = clients.get_mut(&client) else {
                        token_clients.remove(&token);
                        break;
                    };
                    state.routes.receive_ready(token, &mut outbound_buffer)?
                };
                let Some(received) = received else {
                    break;
                };
                if reply_sockets
                    .send(&received.source, client, &outbound_buffer[..received.length])
                    .is_ok()
                {
                    if let Some(state) = clients.get_mut(&client) {
                        state.last_activity = Instant::now();
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_inbound(
    client: SocketAddr,
    target: &Target,
    payload: &[u8],
    clients: &mut HashMap<SocketAddr, ClientState>,
    token_clients: &mut HashMap<Token, SocketAddr>,
    tokens: &mut DatagramTokenAllocator,
    registry: &mio::Registry,
    runtime: &Runtime,
    dns: &Arc<DnsEngine>,
    outbounds: &OutboundRegistry,
) -> bool {
    let endpoint = match proxy::plan_action(runtime, target, TransportProtocol::Udp) {
        ExecutionAction::Reject { .. } => return false,
        ExecutionAction::Route { endpoint } => endpoint,
    };
    if !outbounds
        .capabilities(&endpoint)
        .is_some_and(EndpointCapabilities::supports_udp)
    {
        return false;
    }

    if !clients.contains_key(&client) {
        cleanup_idle_clients(clients, token_clients, Instant::now());
        if clients.len() >= MAX_CLIENTS {
            return false;
        }
        clients.insert(
            client,
            ClientState {
                routes: DatagramRouteSet::new(),
                last_activity: Instant::now(),
            },
        );
    }

    let state = clients.get_mut(&client).expect("client inserted above");
    if state
        .routes
        .send_with(
            endpoint,
            target,
            payload,
            registry,
            tokens,
            |endpoint| outbounds.open_datagram(endpoint, Arc::clone(dns)),
        )
        .is_err()
    {
        return false;
    }
    for token in state.routes.owned_tokens() {
        token_clients.insert(token, client);
    }
    true
}

fn recv_original_datagram(
    socket: &MioUdpSocket,
    buffer: &mut [u8],
) -> io::Result<Option<ReceivedTransparentDatagram>> {
    let mut iov = [IoSliceMut::new(buffer)];
    let mut cmsgs = cmsg_space!(sockaddr_in, sockaddr_in6);
    let message = match recvmsg::<SockaddrStorage>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut cmsgs),
        MsgFlags::MSG_DONTWAIT,
    ) {
        Ok(message) => message,
        Err(Errno::EAGAIN) => return Ok(None),
        Err(Errno::EINTR) => return Ok(None),
        Err(error) => return Err(nix_to_io(error)),
    };
    if message.flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "transparent UDP datagram or original-destination metadata was truncated",
        ));
    }
    let client = message
        .address
        .as_ref()
        .and_then(storage_to_socket_addr)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "UDP client address missing"))?;
    let length = message.bytes;
    let mut original = None;
    for cmsg in message.cmsgs().map_err(nix_to_io)? {
        match cmsg {
            ControlMessageOwned::Ipv4OrigDstAddr(raw) => {
                let address: SockaddrIn = raw.into();
                original = Some(SocketAddr::from(address));
            }
            ControlMessageOwned::Ipv6OrigDstAddr(raw) => {
                let address: SockaddrIn6 = raw.into();
                original = Some(SocketAddr::from(address));
            }
            _ => {}
        }
    }
    let original = original.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "TPROXY UDP datagram arrived without original destination metadata",
        )
    })?;
    let target = Target::new(DestinationHost::Ip(original.ip()), original.port())?;
    Ok(Some(ReceivedTransparentDatagram {
        client,
        target,
        length,
    }))
}

fn storage_to_socket_addr(storage: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(address) = storage.as_sockaddr_in() {
        return Some(SocketAddr::from(*address));
    }
    storage
        .as_sockaddr_in6()
        .map(|address| SocketAddr::from(*address))
}

fn target_socket_addr(target: &Target) -> io::Result<SocketAddr> {
    match target.host {
        DestinationHost::Ip(ip) => Ok(SocketAddr::new(ip, target.port)),
        DestinationHost::Domain(_) => Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "transparent UDP reply source must be an IP address",
        )),
    }
}

fn bind_transparent_reply_socket(source: SocketAddr) -> io::Result<StdUdpSocket> {
    let socket = Socket::new(Domain::for_address(source), Type::DGRAM, Some(Protocol::UDP))?;
    match source {
        SocketAddr::V4(_) => socket.set_ip_transparent_v4(true)?,
        SocketAddr::V6(_) => {
            socket.set_only_v6(true)?;
            socket.set_ip_transparent_v6(true)?;
        }
    }
    socket.bind(&SockAddr::from(source))?;
    Ok(socket.into())
}

fn next_client_timeout(
    clients: &HashMap<SocketAddr, ClientState>,
    now: Instant,
) -> Option<Duration> {
    clients
        .values()
        .map(|state| CLIENT_IDLE_TIMEOUT.saturating_sub(now.saturating_duration_since(state.last_activity)))
        .min()
}

fn cleanup_idle_clients(
    clients: &mut HashMap<SocketAddr, ClientState>,
    token_clients: &mut HashMap<Token, SocketAddr>,
    now: Instant,
) {
    let expired = clients
        .iter()
        .filter(|(_, state)| {
            now.saturating_duration_since(state.last_activity) >= CLIENT_IDLE_TIMEOUT
        })
        .map(|(client, _)| *client)
        .collect::<Vec<_>>();
    for client in expired {
        if let Some(state) = clients.remove(&client) {
            for token in state.routes.owned_tokens() {
                token_clients.remove(&token);
            }
        }
    }
}

fn nix_to_io(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires root/CAP_NET_ADMIN for transparent nonlocal UDP bind"]
    fn privileged_reply_socket_preserves_nonlocal_source_bind() {
        let source: SocketAddr = "198.51.100.77:43123".parse().unwrap();
        let socket = bind_transparent_reply_socket(source).unwrap();
        assert_eq!(socket.local_addr().unwrap(), source);
    }
}
''')

# Server owns TCP and UDP listeners transactionally, then supervises one thread per listener.
Path("crates/daemon/src/server.rs").write_text(r'''use std::{
    io,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use commeatus_core::Runtime;
use commeatus_dns::DnsEngine;
#[cfg(test)]
use commeatus_dns::HostsTable;

use crate::{
    config::{CompiledConfig, ListenerProtocol},
    http_connect,
    outbound::OutboundRegistry,
    socks5, transparent_tcp, transparent_udp,
};

const ACCEPT_ERROR_RETRY_LIMIT: usize = 8;
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
pub const MAX_ACTIVE_CONNECTIONS: usize = 256;

enum BoundListener {
    Tcp {
        protocol: ListenerProtocol,
        listener: TcpListener,
    },
    TproxyUdp {
        address: SocketAddr,
        listener: transparent_udp::TransparentUdpListener,
    },
}

impl BoundListener {
    fn address(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tcp { listener, .. } => listener.local_addr(),
            Self::TproxyUdp { address, .. } => Ok(*address),
        }
    }
}

struct ConnectionLimiter {
    active: AtomicUsize,
    limit: usize,
}

impl ConnectionLimiter {
    fn new(limit: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            limit,
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        let mut active = self.active.load(Ordering::Relaxed);
        loop {
            if active >= self.limit {
                return None;
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(ConnectionPermit { limiter: Arc::clone(self) }),
                Err(current) => active = current,
            }
        }
    }
}

struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::Release);
    }
}

pub struct Server {
    listeners: Vec<BoundListener>,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
    limiter: Arc<ConnectionLimiter>,
}

impl Server {
    pub fn bind(config: &CompiledConfig) -> io::Result<Self> {
        let mut listeners = Vec::with_capacity(config.listeners().len());
        for listener in config.listeners() {
            let bound = match listener.protocol {
                ListenerProtocol::TproxyUdp => BoundListener::TproxyUdp {
                    address: listener.address,
                    listener: transparent_udp::bind_listener(listener.address)?,
                },
                ListenerProtocol::TproxyTcp => BoundListener::Tcp {
                    protocol: listener.protocol,
                    listener: transparent_tcp::bind_listener(listener.address)?,
                },
                ListenerProtocol::Socks5 | ListenerProtocol::HttpConnect => BoundListener::Tcp {
                    protocol: listener.protocol,
                    listener: TcpListener::bind(listener.address)?,
                },
            };
            listeners.push(bound);
        }
        Ok(Self {
            listeners,
            runtime: Arc::new(config.runtime().clone()),
            dns: Arc::clone(config.dns()),
            outbounds: Arc::clone(config.outbounds()),
            limiter: Arc::new(ConnectionLimiter::new(MAX_ACTIVE_CONNECTIONS)),
        })
    }

    pub fn run(self) -> io::Result<()> {
        let (exit_tx, exit_rx) = mpsc::channel();

        for bound in self.listeners {
            let runtime = Arc::clone(&self.runtime);
            let dns = Arc::clone(&self.dns);
            let outbounds = Arc::clone(&self.outbounds);
            let limiter = Arc::clone(&self.limiter);
            let tx = exit_tx.clone();
            let address = bound.address()?;
            thread::Builder::new()
                .name(format!("commeatus-listener-{address}"))
                .spawn(move || {
                    let result = match bound {
                        BoundListener::Tcp { protocol, listener } => serve_forever(
                            listener,
                            protocol,
                            runtime,
                            dns,
                            outbounds,
                            limiter,
                        ),
                        BoundListener::TproxyUdp { listener, .. } => {
                            transparent_udp::serve_forever(listener, runtime, dns, outbounds)
                        }
                    };
                    let _ = tx.send((address, result));
                })?;
        }
        drop(exit_tx);

        match exit_rx.recv() {
            Ok((address, Ok(()))) => Err(io::Error::other(format!(
                "listener {address} exited unexpectedly"
            ))),
            Ok((address, Err(error))) => Err(io::Error::new(
                error.kind(),
                format!("listener {address} failed: {error}"),
            )),
            Err(_) => Err(io::Error::other("all listener supervisors terminated")),
        }
    }
}

fn serve_forever(
    listener: TcpListener,
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
    limiter: Arc<ConnectionLimiter>,
) -> io::Result<()> {
    let mut consecutive_errors = 0_usize;
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                consecutive_errors = 0;
                spawn_connection(
                    stream,
                    peer,
                    protocol,
                    Arc::clone(&runtime),
                    Arc::clone(&dns),
                    Arc::clone(&outbounds),
                    Arc::clone(&limiter),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                consecutive_errors += 1;
                eprintln!(
                    "commeatus: listener accept error ({consecutive_errors}/{ACCEPT_ERROR_RETRY_LIMIT}): {error}"
                );
                if consecutive_errors >= ACCEPT_ERROR_RETRY_LIMIT {
                    return Err(error);
                }
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

fn spawn_connection(
    stream: TcpStream,
    peer: SocketAddr,
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
    limiter: Arc<ConnectionLimiter>,
) {
    let Some(permit) = limiter.try_acquire() else {
        eprintln!(
            "commeatus: connection from {peer} rejected: active connection limit {MAX_ACTIVE_CONNECTIONS} reached"
        );
        drop(stream);
        return;
    };

    if let Err(error) = thread::Builder::new()
        .name("commeatus-session".to_owned())
        .spawn(move || {
            let _permit = permit;
            if let Err(error) = handle_connection(stream, protocol, runtime, dns, outbounds) {
                eprintln!("commeatus: connection from {peer} ended with error: {error}");
            }
        })
    {
        eprintln!(
            "commeatus: connection from {peer} rejected: cannot create handler thread: {error}"
        );
    }
}

fn handle_connection(
    stream: TcpStream,
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
) -> io::Result<()> {
    match protocol {
        ListenerProtocol::Socks5 => socks5::handle(stream, runtime, dns, outbounds),
        ListenerProtocol::HttpConnect => http_connect::handle(stream, runtime, dns, outbounds),
        ListenerProtocol::TproxyTcp => transparent_tcp::handle(stream, runtime, dns, outbounds),
        ListenerProtocol::TproxyUdp => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP listener cannot enter TCP connection dispatch",
        )),
    }
}

#[cfg(test)]
pub(crate) fn spawn_test_listener(
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    connection_count: usize,
) -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    spawn_test_listener_with_runtime(
        protocol,
        runtime,
        Arc::new(DnsEngine::system(HostsTable::default())),
        Arc::new(OutboundRegistry::default()),
        connection_count,
    )
}

#[cfg(test)]
pub(crate) fn spawn_test_listener_with_dns(
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    connection_count: usize,
) -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    spawn_test_listener_with_runtime(
        protocol,
        runtime,
        dns,
        Arc::new(OutboundRegistry::default()),
        connection_count,
    )
}

#[cfg(test)]
pub(crate) fn spawn_test_listener_with_runtime(
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
    connection_count: usize,
) -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let handle = thread::Builder::new()
        .name("commeatus-test-listener".to_owned())
        .spawn(move || {
            serve_n(
                listener,
                protocol,
                runtime,
                dns,
                outbounds,
                connection_count,
            )
        })?;
    Ok((address, handle))
}

#[cfg(test)]
fn serve_n(
    listener: TcpListener,
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
    connection_count: usize,
) -> io::Result<()> {
    let mut connections = Vec::with_capacity(connection_count);
    for _ in 0..connection_count {
        let (stream, _) = listener.accept()?;
        let runtime = Arc::clone(&runtime);
        let dns = Arc::clone(&dns);
        let outbounds = Arc::clone(&outbounds);
        connections.push(
            thread::Builder::new()
                .name("commeatus-test-session".to_owned())
                .spawn(move || handle_connection(stream, protocol, runtime, dns, outbounds))?,
        );
    }

    for connection in connections {
        match connection.join() {
            Ok(Ok(())) | Ok(Err(_)) => {}
            Err(_) => return Err(io::Error::other("test connection handler panicked")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_limiter_never_exceeds_limit_and_releases_permits() {
        let limiter = Arc::new(ConnectionLimiter::new(2));
        let first = limiter.try_acquire().unwrap();
        let second = limiter.try_acquire().unwrap();
        assert!(limiter.try_acquire().is_none());
        drop(first);
        let third = limiter.try_acquire().unwrap();
        assert!(limiter.try_acquire().is_none());
        drop(second);
        drop(third);
        assert_eq!(limiter.active.load(Ordering::Relaxed), 0);
    }
}
''')

# Full Root helper: TCP + UDP, same mark/table, protocol-specific chains and probes.
Path("scripts/android-root-tproxy.sh").write_text(r'''#!/system/bin/sh
set -eu

PORT="${COMMEATUS_TPROXY_PORT:-12948}"
MARK="${COMMEATUS_TPROXY_MARK:-0x66c0}"
MASK="${COMMEATUS_TPROXY_MASK:-0xffff}"
TABLE="${COMMEATUS_TPROXY_TABLE:-20660}"
PREF="${COMMEATUS_TPROXY_PREF:-20660}"
UID_RANGE="${COMMEATUS_UID_RANGE:-10000-999999}"
IPV6="${COMMEATUS_IPV6:-1}"
STATE_DIR="${COMMEATUS_STATE_DIR:-/data/local/tmp/commeatus-root}"
TCP_OUT="CMT_TCP_OUT"
TCP_PRE="CMT_TCP_PRE"
UDP_OUT="CMT_UDP_OUT"
UDP_PRE="CMT_UDP_PRE"
PID_FILE="$STATE_DIR/commeatus.pid"
LOG_FILE="$STATE_DIR/commeatus.log"

say() { echo "commeatus-root: $*" >&2; }
die() { say "$*"; exit 1; }
need_root() { [ "$(id -u)" = "0" ] || die "root is required"; }
need_tools() {
    command -v ip >/dev/null 2>&1 || die "missing ip"
    command -v iptables >/dev/null 2>&1 || die "missing iptables"
    if [ "$IPV6" = "1" ]; then command -v ip6tables >/dev/null 2>&1 || die "IPv6 requested but ip6tables is missing"; fi
}
ipt() { iptables -w "$@"; }
ipt6() { ip6tables -w "$@"; }

remove_family() {
    local cmd="$1" ipcmd="$2"
    for proto_chain in "tcp:$TCP_OUT:$TCP_PRE" "udp:$UDP_OUT:$UDP_PRE"; do
        local proto out pre
        proto="${proto_chain%%:*}"
        local rest="${proto_chain#*:}"
        out="${rest%%:*}"
        pre="${rest#*:}"
        $cmd -t mangle -D OUTPUT -p "$proto" -j "$out" 2>/dev/null || true
        $cmd -t mangle -D PREROUTING -p "$proto" -m mark --mark "$MARK/$MASK" -j "$pre" 2>/dev/null || true
        $cmd -t mangle -F "$out" 2>/dev/null || true
        $cmd -t mangle -X "$out" 2>/dev/null || true
        $cmd -t mangle -F "$pre" 2>/dev/null || true
        $cmd -t mangle -X "$pre" 2>/dev/null || true
    done
    $ipcmd rule del pref "$PREF" fwmark "$MARK/$MASK" lookup "$TABLE" 2>/dev/null || true
    $ipcmd route flush table "$TABLE" 2>/dev/null || true
}
remove_rules() {
    remove_family "iptables -w" "ip"
    if [ "$IPV6" = "1" ]; then remove_family "ip6tables -w" "ip -6"; fi
}

probe_one() {
    local cmd="$1" family="$2" proto="$3" on_ip="$4" suffix="$5"
    local chain="CMT_PROBE_${proto}_${suffix}"
    $cmd -t mangle -N "$chain" 2>/dev/null || die "cannot create $family $proto TPROXY probe chain"
    if ! $cmd -t mangle -A "$chain" -p "$proto" -j TPROXY --on-ip "$on_ip" --on-port "$PORT" --tproxy-mark "$MARK/$MASK"; then
        $cmd -t mangle -F "$chain" 2>/dev/null || true
        $cmd -t mangle -X "$chain" 2>/dev/null || true
        die "$family $proto TPROXY is unavailable"
    fi
    $cmd -t mangle -F "$chain"
    $cmd -t mangle -X "$chain"
}
probe_all() {
    probe_one "iptables -w" IPv4 tcp 127.0.0.1 4
    probe_one "iptables -w" IPv4 udp 127.0.0.1 4
    if [ "$IPV6" = "1" ]; then
        probe_one "ip6tables -w" IPv6 tcp ::1 6
        probe_one "ip6tables -w" IPv6 udp ::1 6
    fi
}

ensure_table_free() {
    [ -z "$(ip route show table "$TABLE" 2>/dev/null)" ] || die "IPv4 route table $TABLE is already in use"
    if [ "$IPV6" = "1" ]; then [ -z "$(ip -6 route show table "$TABLE" 2>/dev/null)" ] || die "IPv6 route table $TABLE is already in use"; fi
}

install_protocol_chain() {
    local cmd="$1" proto="$2" out="$3" pre="$4" on_ip="$5"
    $cmd -t mangle -N "$out"
    if [ "$cmd" = "iptables -w" ]; then
        $cmd -t mangle -A "$out" -d 127.0.0.0/8 -j RETURN
        $cmd -t mangle -A "$out" -d 169.254.0.0/16 -j RETURN
        $cmd -t mangle -A "$out" -d 224.0.0.0/4 -j RETURN
    else
        $cmd -t mangle -A "$out" -d ::1/128 -j RETURN
        $cmd -t mangle -A "$out" -d fe80::/10 -j RETURN
        $cmd -t mangle -A "$out" -d ff00::/8 -j RETURN
    fi
    $cmd -t mangle -A "$out" -p "$proto" -m owner --uid-owner "$UID_RANGE" -j MARK --set-xmark "$MARK/$MASK"
    $cmd -t mangle -N "$pre"
    $cmd -t mangle -A "$pre" -p "$proto" -j TPROXY --on-ip "$on_ip" --on-port "$PORT" --tproxy-mark "$MARK/$MASK"
    $cmd -t mangle -I PREROUTING 1 -p "$proto" -m mark --mark "$MARK/$MASK" -j "$pre"
}

install_rules() {
    need_root; need_tools; remove_rules; ensure_table_free; probe_all
    trap 'remove_rules' INT TERM HUP EXIT
    ip route add local 0.0.0.0/0 dev lo table "$TABLE"
    ip rule add pref "$PREF" fwmark "$MARK/$MASK" lookup "$TABLE"
    install_protocol_chain "iptables -w" tcp "$TCP_OUT" "$TCP_PRE" 127.0.0.1
    install_protocol_chain "iptables -w" udp "$UDP_OUT" "$UDP_PRE" 127.0.0.1
    if [ "$IPV6" = "1" ]; then
        ip -6 route add local ::/0 dev lo table "$TABLE"
        ip -6 rule add pref "$PREF" fwmark "$MARK/$MASK" lookup "$TABLE"
        install_protocol_chain "ip6tables -w" tcp "$TCP_OUT" "$TCP_PRE" ::1
        install_protocol_chain "ip6tables -w" udp "$UDP_OUT" "$UDP_PRE" ::1
    fi
    # Enable app marking only after all local delivery/TPROXY hooks exist.
    ipt -t mangle -I OUTPUT 1 -p tcp -j "$TCP_OUT"
    ipt -t mangle -I OUTPUT 1 -p udp -j "$UDP_OUT"
    if [ "$IPV6" = "1" ]; then
        ipt6 -t mangle -I OUTPUT 1 -p tcp -j "$TCP_OUT"
        ipt6 -t mangle -I OUTPUT 1 -p udp -j "$UDP_OUT"
    fi
    trap - INT TERM HUP EXIT
    say "TCP+UDP TPROXY installed: port=$PORT mark=$MARK/$MASK table=$TABLE uid-range=$UID_RANGE ipv6=$IPV6"
}

process_running() {
    [ -f "$PID_FILE" ] || return 1
    local pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}
start_daemon() {
    need_root; need_tools
    [ "$#" -ge 1 ] || die "start requires <config> [binary]"
    local config="$1" binary="${2:-./commeatus}"
    [ -f "$config" ] || die "config not found: $config"
    [ -x "$binary" ] || die "binary not executable: $binary"
    mkdir -p "$STATE_DIR"
    process_running && die "daemon already running with pid $(cat "$PID_FILE")"
    remove_rules
    : > "$LOG_FILE"
    nohup "$binary" run --config "$config" >>"$LOG_FILE" 2>&1 </dev/null &
    local pid=$!
    echo "$pid" > "$PID_FILE"
    local n=0
    while [ "$n" -lt 50 ]; do
        if ! kill -0 "$pid" 2>/dev/null; then rm -f "$PID_FILE"; tail -n 80 "$LOG_FILE" >&2 || true; die "daemon exited during startup"; fi
        [ "$n" -ge 5 ] && break
        sleep 0.1; n=$((n + 1))
    done
    if ! install_rules; then kill "$pid" 2>/dev/null || true; rm -f "$PID_FILE"; exit 1; fi
    say "daemon started: pid=$pid log=$LOG_FILE"
}
stop_daemon() {
    need_root; need_tools; remove_rules
    if process_running; then
        local pid="$(cat "$PID_FILE")" n=0
        kill "$pid" 2>/dev/null || true
        while kill -0 "$pid" 2>/dev/null && [ "$n" -lt 30 ]; do sleep 0.1; n=$((n + 1)); done
        kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"; say "TPROXY rules removed and daemon stopped"
}
status() {
    need_root; need_tools
    process_running && say "daemon running: pid=$(cat "$PID_FILE")" || say "daemon not running"
    ip rule show | grep -F "fwmark" | grep -F "$TABLE" || true
    for chain in "$TCP_OUT" "$TCP_PRE" "$UDP_OUT" "$UDP_PRE"; do ipt -t mangle -S "$chain" 2>/dev/null || true; done
    if [ "$IPV6" = "1" ]; then
        ip -6 rule show | grep -F "fwmark" | grep -F "$TABLE" || true
        for chain in "$TCP_OUT" "$TCP_PRE" "$UDP_OUT" "$UDP_PRE"; do ipt6 -t mangle -S "$chain" 2>/dev/null || true; done
    fi
}
case "${1:-}" in
    install) install_rules ;;
    remove) need_root; need_tools; remove_rules ;;
    start) shift; start_daemon "$@" ;;
    stop) stop_daemon ;;
    restart) shift; stop_daemon; start_daemon "$@" ;;
    status) status ;;
    *) echo "usage: $0 start <config> [binary] | stop | restart <config> [binary] | install | remove | status" >&2; exit 2 ;;
esac
''')

# Full Root example; TCP and UDP deliberately share the numeric port.
Path("examples/android-root-tproxy.conf").write_text(r'''# Android Root v0.6 development preview: transparent TCP + UDP.
# Replace the TEST-NET-3 Trojan endpoint before real use.
version 1

listen socks5 127.0.0.1:1080
listen tproxy-tcp 127.0.0.1:12948
listen tproxy-udp 127.0.0.1:12948
listen tproxy-tcp [::1]:12948
listen tproxy-udp [::1]:12948

# Optional secure DNS used when Commeatus itself must resolve a domain.
# resolver dot 1.1.1.1:853 cloudflare-dns.com

endpoint edge trojan tls 203.0.113.10:443 trojan.example change-me

rule direct cidr 127.0.0.0/8
rule direct cidr ::1/128
default proxy:edge
''')

Path("docs/android-root-tproxy-preview.md").write_text(r'''# Android Root transparent preview (v0.6 development)

This preview carries ordinary Android application TCP **and UDP** through the native Commeatus runtime without a userspace TUN packet stack.

```text
selected app TCP/UDP
  -> OUTPUT mark
  -> policy route to loopback
  -> protocol-specific TPROXY
  -> tproxy-tcp / tproxy-udp listener
  -> native Flow/Policy
  -> DIRECT or native proxy endpoint (Trojan supports both TCP and UDP)
```

For UDP, the listener receives the kernel original destination through `ORIGDSTADDR` ancillary metadata. Every local UDP client address owns an independent bounded `DatagramRouteSet`; DIRECT and Trojan UDP therefore reuse the same provider boundary as SOCKS5 UDP instead of a second routing implementation.

Replies are sent from a bounded cache of transparent sockets bound to the real remote source IP **and port**. This is necessary because packet-info can choose a source IP but cannot change the UDP source port. CI proves the client observes the exact remote `IP:port` through the full TPROXY namespace path.

## Run

Copy `examples/android-root-tproxy.conf`, replace the TEST-NET endpoint/password, then from a root shell:

```sh
chmod 755 ./commeatus ./scripts/android-root-tproxy.sh
./commeatus check --config ./android-root.conf
./scripts/android-root-tproxy.sh start ./android-root.conf ./commeatus
./scripts/android-root-tproxy.sh status
```

Stop and restore networking:

```sh
./scripts/android-root-tproxy.sh stop
```

The default interception UID range is `10000-999999`. Narrow it while testing with `COMMEATUS_UID_RANGE=<uid>-<uid>`. IPv6 remains enabled by default; disabling it requires explicit `COMMEATUS_IPV6=0`.

## Current alpha constraints

- the daemon still runs as root in this preview; privilege separation is a later supervisor slice;
- transparent UDP state is keyed by local client socket address and expires after 120 seconds idle;
- at most 512 transparent UDP clients, 32 outbound endpoints per client, 256 remote peers per DIRECT association, and 256 cached reply-source sockets are retained;
- root lifecycle is shell-based until the installable module/supervisor package lands;
- QUIC is carried as ordinary UDP but Commeatus does not inspect QUIC semantics;
- no automatic boot enablement is shipped by this source slice.
''')
