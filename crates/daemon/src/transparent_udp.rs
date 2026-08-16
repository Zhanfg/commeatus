use std::{
    collections::HashMap,
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket as StdUdpSocket},
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
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
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
                token_clients
                    .get(&token)
                    .copied()
                    .map(|client| (token, client))
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
                    .send(
                        &received.source,
                        client,
                        &outbound_buffer[..received.length],
                    )
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
        .send_with(endpoint, target, payload, registry, tokens, |endpoint| {
            outbounds.open_datagram(endpoint, Arc::clone(dns))
        })
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
    if message
        .flags
        .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
    {
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
    let socket = Socket::new(
        Domain::for_address(source),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
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
        .map(|state| {
            CLIENT_IDLE_TIMEOUT.saturating_sub(now.saturating_duration_since(state.last_activity))
        })
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
