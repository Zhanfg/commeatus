use std::{
    io,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Arc,
};

use commeatus_core::{DestinationHost, ExecutionAction, Runtime, TransportProtocol};
use commeatus_dns::DnsEngine;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::{
    outbound::OutboundRegistry,
    proxy::{self, Target},
};

const LISTEN_BACKLOG: i32 = 128;

/// Bind a TCP listener suitable for Linux/Android TPROXY delivery.
///
/// TPROXY preserves the original destination. `IP_TRANSPARENT` / `IPV6_TRANSPARENT`
/// is mandatory on the receiving socket; socket2 provides the platform syscall
/// wrapper without requiring unsafe code in Commeatus.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn bind_listener(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    match address {
        SocketAddr::V4(_) => socket.set_ip_transparent_v4(true)?,
        SocketAddr::V6(_) => {
            socket.set_only_v6(true)?;
            socket.set_ip_transparent_v6(true)?;
        }
    }
    socket.bind(&SockAddr::from(address))?;
    socket.listen(LISTEN_BACKLOG)?;
    Ok(socket.into())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn bind_listener(_address: SocketAddr) -> io::Result<TcpListener> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TPROXY listeners are supported only on Linux and Android",
    ))
}

fn target_from_stream(stream: &TcpStream) -> io::Result<Target> {
    let original = stream.local_addr()?;
    Target::new(DestinationHost::Ip(original.ip()), original.port())
}

/// Execute one transparently intercepted TCP flow through the ordinary native
/// planning and outbound execution path.
pub fn handle(
    stream: TcpStream,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
) -> io::Result<()> {
    let target = target_from_stream(&stream)?;
    match proxy::plan_action(&runtime, &target, TransportProtocol::Tcp) {
        ExecutionAction::Route { endpoint } => {
            let session = outbounds.connect_tcp(&endpoint, &target, &dns)?;
            session.relay_to_client(stream)
        }
        ExecutionAction::Reject { reason } => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("transparent TCP flow rejected by policy: {reason:?}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, TcpListener as StdTcpListener, TcpStream as StdTcpStream},
        thread,
    };

    use super::*;

    #[test]
    fn ordinary_stream_local_address_maps_to_ip_target() {
        let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let thread = thread::spawn(move || StdTcpStream::connect(address).unwrap());
        let (accepted, _) = listener.accept().unwrap();
        let target = target_from_stream(&accepted).unwrap();
        assert_eq!(target.host, DestinationHost::Ip(address.ip()));
        assert_eq!(target.port, address.port());
        drop(thread.join().unwrap());
    }

    #[test]
    #[ignore = "requires root/CAP_NET_ADMIN for IP_TRANSPARENT"]
    fn privileged_transparent_bind_smoke() {
        let listener = bind_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        assert_ne!(listener.local_addr().unwrap().port(), 0);
    }
}
