use std::{
    io,
    net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use commeatus_core::{
    Destination, DestinationHost, ExecutionAction, FlowContext, FlowId, NetworkContext, Runtime,
    SourceContext, TransportProtocol,
};

static NEXT_FLOW_ID: AtomicU64 = AtomicU64::new(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESOLVED_ADDRESSES: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    pub host: DestinationHost,
    pub port: u16,
}

impl Target {
    pub fn new(host: DestinationHost, port: u16) -> io::Result<Self> {
        if port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination port must not be zero",
            ));
        }
        Ok(Self { host, port })
    }

    #[must_use]
    pub fn flow(&self, transport: TransportProtocol) -> FlowContext {
        FlowContext::new(
            FlowId::new(NEXT_FLOW_ID.fetch_add(1, Ordering::Relaxed)),
            SourceContext::default(),
            Destination {
                host: self.host.clone(),
                port: self.port,
            },
            transport,
            NetworkContext::default(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authorization {
    Direct,
    Reject,
}

#[must_use]
pub fn authorize(runtime: &Runtime, target: &Target, transport: TransportProtocol) -> Authorization {
    match runtime.plan(&target.flow(transport)).action {
        ExecutionAction::Route { .. } => Authorization::Direct,
        ExecutionAction::Reject { .. } => Authorization::Reject,
    }
}

pub fn connect_direct(target: &Target) -> io::Result<TcpStream> {
    let addresses = resolve_target(target)?;
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut last_error = None;

    for address in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&address, remaining) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "no resolved address connected before timeout",
        )
    }))
}

pub(crate) fn resolve_target(target: &Target) -> io::Result<Vec<SocketAddr>> {
    let mut addresses = match &target.host {
        DestinationHost::Domain(domain) => (domain.as_str(), target.port)
            .to_socket_addrs()?
            .take(MAX_RESOLVED_ADDRESSES)
            .collect::<Vec<_>>(),
        DestinationHost::Ip(address) => vec![SocketAddr::new(*address, target.port)],
    };
    addresses.dedup();
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "destination resolved to no usable addresses",
        ));
    }
    Ok(addresses)
}

/// Copy bytes in both directions while preserving TCP half-close semantics.
pub fn relay(mut client: TcpStream, mut remote: TcpStream) -> io::Result<()> {
    client.set_nodelay(true)?;
    remote.set_nodelay(true)?;

    let mut client_reader = client.try_clone()?;
    let mut remote_writer = remote.try_clone()?;

    let uplink = thread::Builder::new()
        .name("commeatus-relay-up".to_owned())
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

    let downlink_result = io::copy(&mut remote, &mut client);
    let shutdown_result = match &downlink_result {
        Ok(_) => client.shutdown(Shutdown::Write),
        Err(_) => {
            let _ = client.shutdown(Shutdown::Both);
            let _ = remote.shutdown(Shutdown::Both);
            Ok(())
        }
    };
    let uplink_result = uplink
        .join()
        .map_err(|_| io::Error::other("relay worker panicked"))?;

    downlink_result?;
    shutdown_result?;
    uplink_result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener};

    use commeatus_core::{Endpoint, PolicyAction, PolicyEngine};

    use super::*;

    #[test]
    fn policy_rejection_is_preserved_before_connect() {
        let runtime = Runtime::new(PolicyEngine::new(
            Vec::new(),
            PolicyAction::Reject(commeatus_core::RejectReason::Policy),
        ));
        let target = Target::new(DestinationHost::Ip(Ipv4Addr::LOCALHOST.into()), 80).unwrap();
        assert_eq!(
            authorize(&runtime, &target, TransportProtocol::Tcp),
            Authorization::Reject
        );
    }

    #[test]
    fn transport_is_part_of_policy_authorization() {
        let runtime = Runtime::new(PolicyEngine::new(
            vec![commeatus_core::PolicyRule {
                id: commeatus_core::RuleId::new(1),
                tier: commeatus_core::PolicyTier::UserHard,
                matcher: commeatus_core::Matcher::Transport(TransportProtocol::Udp),
                action: PolicyAction::Reject(commeatus_core::RejectReason::Policy),
            }],
            PolicyAction::Route(Endpoint::Direct),
        ));
        let target = Target::new(DestinationHost::Ip(Ipv4Addr::LOCALHOST.into()), 53).unwrap();
        assert_eq!(
            authorize(&runtime, &target, TransportProtocol::Tcp),
            Authorization::Direct
        );
        assert_eq!(
            authorize(&runtime, &target, TransportProtocol::Udp),
            Authorization::Reject
        );
    }

    #[test]
    fn direct_connector_reaches_local_listener() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let runtime = Runtime::new(PolicyEngine::new(
            Vec::new(),
            PolicyAction::Route(Endpoint::Direct),
        ));
        let target = Target::new(DestinationHost::Ip(address.ip()), address.port()).unwrap();
        assert_eq!(
            authorize(&runtime, &target, TransportProtocol::Tcp),
            Authorization::Direct
        );
        let client = connect_direct(&target).unwrap();
        let (_server, _) = listener.accept().unwrap();
        assert_eq!(client.peer_addr().unwrap(), address);
    }

    #[test]
    fn resolver_deduplicates_and_bounds_addresses() {
        let target = Target::new(DestinationHost::Domain("localhost".to_owned()), 80).unwrap();
        let addresses = resolve_target(&target).unwrap();
        assert!(!addresses.is_empty());
        assert!(addresses.len() <= MAX_RESOLVED_ADDRESSES);
        let mut unique = addresses.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), addresses.len());
    }
}
