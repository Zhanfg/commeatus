use std::{
    io,
    net::{SocketAddr, TcpStream},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use commeatus_core::{
    Destination, DestinationHost, ExecutionAction, FlowContext, FlowId, NetworkContext, Runtime,
    SourceContext, TransportProtocol,
};
use commeatus_dns::DnsEngine;

static NEXT_FLOW_ID: AtomicU64 = AtomicU64::new(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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

#[must_use]
pub fn plan_action(
    runtime: &Runtime,
    target: &Target,
    transport: TransportProtocol,
) -> ExecutionAction {
    runtime.plan(&target.flow(transport)).action
}

pub fn connect_direct(target: &Target, dns: &DnsEngine) -> io::Result<TcpStream> {
    let addresses = resolve_target(target, dns)?;
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

pub(crate) fn resolve_target(target: &Target, dns: &DnsEngine) -> io::Result<Vec<SocketAddr>> {
    let addresses = match &target.host {
        DestinationHost::Domain(domain) => dns
            .resolve(domain)
            .map_err(|error| io::Error::new(io::ErrorKind::AddrNotAvailable, error.to_string()))?
            .into_iter()
            .map(|address| SocketAddr::new(address, target.port))
            .collect::<Vec<_>>(),
        DestinationHost::Ip(address) => vec![SocketAddr::new(*address, target.port)],
    };
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "destination resolved to no usable addresses",
        ));
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener};

    use commeatus_core::{Endpoint, PolicyAction, PolicyEngine};
    use commeatus_dns::HostsTable;

    use super::*;

    fn dns() -> DnsEngine {
        DnsEngine::system(HostsTable::default())
    }

    #[test]
    fn policy_rejection_is_preserved_before_connect() {
        let runtime = Runtime::new(PolicyEngine::new(
            Vec::new(),
            PolicyAction::Reject(commeatus_core::RejectReason::Policy),
        ));
        let target = Target::new(DestinationHost::Ip(Ipv4Addr::LOCALHOST.into()), 80).unwrap();
        assert!(matches!(
            plan_action(&runtime, &target, TransportProtocol::Tcp),
            ExecutionAction::Reject { .. }
        ));
    }

    #[test]
    fn transport_is_part_of_policy_planning() {
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
        assert!(matches!(
            plan_action(&runtime, &target, TransportProtocol::Tcp),
            ExecutionAction::Route {
                endpoint: Endpoint::Direct
            }
        ));
        assert!(matches!(
            plan_action(&runtime, &target, TransportProtocol::Udp),
            ExecutionAction::Reject { .. }
        ));
    }

    #[test]
    fn direct_connector_reaches_local_listener() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let target = Target::new(DestinationHost::Ip(address.ip()), address.port()).unwrap();
        let client = connect_direct(&target, &dns()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        assert_eq!(client.peer_addr().unwrap(), address);
    }

    #[test]
    fn resolver_deduplicates_and_bounds_addresses() {
        let target = Target::new(DestinationHost::Domain("localhost".to_owned()), 80).unwrap();
        let addresses = resolve_target(&target, &dns()).unwrap();
        assert!(!addresses.is_empty());
        assert!(addresses.len() <= commeatus_dns::MAX_RESOLVED_ADDRESSES);
        let mut unique = addresses.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), addresses.len());
    }
}
