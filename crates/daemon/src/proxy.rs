use std::{
    io,
    net::{Shutdown, SocketAddr, TcpStream},
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

use commeatus_core::{
    Destination, DestinationHost, ExecutionAction, FlowContext, FlowId, NetworkContext, Runtime,
    SourceContext, TransportProtocol,
};

static NEXT_FLOW_ID: AtomicU64 = AtomicU64::new(1);

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
    pub fn flow(&self) -> FlowContext {
        FlowContext::new(
            FlowId::new(NEXT_FLOW_ID.fetch_add(1, Ordering::Relaxed)),
            SourceContext::default(),
            Destination {
                host: self.host.clone(),
                port: self.port,
            },
            TransportProtocol::Tcp,
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
pub fn authorize(runtime: &Runtime, target: &Target) -> Authorization {
    match runtime.plan(&target.flow()).action {
        ExecutionAction::Route { .. } => Authorization::Direct,
        ExecutionAction::Reject { .. } => Authorization::Reject,
    }
}

pub fn connect_direct(target: &Target) -> io::Result<TcpStream> {
    let stream = match &target.host {
        DestinationHost::Domain(domain) => TcpStream::connect((domain.as_str(), target.port))?,
        DestinationHost::Ip(address) => TcpStream::connect(SocketAddr::new(*address, target.port))?,
    };
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Copy bytes in both directions while preserving TCP half-close semantics.
pub fn relay(mut client: TcpStream, mut remote: TcpStream) -> io::Result<()> {
    client.set_nodelay(true)?;
    remote.set_nodelay(true)?;

    let mut client_reader = client.try_clone()?;
    let mut remote_writer = remote.try_clone()?;

    let uplink = thread::spawn(move || -> io::Result<u64> {
        let copied = io::copy(&mut client_reader, &mut remote_writer)?;
        remote_writer.shutdown(Shutdown::Write)?;
        Ok(copied)
    });

    let downlink_result = io::copy(&mut remote, &mut client);
    let shutdown_result = client.shutdown(Shutdown::Write);
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
        assert_eq!(authorize(&runtime, &target), Authorization::Reject);
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
        assert_eq!(authorize(&runtime, &target), Authorization::Direct);
        let client = connect_direct(&target).unwrap();
        let (_server, _) = listener.accept().unwrap();
        assert_eq!(client.peer_addr().unwrap(), address);
    }
}
