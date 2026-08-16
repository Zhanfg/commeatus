use std::{collections::HashMap, io, sync::Arc};

use commeatus_core::{Endpoint, EndpointId};
use commeatus_dns::DnsEngine;
use commeatus_transport::{
    TcpTransport, TcpTransportSession, TlsTransport, TransportCapabilities, TransportConnector,
    TransportSession,
};

use crate::{
    datagram::{DatagramExecution, DatagramProviderRef, DirectDatagramAssociation},
    protocol::ProtocolRef,
    proxy::{self, Target},
};

#[derive(Clone, Debug)]
pub enum TransportConfig {
    Tcp(TcpTransport),
    Tls(TlsTransport),
}

impl TransportConfig {
    #[must_use]
    fn capabilities(&self) -> TransportCapabilities {
        match self {
            Self::Tcp(transport) => transport.capabilities(),
            Self::Tls(transport) => transport.capabilities(),
        }
    }

    #[must_use]
    fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    fn connect(&self) -> io::Result<Box<dyn TransportSession>> {
        match self {
            Self::Tcp(transport) => transport.connect(),
            Self::Tls(transport) => transport.connect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProxyEndpointConfig {
    pub id: EndpointId,
    pub protocol: ProtocolRef,
    pub datagram: Option<DatagramProviderRef>,
    pub transport: TransportConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointCapabilities {
    tcp: bool,
    udp: bool,
    encrypted_transport: bool,
}

impl EndpointCapabilities {
    #[must_use]
    pub const fn supports_tcp(self) -> bool {
        self.tcp
    }

    #[must_use]
    pub const fn supports_udp(self) -> bool {
        self.udp
    }

    #[must_use]
    pub const fn encrypted_transport(self) -> bool {
        self.encrypted_transport
    }
}

#[derive(Clone, Debug, Default)]
pub struct OutboundRegistry {
    endpoints: HashMap<EndpointId, ProxyEndpointConfig>,
}

impl OutboundRegistry {
    pub fn new(endpoints: Vec<ProxyEndpointConfig>) -> Result<Self, io::Error> {
        let mut registry = HashMap::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let protocol = endpoint.protocol.capabilities();
            if protocol.requires_tls && !endpoint.transport.is_tls() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "{} endpoint `{}` requires a TLS transport",
                        endpoint.protocol.name(),
                        endpoint.id.as_str()
                    ),
                ));
            }

            let id = endpoint.id.clone();
            if registry.insert(id.clone(), endpoint).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("duplicate outbound endpoint `{}`", id.as_str()),
                ));
            }
        }
        Ok(Self {
            endpoints: registry,
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    #[must_use]
    pub fn contains(&self, id: &EndpointId) -> bool {
        self.endpoints.contains_key(id)
    }

    #[must_use]
    pub fn capabilities(&self, endpoint: &Endpoint) -> Option<EndpointCapabilities> {
        match endpoint {
            Endpoint::Direct => Some(EndpointCapabilities {
                tcp: true,
                udp: true,
                encrypted_transport: false,
            }),
            Endpoint::Proxy(id) => self.endpoints.get(id).map(|config| {
                let transport = config.transport.capabilities();
                let protocol = config.protocol.capabilities();
                EndpointCapabilities {
                    tcp: protocol.stream_connect && transport.reliable_stream,
                    udp: config.datagram.is_some(),
                    encrypted_transport: transport.encrypted,
                }
            }),
        }
    }

    pub fn connect_tcp(
        &self,
        endpoint: &Endpoint,
        target: &Target,
        dns: &DnsEngine,
    ) -> io::Result<Box<dyn TransportSession>> {
        if !self
            .capabilities(endpoint)
            .is_some_and(EndpointCapabilities::supports_tcp)
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "selected outbound endpoint does not support TCP",
            ));
        }

        match endpoint {
            Endpoint::Direct => {
                let stream = proxy::connect_direct(target, dns)?;
                Ok(TcpTransportSession::boxed(stream))
            }
            Endpoint::Proxy(id) => {
                let config = self.endpoints.get(id).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("proxy endpoint `{}` is not registered", id.as_str()),
                    )
                })?;
                let mut session = config.transport.connect()?;
                config.protocol.handshake_stream(session.as_mut(), target)?;
                Ok(session)
            }
        }
    }

    /// Open the concrete datagram execution path for an endpoint.
    ///
    /// This is the single factory authority used by inbound datagram
    /// executors. DIRECT is implemented today. Registered proxy endpoints are
    /// deliberately `Unsupported` until a real proxy datagram provider is
    /// attached; callers must never substitute DIRECT for that error.
    pub fn open_datagram(
        &self,
        endpoint: &Endpoint,
        direct_dns: Arc<DnsEngine>,
    ) -> io::Result<Box<dyn DatagramExecution>> {
        match endpoint {
            Endpoint::Direct => Ok(Box::new(DirectDatagramAssociation::new(direct_dns)?)),
            Endpoint::Proxy(id) => {
                let config = self.endpoints.get(id).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("proxy endpoint `{}` is not registered", id.as_str()),
                    )
                })?;
                let provider = config.datagram.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!(
                            "proxy endpoint `{}` has no datagram execution provider",
                            id.as_str()
                        ),
                    )
                })?;
                provider.open()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use commeatus_dns::HostsTable;

    use super::*;
    use crate::{
        datagram::{DatagramAssociation, OutboundDatagramProvider, ReceivedDatagram},
        protocol,
    };

    fn dns() -> Arc<DnsEngine> {
        Arc::new(DnsEngine::system(HostsTable::default()))
    }

    #[test]
    fn provider_requirement_rejects_trojan_over_plain_tcp() {
        let id = EndpointId::new("trojan").unwrap();
        let result = OutboundRegistry::new(vec![ProxyEndpointConfig {
            id,
            protocol: protocol::trojan_with_verifier(
                crate::trojan::TrojanVerifier::new("secret").unwrap(),
            ),
            datagram: None,
            transport: TransportConfig::Tcp(TcpTransport::new("127.0.0.1:443".parse().unwrap())),
        }]);
        assert!(result.is_err());
    }

    #[test]
    fn endpoint_capability_combines_protocol_and_transport() {
        let id = EndpointId::new("edge").unwrap();
        let registry = OutboundRegistry::new(vec![ProxyEndpointConfig {
            id: id.clone(),
            protocol: protocol::socks5(),
            datagram: None,
            transport: TransportConfig::Tcp(TcpTransport::new("127.0.0.1:1081".parse().unwrap())),
        }])
        .unwrap();
        let capabilities = registry.capabilities(&Endpoint::Proxy(id)).unwrap();
        assert!(capabilities.supports_tcp());
        assert!(!capabilities.supports_udp());
        assert!(!capabilities.encrypted_transport());
    }

    #[test]
    fn encrypted_endpoint_capability_comes_from_transport() {
        let id = EndpointId::new("secure").unwrap();
        let tls = TlsTransport::webpki("127.0.0.1:443".parse().unwrap(), "proxy.example").unwrap();
        let registry = OutboundRegistry::new(vec![ProxyEndpointConfig {
            id: id.clone(),
            protocol: protocol::http_connect(),
            datagram: None,
            transport: TransportConfig::Tls(tls),
        }])
        .unwrap();
        let capabilities = registry.capabilities(&Endpoint::Proxy(id)).unwrap();
        assert!(capabilities.supports_tcp());
        assert!(!capabilities.supports_udp());
        assert!(capabilities.encrypted_transport());
    }

    #[test]
    fn datagram_factory_opens_direct_execution() {
        let registry = OutboundRegistry::default();
        let execution = registry.open_datagram(&Endpoint::Direct, dns()).unwrap();
        assert!(execution.readiness_source_count() >= 1);
    }

    #[test]
    fn datagram_factory_rejects_proxy_without_provider() {
        let id = EndpointId::new("edge").unwrap();
        let registry = OutboundRegistry::new(vec![ProxyEndpointConfig {
            id: id.clone(),
            protocol: protocol::socks5(),
            datagram: None,
            transport: TransportConfig::Tcp(TcpTransport::new("127.0.0.1:1081".parse().unwrap())),
        }])
        .unwrap();
        let error = registry
            .open_datagram(&Endpoint::Proxy(id), dns())
            .err()
            .expect("proxy datagram factory unexpectedly succeeded");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[derive(Debug)]
    struct FakeDatagramProvider {
        opens: Arc<AtomicUsize>,
    }

    #[derive(Debug)]
    struct FakeDatagramExecution;

    impl DatagramAssociation for FakeDatagramExecution {
        fn send(&mut self, _target: &Target, _payload: &[u8]) -> io::Result<()> {
            Ok(())
        }

        fn receive(&mut self, _buffer: &mut [u8]) -> io::Result<Option<ReceivedDatagram>> {
            Ok(None)
        }
    }

    impl DatagramExecution for FakeDatagramExecution {
        fn readiness_source_count(&self) -> usize {
            1
        }

        fn register_readiness(
            &mut self,
            _registry: &mio::Registry,
            tokens: &[mio::Token],
        ) -> io::Result<()> {
            if tokens.len() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "fake datagram execution requires one readiness token",
                ));
            }
            Ok(())
        }
    }

    impl OutboundDatagramProvider for FakeDatagramProvider {
        fn open(&self) -> io::Result<Box<dyn DatagramExecution>> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FakeDatagramExecution))
        }
    }

    #[test]
    fn attached_datagram_provider_drives_capability_and_factory() {
        let id = EndpointId::new("udp-edge").unwrap();
        let opens = Arc::new(AtomicUsize::new(0));
        let provider: DatagramProviderRef = Arc::new(FakeDatagramProvider {
            opens: Arc::clone(&opens),
        });
        let registry = OutboundRegistry::new(vec![ProxyEndpointConfig {
            id: id.clone(),
            protocol: protocol::socks5(),
            datagram: Some(provider),
            transport: TransportConfig::Tcp(TcpTransport::new("127.0.0.1:1081".parse().unwrap())),
        }])
        .unwrap();
        let endpoint = Endpoint::Proxy(id);

        let capabilities = registry.capabilities(&endpoint).unwrap();
        assert!(capabilities.supports_tcp());
        assert!(capabilities.supports_udp());
        assert_eq!(opens.load(Ordering::SeqCst), 0);

        let execution = registry.open_datagram(&endpoint, dns()).unwrap();
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        assert_eq!(execution.readiness_source_count(), 1);
    }
}
