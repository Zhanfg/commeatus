use std::{collections::HashMap, io};

use commeatus_core::{Endpoint, EndpointId};
use commeatus_dns::DnsEngine;
use commeatus_transport::{
    TcpTransport, TcpTransportSession, TlsTransport, TransportCapabilities, TransportConnector,
    TransportSession,
};

use crate::{
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
                    udp: false,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol;

    #[test]
    fn provider_requirement_rejects_trojan_over_plain_tcp() {
        let id = EndpointId::new("trojan").unwrap();
        let result = OutboundRegistry::new(vec![ProxyEndpointConfig {
            id,
            protocol: protocol::trojan("secret").unwrap(),
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
            transport: TransportConfig::Tls(tls),
        }])
        .unwrap();
        let capabilities = registry.capabilities(&Endpoint::Proxy(id)).unwrap();
        assert!(capabilities.supports_tcp());
        assert!(!capabilities.supports_udp());
        assert!(capabilities.encrypted_transport());
    }
}
