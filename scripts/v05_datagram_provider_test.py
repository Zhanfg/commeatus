from pathlib import Path

path = Path("crates/daemon/src/outbound.rs")
text = path.read_text()

old_imports = '''mod tests {
    use commeatus_dns::HostsTable;

    use super::*;
    use crate::protocol;
'''
new_imports = '''mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use commeatus_dns::HostsTable;

    use super::*;
    use crate::{
        datagram::{DatagramAssociation, OutboundDatagramProvider, ReceivedDatagram},
        protocol,
    };
'''
if text.count(old_imports) != 1:
    raise SystemExit("unexpected outbound test import block")
text = text.replace(old_imports, new_imports, 1)

marker = '''    #[test]
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
}'''
replacement = '''    #[test]
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
}'''
if text.count(marker) != 1:
    raise SystemExit("unexpected outbound datagram test tail")
text = text.replace(marker, replacement, 1)

path.write_text(text)
