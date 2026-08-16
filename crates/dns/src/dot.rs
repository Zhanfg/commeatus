use std::{
    fmt,
    io::{self, Read, Write},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use commeatus_transport::{TlsTransport, TransportConnector, TransportSession};

use crate::{
    DnsAnswer, DnsError, DnsErrorKind, DnsQuery, Resolver,
    wire::{AddressRecordType, encode_address_query, parse_address_response},
};

const DNS_HEADER_BYTES: usize = 12;
const DOT_LENGTH_BYTES: usize = 2;
const DOT_CONNECT_ATTEMPTS: usize = 2;

pub struct DotResolver {
    connector: Arc<dyn TransportConnector>,
    state: Mutex<DotState>,
    next_id: AtomicU16,
}

impl fmt::Debug for DotResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DotResolver")
            .field("persistent_session", &self.state.lock().is_ok_and(|state| state.session.is_some()))
            .finish_non_exhaustive()
    }
}

impl DotResolver {
    pub fn webpki(address: SocketAddr, server_name: impl Into<String>) -> Result<Self, DnsError> {
        let transport = TlsTransport::webpki(address, server_name).map_err(|error| {
            DnsError::new(
                DnsErrorKind::InvalidConfiguration,
                format!("invalid DNS-over-TLS transport: {error}"),
            )
        })?;
        Ok(Self::with_transport(transport))
    }

    #[must_use]
    pub fn with_transport(transport: TlsTransport) -> Self {
        Self::with_connector(Arc::new(transport))
    }

    fn with_connector(connector: Arc<dyn TransportConnector>) -> Self {
        Self {
            connector,
            state: Mutex::new(DotState::default()),
            next_id: AtomicU16::new(1),
        }
    }

    fn resolve_family(
        &self,
        query: &DnsQuery,
        record_type: AddressRecordType,
    ) -> Result<DnsAnswer, DnsError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = encode_address_query(id, query, record_type)?;
        let mut state = self.state.lock().map_err(|_| {
            DnsError::new(
                DnsErrorKind::ResolverFailure,
                "DNS-over-TLS session lock is poisoned",
            )
        })?;
        let response = state.exchange(&self.connector, &request)?;
        match parse_address_response(id, query, record_type, &response) {
            Ok(answer) => Ok(answer),
            Err(error) => {
                if error.kind() == DnsErrorKind::InvalidResponse {
                    // A malformed response means stream framing can no longer
                    // be trusted for subsequent requests on this connection.
                    state.session = None;
                }
                Err(error)
            }
        }
    }
}

impl Resolver for DotResolver {
    fn resolve(&self, query: &DnsQuery) -> Result<DnsAnswer, DnsError> {
        let mut addresses = Vec::new();
        let mut ttl = None;
        let mut last_error = None;

        for record_type in [AddressRecordType::A, AddressRecordType::Aaaa] {
            match self.resolve_family(query, record_type) {
                Ok(answer) => {
                    for address in answer.addresses() {
                        if !addresses.contains(address) {
                            addresses.push(*address);
                        }
                    }
                    if let Some(answer_ttl) = answer.ttl() {
                        ttl = Some(ttl.map_or(answer_ttl, |current: Duration| current.min(answer_ttl)));
                    }
                }
                Err(error) => last_error = Some(error),
            }
        }

        if addresses.is_empty() {
            Err(last_error.unwrap_or_else(|| {
                DnsError::new(
                    DnsErrorKind::NoRecords,
                    format!("DNS-over-TLS returned no addresses for {}", query.name()),
                )
            }))
        } else {
            DnsAnswer::new(addresses, ttl)
        }
    }
}

#[derive(Default)]
struct DotState {
    session: Option<Box<dyn TransportSession>>,
}

impl DotState {
    fn exchange(
        &mut self,
        connector: &Arc<dyn TransportConnector>,
        request: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        let mut last_error = None;
        for _ in 0..DOT_CONNECT_ATTEMPTS {
            if self.session.is_none() {
                match connector.connect() {
                    Ok(session) => self.session = Some(session),
                    Err(error) => {
                        last_error = Some(error);
                        continue;
                    }
                }
            }

            let result = exchange_message(
                self.session
                    .as_mut()
                    .expect("DoT session exists after successful connector return"),
                request,
            );
            match result {
                Ok(response) => return Ok(response),
                Err(error) => {
                    last_error = Some(error);
                    self.session = None;
                }
            }
        }

        Err(DnsError::new(
            DnsErrorKind::ResolverFailure,
            format!(
                "DNS-over-TLS exchange failed after reconnect: {}",
                last_error
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "unknown transport failure".to_owned())
            ),
        ))
    }
}

fn exchange_message(
    session: &mut Box<dyn TransportSession>,
    request: &[u8],
) -> io::Result<Vec<u8>> {
    let length = u16::try_from(request.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS-over-TLS request exceeds 65535 bytes",
        )
    })?;
    let mut framed = Vec::with_capacity(DOT_LENGTH_BYTES + request.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(request);
    session.write_all(&framed)?;
    session.flush()?;

    let mut length = [0_u8; DOT_LENGTH_BYTES];
    session.read_exact(&mut length)?;
    let length = usize::from(u16::from_be_bytes(length));
    if length < DNS_HEADER_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS-over-TLS response is shorter than a DNS header",
        ));
    }
    let mut response = vec![0_u8; length];
    session.read_exact(&mut response)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        net::{Ipv4Addr, TcpStream},
        sync::atomic::AtomicUsize,
    };

    use commeatus_transport::TransportCapabilities;

    use super::*;

    #[derive(Debug)]
    struct ScriptedConnector {
        connects: Arc<AtomicUsize>,
        ipv4: Ipv4Addr,
        ipv6: std::net::Ipv6Addr,
        ttl_a: u32,
        ttl_aaaa: u32,
    }

    impl TransportConnector for ScriptedConnector {
        fn capabilities(&self) -> TransportCapabilities {
            TransportCapabilities {
                reliable_stream: true,
                datagram: false,
                encrypted: true,
            }
        }

        fn connect(&self) -> io::Result<Box<dyn TransportSession>> {
            self.connects.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(ScriptedSession {
                incoming: Vec::new(),
                outgoing: VecDeque::new(),
                ipv4: self.ipv4,
                ipv6: self.ipv6,
                ttl_a: self.ttl_a,
                ttl_aaaa: self.ttl_aaaa,
            }))
        }
    }

    struct ScriptedSession {
        incoming: Vec<u8>,
        outgoing: VecDeque<u8>,
        ipv4: Ipv4Addr,
        ipv6: std::net::Ipv6Addr,
        ttl_a: u32,
        ttl_aaaa: u32,
    }

    impl ScriptedSession {
        fn process_requests(&mut self) -> io::Result<()> {
            loop {
                if self.incoming.len() < DOT_LENGTH_BYTES {
                    return Ok(());
                }
                let length = usize::from(u16::from_be_bytes([
                    self.incoming[0],
                    self.incoming[1],
                ]));
                let frame_end = DOT_LENGTH_BYTES + length;
                if self.incoming.len() < frame_end {
                    return Ok(());
                }
                let query = self.incoming[DOT_LENGTH_BYTES..frame_end].to_vec();
                self.incoming.drain(..frame_end);
                let response = self.response_for(&query)?;
                let response_length = u16::try_from(response.len())
                    .map_err(|_| io::Error::other("scripted DNS response is too large"))?;
                self.outgoing.extend(response_length.to_be_bytes());
                self.outgoing.extend(response);
            }
        }

        fn response_for(&self, query: &[u8]) -> io::Result<Vec<u8>> {
            if query.len() < DNS_HEADER_BYTES + 5 {
                return Err(io::Error::other("scripted DNS query is truncated"));
            }
            let question_end = query.len();
            let qtype = u16::from_be_bytes([
                query[question_end - 4],
                query[question_end - 3],
            ]);
            let mut response = Vec::new();
            response.extend_from_slice(&query[..2]);
            response.extend_from_slice(&(0x8000_u16 | 0x0100).to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&0_u16.to_be_bytes());
            response.extend_from_slice(&0_u16.to_be_bytes());
            response.extend_from_slice(&query[DNS_HEADER_BYTES..]);
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&qtype.to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            match qtype {
                1 => {
                    response.extend_from_slice(&self.ttl_a.to_be_bytes());
                    response.extend_from_slice(&4_u16.to_be_bytes());
                    response.extend_from_slice(&self.ipv4.octets());
                }
                28 => {
                    response.extend_from_slice(&self.ttl_aaaa.to_be_bytes());
                    response.extend_from_slice(&16_u16.to_be_bytes());
                    response.extend_from_slice(&self.ipv6.octets());
                }
                _ => return Err(io::Error::other("unexpected scripted DNS qtype")),
            }
            Ok(response)
        }
    }

    impl Read for ScriptedSession {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.outgoing.is_empty() {
                return Ok(0);
            }
            let count = buffer.len().min(self.outgoing.len());
            for slot in &mut buffer[..count] {
                *slot = self.outgoing.pop_front().unwrap();
            }
            Ok(count)
        }
    }

    impl Write for ScriptedSession {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.incoming.extend_from_slice(buffer);
            self.process_requests()?;
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl TransportSession for ScriptedSession {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:53000".parse().unwrap())
        }

        fn relay_to_client(self: Box<Self>, _client: TcpStream) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "scripted DNS transport cannot relay arbitrary client streams",
            ))
        }
    }

    #[test]
    fn resolver_reuses_one_stream_and_combines_a_aaaa_with_minimum_ttl() {
        let connects = Arc::new(AtomicUsize::new(0));
        let connector = Arc::new(ScriptedConnector {
            connects: connects.clone(),
            ipv4: Ipv4Addr::new(203, 0, 113, 8),
            ipv6: "2001:db8::8".parse().unwrap(),
            ttl_a: 120,
            ttl_aaaa: 45,
        });
        let resolver = DotResolver::with_connector(connector);
        let answer = resolver.resolve(&DnsQuery::new("secure.example").unwrap()).unwrap();
        assert_eq!(
            answer.addresses(),
            &[
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
                IpAddr::V6("2001:db8::8".parse().unwrap()),
            ]
        );
        assert_eq!(answer.ttl(), Some(Duration::from_secs(45)));
        assert_eq!(connects.load(Ordering::Relaxed), 1);
    }
}
