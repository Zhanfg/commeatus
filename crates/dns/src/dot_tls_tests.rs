use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use commeatus_transport::TlsTransport;
use rcgen::generate_simple_self_signed;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::PrivatePkcs8KeyDer,
};

use crate::{DnsQuery, DotResolver, Resolver};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_SERVER_NAME: &str = "dot.test";
const IPV4_ANSWER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 55);
const A_TTL: u32 = 120;
const AAAA_TTL: u32 = 45;

fn tls_configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let certified = generate_simple_self_signed(vec![TLS_SERVER_NAME.to_owned()]).unwrap();
    let certificate = certified.cert.der().clone();
    let private_key = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());

    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], private_key.into())
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(certificate).unwrap();
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(client), Arc::new(server))
}

fn accept_with_deadline(listener: &TcpListener) -> io::Result<TcpStream> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(TEST_TIMEOUT))?;
                stream.set_write_timeout(Some(TEST_TIMEOUT))?;
                return Ok(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for DNS-over-TLS test connection",
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    }
}

fn read_dot_message<R: Read>(stream: &mut R) -> io::Result<Vec<u8>> {
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length)?;
    let length = usize::from(u16::from_be_bytes(length));
    if length < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS-over-TLS test query is shorter than a DNS header",
        ));
    }
    let mut message = vec![0_u8; length];
    stream.read_exact(&mut message)?;
    Ok(message)
}

fn response_for(query: &[u8]) -> io::Result<Vec<u8>> {
    if query.len() < 17 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS-over-TLS test query does not contain exactly one question",
        ));
    }
    let qtype_offset = query.len() - 4;
    let qtype = u16::from_be_bytes([query[qtype_offset], query[qtype_offset + 1]]);
    let qclass = u16::from_be_bytes([query[qtype_offset + 2], query[qtype_offset + 3]]);
    if qclass != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS-over-TLS test query is not IN class",
        ));
    }

    let (ttl, rdata) = match qtype {
        1 => (A_TTL, IPV4_ANSWER.octets().to_vec()),
        28 => (
            AAAA_TTL,
            "2001:db8::55"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
        ),
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected DNS-over-TLS test query type {other}"),
            ));
        }
    };

    let mut response = Vec::with_capacity(query.len() + 32);
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..]);
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&qtype.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&ttl.to_be_bytes());
    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&rdata);
    Ok(response)
}

fn write_dot_message<W: Write>(stream: &mut W, message: &[u8]) -> io::Result<()> {
    let length = u16::try_from(message.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS-over-TLS test response exceeds 65535 bytes",
        )
    })?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(message)?;
    stream.flush()
}

fn spawn_dot_server(
    config: Arc<ServerConfig>,
) -> (SocketAddr, thread::JoinHandle<io::Result<(usize, usize)>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::Builder::new()
        .name("commeatus-v06-dot-tls-server".to_owned())
        .spawn(move || {
            let mut accepts = 0_usize;
            let mut queries = 0_usize;
            for _ in 0..2 {
                let socket = accept_with_deadline(&listener)?;
                accepts += 1;
                let connection = ServerConnection::new(config.clone())
                    .map_err(|error| io::Error::other(error.to_string()))?;
                let mut tls = StreamOwned::new(connection, socket);
                for _ in 0..2 {
                    let query = read_dot_message(&mut tls)?;
                    queries += 1;
                    let response = response_for(&query)?;
                    write_dot_message(&mut tls, &response)?;
                }
                // Drop the first verified TLS stream after A+AAAA. The next
                // resolver call must detect the dead persistent session and
                // reconnect once rather than making the failure global.
                drop(tls);
            }
            Ok((accepts, queries))
        })
        .unwrap();
    (address, handle)
}

#[test]
fn dot_reuses_verified_tls_for_a_aaaa_and_recovers_after_server_close() {
    let (client_config, server_config) = tls_configs();
    let (address, server) = spawn_dot_server(server_config);
    let transport =
        TlsTransport::with_client_config(address, TLS_SERVER_NAME, client_config).unwrap();
    let resolver = DotResolver::with_transport(transport);
    let query = DnsQuery::new("secure.example").unwrap();

    let first = resolver.resolve(&query).unwrap();
    assert_eq!(
        first.addresses(),
        &[
            IpAddr::V4(IPV4_ANSWER),
            IpAddr::V6("2001:db8::55".parse().unwrap()),
        ]
    );
    assert_eq!(first.ttl(), Some(Duration::from_secs(u64::from(AAAA_TTL))));

    // Give the local server time to close the first stream so the second call
    // deterministically exercises the reconnect path rather than racing EOF.
    thread::sleep(Duration::from_millis(30));

    let second = resolver.resolve(&query).unwrap();
    assert_eq!(second.addresses(), first.addresses());
    assert_eq!(second.ttl(), first.ttl());

    let (accepts, queries) = server.join().unwrap().unwrap();
    assert_eq!(accepts, 2);
    assert_eq!(queries, 4);
}
