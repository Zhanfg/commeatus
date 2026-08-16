from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match in {path}, found {count}: {old[:140]!r}")
    p.write_text(text.replace(old, new, 1))


# Register shared Trojan and datagram provider modules.
replace_once(
    "crates/daemon/src/lib.rs",
    "mod socks5;\n",
    "mod socks5;\nmod trojan;\nmod trojan_datagram;\n",
)

# Stream Trojan uses the same verifier/request encoder as datagram Trojan.
replace_once(
    "crates/daemon/src/protocol.rs",
    "use sha2::{Digest, Sha224};\n\nuse crate::proxy::Target;\n\nconst MAX_HTTP_RESPONSE_HEAD: usize = 16 * 1024;\nconst MAX_TROJAN_PASSWORD_BYTES: usize = 1024;\nconst TROJAN_PASSWORD_HASH_BYTES: usize = 56;",
    "use crate::{\n    proxy::Target,\n    trojan::{TrojanVerifier, encode_connect_request},\n};\n\nconst MAX_HTTP_RESPONSE_HEAD: usize = 16 * 1024;",
)
replace_once(
    "crates/daemon/src/protocol.rs",
    '''pub fn trojan(password: &str) -> io::Result<ProtocolRef> {
    Ok(Arc::new(TrojanProtocol::new(password)?))
}''',
    '''#[must_use]
pub(crate) fn trojan_with_verifier(verifier: TrojanVerifier) -> ProtocolRef {
    Arc::new(TrojanProtocol { verifier })
}''',
)
old_trojan = '''#[derive(Clone, Debug, Eq, PartialEq)]
struct TrojanProtocol {
    password_hash: [u8; TROJAN_PASSWORD_HASH_BYTES],
}

impl TrojanProtocol {
    fn new(password: &str) -> io::Result<Self> {
        if password.is_empty() || password.len() > MAX_TROJAN_PASSWORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Trojan password must contain 1..={MAX_TROJAN_PASSWORD_BYTES} UTF-8 bytes"),
            ));
        }

        let digest = Sha224::digest(password.as_bytes());
        let mut password_hash = [0_u8; TROJAN_PASSWORD_HASH_BYTES];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (index, byte) in digest.iter().copied().enumerate() {
            password_hash[index * 2] = HEX[usize::from(byte >> 4)];
            password_hash[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
        }
        Ok(Self { password_hash })
    }
}
'''
new_trojan = '''#[derive(Clone, Debug, Eq, PartialEq)]
struct TrojanProtocol {
    verifier: TrojanVerifier,
}
'''
replace_once("crates/daemon/src/protocol.rs", old_trojan, new_trojan)
replace_once(
    "crates/daemon/src/protocol.rs",
    '''        let mut request = Vec::with_capacity(TROJAN_PASSWORD_HASH_BYTES + 2 + 1 + 1 + 253 + 2 + 2);
        request.extend_from_slice(&self.password_hash);
        request.extend_from_slice(b"\\r\\n");
        request.push(0x01); // CONNECT
        encode_socks_address(&mut request, &target.host)?;
        request.extend_from_slice(&target.port.to_be_bytes());
        request.extend_from_slice(b"\\r\\n");
        session.write_all(&request)?;
        session.flush()''',
    '''        let request = encode_connect_request(&self.verifier, target)?;
        session.write_all(&request)?;
        session.flush()''',
)
replace_once(
    "crates/daemon/src/protocol.rs",
    '''    #[test]
    fn trojan_password_hash_matches_sha224_hex_vector() {
        let protocol = TrojanProtocol::new("password").unwrap();
        assert_eq!(
            &protocol.password_hash,
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }
''',
    "",
)

# Native config constructs the verifier once and attaches both providers to the
# existing Trojan syntax. No new user-facing config syntax is introduced.
replace_once(
    "crates/daemon/src/config.rs",
    '''use crate::{
    outbound::{OutboundRegistry, ProxyEndpointConfig, TransportConfig},
    protocol,
};''',
    '''use crate::{
    outbound::{OutboundRegistry, ProxyEndpointConfig, TransportConfig},
    protocol,
    trojan::TrojanVerifier,
    trojan_datagram::TrojanDatagramProvider,
};''',
)
replace_once(
    "crates/daemon/src/config.rs",
    "                let (protocol, transport) = match fields.as_slice() {",
    "                let (protocol, datagram, transport) = match fields.as_slice() {",
)
config = Path("crates/daemon/src/config.rs")
text = config.read_text()
for provider in ("protocol::socks5()", "protocol::http_connect()"):
    needle = f"                        {provider},\n                        TransportConfig::"
    count = text.count(needle)
    if count != 2:
        raise SystemExit(f"expected two TCP tuple arms for {provider}, found {count}")
    text = text.replace(
        needle,
        f"                        {provider},\n                        None,\n                        TransportConfig::",
    )
    tls_needle = f"                        {provider},\n                        parse_tls_transport("
    if text.count(tls_needle) != 1:
        raise SystemExit(f"expected one TLS tuple arm for {provider}")
    text = text.replace(
        tls_needle,
        f"                        {provider},\n                        None,\n                        parse_tls_transport(",
        1,
    )
old_trojan_arm = '''                    ] => (
                        protocol::trojan(password)
                            .map_err(|error| ConfigError::at(line_number, error.to_string()))?,
                        parse_tls_transport(address, server_name, line_number)?,
                    ),'''
new_trojan_arm = '''                    ] => {
                        let verifier = TrojanVerifier::new(password)
                            .map_err(|error| ConfigError::at(line_number, error.to_string()))?;
                        let tls = parse_tls_transport_raw(address, server_name, line_number)?;
                        (
                            protocol::trojan_with_verifier(verifier.clone()),
                            Some(
                                TrojanDatagramProvider::new(verifier, tls.clone()).into_ref(),
                            ),
                            TransportConfig::Tls(tls),
                        )
                    },'''
if text.count(old_trojan_arm) != 1:
    raise SystemExit("unexpected Trojan config arm")
text = text.replace(old_trojan_arm, new_trojan_arm, 1)
old_push = '''                endpoint_configs.push(ProxyEndpointConfig {
                    id,
                    protocol,
                    datagram: None,
                    transport,
                });'''
new_push = '''                endpoint_configs.push(ProxyEndpointConfig {
                    id,
                    protocol,
                    datagram,
                    transport,
                });'''
if text.count(old_push) != 1:
    raise SystemExit("unexpected endpoint config push")
text = text.replace(old_push, new_push, 1)
config.write_text(text)

replace_once(
    "crates/daemon/src/config.rs",
    '''fn parse_tls_transport(
    address: &str,
    server_name: &str,
    line: usize,
) -> Result<TransportConfig, ConfigError> {
    let address = parse_proxy_address(address, line)?;
    TlsTransport::webpki(address, server_name)
        .map(TransportConfig::Tls)
        .map_err(|error| ConfigError::at(line, error.to_string()))
}''',
    '''fn parse_tls_transport_raw(
    address: &str,
    server_name: &str,
    line: usize,
) -> Result<TlsTransport, ConfigError> {
    let address = parse_proxy_address(address, line)?;
    TlsTransport::webpki(address, server_name)
        .map_err(|error| ConfigError::at(line, error.to_string()))
}

fn parse_tls_transport(
    address: &str,
    server_name: &str,
    line: usize,
) -> Result<TransportConfig, ConfigError> {
    parse_tls_transport_raw(address, server_name, line).map(TransportConfig::Tls)
}''',
)

# Dispatch any route-owned readiness event, not only READABLE. TLS executions
# need WRITABLE events to flush newly queued ciphertext.
replace_once(
    "crates/daemon/src/socks5.rs",
    '''        let outbound_readable = events
            .iter()
            .filter(|event| event.is_readable() && routes.owns_token(event.token()))
            .map(|event| event.token())
            .collect::<Vec<_>>();''',
    '''        let outbound_ready = events
            .iter()
            .filter(|event| routes.owns_token(event.token()))
            .map(|event| event.token())
            .collect::<Vec<_>>();''',
)
replace_once(
    "crates/daemon/src/socks5.rs",
    "        for token in outbound_readable {",
    "        for token in outbound_ready {",
)

for path in ("crates/daemon/src/lib.rs", "crates/daemon/src/config.rs"):
    if "trojan_datagram" not in Path(path).read_text():
        raise SystemExit(f"Trojan datagram integration missing from {path}")
if "event.is_readable() && routes.owns_token" in Path("crates/daemon/src/socks5.rs").read_text():
    raise SystemExit("SOCKS5 still drops outbound WRITABLE events")
