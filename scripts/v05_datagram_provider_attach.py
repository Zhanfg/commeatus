from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match in {path}, found {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1))


def is_initializer_start(line: str) -> bool:
    if "ProxyEndpointConfig {" not in line:
        return False
    stripped = line.strip()
    return not (
        stripped.startswith("pub struct ProxyEndpointConfig {")
        or stripped.startswith("struct ProxyEndpointConfig {")
    )


def is_transport_field(line: str) -> bool:
    stripped = line.strip()
    return stripped == "transport," or stripped.startswith("transport:")


def insert_datagram_fields(path: Path) -> int:
    """Insert `datagram: None` before each endpoint initializer's transport field.

    Do not parse Rust braces. Initializer values may contain nested blocks,
    closures, or macros; the field order is the stable local invariant we need.
    """
    lines = path.read_text().splitlines(keepends=True)
    output: list[str] = []
    waiting_for_transport = False
    saw_datagram = False
    initializers = 0
    inserted = 0

    for line in lines:
        if is_initializer_start(line):
            if waiting_for_transport:
                raise SystemExit(
                    f"new ProxyEndpointConfig initializer before transport field in {path}"
                )
            waiting_for_transport = True
            saw_datagram = False
            initializers += 1
            output.append(line)
            continue

        if waiting_for_transport:
            stripped = line.strip()
            if stripped.startswith("datagram:"):
                saw_datagram = True
            if is_transport_field(line):
                if not saw_datagram:
                    indent = line[: len(line) - len(line.lstrip())]
                    output.append(f"{indent}datagram: None,\n")
                    inserted += 1
                waiting_for_transport = False
                saw_datagram = False

        output.append(line)

    if waiting_for_transport:
        raise SystemExit(f"ProxyEndpointConfig initializer without transport field in {path}")

    if initializers:
        path.write_text("".join(output))
    return initializers


def verify_datagram_fields(path: Path) -> int:
    lines = path.read_text().splitlines()
    waiting_for_transport = False
    saw_datagram = False
    initializers = 0

    for line in lines:
        if is_initializer_start(line):
            if waiting_for_transport:
                raise SystemExit(
                    f"nested/adjacent ProxyEndpointConfig before transport in {path}"
                )
            waiting_for_transport = True
            saw_datagram = False
            initializers += 1
            continue
        if not waiting_for_transport:
            continue
        stripped = line.strip()
        if stripped.startswith("datagram:"):
            saw_datagram = True
        if is_transport_field(line):
            if not saw_datagram:
                raise SystemExit(f"endpoint initializer missing datagram field in {path}")
            waiting_for_transport = False
            saw_datagram = False

    if waiting_for_transport:
        raise SystemExit(f"unterminated endpoint initializer in {path}")
    return initializers


# Add the provider interface without coupling it to a concrete transport config.
replace_once(
    "crates/daemon/src/datagram.rs",
    "    collections::{HashMap, HashSet},\n    io,",
    "    collections::{HashMap, HashSet},\n    fmt, io,",
)
replace_once(
    "crates/daemon/src/datagram.rs",
    '''pub trait DatagramExecution: DatagramAssociation {
    /// Number of readiness tokens required by this concrete execution path.
    fn readiness_source_count(&self) -> usize;

    /// Register all concrete event sources using exactly `tokens.len()`
    /// caller-owned tokens.
    fn register_readiness(&mut self, registry: &Registry, tokens: &[Token]) -> io::Result<()>;
}

struct DatagramRoute {''',
    '''pub trait DatagramExecution: DatagramAssociation {
    /// Number of readiness tokens required by this concrete execution path.
    fn readiness_source_count(&self) -> usize;

    /// Register all concrete event sources using exactly `tokens.len()`
    /// caller-owned tokens.
    fn register_readiness(&mut self, registry: &Registry, tokens: &[Token]) -> io::Result<()>;
}

/// Factory owned by a proxy endpoint for opening its logical datagram path.
///
/// The provider captures every implementation-specific construction input.
/// `OutboundRegistry` therefore does not need to know whether the provider
/// uses TLS streams, native QUIC datagrams, multiplexing, or another carrier.
pub trait OutboundDatagramProvider: fmt::Debug + Send + Sync {
    fn open(&self) -> io::Result<Box<dyn DatagramExecution>>;
}

pub type DatagramProviderRef = Arc<dyn OutboundDatagramProvider>;

struct DatagramRoute {''',
)

# Add the optional provider attachment and make capability/factory derive from it.
replace_once(
    "crates/daemon/src/outbound.rs",
    "    datagram::{DatagramExecution, DirectDatagramAssociation},",
    "    datagram::{DatagramExecution, DatagramProviderRef, DirectDatagramAssociation},",
)
replace_once(
    "crates/daemon/src/outbound.rs",
    '''pub struct ProxyEndpointConfig {
    pub id: EndpointId,
    pub protocol: ProtocolRef,
    pub transport: TransportConfig,
}''',
    '''pub struct ProxyEndpointConfig {
    pub id: EndpointId,
    pub protocol: ProtocolRef,
    pub datagram: Option<DatagramProviderRef>,
    pub transport: TransportConfig,
}''',
)
replace_once(
    "crates/daemon/src/outbound.rs",
    '''                EndpointCapabilities {
                    tcp: protocol.stream_connect && transport.reliable_stream,
                    udp: false,
                    encrypted_transport: transport.encrypted,
                }''',
    '''                EndpointCapabilities {
                    tcp: protocol.stream_connect && transport.reliable_stream,
                    udp: config.datagram.is_some(),
                    encrypted_transport: transport.encrypted,
                }''',
)
replace_once(
    "crates/daemon/src/outbound.rs",
    '''            Endpoint::Proxy(id) => {
                if !self.endpoints.contains_key(id) {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("proxy endpoint `{}` is not registered", id.as_str()),
                    ));
                }
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "proxy endpoint `{}` has no datagram execution provider",
                        id.as_str()
                    ),
                ))
            }''',
    '''            Endpoint::Proxy(id) => {
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
            }''',
)

# Every existing native endpoint remains explicitly stream-only. Use field
# order rather than Rust brace depth so nested closures/blocks inside values do
# not confuse the migration.
source_files = sorted(Path("crates/daemon/src").glob("*.rs"))
initializer_count = 0
for path in source_files:
    initializer_count += insert_datagram_fields(path)

if initializer_count == 0:
    raise SystemExit("no ProxyEndpointConfig initializers were found")

verified_count = sum(verify_datagram_fields(path) for path in source_files)
if verified_count != initializer_count:
    raise SystemExit(
        f"endpoint initializer verification count changed: {initializer_count} -> {verified_count}"
    )
