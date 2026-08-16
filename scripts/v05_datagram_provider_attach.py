from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match in {path}, found {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1))


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

# Every existing endpoint remains explicitly stream-only. Do not modify the
# struct definition in outbound.rs here; only initializers in Rust files.
for path in Path("crates/daemon/src").glob("*.rs"):
    if path.name == "outbound.rs":
        continue
    text = path.read_text()
    if "ProxyEndpointConfig {" not in text:
        continue
    lines = text.splitlines(keepends=True)
    output = []
    in_init = False
    depth = 0
    inserted_for_block = False
    changed = False
    for line in lines:
        if not in_init and "ProxyEndpointConfig {" in line:
            in_init = True
            depth = line.count("{") - line.count("}")
            inserted_for_block = False
            output.append(line)
            continue
        if in_init:
            if not inserted_for_block and line.lstrip().startswith("transport:"):
                indent = line[: len(line) - len(line.lstrip())]
                output.append(f"{indent}datagram: None,\n")
                inserted_for_block = True
                changed = True
            output.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                if not inserted_for_block:
                    raise SystemExit(f"ProxyEndpointConfig initializer without transport field in {path}")
                in_init = False
            continue
        output.append(line)
    if in_init:
        raise SystemExit(f"unterminated ProxyEndpointConfig initializer in {path}")
    if changed:
        path.write_text("".join(output))

# Add datagram: None to initializers inside outbound.rs itself.
outbound = Path("crates/daemon/src/outbound.rs")
text = outbound.read_text()
needle = "            protocol: "
# Scan only the #[cfg(test)] section to avoid the struct definition.
prefix, marker, tests = text.partition("#[cfg(test)]")
if not marker:
    raise SystemExit("outbound.rs test module missing")
lines = tests.splitlines(keepends=True)
output = []
in_init = False
depth = 0
inserted = False
for line in lines:
    if not in_init and "ProxyEndpointConfig {" in line:
        in_init = True
        depth = line.count("{") - line.count("}")
        inserted = False
        output.append(line)
        continue
    if in_init:
        if not inserted and line.lstrip().startswith("transport:"):
            indent = line[: len(line) - len(line.lstrip())]
            output.append(f"{indent}datagram: None,\n")
            inserted = True
        output.append(line)
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            if not inserted:
                raise SystemExit("outbound test endpoint initializer missing transport")
            in_init = False
        continue
    output.append(line)
outbound.write_text(prefix + marker + "".join(output))

# Hard invariant: every initializer has an explicit datagram attachment field.
for path in Path("crates/daemon/src").glob("*.rs"):
    text = path.read_text()
    start = 0
    while True:
        index = text.find("ProxyEndpointConfig {", start)
        if index < 0:
            break
        # Skip the struct definition.
        line_start = text.rfind("\n", 0, index) + 1
        if text[line_start:index].strip().endswith("struct"):
            start = index + 1
            continue
        depth = 0
        end = None
        for pos in range(index + len("ProxyEndpointConfig "), len(text)):
            if text[pos] == "{":
                depth += 1
            elif text[pos] == "}":
                depth -= 1
                if depth == 0:
                    end = pos + 1
                    break
        if end is None:
            raise SystemExit(f"unterminated endpoint initializer in {path}")
        block = text[index:end]
        if "datagram:" not in block:
            raise SystemExit(f"endpoint initializer missing datagram field in {path}")
        start = end
