use std::net::IpAddr;

/// Stable identifier for one runtime flow.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowId(u64);

impl FlowId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Identity metadata supplied by the platform layer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourceContext {
    pub uid: Option<u32>,
    pub package: Option<String>,
}

/// Destination identity kept separate from DNS resolution state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DestinationHost {
    Domain(String),
    Ip(IpAddr),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Destination {
    pub host: DestinationHost,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NetworkKind {
    #[default]
    Unknown,
    Ethernet,
    Wifi,
    Cellular,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetworkContext {
    pub kind: NetworkKind,
    pub interface: Option<String>,
}

/// Canonical runtime representation of a network flow.
///
/// Import formats and platform-specific objects must be translated before
/// entering this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowContext {
    pub id: FlowId,
    pub source: SourceContext,
    pub destination: Destination,
    pub transport: TransportProtocol,
    pub network: NetworkContext,
}

impl FlowContext {
    #[must_use]
    pub const fn new(
        id: FlowId,
        source: SourceContext,
        destination: Destination,
        transport: TransportProtocol,
        network: NetworkContext,
    ) -> Self {
        Self {
            id,
            source,
            destination,
            transport,
            network,
        }
    }
}
