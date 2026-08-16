use std::{
    collections::HashSet,
    fmt, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use commeatus_compat::{BlocklistStats, MAX_BLOCKLIST_BYTES, compile_blocklist};
use commeatus_core::{
    Endpoint, EndpointId, IpCidr, Matcher, PolicyAction, PolicyEngine, PolicyRule, PolicyTier,
    RejectReason, RuleId, Runtime,
};
use commeatus_dns::{DnsEngine, HostsTable, MAX_HOSTS_BYTES};
use commeatus_transport::{TcpTransport, TlsTransport};

use crate::{
    outbound::{OutboundRegistry, ProxyEndpointConfig, TransportConfig},
    protocol,
    trojan::TrojanVerifier,
    trojan_datagram::TrojanDatagramProvider,
};

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const MAX_RULES: usize = 4096;
pub const MAX_LISTENERS: usize = 16;
pub const MAX_BLOCKLISTS: usize = 8;
pub const MAX_HOSTS_FILES: usize = 4;
pub const MAX_PROXY_ENDPOINTS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerProtocol {
    Socks5,
    HttpConnect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerConfig {
    pub protocol: ListenerProtocol,
    pub address: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlocklistSummary {
    pub path: PathBuf,
    pub stats: BlocklistStats,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostsSummary {
    pub path: PathBuf,
    pub records: usize,
}

#[derive(Clone, Debug)]
pub struct CompiledConfig {
    listeners: Vec<ListenerConfig>,
    blocklists: Vec<BlocklistSummary>,
    hosts: Vec<HostsSummary>,
    runtime: Runtime,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
}

impl CompiledConfig {
    #[must_use]
    pub fn listeners(&self) -> &[ListenerConfig] {
        &self.listeners
    }

    #[must_use]
    pub fn blocklists(&self) -> &[BlocklistSummary] {
        &self.blocklists
    }

    #[must_use]
    pub fn hosts(&self) -> &[HostsSummary] {
        &self.hosts
    }

    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    #[must_use]
    pub fn dns(&self) -> &Arc<DnsEngine> {
        &self.dns
    }

    #[must_use]
    pub fn outbounds(&self) -> &Arc<OutboundRegistry> {
        &self.outbounds
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError {
    line: Option<usize>,
    message: String,
}

impl ConfigError {
    fn global(message: impl Into<String>) -> Self {
        Self {
            line: None,
            message: message.into(),
        }
    }

    fn at(line: usize, message: impl Into<String>) -> Self {
        Self {
            line: Some(line),
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(formatter, "config line {line}: {}", self.message),
            None => formatter.write_str(&self.message),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Active configuration with candidate-then-swap semantics.
///
/// Referenced assets and named outbound endpoints are fully parsed and compiled
/// before a candidate replaces the active snapshot. A failed candidate therefore
/// leaves the Last Known Good policy, DNS engine, and outbound registry untouched.
pub struct ConfigStore {
    active: RwLock<Arc<CompiledConfig>>,
    asset_root: PathBuf,
}

impl ConfigStore {
    pub fn new(text: &str) -> Result<Self, ConfigError> {
        Self::new_at(text, Path::new("."))
    }

    pub fn new_at(text: &str, asset_root: &Path) -> Result<Self, ConfigError> {
        Ok(Self {
            active: RwLock::new(Arc::new(parse_config_at(text, asset_root)?)),
            asset_root: asset_root.to_path_buf(),
        })
    }

    pub fn reload(&self, text: &str) -> Result<(), ConfigError> {
        let candidate = Arc::new(parse_config_at(text, &self.asset_root)?);
        let mut active = self
            .active
            .write()
            .map_err(|_| ConfigError::global("configuration state lock is poisoned"))?;
        *active = candidate;
        Ok(())
    }

    pub fn snapshot(&self) -> Result<Arc<CompiledConfig>, ConfigError> {
        self.active
            .read()
            .map(|active| Arc::clone(&active))
            .map_err(|_| ConfigError::global("configuration state lock is poisoned"))
    }
}

pub fn parse_config(text: &str) -> Result<CompiledConfig, ConfigError> {
    parse_config_at(text, Path::new("."))
}

pub fn parse_config_at(text: &str, asset_root: &Path) -> Result<CompiledConfig, ConfigError> {
    if text.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::global(format!(
            "configuration exceeds {MAX_CONFIG_BYTES} byte limit"
        )));
    }

    let mut version_seen = false;
    let mut default_action = None;
    let mut allow_public_listen = None;
    let mut listeners = Vec::new();
    let mut listener_addresses = HashSet::new();
    let mut blocklists = Vec::new();
    let mut blocklist_paths = HashSet::new();
    let mut hosts = Vec::new();
    let mut hosts_paths = HashSet::new();
    let mut hosts_table = HostsTable::default();
    let mut endpoint_configs = Vec::new();
    let mut endpoint_ids = HashSet::new();
    let mut referenced_endpoints = HashSet::new();
    let mut rules = Vec::new();
    let mut next_rule_id = 1_u64;

    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        match fields.first().copied() {
            Some("version") => {
                expect_fields(&fields, 2, line_number, "version syntax is `version 1`")?;
                if fields[1] != "1" {
                    return Err(ConfigError::at(line_number, "expected exactly `version 1`"));
                }
                if version_seen {
                    return Err(ConfigError::at(line_number, "duplicate version directive"));
                }
                version_seen = true;
            }
            Some("allow-public-listen") => {
                expect_fields(
                    &fields,
                    2,
                    line_number,
                    "allow-public-listen syntax is `allow-public-listen <true|false>`",
                )?;
                if allow_public_listen.is_some() {
                    return Err(ConfigError::at(
                        line_number,
                        "duplicate allow-public-listen directive",
                    ));
                }
                allow_public_listen = Some(match fields[1] {
                    "true" => true,
                    "false" => false,
                    _ => {
                        return Err(ConfigError::at(
                            line_number,
                            "allow-public-listen must be `true` or `false`",
                        ));
                    }
                });
            }
            Some("listen") => {
                expect_fields(
                    &fields,
                    3,
                    line_number,
                    "listen syntax is `listen <socks5|http> <ip:port>`",
                )?;
                if listeners.len() >= MAX_LISTENERS {
                    return Err(ConfigError::at(
                        line_number,
                        format!("listener count exceeds {MAX_LISTENERS}"),
                    ));
                }
                let protocol = match fields[1] {
                    "socks5" => ListenerProtocol::Socks5,
                    "http" => ListenerProtocol::HttpConnect,
                    _ => {
                        return Err(ConfigError::at(
                            line_number,
                            "listener protocol must be `socks5` or `http`",
                        ));
                    }
                };
                let address: SocketAddr = fields[2]
                    .parse()
                    .map_err(|_| ConfigError::at(line_number, "invalid listener address"))?;
                if address.port() == 0 {
                    return Err(ConfigError::at(
                        line_number,
                        "listener port must not be zero",
                    ));
                }
                if !listener_addresses.insert(address) {
                    return Err(ConfigError::at(
                        line_number,
                        "two listeners cannot bind the same socket address",
                    ));
                }
                listeners.push(ListenerConfig { protocol, address });
            }
            Some("endpoint") => {
                if endpoint_configs.len() >= MAX_PROXY_ENDPOINTS {
                    return Err(ConfigError::at(
                        line_number,
                        format!("proxy endpoint count exceeds {MAX_PROXY_ENDPOINTS}"),
                    ));
                }
                let id = fields.get(1).ok_or_else(|| {
                    ConfigError::at(
                        line_number,
                        "endpoint requires an id, protocol and transport configuration",
                    )
                })?;
                let id = EndpointId::new((*id).to_owned())
                    .map_err(|error| ConfigError::at(line_number, error.to_string()))?;
                if !endpoint_ids.insert(id.clone()) {
                    return Err(ConfigError::at(line_number, "duplicate proxy endpoint id"));
                }

                let (protocol, datagram, transport) = match fields.as_slice() {
                    ["endpoint", _, "socks5", address] => (
                        protocol::socks5(),
                        None,
                        TransportConfig::Tcp(TcpTransport::new(parse_proxy_address(
                            address,
                            line_number,
                        )?)),
                    ),
                    ["endpoint", _, "http", address] => (
                        protocol::http_connect(),
                        None,
                        TransportConfig::Tcp(TcpTransport::new(parse_proxy_address(
                            address,
                            line_number,
                        )?)),
                    ),
                    ["endpoint", _, "socks5", "tcp", address] => (
                        protocol::socks5(),
                        None,
                        TransportConfig::Tcp(TcpTransport::new(parse_proxy_address(
                            address,
                            line_number,
                        )?)),
                    ),
                    ["endpoint", _, "http", "tcp", address] => (
                        protocol::http_connect(),
                        None,
                        TransportConfig::Tcp(TcpTransport::new(parse_proxy_address(
                            address,
                            line_number,
                        )?)),
                    ),
                    ["endpoint", _, "socks5", "tls", address, server_name] => (
                        protocol::socks5(),
                        None,
                        parse_tls_transport(address, server_name, line_number)?,
                    ),
                    ["endpoint", _, "http", "tls", address, server_name] => (
                        protocol::http_connect(),
                        None,
                        parse_tls_transport(address, server_name, line_number)?,
                    ),
                    [
                        "endpoint",
                        _,
                        "trojan",
                        "tls",
                        address,
                        server_name,
                        password,
                    ] => {
                        let verifier = TrojanVerifier::new(password)
                            .map_err(|error| ConfigError::at(line_number, error.to_string()))?;
                        let tls = parse_tls_transport_raw(address, server_name, line_number)?;
                        (
                            protocol::trojan_with_verifier(verifier.clone()),
                            Some(TrojanDatagramProvider::new(verifier, tls.clone()).into_ref()),
                            TransportConfig::Tls(tls),
                        )
                    }
                    ["endpoint", _, "trojan", ..] => {
                        return Err(ConfigError::at(
                            line_number,
                            "Trojan endpoint syntax is `endpoint <id> trojan tls <ip:port> <server-name> <password>`; plain TCP is forbidden",
                        ));
                    }
                    _ => {
                        return Err(ConfigError::at(
                            line_number,
                            "endpoint syntax supports SOCKS5/HTTP over implicit TCP, explicit TCP or TLS, and Trojan over TLS only",
                        ));
                    }
                };

                endpoint_configs.push(ProxyEndpointConfig {
                    id,
                    protocol,
                    datagram,
                    transport,
                });
            }
            Some("default") => {
                expect_fields(
                    &fields,
                    2,
                    line_number,
                    "default syntax is `default <direct|reject|proxy:id>`",
                )?;
                if default_action.is_some() {
                    return Err(ConfigError::at(line_number, "duplicate default directive"));
                }
                let parsed = parse_action(fields[1], line_number)?;
                if let Some(id) = &parsed.proxy_ref {
                    referenced_endpoints.insert(id.clone());
                }
                default_action = Some(parsed.action);
            }
            Some("blocklist") => {
                expect_fields(
                    &fields,
                    2,
                    line_number,
                    "blocklist syntax is `blocklist <path>`; paths with whitespace are not supported yet",
                )?;
                if blocklists.len() >= MAX_BLOCKLISTS {
                    return Err(ConfigError::at(
                        line_number,
                        format!("blocklist count exceeds {MAX_BLOCKLISTS}"),
                    ));
                }
                ensure_rule_capacity(rules.len(), line_number)?;
                let source = resolve_asset_path(asset_root, fields[1]);
                if !blocklist_paths.insert(source.clone()) {
                    return Err(ConfigError::at(line_number, "duplicate blocklist path"));
                }
                let (filter, stats) = load_blocklist(&source, line_number)?;
                rules.push(PolicyRule {
                    id: RuleId::new(next_rule_id),
                    tier: PolicyTier::UserHard,
                    matcher: Matcher::DomainFilter(filter),
                    action: PolicyAction::Reject(RejectReason::Policy),
                });
                next_rule_id += 1;
                blocklists.push(BlocklistSummary {
                    path: source,
                    stats,
                });
            }
            Some("hosts") => {
                expect_fields(
                    &fields,
                    2,
                    line_number,
                    "hosts syntax is `hosts <path>`; paths with whitespace are not supported yet",
                )?;
                if hosts.len() >= MAX_HOSTS_FILES {
                    return Err(ConfigError::at(
                        line_number,
                        format!("hosts file count exceeds {MAX_HOSTS_FILES}"),
                    ));
                }
                let source = resolve_asset_path(asset_root, fields[1]);
                if !hosts_paths.insert(source.clone()) {
                    return Err(ConfigError::at(line_number, "duplicate hosts path"));
                }
                let table = load_hosts(&source, line_number)?;
                let records = table.len();
                hosts_table.merge(table);
                hosts.push(HostsSummary {
                    path: source,
                    records,
                });
            }
            Some("rule") => {
                ensure_rule_capacity(rules.len(), line_number)?;
                let parsed = parse_rule(&fields, line_number, next_rule_id)?;
                if let Some(id) = &parsed.proxy_ref {
                    referenced_endpoints.insert(id.clone());
                }
                rules.push(parsed.rule);
                next_rule_id += 1;
            }
            Some(other) => {
                return Err(ConfigError::at(
                    line_number,
                    format!("unknown directive `{other}`"),
                ));
            }
            None => {}
        }
    }

    if !version_seen {
        return Err(ConfigError::global("missing `version 1` directive"));
    }
    if listeners.is_empty() {
        return Err(ConfigError::global("at least one listener is required"));
    }
    if !allow_public_listen.unwrap_or(false)
        && listeners
            .iter()
            .any(|listener| !listener.address.ip().is_loopback())
    {
        return Err(ConfigError::global(
            "non-loopback listeners require explicit `allow-public-listen true` because alpha inbounds have no authentication",
        ));
    }
    let default_action =
        default_action.ok_or_else(|| ConfigError::global("missing default action"))?;
    let outbounds = OutboundRegistry::new(endpoint_configs)
        .map_err(|error| ConfigError::global(error.to_string()))?;
    for id in &referenced_endpoints {
        if !outbounds.contains(id) {
            return Err(ConfigError::global(format!(
                "policy references undefined proxy endpoint `{}`",
                id.as_str()
            )));
        }
    }

    Ok(CompiledConfig {
        listeners,
        blocklists,
        hosts,
        runtime: Runtime::new(PolicyEngine::new(rules, default_action)),
        dns: Arc::new(DnsEngine::system(hosts_table)),
        outbounds: Arc::new(outbounds),
    })
}

struct ParsedAction {
    action: PolicyAction,
    proxy_ref: Option<EndpointId>,
}

fn parse_action(value: &str, line: usize) -> Result<ParsedAction, ConfigError> {
    let (action, proxy_ref) = match value {
        "direct" => (PolicyAction::Route(Endpoint::Direct), None),
        "reject" => (PolicyAction::Reject(RejectReason::Policy), None),
        _ => {
            let value = value.strip_prefix("proxy:").ok_or_else(|| {
                ConfigError::at(line, "action must be `direct`, `reject`, or `proxy:<id>`")
            })?;
            let id = EndpointId::new(value.to_owned())
                .map_err(|error| ConfigError::at(line, error.to_string()))?;
            (PolicyAction::Route(Endpoint::Proxy(id.clone())), Some(id))
        }
    };
    Ok(ParsedAction { action, proxy_ref })
}

struct ParsedRule {
    rule: PolicyRule,
    proxy_ref: Option<EndpointId>,
}

fn parse_rule(fields: &[&str], line: usize, id: u64) -> Result<ParsedRule, ConfigError> {
    if fields.len() < 3 {
        return Err(ConfigError::at(
            line,
            "rule syntax is `rule <direct|reject|proxy:id> <matcher> [value]`",
        ));
    }
    let parsed_action = parse_action(fields[1], line)?;
    let matcher = match fields[2] {
        "any" if fields.len() == 3 => Matcher::Any,
        "domain-exact" if fields.len() == 4 => {
            Matcher::DomainExact(normalize_domain(fields[3], line)?)
        }
        "domain-suffix" if fields.len() == 4 => {
            Matcher::DomainSuffix(normalize_domain(fields[3], line)?)
        }
        "ip" if fields.len() == 4 => Matcher::Ip(
            fields[3]
                .parse()
                .map_err(|_| ConfigError::at(line, "invalid IP address"))?,
        ),
        "cidr" if fields.len() == 4 => Matcher::Cidr(
            fields[3]
                .parse::<IpCidr>()
                .map_err(|error| ConfigError::at(line, error.to_string()))?,
        ),
        "port" if fields.len() == 4 => {
            let port: u16 = fields[3]
                .parse()
                .map_err(|_| ConfigError::at(line, "invalid destination port"))?;
            if port == 0 {
                return Err(ConfigError::at(line, "destination port must not be zero"));
            }
            Matcher::Port(port)
        }
        "transport" if fields.len() == 4 => Matcher::Transport(match fields[3] {
            "tcp" => commeatus_core::TransportProtocol::Tcp,
            "udp" => commeatus_core::TransportProtocol::Udp,
            _ => {
                return Err(ConfigError::at(
                    line,
                    "transport matcher must be `tcp` or `udp`",
                ));
            }
        }),
        _ => {
            return Err(ConfigError::at(
                line,
                "supported matchers: any, domain-exact, domain-suffix, ip, cidr, port, transport",
            ));
        }
    };

    Ok(ParsedRule {
        rule: PolicyRule {
            id: RuleId::new(id),
            tier: PolicyTier::UserHard,
            matcher,
            action: parsed_action.action,
        },
        proxy_ref: parsed_action.proxy_ref,
    })
}

fn parse_proxy_address(value: &str, line: usize) -> Result<SocketAddr, ConfigError> {
    let address: SocketAddr = value.parse().map_err(|_| {
        ConfigError::at(line, "proxy endpoint address must be an IP socket address")
    })?;
    if address.port() == 0 {
        return Err(ConfigError::at(
            line,
            "proxy endpoint port must not be zero",
        ));
    }
    Ok(address)
}

fn parse_tls_transport_raw(
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
}

fn expect_fields(
    fields: &[&str],
    expected: usize,
    line: usize,
    message: &'static str,
) -> Result<(), ConfigError> {
    if fields.len() == expected {
        Ok(())
    } else {
        Err(ConfigError::at(line, message))
    }
}

fn ensure_rule_capacity(current: usize, line: usize) -> Result<(), ConfigError> {
    if current < MAX_RULES {
        Ok(())
    } else {
        Err(ConfigError::at(
            line,
            format!("rule count exceeds {MAX_RULES}"),
        ))
    }
}

fn resolve_asset_path(root: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn load_blocklist(
    path: &Path,
    line: usize,
) -> Result<(commeatus_core::DomainFilter, BlocklistStats), ConfigError> {
    let text = read_bounded_asset(path, MAX_BLOCKLIST_BYTES, "blocklist", line)?;
    let compiled = compile_blocklist(&text).map_err(|error| {
        ConfigError::at(
            line,
            format!("cannot compile blocklist {}: {error}", path.display()),
        )
    })?;
    let stats = compiled.stats();
    Ok((compiled.into_filter(), stats))
}

fn load_hosts(path: &Path, line: usize) -> Result<HostsTable, ConfigError> {
    let text = read_bounded_asset(path, MAX_HOSTS_BYTES, "hosts", line)?;
    HostsTable::parse(&text).map_err(|error| {
        ConfigError::at(
            line,
            format!("cannot compile hosts {}: {error}", path.display()),
        )
    })
}

fn read_bounded_asset(
    path: &Path,
    max_bytes: usize,
    kind: &'static str,
    line: usize,
) -> Result<String, ConfigError> {
    let metadata = fs::metadata(path).map_err(|error| {
        ConfigError::at(
            line,
            format!("cannot stat {kind} {}: {error}", path.display()),
        )
    })?;
    if metadata.len() > max_bytes as u64 {
        return Err(ConfigError::at(
            line,
            format!("{kind} {} exceeds {max_bytes} byte limit", path.display()),
        ));
    }
    fs::read_to_string(path).map_err(|error| {
        ConfigError::at(
            line,
            format!("cannot read {kind} {}: {error}", path.display()),
        )
    })
}

fn normalize_domain(value: &str, line: usize) -> Result<String, ConfigError> {
    let normalized = value.trim_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 {
        Err(ConfigError::at(line, "invalid domain matcher"))
    } else {
        Ok(normalized)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::IpAddr,
        time::{SystemTime, UNIX_EPOCH},
    };

    use commeatus_core::{
        Destination, DestinationHost, ExecutionAction, FlowContext, FlowId, NetworkContext,
        SourceContext, TransportProtocol,
    };

    use super::*;

    const VALID: &str = r#"
        version 1
        listen socks5 127.0.0.1:1080
        default direct
        rule reject domain-suffix ads.example
        rule reject cidr 10.0.0.0/8
    "#;

    fn plan(store: &ConfigStore, host: DestinationHost) -> ExecutionAction {
        let snapshot = store.snapshot().unwrap();
        snapshot
            .runtime()
            .plan(&FlowContext::new(
                FlowId::new(1),
                SourceContext::default(),
                Destination { host, port: 443 },
                TransportProtocol::Tcp,
                NetworkContext::default(),
            ))
            .action
    }

    fn temp_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("commeatus-config-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn native_config_compiles_into_policy_runtime() {
        let store = ConfigStore::new(VALID).unwrap();
        assert!(matches!(
            plan(
                &store,
                DestinationHost::Domain("cdn.ads.example".to_owned())
            ),
            ExecutionAction::Reject { .. }
        ));
        assert!(matches!(
            plan(
                &store,
                DestinationHost::Domain("www.example.com".to_owned())
            ),
            ExecutionAction::Route { .. }
        ));
        assert!(matches!(
            plan(&store, DestinationHost::Ip("10.20.30.40".parse().unwrap())),
            ExecutionAction::Reject { .. }
        ));
    }

    #[test]
    fn named_proxy_endpoint_compiles_into_policy_and_registry() {
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            endpoint edge socks5 127.0.0.1:1081
            rule proxy:edge domain-suffix proxied.example
            default direct
        "#;
        let store = ConfigStore::new(config).unwrap();
        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.outbounds().len(), 1);
        assert!(matches!(
            plan(
                &store,
                DestinationHost::Domain("api.proxied.example".to_owned())
            ),
            ExecutionAction::Route {
                endpoint: Endpoint::Proxy(ref id)
            } if id.as_str() == "edge"
        ));
    }

    #[test]
    fn undefined_proxy_endpoint_rejects_candidate() {
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            rule proxy:missing any
            default direct
        "#;
        assert!(parse_config(config).is_err());
    }

    #[test]
    fn duplicate_proxy_endpoint_id_is_rejected() {
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            endpoint edge socks5 127.0.0.1:1081
            endpoint edge http 127.0.0.1:8081
            default direct
        "#;
        assert!(parse_config(config).is_err());
    }

    #[test]
    fn blocklist_is_compiled_relative_to_config_directory() {
        let root = temp_dir();
        fs::write(
            root.join("ads.txt"),
            "0.0.0.0 ads.example\n||telemetry.example^\n@@||api.telemetry.example^\n",
        )
        .unwrap();
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            blocklist ads.txt
            default direct
        "#;
        let store = ConfigStore::new_at(config, &root).unwrap();
        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.blocklists().len(), 1);
        assert_eq!(snapshot.blocklists()[0].stats.accepted_block, 2);
        assert!(matches!(
            plan(
                &store,
                DestinationHost::Domain("x.telemetry.example".to_owned())
            ),
            ExecutionAction::Reject { .. }
        ));
        assert!(matches!(
            plan(
                &store,
                DestinationHost::Domain("api.telemetry.example".to_owned())
            ),
            ExecutionAction::Route { .. }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hosts_override_is_compiled_into_dns_engine() {
        let root = temp_dir();
        fs::write(root.join("hosts.txt"), "203.0.113.7 service.test\n").unwrap();
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            hosts hosts.txt
            default direct
        "#;
        let store = ConfigStore::new_at(config, &root).unwrap();
        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.hosts().len(), 1);
        assert_eq!(
            snapshot.dns().resolve("service.test").unwrap(),
            vec!["203.0.113.7".parse::<IpAddr>().unwrap()]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_asset_fails_candidate_before_runtime_swap() {
        let root = temp_dir();
        let store = ConfigStore::new_at(VALID, &root).unwrap();
        let before = store.snapshot().unwrap();
        let candidate = r#"
            version 1
            listen socks5 127.0.0.1:1080
            hosts missing.txt
            default direct
        "#;
        assert!(store.reload(candidate).is_err());
        let after = store.snapshot().unwrap();
        assert!(Arc::ptr_eq(&before, &after));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_reload_keeps_last_known_good_snapshot() {
        let store = ConfigStore::new(VALID).unwrap();
        let before = store.snapshot().unwrap();
        assert!(store.reload("version 2").is_err());
        let after = store.snapshot().unwrap();
        assert!(Arc::ptr_eq(&before, &after));
    }

    #[test]
    fn duplicate_bind_address_is_rejected() {
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            listen http 127.0.0.1:1080
            default direct
        "#;
        assert!(parse_config(config).is_err());
    }

    #[test]
    fn public_listener_requires_explicit_opt_in() {
        let unsafe_default = r#"
            version 1
            listen socks5 0.0.0.0:1080
            default direct
        "#;
        assert!(parse_config(unsafe_default).is_err());

        let explicit = r#"
            version 1
            allow-public-listen true
            listen socks5 0.0.0.0:1080
            default direct
        "#;
        assert!(parse_config(explicit).is_ok());
    }

    #[test]
    fn transport_matcher_is_available_to_native_config() {
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            rule reject transport udp
            default direct
        "#;
        assert!(parse_config(config).is_ok());
    }

    #[test]
    fn explicit_tcp_and_tls_endpoint_syntax_compile() {
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            endpoint plain socks5 tcp 127.0.0.1:1081
            endpoint secure http tls 127.0.0.1:8443 proxy.example
            rule proxy:secure domain-suffix secure.example
            default proxy:plain
        "#;
        let compiled = parse_config(config).unwrap();
        assert_eq!(compiled.outbounds().len(), 2);
        let secure = Endpoint::Proxy(EndpointId::new("secure").unwrap());
        let capabilities = compiled.outbounds().capabilities(&secure).unwrap();
        assert!(capabilities.supports_tcp());
        assert!(!capabilities.supports_udp());
        assert!(capabilities.encrypted_transport());
    }

    #[test]
    fn invalid_tls_server_name_rejects_candidate() {
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            endpoint secure socks5 tls 127.0.0.1:8443 bad_name!
            default proxy:secure
        "#;
        assert!(parse_config(config).is_err());
    }

    #[test]
    fn trojan_tls_endpoint_compiles_with_stream_and_datagram_capability() {
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            endpoint secure trojan tls 127.0.0.1:443 trojan.example secret
            default proxy:secure
        "#;
        let compiled = parse_config(config).unwrap();
        assert_eq!(compiled.outbounds().len(), 1);
        let endpoint = Endpoint::Proxy(EndpointId::new("secure").unwrap());
        let capabilities = compiled.outbounds().capabilities(&endpoint).unwrap();
        assert!(capabilities.supports_tcp());
        assert!(capabilities.supports_udp());
        assert!(capabilities.encrypted_transport());
    }

    #[test]
    fn trojan_plain_tcp_is_rejected_by_candidate_parser() {
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            endpoint insecure trojan tcp 127.0.0.1:443 secret
            default proxy:insecure
        "#;
        assert!(parse_config(config).is_err());
    }

    #[test]
    fn config_size_is_bounded() {
        let oversized = "x".repeat(MAX_CONFIG_BYTES + 1);
        assert!(parse_config(&oversized).is_err());
    }
}
