use std::{
    collections::HashSet,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
};

use commeatus_core::{
    Endpoint, IpCidr, Matcher, PolicyAction, PolicyEngine, PolicyRule, PolicyTier, RejectReason,
    RuleId, Runtime,
};

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const MAX_RULES: usize = 4096;
pub const MAX_LISTENERS: usize = 16;

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

#[derive(Clone, Debug)]
pub struct CompiledConfig {
    listeners: Vec<ListenerConfig>,
    runtime: Runtime,
}

impl CompiledConfig {
    #[must_use]
    pub fn listeners(&self) -> &[ListenerConfig] {
        &self.listeners
    }

    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        &self.runtime
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(line) = self.line {
            write!(f, "config line {line}: {}", self.message)
        } else {
            f.write_str(&self.message)
        }
    }
}

impl std::error::Error for ConfigError {}

/// Active configuration holder with transactional replacement semantics.
///
/// A candidate is fully parsed and compiled before the write lock is acquired.
/// Invalid candidates therefore cannot partially mutate the active runtime.
pub struct ConfigStore {
    active: RwLock<Arc<CompiledConfig>>,
}

impl ConfigStore {
    pub fn new(text: &str) -> Result<Self, ConfigError> {
        let compiled = Arc::new(parse_config(text)?);
        Ok(Self {
            active: RwLock::new(compiled),
        })
    }

    pub fn reload(&self, text: &str) -> Result<(), ConfigError> {
        let candidate = Arc::new(parse_config(text)?);
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
    let mut rules = Vec::new();

    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.first().copied() {
            Some("version") => {
                if fields.len() != 2 || fields[1] != "1" {
                    return Err(ConfigError::at(line_number, "expected exactly `version 1`"));
                }
                if version_seen {
                    return Err(ConfigError::at(line_number, "duplicate version directive"));
                }
                version_seen = true;
            }
            Some("allow-public-listen") => {
                if fields.len() != 2 {
                    return Err(ConfigError::at(
                        line_number,
                        "allow-public-listen syntax is `allow-public-listen <true|false>`",
                    ));
                }
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
                if fields.len() != 3 {
                    return Err(ConfigError::at(
                        line_number,
                        "listen syntax is `listen <socks5|http> <ip:port>`",
                    ));
                }
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
            Some("default") => {
                if fields.len() != 2 {
                    return Err(ConfigError::at(
                        line_number,
                        "default syntax is `default <direct|reject>`",
                    ));
                }
                if default_action.is_some() {
                    return Err(ConfigError::at(line_number, "duplicate default directive"));
                }
                default_action = Some(parse_action(fields[1], line_number)?);
            }
            Some("rule") => {
                if rules.len() >= MAX_RULES {
                    return Err(ConfigError::at(
                        line_number,
                        format!("rule count exceeds {MAX_RULES}"),
                    ));
                }
                rules.push(parse_rule(&fields, line_number, rules.len() as u64 + 1)?);
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

    Ok(CompiledConfig {
        listeners,
        runtime: Runtime::new(PolicyEngine::new(rules, default_action)),
    })
}

fn parse_action(value: &str, line: usize) -> Result<PolicyAction, ConfigError> {
    match value {
        "direct" => Ok(PolicyAction::Route(Endpoint::Direct)),
        "reject" => Ok(PolicyAction::Reject(RejectReason::Policy)),
        _ => Err(ConfigError::at(line, "action must be `direct` or `reject`")),
    }
}

fn parse_rule(fields: &[&str], line: usize, id: u64) -> Result<PolicyRule, ConfigError> {
    if fields.len() < 3 {
        return Err(ConfigError::at(
            line,
            "rule syntax is `rule <direct|reject> <matcher> [value]`",
        ));
    }

    let action = parse_action(fields[1], line)?;
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
        _ => {
            return Err(ConfigError::at(
                line,
                "supported matchers: any, domain-exact, domain-suffix, ip, cidr, port",
            ));
        }
    };

    Ok(PolicyRule {
        id: RuleId::new(id),
        tier: PolicyTier::UserHard,
        matcher,
        action,
    })
}

fn normalize_domain(value: &str, line: usize) -> Result<String, ConfigError> {
    let normalized = value.trim_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 {
        return Err(ConfigError::at(line, "invalid domain matcher"));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
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
    fn config_size_is_bounded() {
        let oversized = "x".repeat(MAX_CONFIG_BYTES + 1);
        assert!(parse_config(&oversized).is_err());
    }
}
