from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match in {path}, found {count}: {old!r}")
    p.write_text(text.replace(old, new, 1))


path = Path("crates/daemon/src/config.rs")
text = path.read_text()

replace_once(
    str(path),
    "use commeatus_dns::{DnsEngine, HostsTable, MAX_HOSTS_BYTES};",
    "use commeatus_dns::{\n    DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL, DnsEngine, DotResolver, HostsTable,\n    MAX_HOSTS_BYTES, Resolver, SystemResolver,\n};",
)

replace_once(
    str(path),
    "pub const MAX_PROXY_ENDPOINTS: usize = 64;",
    "pub const MAX_PROXY_ENDPOINTS: usize = 64;\npub const MAX_DNS_RESOLVERS: usize = 8;",
)

replace_once(
    str(path),
    '''#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostsSummary {
    pub path: PathBuf,
    pub records: usize,
}

#[derive(Clone, Debug)]
pub struct CompiledConfig {
''',
    '''#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostsSummary {
    pub path: PathBuf,
    pub records: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsResolverSummary {
    System,
    Dot {
        address: SocketAddr,
        server_name: String,
    },
}

#[derive(Clone, Debug)]
pub struct CompiledConfig {
''',
)

replace_once(
    str(path),
    '''    blocklists: Vec<BlocklistSummary>,
    hosts: Vec<HostsSummary>,
    runtime: Runtime,
''',
    '''    blocklists: Vec<BlocklistSummary>,
    hosts: Vec<HostsSummary>,
    dns_resolvers: Vec<DnsResolverSummary>,
    runtime: Runtime,
''',
)

replace_once(
    str(path),
    '''    pub fn hosts(&self) -> &[HostsSummary] {
        &self.hosts
    }

    #[must_use]
    pub fn runtime(&self) -> &Runtime {
''',
    '''    pub fn hosts(&self) -> &[HostsSummary] {
        &self.hosts
    }

    #[must_use]
    pub fn dns_resolvers(&self) -> &[DnsResolverSummary] {
        &self.dns_resolvers
    }

    #[must_use]
    pub fn runtime(&self) -> &Runtime {
''',
)

replace_once(
    str(path),
    '''    let mut hosts = Vec::new();
    let mut hosts_paths = HashSet::new();
    let mut hosts_table = HostsTable::default();
    let mut endpoint_configs = Vec::new();
''',
    '''    let mut hosts = Vec::new();
    let mut hosts_paths = HashSet::new();
    let mut hosts_table = HostsTable::default();
    let mut dns_resolver_summaries = Vec::new();
    let mut dns_resolvers: Vec<Arc<dyn Resolver>> = Vec::new();
    let mut dns_resolver_keys = HashSet::new();
    let mut endpoint_configs = Vec::new();
''',
)

resolver_arm = '''            Some("resolver") => {
                if dns_resolvers.len() >= MAX_DNS_RESOLVERS {
                    return Err(ConfigError::at(
                        line_number,
                        format!("DNS resolver count exceeds {MAX_DNS_RESOLVERS}"),
                    ));
                }
                match fields.as_slice() {
                    ["resolver", "system"] => {
                        if !dns_resolver_keys.insert("system".to_owned()) {
                            return Err(ConfigError::at(
                                line_number,
                                "duplicate system DNS resolver",
                            ));
                        }
                        dns_resolver_summaries.push(DnsResolverSummary::System);
                        dns_resolvers.push(Arc::new(SystemResolver));
                    }
                    ["resolver", "dot", address, server_name] => {
                        let address: SocketAddr = address.parse().map_err(|_| {
                            ConfigError::at(
                                line_number,
                                "DoT resolver bootstrap address must be an IP socket address",
                            )
                        })?;
                        if address.port() == 0 {
                            return Err(ConfigError::at(
                                line_number,
                                "DoT resolver port must not be zero",
                            ));
                        }
                        let server_name = server_name.to_ascii_lowercase();
                        let key = format!("dot|{address}|{server_name}");
                        if !dns_resolver_keys.insert(key) {
                            return Err(ConfigError::at(
                                line_number,
                                "duplicate DNS-over-TLS resolver",
                            ));
                        }
                        let resolver = DotResolver::webpki(address, server_name.clone())
                            .map_err(|error| ConfigError::at(line_number, error.to_string()))?;
                        dns_resolver_summaries.push(DnsResolverSummary::Dot {
                            address,
                            server_name,
                        });
                        dns_resolvers.push(Arc::new(resolver));
                    }
                    _ => {
                        return Err(ConfigError::at(
                            line_number,
                            "resolver syntax is `resolver system` or `resolver dot <ip:port> <server-name>`",
                        ));
                    }
                }
            }
'''
needle = '            Some("endpoint") => {\n'
if text.count(needle) != 1:
    raise SystemExit("endpoint directive insertion point changed unexpectedly")
text = text.replace(needle, resolver_arm + needle, 1)

old_final = '''    Ok(CompiledConfig {
        listeners,
        blocklists,
        hosts,
        runtime: Runtime::new(PolicyEngine::new(rules, default_action)),
        dns: Arc::new(DnsEngine::system(hosts_table)),
        outbounds: Arc::new(outbounds),
    })
'''
new_final = '''    let (dns, dns_resolver_summaries) = if dns_resolvers.is_empty() {
        (
            DnsEngine::system(hosts_table),
            vec![DnsResolverSummary::System],
        )
    } else {
        let dns = DnsEngine::with_resolvers(
            hosts_table,
            dns_resolvers,
            DEFAULT_CACHE_CAPACITY,
            DEFAULT_CACHE_TTL,
        )
        .map_err(|error| ConfigError::global(error.to_string()))?;
        (dns, dns_resolver_summaries)
    };

    Ok(CompiledConfig {
        listeners,
        blocklists,
        hosts,
        dns_resolvers: dns_resolver_summaries,
        runtime: Runtime::new(PolicyEngine::new(rules, default_action)),
        dns: Arc::new(dns),
        outbounds: Arc::new(outbounds),
    })
'''
if text.count(old_final) != 1:
    raise SystemExit("CompiledConfig DNS construction changed unexpectedly")
text = text.replace(old_final, new_final, 1)

insert_before = '''    #[test]
    fn transport_matcher_is_available_to_native_config() {
'''
if text.count(insert_before) != 1:
    raise SystemExit("DNS config test insertion point changed unexpectedly")

tests = '''    #[test]
    fn no_resolver_directive_preserves_system_default() {
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            default direct
        "#;
        let compiled = parse_config(config).unwrap();
        assert_eq!(compiled.dns_resolvers(), &[DnsResolverSummary::System]);
    }

    #[test]
    fn dot_only_is_secure_only_without_implicit_system_fallback() {
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            resolver dot 1.1.1.1:853 Cloudflare-DNS.com
            default direct
        "#;
        let compiled = parse_config(config).unwrap();
        assert_eq!(
            compiled.dns_resolvers(),
            &[DnsResolverSummary::Dot {
                address: "1.1.1.1:853".parse().unwrap(),
                server_name: "cloudflare-dns.com".to_owned(),
            }]
        );
    }

    #[test]
    fn system_fallback_must_be_explicit_and_preserves_order() {
        let config = r#"
            version 1
            listen socks5 127.0.0.1:1080
            resolver dot 1.1.1.1:853 cloudflare-dns.com
            resolver system
            default direct
        "#;
        let compiled = parse_config(config).unwrap();
        assert_eq!(
            compiled.dns_resolvers(),
            &[
                DnsResolverSummary::Dot {
                    address: "1.1.1.1:853".parse().unwrap(),
                    server_name: "cloudflare-dns.com".to_owned(),
                },
                DnsResolverSummary::System,
            ]
        );
    }

    #[test]
    fn duplicate_or_ambiguous_resolvers_are_rejected() {
        let duplicate_system = r#"
            version 1
            listen socks5 127.0.0.1:1080
            resolver system
            resolver system
            default direct
        "#;
        assert!(parse_config(duplicate_system).is_err());

        let hostname_bootstrap = r#"
            version 1
            listen socks5 127.0.0.1:1080
            resolver dot dns.example:853 dns.example
            default direct
        "#;
        assert!(parse_config(hostname_bootstrap).is_err());

        let invalid_server_name = r#"
            version 1
            listen socks5 127.0.0.1:1080
            resolver dot 127.0.0.1:853 bad_name!
            default direct
        "#;
        assert!(parse_config(invalid_server_name).is_err());
    }

    #[test]
    fn resolver_count_is_bounded() {
        let mut config = String::from("version 1\nlisten socks5 127.0.0.1:1080\n");
        for index in 0..=MAX_DNS_RESOLVERS {
            config.push_str(&format!(
                "resolver dot 127.0.0.1:{} dns-{index}.example\n",
                853 + index
            ));
        }
        config.push_str("default direct\n");
        assert!(parse_config(&config).is_err());
    }

    #[test]
    fn invalid_secure_resolver_reload_keeps_last_known_good_snapshot() {
        let store = ConfigStore::new(VALID).unwrap();
        let before = store.snapshot().unwrap();
        let candidate = r#"
            version 1
            listen socks5 127.0.0.1:1080
            resolver dot dns.example:853 dns.example
            default direct
        "#;
        assert!(store.reload(candidate).is_err());
        let after = store.snapshot().unwrap();
        assert!(Arc::ptr_eq(&before, &after));
    }

'''
text = text.replace(insert_before, tests + insert_before, 1)

path.write_text(text)

final = path.read_text()
for required in [
    "pub const MAX_DNS_RESOLVERS: usize = 8;",
    "pub enum DnsResolverSummary",
    "pub fn dns_resolvers(&self) -> &[DnsResolverSummary]",
    'Some("resolver") => {',
    "DoT resolver bootstrap address must be an IP socket address",
    "dot_only_is_secure_only_without_implicit_system_fallback",
    "system_fallback_must_be_explicit_and_preserves_order",
]:
    if required not in final:
        raise SystemExit(f"missing DNS config invariant: {required}")
if "DnsEngine::system(hosts_table)" not in final:
    raise SystemExit("legacy implicit-system compatibility path was lost")
