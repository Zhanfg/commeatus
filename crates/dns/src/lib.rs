//! Independent DNS failure domain for Commeatus.
//!
//! Resolution order is deliberately explicit:
//!
//! 1. native hosts overrides,
//! 2. bounded in-memory cache,
//! 3. ordered resolver fallback.
//!
//! System DNS remains the default resolver. Secure resolver providers attach
//! behind `Resolver` without changing proxy protocol handlers or daemon callers.

#![forbid(unsafe_code)]

mod dot;
mod wire;

pub use dot::DotResolver;

use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, ToSocketAddrs},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

pub const MAX_HOSTS_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_HOSTS_ENTRIES: usize = 100_000;
pub const MAX_RESOLVED_ADDRESSES: usize = 16;
pub const DEFAULT_CACHE_CAPACITY: usize = 4096;
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);
pub const MAX_CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsErrorKind {
    InvalidName,
    HostsParse,
    NoResolvers,
    NoRecords,
    ResolverFailure,
    InvalidResponse,
    InvalidConfiguration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsError {
    kind: DnsErrorKind,
    message: String,
}

impl DnsError {
    fn new(kind: DnsErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> DnsErrorKind {
        self.kind
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for DnsError {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostsTable {
    records: HashMap<String, Vec<IpAddr>>,
}

impl HostsTable {
    pub fn parse(text: &str) -> Result<Self, DnsError> {
        if text.len() > MAX_HOSTS_BYTES {
            return Err(DnsError::new(
                DnsErrorKind::HostsParse,
                format!("hosts source exceeds {MAX_HOSTS_BYTES} byte limit"),
            ));
        }

        let mut table = Self::default();
        let mut entries = 0_usize;
        for (index, raw_line) in text.lines().enumerate() {
            let line_number = index + 1;
            let line = raw_line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let address: IpAddr = fields
                .next()
                .ok_or_else(|| hosts_error(line_number, "missing IP address"))?
                .parse()
                .map_err(|_| hosts_error(line_number, "invalid IP address"))?;
            let mut names = 0_usize;
            for name in fields {
                if entries >= MAX_HOSTS_ENTRIES {
                    return Err(hosts_error(
                        line_number,
                        format!("hosts entry count exceeds {MAX_HOSTS_ENTRIES}"),
                    ));
                }
                let name = normalize_name(name)
                    .map_err(|_| hosts_error(line_number, "invalid hostname"))?;
                let addresses = table.records.entry(name).or_default();
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
                entries += 1;
                names += 1;
            }
            if names == 0 {
                return Err(hosts_error(line_number, "hosts line has no hostname"));
            }
        }
        Ok(table)
    }

    pub fn merge(&mut self, other: Self) {
        for (name, incoming) in other.records {
            let current = self.records.entry(name).or_default();
            for address in incoming {
                if !current.contains(&address) {
                    current.push(address);
                }
            }
        }
    }

    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<Vec<IpAddr>> {
        self.records.get(name).cloned()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

fn hosts_error(line: usize, message: impl fmt::Display) -> DnsError {
    DnsError::new(
        DnsErrorKind::HostsParse,
        format!("hosts line {line}: {message}"),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuery {
    name: String,
}

impl DnsQuery {
    pub fn new(name: &str) -> Result<Self, DnsError> {
        Ok(Self {
            name: normalize_name(name)?,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsAnswer {
    addresses: Vec<IpAddr>,
    ttl: Option<Duration>,
}

impl DnsAnswer {
    pub fn new(addresses: Vec<IpAddr>, ttl: Option<Duration>) -> Result<Self, DnsError> {
        let addresses = deduplicate_bounded(addresses);
        if addresses.is_empty() {
            return Err(DnsError::new(
                DnsErrorKind::NoRecords,
                "DNS answer contains no usable addresses",
            ));
        }
        Ok(Self { addresses, ttl })
    }

    #[must_use]
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    #[must_use]
    pub const fn ttl(&self) -> Option<Duration> {
        self.ttl
    }

    fn into_parts(self) -> (Vec<IpAddr>, Option<Duration>) {
        (self.addresses, self.ttl)
    }
}

fn normalize_name(name: &str) -> Result<String, DnsError> {
    let name = name.trim_matches('.').to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 253
        || !name.is_ascii()
        || name
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err(DnsError::new(DnsErrorKind::InvalidName, "invalid DNS name"));
    }
    Ok(name)
}

pub trait Resolver: Send + Sync {
    fn resolve(&self, query: &DnsQuery) -> Result<DnsAnswer, DnsError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, query: &DnsQuery) -> Result<DnsAnswer, DnsError> {
        let addresses = (query.name(), 0_u16).to_socket_addrs().map_err(|error| {
            DnsError::new(
                DnsErrorKind::ResolverFailure,
                format!("system resolver failed for {}: {error}", query.name()),
            )
        })?;
        let mut result = Vec::new();
        for address in addresses.take(MAX_RESOLVED_ADDRESSES) {
            if !result.contains(&address.ip()) {
                result.push(address.ip());
            }
        }
        if result.is_empty() {
            Err(DnsError::new(
                DnsErrorKind::NoRecords,
                format!("system resolver returned no addresses for {}", query.name()),
            ))
        } else {
            DnsAnswer::new(result, None)
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DnsStats {
    pub hosts_hits: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub resolver_failures: u64,
}

#[derive(Default)]
struct AtomicDnsStats {
    hosts_hits: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    resolver_failures: AtomicU64,
}

impl AtomicDnsStats {
    fn snapshot(&self) -> DnsStats {
        DnsStats {
            hosts_hits: self.hosts_hits.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            resolver_failures: self.resolver_failures.load(Ordering::Relaxed),
        }
    }
}

struct CacheEntry {
    addresses: Vec<IpAddr>,
    inserted: Instant,
    expires: Instant,
}

struct DnsCache {
    entries: HashMap<String, CacheEntry>,
    capacity: usize,
    max_ttl: Duration,
}

impl DnsCache {
    fn defaults() -> Self {
        Self {
            entries: HashMap::new(),
            capacity: DEFAULT_CACHE_CAPACITY,
            max_ttl: DEFAULT_CACHE_TTL,
        }
    }

    fn new(capacity: usize, ttl: Duration) -> Result<Self, DnsError> {
        if capacity == 0 || ttl.is_zero() || ttl > MAX_CACHE_TTL {
            return Err(DnsError::new(
                DnsErrorKind::InvalidConfiguration,
                "DNS cache requires capacity > 0 and TTL in 1ns..=300s",
            ));
        }
        Ok(Self {
            entries: HashMap::new(),
            capacity,
            max_ttl: ttl,
        })
    }

    fn get(&mut self, name: &str, now: Instant) -> Option<Vec<IpAddr>> {
        if self
            .entries
            .get(name)
            .is_some_and(|entry| entry.expires <= now)
        {
            self.entries.remove(name);
            return None;
        }
        self.entries.get(name).map(|entry| entry.addresses.clone())
    }

    fn insert(
        &mut self,
        name: String,
        addresses: Vec<IpAddr>,
        resolver_ttl: Option<Duration>,
        now: Instant,
    ) {
        let ttl = resolver_ttl.unwrap_or(self.max_ttl).min(self.max_ttl);
        if ttl.is_zero() {
            return;
        }
        self.entries.retain(|_, entry| entry.expires > now);
        if !self.entries.contains_key(&name) && self.entries.len() >= self.capacity {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.inserted)
                .map(|(name, _)| name.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            name,
            CacheEntry {
                addresses,
                inserted: now,
                expires: now + ttl,
            },
        );
    }
}

pub struct DnsEngine {
    hosts: HostsTable,
    cache: Mutex<DnsCache>,
    resolvers: Vec<Arc<dyn Resolver>>,
    stats: AtomicDnsStats,
}

impl fmt::Debug for DnsEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsEngine")
            .field("hosts", &self.hosts.len())
            .field("resolvers", &self.resolvers.len())
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl DnsEngine {
    #[must_use]
    pub fn system(hosts: HostsTable) -> Self {
        Self {
            hosts,
            cache: Mutex::new(DnsCache::defaults()),
            resolvers: vec![Arc::new(SystemResolver)],
            stats: AtomicDnsStats::default(),
        }
    }

    pub fn with_resolvers(
        hosts: HostsTable,
        resolvers: Vec<Arc<dyn Resolver>>,
        cache_capacity: usize,
        cache_ttl: Duration,
    ) -> Result<Self, DnsError> {
        if resolvers.is_empty() {
            return Err(DnsError::new(
                DnsErrorKind::NoResolvers,
                "DNS engine requires at least one resolver",
            ));
        }
        Ok(Self {
            hosts,
            cache: Mutex::new(DnsCache::new(cache_capacity, cache_ttl)?),
            resolvers,
            stats: AtomicDnsStats::default(),
        })
    }

    pub fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        let query = DnsQuery::new(name)?;
        if let Some(addresses) = self.hosts.resolve(query.name()) {
            self.stats.hosts_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(addresses);
        }

        let now = Instant::now();
        {
            let mut cache = self.cache.lock().map_err(|_| {
                DnsError::new(DnsErrorKind::ResolverFailure, "DNS cache lock is poisoned")
            })?;
            if let Some(addresses) = cache.get(query.name(), now) {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(addresses);
            }
        }
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);

        let mut last_error = None;
        for resolver in &self.resolvers {
            match resolver.resolve(&query) {
                Ok(answer) => {
                    let (addresses, resolver_ttl) = answer.into_parts();
                    let addresses = deduplicate_bounded(addresses);
                    if addresses.is_empty() {
                        last_error = Some(DnsError::new(
                            DnsErrorKind::NoRecords,
                            format!("resolver returned no addresses for {}", query.name()),
                        ));
                        continue;
                    }
                    let mut cache = self.cache.lock().map_err(|_| {
                        DnsError::new(DnsErrorKind::ResolverFailure, "DNS cache lock is poisoned")
                    })?;
                    cache.insert(query.name, addresses.clone(), resolver_ttl, now);
                    return Ok(addresses);
                }
                Err(error) => {
                    self.stats.resolver_failures.fetch_add(1, Ordering::Relaxed);
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DnsError::new(
                DnsErrorKind::NoRecords,
                format!("no resolver produced addresses for {}", query.name()),
            )
        }))
    }

    #[must_use]
    pub fn stats(&self) -> DnsStats {
        self.stats.snapshot()
    }

    #[must_use]
    pub fn hosts_len(&self) -> usize {
        self.hosts.len()
    }
}

fn deduplicate_bounded(addresses: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut result = Vec::with_capacity(addresses.len().min(MAX_RESOLVED_ADDRESSES));
    for address in addresses {
        if result.len() >= MAX_RESOLVED_ADDRESSES {
            break;
        }
        if !result.contains(&address) {
            result.push(address);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    struct StaticResolver {
        result: Result<DnsAnswer, DnsError>,
        calls: AtomicUsize,
    }

    impl StaticResolver {
        fn success(address: &str) -> Self {
            Self::success_with_ttl(address, None)
        }

        fn success_with_ttl(address: &str, ttl: Option<Duration>) -> Self {
            Self {
                result: DnsAnswer::new(vec![address.parse().unwrap()], ttl),
                calls: AtomicUsize::new(0),
            }
        }

        fn failure() -> Self {
            Self {
                result: Err(DnsError::new(
                    DnsErrorKind::ResolverFailure,
                    "synthetic resolver failure",
                )),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl Resolver for StaticResolver {
        fn resolve(&self, _query: &DnsQuery) -> Result<DnsAnswer, DnsError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.result.clone()
        }
    }

    #[test]
    fn hosts_override_resolves_before_network_resolver() {
        let hosts = HostsTable::parse("203.0.113.9 service.example\n").unwrap();
        let resolver = Arc::new(StaticResolver::failure());
        let engine =
            DnsEngine::with_resolvers(hosts, vec![resolver.clone()], 16, Duration::from_secs(60))
                .unwrap();
        assert_eq!(
            engine.resolve("SERVICE.EXAMPLE.").unwrap(),
            vec!["203.0.113.9".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 0);
        assert_eq!(engine.stats().hosts_hits, 1);
    }

    #[test]
    fn successful_resolution_is_cached() {
        let resolver = Arc::new(StaticResolver::success("198.51.100.8"));
        let engine = DnsEngine::with_resolvers(
            HostsTable::default(),
            vec![resolver.clone()],
            16,
            Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(engine.resolve("cache.example").unwrap().len(), 1);
        assert_eq!(engine.resolve("cache.example").unwrap().len(), 1);
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
        assert_eq!(engine.stats().cache_hits, 1);
    }

    #[test]
    fn resolver_zero_ttl_is_not_cached() {
        let resolver = Arc::new(StaticResolver::success_with_ttl(
            "198.51.100.9",
            Some(Duration::ZERO),
        ));
        let engine = DnsEngine::with_resolvers(
            HostsTable::default(),
            vec![resolver.clone()],
            16,
            Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(engine.resolve("volatile.example").unwrap().len(), 1);
        assert_eq!(engine.resolve("volatile.example").unwrap().len(), 1);
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 2);
        assert_eq!(engine.stats().cache_hits, 0);
    }

    #[test]
    fn resolver_failure_falls_through_to_next_resolver() {
        let failed = Arc::new(StaticResolver::failure());
        let working = Arc::new(StaticResolver::success("192.0.2.44"));
        let engine = DnsEngine::with_resolvers(
            HostsTable::default(),
            vec![failed.clone(), working.clone()],
            16,
            Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(
            engine.resolve("fallback.example").unwrap(),
            vec!["192.0.2.44".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(failed.calls.load(Ordering::Relaxed), 1);
        assert_eq!(working.calls.load(Ordering::Relaxed), 1);
        assert_eq!(engine.stats().resolver_failures, 1);
    }

    #[test]
    fn hosts_parser_accepts_multiple_names_and_addresses() {
        let mut hosts =
            HostsTable::parse("127.0.0.1 localhost local.test\n::1 localhost local.test\n")
                .unwrap();
        let extra = HostsTable::parse("192.0.2.1 other.test\n").unwrap();
        hosts.merge(extra);
        assert_eq!(hosts.resolve("localhost").unwrap().len(), 2);
        assert_eq!(hosts.resolve("local.test").unwrap().len(), 2);
        assert_eq!(hosts.resolve("other.test").unwrap().len(), 1);
    }

    #[test]
    fn invalid_hosts_name_is_classified_as_hosts_parse() {
        let error = HostsTable::parse("127.0.0.1 bad..name\n").unwrap_err();
        assert_eq!(error.kind(), DnsErrorKind::HostsParse);
    }

    #[test]
    fn system_resolver_handles_localhost() {
        let engine = DnsEngine::system(HostsTable::default());
        assert!(!engine.resolve("localhost").unwrap().is_empty());
    }
}
