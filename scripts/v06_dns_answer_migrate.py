from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match in {path}, found {count}: {old!r}")
    p.write_text(text.replace(old, new, 1))


lib = Path("crates/dns/src/lib.rs")
text = lib.read_text()
text = text.replace(
    "//! System DNS is the only network resolver in v0.2. DoH/DoT/DoQ can be added\n//! behind `Resolver` without changing proxy protocol handlers.\n",
    "//! System DNS remains the default resolver. Secure resolver providers attach\n//! behind `Resolver` without changing proxy protocol handlers or daemon callers.\n",
    1,
)
text = text.replace(
    "#![forbid(unsafe_code)]\n",
    "#![forbid(unsafe_code)]\n\nmod dot;\nmod wire;\n\npub use dot::DotResolver;\n",
    1,
)
text = text.replace(
    "    ResolverFailure,\n    InvalidConfiguration,\n",
    "    ResolverFailure,\n    InvalidResponse,\n    InvalidConfiguration,\n",
    1,
)
marker = "fn normalize_name(name: &str) -> Result<String, DnsError> {\n"
if text.count(marker) != 1:
    raise SystemExit("DnsQuery/normalize_name boundary changed unexpectedly")
answer = '''#[derive(Clone, Debug, Eq, PartialEq)]
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

'''
text = text.replace(marker, answer + marker, 1)
text = text.replace(
    "pub trait Resolver: Send + Sync {\n    fn resolve(&self, query: &DnsQuery) -> Result<Vec<IpAddr>, DnsError>;\n}\n",
    "pub trait Resolver: Send + Sync {\n    fn resolve(&self, query: &DnsQuery) -> Result<DnsAnswer, DnsError>;\n}\n",
    1,
)
text = text.replace(
    "        } else {\n            Ok(result)\n        }\n    }\n}\n\n#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]\npub struct DnsStats",
    "        } else {\n            DnsAnswer::new(result, None)\n        }\n    }\n}\n\n#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]\npub struct DnsStats",
    1,
)
text = text.replace(
    "    ttl: Duration,\n}\n\nimpl DnsCache {\n    fn defaults() -> Self {\n        Self {\n            entries: HashMap::new(),\n            capacity: DEFAULT_CACHE_CAPACITY,\n            ttl: DEFAULT_CACHE_TTL,\n",
    "    max_ttl: Duration,\n}\n\nimpl DnsCache {\n    fn defaults() -> Self {\n        Self {\n            entries: HashMap::new(),\n            capacity: DEFAULT_CACHE_CAPACITY,\n            max_ttl: DEFAULT_CACHE_TTL,\n",
    1,
)
text = text.replace(
    "            entries: HashMap::new(),\n            capacity,\n            ttl,\n        })\n",
    "            entries: HashMap::new(),\n            capacity,\n            max_ttl: ttl,\n        })\n",
    1,
)
old_insert = '''    fn insert(&mut self, name: String, addresses: Vec<IpAddr>, now: Instant) {
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
                expires: now + self.ttl,
            },
        );
    }
'''
new_insert = '''    fn insert(
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
'''
if text.count(old_insert) != 1:
    raise SystemExit("DnsCache::insert shape changed unexpectedly")
text = text.replace(old_insert, new_insert, 1)
old_resolver_loop = '''        let mut last_error = None;
        for resolver in &self.resolvers {
            match resolver.resolve(&query) {
                Ok(addresses) if !addresses.is_empty() => {
                    let addresses = deduplicate_bounded(addresses);
                    let mut cache = self.cache.lock().map_err(|_| {
                        DnsError::new(DnsErrorKind::ResolverFailure, "DNS cache lock is poisoned")
                    })?;
                    cache.insert(query.name, addresses.clone(), now);
                    return Ok(addresses);
                }
                Ok(_) => {
                    last_error = Some(DnsError::new(
                        DnsErrorKind::NoRecords,
                        format!("resolver returned no addresses for {}", query.name()),
                    ));
                }
                Err(error) => {
                    self.stats.resolver_failures.fetch_add(1, Ordering::Relaxed);
                    last_error = Some(error);
                }
            }
        }
'''
new_resolver_loop = '''        let mut last_error = None;
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
'''
if text.count(old_resolver_loop) != 1:
    raise SystemExit("DnsEngine resolver loop changed unexpectedly")
text = text.replace(old_resolver_loop, new_resolver_loop, 1)
text = text.replace(
    "        result: Result<Vec<IpAddr>, DnsError>,\n",
    "        result: Result<DnsAnswer, DnsError>,\n",
    1,
)
text = text.replace(
    '''        fn success(address: &str) -> Self {
            Self {
                result: Ok(vec![address.parse().unwrap()]),
                calls: AtomicUsize::new(0),
            }
        }
''',
    '''        fn success(address: &str) -> Self {
            Self::success_with_ttl(address, None)
        }

        fn success_with_ttl(address: &str, ttl: Option<Duration>) -> Self {
            Self {
                result: DnsAnswer::new(vec![address.parse().unwrap()], ttl),
                calls: AtomicUsize::new(0),
            }
        }
''',
    1,
)
text = text.replace(
    "        fn resolve(&self, _query: &DnsQuery) -> Result<Vec<IpAddr>, DnsError> {\n",
    "        fn resolve(&self, _query: &DnsQuery) -> Result<DnsAnswer, DnsError> {\n",
    1,
)
insert_before = '''    #[test]
    fn resolver_failure_falls_through_to_next_resolver() {
'''
if text.count(insert_before) != 1:
    raise SystemExit("DNS test insertion point changed unexpectedly")
zero_ttl_test = '''    #[test]
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

'''
text = text.replace(insert_before, zero_ttl_test + insert_before, 1)
lib.write_text(text)

# The DNS crate now consumes the transport abstraction for verified DoT.
cargo = Path("crates/dns/Cargo.toml")
cargo_text = cargo.read_text()
if "[dependencies]" in cargo_text:
    raise SystemExit("dns Cargo.toml already has dependencies; migrate explicitly")
cargo.write_text(
    cargo_text.rstrip()
    + '\n\n[dependencies]\ncommeatus-transport = { path = "../transport", version = "=0.5.0-alpha.1" }\n'
)

# No recoverable DNS path may rely on an internal expect().
dot = Path("crates/dns/src/dot.rs")
dot_text = dot.read_text()
old = '''            let result = exchange_message(
                self.session
                    .as_mut()
                    .expect("DoT session exists after successful connector return"),
                request,
            );
'''
new = '''            let Some(session) = self.session.as_mut() else {
                last_error = Some(io::Error::other(
                    "DNS-over-TLS connector returned without a usable session",
                ));
                continue;
            };
            let result = exchange_message(session, request);
'''
if dot_text.count(old) != 1:
    raise SystemExit("DoT session invariant block changed unexpectedly")
dot.write_text(dot_text.replace(old, new, 1))

# Compression pointers must point backward as required by DNS message compression.
wire = Path("crates/dns/src/wire.rs")
wire_text = wire.read_text()
old = '''            if pointer >= message.len() {
                return Err(invalid_response("DNS compression pointer is out of bounds"));
            }
            if resume.is_none() {
'''
new = '''            if pointer >= message.len() {
                return Err(invalid_response("DNS compression pointer is out of bounds"));
            }
            if pointer >= cursor {
                return Err(invalid_response("DNS compression pointer does not point backward"));
            }
            if resume.is_none() {
'''
if wire_text.count(old) != 1:
    raise SystemExit("DNS compression pointer guard changed unexpectedly")
wire.write_text(wire_text.replace(old, new, 1))

# Structural invariants for the migration.
final = lib.read_text()
for required in [
    "pub use dot::DotResolver;",
    "InvalidResponse,",
    "pub struct DnsAnswer",
    "Result<DnsAnswer, DnsError>",
    "resolver_ttl: Option<Duration>",
    "resolver_zero_ttl_is_not_cached",
]:
    if required not in final:
        raise SystemExit(f"missing migrated DNS invariant: {required}")
if "Result<Vec<IpAddr>, DnsError>" in final:
    raise SystemExit("legacy Resolver result type remains in dns lib")
if ".expect(" in dot.read_text():
    raise SystemExit("production DoT implementation still contains expect()")
