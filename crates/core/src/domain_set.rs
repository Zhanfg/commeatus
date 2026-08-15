use std::fmt;

pub const MAX_DOMAIN_LENGTH: usize = 253;

/// Immutable, sorted domain set used by large compiled policy assets.
///
/// `suffixes` use DNS label boundaries: `example.com` matches both
/// `example.com` and `a.example.com`, never `badexample.com`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DomainSet {
    exact: Vec<String>,
    suffixes: Vec<String>,
}

impl DomainSet {
    pub fn compile(
        exact: impl IntoIterator<Item = String>,
        suffixes: impl IntoIterator<Item = String>,
    ) -> Result<Self, DomainSetError> {
        let mut exact = exact
            .into_iter()
            .map(normalize_domain)
            .collect::<Result<Vec<_>, _>>()?;
        let mut suffixes = suffixes
            .into_iter()
            .map(normalize_domain)
            .collect::<Result<Vec<_>, _>>()?;
        exact.sort_unstable();
        exact.dedup();
        suffixes.sort_unstable();
        suffixes.dedup();
        Ok(Self { exact, suffixes })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffixes.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.exact.len() + self.suffixes.len()
    }

    #[must_use]
    pub fn exact_len(&self) -> usize {
        self.exact.len()
    }

    #[must_use]
    pub fn suffix_len(&self) -> usize {
        self.suffixes.len()
    }

    #[must_use]
    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.');
        if domain.is_empty() || domain.len() > MAX_DOMAIN_LENGTH || !domain.is_ascii() {
            return false;
        }

        if self
            .exact
            .binary_search_by(|candidate| candidate.as_str().cmp(domain))
            .is_ok()
        {
            return true;
        }

        let mut candidate = domain;
        loop {
            if self
                .suffixes
                .binary_search_by(|suffix| suffix.as_str().cmp(candidate))
                .is_ok()
            {
                return true;
            }
            let Some(dot) = candidate.find('.') else {
                return false;
            };
            candidate = &candidate[dot + 1..];
        }
    }
}

/// A block domain set with an exception set. Exceptions are filter semantics,
/// not routing actions, so an allow exception does not accidentally force DIRECT.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DomainFilter {
    blocked: DomainSet,
    allowed: DomainSet,
}

impl DomainFilter {
    #[must_use]
    pub const fn new(blocked: DomainSet, allowed: DomainSet) -> Self {
        Self { blocked, allowed }
    }

    #[must_use]
    pub fn is_blocked(&self, domain: &str) -> bool {
        self.blocked.matches(domain) && !self.allowed.matches(domain)
    }

    #[must_use]
    pub fn blocked_len(&self) -> usize {
        self.blocked.len()
    }

    #[must_use]
    pub fn allowed_len(&self) -> usize {
        self.allowed.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainSetError {
    message: String,
}

impl fmt::Display for DomainSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for DomainSetError {}

fn normalize_domain(value: String) -> Result<String, DomainSetError> {
    let value = value.trim_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > MAX_DOMAIN_LENGTH
        || !value.is_ascii()
        || value
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err(DomainSetError {
            message: format!("invalid domain `{value}`"),
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_matching_uses_label_boundaries_without_allocating_per_suffix() {
        let set = DomainSet::compile(Vec::new(), vec!["example.com".to_owned()]).unwrap();
        assert!(set.matches("example.com"));
        assert!(set.matches("api.example.com"));
        assert!(!set.matches("badexample.com"));
    }

    #[test]
    fn compile_normalizes_sorts_and_deduplicates() {
        let set = DomainSet::compile(
            vec!["EXAMPLE.COM.".to_owned(), "example.com".to_owned()],
            vec!["Ads.Example".to_owned(), "ads.example".to_owned()],
        )
        .unwrap();
        assert_eq!(set.exact_len(), 1);
        assert_eq!(set.suffix_len(), 1);
        assert!(set.matches("example.com"));
        assert!(set.matches("x.ads.example"));
    }

    #[test]
    fn allow_exception_overrides_only_filter_not_route() {
        let blocked = DomainSet::compile(Vec::new(), vec!["example.com".to_owned()]).unwrap();
        let allowed = DomainSet::compile(Vec::new(), vec!["api.example.com".to_owned()]).unwrap();
        let filter = DomainFilter::new(blocked, allowed);
        assert!(filter.is_blocked("ads.example.com"));
        assert!(!filter.is_blocked("api.example.com"));
    }
}
