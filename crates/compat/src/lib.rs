//! Compatibility boundary with existing proxy and filtering ecosystems.
//!
//! Source formats terminate here and compile into native typed structures.

#![forbid(unsafe_code)]

use std::{fmt, net::IpAddr};

use commeatus_core::{DomainFilter, DomainSet};

pub const MAX_BLOCKLIST_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_BLOCKLIST_ENTRIES: usize = 250_000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlocklistStats {
    pub source_lines: usize,
    pub accepted_block: usize,
    pub accepted_allow: usize,
    pub ignored: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledBlocklist {
    filter: DomainFilter,
    stats: BlocklistStats,
}

impl CompiledBlocklist {
    #[must_use]
    pub const fn filter(&self) -> &DomainFilter {
        &self.filter
    }

    #[must_use]
    pub const fn stats(&self) -> BlocklistStats {
        self.stats
    }

    #[must_use]
    pub fn into_filter(self) -> DomainFilter {
        self.filter
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlocklistError {
    line: Option<usize>,
    message: String,
}

impl BlocklistError {
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

impl fmt::Display for BlocklistError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(formatter, "blocklist line {line}: {}", self.message),
            None => formatter.write_str(&self.message),
        }
    }
}

impl std::error::Error for BlocklistError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuleKind {
    BlockExact,
    BlockSuffix,
    AllowSuffix,
}

pub fn compile_blocklist(text: &str) -> Result<CompiledBlocklist, BlocklistError> {
    if text.len() > MAX_BLOCKLIST_BYTES {
        return Err(BlocklistError::global(format!(
            "blocklist exceeds {MAX_BLOCKLIST_BYTES} byte limit"
        )));
    }

    let mut blocked_exact = Vec::new();
    let mut blocked_suffix = Vec::new();
    let mut allowed_suffix = Vec::new();
    let mut stats = BlocklistStats::default();

    for (index, raw_line) in text.lines().enumerate() {
        stats.source_lines += 1;
        let line_number = index + 1;
        match parse_line(raw_line, line_number)? {
            Some((RuleKind::BlockExact, domain)) => {
                enforce_entry_limit(
                    blocked_exact.len() + blocked_suffix.len() + allowed_suffix.len(),
                    line_number,
                )?;
                blocked_exact.push(domain);
                stats.accepted_block += 1;
            }
            Some((RuleKind::BlockSuffix, domain)) => {
                enforce_entry_limit(
                    blocked_exact.len() + blocked_suffix.len() + allowed_suffix.len(),
                    line_number,
                )?;
                blocked_suffix.push(domain);
                stats.accepted_block += 1;
            }
            Some((RuleKind::AllowSuffix, domain)) => {
                enforce_entry_limit(
                    blocked_exact.len() + blocked_suffix.len() + allowed_suffix.len(),
                    line_number,
                )?;
                allowed_suffix.push(domain);
                stats.accepted_allow += 1;
            }
            None => stats.ignored += 1,
        }
    }

    let blocked = DomainSet::compile(blocked_exact, blocked_suffix)
        .map_err(|error| BlocklistError::global(error.to_string()))?;
    let allowed = DomainSet::compile(Vec::new(), allowed_suffix)
        .map_err(|error| BlocklistError::global(error.to_string()))?;
    Ok(CompiledBlocklist {
        filter: DomainFilter::new(blocked, allowed),
        stats,
    })
}

fn enforce_entry_limit(current: usize, line: usize) -> Result<(), BlocklistError> {
    if current >= MAX_BLOCKLIST_ENTRIES {
        Err(BlocklistError::at(
            line,
            format!("entry count exceeds {MAX_BLOCKLIST_ENTRIES}"),
        ))
    } else {
        Ok(())
    }
}

fn parse_line(raw: &str, line: usize) -> Result<Option<(RuleKind, String)>, BlocklistError> {
    let value = raw.trim();
    if value.is_empty() || value.starts_with('#') || value.starts_with('!') {
        return Ok(None);
    }

    if let Some(domain) = value
        .strip_prefix("@@||")
        .and_then(|value| value.strip_suffix('^'))
    {
        return Ok(Some((RuleKind::AllowSuffix, parse_domain(domain, line)?)));
    }
    if let Some(domain) = value
        .strip_prefix("||")
        .and_then(|value| value.strip_suffix('^'))
    {
        return Ok(Some((RuleKind::BlockSuffix, parse_domain(domain, line)?)));
    }

    let before_comment = value.split('#').next().unwrap_or_default().trim();
    let mut fields = before_comment.split_whitespace();
    let Some(first) = fields.next() else {
        return Ok(None);
    };
    if first.parse::<IpAddr>().is_ok() {
        let mut accepted = None;
        for host in fields {
            if is_localhost_alias(host) {
                continue;
            }
            if accepted.is_some() {
                return Err(BlocklistError::at(
                    line,
                    "hosts lines must contain at most one non-localhost hostname in this alpha",
                ));
            }
            accepted = Some(parse_domain(host, line)?);
        }
        return Ok(accepted.map(|domain| (RuleKind::BlockExact, domain)));
    }

    if fields.next().is_some() {
        return Err(BlocklistError::at(
            line,
            "unsupported blocklist syntax; expected one domain, hosts entry, `||domain^`, or `@@||domain^`",
        ));
    }
    Ok(Some((RuleKind::BlockExact, parse_domain(first, line)?)))
}

fn is_localhost_alias(value: &str) -> bool {
    value.eq_ignore_ascii_case("localhost")
        || value.eq_ignore_ascii_case("localhost.localdomain")
        || value.eq_ignore_ascii_case("broadcasthost")
        || value.eq_ignore_ascii_case("ip6-localhost")
        || value.eq_ignore_ascii_case("ip6-loopback")
}

fn parse_domain(value: &str, line: usize) -> Result<String, BlocklistError> {
    let value = value.trim_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value.split('.').any(|label| label.is_empty() || label.len() > 63)
    {
        return Err(BlocklistError::at(line, "invalid domain"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_hosts_plain_and_adblock_domains() {
        let list = r#"
            # comment
            0.0.0.0 ads.example.com
            tracker.example
            ||telemetry.example^
            @@||api.telemetry.example^
        "#;
        let compiled = compile_blocklist(list).unwrap();
        assert!(compiled.filter().is_blocked("ads.example.com"));
        assert!(compiled.filter().is_blocked("tracker.example"));
        assert!(compiled.filter().is_blocked("x.telemetry.example"));
        assert!(!compiled.filter().is_blocked("api.telemetry.example"));
        assert_eq!(compiled.stats().accepted_block, 3);
        assert_eq!(compiled.stats().accepted_allow, 1);
    }

    #[test]
    fn adblock_suffix_respects_dns_label_boundary() {
        let compiled = compile_blocklist("||example.com^\n").unwrap();
        assert!(compiled.filter().is_blocked("a.example.com"));
        assert!(!compiled.filter().is_blocked("badexample.com"));
    }

    #[test]
    fn rejects_ambiguous_multi_hostname_hosts_line() {
        assert!(compile_blocklist("0.0.0.0 a.example b.example\n").is_err());
    }

    #[test]
    fn byte_limit_is_enforced_before_parsing() {
        let oversized = "#".repeat(MAX_BLOCKLIST_BYTES + 1);
        assert!(compile_blocklist(&oversized).is_err());
    }
}
