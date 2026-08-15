use std::net::IpAddr;

use crate::{
    flow::{DestinationHost, FlowContext, TransportProtocol},
    plan::{Endpoint, RejectReason},
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RuleId(u64);

impl RuleId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Policy authority, ordered from strongest to weakest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyTier {
    UserHard,
    Safety,
    Compatibility,
    Adaptive,
    Default,
}

impl PolicyTier {
    const PRECEDENCE: [Self; 5] = [
        Self::UserHard,
        Self::Safety,
        Self::Compatibility,
        Self::Adaptive,
        Self::Default,
    ];
}

/// Typed match expression. Compatibility rule DSLs must compile into this form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Matcher {
    Any,
    Uid(u32),
    Package(String),
    DomainExact(String),
    DomainSuffix(String),
    Ip(IpAddr),
    Port(u16),
    Transport(TransportProtocol),
    Network(crate::flow::NetworkKind),
    All(Vec<Self>),
    AnyOf(Vec<Self>),
    Not(Box<Self>),
}

impl Matcher {
    #[must_use]
    pub fn matches(&self, flow: &FlowContext) -> bool {
        match self {
            Self::Any => true,
            Self::Uid(uid) => flow.source.uid == Some(*uid),
            Self::Package(package) => flow
                .source
                .package
                .as_deref()
                .is_some_and(|value| value == package),
            Self::DomainExact(expected) => match &flow.destination.host {
                DestinationHost::Domain(domain) => domain.eq_ignore_ascii_case(expected),
                DestinationHost::Ip(_) => false,
            },
            Self::DomainSuffix(suffix) => match &flow.destination.host {
                DestinationHost::Domain(domain) => domain_matches_suffix(domain, suffix),
                DestinationHost::Ip(_) => false,
            },
            Self::Ip(expected) => match flow.destination.host {
                DestinationHost::Ip(actual) => actual == *expected,
                DestinationHost::Domain(_) => false,
            },
            Self::Port(port) => flow.destination.port == *port,
            Self::Transport(protocol) => flow.transport == *protocol,
            Self::Network(kind) => flow.network.kind == *kind,
            Self::All(matchers) => matchers.iter().all(|matcher| matcher.matches(flow)),
            Self::AnyOf(matchers) => matchers.iter().any(|matcher| matcher.matches(flow)),
            Self::Not(matcher) => !matcher.matches(flow),
        }
    }
}

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    let domain = domain.trim_end_matches('.');
    let suffix = suffix.trim_matches('.');

    if suffix.is_empty() {
        return false;
    }

    if domain.eq_ignore_ascii_case(suffix) {
        return true;
    }

    let Some(prefix_len) = domain.len().checked_sub(suffix.len() + 1) else {
        return false;
    };

    domain.is_char_boundary(prefix_len)
        && domain.as_bytes().get(prefix_len) == Some(&b'.')
        && domain
            .get(prefix_len + 1..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyAction {
    Route(Endpoint),
    Reject(RejectReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    pub id: RuleId,
    pub tier: PolicyTier,
    pub matcher: Matcher,
    pub action: PolicyAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    pub rule_id: Option<RuleId>,
    pub tier: PolicyTier,
    pub action: PolicyAction,
}

/// Deterministic first-match engine within each authority tier.
#[derive(Clone, Debug)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
    default_action: PolicyAction,
}

impl PolicyEngine {
    #[must_use]
    pub fn new(rules: Vec<PolicyRule>, default_action: PolicyAction) -> Self {
        Self {
            rules,
            default_action,
        }
    }

    #[must_use]
    pub fn decide(&self, flow: &FlowContext) -> PolicyDecision {
        for tier in PolicyTier::PRECEDENCE {
            if let Some(rule) = self
                .rules
                .iter()
                .find(|rule| rule.tier == tier && rule.matcher.matches(flow))
            {
                return PolicyDecision {
                    rule_id: Some(rule.id),
                    tier,
                    action: rule.action.clone(),
                };
            }
        }

        PolicyDecision {
            rule_id: None,
            tier: PolicyTier::Default,
            action: self.default_action.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::flow::{
        Destination, FlowId, NetworkContext, SourceContext, TransportProtocol,
    };

    fn domain_flow(domain: &str, uid: u32) -> FlowContext {
        FlowContext::new(
            FlowId::new(1),
            SourceContext {
                uid: Some(uid),
                package: None,
            },
            Destination {
                host: DestinationHost::Domain(domain.to_owned()),
                port: 443,
            },
            TransportProtocol::Tcp,
            NetworkContext::default(),
        )
    }

    #[test]
    fn suffix_matching_respects_label_boundaries() {
        let matcher = Matcher::DomainSuffix("example.com".to_owned());
        assert!(matcher.matches(&domain_flow("example.com", 1)));
        assert!(matcher.matches(&domain_flow("api.example.com", 1)));
        assert!(!matcher.matches(&domain_flow("badexample.com", 1)));
    }

    #[test]
    fn hard_policy_outranks_adaptive_policy() {
        let engine = PolicyEngine::new(
            vec![
                PolicyRule {
                    id: RuleId::new(1),
                    tier: PolicyTier::Adaptive,
                    matcher: Matcher::Any,
                    action: PolicyAction::Route(Endpoint::Direct),
                },
                PolicyRule {
                    id: RuleId::new(2),
                    tier: PolicyTier::UserHard,
                    matcher: Matcher::Uid(10042),
                    action: PolicyAction::Reject(RejectReason::Policy),
                },
            ],
            PolicyAction::Route(Endpoint::Direct),
        );

        let decision = engine.decide(&domain_flow("example.com", 10042));
        assert_eq!(decision.rule_id, Some(RuleId::new(2)));
        assert_eq!(decision.tier, PolicyTier::UserHard);
        assert_eq!(decision.action, PolicyAction::Reject(RejectReason::Policy));
    }

    #[test]
    fn ip_match_does_not_match_domain_identity() {
        let matcher = Matcher::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!matcher.matches(&domain_flow("one.one.one.one", 1)));
    }
}
