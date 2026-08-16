use std::{fmt, hash::Hash};

use crate::{
    flow::FlowId,
    policy::{PolicyTier, RuleId},
};

pub const MAX_ENDPOINT_ID_LENGTH: usize = 64;

/// Stable native identity for an execution endpoint.
///
/// The core intentionally knows only the identity, not whether the endpoint is
/// SOCKS5, HTTP CONNECT, VLESS, Trojan, QUIC, or another future implementation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EndpointId(String);

impl EndpointId {
    pub fn new(value: impl Into<String>) -> Result<Self, EndpointIdError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_ENDPOINT_ID_LENGTH
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(EndpointIdError);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointIdError;

impl fmt::Display for EndpointIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "endpoint id must be 1..={MAX_ENDPOINT_ID_LENGTH} ASCII alphanumeric/._- characters"
        )
    }
}

impl std::error::Error for EndpointIdError {}

/// A concrete egress target. Actions are deliberately not represented here.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Endpoint {
    Direct,
    Proxy(EndpointId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectReason {
    Policy,
    Security,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionAction {
    Route { endpoint: Endpoint },
    Reject { reason: RejectReason },
}

/// Immutable result of policy evaluation for one flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionPlan {
    pub flow_id: FlowId,
    pub action: ExecutionAction,
    pub matched_rule: Option<RuleId>,
    pub tier: PolicyTier,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_id_rejects_config_like_or_unbounded_values() {
        assert!(EndpointId::new("edge-jp_01").is_ok());
        assert!(EndpointId::new("").is_err());
        assert!(EndpointId::new("socks5://127.0.0.1:1080").is_err());
        assert!(EndpointId::new("x".repeat(MAX_ENDPOINT_ID_LENGTH + 1)).is_err());
    }
}
