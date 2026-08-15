use crate::{flow::FlowId, policy::{PolicyTier, RuleId}};

/// A concrete egress target. Actions are deliberately not represented here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Endpoint {
    Direct,
}

/// Why a flow was rejected. This remains an action outcome, not an endpoint.
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
