use crate::{
    flow::FlowContext,
    plan::{ExecutionAction, ExecutionPlan},
    policy::{PolicyAction, PolicyEngine},
};

/// Minimal V0.1 runtime boundary: canonical flow in, immutable execution plan out.
///
/// Network I/O is intentionally not performed here yet. Platform and transport
/// executors will consume the plan in later slices without gaining policy
/// authority themselves.
#[derive(Clone, Debug)]
pub struct Runtime {
    policy: PolicyEngine,
}

impl Runtime {
    #[must_use]
    pub fn new(policy: PolicyEngine) -> Self {
        Self { policy }
    }

    #[must_use]
    pub fn plan(&self, flow: &FlowContext) -> ExecutionPlan {
        let decision = self.policy.decide(flow);
        let action = match decision.action {
            PolicyAction::Route(endpoint) => ExecutionAction::Route { endpoint },
            PolicyAction::Reject(reason) => ExecutionAction::Reject { reason },
        };

        ExecutionPlan {
            flow_id: flow.id,
            action,
            matched_rule: decision.rule_id,
            tier: decision.tier,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        flow::{
            Destination, DestinationHost, FlowId, NetworkContext, SourceContext,
            TransportProtocol,
        },
        plan::{Endpoint, RejectReason},
        policy::{Matcher, PolicyAction, PolicyRule, PolicyTier, RuleId},
    };

    fn flow(uid: u32) -> FlowContext {
        FlowContext::new(
            FlowId::new(7),
            SourceContext {
                uid: Some(uid),
                package: Some("org.example.app".to_owned()),
            },
            Destination {
                host: DestinationHost::Domain("example.com".to_owned()),
                port: 443,
            },
            TransportProtocol::Tcp,
            NetworkContext::default(),
        )
    }

    #[test]
    fn default_direct_becomes_route_plan() {
        let runtime = Runtime::new(PolicyEngine::new(
            Vec::new(),
            PolicyAction::Route(Endpoint::Direct),
        ));
        let plan = runtime.plan(&flow(10001));

        assert_eq!(plan.flow_id, FlowId::new(7));
        assert_eq!(plan.matched_rule, None);
        assert_eq!(
            plan.action,
            ExecutionAction::Route {
                endpoint: Endpoint::Direct
            }
        );
    }

    #[test]
    fn reject_remains_an_action_not_an_endpoint() {
        let runtime = Runtime::new(PolicyEngine::new(
            vec![PolicyRule {
                id: RuleId::new(9),
                tier: PolicyTier::UserHard,
                matcher: Matcher::Uid(10001),
                action: PolicyAction::Reject(RejectReason::Policy),
            }],
            PolicyAction::Route(Endpoint::Direct),
        ));
        let plan = runtime.plan(&flow(10001));

        assert_eq!(plan.matched_rule, Some(RuleId::new(9)));
        assert_eq!(
            plan.action,
            ExecutionAction::Reject {
                reason: RejectReason::Policy
            }
        );
    }
}
