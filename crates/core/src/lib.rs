//! Native runtime core of Commeatus.
//!
//! V0.1 establishes a flow-centric policy pipeline. Compatibility formats and
//! platform-specific objects must terminate at their boundaries before data
//! enters these types.
//!
//! ## Safety
//!
//! Business code in this crate is safe-only. `unsafe` belongs strictly at
//! audited platform/FFI boundaries outside this crate.

#![forbid(unsafe_code)]

pub mod flow;
pub mod plan;
pub mod policy;
pub mod runtime;

pub use flow::{
    Destination, DestinationHost, FlowContext, FlowId, NetworkContext, NetworkKind, SourceContext,
    TransportProtocol,
};
pub use plan::{Endpoint, ExecutionAction, ExecutionPlan, RejectReason};
pub use policy::{
    Matcher, PolicyAction, PolicyDecision, PolicyEngine, PolicyRule, PolicyTier, RuleId,
};
pub use runtime::Runtime;
