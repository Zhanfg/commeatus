//! Native runtime core of Commeatus.
//!
//! V0.3 keeps a flow-centric policy pipeline while allowing execution plans to
//! refer to opaque proxy endpoint identities. Compatibility formats, protocol
//! implementations and platform-specific objects terminate at their boundaries
//! before data enters these types.
//!
//! ## Safety
//!
//! Business code in this crate is safe-only. `unsafe` belongs strictly at
//! audited platform/FFI boundaries outside this crate.

#![forbid(unsafe_code)]

pub mod cidr;
pub mod domain_set;
pub mod flow;
pub mod plan;
pub mod policy;
pub mod runtime;

pub use cidr::{CidrParseError, IpCidr};
pub use domain_set::{DomainFilter, DomainSet, DomainSetError, MAX_DOMAIN_LENGTH};
pub use flow::{
    Destination, DestinationHost, FlowContext, FlowId, NetworkContext, NetworkKind, SourceContext,
    TransportProtocol,
};
pub use plan::{
    Endpoint, EndpointId, EndpointIdError, ExecutionAction, ExecutionPlan, MAX_ENDPOINT_ID_LENGTH,
    RejectReason,
};
pub use policy::{
    Matcher, PolicyAction, PolicyDecision, PolicyEngine, PolicyRule, PolicyTier, RuleId,
};
pub use runtime::Runtime;
