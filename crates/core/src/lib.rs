//! `agent-core`: the native runtime core of the proxy engine.
//!
//! Future home of the project's internal data model and runtime:
//! Flow, Policy, Routing, ExecutionPlan, Runtime, DNS, Protocol and
//! Adaptive logic.
//!
//! Bootstrap stage: no functionality is implemented yet.
//!
//! ## Safety
//!
//! Business code in this crate must stay `safe`-only. `unsafe` code, when
//! it becomes necessary, belongs strictly at the platform/FFI boundary.

#![forbid(unsafe_code)]
