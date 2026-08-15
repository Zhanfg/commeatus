//! `agent-platform`: platform-specific integration layer.
//!
//! Future home of Linux/Android platform support: Root, TProxy, TUN and
//! eBPF / BTF / CO-RE integration.
//!
//! Bootstrap stage: no functionality is implemented yet.
//!
//! ## Safety
//!
//! This crate hosts the future platform/FFI boundary. `unsafe` code is
//! only acceptable here, behind narrowly scoped APIs with documented
//! SAFETY invariants, and never in business logic.

#![forbid(unsafe_code)]
