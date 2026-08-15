//! `agent-compat`: compatibility boundary with existing proxy ecosystems.
//!
//! Future home of translation layers for mihomo, sing-box, Clash API and
//! subscription formats.
//!
//! ## Boundary rule
//!
//! Compatibility formats terminate at this crate's boundary. They are
//! translated into the project's native typed representation and must
//! never become the core's internal data model.
//!
//! Bootstrap stage: no functionality is implemented yet.

#![forbid(unsafe_code)]
