#![forbid(unsafe_code)]

pub mod config;
mod http_connect;
mod outbound;
mod proxy;
pub mod server;
mod socks5;

pub use config::{CompiledConfig, ConfigError, ConfigStore, ListenerConfig, ListenerProtocol};
pub use server::Server;

#[cfg(test)]
mod e2e;
#[cfg(test)]
mod outbound_e2e;
#[cfg(test)]
mod tls_outbound_e2e;
