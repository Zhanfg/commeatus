#![forbid(unsafe_code)]

pub mod config;
mod datagram;
mod http_connect;
mod outbound;
mod protocol;
mod proxy;
pub mod server;
mod socks5;
mod trojan;
mod trojan_datagram;

pub use config::{CompiledConfig, ConfigError, ConfigStore, ListenerConfig, ListenerProtocol};
pub use server::Server;

#[cfg(test)]
mod e2e;
#[cfg(test)]
mod outbound_e2e;
#[cfg(test)]
mod tls_outbound_e2e;
#[cfg(test)]
mod trojan_outbound_e2e;
#[cfg(test)]
mod trojan_udp_e2e;
