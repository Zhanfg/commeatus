use std::{
    io,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use commeatus_core::Runtime;
use commeatus_dns::DnsEngine;
#[cfg(test)]
use commeatus_dns::HostsTable;

use crate::{
    config::{CompiledConfig, ListenerProtocol},
    http_connect,
    outbound::OutboundRegistry,
    socks5,
};

const ACCEPT_ERROR_RETRY_LIMIT: usize = 8;
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
pub const MAX_ACTIVE_CONNECTIONS: usize = 256;

struct BoundListener {
    protocol: ListenerProtocol,
    listener: TcpListener,
}

struct ConnectionLimiter {
    active: AtomicUsize,
    limit: usize,
}

impl ConnectionLimiter {
    fn new(limit: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            limit,
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        let mut active = self.active.load(Ordering::Relaxed);
        loop {
            if active >= self.limit {
                return None;
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(ConnectionPermit {
                        limiter: Arc::clone(self),
                    });
                }
                Err(current) => active = current,
            }
        }
    }
}

struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::Release);
    }
}

pub struct Server {
    listeners: Vec<BoundListener>,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
    limiter: Arc<ConnectionLimiter>,
}

impl Server {
    pub fn bind(config: &CompiledConfig) -> io::Result<Self> {
        let mut listeners = Vec::with_capacity(config.listeners().len());
        for listener in config.listeners() {
            let socket = TcpListener::bind(listener.address)?;
            listeners.push(BoundListener {
                protocol: listener.protocol,
                listener: socket,
            });
        }
        Ok(Self {
            listeners,
            runtime: Arc::new(config.runtime().clone()),
            dns: Arc::clone(config.dns()),
            outbounds: Arc::clone(config.outbounds()),
            limiter: Arc::new(ConnectionLimiter::new(MAX_ACTIVE_CONNECTIONS)),
        })
    }

    pub fn run(self) -> io::Result<()> {
        let (exit_tx, exit_rx) = mpsc::channel();

        for bound in self.listeners {
            let runtime = Arc::clone(&self.runtime);
            let dns = Arc::clone(&self.dns);
            let outbounds = Arc::clone(&self.outbounds);
            let limiter = Arc::clone(&self.limiter);
            let tx = exit_tx.clone();
            let address = bound.listener.local_addr()?;
            thread::Builder::new()
                .name(format!("commeatus-listener-{address}"))
                .spawn(move || {
                    let result = serve_forever(
                        bound.listener,
                        bound.protocol,
                        runtime,
                        dns,
                        outbounds,
                        limiter,
                    );
                    let _ = tx.send((address, result));
                })?;
        }
        drop(exit_tx);

        match exit_rx.recv() {
            Ok((address, Ok(()))) => Err(io::Error::other(format!(
                "listener {address} exited unexpectedly"
            ))),
            Ok((address, Err(error))) => Err(io::Error::new(
                error.kind(),
                format!("listener {address} failed: {error}"),
            )),
            Err(_) => Err(io::Error::other("all listener supervisors terminated")),
        }
    }
}

fn serve_forever(
    listener: TcpListener,
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
    limiter: Arc<ConnectionLimiter>,
) -> io::Result<()> {
    let mut consecutive_errors = 0_usize;
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                consecutive_errors = 0;
                spawn_connection(
                    stream,
                    peer,
                    protocol,
                    Arc::clone(&runtime),
                    Arc::clone(&dns),
                    Arc::clone(&outbounds),
                    Arc::clone(&limiter),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                consecutive_errors += 1;
                eprintln!(
                    "commeatus: listener accept error ({consecutive_errors}/{ACCEPT_ERROR_RETRY_LIMIT}): {error}"
                );
                if consecutive_errors >= ACCEPT_ERROR_RETRY_LIMIT {
                    return Err(error);
                }
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

fn spawn_connection(
    stream: TcpStream,
    peer: SocketAddr,
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
    limiter: Arc<ConnectionLimiter>,
) {
    let Some(permit) = limiter.try_acquire() else {
        eprintln!(
            "commeatus: connection from {peer} rejected: active connection limit {MAX_ACTIVE_CONNECTIONS} reached"
        );
        drop(stream);
        return;
    };

    if let Err(error) = thread::Builder::new()
        .name("commeatus-session".to_owned())
        .spawn(move || {
            let _permit = permit;
            if let Err(error) = handle_connection(stream, protocol, runtime, dns, outbounds) {
                eprintln!("commeatus: connection from {peer} ended with error: {error}");
            }
        })
    {
        eprintln!(
            "commeatus: connection from {peer} rejected: cannot create handler thread: {error}"
        );
    }
}

fn handle_connection(
    stream: TcpStream,
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
) -> io::Result<()> {
    match protocol {
        ListenerProtocol::Socks5 => socks5::handle(stream, runtime, dns, outbounds),
        ListenerProtocol::HttpConnect => http_connect::handle(stream, runtime, dns, outbounds),
    }
}

#[cfg(test)]
pub(crate) fn spawn_test_listener(
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    connection_count: usize,
) -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    spawn_test_listener_with_runtime(
        protocol,
        runtime,
        Arc::new(DnsEngine::system(HostsTable::default())),
        Arc::new(OutboundRegistry::default()),
        connection_count,
    )
}

#[cfg(test)]
pub(crate) fn spawn_test_listener_with_dns(
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    connection_count: usize,
) -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    spawn_test_listener_with_runtime(
        protocol,
        runtime,
        dns,
        Arc::new(OutboundRegistry::default()),
        connection_count,
    )
}

#[cfg(test)]
pub(crate) fn spawn_test_listener_with_runtime(
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
    connection_count: usize,
) -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let handle = thread::Builder::new()
        .name("commeatus-test-listener".to_owned())
        .spawn(move || {
            serve_n(
                listener,
                protocol,
                runtime,
                dns,
                outbounds,
                connection_count,
            )
        })?;
    Ok((address, handle))
}

#[cfg(test)]
fn serve_n(
    listener: TcpListener,
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    dns: Arc<DnsEngine>,
    outbounds: Arc<OutboundRegistry>,
    connection_count: usize,
) -> io::Result<()> {
    let mut connections = Vec::with_capacity(connection_count);
    for _ in 0..connection_count {
        let (stream, _) = listener.accept()?;
        let runtime = Arc::clone(&runtime);
        let dns = Arc::clone(&dns);
        let outbounds = Arc::clone(&outbounds);
        connections.push(
            thread::Builder::new()
                .name("commeatus-test-session".to_owned())
                .spawn(move || handle_connection(stream, protocol, runtime, dns, outbounds))?,
        );
    }

    for connection in connections {
        match connection.join() {
            Ok(Ok(())) | Ok(Err(_)) => {}
            Err(_) => return Err(io::Error::other("test connection handler panicked")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_limiter_never_exceeds_limit_and_releases_permits() {
        let limiter = Arc::new(ConnectionLimiter::new(2));
        let first = limiter.try_acquire().unwrap();
        let second = limiter.try_acquire().unwrap();
        assert!(limiter.try_acquire().is_none());
        drop(first);
        let third = limiter.try_acquire().unwrap();
        assert!(limiter.try_acquire().is_none());
        drop(second);
        drop(third);
        assert_eq!(limiter.active.load(Ordering::Relaxed), 0);
    }
}
