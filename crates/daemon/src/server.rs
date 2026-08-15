use std::{
    io,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use commeatus_core::Runtime;

use crate::{
    config::{CompiledConfig, ListenerProtocol},
    http_connect, socks5,
};

const ACCEPT_ERROR_RETRY_LIMIT: usize = 8;
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

struct BoundListener {
    protocol: ListenerProtocol,
    listener: TcpListener,
}

pub struct Server {
    listeners: Vec<BoundListener>,
    runtime: Arc<Runtime>,
}

impl Server {
    /// Bind every configured listener before starting any accept loop.
    ///
    /// If one bind fails, already-bound sockets are dropped and no partial
    /// service is started.
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
        })
    }

    pub fn run(self) -> io::Result<()> {
        let (exit_tx, exit_rx) = mpsc::channel();

        for bound in self.listeners {
            let runtime = Arc::clone(&self.runtime);
            let tx = exit_tx.clone();
            let address = bound.listener.local_addr()?;
            thread::spawn(move || {
                let result = serve_forever(bound.listener, bound.protocol, runtime);
                let _ = tx.send((address, result));
            });
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
) -> io::Result<()> {
    let mut consecutive_errors = 0_usize;
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                consecutive_errors = 0;
                spawn_connection(stream, peer, protocol, Arc::clone(&runtime));
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
) {
    thread::spawn(move || {
        if let Err(error) = handle_connection(stream, protocol, runtime) {
            eprintln!("commeatus: connection from {peer} ended with error: {error}");
        }
    });
}

fn handle_connection(
    stream: TcpStream,
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
) -> io::Result<()> {
    match protocol {
        ListenerProtocol::Socks5 => socks5::handle(stream, runtime),
        ListenerProtocol::HttpConnect => http_connect::handle(stream, runtime),
    }
}

#[cfg(test)]
pub(crate) fn spawn_test_listener(
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    connection_count: usize,
) -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let handle = thread::spawn(move || serve_n(listener, protocol, runtime, connection_count));
    Ok((address, handle))
}

#[cfg(test)]
fn serve_n(
    listener: TcpListener,
    protocol: ListenerProtocol,
    runtime: Arc<Runtime>,
    connection_count: usize,
) -> io::Result<()> {
    let mut connections = Vec::with_capacity(connection_count);
    for _ in 0..connection_count {
        let (stream, _) = listener.accept()?;
        let runtime = Arc::clone(&runtime);
        connections.push(thread::spawn(move || {
            handle_connection(stream, protocol, runtime)
        }));
    }

    for connection in connections {
        match connection.join() {
            Ok(Ok(())) | Ok(Err(_)) => {}
            Err(_) => return Err(io::Error::other("test connection handler panicked")),
        }
    }
    Ok(())
}
