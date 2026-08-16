use std::{
    collections::VecDeque,
    fmt, io,
    sync::Arc,
};

use commeatus_transport::{TlsFramedSession, TlsTransport};
use mio::{Registry, Token};

use crate::{
    datagram::{
        DatagramAssociation, DatagramExecution, DatagramProviderRef, OutboundDatagramProvider,
        ReceivedDatagram,
    },
    proxy::Target,
    trojan::{TrojanVerifier, encode_udp_associate_request, encode_udp_frame, parse_udp_frame},
};

const MAX_PENDING_FRAMES: usize = 64;
const MAX_PENDING_BYTES: usize = 512 * 1024;
const MAX_RX_BYTES: usize = 128 * 1024;
const TLS_PLAINTEXT_READ_CHUNK: usize = 16 * 1024;

#[derive(Clone)]
pub struct TrojanDatagramProvider {
    verifier: TrojanVerifier,
    transport: TlsTransport,
}

impl TrojanDatagramProvider {
    #[must_use]
    pub fn new(verifier: TrojanVerifier, transport: TlsTransport) -> Self {
        Self {
            verifier,
            transport,
        }
    }

    #[must_use]
    pub fn into_ref(self) -> DatagramProviderRef {
        Arc::new(self)
    }
}

impl fmt::Debug for TrojanDatagramProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrojanDatagramProvider")
            .field("verifier", &self.verifier)
            .field("transport", &self.transport)
            .finish()
    }
}

impl OutboundDatagramProvider for TrojanDatagramProvider {
    fn open(&self) -> io::Result<Box<dyn DatagramExecution>> {
        let tls = self.transport.connect_framed()?;
        let mut execution = TrojanDatagramExecution {
            tls,
            pending: VecDeque::new(),
            pending_bytes: 0,
            rx: Vec::new(),
            registry: None,
            token: None,
        };
        execution.enqueue(encode_udp_associate_request(&self.verifier))?;
        execution.drain_pending()?;
        Ok(Box::new(execution))
    }
}

struct PendingFrame {
    bytes: Vec<u8>,
    offset: usize,
}

pub struct TrojanDatagramExecution {
    tls: TlsFramedSession,
    pending: VecDeque<PendingFrame>,
    pending_bytes: usize,
    rx: Vec<u8>,
    registry: Option<Registry>,
    token: Option<Token>,
}

impl TrojanDatagramExecution {
    fn enqueue(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        if self.pending.len() >= MAX_PENDING_FRAMES {
            return Err(io::Error::new(
                io::ErrorKind::QuotaExceeded,
                format!("Trojan UDP pending frame limit {MAX_PENDING_FRAMES} reached"),
            ));
        }
        let next = self.pending_bytes.checked_add(bytes.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::OutOfMemory, "Trojan UDP pending byte count overflow")
        })?;
        if next > MAX_PENDING_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::QuotaExceeded,
                format!("Trojan UDP pending byte limit {MAX_PENDING_BYTES} reached"),
            ));
        }
        self.pending_bytes = next;
        self.pending.push_back(PendingFrame { bytes, offset: 0 });
        Ok(())
    }

    fn drain_pending(&mut self) -> io::Result<()> {
        loop {
            let Some(frame) = self.pending.front_mut() else {
                return Ok(());
            };
            let remaining = &frame.bytes[frame.offset..];
            if remaining.is_empty() {
                self.pending.pop_front();
                continue;
            }
            match self.tls.write_plaintext(remaining) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "framed TLS accepted zero Trojan UDP plaintext bytes",
                    ));
                }
                Ok(written) => {
                    frame.offset += written;
                    self.pending_bytes = self.pending_bytes.saturating_sub(written);
                    if frame.offset == frame.bytes.len() {
                        self.pending.pop_front();
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn refresh_readiness(&mut self) -> io::Result<()> {
        match (&self.registry, self.token) {
            (Some(registry), Some(token)) => self.tls.refresh_readiness(registry, token),
            (None, None) => Ok(()),
            _ => Err(io::Error::other(
                "Trojan UDP readiness registration state is inconsistent",
            )),
        }
    }

    fn service_ready(&mut self) -> io::Result<()> {
        self.drain_pending()?;
        self.tls.service_io()?;
        self.drain_pending()?;
        self.read_plaintext_into_rx()?;
        self.refresh_readiness()
    }

    fn read_plaintext_into_rx(&mut self) -> io::Result<()> {
        loop {
            if self.rx.len() >= MAX_RX_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Trojan UDP receive buffer exceeds {MAX_RX_BYTES} bytes"),
                ));
            }
            let remaining = MAX_RX_BYTES - self.rx.len();
            let mut buffer = [0_u8; TLS_PLAINTEXT_READ_CHUNK];
            let limit = remaining.min(buffer.len());
            match self.tls.read_plaintext(&mut buffer[..limit]) {
                Ok(0) => return Ok(()),
                Ok(read) => self.rx.extend_from_slice(&buffer[..read]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn take_frame(&mut self, output: &mut [u8]) -> io::Result<Option<ReceivedDatagram>> {
        let Some(frame) = parse_udp_frame(&self.rx)? else {
            return Ok(None);
        };
        let payload_len = frame.payload.len();
        if output.len() < payload_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Trojan UDP output buffer is {} bytes but frame payload requires {payload_len}",
                    output.len()
                ),
            ));
        }
        output[..payload_len].copy_from_slice(&self.rx[frame.payload.clone()]);
        let source = frame.source;
        let consumed = frame.consumed;
        self.rx.copy_within(consumed.., 0);
        self.rx.truncate(self.rx.len() - consumed);
        Ok(Some(ReceivedDatagram {
            source,
            length: payload_len,
        }))
    }
}

impl DatagramAssociation for TrojanDatagramExecution {
    fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        self.enqueue(encode_udp_frame(target, payload)?)?;
        self.drain_pending()?;
        self.refresh_readiness()
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<ReceivedDatagram>> {
        if let Some(frame) = self.take_frame(buffer)? {
            return Ok(Some(frame));
        }

        self.service_ready()?;
        if let Some(frame) = self.take_frame(buffer)? {
            return Ok(Some(frame));
        }

        if self.tls.remote_eof() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Trojan UDP TLS carrier closed without another complete frame",
            ));
        }
        Ok(None)
    }
}

impl DatagramExecution for TrojanDatagramExecution {
    fn readiness_source_count(&self) -> usize {
        1
    }

    fn register_readiness(&mut self, registry: &Registry, tokens: &[Token]) -> io::Result<()> {
        if tokens.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Trojan UDP execution requires exactly one readiness token, got {}",
                    tokens.len()
                ),
            ));
        }
        if self.registry.is_some() || self.token.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Trojan UDP execution is already registered",
            ));
        }
        let cloned = registry.try_clone()?;
        self.tls.register_readiness(registry, tokens[0])?;
        self.registry = Some(cloned);
        self.token = Some(tokens[0]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_debug_does_not_expose_verifier_bytes() {
        // Construction of TlsTransport requires a valid server name but does
        // not connect until `open()`, so this test is network-free.
        let verifier = TrojanVerifier::new("super-secret").unwrap();
        let transport = TlsTransport::webpki("127.0.0.1:443".parse().unwrap(), "proxy.test").unwrap();
        let debug = format!("{:?}", TrojanDatagramProvider::new(verifier.clone(), transport));
        let verifier_text = std::str::from_utf8(verifier.as_bytes()).unwrap();
        assert!(!debug.contains(verifier_text));
        assert!(debug.contains("[REDACTED]"));
    }
}
