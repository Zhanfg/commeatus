use std::{
    io::{self, Read, Write},
    net::{IpAddr, TcpStream},
    sync::Arc,
};

use commeatus_core::{DestinationHost, Runtime};

use crate::proxy::{self, Authorization, Target};

const MAX_HEADER_BYTES: usize = 16 * 1024;

pub fn handle(mut client: TcpStream, runtime: Arc<Runtime>) -> io::Result<()> {
    let (target, buffered_tunnel_bytes) = match read_request(&mut client) {
        Ok(request) => request,
        Err(error) => {
            let _ = client.write_all(
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            );
            return Err(error);
        }
    };

    if proxy::authorize(&runtime, &target) == Authorization::Reject {
        client.write_all(
            b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        )?;
        return Ok(());
    }

    let mut remote = match proxy::connect_direct(&target) {
        Ok(remote) => remote,
        Err(error) => {
            let _ = client.write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            );
            return Err(error);
        }
    };

    client.write_all(
        b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: Commeatus/0.1.0-alpha.1\r\n\r\n",
    )?;
    if !buffered_tunnel_bytes.is_empty() {
        remote.write_all(&buffered_tunnel_bytes)?;
    }
    proxy::relay(client, remote)
}

fn read_request(stream: &mut TcpStream) -> io::Result<(Target, Vec<u8>)> {
    let mut buffer = Vec::with_capacity(1024);
    let header_end = loop {
        if let Some(end) = find_header_end(&buffer) {
            break end;
        }
        if buffer.len() >= MAX_HEADER_BYTES {
            return Err(invalid_data("HTTP CONNECT header is too large"));
        }

        let remaining = MAX_HEADER_BYTES - buffer.len();
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk[..remaining.min(chunk.len())])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP CONNECT client closed before headers completed",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let header = std::str::from_utf8(&buffer[..header_end])
        .map_err(|_| invalid_data("HTTP CONNECT headers are not UTF-8"))?;
    let request_line = header
        .split("\r\n")
        .next()
        .ok_or_else(|| invalid_data("missing HTTP request line"))?;
    let mut fields = request_line.split_whitespace();
    let method = fields
        .next()
        .ok_or_else(|| invalid_data("missing HTTP method"))?;
    let authority = fields
        .next()
        .ok_or_else(|| invalid_data("missing CONNECT authority"))?;
    let version = fields
        .next()
        .ok_or_else(|| invalid_data("missing HTTP version"))?;
    if fields.next().is_some() || method != "CONNECT" || !version.starts_with("HTTP/1.") {
        return Err(invalid_data("only HTTP/1.x CONNECT is supported"));
    }

    let target = parse_authority(authority)?;
    Ok((target, buffer[header_end + 4..].to_vec()))
}

fn parse_authority(authority: &str) -> io::Result<Target> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| invalid_data("invalid bracketed IPv6 authority"))?;
        let host = &rest[..close];
        let port = rest[close + 1..]
            .strip_prefix(':')
            .ok_or_else(|| invalid_data("missing CONNECT port"))?;
        if port.contains(':') {
            return Err(invalid_data("invalid CONNECT port"));
        }
        let address: IpAddr = host
            .parse()
            .map_err(|_| invalid_data("invalid IPv6 CONNECT address"))?;
        if !address.is_ipv6() {
            return Err(invalid_data("bracketed CONNECT address must be IPv6"));
        }
        return Target::new(DestinationHost::Ip(address), parse_port(port)?);
    }

    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| invalid_data("CONNECT authority must include a port"))?;
    if host.is_empty() || host.contains(':') {
        return Err(invalid_data("invalid CONNECT host"));
    }

    let destination = if let Ok(address) = host.parse::<IpAddr>() {
        DestinationHost::Ip(address)
    } else {
        let domain = host.trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() || domain.len() > 253 {
            return Err(invalid_data("invalid CONNECT domain"));
        }
        DestinationHost::Domain(domain)
    };
    Target::new(destination, parse_port(port)?)
}

fn parse_port(value: &str) -> io::Result<u16> {
    value
        .parse::<u16>()
        .map_err(|_| invalid_data("invalid CONNECT port"))
        .and_then(|port| {
            if port == 0 {
                Err(invalid_data("CONNECT port must not be zero"))
            } else {
                Ok(port)
            }
        })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_domain_authority() {
        let target = parse_authority("Example.COM:443").unwrap();
        assert_eq!(
            target,
            Target::new(DestinationHost::Domain("example.com".to_owned()), 443).unwrap()
        );
    }

    #[test]
    fn parses_bracketed_ipv6_authority() {
        let target = parse_authority("[2001:db8::1]:8443").unwrap();
        assert_eq!(target.port, 8443);
        assert!(matches!(target.host, DestinationHost::Ip(address) if address.is_ipv6()));
    }

    #[test]
    fn rejects_ambiguous_unbracketed_ipv6() {
        assert!(parse_authority("2001:db8::1:443").is_err());
    }
}
