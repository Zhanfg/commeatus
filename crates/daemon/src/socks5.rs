use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    sync::Arc,
};

use commeatus_core::{DestinationHost, Runtime};

use crate::proxy::{self, Authorization, Target};

const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_UNACCEPTABLE: u8 = 0xff;
const COMMAND_CONNECT: u8 = 0x01;

pub fn handle(mut client: TcpStream, runtime: Arc<Runtime>) -> io::Result<()> {
    negotiate_method(&mut client)?;
    let target = read_connect_request(&mut client)?;

    if proxy::authorize(&runtime, &target) == Authorization::Reject {
        write_reply(&mut client, 0x02, None)?;
        return Ok(());
    }

    let remote = match proxy::connect_direct(&target) {
        Ok(remote) => remote,
        Err(error) => {
            let code = connect_error_code(&error);
            let _ = write_reply(&mut client, code, None);
            return Err(error);
        }
    };

    write_reply(&mut client, 0x00, remote.local_addr().ok())?;
    proxy::relay(client, remote)
}

fn negotiate_method(stream: &mut TcpStream) -> io::Result<()> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header)?;
    if header[0] != VERSION || header[1] == 0 {
        return Err(invalid_data("invalid SOCKS5 greeting"));
    }

    let mut methods = vec![0_u8; usize::from(header[1])];
    stream.read_exact(&mut methods)?;
    if methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[VERSION, METHOD_NO_AUTH])?;
        Ok(())
    } else {
        stream.write_all(&[VERSION, METHOD_UNACCEPTABLE])?;
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 client did not offer no-auth method",
        ))
    }
}

fn read_connect_request(stream: &mut TcpStream) -> io::Result<Target> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != VERSION || header[2] != 0 {
        return Err(invalid_data("invalid SOCKS5 request header"));
    }
    if header[1] != COMMAND_CONNECT {
        write_reply(stream, 0x07, None)?;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SOCKS5 command is not CONNECT",
        ));
    }

    let host = match header[3] {
        0x01 => {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes)?;
            DestinationHost::Ip(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        0x03 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length)?;
            let length = usize::from(length[0]);
            if length == 0 || length > 253 {
                write_reply(stream, 0x08, None)?;
                return Err(invalid_data("invalid SOCKS5 domain length"));
            }
            let mut bytes = vec![0_u8; length];
            stream.read_exact(&mut bytes)?;
            let domain = std::str::from_utf8(&bytes)
                .map_err(|_| invalid_data("SOCKS5 domain is not UTF-8"))?
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if domain.is_empty() {
                return Err(invalid_data("empty SOCKS5 domain"));
            }
            DestinationHost::Domain(domain)
        }
        0x04 => {
            let mut bytes = [0_u8; 16];
            stream.read_exact(&mut bytes)?;
            DestinationHost::Ip(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => {
            write_reply(stream, 0x08, None)?;
            return Err(invalid_data("unsupported SOCKS5 address type"));
        }
    };

    let mut port = [0_u8; 2];
    stream.read_exact(&mut port)?;
    Target::new(host, u16::from_be_bytes(port))
}

fn write_reply(stream: &mut TcpStream, code: u8, address: Option<SocketAddr>) -> io::Result<()> {
    match address.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))) {
        SocketAddr::V4(address) => {
            let mut reply = Vec::with_capacity(10);
            reply.extend_from_slice(&[VERSION, code, 0x00, 0x01]);
            reply.extend_from_slice(&address.ip().octets());
            reply.extend_from_slice(&address.port().to_be_bytes());
            stream.write_all(&reply)
        }
        SocketAddr::V6(address) => {
            let mut reply = Vec::with_capacity(22);
            reply.extend_from_slice(&[VERSION, code, 0x00, 0x04]);
            reply.extend_from_slice(&address.ip().octets());
            reply.extend_from_slice(&address.port().to_be_bytes());
            stream.write_all(&reply)
        }
    }
}

fn connect_error_code(error: &io::Error) -> u8 {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => 0x05,
        io::ErrorKind::TimedOut => 0x04,
        io::ErrorKind::PermissionDenied => 0x02,
        io::ErrorKind::NotFound | io::ErrorKind::AddrNotAvailable => 0x04,
        _ => 0x01,
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
