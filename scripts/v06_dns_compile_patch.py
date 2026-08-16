from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match in {path}, found {count}: {old!r}")
    p.write_text(text.replace(old, new, 1))


replace_once(
    "crates/dns/src/lib.rs",
    "impl Resolver for SystemResolver {\n    fn resolve(&self, query: &DnsQuery) -> Result<Vec<IpAddr>, DnsError> {",
    "impl Resolver for SystemResolver {\n    fn resolve(&self, query: &DnsQuery) -> Result<DnsAnswer, DnsError> {",
)

replace_once(
    "crates/dns/src/dot.rs",
    "        net::{Ipv4Addr, TcpStream},",
    "        net::{IpAddr, Ipv4Addr, TcpStream},",
)

lib = Path("crates/dns/src/lib.rs").read_text()
if "impl Resolver for SystemResolver {\n    fn resolve(&self, query: &DnsQuery) -> Result<DnsAnswer, DnsError> {" not in lib:
    raise SystemExit("SystemResolver typed-answer signature was not applied")
if lib.count("pub fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, DnsError>") != 1:
    raise SystemExit("DnsEngine public address-list API was not preserved exactly once")
