from pathlib import Path

path = Path("scripts/v06_dns_answer_migrate.py")
text = path.read_text()
old = '''if "Result<Vec<IpAddr>, DnsError>" in final:
    raise SystemExit("legacy Resolver result type remains in dns lib")
'''
new = '''legacy_trait = "fn resolve(&self, query: &DnsQuery) -> Result<Vec<IpAddr>, DnsError>;"
if legacy_trait in final:
    raise SystemExit("legacy Resolver trait result type remains in dns lib")
engine_api = "pub fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, DnsError>"
if engine_api not in final:
    raise SystemExit("DnsEngine public address-list API changed unexpectedly")
'''
if text.count(old) != 1:
    raise SystemExit("typed resolver final assertion changed unexpectedly")
path.write_text(text.replace(old, new, 1))
