from pathlib import Path

path = Path("scripts/v06_dns_config_migrate.py")
text = path.read_text()
needle = '''replace_once(
    str(path),
    ''' + "'''" + '''    let mut hosts = Vec::new();
    let mut hosts_paths = HashSet::new();
    let mut hosts_table = HostsTable::default();
    let mut endpoint_configs = Vec::new();
''' + "'''" + ''',
    ''' + "'''" + '''    let mut hosts = Vec::new();
    let mut hosts_paths = HashSet::new();
    let mut hosts_table = HostsTable::default();
    let mut dns_resolver_summaries = Vec::new();
    let mut dns_resolvers: Vec<Arc<dyn Resolver>> = Vec::new();
    let mut dns_resolver_keys = HashSet::new();
    let mut endpoint_configs = Vec::new();
''' + "'''" + ''',
)

resolver_arm = ''' + "'''"
replacement = needle.replace(")\n\nresolver_arm = '''", ")\n\n# The preceding replace_once() calls mutate config.rs on disk. Refresh the\n# in-memory source before applying the remaining resolver arm/final/test edits,\n# otherwise the stale snapshot would overwrite those staged changes.\ntext = path.read_text()\n\nresolver_arm = '''")
if text.count(needle) != 1:
    raise SystemExit("DNS config migration refresh insertion point changed unexpectedly")
path.write_text(text.replace(needle, replacement, 1))
