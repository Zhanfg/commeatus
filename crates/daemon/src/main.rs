use std::{env, fs, path::Path, process};

use commeatus::{Server, config};
use commeatus_platform::{PlatformCapabilities, PlatformKind, SupportLevel};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    if let Err(error) = run_cli() {
        eprintln!("commeatus: {error}");
        process::exit(1);
    }
}

fn run_cli() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("version") if args.len() == 1 => {
            println!("commeatus {VERSION}");
            Ok(())
        }
        Some("platform") if args.len() == 1 => {
            print_platform(&PlatformCapabilities::probe());
            Ok(())
        }
        Some("check") => {
            let path = parse_config_argument(&args[1..])?;
            let text = read_config(path)?;
            let compiled = config::parse_config_at(&text, config_root(path))
                .map_err(|error| error.to_string())?;
            let block_entries: usize = compiled
                .blocklists()
                .iter()
                .map(|list| list.stats.accepted_block + list.stats.accepted_allow)
                .sum();
            println!(
                "configuration valid: {} listener(s), {} blocklist(s), {} compiled blocklist entry/entries",
                compiled.listeners().len(),
                compiled.blocklists().len(),
                block_entries
            );
            Ok(())
        }
        Some("run") => {
            let path = parse_config_argument(&args[1..])?;
            let text = read_config(path)?;
            let compiled = config::parse_config_at(&text, config_root(path))
                .map_err(|error| error.to_string())?;
            for blocklist in compiled.blocklists() {
                eprintln!(
                    "commeatus: blocklist {} compiled: {} block, {} allow, {} ignored line(s)",
                    blocklist.path.display(),
                    blocklist.stats.accepted_block,
                    blocklist.stats.accepted_allow,
                    blocklist.stats.ignored
                );
            }
            for listener in compiled.listeners() {
                eprintln!(
                    "commeatus: listening {:?} on {}",
                    listener.protocol, listener.address
                );
            }
            let server = Server::bind(&compiled).map_err(|error| error.to_string())?;
            server.run().map_err(|error| error.to_string())
        }
        Some("help") | Some("--help") | Some("-h") => {
            print_usage();
            Ok(())
        }
        _ => {
            print_usage();
            Err("invalid command line".to_owned())
        }
    }
}

fn parse_config_argument(args: &[String]) -> Result<&Path, String> {
    if args.len() != 2 || args[0] != "--config" {
        return Err("expected `--config <path>`".to_owned());
    }
    Ok(Path::new(&args[1]))
}

fn config_root(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn read_config(path: &Path) -> Result<String, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot stat config {}: {error}", path.display()))?;
    if metadata.len() > config::MAX_CONFIG_BYTES as u64 {
        return Err(format!(
            "config {} exceeds {} byte limit",
            path.display(),
            config::MAX_CONFIG_BYTES
        ));
    }
    fs::read_to_string(path)
        .map_err(|error| format!("cannot read config {}: {error}", path.display()))
}

fn print_platform(capabilities: &PlatformCapabilities) {
    println!("platform={}", platform_name(capabilities.platform));
    println!("tun={}", support_name(capabilities.tun));
    println!("tproxy={}", support_name(capabilities.tproxy));
    println!("ebpf={}", support_name(capabilities.ebpf));
    println!("btf={}", support_name(capabilities.btf));
    println!("bpffs={}", support_name(capabilities.bpffs));
}

const fn platform_name(platform: PlatformKind) -> &'static str {
    match platform {
        PlatformKind::Android => "android",
        PlatformKind::Linux => "linux",
        PlatformKind::Other => "other",
    }
}

const fn support_name(support: SupportLevel) -> &'static str {
    match support {
        SupportLevel::Available => "available",
        SupportLevel::Unavailable => "unavailable",
        SupportLevel::Unknown => "unknown",
    }
}

fn print_usage() {
    eprintln!(
        "Commeatus {VERSION}\n\nUsage:\n  commeatus run --config <path>\n  commeatus check --config <path>\n  commeatus platform\n  commeatus version\n"
    );
}
