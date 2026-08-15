use std::{env, fs, path::Path, process};

use commeatus::{config, Server};

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
        Some("check") => {
            let path = parse_config_argument(&args[1..])?;
            let text = read_config(path)?;
            let compiled = config::parse_config(&text).map_err(|error| error.to_string())?;
            println!(
                "configuration valid: {} listener(s)",
                compiled.listeners().len()
            );
            Ok(())
        }
        Some("run") => {
            let path = parse_config_argument(&args[1..])?;
            let text = read_config(path)?;
            let compiled = config::parse_config(&text).map_err(|error| error.to_string())?;
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

fn print_usage() {
    eprintln!(
        "Commeatus {VERSION}\n\nUsage:\n  commeatus run --config <path>\n  commeatus check --config <path>\n  commeatus version\n"
    );
}
