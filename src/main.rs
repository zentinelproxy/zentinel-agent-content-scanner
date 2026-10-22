//! Content Scanner agent CLI.
//!
//! Scans uploaded files for malware using ClamAV daemon.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::{Path, PathBuf};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use zentinel_agent_content_scanner::{Config, ContentScannerAgent};
use zentinel_agent_protocol::v2::{GrpcAgentServerV2, UdsAgentServerV2};

/// The configuration file read when `--config` is not given (if it exists).
const DEFAULT_CONFIG: &str = "config.yaml";

/// Content Scanner agent for Zentinel - malware scanning with ClamAV.
#[derive(Parser, Debug)]
#[command(name = "zentinel-content-scanner-agent")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file. Without this flag the agent reads
    /// `config.yaml` from the working directory if it exists and otherwise
    /// starts with the built-in defaults.
    #[arg(short, long, env = "CONTENT_SCANNER_CONFIG")]
    config: Option<PathBuf>,

    /// Unix socket to listen on (agent protocol v2 over UDS). Used unless
    /// `--grpc-address` is given.
    #[arg(
        short,
        long,
        default_value = "/tmp/zentinel-content-scanner.sock",
        env = "AGENT_SOCKET"
    )]
    socket: PathBuf,

    /// gRPC address to listen on (e.g. "127.0.0.1:50051"). When given, the
    /// agent serves agent protocol v2 over gRPC instead of the Unix socket.
    #[arg(short, long, env = "CONTENT_SCANNER_GRPC_ADDRESS")]
    grpc_address: Option<String>,

    /// Path to the clamd Unix socket. Overrides `clamd.socket_path` from the
    /// configuration file.
    #[arg(long, env = "CLAMD_SOCKET")]
    clamd_socket: Option<PathBuf>,

    /// Print example configuration and exit.
    #[arg(long)]
    example_config: bool,

    /// Validate configuration and exit.
    #[arg(long)]
    validate: bool,
}

/// Load the configuration the agent starts with.
///
/// An explicit `--config` must exist. Without it, `config.yaml` is used when
/// present and the built-in defaults otherwise.
fn load_config(args: &Args) -> Result<Config> {
    let mut config = match &args.config {
        Some(path) => Config::load(path)
            .with_context(|| format!("Failed to load configuration from {}", path.display()))?,
        None if Path::new(DEFAULT_CONFIG).exists() => Config::load(Path::new(DEFAULT_CONFIG))
            .with_context(|| format!("Failed to load configuration from {DEFAULT_CONFIG}"))?,
        None => Config::default(),
    };
    if let Some(socket) = &args.clamd_socket {
        config.clamd.socket_path = socket.clone();
    }
    config.validate()?;
    Ok(config)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    // Print example config if requested
    if args.example_config {
        println!("{}", Config::example());
        return Ok(());
    }

    let config = load_config(&args)?;

    // Validate only if requested
    if args.validate {
        info!("Configuration is valid");
        return Ok(());
    }

    info!(
        version = env!("CARGO_PKG_VERSION"),
        clamd_socket = %config.clamd.socket_path.display(),
        fail_action = ?config.settings.fail_action,
        "Starting Content Scanner agent"
    );

    let agent = ContentScannerAgent::new(config);

    if let Some(grpc_addr) = args.grpc_address {
        let addr = grpc_addr
            .parse()
            .context("Invalid gRPC address format (expected host:port)")?;
        info!(grpc_address = %grpc_addr, "Listening on gRPC (agent protocol v2)");
        GrpcAgentServerV2::new("content-scanner", Box::new(agent))
            .run(addr)
            .await
            .context("Failed to run Content Scanner gRPC server")?;
    } else {
        info!(socket = %args.socket.display(), "Listening on Unix socket (agent protocol v2)");
        UdsAgentServerV2::new("content-scanner", args.socket, Box::new(agent))
            .run()
            .await
            .context("Failed to run Content Scanner UDS server")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_names_the_binary() {
        let err = Args::try_parse_from(["x", "--version"]).unwrap_err();
        assert_eq!(
            err.to_string().trim(),
            format!(
                "zentinel-content-scanner-agent {}",
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    #[test]
    fn starts_without_a_config_file() {
        let args = Args::try_parse_from(["x", "--clamd-socket", "/tmp/clamd.sock"]).unwrap();
        assert!(args.grpc_address.is_none());
        let config = load_config(&args).unwrap();
        assert_eq!(config.clamd.socket_path, PathBuf::from("/tmp/clamd.sock"));
    }

    #[test]
    fn explicit_missing_config_is_an_error() {
        let args = Args::try_parse_from(["x", "--config", "/nonexistent/cs.yaml"]).unwrap();
        assert!(load_config(&args).is_err());
    }
}
