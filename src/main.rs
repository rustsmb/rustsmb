//! RustSMB - A Rust SMB2/SMB3 server with pluggable storage backends.
//!
//! This is the main entry point for the rustsmb server binary.

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// RustSMB Server - SMB2/SMB3 file server
#[derive(Parser, Debug)]
#[command(name = "rustsmb")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/rustsmb/config.toml")]
    config: String,

    /// Listen address
    #[arg(short, long, default_value = "0.0.0.0:445")]
    listen: String,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    let filter = if args.debug {
        "rustsmb=debug,tower_http=debug"
    } else {
        "rustsmb=info"
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("RustSMB starting...");
    info!("Config file: {}", args.config);
    info!("Listen address: {}", args.listen);

    // TODO: Load configuration
    // TODO: Initialize state store
    // TODO: Initialize storage backend
    // TODO: Start server

    info!("Server implementation pending - Phase 2+");

    Ok(())
}
