//! RustSMB Coordinator Service
//!
//! A standalone service that manages SMB server cluster membership and cache coordination.
//! Deployed as 3 or 5 nodes using Raft consensus.
//!
//! # Usage
//!
//! ```bash
//! # Start a 3-node cluster
//! rustsmb-coordinator --node-id 1 --listen 0.0.0.0:9000 --peers node2:9000,node3:9000
//! rustsmb-coordinator --node-id 2 --listen 0.0.0.0:9000 --peers node1:9000,node3:9000
//! rustsmb-coordinator --node-id 3 --listen 0.0.0.0:9000 --peers node1:9000,node2:9000
//! ```

mod config;
mod service;
mod state;

use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

/// RustSMB Coordinator - Cluster coordination service
#[derive(Parser, Debug)]
#[command(name = "rustsmb-coordinator")]
#[command(about = "Cluster coordination service for RustSMB")]
struct Args {
    /// Node ID for this coordinator instance (1, 2, 3, etc.)
    #[arg(long, default_value = "1")]
    node_id: u64,

    /// Address to listen on for gRPC connections
    #[arg(long, default_value = "0.0.0.0:9000")]
    listen: String,

    /// Comma-separated list of peer addresses (e.g., "node2:9000,node3:9000")
    #[arg(long, default_value = "")]
    peers: String,

    /// Path to configuration file
    #[arg(long, short)]
    config: Option<String>,

    /// Heartbeat timeout in seconds (servers are marked failed after this)
    #[arg(long, default_value = "15")]
    heartbeat_timeout: u64,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    let level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!(
        node_id = args.node_id,
        listen = %args.listen,
        peers = %args.peers,
        "Starting RustSMB Coordinator"
    );

    // Parse peers
    let peers: Vec<String> = if args.peers.is_empty() {
        vec![]
    } else {
        args.peers
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    };

    // Create configuration
    let config = config::CoordinatorConfig {
        node_id: args.node_id,
        listen_addr: args.listen,
        peers,
        heartbeat_timeout_secs: args.heartbeat_timeout,
    };

    // Start the coordinator service
    service::run(config).await
}
