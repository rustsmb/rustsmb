//! RustSMB - A Rust SMB2/SMB3 server with pluggable storage backends.
//!
//! This is the main entry point for the rustsmb server binary.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use rustsmb_auth::{NtlmAuthProvider, SpnegoProvider};
use rustsmb_backend_local::LocalBackend;
use rustsmb_server::{ServerConfig, ShareConfig, SmbServer};
use rustsmb_state_memory::MemoryStateStore;
use rustsmb_vfs::StorageBackend;

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

    /// Share path (directory to share)
    #[arg(short, long, default_value = "/tmp/rustsmb")]
    share_path: String,

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
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("RustSMB starting...");
    info!("Listen address: {}", args.listen);
    info!("Share path: {}", args.share_path);

    // Initialize state store (in-memory for now)
    let state: Arc<dyn rustsmb_state::StateStore + Send + Sync> = Arc::new(MemoryStateStore::new());

    // Initialize auth provider (SPNEGO wrapping NTLM)
    let ntlm_provider = NtlmAuthProvider::new("RUSTSMB", "WORKGROUP").with_anonymous();
    ntlm_provider.add_user("testuser", "testpass", false);
    ntlm_provider.add_user("admin", "admin", true);
    let auth: Arc<dyn rustsmb_auth::AuthProvider> =
        Arc::new(SpnegoProvider::ntlm(Arc::new(ntlm_provider)));

    // Create server config
    let config = ServerConfig {
        listen_addr: args.listen.parse()?,
        require_signing: false,
        enable_signing: false,
        enable_encryption: false,
        ..Default::default()
    };

    // Create server
    let server = SmbServer::new(config, state, auth);

    // Add a test share with local filesystem backend
    let share_config = ShareConfig {
        name: "test".to_string(),
        path: args.share_path.clone(),
        read_only: false,
        guest_ok: true,
        valid_users: vec![],
        browseable: true,
    };

    // Use local filesystem backend with the provided share path
    let backend: Arc<dyn StorageBackend + Send + Sync> = Arc::new(
        LocalBackend::new(std::path::PathBuf::from(&args.share_path))
            .await
            .expect("Failed to create local backend"),
    );
    server.shares().add_share("test", backend, share_config);

    info!("Share 'test' configured");

    // Run server
    info!("Starting SMB server...");
    server.run().await?;

    Ok(())
}
