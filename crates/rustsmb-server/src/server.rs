//! Main server implementation.
//!
//! Provides the SMB server with TCP listener, TLS support, and graceful shutdown.

use crate::coordination::ServerCoordination;
use crate::handler::ConnectionHandler;
use crate::{ServerConfig, ShareManager};
use rustsmb_auth::DynAuthProvider;
use rustsmb_session::SessionManager;
use rustsmb_state::DynStateStore;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig as TlsServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// SMB Server.
pub struct SmbServer {
    /// Server configuration.
    config: Arc<ServerConfig>,
    /// Session manager.
    session_manager: Arc<SessionManager>,
    /// Authentication provider.
    auth_provider: DynAuthProvider,
    /// Share manager.
    shares: Arc<ShareManager>,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
    /// Active connection count.
    active_connections: Arc<AtomicUsize>,
    /// Connection semaphore for limiting concurrent connections.
    connection_semaphore: Arc<Semaphore>,
    /// Coordination layer (optional, for multi-server deployments).
    coordination: Option<Arc<ServerCoordination>>,
}

impl SmbServer {
    /// Create a new SMB server.
    pub fn new(
        config: ServerConfig,
        state_store: DynStateStore,
        auth_provider: DynAuthProvider,
    ) -> Self {
        let connection_semaphore = Arc::new(Semaphore::new(config.max_connections));
        let config = Arc::new(config);
        let session_manager = Arc::new(SessionManager::with_defaults(state_store));

        Self {
            config,
            session_manager,
            auth_provider,
            shares: Arc::new(ShareManager::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            connection_semaphore,
            coordination: None,
        }
    }

    /// Create a new SMB server with coordination support for multi-server deployments.
    ///
    /// This enables:
    /// - Local caching with LRU eviction
    /// - Server heartbeats for failure detection
    /// - Cache invalidation on server failure
    /// - Coordination for leases and locks
    pub fn with_coordination(
        config: ServerConfig,
        bulk_store: DynStateStore,
        auth_provider: DynAuthProvider,
    ) -> Self {
        let connection_semaphore = Arc::new(Semaphore::new(config.max_connections));

        // Create coordination layer
        let coordination = Arc::new(ServerCoordination::new(
            &config.coordination,
            &config.server_name,
            config.listen_addr.port(),
            bulk_store,
        ));

        // Use the cached state store from coordination
        let state_store = coordination.state_store();
        let session_manager = Arc::new(SessionManager::with_defaults(state_store));

        let config = Arc::new(config);

        Self {
            config,
            session_manager,
            auth_provider,
            shares: Arc::new(ShareManager::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            connection_semaphore,
            coordination: Some(coordination),
        }
    }

    /// Create server with custom session manager config.
    pub fn with_session_manager(
        config: ServerConfig,
        session_manager: Arc<SessionManager>,
        auth_provider: DynAuthProvider,
    ) -> Self {
        let connection_semaphore = Arc::new(Semaphore::new(config.max_connections));
        let config = Arc::new(config);

        Self {
            config,
            session_manager,
            auth_provider,
            shares: Arc::new(ShareManager::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            connection_semaphore,
            coordination: None,
        }
    }

    /// Get the share manager.
    pub fn shares(&self) -> &Arc<ShareManager> {
        &self.shares
    }

    /// Get the session manager.
    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.session_manager
    }

    /// Get the auth provider.
    pub fn auth_provider(&self) -> &DynAuthProvider {
        &self.auth_provider
    }

    /// Get the coordination layer (if enabled).
    pub fn coordination(&self) -> Option<&Arc<ServerCoordination>> {
        self.coordination.as_ref()
    }

    /// Get the number of active connections.
    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Signal the server to shut down.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// Check if shutdown has been signaled.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Run the server.
    ///
    /// This starts listening for connections and handling SMB requests.
    /// Returns when shutdown is signaled and all connections have drained.
    pub async fn run(&self) -> Result<(), ServerError> {
        info!(
            addr = %self.config.listen_addr,
            max_connections = self.config.max_connections,
            tls = self.config.tls_enabled,
            coordination = self.coordination.is_some(),
            "Starting SMB server"
        );

        // Start coordination if enabled
        if let Some(ref coord) = self.coordination {
            coord
                .start()
                .await
                .map_err(|e| ServerError::Config(format!("Coordination error: {}", e)))?;
            info!(
                server_id = %coord.server_id(),
                "Coordination started"
            );
        }

        // Create TCP listener
        let listener = TcpListener::bind(self.config.listen_addr)
            .await
            .map_err(|e| ServerError::Bind(e.to_string()))?;

        // Setup TLS if enabled
        let tls_acceptor = if self.config.tls_enabled {
            Some(self.create_tls_acceptor()?)
        } else {
            None
        };

        // Spawn shutdown signal handler
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = tokio::signal::ctrl_c().await {
                error!(error = %e, "Failed to listen for ctrl+c");
                return;
            }
            info!("Received shutdown signal");
            shutdown.store(true, Ordering::Release);
        });

        // Accept connections
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            // Check shutdown before accepting
                            if self.is_shutdown() {
                                debug!("Rejecting connection during shutdown");
                                continue;
                            }

                            // Try to acquire connection permit
                            let permit = match self.connection_semaphore.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    warn!(peer = %addr, "Connection limit reached, rejecting");
                                    continue;
                                }
                            };

                            self.active_connections.fetch_add(1, Ordering::Relaxed);

                            // Get server_id from coordination or generate default
                            let server_id = self
                                .coordination
                                .as_ref()
                                .map(|c| c.server_id().to_string())
                                .unwrap_or_else(|| format!("standalone-{}", std::process::id()));

                            // Spawn connection handler
                            let handler_context = HandlerContext {
                                config: self.config.clone(),
                                session_manager: self.session_manager.clone(),
                                auth_provider: self.auth_provider.clone(),
                                shares: self.shares.clone(),
                                active_connections: self.active_connections.clone(),
                                _permit: permit,
                                server_id,
                            };

                            if let Some(ref acceptor) = tls_acceptor {
                                let acceptor = acceptor.clone();
                                tokio::spawn(async move {
                                    match acceptor.accept(stream).await {
                                        Ok(tls_stream) => {
                                            Self::handle_connection(tls_stream, addr, handler_context).await;
                                        }
                                        Err(e) => {
                                            warn!(peer = %addr, error = %e, "TLS handshake failed");
                                            handler_context.active_connections.fetch_sub(1, Ordering::Relaxed);
                                        }
                                    }
                                });
                            } else {
                                tokio::spawn(async move {
                                    Self::handle_connection(stream, addr, handler_context).await;
                                });
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to accept connection");
                        }
                    }
                }
                _ = self.wait_for_shutdown() => {
                    info!("Shutdown signaled, stopping accept loop");
                    break;
                }
            }
        }

        // Wait for active connections to drain
        self.drain_connections().await;

        // Stop coordination if enabled
        if let Some(ref coord) = self.coordination {
            coord.stop().await;
            info!("Coordination stopped");
        }

        info!("Server stopped");
        Ok(())
    }

    /// Handle a single connection.
    async fn handle_connection<S>(stream: S, addr: std::net::SocketAddr, ctx: HandlerContext)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        debug!(peer = %addr, "Accepted connection");

        let mut handler = ConnectionHandler::new(
            stream,
            addr,
            ctx.config,
            ctx.session_manager,
            ctx.auth_provider,
            ctx.shares,
            ctx.server_id,
        );

        if let Err(e) = handler.run().await {
            warn!(peer = %addr, error = %e, "Connection handler error");
        }

        ctx.active_connections.fetch_sub(1, Ordering::Relaxed);
        debug!(peer = %addr, "Connection closed");
    }

    /// Wait for shutdown signal.
    async fn wait_for_shutdown(&self) {
        while !self.is_shutdown() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// Drain active connections with timeout.
    async fn drain_connections(&self) {
        let drain_timeout = std::time::Duration::from_secs(30);
        let start = std::time::Instant::now();

        while self.active_connections() > 0 {
            if start.elapsed() > drain_timeout {
                warn!(
                    remaining = self.active_connections(),
                    "Connection drain timeout, forcing shutdown"
                );
                break;
            }

            debug!(
                remaining = self.active_connections(),
                "Waiting for connections to drain"
            );
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    /// Create TLS acceptor from configured certificates.
    fn create_tls_acceptor(&self) -> Result<TlsAcceptor, ServerError> {
        let cert_path = self
            .config
            .tls_cert
            .as_ref()
            .ok_or_else(|| ServerError::Config("TLS enabled but no certificate path".into()))?;

        let key_path = self
            .config
            .tls_key
            .as_ref()
            .ok_or_else(|| ServerError::Config("TLS enabled but no key path".into()))?;

        let certs = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;

        let config = TlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ServerError::Tls(e.to_string()))?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

/// Context passed to connection handlers.
struct HandlerContext {
    config: Arc<ServerConfig>,
    session_manager: Arc<SessionManager>,
    auth_provider: DynAuthProvider,
    shares: Arc<ShareManager>,
    active_connections: Arc<AtomicUsize>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    server_id: String,
}

/// Server error types.
#[derive(Debug)]
pub enum ServerError {
    /// Bind error.
    Bind(String),
    /// Configuration error.
    Config(String),
    /// TLS error.
    Tls(String),
    /// I/O error.
    Io(String),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind(e) => write!(f, "Bind error: {}", e),
            Self::Config(e) => write!(f, "Config error: {}", e),
            Self::Tls(e) => write!(f, "TLS error: {}", e),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for ServerError {}

/// Load certificates from a PEM file.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, ServerError> {
    let file =
        File::open(path).map_err(|e| ServerError::Tls(format!("Failed to open cert: {}", e)))?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ServerError::Tls(format!("Failed to parse certs: {}", e)))
}

/// Load private key from a PEM file.
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, ServerError> {
    let file =
        File::open(path).map_err(|e| ServerError::Tls(format!("Failed to open key: {}", e)))?;
    let mut reader = BufReader::new(file);

    // Try different key formats
    loop {
        match rustls_pemfile::read_one(&mut reader) {
            Ok(Some(rustls_pemfile::Item::Pkcs1Key(key))) => {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
            Ok(Some(rustls_pemfile::Item::Pkcs8Key(key))) => {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
            Ok(Some(rustls_pemfile::Item::Sec1Key(key))) => {
                return Ok(PrivateKeyDer::Sec1(key));
            }
            Ok(Some(_)) => continue, // Skip other items
            Ok(None) => break,
            Err(e) => return Err(ServerError::Tls(format!("Failed to parse key: {}", e))),
        }
    }

    Err(ServerError::Tls("No private key found in file".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config() {
        let config = ServerConfig::default();
        assert_eq!(config.listen_addr.port(), 445);
        assert!(!config.tls_enabled);
    }
}
