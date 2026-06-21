//! Dependency injection and application bootstrap.
//!
//! # Architecture
//! This is the **only** place in the entire codebase that creates
//! infrastructure implementations (Security, Networking, Persistence, Notifications).
//! It wires them into Application use cases via port traits.
//!
//! # Security
//! - All port implementations are created here with secure defaults.
//! - No key material is logged or exposed.
//! - Failures during bootstrap are fatal (app exits with error).

use application::ports::{
    network_port::NetworkPort,
    notification_port::NotificationPort,
    persistence_port::PersistencePort,
    security_port::SecurityPort,
    trust_port::TrustPort,
};
use application::usecases::{
    connect_peer::ConnectPeerUseCase,
    discover_peer::DiscoverPeerUseCase,
    receive_message::ReceiveMessageUseCase,
    reset_identity::ResetIdentityUseCase,
    send_message::SendMessageUseCase,
};
use domain::identity::Identity;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use ui::{AppController, UiState};

/// Bootstrap error — fatal during startup.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("security initialization failed: {0}")]
    Security(String),
    #[error("persistence initialization failed: {0}")]
    Persistence(String),
    #[error("network initialization failed: {0}")]
    Network(String),
    #[error("notification initialization failed: {0}")]
    Notification(String),
    #[error("identity not found — run first-time setup")]
    IdentityNotFound,
    #[error("internal bootstrap error: {0}")]
    Internal(String),
}

/// Bootstrap the entire application.
///
/// # Sequence
/// 1. Create persistence port (SQLite).
/// 2. Create security port (Noise + key storage).
/// 3. Load or create identity.
/// 4. Create network port (TCP + UDP + mDNS).
/// 5. Create notification port (OS notifications).
/// 6. Create trust port (persistence-backed).
/// 7. Wire all into use cases.
/// 8. Start background services (receive messages, discovery).
/// 9. Return AppController for UI.
///
/// # Performance
/// Target: <3 seconds total. Each step is timed and logged.
pub async fn bootstrap() -> Result<AppController, BootstrapError> {
    info!("=== BOOTSTRAP START ===");
    let start = tokio::time::Instant::now();

    // ── 1. Persistence ───────────────────────────────────────────────────
    info!("initializing persistence…");
    let persistence = create_persistence_port().await?;
    info!("persistence ready");

    // ── 2. Security ────────────────────────────────────────────────────
    info!("initializing security…");
    let security = create_security_port().await?;
    info!("security ready");

    // ── 3. Identity ────────────────────────────────────────────────────
    info!("loading identity…");
    let identity = match security.load_identity().await {
        Ok(Some(id)) => {
            info!(fp = %id.fingerprint(), "identity loaded");
            Arc::new(RwLock::new(id))
        }
        Ok(None) => {
            warn!("no identity found — generating new identity");
            let new_id = security
                .generate_identity("Anonymous")
                .await
                .map_err(|e| BootstrapError::Security(e.to_string()))?;
            security
                .save_identity(&new_id)
                .await
                .map_err(|e| BootstrapError::Security(e.to_string()))?;
            Arc::new(RwLock::new(new_id))
        }
        Err(e) => return Err(BootstrapError::Security(e.to_string())),
    };

    // ── 4. Network ─────────────────────────────────────────────────────
    info!("initializing network…");
    let network = create_network_port().await?;
    info!("network ready");

    // ── 5. Notifications ───────────────────────────────────────────────
    info!("initializing notifications…");
    let notification = create_notification_port().await?;
    info!("notifications ready");

    // ── 6. Trust ───────────────────────────────────────────────────────
    info!("initializing trust store…");
    let trust = create_trust_port(persistence.clone()).await?;
    info!("trust store ready");

    // ── 7. Wire Use Cases ──────────────────────────────────────────────
    info!("wiring use cases…");
    let send_message = Arc::new(SendMessageUseCase::new(
        identity.clone(),
        network.clone(),
        persistence.clone(),
        security.clone(),
        notification.clone(),
    ));
    let connect_peer = Arc::new(ConnectPeerUseCase::new(
        network.clone(),
        persistence.clone(),
        trust.clone(),
    ));
    let discover_peer = Arc::new(DiscoverPeerUseCase::new(
        network.clone(),
        persistence.clone(),
    ));
    let receive_message = Arc::new(ReceiveMessageUseCase::new(
        network.clone(),
        persistence.clone(),
        security.clone(),
        trust.clone(),
        notification.clone(),
    ));
    let reset_identity = Arc::new(ResetIdentityUseCase::new(
        identity.clone(),
        security.clone(),
        network.clone(),
        persistence.clone(),
        notification.clone(),
    ));
    info!("use cases wired");

    // ── 8. Start Background Services ────────────────────────────────────
    info!("starting background services…");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let receive_clone = receive_message.clone();
    tokio::spawn(async move {
        if let Err(e) = receive_clone.run(shutdown_rx).await {
            error!(error = ?e, "message receiver service failed");
        }
    });
    info!("background services started");

    // ── 9. Create UI State & Controller ────────────────────────────────
    let ui_state = Arc::new(RwLock::new(UiState::default()));
    {
        let id_guard = identity.read().await;
        let mut s = ui_state.write().await;
        s.identity_fingerprint = Some(id_guard.fingerprint().to_formatted_string());
        s.identity_display_name = id_guard.display_name().to_string();
    }

    let controller = AppController::new(
        ui_state.clone(),
        send_message,
        connect_peer,
        discover_peer,
        receive_message,
        reset_identity,
        notification,
    );

    let elapsed = start.elapsed();
    info!(elapsed_ms = elapsed.as_millis(), "=== BOOTSTRAP COMPLETE ===");

    if elapsed.as_secs() > 3 {
        warn!("bootstrap exceeded 3-second target");
    }

    Ok(controller)
}

// ── Infrastructure Factory Functions ─────────────────────────────────────
// These create port implementations. They are stubs until the
// infrastructure crates are fully implemented.

async fn create_persistence_port() -> Result<Arc<dyn PersistencePort>, BootstrapError> {
    // TODO: Replace with actual PersistencePort implementation
    Err(BootstrapError::Persistence(
        "persistence infrastructure not yet implemented — stub".into(),
    ))
}

async fn create_security_port() -> Result<Arc<dyn SecurityPort>, BootstrapError> {
    // TODO: Replace with actual SecurityPort implementation (Noise + key storage)
    Err(BootstrapError::Security(
        "security infrastructure not yet implemented — stub".into(),
    ))
}

async fn create_network_port() -> Result<Arc<dyn NetworkPort>, BootstrapError> {
    // TODO: Replace with actual NetworkPort implementation (TCP + UDP + mDNS)
    Err(BootstrapError::Network(
        "network infrastructure not yet implemented — stub".into(),
    ))
}

async fn create_notification_port() -> Result<Arc<dyn NotificationPort>, BootstrapError> {
    use async_trait::async_trait;
    use domain::identity::Fingerprint;
    use domain::peer::Peer;
    use application::ports::notification_port::{NotificationError, NotificationPort};

    #[derive(Debug)]
    struct NoopNotifier;

    #[async_trait]
    impl NotificationPort for NoopNotifier {
        async fn notify_message_received(
            &self,
            _sender_fp: &Fingerprint,
            _preview: &str,
        ) -> Result<(), NotificationError> {
            Ok(())
        }
        async fn notify_peer_connected(&self, _peer: &Peer) -> Result<(), NotificationError> {
            Ok(())
        }
        async fn notify_peer_disconnected(
            &self,
            _fingerprint: &Fingerprint,
        ) -> Result<(), NotificationError> {
            Ok(())
        }
        async fn notify_identity_reset(
            &self,
            _new_fp: &Fingerprint,
        ) -> Result<(), NotificationError> {
            Ok(())
        }
    }

    info!("using no-op notifier (infrastructure pending)");
    Ok(Arc::new(NoopNotifier))
}

async fn create_trust_port(
    _persistence: Arc<dyn PersistencePort>,
) -> Result<Arc<dyn TrustPort>, BootstrapError> {
    use async_trait::async_trait;
    use application::ports::trust_port::{TrustError, TrustPort};
    use domain::identity::Fingerprint;

    #[derive(Debug)]
    struct FailClosedTrust;

    #[async_trait]
    impl TrustPort for FailClosedTrust {
        async fn is_trusted(&self, _fingerprint: &Fingerprint) -> Result<bool, TrustError> {
            Ok(false) // Fail-closed: nobody is trusted
        }
        async fn add_trusted(&self, _fingerprint: &Fingerprint) -> Result<(), TrustError> {
            Ok(())
        }
        async fn remove_trusted(&self, _fingerprint: &Fingerprint) -> Result<(), TrustError> {
            Ok(())
        }
        async fn list_trusted(&self) -> Result<Vec<Fingerprint>, TrustError> {
            Ok(vec![])
        }
    }

    info!("using fail-closed trust store (infrastructure pending)");
    Ok(Arc::new(FailClosedTrust))
}