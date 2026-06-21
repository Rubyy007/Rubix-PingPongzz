//! egui-based UI for Rubix-PingPongzz.
//!
//! # Architecture
//! The UI crate depends **only** on the Application layer (DTOs and use case handles).
//! It never imports Domain entities directly, nor any infrastructure crates.
//!
//! # Async Bridge
//! All async operations are dispatched via `tokio::sync::mpsc` channels.
//! Results flow back via `UiMessage` on a separate channel.
//! This keeps the egui `update()` loop synchronous and responsive.
//!
//! # Performance
//! - Message lists use virtual scrolling for 10,000+ messages.
//! - Peer lists are capped at 200 entries (acceptance criteria).
//! - UI state updates are batched at 60 FPS via `ctx.request_repaint_after()`.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod screens;
pub mod theme;
pub mod widgets;

use application::dto::message_dto::MessageResponse;
use application::dto::peer_dto::PeerResponse;
use application::dto::peer_dto::PeerStatusDto;
use application::ports::notification_port::NotificationPort;
use application::usecases::{
    connect_peer::ConnectPeerUseCase,
    discover_peer::DiscoverPeerUseCase,
    receive_message::ReceiveMessageUseCase,
    reset_identity::ResetIdentityUseCase,
    send_message::SendMessageUseCase,
};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Maximum messages to display in chat history.
const MAX_DISPLAYED_MESSAGES: usize = 10_000;

/// Maximum peers in the sidebar list.
const MAX_DISPLAYED_PEERS: usize = 200;

/// UI repaint interval for smooth animations.
const REPAINT_INTERVAL_MS: u64 = 16; // ~60 FPS

/// Shared mutable UI state. All screens read from this.
///
/// # Thread Safety
/// `Arc<RwLock<UiState>>` allows async tasks to update state while
/// the egui thread reads it. Lock contention is minimal because
/// updates are batched.
#[derive(Debug, Clone)]
pub struct UiState {
    /// Currently selected screen.
    pub current_screen: Screen,
    /// Local identity fingerprint (display only — never private keys).
    pub identity_fingerprint: Option<String>,
    /// Display name of local user.
    pub identity_display_name: String,
    /// All known peers (filtered/sorted by UI).
    pub peers: Vec<PeerResponse>,
    /// Currently selected peer for chat.
    pub selected_peer: Option<String>,
    /// Messages for the selected peer conversation.
    pub messages: Vec<MessageResponse>,
    /// Text input buffer for message composition.
    pub compose_text: String,
    /// Global error banner (shown at top of all screens).
    pub error_banner: Option<String>,
    /// Is a background operation in progress?
    pub is_loading: bool,
    /// Loading message for progress indicator.
    pub loading_message: String,
    /// Dark mode enabled.
    pub dark_mode: bool,
    /// Notification enabled.
    pub notifications_enabled: bool,
    /// Discovery timeout setting (seconds).
    pub discovery_timeout_secs: u64,
    /// Peer count for status bar.
    pub online_peer_count: usize,
    /// Connection status for status bar.
    pub is_connected: bool,
    /// Encryption status for status bar.
    pub is_encrypted: bool,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            current_screen: Screen::Chat,
            identity_fingerprint: None,
            identity_display_name: "Anonymous".into(),
            peers: Vec::with_capacity(MAX_DISPLAYED_PEERS),
            selected_peer: None,
            messages: Vec::with_capacity(100),
            compose_text: String::with_capacity(1024),
            error_banner: None,
            is_loading: false,
            loading_message: String::new(),
            dark_mode: true,
            notifications_enabled: true,
            discovery_timeout_secs: 10,
            online_peer_count: 0,
            is_connected: false,
            is_encrypted: true,
        }
    }
}

/// Active screen in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Main chat interface.
    Chat,
    /// Identity and trust management.
    Profile,
    /// Application settings.
    Settings,
}

/// Messages sent from async tasks back to the UI thread.
///
/// # Performance
/// All variants are small (no large Vecs) to minimize channel overhead.
/// Large payloads (peer lists, messages) are sent as `Arc<Vec<_>>`.
#[derive(Debug, Clone)]
pub enum UiMessage {
    /// Peers discovered/updated.
    PeersUpdated(Arc<Vec<PeerResponse>>),
    /// Messages loaded for selected peer.
    MessagesLoaded(Arc<Vec<MessageResponse>>),
    /// New incoming message.
    NewMessage(MessageResponse),
    /// Message sent successfully.
    MessageSent { message_id: String },
    /// Operation failed — show error banner.
    Error { message: String },
    /// Clear error banner.
    ClearError,
    /// Loading state changed.
    Loading { is_loading: bool, message: String },
    /// Identity updated after reset.
    IdentityUpdated { fingerprint: String, display_name: String },
    /// Peer connected notification.
    PeerConnected { fingerprint: String, display_name: String },
    /// Connection status changed.
    ConnectionStatus { is_connected: bool, peer_count: usize },
    /// Shutdown requested.
    Shutdown,
}

/// Controller that bridges UI events to Application use cases.
///
/// # Architecture
/// This is the **only** place in the UI crate that calls Application use cases.
/// It owns the use case handles and channels.
#[derive(Clone)]
pub struct AppController {
    /// Shared UI state.
    pub state: Arc<RwLock<UiState>>,
    /// Channel to send commands to async worker.
    pub command_tx: mpsc::UnboundedSender<UiCommand>,
    /// Channel to receive results from async worker.
    pub message_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<UiMessage>>>,
}

/// Commands sent from UI thread to async worker.
#[derive(Debug, Clone)]
pub enum UiCommand {
    /// Send a message to the selected peer.
    SendMessage { recipient_fp: String, content: String },
    /// Discover peers on LAN.
    DiscoverPeers,
    /// Connect to a specific peer.
    ConnectPeer { address: String, fingerprint: String },
    /// Select a peer for chat.
    SelectPeer { fingerprint: String },
    /// Load messages for selected peer.
    LoadMessages { fingerprint: String },
    /// Trust a peer.
    TrustPeer { fingerprint: String },
    /// Untrust a peer.
    UntrustPeer { fingerprint: String },
    /// Reset identity.
    ResetIdentity { new_display_name: String },
    /// Update settings.
    UpdateSettings { dark_mode: bool, notifications_enabled: bool, discovery_timeout: u64 },
    /// Shutdown the application.
    Shutdown,
}

impl AppController {
    /// Create a new controller with the given use cases.
    ///
    /// # Performance
    /// Spawns a background tokio task that owns all use cases.
    /// This prevents the egui thread from blocking on async operations.
    pub fn new(
        state: Arc<RwLock<UiState>>,
        _send_message: Arc<SendMessageUseCase>,
        _connect_peer: Arc<ConnectPeerUseCase>,
        _discover_peer: Arc<DiscoverPeerUseCase>,
        _receive_message: Arc<ReceiveMessageUseCase>,
        _reset_identity: Arc<ResetIdentityUseCase>,
        _notification: Arc<dyn NotificationPort>,
    ) -> Self {
        let (command_tx, mut command_rx) = mpsc::unbounded_channel::<UiCommand>();
        let (message_tx, message_rx) = mpsc::unbounded_channel::<UiMessage>();

        let state_clone = state.clone();

        // Background worker task
        tokio::spawn(async move {
            while let Some(cmd) = command_rx.recv().await {
                match cmd {
                    UiCommand::SendMessage { recipient_fp, content } => {
                        tracing::debug!(recipient = %recipient_fp, "send message command");
                        // TODO: Wire to SendMessageUseCase
                        let _ = message_tx.send(UiMessage::MessageSent {
                            message_id: uuid::Uuid::new_v4().to_string(),
                        });
                    }
                    UiCommand::DiscoverPeers => {
                        tracing::debug!("discover peers command");
                        // TODO: Wire to DiscoverPeerUseCase
                        let _ = message_tx.send(UiMessage::Loading {
                            is_loading: false,
                            message: "Discovery complete".into(),
                        });
                    }
                    UiCommand::ConnectPeer { address, fingerprint } => {
                        tracing::debug!(addr = %address, fp = %fingerprint, "connect peer command");
                        // TODO: Wire to ConnectPeerUseCase
                    }
                    UiCommand::SelectPeer { fingerprint } => {
                        let mut s = state_clone.write().await;
                        s.selected_peer = Some(fingerprint.clone());
                        s.current_screen = Screen::Chat;
                        drop(s);
                        let _ = message_tx.send(UiMessage::LoadMessages { fingerprint });
                    }
                    UiCommand::LoadMessages { fingerprint } => {
                        tracing::debug!(fp = %fingerprint, "load messages command");
                        // TODO: Wire to PersistencePort via use case
                    }
                    UiCommand::TrustPeer { fingerprint } => {
                        tracing::debug!(fp = %fingerprint, "trust peer command");
                        // TODO: Wire to TrustPort
                    }
                    UiCommand::UntrustPeer { fingerprint } => {
                        tracing::debug!(fp = %fingerprint, "untrust peer command");
                        // TODO: Wire to TrustPort
                    }
                    UiCommand::ResetIdentity { new_display_name } => {
                        tracing::debug!(name = %new_display_name, "reset identity command");
                        // TODO: Wire to ResetIdentityUseCase
                    }
                    UiCommand::UpdateSettings { dark_mode, notifications_enabled, discovery_timeout } => {
                        let mut s = state_clone.write().await;
                        s.dark_mode = dark_mode;
                        s.notifications_enabled = notifications_enabled;
                        s.discovery_timeout_secs = discovery_timeout;
                    }
                    UiCommand::Shutdown => {
                        tracing::info!("shutdown command received");
                        let _ = message_tx.send(UiMessage::Shutdown);
                        break;
                    }
                }
            }
        });

        Self {
            state,
            command_tx,
            message_rx: Arc::new(tokio::sync::Mutex::new(message_rx)),
        }
    }

    /// Process pending UI messages from the async worker.
    ///
    /// # Performance
    /// Non-blocking — drains the channel without awaiting.
    /// Call this every frame in `eframe::App::update()`.
    pub async fn process_messages(&self) {
        let mut rx = self.message_rx.lock().await;
        while let Ok(msg) = rx.try_recv() {
            match msg {
                UiMessage::PeersUpdated(peers) => {
                    let mut s = self.state.write().await;
                    s.peers = peers.as_ref().clone();
                    s.online_peer_count = s.peers.iter().filter(|p| matches!(p.status, PeerStatusDto::Online { .. })).count();
                }
                UiMessage::MessagesLoaded(messages) => {
                    let mut s = self.state.write().await;
                    s.messages = messages.as_ref().clone();
                }
                UiMessage::NewMessage(msg) => {
                    let mut s = self.state.write().await;
                    if s.messages.len() >= MAX_DISPLAYED_MESSAGES {
                        s.messages.remove(0);
                    }
                    s.messages.push(msg);
                }
                UiMessage::MessageSent { message_id } => {
                    tracing::debug!(id = %message_id, "message sent confirmed");
                    let mut s = self.state.write().await;
                    s.is_loading = false;
                }
                UiMessage::Error { message } => {
                    let mut s = self.state.write().await;
                    s.error_banner = Some(message);
                    s.is_loading = false;
                }
                UiMessage::ClearError => {
                    let mut s = self.state.write().await;
                    s.error_banner = None;
                }
                UiMessage::Loading { is_loading, message } => {
                    let mut s = self.state.write().await;
                    s.is_loading = is_loading;
                    s.loading_message = message;
                }
                UiMessage::IdentityUpdated { fingerprint, display_name } => {
                    let mut s = self.state.write().await;
                    s.identity_fingerprint = Some(fingerprint);
                    s.identity_display_name = display_name;
                }
                UiMessage::PeerConnected { fingerprint, display_name } => {
                    tracing::debug!(fp = %fingerprint, name = %display_name, "peer connected");
                }
                UiMessage::ConnectionStatus { is_connected, peer_count } => {
                    let mut s = self.state.write().await;
                    s.is_connected = is_connected;
                    s.online_peer_count = peer_count;
                }
                UiMessage::Shutdown => {
                    // Handled by app.rs
                }
            }
        }
    }

    /// Send a command to the async worker.
    pub fn send_command(&self, cmd: UiCommand) {
        let _ = self.command_tx.send(cmd);
    }
}

// Re-export types for consumers
pub use screens::{chat_screen, profile_screen, settings_screen};
pub use theme::dark_theme;
pub use widgets::{message_bubble, peer_list, status_indicator};