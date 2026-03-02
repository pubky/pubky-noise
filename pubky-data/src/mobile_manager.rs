//! Mobile-optimized Noise session manager with lifecycle management.
//!
//! This module provides a high-level API specifically designed for mobile applications
//! that need to manage Noise sessions with proper lifecycle handling and state persistence.
//!
//! ## Reconnection
//!
//! Reconnection logic must be implemented by the application. The `MobileConfig` provides
//! configuration hints (`auto_reconnect`, `max_reconnect_attempts`, `reconnect_delay_ms`)
//! that applications can use to configure their own reconnection behavior. Use
//! `save_state()` to persist session metadata before app suspension, and `restore_state()`
//! followed by a new `initiate_connection()` to reconnect after resuming.
//!
//! ## 3-Step Handshake Flow
//!
//! **Client:**
//! 1. Call `initiate_connection()` - returns first message to send to server
//! 2. Send message over your transport (TCP, WebSocket, etc.)
//! 3. Receive server response
//! 4. Call `complete_connection()` with response - establishes session
//!
//! **Server:**
//! 1. Receive client's first message
//! 2. Call `accept_connection()` - processes message and returns response + SessionId
//! 3. Send response back to client over your transport
//! 4. Session established

use snow::HandshakeState;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::thread::JoinHandle;

use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::{
    ConversationId, LinkId, PubkyDataEncryptor, PubkyDataError, PubkyKeySet, TemporaryLinkId,
};

use pubky::{PubkyHttpClient, PubkySession};

use pubky::{Keypair, Pubky, PublicKey};

/// Connection status for a Noise session.
///
/// ## Persistence
///
/// When the `storage-queue` feature is enabled, this enum derives `Serialize`/`Deserialize`
/// to support state persistence across app restarts. Applications should:
///
/// 1. Persist `SessionState` (which includes `ConnectionStatus`) before app suspension
/// 2. Restore on resume using `NoiseManager::restore_state()`
/// 3. Check status and initiate reconnection if needed
///
/// ## Reconnection Strategy
///
/// Applications should implement **laddered backoff** for reconnection:
///
/// ```text
/// Attempt 1: wait 1s
/// Attempt 2: wait 2s
/// Attempt 3: wait 4s
/// Attempt 4: wait 8s
/// Attempt 5: wait 16s (capped)
/// ```
///
/// Use `MobileConfig::reconnect_delay_ms` as the initial delay, then double
/// for each subsequent attempt up to a reasonable maximum (e.g., 30s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "storage-queue",
    derive(serde::Serialize, serde::Deserialize)
)]
pub enum ConnectionStatus {
    /// Session is connected and ready for encryption/decryption.
    Connected,
    /// Session is attempting to reconnect (application-managed).
    /// Track reconnection attempts externally and use laddered backoff.
    Reconnecting,
    /// Session is disconnected. Call `initiate_connection()` to reconnect.
    Disconnected,
    /// Session encountered an error. Check logs and potentially retry.
    Error,
}

#[derive(Debug, Clone)]
struct SessionId;

//TODO: move SessionState in `lib.rs`
//	- rename SessionState
/// Serializable session state for persistence across app restarts.
#[cfg_attr(
    feature = "storage-queue",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Debug, Clone)]
pub struct SessionState {
    /// Session identifier.
    pub session_id: SessionId,
    /// Peer's public key (for reconnection).
    pub peer_static_pk: [u8; 32],
    /// Write counter (for storage-backed messaging).
    pub write_counter: u64,
    /// Read counter (for storage-backed messaging).
    pub read_counter: u64,
    /// Connection status.
    pub status: ConnectionStatus,
}

struct NoiseError;

/// Mobile-optimized configuration for Noise sessions.
///
/// ## Reconnection Settings
///
/// The `auto_reconnect`, `max_reconnect_attempts`, and `reconnect_delay_ms` fields
/// are **configuration hints** for application-level reconnection logic. The
/// `NoiseManager` does not implement automatic reconnection internally; applications
/// must implement their own reconnection handling using `restore_state()` and
/// `initiate_connection()`.
///
/// These fields are exposed in the configuration to provide a standard way for
/// applications to configure their reconnection behavior.
#[derive(Debug, Clone)]
pub struct MobileConfig {
    /// Hint: Whether the application should attempt reconnection on disconnect.
    /// Applications must implement their own reconnection logic.
    pub auto_reconnect: bool,
    /// Hint: Maximum number of reconnection attempts before giving up.
    /// Applications must implement their own retry counter.
    pub max_reconnect_attempts: u32,
    /// Hint: Initial delay in milliseconds between reconnection attempts.
    /// Applications should use exponential backoff (e.g., delay * 2^attempt).
    pub reconnect_delay_ms: u64,
    /// Enable aggressive battery saving (reduces background activity).
    pub battery_saver: bool,
    /// Chunk size for streaming (smaller for mobile networks).
    pub chunk_size: usize,
    /// Pubky Data protocol specific versioning
    pub pubky_data: u32,
    /// Pubky Data pattern string
    pub pattern_string: String,
    /// Homeserver outbox path
    pub outbox_path: String,
    /// Default Relay IP:
    pub default_relay: String,
}

impl Default for MobileConfig {
    fn default() -> Self {
        Self {
            auto_reconnect: true,
            max_reconnect_attempts: 5,
            reconnect_delay_ms: 1000,
            battery_saver: false,
            chunk_size: 32768, // 32KB chunks for mobile
            pubky_data: 0,
            pattern_string: "NN".to_string(),
            outbox_path: format!("/pub/data"),
            default_relay: format!("http://127.0.0.1:6881"),
        }
    }
}

//TODO: enforce max concurrent handshakes ?
//const MAX_CONCURRENT_HANDSHAKE: usize = 100;

pub struct NoiseManager {
    config: MobileConfig,
    pubky_encryptor: Mutex<PubkyDataEncryptor>,

    conversation_to_link: Mutex<HashMap<ConversationId, LinkId>>,

    /// Client keypair used for connecting to homeservers
    client_keypair: Keypair,
}

impl NoiseManager {
    pub fn new(
        config: MobileConfig,
        root_seckey: [u8; 32],
        local_session: PubkySession,
        outbox_client: Pubky,
    ) -> Option<Self> {
        let version = config.pubky_data.clone();
        let pattern = config.pattern_string.clone();
        let outbox_path = config.outbox_path.clone();
        let client_keypair = Keypair::random();
        if let Ok(pubky_encryptor) = PubkyDataEncryptor::init_encryptor_stack(
            root_seckey,
            version,
            pattern,
            local_session,
            outbox_path,
            outbox_client,
            false,
        ) {
            let mut noise_manager = NoiseManager {
                config,
                pubky_encryptor: Mutex::new(pubky_encryptor),
                conversation_to_link: Mutex::new(HashMap::new()),
                client_keypair,
            };
            return Some(noise_manager);
        } else {
            return None;
        }
    }

    pub async fn open_link(
        &mut self,
        peer_static_pkey: Option<PublicKey>,
        holder_static_skey: Option<[u8; 32]>,
        path_pubkey: PublicKey,
        homeserver_pubkey: PublicKey,
        conversation_id: Option<ConversationId>,
    ) -> Result<ConversationId, NoiseError> {
        //TODO: make the conditional on the existence of a pubky http client
        let key_set = PubkyKeySet::new(holder_static_skey, peer_static_pkey);

        let init_ret = {
            let ret = if let Ok(mut pubky_encryptor_lock) = self.pubky_encryptor.lock() {
                pubky_encryptor_lock.init_context(key_set, true, path_pubkey.clone())
            } else {
                Err(PubkyDataError::OtherError)
            };
            ret
        };

        if init_ret.is_err() {
            return Err(NoiseError);
        }

        let start_clock = Instant::now();
        let transition_ret = loop {
            //TODO: maybe do try_lock
            if let Ok(mut pubky_encryptor_lock) = self.pubky_encryptor.lock() {
                if pubky_encryptor_lock
                    .is_handshake(init_ret.as_ref().unwrap())
                    .is_ok()
                {
                    pubky_encryptor_lock.handle_handshake(
                        true,
                        *init_ret.as_ref().unwrap(),
                        path_pubkey.clone(),
                    );
                } else {
                    let transition_ret =
                        pubky_encryptor_lock.transition_transport(*init_ret.as_ref().unwrap());
                    break transition_ret;
                }
            }
            sleep(Duration::from_millis(100));
            let cmp_clock = Instant::now();
            if start_clock + Duration::from_secs(60) < cmp_clock {
                //TODO: clean up context
                return Err(NoiseError);
            }
        };

        let conversation_id = if conversation_id.is_none() {
            ConversationId::gen_new_random()
        } else {
            conversation_id.unwrap()
        };

        if let Ok(mut conversation_to_link_lock) = self.conversation_to_link.lock() {
            conversation_to_link_lock.insert(conversation_id.clone(), transition_ret.unwrap());
        }

        return Ok(conversation_id);
    }

    pub async fn accept_link(
        &mut self,
        peer_static_key: Option<PublicKey>,
        holder_static_skey: Option<[u8; 32]>,
        path_pubkey: PublicKey,
        homeserver_pubkey: PublicKey,
        conversation_id: Option<ConversationId>,
    ) -> Result<ConversationId, NoiseError> {
        let key_set = PubkyKeySet::new(holder_static_skey, peer_static_key);

        let init_ret = {
            let ret = if let Ok(mut pubky_encryptor_lock) = self.pubky_encryptor.lock() {
                pubky_encryptor_lock.init_context(key_set, false, path_pubkey.clone())
            } else {
                Err(PubkyDataError::OtherError)
            };
            ret
        };

        if init_ret.is_err() {
            return Err(NoiseError);
        }

        let start_clock = Instant::now();
        let transition_ret = loop {
            if let Ok(mut pubky_encryptor_lock) = self.pubky_encryptor.lock() {
                if pubky_encryptor_lock
                    .is_handshake(init_ret.as_ref().unwrap())
                    .is_ok()
                {
                    pubky_encryptor_lock.handle_handshake(
                        true,
                        *init_ret.as_ref().unwrap(),
                        path_pubkey.clone(),
                    );
                } else {
                    let transition_ret =
                        pubky_encryptor_lock.transition_transport(*init_ret.as_ref().unwrap());
                    break transition_ret;
                }
            }
            sleep(Duration::from_millis(100));
            let cmp_clock = Instant::now();
            if start_clock + Duration::from_secs(60) < cmp_clock {
                //TODO: clean up context
                return Err(NoiseError);
            }
        };

        let conversation_id = if conversation_id.is_none() {
            ConversationId::gen_new_random()
        } else {
            conversation_id.unwrap()
        };

        if let Ok(mut conversation_to_link_lock) = self.conversation_to_link.lock() {
            conversation_to_link_lock.insert(conversation_id.clone(), transition_ret.unwrap());
        }

        return Ok(conversation_id);
    }

    /// Get a session link for encryption/decryption
    pub fn get_session(&self, session_id: &SessionId) -> Option<()> {
        return None;
    }

    /// Get a mutable session link
    pub fn get_session_mut(&mut self, session_id: &SessionId) -> Option<()> {
        //self.sessions.get_mut(session_id)
        return None;
    }

    /// Remove a session
    pub fn remove_session(&mut self, session_id: &SessionId) -> Option<()> {
        return None;
    }

    /// List all active sessions
    pub fn list_sessions(&self) -> Vec<SessionId> {
        //self.sessions.keys().cloned().collect()
        return vec![];
    }

    /// Get the connection status for a session
    pub fn get_status(&self, session_id: &SessionId) -> Option<ConnectionStatus> {
        //self.session_states.get(session_id).map(|s| s.status)
        return None;
    }

    /// Update the connection status for a session
    pub fn set_status(&mut self, session_id: &SessionId, status: ConnectionStatus) {
        //if let Some(state) = self.session_states.get_mut(session_id) {
        //    state.status = status;
        //}
    }

    /// Save the current state of a session for persistence
    ///
    /// **Critical**: Call this before app suspension to enable session restoration
    pub fn save_state(&self, session_id: &SessionId) -> Result<SessionState, NoiseError> {
        //self.session_states
        //    .get(session_id)
        //    .cloned()
        //    .ok_or_else(|| NoiseError::Other("Session not found".to_string()))
        return Err(NoiseError);
    }

    /// Restore a session from saved state
    ///
    /// Note: This only restores the state metadata. You'll need to reconnect
    /// to re-establish the actual Noise transport.
    pub fn restore_state(&mut self, state: SessionState) -> Result<(), NoiseError> {
        //self.session_states.insert(state.session_id.clone(), state);
        //Ok(())
        return Err(NoiseError);
    }

    /// Get the mobile configuration
    pub fn config(&self) -> &MobileConfig {
        &self.config
    }

    /// Update the mobile configuration
    pub fn set_config(&mut self, config: MobileConfig) {
        self.config = config;
    }

    /// Encrypt data using a specific conversation
    pub async fn encrypt(
        &mut self,
        conversation_id: &ConversationId,
        plaintext: Vec<u8>,
    ) -> Result<(), NoiseError> {
        let link_id = if let Ok(conversation_to_link_lock) = self.conversation_to_link.lock() {
            if let Some(link_id) = conversation_to_link_lock.get(&conversation_id) {
                link_id.clone()
            } else {
                return Err(NoiseError);
            }
        } else {
            return Err(NoiseError);
        };

        if let Ok(mut pubky_encryptor_lock) = self.pubky_encryptor.lock() {
            pubky_encryptor_lock.send_message(plaintext, link_id).await;
        }
        Ok(())
    }

    /// Decrypt data using a specific session
    pub async fn decrypt(
        &mut self,
        conversation_id: &ConversationId,
    ) -> Result<Vec<[u8; 1000]>, NoiseError> {
        let link_id = if let Ok(conversation_to_link_lock) = self.conversation_to_link.lock() {
            if let Some(link_id) = conversation_to_link_lock.get(&conversation_id) {
                link_id.clone()
            } else {
                return Err(NoiseError);
            }
        } else {
            return Err(NoiseError);
        };

        if let Ok(mut pubky_encryptor_lock) = self.pubky_encryptor.lock() {
            let plaintext = pubky_encryptor_lock.receive_message(link_id).await;
            return Ok(plaintext);
        }
        return Err(NoiseError);
    }
}
