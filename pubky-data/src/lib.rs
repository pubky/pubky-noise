pub mod identity_payload;
pub mod path_derivation;
pub mod serializer;
pub mod snow_crypto;

use std::sync::Arc;

use pubky::prelude::*;
use pubky::PubkySession;

use serializer::PubkyDataBackupFormatter;
use snow_crypto::{DataLinkContext, HandshakeAction, HandshakePattern, PUBKY_DATA_MSG_LEN};

// Derived from noise handshake ; changes on every handshake
#[derive(Eq, Hash, PartialEq, Clone, Copy, Debug)]
pub struct LinkId(pub [u8; 32]);

#[derive(Eq, Hash, PartialEq, Debug)]
pub enum PubkyDataError {
    UnknownNoisePattern,
    SnowNoiseBuildError,
    BadLengthCiphertext,
    /// the homeserver path error
    HomeserverPathError,
    /// the homeserver response is a failure
    HomeserverResponseError,
    IsTransport,
    IsHandshake,
    OtherError,
}

#[derive(Eq, Hash, PartialEq, Debug)]
pub enum HandshakeResult {
    Pending,
    Terminal,
}

/// Shared configuration and resources for multiple `PubkyDataEncryptor` instances.
///
/// This struct holds the resources that are common across all Noise sessions for
/// a given user: the HTTP client, the authenticated homeserver session, the
/// write/read paths, and the root keypair. Wrap it in `Arc` and share it across
/// multiple single-session encryptors.
///
/// ## Asymmetric paths
///
/// `write_path` is the folder prefix used when writing messages to the local
/// homeserver. `read_path` is the folder prefix used when reading messages from
/// the remote homeserver. For symmetric usage (same path for both), pass the
/// same value to both fields via [`PubkyDataConfig::new`].
///
/// For per-peer-pair path privacy, use [`path_derivation::derive_asymmetric_paths`]
/// to compute distinct write/read paths from a DH shared secret.
pub struct PubkyDataConfig {
    pub outbox_client: Pubky,
    pub local_session: PubkySession,
    /// Folder prefix for writing messages to the local homeserver.
    pub write_path: String,
    /// Folder prefix for reading messages from the remote homeserver.
    pub read_path: String,
    pub pubky_root_keypair: Keypair,
    pub pubky_data_version: u32,
    pub default_pattern: HandshakePattern,
}

impl PubkyDataConfig {
    /// Create a new shared configuration with a single symmetric path.
    ///
    /// This is a convenience constructor that uses the same path for both
    /// reading and writing. For per-peer-pair path privacy, use
    /// [`PubkyDataConfig::new_with_paths`] instead.
    ///
    /// # Parameters:
    ///      - `pubky_root_seckey`: A 32-byte root secret key.
    ///      - `pubky_data_version`: Protocol version identifier.
    ///      - `pattern_string`: Default Noise pattern (e.g. "NN", "XX").
    ///      - `homeserver_auth_session`: An authenticated PubkySession.
    ///      - `destination_path`: Custom destination prefix for message sharing
    ///        (used for both reads and writes).
    ///      - `outbox_client`: HTTP Pubky client.
    ///
    /// # Errors:
    ///      - Returns [`PubkyDataError::UnknownNoisePattern`] if the pattern string is invalid.
    pub fn new(
        pubky_root_seckey: [u8; 32],
        pubky_data_version: u32,
        pattern_string: String,
        homeserver_auth_session: PubkySession,
        destination_path: String,
        outbox_client: Pubky,
    ) -> Result<Arc<Self>, PubkyDataError> {
        Self::new_with_paths(
            pubky_root_seckey,
            pubky_data_version,
            pattern_string,
            homeserver_auth_session,
            destination_path.clone(),
            destination_path,
            outbox_client,
        )
    }

    /// Create a new shared configuration with separate write and read paths.
    ///
    /// Use this constructor when the local party writes to a different path
    /// than it reads from (e.g., when using
    /// [`path_derivation::derive_asymmetric_paths`] for per-peer-pair privacy).
    ///
    /// # Parameters:
    ///      - `pubky_root_seckey`: A 32-byte root secret key.
    ///      - `pubky_data_version`: Protocol version identifier.
    ///      - `pattern_string`: Default Noise pattern (e.g. "NN", "XX").
    ///      - `homeserver_auth_session`: An authenticated PubkySession.
    ///      - `write_path`: Folder prefix for writing messages to the local homeserver.
    ///      - `read_path`: Folder prefix for reading messages from the remote homeserver.
    ///      - `outbox_client`: HTTP Pubky client.
    ///
    /// # Errors:
    ///      - Returns [`PubkyDataError::UnknownNoisePattern`] if the pattern string is invalid.
    pub fn new_with_paths(
        pubky_root_seckey: [u8; 32],
        pubky_data_version: u32,
        pattern_string: String,
        homeserver_auth_session: PubkySession,
        write_path: String,
        read_path: String,
        outbox_client: Pubky,
    ) -> Result<Arc<Self>, PubkyDataError> {
        let pubky_root_keypair = Keypair::from_secret(&pubky_root_seckey);
        let default_pattern = HandshakePattern::from_string(pattern_string)
            .map_err(|_| PubkyDataError::UnknownNoisePattern)?;

        Ok(Arc::new(PubkyDataConfig {
            outbox_client,
            local_session: homeserver_auth_session,
            write_path,
            read_path,
            pubky_root_keypair,
            pubky_data_version,
            default_pattern,
        }))
    }
}

/// A single-session Noise encryptor for Pubky Data.
///
/// Each instance manages exactly one Noise session (handshake + transport) with
/// a single remote peer. To manage multiple concurrent sessions, create multiple
/// `PubkyDataEncryptor` instances sharing the same `Arc<PubkyDataConfig>`.
#[derive(Debug)]
pub struct PubkyDataEncryptor {
    config: Arc<PubkyDataConfig>,
    context: DataLinkContext,
    link_id: Option<LinkId>,
    endpoint_pubkey: PublicKey,

    // test-only fields
    simulate_tampering: bool,
    last_ciphertext: Option<[u8; PUBKY_DATA_MSG_LEN + 2]>,
}

impl PubkyDataEncryptor {
    /// Create a new single-session Noise encryptor.
    ///
    /// # Parameters:
    ///      - `config`: Shared configuration (wrapped in Arc).
    ///      - `holder_skey`: Local static secret key for this session.
    ///      - `remote_pkey`: Remote peer's static ed25519 public key.
    ///      - `initiator`: Whether this side initiates the Noise handshake.
    ///      - `endpoint_pubkey`: Remote peer's public key used as path suffix.
    ///
    /// # Errors:
    ///      - Returns [`PubkyDataError::SnowNoiseBuildError`] if the Noise stack fails to build.
    pub fn new(
        config: Arc<PubkyDataConfig>,
        holder_skey: [u8; 32],
        _remote_pkey: PublicKey,
        initiator: bool,
        endpoint_pubkey: PublicKey,
    ) -> Result<Self, PubkyDataError> {
        let data_link_context = DataLinkContext::new(
            config.default_pattern,
            initiator,
            vec![],
            Some(holder_skey),
            endpoint_pubkey.clone(),
            None,
        )
        .map_err(|_| PubkyDataError::SnowNoiseBuildError)?;

        Ok(PubkyDataEncryptor {
            config,
            context: data_link_context,
            link_id: None,
            endpoint_pubkey,
            simulate_tampering: false,
            last_ciphertext: None,
        })
    }

    /// Check if this encryptor is still in the Noise Handshake phase.
    ///
    /// # Errors:
    ///      - Returns [`PubkyDataError::IsTransport`] if already transitioned to transport.
    pub fn is_handshake(&self) -> Result<(), PubkyDataError> {
        if self.context.is_handshake() {
            Ok(())
        } else {
            Err(PubkyDataError::IsTransport)
        }
    }

    /// Handle the forwarding and processing of Noise handshake messages.
    ///
    /// This method is **polling-safe**: it can be called repeatedly by either
    /// the initiator or responder in any order. If the peer's message is not
    /// yet available, returns `HandshakeResult::Pending` without advancing state.
    ///
    /// # Errors:
    ///      - Returns [`PubkyDataError::BadLengthCiphertext`] on malformed messages.
    ///      - Returns [`PubkyDataError::HomeserverResponseError`] on response parse failure.
    pub async fn handle_handshake(&mut self) -> Result<HandshakeResult, PubkyDataError> {
        println!("IN HANDLE HANDSHAKE");

        let remaining_actions = self.context.remaining_handshake_actions();
        for action in remaining_actions {
            match action {
                HandshakeAction::Read => {
                    println!("Handshake Read");
                    let path = self.config.read_path.as_str();
                    let counter = self.context.get_counter();
                    println!("Reading at Slot {counter}");
                    let public_key = &self.endpoint_pubkey;
                    let formatted_path = format!("{public_key}/{path}/{counter}");

                    if let Ok(response) = self
                        .config
                        .outbox_client
                        .public_storage()
                        .get(formatted_path)
                        .await
                    {
                        if response.status().is_success() {
                            if let Ok(ciphertext) = response.bytes().await {
                                println!("getting response bytes...");
                                if ciphertext.len() > PUBKY_DATA_MSG_LEN + 2 {
                                    return Err(PubkyDataError::BadLengthCiphertext);
                                }
                                let mut buf_len = [0; 2];
                                buf_len[0..2].copy_from_slice(&ciphertext[0..2]);
                                let len = u16::from_be_bytes(buf_len);
                                let mut message = [0; PUBKY_DATA_MSG_LEN];
                                message[0..len as usize]
                                    .copy_from_slice(&ciphertext[2..len as usize + 2]);
                                let mut payload = [0; PUBKY_DATA_MSG_LEN];
                                println!("RCV LEN {len} CIPHER {message:?}");
                                let _ =
                                    self.context
                                        .read_act(&mut message, &mut payload, len as usize);
                            } else {
                                return Err(PubkyDataError::HomeserverResponseError);
                            }
                            self.context.increment_counter();
                            self.context.advance_sub_step();
                        } else {
                            return Ok(HandshakeResult::Pending);
                        }
                    } else {
                        return Ok(HandshakeResult::Pending);
                    }
                }
                HandshakeAction::Write => {
                    println!("Handshake Write");
                    let mut message = [0; PUBKY_DATA_MSG_LEN];
                    if let Ok(len) = self.context.write_act(vec![], &mut message) {
                        println!("FWD LEN {len} CIPHER {message:?}");
                        let path = self.config.write_path.as_str();
                        let counter = self.context.get_counter();
                        println!("Writing at Slot {counter}");
                        let formatted_path = format!("{path}/{counter}");
                        let mut packet = [0; PUBKY_DATA_MSG_LEN + 2];
                        let be_bytes = (len as u16).to_be_bytes();
                        packet[0..2].copy_from_slice(&be_bytes[0..2]);
                        packet[2..len + 2].copy_from_slice(&message[0..len]);
                        let _ = self
                            .config
                            .local_session
                            .storage()
                            .put(formatted_path, packet.to_vec())
                            .await;
                        self.context.increment_counter();
                        self.context.advance_sub_step();
                    }
                }
                HandshakeAction::Pending => {
                    self.context.advance_sub_step();
                    self.context.complete_step();
                    return Ok(HandshakeResult::Pending);
                }
                HandshakeAction::Terminal => {
                    self.context.complete_step();
                    return Ok(HandshakeResult::Terminal);
                }
            }
        }
        self.context.complete_step();
        Ok(HandshakeResult::Pending)
    }

    /// Transition from Noise Handshake phase to Transport phase.
    ///
    /// Call this once `is_handshake()` returns `Err(IsTransport)`.
    /// Returns the `LinkId` derived from the handshake transcript hash.
    ///
    /// # Errors:
    ///      - Returns [`PubkyDataError::IsHandshake`] if still in handshake phase.
    pub fn transition_transport(&mut self) -> Result<LinkId, PubkyDataError> {
        if self.context.is_handshake() {
            return Err(PubkyDataError::IsHandshake);
        }
        let link_id = LinkId(self.context.get_handshake_hash().unwrap());
        let _ = self.context.to_transport();
        self.link_id = Some(link_id);
        Ok(link_id)
    }

    /// Encrypt and send plaintext over the established transport.
    ///
    /// # Parameters:
    ///      - `plaintext`: Arbitrary byte payload to encrypt and send.
    ///
    /// # Returns:
    ///      - `true` on success, `false` on failure.
    pub async fn send_message(&mut self, plaintext: Vec<u8>) -> bool {
        println!("in send message");

        let mut out = [0; PUBKY_DATA_MSG_LEN];
        let len = match self.context.write_act(plaintext, &mut out) {
            Ok(len) => len,
            Err(_) => return false,
        };

        println!("FWD LEN {len} CIPHER {out:?}");
        let mut packet = [0; PUBKY_DATA_MSG_LEN + 2];
        let be_bytes = (len as u16).to_be_bytes();
        packet[0..2].copy_from_slice(&be_bytes[0..2]);
        packet[2..len + 2].copy_from_slice(&out[0..len]);

        if self.simulate_tampering {
            self.last_ciphertext = Some(packet);
        }

        println!("write path {:?}", self.config.write_path.as_str());
        let path = self.config.write_path.as_str();
        let counter = self.context.get_counter();
        println!("Writing at Slot {counter}");
        let formatted_path = format!("{path}/{counter}");
        if self
            .config
            .local_session
            .storage()
            .put(formatted_path, packet.to_vec())
            .await
            .is_err()
        {
            return false;
        }
        self.context.increment_counter();
        true
    }

    /// Receive and decrypt a message from the remote peer.
    ///
    /// # Returns:
    ///      - A vector of decrypted payloads (empty on failure).
    pub async fn receive_message(&mut self) -> Vec<[u8; PUBKY_DATA_MSG_LEN]> {
        let mut results = Vec::new();
        let path = self.config.read_path.as_str();
        let counter = self.context.get_counter();
        println!("Reading at Slot {counter}");
        let public_key = self.context.get_endpoint();
        let formatted_path = format!("{public_key}/{path}/{counter}");
        if let Ok(response) = self
            .config
            .outbox_client
            .public_storage()
            .get(formatted_path)
            .await
        {
            println!("getting result");
            if response.status().is_success() {
                if let Ok(ciphertext) = response.bytes().await {
                    println!("getting response bytes...");
                    if ciphertext.len() > PUBKY_DATA_MSG_LEN + 2 {
                        //TODO: BadLengthCiphertext
                    }
                    let mut buf_len = [0; 2];
                    buf_len[0..2].copy_from_slice(&ciphertext[0..2]);
                    let len = u16::from_be_bytes(buf_len);
                    let mut message = [0; PUBKY_DATA_MSG_LEN];
                    message[0..len as usize].copy_from_slice(&ciphertext[2..len as usize + 2]);
                    let mut payload = [0; PUBKY_DATA_MSG_LEN];
                    println!("RCV LEN {len} CIPHER {message:?}");

                    if self.simulate_tampering {
                        message[1] = 0xff;
                    }

                    let _ = self
                        .context
                        .read_act(&mut message, &mut payload, len as usize);
                    results.push(payload);
                    self.context.increment_counter();
                }
            }
        }
        results
    }

    /// Close and clean up this encryptor's Noise session.
    pub fn close(&mut self) {
        self.context.delete();
    }

    /// Generate a backup of the current session state.
    pub async fn generate_backup(&self, _commit: bool) -> Result<(), PubkyDataError> {
        let backup_formatter = PubkyDataBackupFormatter::new();
        let serialized_backup = backup_formatter.serialize();
        let public_key = self.config.pubky_root_keypair.public_key();
        let formatted_backup_path = format!("pubky/{public_key}/backup");
        let _ = self
            .config
            .local_session
            .storage()
            .put(formatted_backup_path, serialized_backup.to_vec())
            .await;
        Ok(())
    }

    /// Get the LinkId for this session (available after transition_transport).
    pub fn get_link_id(&self) -> Option<LinkId> {
        self.link_id
    }

    // Test-only methods
    #[cfg(test)]
    pub fn enable_tampering(&mut self) {
        self.simulate_tampering = true;
    }

    #[cfg(test)]
    pub fn test_get_last_ciphertext(&self) -> Option<[u8; PUBKY_DATA_MSG_LEN + 2]> {
        self.last_ciphertext
    }
}

// Allow test access from e2e crate (not #[cfg(test)] since e2e is a separate crate)
impl PubkyDataEncryptor {
    /// Test-only: enable ciphertext tampering simulation.
    /// This method is intended for use in integration tests.
    pub fn test_enable_tampering(&mut self) {
        self.simulate_tampering = true;
    }

    /// Test-only: get the last ciphertext produced by send_message.
    pub fn test_last_ciphertext(&self) -> Option<[u8; PUBKY_DATA_MSG_LEN + 2]> {
        self.last_ciphertext
    }
}

impl std::fmt::Debug for PubkyDataConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PubkyDataConfig")
            .field("write_path", &self.write_path)
            .field("read_path", &self.read_path)
            .field("pubky_data_version", &self.pubky_data_version)
            .field("default_pattern", &self.default_pattern)
            .finish_non_exhaustive()
    }
}
