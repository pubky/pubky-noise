pub mod identity_payload;
pub mod path_derivation;
pub mod serializer;
pub mod snow_crypto;
pub mod snow_crypto_resolver;

use std::sync::Arc;

use pubky::prelude::*;
use pubky::PubkySession;

use serializer::PubkyDataSessionState;
use snow_crypto::{
    full_handshake_actions, DataLinkContext, HandshakeAction, HandshakePattern, NoisePhase,
    PUBKY_DATA_MSG_LEN,
};

/// A 32-byte identifier derived from the Noise handshake.
///
/// If ephemeral keys are used by the Noise pattern relied
/// on for the handshake, should change after every handshake.
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
    HomeserverWriteError,
    HomeserverReadError,
    IsTransport,
    IsHandshake,
    /// Restore failed: handshake replay error.
    RestoreReplayError,
    /// Restore failed: handshake hash mismatch after replay.
    RestoreHashMismatch,
    /// Restore failed: deserialization error.
    RestoreDeserializeError,
    NoiseContextError,
    OtherError,
}

// TODO: impl from ContextError for PubkyDataError
impl From<snow_crypto::ContextError> for PubkyDataError {
    fn from(_: snow_crypto::ContextError) -> Self {
        PubkyDataError::NoiseContextError
    }
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
/// Alternatively, a unique PubkyDataConfig can be passed to each `PubkyDataEncryptor`
/// to customize the ressource for performance reasons.
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
        let default_pattern = pattern_string
            .parse::<HandshakePattern>()
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
        _remote_pkey: PublicKey, // TODO: remove it!
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
                                return Err(PubkyDataError::HomeserverReadError);
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
    pub async fn send_message(&mut self, plaintext: Vec<u8>) -> Result<(), PubkyDataError> {
        println!("in send message");

        // Phase guard: must be in transport mode
        if !self.context.is_transport() {
            println!("send_message called but not in transport phase");
            return Err(PubkyDataError::IsHandshake);
        }

        let mut out = [0; PUBKY_DATA_MSG_LEN];
        let len = self.context.write_act(plaintext, &mut out)?;

        println!("FWD LEN {len} CIPHER {out:?}");
        let mut packet = [0; PUBKY_DATA_MSG_LEN + 2];
        let be_bytes = (len as u16).to_be_bytes();
        packet[0..2].copy_from_slice(&be_bytes[0..2]);
        packet[2..len + 2].copy_from_slice(&out[0..len]);

        // This code path is enabled only for testing
        // of the correct enciphering of a payload.
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
            return Err(PubkyDataError::HomeserverWriteError);
        }
        self.context.increment_counter();
        Ok(())
    }

    /// Receive and decrypt a message from the remote peer.
    ///
    /// # Returns:
    ///      - A vector of decrypted payloads (empty on failure).
    pub async fn receive_message(
        &mut self,
    ) -> Result<Vec<[u8; PUBKY_DATA_MSG_LEN]>, PubkyDataError> {
        println!("in receive message");
        // Phase guard: must be in transport mode
        if !self.context.is_transport() {
            return Err(PubkyDataError::IsHandshake);
        }

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

                    // This code path is enabled only for testing
                    // of the correct deciphering of a payload.
                    if self.simulate_tampering {
                        message[1] = 0xff;
                    }

                    let _ = self
                        .context
                        .read_act(&mut message, &mut payload, len as usize);
                    results.push(payload);
                    self.context.increment_counter();
                }
            } else {
                return Err(PubkyDataError::HomeserverReadError);
            }
        } else {
            return Err(PubkyDataError::HomeserverReadError);
        }
        Ok(results)
    }

    /// Close and clean up this encryptor's Noise session.
    pub fn close(&mut self) {
        self.context.delete();
    }

    /// Capture the current session state as a serializable snapshot.
    ///
    /// This snapshot contains everything needed to restore the session later
    /// by replaying persisted handshake messages.
    pub fn snapshot(&self) -> PubkyDataSessionState {
        let phase = self.context.get_phase();
        let handshake_hash = self.context.get_handshake_hash();

        PubkyDataSessionState {
            version: 1,
            phase,
            pattern: self.context.get_pattern(),
            initiator: self.context.is_initiator(),
            ephemeral_secret: *self.context.get_ephemeral_secret(),
            static_secret: self.context.get_static_secret().copied(),
            counter: self.context.get_counter(),
            noise_step: self.context.get_noise_step(),
            sub_step_index: self.context.get_sub_step_index() as u8,
            handshake_hash,
            link_id: self.link_id.map(|id| id.0),
            sending_nonce: self.context.get_sending_nonce(),
            receiving_nonce: self.context.get_receiving_nonce(),
            endpoint_pubkey: self.endpoint_pubkey.to_bytes(),
        }
    }

    /// Persist the current session snapshot to the homeserver (encrypted path).
    pub async fn persist_snapshot(&self) -> Result<(), PubkyDataError> {
        let state = self.snapshot();
        let serialized = state.serialize();
        // TODO: encrypt serialized bytes with a key derived from pubky_root_keypair
        // before storing. For now, store as-is.
        let path = format!("{}/backup", self.config.write_path);
        self.config
            .local_session
            .storage()
            .put(path, serialized)
            .await
            .map_err(|_| PubkyDataError::OtherError)?;
        Ok(())
    }

    /// Restore a `PubkyDataEncryptor` from a previously saved session state.
    ///
    /// This method:
    /// 1. Builds a fresh `DataLinkContext` with the saved ephemeral key
    /// 2. Reads all handshake messages from the homeservers
    /// 3. Replays them through the fresh `HandshakeState` to re-derive state
    /// 4. For transport restore: transitions to transport and sets nonces
    /// 5. For handshake restore: stops at the saved step position
    ///
    /// # Parameters:
    ///      - `config`: Shared configuration (must match the original session).
    ///      - `state`: The saved session state snapshot.
    ///
    /// # Errors:
    ///      - Returns [`PubkyDataError::SnowNoiseBuildError`] if the Noise stack fails to build.
    ///      - Returns [`PubkyDataError::RestoreReplayError`] if handshake replay fails.
    ///      - Returns [`PubkyDataError::RestoreHashMismatch`] if the replayed handshake
    ///        produces a different hash than the saved one.
    pub async fn restore(
        config: Arc<PubkyDataConfig>,
        state: PubkyDataSessionState,
        endpoint_pubkey: PublicKey,
    ) -> Result<Self, PubkyDataError> {
        // Verify the caller-provided pubkey matches the snapshot (consistency check)
        if endpoint_pubkey.to_bytes() != state.endpoint_pubkey {
            return Err(PubkyDataError::RestoreDeserializeError);
        }

        // Build a fresh context with the saved ephemeral key
        let mut context = DataLinkContext::new_with_ephemeral(
            state.pattern,
            state.initiator,
            vec![],
            state.static_secret,
            endpoint_pubkey.clone(),
            None,
            Some(state.ephemeral_secret),
        )
        .map_err(|_| PubkyDataError::SnowNoiseBuildError)?;

        // Determine the full sequence of handshake Write/Read actions
        let all_actions = full_handshake_actions(state.pattern, state.initiator);

        // Determine how many actions to replay:
        // - For transport restore: replay ALL handshake actions
        // - For handshake restore: replay up to the saved position
        let replay_all = state.phase == NoisePhase::Transport;

        // We need to figure out which homeserver slots correspond to which actions.
        // The counter tracks slot indices. During the original handshake:
        // - Write actions write to local homeserver at write_path/counter, then increment
        // - Read actions read from remote homeserver at read_path/counter, then increment
        //
        // For replay, we need to re-read ALL messages (both our own writes and
        // the peer's writes) from the homeservers and feed them through Snow.

        // Compute the local public key (for reading our own writes back)
        let _local_public_key = config.local_session.info().public_key();

        let mut replay_counter: u32 = 0;

        // How many actions were completed in the original session?
        // For transport: all of them. For handshake: we need to count.
        let actions_to_replay = if replay_all {
            all_actions.len()
        } else {
            // Count completed actions based on saved counter.
            // Each Write or Read increments the counter by 1.
            // The saved counter tells us how many Write/Read actions completed.
            state.counter as usize
        };

        for (i, action) in all_actions.iter().enumerate() {
            if i >= actions_to_replay {
                break;
            }

            match action {
                HandshakeAction::Write => {
                    // During replay, we need to re-read our own written message
                    // from the homeserver and feed it through Snow's write_message.
                    //
                    // However, Snow's write_message generates the message -- it doesn't
                    // consume an existing one. So for Write actions during replay,
                    // we just call write_message with empty payload (same as original)
                    // and discard the output. The important thing is that Snow's
                    // internal state advances correctly.
                    let mut message = [0; PUBKY_DATA_MSG_LEN];
                    context
                        .write_act(vec![], &mut message)
                        .map_err(|_| PubkyDataError::RestoreReplayError)?;
                    replay_counter += 1;
                }
                HandshakeAction::Read => {
                    // Read the peer's message from their homeserver
                    let read_path = config.read_path.as_str();
                    let formatted_path = format!("{endpoint_pubkey}/{read_path}/{replay_counter}");

                    let response = config
                        .outbox_client
                        .public_storage()
                        .get(formatted_path)
                        .await
                        .map_err(|_| PubkyDataError::RestoreReplayError)?;

                    if !response.status().is_success() {
                        return Err(PubkyDataError::RestoreReplayError);
                    }

                    let ciphertext = response
                        .bytes()
                        .await
                        .map_err(|_| PubkyDataError::RestoreReplayError)?;

                    if ciphertext.len() > PUBKY_DATA_MSG_LEN + 2 {
                        return Err(PubkyDataError::BadLengthCiphertext);
                    }

                    let mut buf_len = [0; 2];
                    buf_len[0..2].copy_from_slice(&ciphertext[0..2]);
                    let len = u16::from_be_bytes(buf_len) as usize;
                    let mut message = [0; PUBKY_DATA_MSG_LEN];
                    message[0..len].copy_from_slice(&ciphertext[2..len + 2]);
                    let mut payload = [0; PUBKY_DATA_MSG_LEN];

                    context
                        .read_act(&mut message, &mut payload, len)
                        .map_err(|_| PubkyDataError::RestoreReplayError)?;
                    replay_counter += 1;
                }
                HandshakeAction::Pending | HandshakeAction::Terminal => {
                    // These don't correspond to actual messages
                }
            }
        }

        // Now set the context state to match the saved snapshot
        let link_id;

        if state.phase == NoisePhase::Transport {
            // Verify the handshake completed
            if context.is_handshake() {
                return Err(PubkyDataError::RestoreReplayError);
            }

            // Verify handshake hash matches (integrity check)
            if let Some(saved_hash) = state.handshake_hash {
                if let Some(replayed_hash) = context.get_handshake_hash() {
                    if saved_hash != replayed_hash {
                        return Err(PubkyDataError::RestoreHashMismatch);
                    }
                }
            }

            // Transition to transport
            let hash = context.get_handshake_hash().unwrap();
            context
                .to_transport()
                .map_err(|_| PubkyDataError::RestoreReplayError)?;

            // Set nonces from saved state
            context.set_sending_nonce(state.sending_nonce);
            context.set_receiving_nonce(state.receiving_nonce);

            // Set counter to saved value (includes handshake + transport messages)
            context.set_counter(state.counter);

            link_id = if let Some(id) = state.link_id {
                Some(LinkId(id))
            } else {
                Some(LinkId(hash))
            };
        } else {
            // Handshake restore: set step/sub_step/counter
            context.set_noise_step(state.noise_step);
            context.set_sub_step_index(state.sub_step_index as usize);
            context.set_counter(state.counter);
            link_id = None;
        }

        Ok(PubkyDataEncryptor {
            config,
            context,
            link_id,
            endpoint_pubkey,
            simulate_tampering: false,
            last_ciphertext: None,
        })
    }

    /// Generate a backup of the current session state (legacy method).
    pub async fn generate_backup(&self, _commit: bool) -> Result<(), PubkyDataError> {
        self.persist_snapshot().await
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
