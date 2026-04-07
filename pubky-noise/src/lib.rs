pub mod identity_payload;
pub mod path_derivation;
pub mod serializer;
pub mod snow_crypto;
pub mod snow_crypto_resolver;

use std::str::FromStr;
use std::sync::Arc;

use pubky::prelude::*;
use pubky::PubkySession;

use serializer::PubkyNoiseSessionState;
use snow_crypto::{
    full_handshake_actions, DataLinkContext, HandshakeAction, HandshakePattern, NoisePhase,
    PUBKY_NOISE_MSG_LEN,
};

/// A 32-byte identifier derived from the Noise handshake.
///
/// If ephemeral keys are used by the Noise pattern relied
/// on for the handshake, should change after every handshake.
#[derive(Eq, Hash, PartialEq, Clone, Copy, Debug)]
pub struct LinkId(pub [u8; 32]);

/// Decode a length-prefixed packet into a message buffer and its length.
///
/// Wire format: `[len_hi, len_lo, payload...]` where len is big-endian u16.
fn decode_packet(ciphertext: &[u8]) -> Result<([u8; PUBKY_NOISE_MSG_LEN], usize), PubkyNoiseError> {
    if ciphertext.len() > PUBKY_NOISE_MSG_LEN + 2 {
        return Err(PubkyNoiseError::BadLengthCiphertext);
    }
    let len = u16::from_be_bytes([ciphertext[0], ciphertext[1]]) as usize;
    let mut message = [0u8; PUBKY_NOISE_MSG_LEN];
    message[..len].copy_from_slice(&ciphertext[2..len + 2]);
    Ok((message, len))
}

/// Encode a message into a length-prefixed packet.
///
/// Wire format: `[len_hi, len_lo, payload...]` where len is big-endian u16.
fn encode_packet(data: &[u8], len: usize) -> [u8; PUBKY_NOISE_MSG_LEN + 2] {
    let mut packet = [0u8; PUBKY_NOISE_MSG_LEN + 2];
    let be_bytes = (len as u16).to_be_bytes();
    packet[0..2].copy_from_slice(&be_bytes);
    packet[2..len + 2].copy_from_slice(&data[..len]);
    packet
}

#[derive(Eq, Hash, PartialEq, Debug)]
pub enum PubkyNoiseError {
    UnknownNoisePattern,
    SnowNoiseBuildError,
    BadLengthCiphertext,
    /// the homeserver response is a failure
    HomeserverResponseError,
    /// Handshake write failed to reach the homeserver.
    /// The Noise state has already advanced irreversibly; recovery requires
    /// restoring from [`PubkyNoiseEncryptor::last_good_snapshot()`].
    HomeserverWriteError,
    IsHandshake,
    /// Restore failed: handshake replay error.
    RestoreReplayError,
    /// Restore failed: handshake hash mismatch after replay.
    RestoreHashMismatch,
    /// Restore failed: deserialization error.
    RestoreDeserializeError,
    /// Transport-phase encryption (write_act) failed.
    EncryptionError,
    /// Transport-phase decryption (read_act) failed.
    DecryptionError,
    OtherError,
}

#[derive(Eq, Hash, PartialEq, Debug)]
pub enum HandshakeResult {
    Pending,
    Terminal,
}

/// Shared configuration and resources for multiple `PubkyNoiseEncryptor` instances.
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
/// same value to both fields via [`PubkyNoiseConfig::new`].
///
/// For per-peer-pair path privacy, use [`path_derivation::derive_asymmetric_paths`]
/// to compute distinct write/read paths from a DH shared secret.
pub struct PubkyNoiseConfig {
    pub outbox_client: Pubky,
    pub local_session: PubkySession,
    /// Folder prefix for writing messages to the local homeserver.
    pub write_path: String,
    /// Folder prefix for reading messages from the remote homeserver.
    pub read_path: String,
    pub pubky_root_keypair: Keypair,
    pub pubky_noise_version: u32,
    pub default_pattern: HandshakePattern,
}

impl PubkyNoiseConfig {
    /// Create a new shared configuration with a single symmetric path.
    ///
    /// This is a convenience constructor that uses the same path for both
    /// reading and writing. For per-peer-pair path privacy, use
    /// [`PubkyNoiseConfig::new_with_paths`] instead.
    ///
    /// # Parameters:
    ///      - `pubky_root_seckey`: A 32-byte root secret key.
    ///      - `pubky_noise_version`: Protocol version identifier.
    ///      - `pattern_string`: Default Noise pattern (e.g. "NN", "XX").
    ///      - `homeserver_auth_session`: An authenticated PubkySession.
    ///      - `destination_path`: Custom destination prefix for message sharing
    ///        (used for both reads and writes).
    ///      - `outbox_client`: HTTP Pubky client.
    ///
    /// # Errors:
    ///      - Returns [`PubkyNoiseError::UnknownNoisePattern`] if the pattern string is invalid.
    pub fn new(
        pubky_root_seckey: [u8; 32],
        pubky_noise_version: u32,
        pattern_string: &str,
        homeserver_auth_session: PubkySession,
        destination_path: String,
        outbox_client: Pubky,
    ) -> Result<Arc<Self>, PubkyNoiseError> {
        Self::new_with_paths(
            pubky_root_seckey,
            pubky_noise_version,
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
    ///      - `pubky_noise_version`: Protocol version identifier.
    ///      - `pattern_string`: Default Noise pattern (e.g. "NN", "XX").
    ///      - `homeserver_auth_session`: An authenticated PubkySession.
    ///      - `write_path`: Folder prefix for writing messages to the local homeserver.
    ///      - `read_path`: Folder prefix for reading messages from the remote homeserver.
    ///      - `outbox_client`: HTTP Pubky client.
    ///
    /// # Errors:
    ///      - Returns [`PubkyNoiseError::UnknownNoisePattern`] if the pattern string is invalid.
    pub fn new_with_paths(
        pubky_root_seckey: [u8; 32],
        pubky_noise_version: u32,
        pattern_string: &str,
        homeserver_auth_session: PubkySession,
        write_path: String,
        read_path: String,
        outbox_client: Pubky,
    ) -> Result<Arc<Self>, PubkyNoiseError> {
        let pubky_root_keypair = Keypair::from_secret(&pubky_root_seckey);
        let default_pattern = HandshakePattern::from_str(pattern_string)
            .map_err(|_| PubkyNoiseError::UnknownNoisePattern)?;

        Ok(Arc::new(PubkyNoiseConfig {
            outbox_client,
            local_session: homeserver_auth_session,
            write_path,
            read_path,
            pubky_root_keypair,
            pubky_noise_version,
            default_pattern,
        }))
    }
}

/// A single-session Noise encryptor for Pubky Noise.
///
/// Each instance manages exactly one Noise session (handshake + transport) with
/// a single remote peer. To manage multiple concurrent sessions, create multiple
/// `PubkyNoiseEncryptor` instances sharing the same `Arc<PubkyNoiseConfig>`.
#[derive(Debug)]
pub struct PubkyNoiseEncryptor {
    config: Arc<PubkyNoiseConfig>,
    context: DataLinkContext,
    link_id: Option<LinkId>,
    endpoint_pubkey: PublicKey,

    /// Snapshot captured automatically at the start of each
    /// [`handle_handshake()`](Self::handle_handshake) call, before any
    /// state-mutating work. See [`last_good_snapshot()`](Self::last_good_snapshot).
    last_good_snapshot: Option<PubkyNoiseSessionState>,

    // test-only fields — stripped from production builds
    #[cfg(feature = "test-utils")]
    simulate_tampering: bool,
    #[cfg(feature = "test-utils")]
    simulate_write_failure: bool,
    #[cfg(feature = "test-utils")]
    last_ciphertext: Option<[u8; PUBKY_NOISE_MSG_LEN + 2]>,
}

impl PubkyNoiseEncryptor {
    /// Create a new single-session Noise encryptor.
    ///
    /// # Parameters:
    ///      - `config`: Shared configuration (wrapped in Arc).
    ///      - `holder_skey`: Local static secret key for this session.
    ///      - `initiator`: Whether this side initiates the Noise handshake.
    ///      - `endpoint_pubkey`: Remote peer's public key used as path suffix.
    ///
    /// # Errors:
    ///      - Returns [`PubkyNoiseError::SnowNoiseBuildError`] if the Noise stack fails to build.
    pub fn new(
        config: Arc<PubkyNoiseConfig>,
        mut holder_skey: [u8; 32],
        initiator: bool,
        endpoint_pubkey: PublicKey,
    ) -> Result<Self, PubkyNoiseError> {
        let data_link_context = DataLinkContext::new(
            config.default_pattern,
            initiator,
            Some(holder_skey),
            endpoint_pubkey.clone(),
        )
        .map_err(|_| PubkyNoiseError::SnowNoiseBuildError)?;

        // zeroize holder_skey after DataLinkContext load.
        holder_skey.copy_from_slice(&[0; 32][..]);
        //TODO: add assert on holder_skey byte pattern

        Ok(PubkyNoiseEncryptor {
            config,
            context: data_link_context,
            link_id: None,
            endpoint_pubkey,
            last_good_snapshot: None,
            #[cfg(feature = "test-utils")]
            simulate_tampering: false,
            #[cfg(feature = "test-utils")]
            simulate_write_failure: false,
            #[cfg(feature = "test-utils")]
            last_ciphertext: None,
        })
    }

    /// Returns `true` if the Noise handshake has completed.
    pub fn is_handshake_complete(&self) -> bool {
        !self.context.is_handshake()
    }

    /// Handle the forwarding and processing of Noise handshake messages.
    ///
    /// This method is **polling-safe**: it can be called repeatedly by either
    /// the initiator or responder in any order. If the peer's message is not
    /// yet available, returns `HandshakeResult::Pending` without advancing state.
    ///
    /// # Outbox reliability and recovery
    ///
    /// In the outbox model, two kinds of interruption can occur:
    ///
    /// - **Read failure** (Responder fails to read from Initiator's outbox):
    ///   The method returns `Pending` without advancing `step`, `sub_step`, or
    ///   `counter`. Subsequent calls will retry the same read and succeed once
    ///   the message appears. No special recovery is needed.
    ///
    /// - **Write failure** (Initiator fails to write to her outbox):
    ///   If the homeserver `put()` call fails, this method returns
    ///   [`PubkyNoiseError::HomeserverWriteError`]. Because Snow's internal
    ///   `HandshakeState` has already been irreversibly advanced by
    ///   `write_message`, the encryptor is in a corrupted state and **cannot**
    ///   simply retry. The caller must recover by restoring from the
    ///   pre-mutation snapshot captured at the start of this call.
    ///
    ///   **Recovery**: each call to `handle_handshake` automatically captures
    ///   a pre-mutation snapshot accessible via
    ///   [`last_good_snapshot()`](Self::last_good_snapshot). Callers should
    ///   persist this snapshot (e.g. via [`persist_snapshot()`](Self::persist_snapshot))
    ///   so that on restart they can pass it to if there has been a failure
    ///   [`restore()`](Self::restore).
    ///   The replay mechanism will rebuild the Noise state from what is
    ///   actually on the homeservers, correcting the state and allowing the
    ///   handshake to resume from the right position.
    ///
    ///   Note: if the `put()` succeeds but the data is subsequently lost
    ///   (e.g. homeserver crash after acknowledgment), the same snapshot-based
    ///   recovery path applies — but the failure is not detectable by this
    ///   method.
    ///
    /// # Errors:
    ///      - Returns [`PubkyNoiseError::BadLengthCiphertext`] on malformed messages.
    ///      - Returns [`PubkyNoiseError::HomeserverResponseError`] on response parse failure.
    ///      - Returns [`PubkyNoiseError::HomeserverWriteError`] if the homeserver
    ///        write fails. Recovery via [`last_good_snapshot()`](Self::last_good_snapshot)
    ///        and [`restore()`](Self::restore) is required.
    pub async fn handle_handshake(&mut self) -> Result<HandshakeResult, PubkyNoiseError> {
        // Capture pre-mutation snapshot so callers can recover from write failures.
        self.last_good_snapshot = Some(self.snapshot());

        let remaining_actions = self.context.remaining_handshake_actions();
        for action in remaining_actions {
            match action {
                HandshakeAction::Read => {
                    let path = self.config.read_path.as_str();
                    let counter = self.context.get_counter();
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
                                let (mut message, len) = decode_packet(&ciphertext)?;
                                let mut payload = [0; PUBKY_NOISE_MSG_LEN];
                                let _ = self.context.read_act(&mut message, &mut payload, len);
                            } else {
                                return Err(PubkyNoiseError::HomeserverResponseError);
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
                    let mut message = [0; PUBKY_NOISE_MSG_LEN];
                    if let Ok(len) = self.context.write_act(&[], &mut message) {
                        let path = self.config.write_path.as_str();
                        let counter = self.context.get_counter();
                        let formatted_path = format!("{path}/{counter}");
                        let packet = encode_packet(&message, len);
                        // Check for simulated write failure (test-only) or
                        // actual homeserver write failure.
                        #[cfg(feature = "test-utils")]
                        let write_failed = if self.simulate_write_failure {
                            true
                        } else {
                            self.config
                                .local_session
                                .storage()
                                .put(formatted_path, packet.to_vec())
                                .await
                                .is_err()
                        };
                        #[cfg(not(feature = "test-utils"))]
                        let write_failed = self
                            .config
                            .local_session
                            .storage()
                            .put(formatted_path, packet.to_vec())
                            .await
                            .is_err();
                        if write_failed {
                            // Snow's HandshakeState has already advanced
                            // irreversibly. The caller must recover via
                            // last_good_snapshot() + restore().
                            return Err(PubkyNoiseError::HomeserverWriteError);
                        }
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
    /// Call this once `is_handshake_complete()` returns `true`.
    /// Returns the `LinkId` derived from the handshake transcript hash.
    ///
    /// # Errors:
    ///      - Returns [`PubkyNoiseError::IsHandshake`] if still in handshake phase.
    pub fn transition_transport(&mut self) -> Result<LinkId, PubkyNoiseError> {
        if self.context.is_handshake() {
            return Err(PubkyNoiseError::IsHandshake);
        }
        let link_id = LinkId(self.context.get_handshake_hash().unwrap());
        let _ = self.context.to_transport();
        self.link_id = Some(link_id);
        Ok(link_id)
    }

    /// Encrypt and send plaintext over the established transport.
    ///
    /// # Errors:
    ///      - Returns [`PubkyNoiseError::IsHandshake`] if not yet in transport phase.
    ///      - Returns [`PubkyNoiseError::EncryptionError`] if Noise encryption fails.
    ///      - Returns [`PubkyNoiseError::HomeserverWriteError`] if the homeserver
    ///        write fails.
    pub async fn send_message(&mut self, plaintext: &[u8]) -> Result<(), PubkyNoiseError> {
        // Phase guard: must be in transport mode
        if !self.context.is_transport() {
            return Err(PubkyNoiseError::IsHandshake);
        }

        let mut out = [0; PUBKY_NOISE_MSG_LEN];
        let len = self
            .context
            .write_act(plaintext, &mut out)
            .map_err(|_| PubkyNoiseError::EncryptionError)?;

        let packet = encode_packet(&out, len);

        #[cfg(feature = "test-utils")]
        if self.simulate_tampering {
            self.last_ciphertext = Some(packet);
        }

        let path = self.config.write_path.as_str();
        let counter = self.context.get_counter();
        let formatted_path = format!("{path}/{counter}");
        self.config
            .local_session
            .storage()
            .put(formatted_path, packet.to_vec())
            .await
            .map_err(|_| PubkyNoiseError::HomeserverWriteError)?;
        // Advance the sending nonce only after the write is confirmed.
        // write_act() no longer increments the nonce internally, so that
        // a failed put() does not desynchronize the nonce with the receiver.
        self.context.increment_sending_nonce();
        self.context.increment_counter();
        Ok(())
    }

    /// Receive and decrypt a message from the remote peer.
    ///
    /// Returns `Ok` with an empty vector when no message is available yet
    /// (normal polling behaviour).
    ///
    /// # Errors:
    ///      - Returns [`PubkyNoiseError::IsHandshake`] if not yet in transport phase.
    ///      - Returns [`PubkyNoiseError::HomeserverResponseError`] if the response body
    ///        cannot be read.
    ///      - Returns [`PubkyNoiseError::BadLengthCiphertext`] if the packet is malformed.
    ///      - Returns [`PubkyNoiseError::DecryptionError`] if Noise decryption fails.
    pub async fn receive_message(
        &mut self,
    ) -> Result<Vec<[u8; PUBKY_NOISE_MSG_LEN]>, PubkyNoiseError> {
        // Phase guard: must be in transport mode
        if !self.context.is_transport() {
            return Err(PubkyNoiseError::IsHandshake);
        }

        let mut results = Vec::new();
        let path = self.config.read_path.as_str();
        let counter = self.context.get_counter();
        let public_key = self.context.get_endpoint();
        let formatted_path = format!("{public_key}/{path}/{counter}");
        if let Ok(response) = self
            .config
            .outbox_client
            .public_storage()
            .get(formatted_path)
            .await
        {
            if response.status().is_success() {
                let ciphertext = response
                    .bytes()
                    .await
                    .map_err(|_| PubkyNoiseError::HomeserverResponseError)?;
                let (mut message, len) = decode_packet(&ciphertext)?;
                let mut payload = [0; PUBKY_NOISE_MSG_LEN];

                #[cfg(feature = "test-utils")]
                if self.simulate_tampering {
                    message[1] = 0xff;
                }

                self.context
                    .read_act(&mut message, &mut payload, len)
                    .map_err(|_| PubkyNoiseError::DecryptionError)?;
                results.push(payload);
                self.context.increment_counter();
            }
        }
        Ok(results)
    }

    /// Close and clean up this encryptor's Noise session.
    pub fn close(&mut self) {
        self.context.delete();
        // when the last atomically reference counted pointer
        // to the config including the pubky_root_seckey, the
        // inner value allocation is destroyed.
        // TODO: verify the Arc implementation to check what
        // is mean by destroyed, it the memory free'd ?
    }

    /// Capture the current session state as a serializable snapshot.
    ///
    /// This snapshot contains everything needed to restore the session later
    /// by replaying persisted handshake messages.
    ///
    /// During the handshake phase, a pre-mutation snapshot is captured
    /// automatically by [`handle_handshake()`](Self::handle_handshake) and
    /// is accessible via [`last_good_snapshot()`](Self::last_good_snapshot).
    /// This method remains useful for taking snapshots at arbitrary points
    /// (e.g. after transitioning to transport or after exchanging messages).
    pub fn snapshot(&self) -> PubkyNoiseSessionState {
        let phase = self.context.get_phase();
        let handshake_hash = self.context.get_handshake_hash();

        PubkyNoiseSessionState {
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
    pub async fn persist_snapshot(&self) -> Result<(), PubkyNoiseError> {
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
            .map_err(|_| PubkyNoiseError::OtherError)?;
        Ok(())
    }

    /// Restore a `PubkyNoiseEncryptor` from a previously saved session state.
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
    ///      - Returns [`PubkyNoiseError::SnowNoiseBuildError`] if the Noise stack fails to build.
    ///      - Returns [`PubkyNoiseError::RestoreReplayError`] if handshake replay fails.
    ///      - Returns [`PubkyNoiseError::RestoreHashMismatch`] if the replayed handshake
    ///        produces a different hash than the saved one.
    pub async fn restore(
        config: Arc<PubkyNoiseConfig>,
        state: PubkyNoiseSessionState,
        endpoint_pubkey: PublicKey,
    ) -> Result<Self, PubkyNoiseError> {
        // Verify the caller-provided pubkey matches the snapshot (consistency check)
        if endpoint_pubkey.to_bytes() != state.endpoint_pubkey {
            return Err(PubkyNoiseError::RestoreDeserializeError);
        }

        // Build a fresh context with the saved ephemeral key
        let mut context = DataLinkContext::new_with_ephemeral(
            state.pattern,
            state.initiator,
            state.static_secret,
            endpoint_pubkey.clone(),
            Some(state.ephemeral_secret),
        )
        .map_err(|_| PubkyNoiseError::SnowNoiseBuildError)?;

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
                    let mut message = [0; PUBKY_NOISE_MSG_LEN];
                    context
                        .write_act(&[], &mut message)
                        .map_err(|_| PubkyNoiseError::RestoreReplayError)?;
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
                        .map_err(|_| PubkyNoiseError::RestoreReplayError)?;

                    if !response.status().is_success() {
                        return Err(PubkyNoiseError::RestoreReplayError);
                    }

                    let ciphertext = response
                        .bytes()
                        .await
                        .map_err(|_| PubkyNoiseError::RestoreReplayError)?;

                    let (mut message, len) = decode_packet(&ciphertext)?;
                    let mut payload = [0; PUBKY_NOISE_MSG_LEN];

                    context
                        .read_act(&mut message, &mut payload, len)
                        .map_err(|_| PubkyNoiseError::RestoreReplayError)?;
                    replay_counter += 1;
                }
                HandshakeAction::Pending | HandshakeAction::Terminal => {
                    // These don't correspond to actual messages
                }
            }
        }

        // Now set the context state to match the saved snapshot
        let link_id = if state.phase == NoisePhase::Transport {
            // Verify the handshake completed
            if context.is_handshake() {
                return Err(PubkyNoiseError::RestoreReplayError);
            }

            // Verify handshake hash matches (integrity check)
            if let Some(saved_hash) = state.handshake_hash {
                if let Some(replayed_hash) = context.get_handshake_hash() {
                    if saved_hash != replayed_hash {
                        return Err(PubkyNoiseError::RestoreHashMismatch);
                    }
                }
            }

            // Transition to transport
            let hash = context.get_handshake_hash().unwrap();
            context
                .to_transport()
                .map_err(|_| PubkyNoiseError::RestoreReplayError)?;

            // Set nonces from saved state
            context.set_sending_nonce(state.sending_nonce);
            context.set_receiving_nonce(state.receiving_nonce);

            // Set counter to saved value (includes handshake + transport messages)
            context.set_counter(state.counter);

            Some(LinkId(state.link_id.unwrap_or(hash)))
        } else {
            // Handshake restore: set step/sub_step/counter
            context.set_noise_step(state.noise_step);
            context.set_sub_step_index(state.sub_step_index as usize);
            context.set_counter(state.counter);
            None
        };

        Ok(PubkyNoiseEncryptor {
            config,
            context,
            link_id,
            endpoint_pubkey,
            last_good_snapshot: None,
            #[cfg(feature = "test-utils")]
            simulate_tampering: false,
            #[cfg(feature = "test-utils")]
            simulate_write_failure: false,
            #[cfg(feature = "test-utils")]
            last_ciphertext: None,
        })
    }

    /// Get the LinkId for this session (available after transition_transport).
    pub fn get_link_id(&self) -> Option<LinkId> {
        self.link_id
    }

    /// Returns the snapshot captured at the start of the last
    /// [`handle_handshake()`](Self::handle_handshake) call, before any
    /// state-mutating work.
    ///
    /// The snapshot always reflects the state just before the **most recent**
    /// `handle_handshake` call — each call overwrites the previous snapshot.
    /// Callers that need to preserve a specific pre-failure snapshot should
    /// clone or persist it before the next `handle_handshake` call.
    ///
    /// If a write to the local homeserver was lost during the handshake, the
    /// caller can pass the persisted snapshot to [`restore()`](Self::restore)
    /// to recover the session.
    ///
    /// Returns `None` if `handle_handshake` has never been called.
    pub fn last_good_snapshot(&self) -> Option<&PubkyNoiseSessionState> {
        self.last_good_snapshot.as_ref()
    }

    /// Test-only: enable ciphertext tampering simulation.
    #[cfg(feature = "test-utils")]
    pub fn test_enable_tampering(&mut self) {
        self.simulate_tampering = true;
    }

    /// Test-only: simulate homeserver write failures during handshake.
    ///
    /// When enabled, `handle_handshake` will skip the `put()` call and
    /// return `Err(PubkyNoiseError::HomeserverWriteError)` on Write actions.
    #[cfg(feature = "test-utils")]
    pub fn test_enable_write_failure(&mut self) {
        self.simulate_write_failure = true;
    }

    /// Test-only: get the last ciphertext produced by send_message.
    #[cfg(feature = "test-utils")]
    pub fn test_last_ciphertext(&self) -> Option<[u8; PUBKY_NOISE_MSG_LEN + 2]> {
        self.last_ciphertext
    }
}

impl std::fmt::Debug for PubkyNoiseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PubkyNoiseConfig")
            .field("write_path", &self.write_path)
            .field("read_path", &self.read_path)
            .field("pubky_noise_version", &self.pubky_noise_version)
            .field("default_pattern", &self.default_pattern)
            .finish_non_exhaustive()
    }
}
