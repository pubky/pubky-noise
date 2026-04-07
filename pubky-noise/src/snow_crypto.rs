use ed25519_dalek::SecretKey;
use pubky::PublicKey;

use snow::Builder;
use snow::{HandshakeState, StatelessTransportState};

use crate::snow_crypto_resolver::ReplayResolver;

pub const PUBKY_NOISE_MSG_LEN: usize = 1000;
/// ChaChaPoly AEAD authentication tag size (Poly1305).
pub const PUBKY_NOISE_TAG_LEN: usize = 16;
/// Ciphertext buffer size: plaintext + AEAD tag.
pub const PUBKY_NOISE_CIPHERTEXT_LEN: usize = PUBKY_NOISE_MSG_LEN + PUBKY_NOISE_TAG_LEN;

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum NoisePhase {
    HandShake,
    Transport,
}

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum NoiseStep {
    StepOne,
    StepTwo,
    Final,
}

impl NoiseStep {
    pub fn next_step(&self) -> NoiseStep {
        match self {
            NoiseStep::StepOne => NoiseStep::StepTwo,
            NoiseStep::StepTwo => NoiseStep::Final,
            // if final echo final
            NoiseStep::Final => NoiseStep::Final,
        }
    }

    /// Convert to a u8 for serialization.
    pub fn to_u8(&self) -> u8 {
        match self {
            NoiseStep::StepOne => 0,
            NoiseStep::StepTwo => 1,
            NoiseStep::Final => 2,
        }
    }

    /// Convert from a u8 for deserialization.
    pub fn from_u8(val: u8) -> Option<NoiseStep> {
        match val {
            0 => Some(NoiseStep::StepOne),
            1 => Some(NoiseStep::StepTwo),
            2 => Some(NoiseStep::Final),
            _ => None,
        }
    }
}

#[derive(PartialEq, Eq)]
pub enum HandshakeAction {
    Read,
    Write,
    Pending,
    Terminal,
}

/// The source properties are:
///
/// 0. **No authentication**. This payload may have been sent by any party, including an active attacker.
///
/// 1. **Sender authentication vulnerable to key-compromise impersonation (KCI)**. The sender authentication
///    is based on a static-static DH ("ss") involving both parties' static key pairs. If the recipient's
///    long-term private key has been compromised, this authentication can be forged. Note that a future
///    version of Noise might include signatures, which could improve this security property, but brings
///    other trade-offs.
///
/// 2. **Sender authentication resistant to key-compromise impersonation (KCI)**. The sender authentication
///    is based on an ephemeral-static DH ("es" or "se") between the sender's static key pair and the recipient's
///    ephemeral key pair. Assuming the corresponding private keys are secure, this authentication cannot be
///    forged.
///
/// The destination properties are:
///
/// 0. **No confidentiality**. This payload is sent in cleartext.
///
/// 1. **Encryption to an ephemeral recipient**. This payload has forward secrecy, since encryption involves
///    an ephemeral-ephemeral DH ("ee"). However, the sender has not authenticated the recipient, so this payload
///    might be sent to any party, including an active attacker.
///
/// 2. **Encryption to a known recipient, forward secrecy for sender compromise only, vulnerable to replay**.
///    This payload is encrypted based only on DHs involving the recipient's static key pair. If the recipient's
///    static private key is compromised, even at a later date, this payload can be decrypted. This message can
///    also be replayed, since there's no ephemeral contribution from the recipient.
///
/// 3. **Encryption to a known recipient, weak forward secrecy**. This payload is encrypted based on an
///    ephemeral-ephemeral DH and also an ephemeral-static DH involving the recipient's static key pair. However,
///    the binding between the recipient's alleged ephemeral public key and the recipient's static public key
///    hasn't been verified by the sender, so the recipient's alleged ephemeral public key may have been forged
///    by an active attacker. In this case, the attacker could later compromise the recipient's static private
///    key to decrypt the payload. Note that a future version of Noise might include signatures, which could
///    improve this security property, but brings other trade-offs.
///
/// 4. **Encryption to a known recipient, weak forward secrecy if the sender's private key has been compromised**.
///    This payload is encrypted based on an ephemeral-ephemeral DH, and also based on an ephemeral-static DH
///    involving the recipient's static key pair. However, the binding between the recipient's alleged ephemeral
///    public and the recipient's static public key has only been verified based on DHs involving both those public
///    keys and the sender's static private key. Thus, if the sender's static private key was previously compromised,
///    the recipient's alleged ephemeral public key may have been forged by an active attacker. In this case, the
///    attacker could later compromise the intended recipient's static private key to decrypt the payload (this is
///    a variant of a "KCI" attack enabling a "weak forward secrecy" attack). Note that a future version of Noise
///    might include signatures, which could improve this security property, but brings other trade-offs.
///
/// 5. **Encryption to a known recipient, strong forward secrecy**. This payload is encrypted based on an
///    ephemeral-ephemeral DH as well as an ephemeral-static DH with the recipient's static key pair. Assuming
///    the ephemeral private keys are secure, and the recipient is not being actively impersonated by an attacker
///    that has stolen its static private key, this payload cannot be decrypted.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum HandshakePattern {
    /// <- s                      0                0
    /// ...
    /// -> e, es                  0                2
    PatternN,
    /// -> e                      0                0
    /// <- e, ee                  0                1
    /// ->                        0                1
    PatternNN,
    /// -> e                      0                0
    /// <- e, ee, s, es           2                1
    /// -> s, se                  2                5
    /// <-                        2                5
    PatternXX,
    /// <- s
    /// ...
    /// -> e, es, s, ss           1                2
    /// <- e, ee, se              2                4
    /// ->                        2                5
    /// <-                        2                5
    PatternIK,
    /// <- s
    /// ...
    /// -> e, es                  0                2
    /// <- e, ee                  2                1
    /// ->                        0                5
    PatternNK,

    // TODO ???:
    //   -> s
    //   <- s
    //   ...
    //   -> e, es, ss              1                2
    //   <- e, ee, se              2                4
    //   ->                        2                5
    //   <-                        2                5
    // KK
    //
    //   -> s
    //   ...
    //   -> e                      0                0
    //   <- e, ee, se, s, es       2                3
    //   ->                        2                5
    //   <-                        2                5
    // KX
    //
    //   -> e, s                   0                0
    //   <- e, ee, se              0                3
    //   ->                        2                1
    //   <-                        0                5
    // IN
    //
    //   <- s
    //   ...
    //   -> e, es, s, ss           1                2
    //   <- e, ee, se              2                4
    //   ->                        2                5
    //   <-                        2                5
    // IK
    //
    //   -> e, s                   0                0
    //   <- e, ee, se, s, es       2                3
    //   ->                        2                5
    //   <-                        2                5
    // IX
    //
    /// Test-only pattern to inject build fault.
    #[cfg(feature = "test-utils")]
    TestOnlyPatternAA,
}

pub enum PatternError {
    UnknownLiteralPattern,
}

impl std::str::FromStr for HandshakePattern {
    type Err = PatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "N" => Ok(HandshakePattern::PatternN),
            "NN" => Ok(HandshakePattern::PatternNN),
            "XX" => Ok(HandshakePattern::PatternXX),
            "IK" => Ok(HandshakePattern::PatternIK),
            "NK" => Ok(HandshakePattern::PatternNK),
            _ => Err(PatternError::UnknownLiteralPattern),
        }
    }
}

impl HandshakePattern {
    pub fn as_str(&self) -> &'static str {
        match self {
            HandshakePattern::PatternN => "N",
            HandshakePattern::PatternNN => "NN",
            HandshakePattern::PatternXX => "XX",
            HandshakePattern::PatternIK => "IK",
            HandshakePattern::PatternNK => "NK",
            #[cfg(feature = "test-utils")]
            HandshakePattern::TestOnlyPatternAA => "AA",
        }
    }

    pub fn needs_local_key(&self) -> bool {
        match self {
            HandshakePattern::PatternN => false,
            HandshakePattern::PatternNN => false,
            HandshakePattern::PatternXX => true,
            HandshakePattern::PatternIK => true,
            HandshakePattern::PatternNK => true,
            #[cfg(feature = "test-utils")]
            HandshakePattern::TestOnlyPatternAA => false,
        }
    }

    /// Convert to a u8 for serialization.
    pub fn to_u8(&self) -> u8 {
        match self {
            HandshakePattern::PatternN => 0,
            HandshakePattern::PatternNN => 1,
            HandshakePattern::PatternXX => 2,
            HandshakePattern::PatternIK => 3,
            HandshakePattern::PatternNK => 4,
            #[cfg(feature = "test-utils")]
            HandshakePattern::TestOnlyPatternAA => 255,
        }
    }

    /// Convert from a u8 for deserialization.
    pub fn from_u8(val: u8) -> Option<HandshakePattern> {
        match val {
            0 => Some(HandshakePattern::PatternN),
            1 => Some(HandshakePattern::PatternNN),
            2 => Some(HandshakePattern::PatternXX),
            3 => Some(HandshakePattern::PatternIK),
            4 => Some(HandshakePattern::PatternNK),
            #[cfg(feature = "test-utils")]
            255 => Some(HandshakePattern::TestOnlyPatternAA),
            _ => None,
        }
    }
}

pub fn resolve_pattern_nn(noise_step: NoiseStep, initiator: bool) -> Vec<HandshakeAction> {
    if initiator {
        match noise_step {
            NoiseStep::StepOne => vec![HandshakeAction::Write, HandshakeAction::Pending],
            NoiseStep::StepTwo => vec![HandshakeAction::Read],
            NoiseStep::Final => vec![HandshakeAction::Terminal],
        }
    } else {
        match noise_step {
            NoiseStep::StepOne => vec![HandshakeAction::Read, HandshakeAction::Write],
            NoiseStep::StepTwo => vec![HandshakeAction::Terminal],
            NoiseStep::Final => vec![HandshakeAction::Terminal],
        }
    }
}

pub fn resolve_pattern_xx(noise_step: NoiseStep, initiator: bool) -> Vec<HandshakeAction> {
    if initiator {
        match noise_step {
            NoiseStep::StepOne => vec![HandshakeAction::Write, HandshakeAction::Pending],
            NoiseStep::StepTwo => vec![HandshakeAction::Read, HandshakeAction::Write],
            NoiseStep::Final => vec![HandshakeAction::Terminal],
        }
    } else {
        match noise_step {
            NoiseStep::StepOne => {
                vec![
                    HandshakeAction::Read,
                    HandshakeAction::Write,
                    HandshakeAction::Pending,
                ]
            }
            NoiseStep::StepTwo => vec![HandshakeAction::Read],
            NoiseStep::Final => vec![HandshakeAction::Terminal],
        }
    }
}

/// Resolve the handshake actions for a given pattern, step, and role.
///
/// Only NN and XX patterns are currently implemented. IK and NK will
/// panic with "not yet implemented" if called.
fn resolve_pattern(
    pattern: HandshakePattern,
    noise_step: NoiseStep,
    initiator: bool,
) -> Vec<HandshakeAction> {
    match pattern {
        HandshakePattern::PatternNN => resolve_pattern_nn(noise_step, initiator),
        HandshakePattern::PatternXX => resolve_pattern_xx(noise_step, initiator),
        HandshakePattern::PatternN | HandshakePattern::PatternIK | HandshakePattern::PatternNK => {
            unimplemented!("handshake pattern {:?} is not yet implemented", pattern)
        }
        #[cfg(feature = "test-utils")]
        HandshakePattern::TestOnlyPatternAA => {
            panic!("TestOnlyPatternAA cannot be resolved to handshake actions")
        }
    }
}

/// Return the flat sequence of Write/Read actions for a complete handshake,
/// given the pattern and role (initiator/respnder). Used by the replay logic
/// to know which operations to perform when re-feeding persisted messages.
/// # Parameters:
///      - `pattern`: a handshake pattern
///      - `initiator`: boolean parameter which indicates who is initiator and who is responder
pub fn full_handshake_actions(pattern: HandshakePattern, initiator: bool) -> Vec<HandshakeAction> {
    let mut actions = Vec::new();
    let steps = [NoiseStep::StepOne, NoiseStep::StepTwo, NoiseStep::Final];
    for step in &steps {
        let step_actions = resolve_pattern(pattern, *step, initiator);
        for action in step_actions {
            match action {
                HandshakeAction::Write | HandshakeAction::Read => actions.push(action),
                HandshakeAction::Pending | HandshakeAction::Terminal => {
                    // Skip control actions; we only care about Write/Read for replay
                }
            }
        }
    }
    actions
}

//TODO: more granularity for errors
pub enum ContextError {
    Init,
    OngoingHandshake,
    InternalSnowTransitionErr,
    InternalSnowWriteErr,
    InternalSnowReadErr,
}

/// A Noise state machine
#[derive(Debug)]
pub struct DataLinkContext {
    initiator: bool,
    message_patterns: HandshakePattern,

    // ephemeral key always handled by the snow
    local_static_seckey: Option<SecretKey>,

    /// The local ephemeral secret key used for this session.
    /// Captured at construction time so it can be persisted for restore.
    local_ephemeral_seckey: [u8; 32],

    noise_step: NoiseStep,
    noise_phase: NoisePhase,

    noise_handshake: Option<HandshakeState>,
    noise_transport: Option<StatelessTransportState>,

    /// Explicit nonce for outbound transport messages.
    sending_nonce: u64,
    /// Explicit nonce for inbound transport messages.
    receiving_nonce: u64,

    endpoint_pubkey: PublicKey,

    counter: u32,

    // Tracks progress within the current step's action list for polling-safe handshake.
    // When a Read fails (peer hasn't written yet), we return Pending without advancing
    // sub_step_index, so the next poll retries from the same action.
    sub_step_index: usize,
}

impl DataLinkContext {
    /// Build the Snow protocol name string for the given pattern.
    /// We're using ChaCha as the stream cipher. Poly1305 as the MAC and SHA256 as a hash function.
    fn build_protocol_name(handshake_pattern: &HandshakePattern) -> String {
        format!(
            "Noise_{}_25519_ChaChaPoly_SHA256",
            handshake_pattern.as_str()
        )
    }

    /// Build a Snow HandshakeState using the ReplayResolver with the given ephemeral seed.
    fn build_handshake_state(
        protocol_name: &str,
        handshake_pattern: &HandshakePattern,
        initiator: bool,
        local_static_key: &Option<SecretKey>,
        ephemeral_seed: &[u8; 32],
    ) -> Result<HandshakeState, ContextError> {
        let params = protocol_name.parse().map_err(|_| ContextError::Init)?;

        let resolver = ReplayResolver::new(*ephemeral_seed);
        let builder = Builder::with_resolver(params, resolver);

        let noise_stack = if handshake_pattern.needs_local_key() {
            let key = local_static_key.as_ref().ok_or(ContextError::Init)?;
            if initiator {
                builder
                    .local_private_key(key)
                    .map_err(|_| ContextError::Init)?
                    .build_initiator()
            } else {
                builder
                    .local_private_key(key)
                    .map_err(|_| ContextError::Init)?
                    .build_responder()
            }
        } else if initiator {
            builder.build_initiator()
        } else {
            builder.build_responder()
        };

        noise_stack.map_err(|_| ContextError::Init)
    }

    pub fn new(
        handshake_pattern: HandshakePattern,
        initiator: bool,
        local_static_key: Option<SecretKey>,
        endpoint_pubkey: PublicKey,
    ) -> Result<DataLinkContext, ContextError> {
        Self::new_with_ephemeral(
            handshake_pattern,
            initiator,
            local_static_key,
            endpoint_pubkey,
            None,
        )
    }

    /// Create a new DataLinkContext, optionally with a pre-set ephemeral key.
    ///
    /// When `ephemeral_secret` is `None`, a fresh 32-byte random seed is generated.
    /// When `Some`, the provided seed is used (for session restore / replay).
    pub fn new_with_ephemeral(
        handshake_pattern: HandshakePattern,
        initiator: bool,
        local_static_key: Option<SecretKey>,
        endpoint_pubkey: PublicKey,
        ephemeral_secret: Option<[u8; 32]>,
    ) -> Result<DataLinkContext, ContextError> {
        // Section 5.3 The Handshake Object
        //
        // Perform the following steps:
        // - Derives a protocol_name byte sequence by combining the names for
        //   the handshake pattern and crypto functions, as specified in Section 8.
        //   Calls InitializeSymmetric(protocol_name).

        let protocol_name = Self::build_protocol_name(&handshake_pattern);

        // Generate or use provided ephemeral seed
        let ephemeral_seed = match ephemeral_secret {
            Some(seed) => seed,
            None => {
                let mut seed = [0u8; 32];
                getrandom::fill(&mut seed).map_err(|_| ContextError::Init)?;
                seed
            }
        };

        let handshake_state = Self::build_handshake_state(
            &protocol_name,
            &handshake_pattern,
            initiator,
            &local_static_key,
            &ephemeral_seed,
        )?;

        // - Sets the initator s, e, rs and re variables to the corresponding
        //   arguments.

        // - Calls MixHash() once for each public key listed in the pre-messages
        //   from handshake_pattern, with the specified public key as input (see
        //   Section 7 for an explanation of pre-messages). If both initiator and
        //   responder have pre-messages, the initiator's public key are hashed
        //   first. If multiple public keys are listed in either party's pre-message,
        //   the public keys are hashed in the order they are listed.

        Ok(DataLinkContext {
            initiator,
            message_patterns: handshake_pattern,

            //TODO: for now keep keys separated from the state.
            local_static_seckey: local_static_key,

            local_ephemeral_seckey: ephemeral_seed,

            noise_step: NoiseStep::StepOne,
            noise_phase: NoisePhase::HandShake,

            noise_handshake: Some(handshake_state),
            noise_transport: None,

            sending_nonce: 0,
            receiving_nonce: 0,

            endpoint_pubkey,

            counter: 0,

            sub_step_index: 0,
        })
    }

    pub fn get_endpoint(&self) -> &PublicKey {
        &self.endpoint_pubkey
    }

    pub fn get_counter(&self) -> u32 {
        self.counter
    }

    //TODO: counter overflow
    pub fn increment_counter(&mut self) {
        self.counter += 1;
    }

    pub fn delete(&mut self) {
        if let Some(seckey) = &mut self.local_static_seckey {
            seckey.as_mut_slice().copy_from_slice(&[0; 32][..]);
        }
        self.local_static_seckey = None;
        self.local_ephemeral_seckey.copy_from_slice(&[0; 32][..]);
    }

    pub fn is_handshake(&self) -> bool {
        match &self.noise_handshake {
            Some(hs) => !hs.is_handshake_finished(),
            None => false,
        }
    }

    /// Check if this context is in transport phase.
    pub fn is_transport(&self) -> bool {
        self.noise_phase == NoisePhase::Transport
    }

    pub fn get_handshake_hash(&self) -> Option<[u8; 32]> {
        if let Some(handshake_state) = &self.noise_handshake {
            let mut buf = [0; 32];
            let hash = handshake_state.get_handshake_hash();
            assert_eq!(hash.len(), 32);
            buf[0..32].copy_from_slice(&hash[0..32]);
            return Some(buf);
        }
        None
    }

    pub fn to_transport(&mut self) -> Result<(), ContextError> {
        let hs = self
            .noise_handshake
            .as_ref()
            .ok_or(ContextError::OngoingHandshake)?;
        if !hs.is_handshake_finished() {
            return Err(ContextError::OngoingHandshake);
        }
        let transport = self
            .noise_handshake
            .take()
            .unwrap()
            .into_stateless_transport_mode()
            .map_err(|_| ContextError::InternalSnowTransitionErr)?;
        self.noise_transport = Some(transport);
        self.noise_phase = NoisePhase::Transport;
        self.sending_nonce = 0;
        self.receiving_nonce = 0;
        Ok(())
    }

    /// Returns the remaining actions for the current step, starting from sub_step_index.
    /// Uses the stored `initiator` flag -- callers no longer need to pass it.
    /// Does NOT advance noise_step -- call `complete_step()` for that.
    pub fn remaining_handshake_actions(&self) -> Vec<HandshakeAction> {
        let all_actions = resolve_pattern(self.message_patterns, self.noise_step, self.initiator);
        all_actions.into_iter().skip(self.sub_step_index).collect()
    }

    /// Mark one sub-step action as completed, advancing the sub-step index.
    pub fn advance_sub_step(&mut self) {
        self.sub_step_index += 1;
    }

    /// Complete the current step and move to the next one, resetting sub-step index.
    pub fn complete_step(&mut self) {
        self.noise_step = self.noise_step.next_step();
        self.sub_step_index = 0;
    }

    pub fn write_act(
        &mut self,
        payload: &[u8],
        message: &mut [u8; PUBKY_NOISE_CIPHERTEXT_LEN],
    ) -> Result<usize, ContextError> {
        match self.noise_phase {
            NoisePhase::HandShake => self
                .noise_handshake
                .as_mut()
                .unwrap()
                .write_message(payload, message.as_mut())
                .map_err(|_| ContextError::InternalSnowWriteErr),
            NoisePhase::Transport => {
                let nonce = self.sending_nonce;
                let size = self
                    .noise_transport
                    .as_ref()
                    .unwrap()
                    .write_message(nonce, payload, message.as_mut())
                    .map_err(|_| ContextError::InternalSnowWriteErr)?;
                // NOTE: sending_nonce is NOT incremented here. The caller
                // must call increment_sending_nonce() after confirming the
                // write reached the homeserver. This prevents nonce desync
                // when put() fails after a successful encryption.
                Ok(size)
            }
        }
    }

    pub fn read_act(
        &mut self,
        message: &mut [u8; PUBKY_NOISE_CIPHERTEXT_LEN],
        payload: &mut [u8; PUBKY_NOISE_MSG_LEN],
        index: usize,
    ) -> Result<(), ContextError> {
        match self.noise_phase {
            NoisePhase::HandShake => {
                self.noise_handshake
                    .as_mut()
                    .unwrap()
                    .read_message(&message[..index], payload)
                    .map_err(|_| ContextError::InternalSnowReadErr)?;
                Ok(())
            }
            NoisePhase::Transport => {
                self.noise_transport
                    .as_ref()
                    .unwrap()
                    .read_message(self.receiving_nonce, &message[..index], payload)
                    .map_err(|_| ContextError::InternalSnowReadErr)?;
                self.receiving_nonce += 1;
                Ok(())
            }
        }
    }

    // --- Snapshot / restore accessors ---

    /// Get the current noise phase.
    pub fn get_phase(&self) -> NoisePhase {
        self.noise_phase
    }

    /// Get the handshake pattern.
    pub fn get_pattern(&self) -> HandshakePattern {
        self.message_patterns
    }

    /// Whether this side is the initiator.
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    /// Get the local ephemeral secret key (for backup/restore).
    pub fn get_ephemeral_secret(&self) -> &[u8; 32] {
        &self.local_ephemeral_seckey
    }

    /// Get the local static secret key (for backup/restore).
    pub fn get_static_secret(&self) -> Option<&SecretKey> {
        self.local_static_seckey.as_ref()
    }

    /// Get the current noise step.
    pub fn get_noise_step(&self) -> NoiseStep {
        self.noise_step
    }

    /// Get the current sub-step index.
    pub fn get_sub_step_index(&self) -> usize {
        self.sub_step_index
    }

    /// Get the sending nonce (transport phase).
    pub fn get_sending_nonce(&self) -> u64 {
        self.sending_nonce
    }

    /// Get the receiving nonce (transport phase).
    pub fn get_receiving_nonce(&self) -> u64 {
        self.receiving_nonce
    }

    /// Set the counter (used during restore).
    pub fn set_counter(&mut self, counter: u32) {
        self.counter = counter;
    }

    /// Set the noise step (used during restore).
    pub fn set_noise_step(&mut self, step: NoiseStep) {
        self.noise_step = step;
    }

    /// Set the sub-step index (used during restore).
    pub fn set_sub_step_index(&mut self, index: usize) {
        self.sub_step_index = index;
    }

    /// Advance the sending nonce by 1.
    ///
    /// Call this **after** confirming the encrypted message was successfully
    /// written to the homeserver. This ensures the nonce stays in sync with
    /// what the receiver expects, even if a write fails.
    pub fn increment_sending_nonce(&mut self) {
        self.sending_nonce += 1;
    }

    /// Set the sending nonce (used during restore after transport transition).
    pub fn set_sending_nonce(&mut self, nonce: u64) {
        self.sending_nonce = nonce;
    }

    /// Set the receiving nonce (used during restore after transport transition).
    pub fn set_receiving_nonce(&mut self, nonce: u64) {
        self.receiving_nonce = nonce;
    }
}
