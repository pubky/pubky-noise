//! Session state serialization for backup and restore.
//!
//! [`PubkyNoiseSessionState`] captures all the information needed to restore a
//! `PubkyNoiseEncryptor` session, whether it was interrupted during the handshake
//! or is already in transport mode.

use crate::snow_crypto::{HandshakePattern, NoisePhase, NoiseStep};

/// Current serialization format version.
pub const SESSION_STATE_VERSION: u8 = 1;
const SESSION_STATE_LEN: usize = 197;
/// Noise reserves 2^64 - 1, so 2^64 - 2 is the last usable nonce.
const MAX_USABLE_NOISE_NONCE: u64 = u64::MAX - 1;

/// Serializable snapshot of a `PubkyNoiseEncryptor` session.
///
/// This struct contains everything needed to reconstruct the Noise session
/// by replaying persisted handshake messages through a fresh `HandshakeState`
/// built with the same ephemeral key material.
#[derive(Debug, Clone)]
pub struct PubkyNoiseSessionState {
    /// Format version for forward compatibility.
    pub version: u8,
    /// Current phase: Handshake or Transport.
    pub phase: NoisePhase,
    /// The Noise handshake pattern (NN, XX, etc.).
    pub pattern: HandshakePattern,
    /// Whether this side is the initiator.
    pub initiator: bool,
    /// The local ephemeral secret key seed (32 bytes).
    /// This is the critical piece that allows replay to re-derive
    /// the same transport keys.
    pub ephemeral_secret: [u8; 32],
    /// The local static secret key (32 bytes), if the pattern requires one.
    pub static_secret: Option<[u8; 32]>,
    /// Handshake message slot counter, or transport base slot after handshake.
    pub counter: u32,
    /// Which handshake step we're at.
    pub noise_step: NoiseStep,
    /// Progress within the current step's action list.
    pub sub_step_index: u8,
    /// The handshake transcript hash (available after handshake completes).
    pub handshake_hash: Option<[u8; 32]>,
    /// The link ID (available after transition_transport).
    pub link_id: Option<[u8; 32]>,
    /// Transport sending nonce.
    pub sending_nonce: u64,
    /// Transport receiving nonce.
    pub receiving_nonce: u64,
    /// Next outbound homeserver slot in transport mode.
    pub write_counter: u32,
    /// Next remote outbound homeserver slot to read in transport mode.
    pub read_counter: u32,
    /// The remote peer's public key (endpoint).
    pub endpoint_pubkey: [u8; 32],
}

impl PubkyNoiseSessionState {
    /// Serialize to a compact binary format.
    ///
    /// Layout:
    /// ```text
    /// [0]       version (u8)
    /// [1]       phase (u8: 0=Handshake, 1=Transport)
    /// [2]       pattern (u8)
    /// [3]       initiator (u8: 0 or 1)
    /// [4..36]   ephemeral_secret (32 bytes)
    /// [36]      has_static_secret (u8: 0 or 1)
    /// [37..69]  static_secret (32 bytes, zeros if absent)
    /// [69..73]  counter (u32 big-endian)
    /// [73]      noise_step (u8)
    /// [74]      sub_step_index (u8)
    /// [75]      has_handshake_hash (u8: 0 or 1)
    /// [76..108] handshake_hash (32 bytes, zeros if absent)
    /// [108]     has_link_id (u8: 0 or 1)
    /// [109..141] link_id (32 bytes, zeros if absent)
    /// [141..149] sending_nonce (u64 big-endian)
    /// [149..157] receiving_nonce (u64 big-endian)
    /// [157..161] write_counter (u32 big-endian)
    /// [161..165] read_counter (u32 big-endian)
    /// [165..197] endpoint_pubkey (32 bytes)
    /// ```
    /// Total: 197 bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SESSION_STATE_LEN);

        // [0] version
        buf.push(SESSION_STATE_VERSION);

        // [1] phase
        buf.push(match self.phase {
            NoisePhase::HandShake => 0,
            NoisePhase::Transport => 1,
        });

        // [2] pattern
        buf.push(self.pattern.to_u8());

        // [3] initiator
        buf.push(if self.initiator { 1 } else { 0 });

        // [4..36] ephemeral_secret
        buf.extend_from_slice(&self.ephemeral_secret);

        // [36] has_static_secret
        if let Some(ref key) = self.static_secret {
            buf.push(1);
            buf.extend_from_slice(key);
        } else {
            buf.push(0);
            buf.extend_from_slice(&[0u8; 32]);
        }

        // [69..73] counter
        buf.extend_from_slice(&self.counter.to_be_bytes());

        // [73] noise_step
        buf.push(self.noise_step.to_u8());

        // [74] sub_step_index
        buf.push(self.sub_step_index);

        // [75] has_handshake_hash
        if let Some(ref hash) = self.handshake_hash {
            buf.push(1);
            buf.extend_from_slice(hash);
        } else {
            buf.push(0);
            buf.extend_from_slice(&[0u8; 32]);
        }

        // [108] has_link_id
        if let Some(ref id) = self.link_id {
            buf.push(1);
            buf.extend_from_slice(id);
        } else {
            buf.push(0);
            buf.extend_from_slice(&[0u8; 32]);
        }

        // [141..149] sending_nonce
        buf.extend_from_slice(&self.sending_nonce.to_be_bytes());

        // [149..157] receiving_nonce
        buf.extend_from_slice(&self.receiving_nonce.to_be_bytes());

        // [157..161] write_counter
        buf.extend_from_slice(&self.write_counter.to_be_bytes());

        // [161..165] read_counter
        buf.extend_from_slice(&self.read_counter.to_be_bytes());

        // [165..197] endpoint_pubkey
        buf.extend_from_slice(&self.endpoint_pubkey);

        debug_assert_eq!(buf.len(), SESSION_STATE_LEN);
        buf
    }

    /// Deserialize from the compact binary format.
    pub fn deserialize(data: &[u8]) -> Result<Self, SerializerError> {
        if data.len() < SESSION_STATE_LEN {
            return Err(SerializerError::TooShort);
        }

        let version = data[0];
        if version != SESSION_STATE_VERSION {
            return Err(SerializerError::UnsupportedVersion(version));
        }

        let phase = match data[1] {
            0 => NoisePhase::HandShake,
            1 => NoisePhase::Transport,
            v => return Err(SerializerError::InvalidField("phase", v)),
        };

        let pattern = HandshakePattern::from_u8(data[2])
            .ok_or(SerializerError::InvalidField("pattern", data[2]))?;

        let initiator = match data[3] {
            0 => false,
            1 => true,
            v => return Err(SerializerError::InvalidField("initiator", v)),
        };

        let mut ephemeral_secret = [0u8; 32];
        ephemeral_secret.copy_from_slice(&data[4..36]);

        let has_static = data[36] == 1;
        let static_secret = if has_static {
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[37..69]);
            Some(key)
        } else {
            None
        };

        let counter = u32::from_be_bytes([data[69], data[70], data[71], data[72]]);

        let noise_step = NoiseStep::from_u8(data[73])
            .ok_or(SerializerError::InvalidField("noise_step", data[73]))?;

        let sub_step_index = data[74];

        let has_hash = data[75] == 1;
        let handshake_hash = if has_hash {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[76..108]);
            Some(hash)
        } else {
            None
        };

        let has_link_id = data[108] == 1;
        let link_id = if has_link_id {
            let mut id = [0u8; 32];
            id.copy_from_slice(&data[109..141]);
            Some(id)
        } else {
            None
        };

        let sending_nonce = u64::from_be_bytes([
            data[141], data[142], data[143], data[144], data[145], data[146], data[147], data[148],
        ]);

        let receiving_nonce = u64::from_be_bytes([
            data[149], data[150], data[151], data[152], data[153], data[154], data[155], data[156],
        ]);

        let write_counter = u32::from_be_bytes([data[157], data[158], data[159], data[160]]);

        let read_counter = u32::from_be_bytes([data[161], data[162], data[163], data[164]]);

        let mut endpoint_pubkey = [0u8; 32];
        endpoint_pubkey.copy_from_slice(&data[165..197]);

        validate_counters(
            phase,
            counter,
            write_counter,
            read_counter,
            sending_nonce,
            receiving_nonce,
        )?;

        Ok(PubkyNoiseSessionState {
            version,
            phase,
            pattern,
            initiator,
            ephemeral_secret,
            static_secret,
            counter,
            noise_step,
            sub_step_index,
            handshake_hash,
            link_id,
            sending_nonce,
            receiving_nonce,
            write_counter,
            read_counter,
            endpoint_pubkey,
        })
    }
}

/// Errors that can occur during session state serialization/deserialization.
#[derive(Debug, PartialEq)]
pub enum SerializerError {
    /// The input data is too short.
    TooShort,
    /// Unsupported format version.
    UnsupportedVersion(u8),
    /// An invalid value was found for a field.
    InvalidField(&'static str, u8),
    /// Serialized counter cannot advance in the slot space.
    CounterOverflow,
    /// Serialized nonce cannot be represented in the Noise nonce space.
    NonceOverflow,
    /// Serialized counters are internally inconsistent.
    InvalidCounter,
}

fn validate_counters(
    phase: NoisePhase,
    counter: u32,
    write_counter: u32,
    read_counter: u32,
    sending_nonce: u64,
    receiving_nonce: u64,
) -> Result<(), SerializerError> {
    if counter == u32::MAX {
        return Err(SerializerError::CounterOverflow);
    }

    if phase == NoisePhase::HandShake {
        if sending_nonce == 0 && receiving_nonce == 0 && write_counter == 0 && read_counter == 0 {
            return Ok(());
        }
        return Err(SerializerError::InvalidCounter);
    }

    if sending_nonce > MAX_USABLE_NOISE_NONCE || receiving_nonce > MAX_USABLE_NOISE_NONCE {
        return Err(SerializerError::NonceOverflow);
    }

    if write_counter == u32::MAX || read_counter == u32::MAX {
        return Err(SerializerError::CounterOverflow);
    }

    if write_counter < counter || read_counter < counter {
        return Err(SerializerError::InvalidCounter);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport_state() -> PubkyNoiseSessionState {
        PubkyNoiseSessionState {
            version: SESSION_STATE_VERSION,
            phase: NoisePhase::Transport,
            pattern: HandshakePattern::PatternNN,
            initiator: true,
            ephemeral_secret: [1; 32],
            static_secret: None,
            counter: 2,
            noise_step: NoiseStep::Final,
            sub_step_index: 0,
            handshake_hash: Some([2; 32]),
            link_id: Some([3; 32]),
            sending_nonce: 2,
            receiving_nonce: 1,
            write_counter: 9,
            read_counter: 7,
            endpoint_pubkey: [4; 32],
        }
    }

    #[test]
    fn roundtrip_preserves_transport_counters_and_nonces() {
        let state = transport_state();
        let bytes = state.serialize();

        assert_eq!(bytes.len(), SESSION_STATE_LEN);

        let restored = PubkyNoiseSessionState::deserialize(&bytes).unwrap();
        assert_eq!(restored.version, SESSION_STATE_VERSION);
        assert_eq!(restored.counter, state.counter);
        assert_eq!(restored.sending_nonce, state.sending_nonce);
        assert_eq!(restored.receiving_nonce, state.receiving_nonce);
        assert_eq!(restored.write_counter, state.write_counter);
        assert_eq!(restored.read_counter, state.read_counter);
    }

    #[test]
    fn transport_snapshot_rejects_exhausted_sending_nonce() {
        let mut bytes = transport_state().serialize();
        bytes[141..149].copy_from_slice(&u64::MAX.to_be_bytes());

        assert!(matches!(
            PubkyNoiseSessionState::deserialize(&bytes),
            Err(SerializerError::NonceOverflow)
        ));
    }

    #[test]
    fn transport_snapshot_accepts_max_usable_noise_nonce() {
        let mut state = transport_state();
        state.sending_nonce = MAX_USABLE_NOISE_NONCE;
        state.receiving_nonce = MAX_USABLE_NOISE_NONCE;
        let bytes = state.serialize();

        let restored = PubkyNoiseSessionState::deserialize(&bytes).unwrap();
        assert_eq!(restored.sending_nonce, MAX_USABLE_NOISE_NONCE);
        assert_eq!(restored.receiving_nonce, MAX_USABLE_NOISE_NONCE);
    }

    #[test]
    fn transport_snapshot_rejects_exhausted_receiving_nonce() {
        let mut bytes = transport_state().serialize();
        bytes[149..157].copy_from_slice(&u64::MAX.to_be_bytes());

        assert!(matches!(
            PubkyNoiseSessionState::deserialize(&bytes),
            Err(SerializerError::NonceOverflow)
        ));
    }

    #[test]
    fn transport_snapshot_rejects_write_counter_before_base() {
        let mut bytes = transport_state().serialize();
        bytes[157..161].copy_from_slice(&1u32.to_be_bytes());

        assert!(matches!(
            PubkyNoiseSessionState::deserialize(&bytes),
            Err(SerializerError::InvalidCounter)
        ));
    }

    #[test]
    fn transport_snapshot_rejects_read_counter_before_base() {
        let mut bytes = transport_state().serialize();
        bytes[161..165].copy_from_slice(&1u32.to_be_bytes());

        assert!(matches!(
            PubkyNoiseSessionState::deserialize(&bytes),
            Err(SerializerError::InvalidCounter)
        ));
    }

    #[test]
    fn transport_snapshot_rejects_exhausted_write_counter() {
        let mut bytes = transport_state().serialize();
        bytes[157..161].copy_from_slice(&u32::MAX.to_be_bytes());

        assert!(matches!(
            PubkyNoiseSessionState::deserialize(&bytes),
            Err(SerializerError::CounterOverflow)
        ));
    }

    #[test]
    fn transport_snapshot_rejects_exhausted_read_counter() {
        let mut bytes = transport_state().serialize();
        bytes[161..165].copy_from_slice(&u32::MAX.to_be_bytes());

        assert!(matches!(
            PubkyNoiseSessionState::deserialize(&bytes),
            Err(SerializerError::CounterOverflow)
        ));
    }

    #[test]
    fn handshake_snapshot_rejects_transport_nonces() {
        let mut state = transport_state();
        state.phase = NoisePhase::HandShake;
        let bytes = state.serialize();

        assert!(matches!(
            PubkyNoiseSessionState::deserialize(&bytes),
            Err(SerializerError::InvalidCounter)
        ));
    }
}
