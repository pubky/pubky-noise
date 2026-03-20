//! Session state serialization for backup and restore.
//!
//! [`PubkyDataSessionState`] captures all the information needed to restore a
//! `PubkyDataEncryptor` session, whether it was interrupted during the handshake
//! or is already in transport mode.

use crate::snow_crypto::{HandshakePattern, NoisePhase, NoiseStep};

/// Current serialization format version.
const SESSION_STATE_VERSION: u8 = 1;

/// Serializable snapshot of a `PubkyDataEncryptor` session.
///
/// This struct contains everything needed to reconstruct the Noise session
/// by replaying persisted handshake messages through a fresh `HandshakeState`
/// built with the same ephemeral key material.
#[derive(Debug, Clone)]
pub struct PubkyDataSessionState {
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
    /// Current message slot counter.
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
    /// The remote peer's public key (endpoint).
    pub endpoint_pubkey: [u8; 32],
}

impl PubkyDataSessionState {
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
    /// [157..189] endpoint_pubkey (32 bytes)
    /// ```
    /// Total: 189 bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(189);

        // [0] version
        buf.push(self.version);

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

        // [157..189] endpoint_pubkey
        buf.extend_from_slice(&self.endpoint_pubkey);

        debug_assert_eq!(buf.len(), 189);
        buf
    }

    /// Deserialize from the compact binary format.
    pub fn deserialize(data: &[u8]) -> Result<Self, SerializerError> {
        if data.len() < 189 {
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

        let mut endpoint_pubkey = [0u8; 32];
        endpoint_pubkey.copy_from_slice(&data[157..189]);

        Ok(PubkyDataSessionState {
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
}

/// Legacy backup formatter (kept for backward compatibility).
pub struct PubkyDataBackupFormatter {
    file_format: u8,
    pubky_data_version: u8,
    serial_id: u8,
    reserved_field: u8,
    //TODO: signature
}

impl Default for PubkyDataBackupFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl PubkyDataBackupFormatter {
    pub fn new() -> Self {
        PubkyDataBackupFormatter {
            file_format: 0,
            pubky_data_version: 0,
            serial_id: 0,
            reserved_field: 0,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(4);
        buffer.push(self.file_format);
        buffer.push(self.pubky_data_version);
        buffer.push(self.serial_id);
        buffer.push(self.reserved_field);
        buffer
    }

    pub fn deserialize(mut raw_bytes: Vec<u8>) -> Result<Self, ()> {
        if raw_bytes.len() < 4 {
            return Err(());
        }
        let file_format = raw_bytes.remove(0);
        let pubky_data_version = raw_bytes.remove(0);
        let serial_id = raw_bytes.remove(0);
        let reserved_field = raw_bytes.remove(0);
        Ok(PubkyDataBackupFormatter {
            file_format,
            pubky_data_version,
            serial_id,
            reserved_field,
        })
    }
}
