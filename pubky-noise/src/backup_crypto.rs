//! Encryption for session snapshots persisted to the homeserver.
//!
//! A serialized [`PubkyNoiseSessionState`] contains the session's ephemeral
//! secret (and optionally the static secret), so it must be encrypted before
//! it leaves the device. Encryption follows the Pubky convention used for
//! recovery files: `XSalsa20Poly1305` with a random 192-bit nonce per write.
//!
//! ## Envelope Format (version 1)
//!
//! ```text
//! [0..4]    magic: "PNBK"
//! [4]       envelope format version (1)
//! [5]       algorithm ID (1 = XSalsa20Poly1305 with the KDF below)
//! [6..30]   nonce (192-bit, random per write)
//! [30..]    ciphertext || Poly1305 tag
//! ```
//!
//! The NaCl `XSalsa20Poly1305` construction used by [`pubky_common::crypto`]
//! does not support AAD, so the 6-byte header is duplicated at the start of
//! the authenticated plaintext and validated against the outer header on
//! decryption. The authenticated plaintext is therefore
//! `header (6) || generation (8, big-endian) || session state (197 bytes)`.
//! Envelope versioning is intentionally separate from the session-state
//! serialization version inside the plaintext.
//!
//! ## Key Derivation
//!
//! The encryption key is derived from the Pubky root secret with a
//! domain-separated SHA-256 KDF, mirroring the domain-separation idiom used
//! by [`crate::path_derivation`]:
//!
//! ```text
//! backup_key = SHA-256("pubky-noise/session-backup/v0" || root_secret)
//! ```
//!
//! The root secret has 256 bits of entropy, so a plain hash KDF is
//! sufficient — no password KDF (Argon2) is needed. Domain separation ensures
//! this key can never be confused with keys derived for other purposes from
//! the same root secret.
//!
//! No compression is applied: the serialized snapshot is a fixed 197 bytes of
//! mostly high-entropy key material, which does not compress.
//!
//! ## Rollback Protection
//!
//! AEAD authenticates the bytes but provides no freshness: a stale or
//! malicious homeserver can return an older, still-valid backup after the
//! session has advanced. To detect this, every backup carries a monotonic
//! `generation` in its authenticated plaintext. The caller persists each new
//! generation in *trusted local storage* and passes the latest observed value
//! as `min_generation` to [`decrypt_backup_with_key`]; older records are
//! rejected with
//! [`BackupCryptoError::Rollback`]. Without a trusted checkpoint (fresh
//! device, `min_generation = None`) rollback cannot be detected — a signed or
//! hash-chained sequence alone is not sufficient either, since the homeserver
//! can simply withhold the newest element.

use pubky_common::crypto;
use sha2::{Digest, Sha256};

use crate::serializer::{PubkyNoiseSessionState, SESSION_STATE_LEN};

/// Domain separation tag for backup key derivation.
const BACKUP_KEY_DOMAIN: &[u8] = b"pubky-noise/session-backup/v0";

/// Magic bytes identifying a pubky-noise session backup envelope.
const ENVELOPE_MAGIC: &[u8; 4] = b"PNBK";
/// Current backup envelope format version.
const ENVELOPE_VERSION: u8 = 1;
/// Algorithm ID: XSalsa20Poly1305 with the domain-separated SHA-256 KDF.
const ALG_XSALSA20POLY1305: u8 = 1;

/// Header length: magic (4) || version (1) || algorithm (1).
const HEADER_LEN: usize = 6;
/// XSalsa20Poly1305 nonce length.
const NONCE_LEN: usize = 24;
/// Poly1305 authentication tag length.
const TAG_LEN: usize = 16;
/// Monotonic generation counter length (big-endian u64).
const GENERATION_LEN: usize = 8;

/// v1 authenticated plaintext length: header (6) || generation (8) ||
/// session state (197). The header is duplicated inside the plaintext because
/// `crypto_secretbox` does not support AAD.
const PLAINTEXT_LEN_V1: usize = HEADER_LEN + GENERATION_LEN + SESSION_STATE_LEN;
/// v1 record length: header (6) || nonce (24) || ciphertext (211 + tag 16).
pub const BACKUP_RECORD_LEN_V1: usize = HEADER_LEN + NONCE_LEN + PLAINTEXT_LEN_V1 + TAG_LEN;

/// Hard cap on the homeserver response body when fetching a backup.
///
/// Bounds memory allocation against a malicious homeserver returning a huge
/// body. The v1 record is 257 bytes; this leaves ample room for future
/// envelope versions while keeping allocation strictly bounded.
pub const MAX_BACKUP_RESPONSE_BYTES: usize = 4096;

// The size cap must always fit the current record format.
const _: () = assert!(BACKUP_RECORD_LEN_V1 <= MAX_BACKUP_RESPONSE_BYTES);

/// Errors produced when parsing or decrypting a backup envelope.
#[derive(Debug, PartialEq, Eq)]
pub enum BackupCryptoError {
    /// Record does not start with the backup magic bytes (e.g. a legacy
    /// plaintext snapshot or unrelated data).
    InvalidMagic,
    /// Unsupported envelope format version.
    UnsupportedEnvelopeVersion(u8),
    /// Unsupported algorithm identifier.
    UnsupportedAlgorithm(u8),
    /// Record length does not match the exact length of its envelope version.
    InvalidLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// AEAD decryption failed (wrong key or tampered record).
    DecryptError,
    /// The backup generation is older than the trusted local checkpoint.
    Rollback {
        /// Generation found in the backup.
        generation: u64,
        /// Trusted local checkpoint the backup was checked against.
        min_generation: u64,
    },
}

/// Derives the snapshot backup encryption key from the Pubky root secret.
///
/// `SHA-256(BACKUP_KEY_DOMAIN || root_secret)`.
pub fn derive_backup_key(root_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BACKUP_KEY_DOMAIN);
    hasher.update(root_secret);
    hasher.finalize().into()
}

/// Encrypts a session snapshot into a versioned backup envelope using a
/// caller-provided 32-byte encryption key directly.
///
/// `generation` is a caller-managed, monotonically increasing counter used
/// for rollback detection (see the module docs). The caller must persist the
/// latest generation in trusted local storage and supply it as
/// `min_generation` when loading.
///
/// Returns `magic || version || algorithm || nonce || ciphertext`, with the
/// header duplicated inside the authenticated plaintext.
pub fn encrypt_backup_with_key(
    key: &[u8; 32],
    generation: u64,
    state: &PubkyNoiseSessionState,
) -> Vec<u8> {
    let header = envelope_header();

    let mut plaintext = Vec::with_capacity(PLAINTEXT_LEN_V1);
    plaintext.extend_from_slice(&header);
    plaintext.extend_from_slice(&generation.to_be_bytes());
    plaintext.extend_from_slice(&state.serialize());
    debug_assert_eq!(plaintext.len(), PLAINTEXT_LEN_V1);

    // `pubky_common::crypto::encrypt` prepends a fresh random 192-bit nonce.
    let ciphertext = crypto::encrypt(&plaintext, key);

    let mut out = Vec::with_capacity(BACKUP_RECORD_LEN_V1);
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    debug_assert_eq!(out.len(), BACKUP_RECORD_LEN_V1);
    out
}

/// Encrypts a session snapshot into a versioned backup envelope, deriving the
/// encryption key from the Pubky root secret via [`derive_backup_key()`].
///
/// Convenience wrapper around [`encrypt_backup_with_key()`] for callers that
/// hold the root identity secret directly.
pub fn encrypt_backup(
    root_secret: &[u8; 32],
    generation: u64,
    state: &PubkyNoiseSessionState,
) -> Vec<u8> {
    let key = derive_backup_key(root_secret);
    encrypt_backup_with_key(&key, generation, state)
}

/// Decrypts and parses a backup envelope produced by
/// [`encrypt_backup_with_key()`] or [`encrypt_backup()`], using a
/// caller-provided 32-byte decryption key directly.
///
/// Only explicitly supported envelope versions and algorithms are accepted,
/// and the record must match the exact length of its envelope version.
///
/// `min_generation` is the caller's trusted local checkpoint: the highest
/// generation previously observed for this backup path. Records older than
/// the checkpoint are rejected with [`BackupCryptoError::Rollback`].
///
/// Returns the backup generation and the serialized session state.
pub fn decrypt_backup_with_key(
    key: &[u8; 32],
    record: &[u8],
    min_generation: Option<u64>,
) -> Result<(u64, Vec<u8>), BackupCryptoError> {
    if record.len() < HEADER_LEN {
        return Err(BackupCryptoError::InvalidLength {
            expected: HEADER_LEN,
            actual: record.len(),
        });
    }
    if &record[..4] != ENVELOPE_MAGIC {
        return Err(BackupCryptoError::InvalidMagic);
    }
    let version = record[4];
    if version != ENVELOPE_VERSION {
        return Err(BackupCryptoError::UnsupportedEnvelopeVersion(version));
    }
    let algorithm = record[5];
    if algorithm != ALG_XSALSA20POLY1305 {
        return Err(BackupCryptoError::UnsupportedAlgorithm(algorithm));
    }
    if record.len() != BACKUP_RECORD_LEN_V1 {
        return Err(BackupCryptoError::InvalidLength {
            expected: BACKUP_RECORD_LEN_V1,
            actual: record.len(),
        });
    }

    let header = &record[..HEADER_LEN];

    // `pubky_common::crypto::decrypt` splits off the leading 192-bit nonce.
    let plaintext =
        crypto::decrypt(&record[HEADER_LEN..], key).map_err(|_| BackupCryptoError::DecryptError)?;
    if plaintext.len() != PLAINTEXT_LEN_V1 {
        return Err(BackupCryptoError::InvalidLength {
            expected: PLAINTEXT_LEN_V1,
            actual: plaintext.len(),
        });
    }

    // The header is duplicated inside the authenticated plaintext (the NaCl
    // construction has no AAD): a mismatch means the outer header was swapped.
    if plaintext[..HEADER_LEN] != *header {
        return Err(BackupCryptoError::DecryptError);
    }

    let generation = u64::from_be_bytes(
        plaintext[HEADER_LEN..HEADER_LEN + GENERATION_LEN]
            .try_into()
            .expect("plaintext length is validated above"),
    );
    if let Some(min_generation) = min_generation {
        if generation < min_generation {
            return Err(BackupCryptoError::Rollback {
                generation,
                min_generation,
            });
        }
    }

    Ok((
        generation,
        plaintext[HEADER_LEN + GENERATION_LEN..].to_vec(),
    ))
}

/// Decrypts and parses a backup envelope, deriving the decryption key from
/// the Pubky root secret via [`derive_backup_key()`].
///
/// Convenience wrapper around [`decrypt_backup_with_key()`] for callers that
/// hold the root identity secret directly.
pub fn decrypt_backup(
    root_secret: &[u8; 32],
    record: &[u8],
    min_generation: Option<u64>,
) -> Result<(u64, Vec<u8>), BackupCryptoError> {
    let key = derive_backup_key(root_secret);
    decrypt_backup_with_key(&key, record, min_generation)
}

/// Builds the authenticated 6-byte envelope header.
fn envelope_header() -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(ENVELOPE_MAGIC);
    header[4] = ENVELOPE_VERSION;
    header[5] = ALG_XSALSA20POLY1305;
    header
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snow_crypto::{HandshakePattern, NoisePhase, NoiseStep};

    fn test_state() -> PubkyNoiseSessionState {
        PubkyNoiseSessionState {
            version: 1,
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

    /// Manually build a record encrypting an arbitrary `plaintext`. Used to
    /// construct records the public API would never produce (wrong inner
    /// header, non-standard plaintext lengths).
    fn craft_record(root_secret: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let key = derive_backup_key(root_secret);
        let ciphertext = crypto::encrypt(plaintext, &key);

        let mut record = envelope_header().to_vec();
        record.extend_from_slice(&ciphertext);
        record
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let root_secret = [42u8; 32];
        let state = test_state();

        let record = encrypt_backup(&root_secret, 7, &state);
        let (generation, plaintext) = decrypt_backup(&root_secret, &record, Some(7)).unwrap();

        assert_eq!(generation, 7);
        assert_eq!(plaintext, state.serialize());
    }

    #[test]
    fn record_has_exact_envelope_length() {
        let root_secret = [42u8; 32];
        let record = encrypt_backup(&root_secret, 1, &test_state());

        assert_eq!(record.len(), BACKUP_RECORD_LEN_V1);
        assert_eq!(&record[..4], ENVELOPE_MAGIC);
        assert_eq!(record[4], ENVELOPE_VERSION);
        assert_eq!(record[5], ALG_XSALSA20POLY1305);
    }

    #[test]
    fn ciphertext_is_not_plaintext() {
        let root_secret = [42u8; 32];
        let state = test_state();

        let record = encrypt_backup(&root_secret, 1, &state);

        assert!(!record
            .windows(SESSION_STATE_LEN)
            .any(|w| w == state.serialize().as_slice()));
    }

    #[test]
    fn random_nonce_produces_unique_ciphertexts() {
        let root_secret = [42u8; 32];
        let state = test_state();

        let a = encrypt_backup(&root_secret, 1, &state);
        let b = encrypt_backup(&root_secret, 1, &state);

        assert_ne!(a, b, "each encryption must use a fresh random nonce");
    }

    #[test]
    fn wrong_root_secret_fails() {
        let record = encrypt_backup(&[1u8; 32], 1, &test_state());

        assert_eq!(
            decrypt_backup(&[2u8; 32], &record, None),
            Err(BackupCryptoError::DecryptError)
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let root_secret = [42u8; 32];
        let mut record = encrypt_backup(&root_secret, 1, &test_state());
        let last = record.len() - 1;
        record[last] ^= 1;

        assert_eq!(
            decrypt_backup(&root_secret, &record, None),
            Err(BackupCryptoError::DecryptError)
        );
    }

    #[test]
    fn tampered_nonce_fails() {
        let root_secret = [42u8; 32];
        let mut record = encrypt_backup(&root_secret, 1, &test_state());
        record[HEADER_LEN] ^= 1;

        assert_eq!(
            decrypt_backup(&root_secret, &record, None),
            Err(BackupCryptoError::DecryptError)
        );
    }

    #[test]
    fn header_is_authenticated() {
        // The outer header is duplicated inside the authenticated plaintext;
        // a record whose inner header differs from the outer one must fail.
        let root_secret = [42u8; 32];
        let state = test_state();
        let mut plaintext = b"XXXXXX".to_vec();
        plaintext.extend_from_slice(&1u64.to_be_bytes());
        plaintext.extend_from_slice(&state.serialize());
        let record = craft_record(&root_secret, &plaintext);

        assert_eq!(record.len(), BACKUP_RECORD_LEN_V1);
        assert_eq!(
            decrypt_backup(&root_secret, &record, None),
            Err(BackupCryptoError::DecryptError)
        );
    }

    #[test]
    fn legacy_plaintext_snapshot_is_classified() {
        let root_secret = [42u8; 32];
        let legacy = test_state().serialize();

        assert_eq!(
            decrypt_backup(&root_secret, &legacy, None),
            Err(BackupCryptoError::InvalidMagic)
        );
    }

    #[test]
    fn bad_magic_is_classified() {
        let root_secret = [42u8; 32];
        let mut record = encrypt_backup(&root_secret, 1, &test_state());
        record[0] ^= 1;

        assert_eq!(
            decrypt_backup(&root_secret, &record, None),
            Err(BackupCryptoError::InvalidMagic)
        );
    }

    #[test]
    fn unsupported_envelope_version_is_classified() {
        let root_secret = [42u8; 32];
        let mut record = encrypt_backup(&root_secret, 1, &test_state());
        record[4] = 2;

        assert_eq!(
            decrypt_backup(&root_secret, &record, None),
            Err(BackupCryptoError::UnsupportedEnvelopeVersion(2))
        );
    }

    #[test]
    fn unsupported_algorithm_is_classified() {
        let root_secret = [42u8; 32];
        let mut record = encrypt_backup(&root_secret, 1, &test_state());
        record[5] = 9;

        assert_eq!(
            decrypt_backup(&root_secret, &record, None),
            Err(BackupCryptoError::UnsupportedAlgorithm(9))
        );
    }

    #[test]
    fn exact_minus_one_length_is_rejected() {
        let root_secret = [42u8; 32];
        let record = encrypt_backup(&root_secret, 1, &test_state());
        let truncated = &record[..record.len() - 1];

        assert_eq!(
            decrypt_backup(&root_secret, truncated, None),
            Err(BackupCryptoError::InvalidLength {
                expected: BACKUP_RECORD_LEN_V1,
                actual: BACKUP_RECORD_LEN_V1 - 1,
            })
        );
    }

    #[test]
    fn exact_plus_one_length_is_rejected() {
        let root_secret = [42u8; 32];
        let mut record = encrypt_backup(&root_secret, 1, &test_state());
        record.push(0);
        let actual = record.len();

        assert_eq!(
            decrypt_backup(&root_secret, &record, None),
            Err(BackupCryptoError::InvalidLength {
                expected: BACKUP_RECORD_LEN_V1,
                actual,
            })
        );
    }

    #[test]
    fn oversized_record_is_rejected() {
        let root_secret = [42u8; 32];
        let mut record = encrypt_backup(&root_secret, 1, &test_state());
        record.resize(MAX_BACKUP_RESPONSE_BYTES + 1, 0);
        let actual = record.len();

        assert_eq!(
            decrypt_backup(&root_secret, &record, None),
            Err(BackupCryptoError::InvalidLength {
                expected: BACKUP_RECORD_LEN_V1,
                actual,
            })
        );
    }

    #[test]
    fn trailing_plaintext_is_rejected() {
        // A valid 197-byte state plus trailing bytes inside the authenticated
        // plaintext must not be accepted: the record length no longer matches
        // the exact v1 contract.
        let root_secret = [42u8; 32];
        let state = test_state();
        let mut plaintext = envelope_header().to_vec();
        plaintext.extend_from_slice(&1u64.to_be_bytes());
        plaintext.extend_from_slice(&state.serialize());
        plaintext.push(0);
        let record = craft_record(&root_secret, &plaintext);
        let actual = record.len();

        assert_eq!(
            decrypt_backup(&root_secret, &record, None),
            Err(BackupCryptoError::InvalidLength {
                expected: BACKUP_RECORD_LEN_V1,
                actual,
            })
        );
    }

    #[test]
    fn rolled_back_generation_is_rejected() {
        let root_secret = [42u8; 32];
        let record = encrypt_backup(&root_secret, 5, &test_state());

        assert_eq!(
            decrypt_backup(&root_secret, &record, Some(6)),
            Err(BackupCryptoError::Rollback {
                generation: 5,
                min_generation: 6,
            })
        );
    }

    #[test]
    fn current_and_newer_generations_are_accepted() {
        let root_secret = [42u8; 32];
        let record = encrypt_backup(&root_secret, 5, &test_state());

        assert!(decrypt_backup(&root_secret, &record, Some(5)).is_ok());
        assert!(decrypt_backup(&root_secret, &record, Some(4)).is_ok());
        assert!(decrypt_backup(&root_secret, &record, None).is_ok());
    }

    #[test]
    fn key_derivation_is_deterministic_and_domain_separated() {
        let root_secret = [42u8; 32];

        assert_eq!(
            derive_backup_key(&root_secret),
            derive_backup_key(&root_secret)
        );
        assert_ne!(
            derive_backup_key(&root_secret),
            Sha256::digest(root_secret).as_slice(),
            "derived key must differ from a bare hash of the secret"
        );
    }
}
