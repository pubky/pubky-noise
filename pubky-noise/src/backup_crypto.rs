//! Encryption for session snapshots persisted to the homeserver.
//!
//! A serialized [`crate::serializer::PubkyNoiseSessionState`] contains the
//! session's ephemeral secret (and optionally the static secret), so it must
//! be encrypted before it leaves the device. Encryption follows the Pubky
//! convention used for recovery files: `XSalsa20Poly1305` with a random
//! 24-byte nonce prepended to the ciphertext (`pubky_common::crypto`).
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

use pubky_common::crypto;
use sha2::{Digest, Sha256};

/// Domain separation tag for backup key derivation.
const BACKUP_KEY_DOMAIN: &[u8] = b"pubky-noise/session-backup/v0";

/// Derives the snapshot backup encryption key from the Pubky root secret.
///
/// `SHA-256(BACKUP_KEY_DOMAIN || root_secret)`.
pub fn derive_backup_key(root_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BACKUP_KEY_DOMAIN);
    hasher.update(root_secret);
    hasher.finalize().into()
}

/// Encrypts a serialized session snapshot for storage on the homeserver.
///
/// The returned bytes are `nonce (24) || ciphertext || tag (16)`.
pub fn encrypt_backup(root_secret: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    crypto::encrypt(plaintext, &derive_backup_key(root_secret))
}

/// Decrypts a session snapshot previously encrypted with [`encrypt_backup`].
pub fn decrypt_backup(
    root_secret: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, crypto::DecryptError> {
    crypto::decrypt(ciphertext, &derive_backup_key(root_secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let root_secret = [42u8; 32];
        let plaintext = b"serialized session state";

        let ciphertext = encrypt_backup(&root_secret, plaintext);
        let decrypted = decrypt_backup(&root_secret, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn ciphertext_is_not_plaintext() {
        let root_secret = [42u8; 32];
        let plaintext = b"serialized session state";

        let ciphertext = encrypt_backup(&root_secret, plaintext);

        assert_ne!(ciphertext, plaintext);
        // nonce (24) + plaintext + tag (16)
        assert_eq!(ciphertext.len(), 24 + plaintext.len() + 16);
    }

    #[test]
    fn random_nonce_produces_unique_ciphertexts() {
        let root_secret = [42u8; 32];
        let plaintext = b"serialized session state";

        let a = encrypt_backup(&root_secret, plaintext);
        let b = encrypt_backup(&root_secret, plaintext);

        assert_ne!(a, b, "each encryption must use a fresh random nonce");
    }

    #[test]
    fn wrong_root_secret_fails() {
        let ciphertext = encrypt_backup(&[1u8; 32], b"secret state");

        assert!(decrypt_backup(&[2u8; 32], &ciphertext).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let root_secret = [42u8; 32];
        let mut ciphertext = encrypt_backup(&root_secret, b"secret state");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 1;

        assert!(decrypt_backup(&root_secret, &ciphertext).is_err());
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let root_secret = [42u8; 32];
        let ciphertext = encrypt_backup(&root_secret, b"secret state");

        assert!(decrypt_backup(&root_secret, &ciphertext[..23]).is_err());
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
