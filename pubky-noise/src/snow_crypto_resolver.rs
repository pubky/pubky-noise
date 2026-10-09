//! Suite-bound AES-256-GCM-SIV resolver and deterministic ephemeral replay.
//!
//! Snow's `Builder` always generates ephemeral keys internally via its RNG.
//! To support session restore (replaying handshake messages to re-derive the
//! same transport keys), we need to inject the same ephemeral key material
//! that was used in the original session.
//!
use aes_gcm_siv::{AeadInOut, Aes256GcmSiv, KeyInit, Nonce, Tag};
use snow::params::{CipherChoice, NoiseParams};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};
use snow::Builder;

use crate::snow_crypto::HandshakePattern;

/// Keep the custom cipher and its transcript name inseparable. Snow has no
/// AESGCMSIV enum: AESGCM is only a private resolver dispatch token, never the
/// negotiated cipher or transcript name. There is no standard-cipher fallback.
pub(crate) fn replay_builder(
    pattern: &HandshakePattern,
    seed: [u8; 32],
) -> Result<Builder<'static>, snow::Error> {
    let mut params: NoiseParams =
        format!("Noise_{}_25519_AESGCM_SHA256", pattern.as_str()).parse()?;
    params.name = format!("Noise_{}_25519_AESGCMSIV_SHA256", pattern.as_str());
    Ok(Builder::with_resolver(params, ReplayResolver::new(seed)))
}

struct AesGcmSivCipher(Aes256GcmSiv);

impl AesGcmSivCipher {
    fn nonce(counter: u64) -> Nonce {
        let mut bytes = [0; 12];
        bytes[4..].copy_from_slice(&counter.to_be_bytes());
        bytes.into()
    }
}

impl Cipher for AesGcmSivCipher {
    fn name(&self) -> &'static str {
        "AESGCMSIV"
    }

    fn set(&mut self, key: &[u8; 32]) {
        self.0 = Aes256GcmSiv::new(key.into());
    }

    fn encrypt(&self, nonce: u64, aad: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let (buffer, tag_out) = out.split_at_mut(plaintext.len());
        buffer.copy_from_slice(plaintext);
        // Snow bounds its messages to 65535 bytes and supplies tag capacity;
        // both message and AAD lengths are below RFC 8452's 2^36-byte limit.
        // Its Cipher trait cannot return an encryption error.
        let tag = self
            .0
            .encrypt_inout_detached(&Self::nonce(nonce), aad, buffer.into())
            .expect("bounded Noise plaintext and AAD");
        tag_out[..16].copy_from_slice(&tag);
        plaintext.len() + 16
    }

    fn decrypt(
        &self,
        nonce: u64,
        aad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, snow::Error> {
        let len = ciphertext
            .len()
            .checked_sub(16)
            .ok_or(snow::Error::Decrypt)?;
        let buffer = out.get_mut(..len).ok_or(snow::Error::Decrypt)?;
        buffer.copy_from_slice(&ciphertext[..len]);
        let tag = Tag::try_from(&ciphertext[len..]).map_err(|_| snow::Error::Decrypt)?;
        // Use the primitive in-place; never its separate input/output mode.
        // On failure also clear the output, so unauthenticated plaintext cannot
        // escape regardless of the primitive's failure-buffer behavior.
        if self
            .0
            .decrypt_inout_detached(&Self::nonce(nonce), aad, buffer.into(), &tag)
            .is_err()
        {
            out[..len].fill(0);
            return Err(snow::Error::Decrypt);
        }
        Ok(len)
    }
}

/// A deterministic RNG that returns a pre-set seed on the first 32-byte fill.
///
/// Snow calls `resolve_rng()` to get an RNG, then uses it exactly once during
/// `build_initiator()` / `build_responder()` to generate the local ephemeral
/// keypair (via `Dh::generate()`). By returning our pre-set seed bytes, we
/// force Snow to derive the same ephemeral keypair every time.
///
/// After the first fill, subsequent calls delegate to the real OS RNG (via
/// `getrandom`). In practice, Snow only calls the RNG once for ephemeral key
/// generation during handshake construction.
struct DeterministicRng {
    seed: [u8; 32],
    used: bool,
}

impl DeterministicRng {
    fn new(seed: [u8; 32]) -> Self {
        DeterministicRng { seed, used: false }
    }
}

impl Random for DeterministicRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::error::Error> {
        if !self.used && dest.len() == 32 {
            dest.copy_from_slice(&self.seed);
            self.used = true;
            Ok(())
        } else {
            // Fallback to real randomness for any other calls.
            // This should not happen during normal handshake construction,
            // but we handle it gracefully.
            getrandom::fill(dest).map_err(|_| snow::error::Error::Rng)
        }
    }
}

/// A CryptoResolver that injects a deterministic RNG for ephemeral key replay.
///
/// DH and hashing use Snow's default implementation. All handshake and
/// transport cipher instances use the suite's AES-256-GCM-SIV implementation.
struct ReplayResolver {
    default: DefaultResolver,
    seed: [u8; 32],
}

impl ReplayResolver {
    fn new(seed: [u8; 32]) -> Box<Self> {
        Box::new(ReplayResolver {
            default: DefaultResolver,
            seed,
        })
    }
}

impl CryptoResolver for ReplayResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(DeterministicRng::new(self.seed)))
    }

    fn resolve_dh(&self, choice: &snow::params::DHChoice) -> Option<Box<dyn Dh>> {
        self.default.resolve_dh(choice)
    }

    fn resolve_hash(&self, choice: &snow::params::HashChoice) -> Option<Box<dyn Hash>> {
        self.default.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &snow::params::CipherChoice) -> Option<Box<dyn Cipher>> {
        match choice {
            CipherChoice::AESGCM => Some(Box::new(AesGcmSivCipher(Aes256GcmSiv::new(
                &[0; 32].into(),
            )))),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn cipher(key: [u8; 32]) -> AesGcmSivCipher {
        let mut cipher = AesGcmSivCipher(Aes256GcmSiv::new(&[0; 32].into()));
        cipher.set(&key);
        cipher
    }

    #[test]
    fn aes256_gcm_siv_rfc8452_vectors() {
        // RFC 8452 Appendix C.2: empty, nonempty, and authenticated-data cases.
        let mut key = [0; 32];
        key[0] = 1;
        let cipher = cipher(key);
        let mut nonce = [0; 12];
        nonce[0] = 3;
        for (plaintext, aad, expected) in [
            ("", "", "07f5f4169bbf55a8400cd47ea6fd400f"),
            (
                "0100000000000000",
                "",
                "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
            ),
            (
                "0200000000000000",
                "01",
                "1de22967237a813291213f267e3b452f02d01ae33e4ec854",
            ),
        ] {
            let plaintext = hex::decode(plaintext).unwrap();
            let aad = hex::decode(aad).unwrap();
            let mut buffer = plaintext.clone();
            let tag = cipher
                .0
                .encrypt_inout_detached(&nonce.into(), &aad, buffer.as_mut_slice().into())
                .unwrap();
            let mut packet = buffer.clone();
            packet.extend_from_slice(&tag);
            assert_eq!(hex::encode(packet), expected);
            cipher
                .0
                .decrypt_inout_detached(&nonce.into(), &aad, buffer.as_mut_slice().into(), &tag)
                .unwrap();
            assert_eq!(buffer, plaintext);
        }
    }

    #[test]
    fn cipher_uses_big_endian_counter_and_appended_tag() {
        let cipher = cipher(std::array::from_fn(|i| i as u8));
        let nonce = 0x0102030405060708;
        assert_eq!(
            AesGcmSivCipher::nonce(nonce).as_slice(),
            &[0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
        );
        let plaintext = b"Noise counter encoding";
        let mut packet = [0; 38];
        assert_eq!(
            cipher.encrypt(nonce, b"transcript", plaintext, &mut packet),
            38
        );
        // Independently generated with OpenSSL via Python cryptography AESGCMSIV.
        assert_eq!(
            hex::encode(packet),
            "5775c99ecff5d7247fac6189f66494abdd1e798ccf8df4f638401535e7403ec108d054698413"
        );
        let mut output = [0; 22];
        assert_eq!(
            cipher.decrypt(nonce, b"transcript", &packet, &mut output),
            Ok(22)
        );
        assert_eq!(&output, plaintext);
        // Snow reserves this nonce for rekeying; it must still encode exactly.
        assert_eq!(&AesGcmSivCipher::nonce(u64::MAX)[4..], &[255; 8]);
    }

    #[test]
    fn authentication_failure_clears_output_and_rejects_short_buffers() {
        let cipher = cipher([7; 32]);
        let plaintext = [0x42; 1002];
        let mut packet = [0; 1018];
        cipher.encrypt(9, b"transcript", &plaintext, &mut packet);
        for index in 0..packet.len() {
            let mut corrupted = packet;
            corrupted[index] ^= 1;
            let mut output = [0xFF; 1003];
            assert_eq!(
                cipher.decrypt(9, b"transcript", &corrupted, &mut output),
                Err(snow::Error::Decrypt)
            );
            assert_eq!(output[..1002], [0; 1002]);
            assert_eq!(output[1002], 0xFF);
        }
        for (nonce, aad) in [(10, b"transcript".as_slice()), (9, b"wrong")] {
            let mut output = [0xFF; 1002];
            assert_eq!(
                cipher.decrypt(nonce, aad, &packet, &mut output),
                Err(snow::Error::Decrypt)
            );
            assert_eq!(output, [0; 1002]);
        }
        let mut short = [0xFF; 1001];
        assert_eq!(
            cipher.decrypt(9, b"transcript", &packet, &mut short),
            Err(snow::Error::Decrypt)
        );
        assert_eq!(short, [0xFF; 1001]);
        assert_eq!(
            cipher.decrypt(9, b"", &[0; 15], &mut short),
            Err(snow::Error::Decrypt)
        );
        assert_eq!(short, [0xFF; 1001]);
    }

    #[test]
    fn legacy_transport_ciphertext_is_not_reinterpreted() {
        let key = [7; 32];
        let receiver = cipher(key);
        for choice in [CipherChoice::AESGCM, CipherChoice::ChaChaPoly] {
            let mut legacy = DefaultResolver.resolve_cipher(&choice).unwrap();
            legacy.set(&key);
            let mut packet = [0; 1018];
            legacy.encrypt(9, b"", &[0x42; 1002], &mut packet);
            let mut output = [0xFF; 1002];
            assert_eq!(
                receiver.decrypt(9, b"", &packet, &mut output),
                Err(snow::Error::Decrypt)
            );
            assert_eq!(output, [0; 1002]);
        }
    }

    #[test]
    fn suite_name_is_bound_to_the_handshake() {
        for pattern in [HandshakePattern::PatternNN, HandshakePattern::PatternXX] {
            let name = format!("Noise_{}_25519_AESGCMSIV_SHA256", pattern.as_str());
            assert!(name.parse::<NoiseParams>().is_err());
            let key = [1; 32];
            let state = replay_builder(&pattern, [2; 32])
                .unwrap()
                .local_private_key(&key)
                .unwrap()
                .build_initiator()
                .unwrap();
            let mut expected = [0; 32];
            expected[..name.len()].copy_from_slice(name.as_bytes());
            // Snow mixes the empty prologue after initializing the name.
            assert_eq!(
                state.get_handshake_hash(),
                Sha256::digest(expected).as_slice()
            );
        }
        let resolver = ReplayResolver::new([3; 32]);
        assert!(resolver.resolve_cipher(&CipherChoice::ChaChaPoly).is_none());
        assert_eq!(
            resolver
                .resolve_cipher(&CipherChoice::AESGCM)
                .unwrap()
                .name(),
            "AESGCMSIV"
        );
    }

    #[test]
    fn mixed_cipher_suites_cannot_complete_handshake() {
        let key = [1; 32];
        for pattern in [HandshakePattern::PatternNN, HandshakePattern::PatternXX] {
            for legacy_cipher in ["ChaChaPoly", "AESGCM"] {
                for siv_initiator in [false, true] {
                    let siv = replay_builder(&pattern, [2; 32]).unwrap();
                    let legacy = Builder::new(
                        format!("Noise_{}_25519_{legacy_cipher}_SHA256", pattern.as_str())
                            .parse()
                            .unwrap(),
                    );
                    let (initiator, responder) = if siv_initiator {
                        (siv, legacy)
                    } else {
                        (legacy, siv)
                    };
                    let mut initiator = initiator
                        .local_private_key(&key)
                        .unwrap()
                        .build_initiator()
                        .unwrap();
                    let mut responder = responder
                        .local_private_key(&key)
                        .unwrap()
                        .build_responder()
                        .unwrap();
                    let mut packet = [0; 1024];
                    let mut output = [0; 1024];
                    let len = initiator.write_message(&[], &mut packet).unwrap();
                    // The first message is unauthenticated; the second must fail.
                    responder.read_message(&packet[..len], &mut output).unwrap();
                    let len = responder.write_message(&[], &mut packet).unwrap();
                    assert_eq!(
                        initiator.read_message(&packet[..len], &mut output),
                        Err(snow::Error::Decrypt)
                    );
                    assert!(!initiator.is_handshake_finished());
                }
            }
        }
    }
}
