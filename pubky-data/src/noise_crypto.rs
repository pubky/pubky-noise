use pubky::{PublicKey, Keypair};
use ed25519_dalek::{SecretKey, VerifyingKey};
use x25519_dalek::{StaticSecret, PublicKey as XPublicKey};
use crypto::hmac::Hmac;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use crypto::mac::Mac;
use chacha20poly1305::{ChaCha20Poly1305, Nonce, KeyInit, Tag};
use chacha20poly1305::aead::AeadInPlace;

use curve25519_dalek::montgomery::MontgomeryPoint;

const HASHLEN: usize = 32;
const DHLEN: usize = 32;

pub const PUBKY_DATA_MSG_LEN: usize = 65000;

fn noise_hmac(key: [u8;HASHLEN], input_key_material: Vec<u8>, output: &mut [u8; HASHLEN]) {
	// Section 4.3 Hash Functions
	//
	// HMAC-HASH(key, data): Applies HMAC from using the HASH() function.
	// This function is only called as part of HDKF(), below.
	let hasher = Sha256::new();
	let mut hmac_engine = Hmac::new(hasher, &key);

	hmac_engine.input(&input_key_material);
	let ret = hmac_engine.result();
	// Be careful w.r.t timing attacks
	let mac_code = ret.code();
	let mut counter = 0;
	for byte in mac_code.iter() {
		output[counter] = *byte;
		counter += 1;
	}
}

enum NoiseHkdfResult {
	Two([u8; HASHLEN], [u8;HASHLEN])
}

fn noise_hkdf(chaining_key: [u8;HASHLEN], input_key_material: Vec<u8>, num_outputs: u8) -> NoiseHkdfResult {
	//TODO: write comment 
	let mut temp_key = [0; HASHLEN];
	noise_hmac(chaining_key, input_key_material.clone(), &mut temp_key);

	let mut output1 = [0; HASHLEN];
	noise_hmac(temp_key, vec![0x01], &mut output1);

	//TODO: implement what if 3 outputs

	let mut input_2 = [0; HASHLEN+1];
	let mut counter = 0;
	for b in output1.iter() {
		input_2[counter] = *b;
		counter += 1;
	}
	input_2[32] = 0x02;

	let mut output2 = [0; HASHLEN];
	noise_hmac(temp_key, input_2.to_vec(), &mut output2);

	return NoiseHkdfResult::Two(output1, output2);
}

#[derive(PartialEq)]
enum NoisePhase {
	HandShake,
	Transport,
}

#[derive(PartialEq)]
enum NoiseStep {
	StepOne,
	StepTwo,
	Final,
}

#[derive(PartialEq)]
pub enum HandshakeAction {
	Read,
	Write,
	Pending,
	Terminal,
}

#[derive(PartialEq, Copy, Clone)]
pub enum HandshakeState {
	/// <- s
	/// ...
	/// -> e, es
	PatternN,
	/// -> e,
	/// <- e, ee
	PatternNN,
}

impl HandshakeState {
	fn to_string(&self) -> Result<String, ()> {
		match self {
			HandshakeState::PatternN => { return Ok(String::from("N")); }
			HandshakeState::PatternNN => { return Ok(String::from("NN")); }
			_ => { return Err(()); }
		}
	}

	//TODO: fix
	pub fn from_string(pattern_string: String) -> Result<Self, ()> {
		match pattern_string.as_str() {
			"N" => { return Ok(HandshakeState::PatternN); }
			"NN" => { return Ok(HandshakeState::PatternNN); }
			_ => { return Err(()); }
		}
	}
}

/// Wrapper to hold asymmetric crypto state variables.
/// 
/// The cipher state is unique during the handshakce. Once entered
/// in the transport phase, the cipher state is duplicated, each
/// communication party holds two cipher states.
struct CipherState {
	k: Option<[u8; 32]>,
	n: u64,
}

impl CipherState {
	fn init_key(key_option: Option<[u8; 32]>) -> CipherState {
		// Section 5.2 The Symmetric State Object
		//
		// Sets k = key.
		// Sets n = 0.
		CipherState {
			k: key_option,
			n: 0,
		}
	}
	fn update_key(&mut self, key_option: Option<[u8; 32]>) {
		self.k = key_option;
	}
	fn has_key() {}
	fn set_nonce() {}
	fn encrypt_with_ad(&mut self, h: [u8; HASHLEN], payload: Vec<u8>, buf_msg: &mut [u8; PUBKY_DATA_MSG_LEN], buf_tag: &mut [u8; 16]) {
		// Section 5.1 The CipherState Object
		//
		// If EncryptWithAd(ad, plaintext): If k is non-empty returns ENCRYPT(k,
		// n++, ad, ciphertext). Otherwise returns ciphertext.
		if self.k.is_none() || payload.is_empty() { return; }

		// ENCRYPT(k, n, ad, plaintext): Encrypts plaintext using the cipher
		// key k of 32 bytes and an 8-byte unsigned integer nonce n which must be
		// unique for the key k. Returns the ciphertext. Encryption must be done
		// with an "AEAD" encryption mode with the associated data ad
		// and returns a ciphertext that is the same size as the
		// plaintext plus 16 bytes for authentication data. The entire ciphertext must
		// be indistinguishable from random if the key is secret (note that this is an
		// additional requirement that isn't necessiarily met by all AEAD schemes)
		let mut nonce = vec![0x0, 0x0, 0x0, 0x0];
		nonce.append(&mut self.n.to_le_bytes().to_vec());
		let aad = h;
		//println!("key {:?}", self.k.unwrap());
		let encryption_engine = ChaCha20Poly1305::new(&self.k.unwrap().into());

		let mut tmp_payload = [0; PUBKY_DATA_MSG_LEN];
		let mut counter = 0;
		for b in payload.iter() {
			tmp_payload[counter] = *b as u8;
			counter += 1;
		}
		buf_msg.copy_from_slice(&tmp_payload);
		let nonce = Nonce::from_slice(&nonce);
		//println!("nonce {:?}", nonce);
		//println!("authenticated data {:?}", aad);
		let ret = encryption_engine.encrypt_in_place_detached(nonce, &aad, buf_msg);
		if ret.is_ok() {
			buf_tag.copy_from_slice(ret.unwrap().as_slice());
		}
		//println!("tag {:?}", buf_tag);
		//println!("ciphertext {:?}", buf_msg);

		// increment the nonce
		self.n += 1;
	}
	fn decrypt_with_ad(&mut self, h: [u8; HASHLEN], payload: Vec<u8>, buf_msg: &mut [u8; PUBKY_DATA_MSG_LEN], buf_tag: &mut [u8; 16]) {
		if self.k.is_none() { return; }

		let mut nonce = vec![0x0, 0x0, 0x0, 0x0];
		let aad = h;
		nonce.append(&mut self.n.to_le_bytes().to_vec());
		//println!("key {:?}", self.k.unwrap());
		let encryption_engine = ChaCha20Poly1305::new(&self.k.unwrap().into());

		let nonce = Nonce::from_slice(&nonce);
		let tag = Tag::from_slice(buf_tag);
		//println!("nonce {:?}", nonce);
		//println!("authenticated data {:?}", aad);
		//println!("ciphertext {:?}", buf_msg);
		//println!("tag {:?}", tag);
		let ret = encryption_engine.decrypt_in_place_detached(nonce, &aad, buf_msg, tag);
		if ret.is_ok() {
			// increment the nonce
			self.n += 1;
		}
		if ret.is_ok() { println!("[DECRYPT] Success"); } else if ret.is_err() { println!("[DECRYPT] Failure"); }
	}
	fn rekey() {}
}

/// Wrapper to hold symmetric crypto state variables.
///
/// The cipher state should be deleted when the handshake
/// phase is over.
struct SymmetricState {
	h: [u8;HASHLEN],
	ck: [u8;HASHLEN],
	cipher_state: CipherState,
}

impl SymmetricState {
	fn init_symmetric(protocol_name: Vec<u8>) -> SymmetricState {
		// Section 5.1 - The CipherState object
		//
		// - If protocol_name is less than or equal to HASHLEN bytes in length,
		//   sets h equal to protocol_name with zero bytes appended to make 
		//   HASHLEN bytes. Otherwise sets h = HASH(protocol_name)
		let mut h = [0;HASHLEN];
		let mut counter = 0;
		if protocol_name.len() <= HASHLEN {
			for e in protocol_name.iter() {
				h[counter] = *e as u8;
				counter += 1;
			}
		} else {
			//TODO: sanitize it is utf-8
			let protocol_name_string = String::from_utf8(protocol_name).unwrap();
			let ret = sha256::digest(protocol_name_string);
			for c in ret.chars() {
				h[counter] = c as u8;
				counter += 1;
			}
		}
		let fresh_cipher = CipherState::init_key(None);
		SymmetricState {
			h: h,
			// Sets ck = h
			ck: h,
			// Calls InitializeKey(empty)
			cipher_state: fresh_cipher,
		}
	}
	fn mix_key(&mut self, input_key_material: Vec<u8>) {
		// Section 5.1 - The SymmetricState object
		//
		// - Sets ck, temp_k = HDKF(ck, input_key_material, 2)
		let hdkf_ret = noise_hkdf(self.ck, input_key_material, 2);
		let mut temp_k = [0; HASHLEN];
		match hdkf_ret {
			NoiseHkdfResult::Two(output1, output2) => {
				let mut counter = 0;
				for c in output1.iter() {
					self.ck[counter] = *c as u8;
					counter += 1;
				}
				let mut counter = 0;
				for c in output2.iter() {
					temp_k[counter] = *c as u8;
					counter += 1;
				}
			}
		}
		// - If HASHLEN is 64, then truncates temp_k to 32 bytes.
	
		// - Calls InitializeKey(temp_k).
		self.cipher_state.update_key(Some(temp_k));
	}
	fn mix_hash(&mut self, mut data: Vec<u8>) {
		// Section 5.1 - The CipherState object 
		//
		// Sets h = HASH(h || data)
		let mut buf: Vec<u8> = Vec::from(self.h);
		buf.append(&mut data);
		let mut hash_engine = Sha256::new();
		hash_engine.input(&buf);
		let mut out_buf = [0;HASHLEN];
		hash_engine.result(&mut out_buf);

		let mut counter = 0;
		for c in out_buf.iter() {
			self.h[counter] = *c as u8;
			counter += 1;
		}
	}
	fn mix_key_and_hash() {}
	fn get_handshake_hash() {}
	fn encrypt_and_hash(&mut self, payload: Vec<u8>, buf_msg: &mut [u8; PUBKY_DATA_MSG_LEN], buf_tag: &mut [u8; 16]) {
		// Section 5.2 - The CipherState object
		//
		// Sets ciphertext = EncryptdWithAd(h, plaintext);
		if payload.is_empty() { return; }
		self.cipher_state.encrypt_with_ad(self.h, payload, buf_msg, buf_tag);
		// Calls MixHash(ciphertext)
		self.mix_hash(buf_msg.to_vec());
		//println!("tag {:?}", buf_tag);
	}
	fn decrypt_and_hash(&mut self, payload: Vec<u8>, buf_msg: &mut [u8; PUBKY_DATA_MSG_LEN], buf_tag: &mut [u8; 16]) {
		// Section 5.2 The CipherState object
		//
		// Sets plaintext = DecriptWithAd(h, ciphertext);
		if payload.is_empty() { return; }
		self.cipher_state.decrypt_with_ad(self.h, payload, buf_msg, buf_tag);
		// Calls MixHash(ciphertext);
		self.mix_hash(buf_msg.to_vec());
	}
	fn split(&self) -> (CipherState, CipherState) {
		// Returns a pair of Cipherstate objects for encrypting transport
		// messages. Executes the following steps, where zerolen is a zero-length
		// byte sequence:
		// 	- Sets temp_k1, temp_k2 = HKDF(ck, zerolen, 2).
		// 	- If HASHLEN is 64, then truncates temp_k1 and temp_k2 to 32 bytes.
		// 	- Creates two new CipherState objects c1 and c2.
		// 	- Calls c1.InitializeKey(temp_k1) and c2.InitializeKey(temp_k2).
		// 	- Returns the pair (c1, c2)
		let zerolen: Vec<u8> = vec![];
		let hdkf_ret = noise_hkdf(self.ck, zerolen, 2);
		let mut temp_k_one = [0; HASHLEN];
		let mut temp_k_two = [0; HASHLEN];
		match hdkf_ret {
			NoiseHkdfResult::Two(output1, output2) => {
				let mut counter = 0;
				for c in output1.iter() {
					temp_k_one[counter] = *c as u8;
					counter += 1;
				}
				counter = 0;
				for c in output2.iter() {
					temp_k_two[counter] = *c as u8;
					counter += 1;
				}
			}
		}
		//println!("key one {:?}", temp_k_one);
		//println!("key two {:?}", temp_k_two);
		let (cipherstate_one, cipherstate_two) = (CipherState::init_key(Some(temp_k_one)), CipherState::init_key(Some(temp_k_two)));
		return (cipherstate_one, cipherstate_two);
	}
}

/// A Noise state machine
pub struct DataLinkSession {
	initiator: bool,
	message_patterns: HandshakeState,

	local_ephemeral_seckey: Option<SecretKey>,
	local_static_seckey: Option<SecretKey>,

	remote_ephemeral_pubkey: Option<PublicKey>,
	remote_static_pubkey: Option<PublicKey>,

	//TODO: make a handshake / transport wrapper structure
	symmetric_state: SymmetricState,

	from_cipher_state: Option<CipherState>,
	to_cipher_state: Option<CipherState>,

	noise_state: NoisePhase,
	noise_step: NoiseStep,
}

impl DataLinkSession {
	pub fn new(handshake_pattern: HandshakeState, initiator: bool, prologue: Vec<u8>, ephemeral_key: Option<SecretKey>, static_key: Option<SecretKey>, ephemeral_pubkey: Option<PublicKey>, static_pubkey: Option<PublicKey>) -> Result<DataLinkSession, ()> {
		// Section 5.3 The Handshake Object
		//
		// Perform the following steps:
		// - Derives a protocol_name byte sequence by combining the names for
		//   the handshake pattern and crypto functions, as specified in Section 8.
		//   Calls InitializeSymmetric(protocol_name). 
		let mut protocol_name = String::from("Noise");
		protocol_name.push('_');
		let pattern_string = if let Ok(pattern_string) = handshake_pattern.to_string() {
			pattern_string
		} else { return Err(()) };
		protocol_name.push_str(&pattern_string);

		let mut fresh_symmetric = SymmetricState::init_symmetric(protocol_name.into());

		// - Calls MixHash(prologue).
		fresh_symmetric.mix_hash(prologue);

		// - Sets the initator s, e, rs and re variables to the corresponding 
		//   arguments.

		// - Calls MixHash() once for each public key listed in the pre-messages
		//   from handshake_pattern, with the specified public key as input (see
		//   Section 7 for an explanation of pre-messages). If both initiator and
		//   responder have pre-messages, the initiator's public key are hashed
		//   first. If multiple public keys are listed in either party's pre-message,
		//   the public keys are hashed in the order they are listed.

		if initiator && handshake_pattern == HandshakeState::PatternN {
			fresh_symmetric.mix_hash(static_pubkey.clone().unwrap().as_bytes().to_vec());
		} else if handshake_pattern == HandshakeState::PatternNN {

		} else {
			let static_pubkey = Keypair::from_secret_key(&static_key.unwrap()).public_key();
			fresh_symmetric.mix_hash(static_pubkey.as_bytes().to_vec());
		}
		//TODO: HandshakeState::PatternNN

		Ok(DataLinkSession {
			initiator,
			message_patterns: handshake_pattern,

			//TODO: for now keep keys separated from the state.
			local_ephemeral_seckey: ephemeral_key,
			local_static_seckey: static_key,

			remote_ephemeral_pubkey: ephemeral_pubkey,
			remote_static_pubkey: static_pubkey,

			symmetric_state: fresh_symmetric,

			from_cipher_state: None,
			to_cipher_state: None,

			noise_state: NoisePhase::HandShake,
			noise_step: NoiseStep::StepOne,

		})
	}

	pub fn delete(&mut self) {
		//TODO: memorize the cryptographic state by forcing the flush of zeroized
		// memory pages to disk.
		self.local_ephemeral_seckey = None;
		self.local_static_seckey = None;

		self.symmetric_state.h = [0; HASHLEN];
		self.symmetric_state.ck = [0; HASHLEN];

		self.symmetric_state.cipher_state.k = None;
		self.symmetric_state.cipher_state.n = 0;
	}

	pub fn is_handshake(&self) -> bool {
		return self.noise_state == NoisePhase::HandShake;
	}

	pub fn handshake_steps(&self, initiator: bool) -> Vec<HandshakeAction> {
		//TODO: write resolve pattern
		let mut steps_to_be_done: Vec<HandshakeAction> = Vec::new();
		assert!(self.message_patterns == HandshakeState::PatternNN);
		if initiator {
			match self.noise_step {
				NoiseStep::StepOne => {
					steps_to_be_done.push(HandshakeAction::Write);
					steps_to_be_done.push(HandshakeAction::Pending);
				},
				NoiseStep::StepTwo => {
					steps_to_be_done.push(HandshakeAction::Read);
				},
				NoiseStep::Final => {
					steps_to_be_done.push(HandshakeAction::Terminal);
				},
			}
		} else { // == responder
			 match self.noise_step {
				NoiseStep::StepOne => {
					steps_to_be_done.push(HandshakeAction::Read);
					steps_to_be_done.push(HandshakeAction::Write);
				},
				NoiseStep::StepTwo => {
					steps_to_be_done.push(HandshakeAction::Terminal);
				},
				NoiseStep::Final => {
					steps_to_be_done.push(HandshakeAction::Terminal);
				},
			}
		}
		return steps_to_be_done;
	}


	pub fn perform_act(&mut self, buf_msg: &mut [u8; PUBKY_DATA_MSG_LEN], payload: Vec<u8>, buf_tag: &mut [u8; 16]) -> Result<(), ()> {
		// Section 5.3 The HandshakeState object
		//
		// For "e": Sets e (which must be empty) to GENERATE_KEYPAIR().
		// Appends e.public_key to the buffer. Calls MixHash(e.public_key).
		//
		// For "ee": Calls MixKey(DH(e, re))
		//
		// For "es": Calls MixKey (DH(e, rs)) if initiator, MixKey(DH(s, re) 
		// if responder.

		if self.noise_state == NoisePhase::HandShake {
			match self.message_patterns {
				HandshakeState::PatternN => {
					// Processing "e"
					//let ephemeral_public_key = Keypair::from_secret_key(&self.local_ephemeral_seckey.unwrap()).public_key();
					let ephemeral_secret = StaticSecret::from(self.local_ephemeral_seckey.clone().unwrap());
					let ephemeral_public_key = XPublicKey::from(&ephemeral_secret);
					//println!("ephemeral public key buffer write{:?}", ephemeral_public_key.as_bytes());
					let mut counter = 0;
					for byte in ephemeral_public_key.as_bytes() {
						buf_msg[counter] = *byte;
						counter += 1;
					}
					//println!("key located {:?}\n", buf_msg);
					self.symmetric_state.mix_hash(ephemeral_public_key.as_bytes().to_vec());

					// Processing "es"
					if self.initiator {
						//println!("static public key {:?}", self.remote_static_pubkey.clone().unwrap().as_bytes());
						//println!("ephemeral public key {:?}", Keypair::from_secret_key(&self.local_ephemeral_seckey.clone().unwrap()).public_key().as_bytes());
						let ephemeral_secret = StaticSecret::from(self.local_ephemeral_seckey.clone().unwrap());
						let responder_static_pk = XPublicKey::from(self.remote_static_pubkey.clone().unwrap().verifying_key().to_montgomery().to_bytes());
						//println!("ephemeral_secret {:?}", ephemeral_secret.to_bytes());
						//println!("static_pubkey {:?}", responder_static_pk.as_bytes());
						let initiator_shared_secret = ephemeral_secret.diffie_hellman(&responder_static_pk);
						//println!("initiator shared secret {:?}", initiator_shared_secret.as_bytes());
						self.symmetric_state.mix_key(initiator_shared_secret.as_bytes().to_vec());
					} else {
						//TODO: no-implemented: "half-way"
					}
				},
				HandshakeState::PatternNN => {
					match self.noise_step {
						NoiseStep::StepOne => {
							// Processing "e"
							let ephemeral_secret = StaticSecret::from(self.local_ephemeral_seckey.clone().unwrap());
							let ephemeral_public_key = XPublicKey::from(&ephemeral_secret);

							let mut counter = 0;
							for byte in ephemeral_public_key.as_bytes() {
								buf_msg[counter] = *byte;
								counter += 1;
							}
							self.symmetric_state.mix_hash(ephemeral_public_key.as_bytes().to_vec());
							self.noise_step = NoiseStep::StepTwo;
						},
						NoiseStep::StepTwo => { panic!("NN PATTERN IS ONE ROUND TRIP !"); },
						_ => {},
					}
					// Processing "e"

					// Processing "ee"
					let ephemeral_secret = StaticSecret::from(self.local_ephemeral_seckey.clone().unwrap());
					let responder_ephemeral_pk = XPublicKey::from(self.remote_ephemeral_pubkey.clone().unwrap().verifying_key().to_montgomery().to_bytes());

					let initiator_shared_secret = ephemeral_secret.diffie_hellman(&responder_ephemeral_pk);

					self.symmetric_state.mix_key(initiator_shared_secret.as_bytes().to_vec());
				},
				_ => { return Err(()) } // no supported pattern
			}

			// Appends EncryptAndHash(payload) to the buffer.
			self.symmetric_state.encrypt_and_hash(payload, buf_msg, buf_tag);

			// If there are no more message patterns returns to new CipherState
			// objects by calling Split().
			let (cipher_state_one, cipher_state_two) = self.symmetric_state.split();

			self.from_cipher_state = Some(cipher_state_one);
			self.to_cipher_state = Some(cipher_state_two);
			self.noise_state = NoisePhase::Transport;
		} else if self.noise_state == NoisePhase::Transport {
			let ad = [0; HASHLEN];
			self.from_cipher_state.as_mut().unwrap().encrypt_with_ad(ad, payload, buf_msg, buf_tag);
			//println!("tag {:?}", buf_tag);
		}

		return Ok(());
	}

	pub fn handle_act(&mut self, buf_msg: &mut [u8; PUBKY_DATA_MSG_LEN], payload: Vec<u8>, buf_tag: &mut [u8; 16]) -> Result <(), ()> {
		// Section 5.3 The HandshakeState Object
		// 
		// For "e": Sets re (which must be empty) to the next DHLEN bytes
		// from the message. Calls MixHash(re.public_keys).
		//
		// For "ee": Calls MixKey (DH(e, re)).
		//
		// For "es": Calls MixKey (DH(e, rs)) if initiator, MixKey(DH(s, re))
		// if responder.

		if self.noise_state == NoisePhase::HandShake {
			match self.message_patterns {
				HandshakeState::PatternN => {
					// Processing "e"
					let mut key_buf = [0; 32];
					let mut counter = 0;
					for b in buf_msg.iter() {
						key_buf[counter] = *b as u8;
						counter += 1;
						if counter == 32 { break; }
					}
					//println!("key buf {:?}", key_buf);
					let edwards_point = MontgomeryPoint(key_buf).to_edwards(0);
					let verifying_key = VerifyingKey::from(edwards_point.unwrap());
					//println!("verifying key {:?}", verifying_key);
					let mut buffer_bytes = [0; 32];
					buffer_bytes[0..32].copy_from_slice(verifying_key.as_ref());
					let remote_e_pubkey: PublicKey = (&buffer_bytes).try_into().unwrap();
					self.remote_ephemeral_pubkey = Some(remote_e_pubkey);

					self.symmetric_state.mix_hash(self.remote_ephemeral_pubkey.clone().unwrap().as_bytes().to_vec());
					//println!("mix hash good");

					// Processing "es"
					if !self.initiator {
						//println!("static public key {:?}", Keypair::from_secret_key(&self.local_static_seckey.clone().unwrap()).public_key().as_bytes());
						//println!("ephemeral public key {:?}", self.remote_ephemeral_pubkey.clone().unwrap().as_bytes());
						let static_secret = StaticSecret::from(self.local_static_seckey.clone().unwrap());
						let remote_ephemeral_pubkey = XPublicKey::from(self.remote_ephemeral_pubkey.clone().unwrap().verifying_key().to_montgomery().to_bytes());
						//println!("static_secret {:?}", static_secret.to_bytes());
						//println!("ephemeral_pubkey {:?}", remote_ephemeral_pubkey.as_bytes());
						let responder_shared_secret = static_secret.diffie_hellman(&remote_ephemeral_pubkey);
						//println!("responder shared secret {:?}", responder_shared_secret.as_bytes());
						self.symmetric_state.mix_key(responder_shared_secret.as_bytes().to_vec());
						//println!("mix key good");
					} else {
						//TODO:  no-implemented: "one-way"
					}
				}
				HandshakeState::PatternNN => {
					match self.noise_step {
						NoiseStep::StepOne => {
							// Processing "e"
							let mut key_buf = [0;32];
							let mut counter = 0;
							for b in buf_msg.iter() {
								key_buf[counter] = *b as u8;
								counter += 1;
								if counter == 32 { break; }
							}
							let edwards_point = MontgomeryPoint(key_buf).to_edwards(0);
							let verifying_key = VerifyingKey::from(edwards_point.unwrap());
							let mut buffer_bytes = [0; 32];
							buffer_bytes[0..32].copy_from_slice(verifying_key.as_ref());
							let remote_e_pubkey: PublicKey = (&buffer_bytes).try_into().unwrap();
							self.remote_ephemeral_pubkey = Some(PublicKey::from(remote_e_pubkey));

							self.symmetric_state.mix_hash(self.remote_ephemeral_pubkey.clone().unwrap().as_bytes().to_vec());
							self.noise_step = NoiseStep::StepTwo;
						}
						NoiseStep::StepTwo => {
							// Processing "ee"
							let static_secret = StaticSecret::from(self.local_ephemeral_seckey.clone().unwrap());
							let remote_ephemeral_pubkey = XPublicKey::from(self.remote_ephemeral_pubkey.clone().unwrap().verifying_key().to_montgomery().to_bytes());
							let responder_shared_secret = static_secret.diffie_hellman(&remote_ephemeral_pubkey);
							self.symmetric_state.mix_key(responder_shared_secret.as_bytes().to_vec());
							self.noise_step = NoiseStep::Final;
						}
						_ => {},
					}
				}
			}

			let mut remaining_buffer = [0;PUBKY_DATA_MSG_LEN];
			let mut counter = 0;
			for c in buf_msg[32..PUBKY_DATA_MSG_LEN].iter() {
				remaining_buffer[counter] = *c as u8;
			}
			self.symmetric_state.decrypt_and_hash(payload, &mut remaining_buffer, buf_tag);

			let (cipher_state_one, cipher_state_two) = self.symmetric_state.split();

			self.from_cipher_state = Some(cipher_state_two);
			self.to_cipher_state = Some(cipher_state_one);
			self.noise_state = NoisePhase::Transport;
		} else if self.noise_state == NoisePhase::Transport {
			let ad = [0; HASHLEN];
			self.to_cipher_state.as_mut().unwrap().decrypt_with_ad(ad, payload, buf_msg, buf_tag);
		}

		return Ok(());
	}
}
