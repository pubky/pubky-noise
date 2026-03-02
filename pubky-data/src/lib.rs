pub mod identity_payload;
pub mod mobile_manager;
pub mod serializer;
pub mod snow_crypto;

use std::collections::HashMap;

use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use pubky::prelude::*;
use pubky::PubkySession;

use crypto::digest::Digest;
use crypto::sha2::Sha512;

use serializer::PubkyDataBackupFormatter;
use snow_crypto::{DataLinkContext, HandshakeAction, HandshakePattern, PUBKY_DATA_MSG_LEN};

// ekey: ephmeral key
// skey: static key
#[derive(Eq, Hash, PartialEq, Clone)]
pub struct PubkyKeySet {
    holder_skey: Option<[u8; 32]>,
    remote_pkey: Option<PublicKey>,
    //TODO: derive
}

impl PubkyKeySet {
    pub fn new(holder_skey: Option<[u8; 32]>, remote_pkey: Option<PublicKey>) -> Self {
        PubkyKeySet {
            holder_skey,
            remote_pkey,
        }
    }
}

// LinkId: derived from Noise handshake transcript hash | changes every handshake
// ConversationId: random per thread | stable for thread lifetime
// PairContextId: derived from peer pubkey pair | stable across all threads

// Derived from noise handshake ; changes on every handshake
#[derive(Eq, Hash, PartialEq, Clone, Copy, Debug)]
pub struct LinkId(pub [u8; 32]);

#[derive(Eq, Hash, PartialEq, Clone, Copy, Debug)]
pub struct TemporaryLinkId(pub [u8; 32]);

impl TemporaryLinkId {
    fn gen_new_random() -> TemporaryLinkId {
        let mut buf = [0; 32];
        rand::fill(&mut buf[..]);
        TemporaryLinkId(buf)
    }
}

#[derive(Eq, Hash, PartialEq, Clone, Copy, Debug)]
pub struct ConversationId(pub [u8; 32]);

impl ConversationId {
    fn gen_new_random() -> ConversationId {
        let mut buf = [0; 32];
        rand::fill(&mut buf[..]);
        ConversationId(buf)
    }
}

// opaque data type
// assuming peers keys uniqueness holds, a
// context id should be unique too and not
// collide with another context id.
// TODO: should the ContextId consume Stack-local
// entropy to avoid cross-stack collision if the
// same pair of static keys is given ?
#[derive(Eq, Hash, PartialEq, Clone, Debug)]
pub struct PairContextId(pub [u8; 64]);

//TODO: verify if PairContextId is good with standard
impl PairContextId {
    fn generate_from(holder_context_key: [u8; 32], remote_context_key: PublicKey) -> Self {
        let holder_secret = StaticSecret::from(holder_context_key);
        let remote_public_key = XPublicKey::from(
            remote_context_key
                .verifying_key()
                .to_montgomery()
                .to_bytes(),
        );
        let shared_secret = holder_secret.diffie_hellman(&remote_public_key);

        //TODO: check the derivation
        let shared_pubkey = XPublicKey::from(shared_secret.to_bytes());

        let mut hash_engine = Sha512::new();
        hash_engine.input(&shared_pubkey.to_bytes());
        let mut out_buf = [0; 64];
        hash_engine.result(&mut out_buf);

        PairContextId(out_buf)
    }
}

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
pub enum LinkStatus {
    HandshakeInitiated,
    Opened,
    Closed,
}

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
pub struct LinkState {
    link_status: LinkStatus,
    messages_counter: u32,
    message_available: bool,
}

impl LinkState {
    #[allow(dead_code)]
    fn generate_from(status: LinkStatus, counter: u32, available: bool) -> Self {
        LinkState {
            link_status: status,
            messages_counter: counter,
            message_available: available,
        }
    }
}

//TODO: implement Hash trait

#[derive(Eq, Hash, PartialEq, Debug)]
pub enum PubkyDataError {
    UnknownNoisePattern,
    SnowNoiseBuildError,
    AlreadyExistentContext,
    BadLengthCiphertext,
    /// the homeserver
    HomeserverPathError,
    /// the homeserver response is a failure
    HomeserverResponseError,
    NoiseContextNotFound,
    IsTransport,
    IsHandshake,
    OtherError,
}

#[derive(Eq, Hash, PartialEq, Debug)]
enum LinkIdentifier {
    Temporary(TemporaryLinkId),
    #[allow(dead_code)]
    Set(LinkId),
}

#[derive(Debug)]
pub struct PubkyDataEncryptor {
    // for now we only assume one session per peer.
    handshake_contexts: HashMap<TemporaryLinkId, DataLinkContext>,
    transport_contexts: HashMap<LinkId, DataLinkContext>,

    outbox_client: Pubky,

    pair_context_id_to_link: HashMap<PairContextId, LinkIdentifier>,

    // for now there is no additional derivation from pubky data root
    #[allow(dead_code)]
    pubky_root_keypair: Keypair,

    // highest supported pubky data version
    // TODO: add minimal versioning
    #[allow(dead_code)]
    pubky_data_version: u32,

    // default pattern asked by application
    // public for testing
    pub default_pattern: HandshakePattern,

    // for now we assume one local homeserver per client.
    local_session: PubkySession,

    destination_path: String,

    // test-only configuration flags
    simulate_tampering: bool,
    last_ciphertext: Option<[u8; PUBKY_DATA_MSG_LEN + 2]>,
}

impl PubkyDataEncryptor {
    /// Init an encryptor stack to share Noise messages with a target Pubky homeserver.
    ///
    /// Use this method to get an application-wise generic manager of the forwarding and
    /// reading of Noise messages with multiple Pubky Data peers.
    ///
    /// # Parameters:
    ///      - `pubky_root_seckey`: A 32-byte root secret key from which to derive per-link static key. Currently unused.
    ///      - `pubky_data_version`: An integer identifier versioning which version of Pubky Data protocol to be talk by this encryptor.
    ///      - `pattern_string`: A 2-byte sized string encoding the default Noise pattern to be talk by this encryptor.
    ///      - `homeserver_auth_session`: A signed-up PubkySession to authenticate with the target Pubky homeserver.
    ///      - `destination_path`: A custom destination prefix to designate the Noise messages sharing endpoint.
    ///      - `pubky_client`: A HTTP Pubky client to connectwith the target Pubky homeserver.
    ///
    /// The `simulate_tampering` is a test-only parameter and it should be set to false when
    /// the encryption library is used in production.
    ///
    /// # Errors:
    ///      - Returns [`PubkyDataError::UnknownNoisePattern`] if the `pattern_string` is not a valid supported Noise pattern.
    pub fn init_encryptor_stack(
        pubky_root_seckey: [u8; 32],
        pubky_data_version: u32,
        pattern_string: String,
        homeserver_auth_session: PubkySession,
        destination_path: String,
        outbox_client: Pubky,
        simulate_tampering: bool,
    ) -> Result<Self, PubkyDataError> {
        let pubky_root_keypair = Keypair::from_secret(&pubky_root_seckey);
        let handshake_contexts = HashMap::new();
        let transport_contexts = HashMap::new();
        let pair_context_id_to_link = HashMap::new();

        let default_pattern = if let Ok(hds) = HandshakePattern::from_string(pattern_string) {
            hds
        } else {
            return Err(PubkyDataError::UnknownNoisePattern);
        }; // unknown noise pattern (api error)
        Ok(PubkyDataEncryptor {
            handshake_contexts,
            transport_contexts,
            outbox_client,
            pair_context_id_to_link,
            pubky_root_keypair,
            pubky_data_version,
            default_pattern,
            local_session: homeserver_auth_session,
            destination_path,
            simulate_tampering,
            last_ciphertext: None,
        })
    }

    //TODO: add outbox path where local client has read / write on it
    /// Init a data-link context to encrypt / decrypt messages at destination / from a Pubky Data peer.
    ///
    /// Use this method to get a data link context initialized with local application and remote peer
    /// public keys. The generated `PairContextId` should be an opaque unique identifier of the data link context.
    ///
    /// # Parameters:
    ///      - `key_set`: A pair of a local application static secret key and a remote peer static ed25519 public key.
    ///      - `initiator`: A boolean flag if the local application is the Noise handshake initiator or not.
    ///      - `endpoint_pubkey`: A remote peer ed25519 public key to be used as a suffix in the path to the sharing endpoiint.
    ///
    /// # Errors:
    ///      - Returns [`PubkyDataError::SnowNoiseBuildError`] if the internal Snow stack building fails.
    ///      - Returns [`PubkyDataError::AlreadyExistentContext`] if the context is already existent for this key set.
    //TODO: Expose PairContextId in Ok result ?
    pub fn init_context(
        &mut self,
        key_set: PubkyKeySet,
        initiator: bool,
        endpoint_pubkey: PublicKey,
    ) -> Result<TemporaryLinkId, PubkyDataError> {
        // we pick up ephemeral key in priority as it's more "ephemeral" like a context.
        let holder_context_skey = key_set.holder_skey.unwrap();
        let remote_context_key = key_set.remote_pkey.clone().unwrap();

        //let context_id = PairContextId::generate_from(holder_context_skey, remote_context_key);
        let temporary_link_id = TemporaryLinkId::gen_new_random();
        let pair_context_id = PairContextId::generate_from(holder_context_skey, remote_context_key);

        let ret = self.pair_context_id_to_link.insert(
            pair_context_id,
            LinkIdentifier::Temporary(temporary_link_id),
        );
        if ret.is_some() {
            return Err(PubkyDataError::AlreadyExistentContext);
        }

        let data_link_context = if let Ok(dls) = DataLinkContext::new(
            self.default_pattern,
            initiator,
            vec![],
            key_set.holder_skey,
            endpoint_pubkey,
            None, // TODO: revise API
        ) {
            dls
        } else {
            return Err(PubkyDataError::SnowNoiseBuildError);
        };

        let ret = self
            .handshake_contexts
            .insert(temporary_link_id, data_link_context);
        //TODO: check before inserting ?
        if ret.is_some() {
            return Err(PubkyDataError::AlreadyExistentContext);
        }

        Ok(temporary_link_id)
    }

    /// Check a data link context Noise phase status.
    ///
    /// Use this method to determinate if a data link context is either in Handshake phase
    /// or already in Transport phase.
    ///
    /// # Parameters:
    ///      - `context_id`: the opaque unique identifer of the data link context.
    ///
    /// # Errors:
    ///      - Returns [`PubkyDataError::NoiseContextNotFound`] if the stack does not know this context.
    pub fn is_handshake(&self, tmp_link_id: &TemporaryLinkId) -> Result<(), PubkyDataError> {
        //TODO: code can be simplified from the handhsake / transport maps
        if let Some(data_link_context) = self.handshake_contexts.get(tmp_link_id) {
            println!("is handshake {}", data_link_context.is_handshake());
            if data_link_context.is_handshake() {
                Ok(())
            } else {
                Err(PubkyDataError::IsTransport)
            }
        } else {
            Err(PubkyDataError::NoiseContextNotFound)
        }
    }

    /// Handle the forwarding and processing of newer Noise handshake messages for a data link.
    ///
    /// Use this method to advance forward the status of the data link undergoing a handshake
    /// with a remote peer. This method might have to be called numerous times until the handshake
    /// is over for the specifically initialized Noise pattern, i.e as long as `is_handshake()` keeps
    /// yielding a `true` Result.
    ///
    /// # Parameters:
    ///      - `initiate`: A boolean flag if the local application is the Noise handshake initator or not.
    ///      - `context_id`: The opaque unique identifier of the data link context.
    ///      - `public_key`: A remote peer ed25519 public key to be used as a suffix in the path to the sharing endpoiint.
    ///
    /// # Errors:
    ///      - Returns [`PubkyDataError::NoiseContextNotFound`] if the stack does not know this context.
    pub async fn handle_handshake(
        &mut self,
        initiate: bool,
        tmp_link_id: TemporaryLinkId,
        public_key: PublicKey,
    ) -> Result<bool, PubkyDataError> {
        println!("IN HANDLE HANDSHAKE");

        if let Some(data_link_context) = self.handshake_contexts.get_mut(&tmp_link_id) {
            let steps_to_be_done = data_link_context.handshake_steps(initiate);
            for step in steps_to_be_done {
                match step {
                    HandshakeAction::Read => {
                        //TODO: what if more to read: Vec<u8> should be size bounded
                        println!("Handshake Read");
                        let path = self.destination_path.as_str();
                        let counter = data_link_context.get_counter();
                        println!("Reading at Slot {counter}");
                        let formatted_path = format!("{public_key}/{path}/{counter}");

                        if let Ok(response) = self
                            .outbox_client
                            .public_storage()
                            .get(formatted_path)
                            .await
                        {
                            if response.status().is_success() {
                                if let Ok(ciphertext) = response.bytes().await {
                                    println!("getting response bytes...");
                                    //TODO: handle non-standard messages better
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
                                    let _ = data_link_context.read_act(
                                        &mut message,
                                        &mut payload,
                                        len as usize,
                                    );
                                    // we do not care about the result as we shouldn't get plaintext during
                                } else {
                                    return Err(PubkyDataError::HomeserverResponseError);
                                }
                                data_link_context.increment_counter();
                            }
                        }
                        //TODO: make a single message buffer + tag
                    }
                    HandshakeAction::Write => {
                        println!("Handshake Write");
                        let mut message = [0; PUBKY_DATA_MSG_LEN];
                        // the data payload stay empty during the handshake
                        if let Ok(len) = data_link_context.write_act(vec![], &mut message) {
                            println!("FWD LEN {len} CIPHER {message:?}");
                            let path = self.destination_path.as_str();
                            let counter = data_link_context.get_counter();
                            println!("Writing at Slot {counter}");
                            let formatted_path = format!("{path}/{counter}");
                            let mut packet = [0; PUBKY_DATA_MSG_LEN + 2];
                            let be_bytes = (len as u16).to_be_bytes();
                            packet[0..2].copy_from_slice(&be_bytes[0..2]);
                            packet[2..len + 2].copy_from_slice(&message[0..len]);
                            let _ = self
                                .local_session
                                .storage()
                                .put(formatted_path, packet.to_vec())
                                .await;
                            data_link_context.increment_counter();
                        }
                    }
                    HandshakeAction::Pending => {
                        // we return responsibility processing to network runtime
                        break;
                    }
                    HandshakeAction::Terminal => {
                        break;
                    }
                }
            }
        } else {
            return Err(PubkyDataError::NoiseContextNotFound);
        }
        Ok(true)
    }

    /// Transition a data link context from the Noise Handshake phase to the Transport phase.
    ///
    /// Use this method to move a data link context status from the Noise Handshake pahse to
    /// the Transport phase, i.e once the `is_handshake()` method yields a `false` Result.
    ///
    /// # Parameters:
    ///      - `context_id`: The opaque unique identifier of the data link context.
    ///
    /// # Errors:
    ///      - Returns [`PubkyDataError::IsHandshake`] if the data link context is still in Handshake phase.
    ///      - Returns [`PubkyDataError::NoiseContextNotFound`] if the stack does not know this context.
    pub fn transition_transport(
        &mut self,
        tmp_link_id: TemporaryLinkId,
    ) -> Result<LinkId, PubkyDataError> {
        if let Some(data_link_context) = self.handshake_contexts.get_mut(&tmp_link_id) {
            if data_link_context.is_handshake() {
                return Err(PubkyDataError::IsHandshake);
            }
        }
        if let Some(mut data_link_context) = self.handshake_contexts.remove(&tmp_link_id) {
            let link_id = LinkId(data_link_context.get_handshake_hash().unwrap());
            //TODO: send IdentityPayload now ?
            let _ = data_link_context.to_transport();
            self.transport_contexts.insert(link_id, data_link_context);
            return Ok(link_id);
        }
        Err(PubkyDataError::NoiseContextNotFound)
    }

    /// Encrypt and send the given plaintext over the data link associated with the context.
    ///
    /// Use this method to encrypt and send an arbitary byte-vector data paylaod to a remote
    /// peer through the means of a target homeserver. The target homeserver should have been
    /// picked up at the stack initialization, and currently it cannot be "hot"-updated.
    ///
    /// # Parameters:
    ///      - `plaintext`: An arbitrary byte-vector data payload to be encrypted to a given remote peer.
    ///      - `context_id`: the opaque unique identifier of the data link context.
    ///
    /// # Errors:
    ///      - Returns false if there is a problem
    //TODO: upgrade error handling
    pub async fn send_message(&mut self, plaintext: Vec<u8>, link_id: LinkId) -> bool {
        //TODO: implement thread pool here:
        //	- parallelize at the session-level
        //	- impossible at the message-level due the cryptographic accumulation

        println!("in send message");
        let mut results = Vec::new();
        if let Some(data_link_context) = self.transport_contexts.get_mut(&link_id) {
            let mut out = [0; PUBKY_DATA_MSG_LEN];
            if let Ok(len) = data_link_context.write_act(plaintext, &mut out) {
                println!("FWD LEN {len} CIPHER {out:?}");
                let mut packet = [0; PUBKY_DATA_MSG_LEN + 2];
                let be_bytes = (len as u16).to_be_bytes();
                packet[0..2].copy_from_slice(&be_bytes[0..2]);
                packet[2..len + 2].copy_from_slice(&out[0..len]);

                if self.simulate_tampering {
                    self.last_ciphertext = Some(packet);
                }

                results.push(packet);
            }
        } else {
            return false;
        }

        println!("number of cipher to send {}", results.len());
        println!("destination path {:?}", self.destination_path.as_str());
        if let Some(data_link_context) = self.transport_contexts.get_mut(&link_id) {
            for packet in results {
                let path = self.destination_path.as_str();
                let counter = data_link_context.get_counter();
                println!("Writing at Slot {counter}");
                let formatted_path = format!("{path}/{counter}");
                if (self
                    .local_session
                    .storage()
                    .put(formatted_path, packet.to_vec())
                    .await)
                    .is_ok()
                {
                } else {
                    return false;
                }
                data_link_context.increment_counter();
            }
        } else {
            return false;
        }

        true
    }

    /// Receive a given plaintext over the data link associated with the context.
    ///
    /// Use this method to receive and decrypt an arbitrary byte-vector data payload to a remote
    /// peer through the means of a target homeserver. The target homeserver should have been
    /// picked up at the stack initialization, and currently it cannot be "hot"-updated.
    ///
    /// # Parameters:
    ///      - `context_id`: the opaque unique identifier of the data link context.
    ///
    /// # Errors:
    ///      - Returns an empty vector if there is a problem
    //TODO: upgrade error handling
    pub async fn receive_message(&mut self, link_id: LinkId) -> Vec<[u8; PUBKY_DATA_MSG_LEN]> {
        let mut results = Vec::new();
        if let Some(data_link_context) = self.transport_contexts.get_mut(&link_id) {
            let path = self.destination_path.as_str();
            let counter = data_link_context.get_counter();
            println!("Reading at Slot {counter}");
            let public_key = data_link_context.get_endpoint();
            let formatted_path = format!("{public_key}/{path}/{counter}");
            if let Ok(response) = self
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
                        //TODO: handle non-standard messages better
                        let mut buf_len = [0; 2];
                        buf_len[0..2].copy_from_slice(&ciphertext[0..2]);
                        let len = u16::from_be_bytes(buf_len);
                        let mut message = [0; PUBKY_DATA_MSG_LEN];
                        message[0..len as usize].copy_from_slice(&ciphertext[2..len as usize + 2]);
                        let mut payload = [0; PUBKY_DATA_MSG_LEN];
                        println!("RCV LEN {len} CIPHER {message:?}");

                        // TEST-ONLY CODE PATHS
                        if self.simulate_tampering {
                            message[1] = 0xff;
                        }

                        let _ =
                            data_link_context.read_act(&mut message, &mut payload, len as usize);
                        results.push(payload);
                        data_link_context.increment_counter();
                    }
                }
            }
        }
        results
    }

    /// Get the context state corresponding to the provided data link context identifier.
    ///
    /// Use this method to yield the context state for a data link. Currently, it's
    /// only a counter of the number of messages exchanged.
    ///
    /// # Parameters:
    ///      - `context_id`: the opaque unique identifier of the data link context.
    ///
    /// # Errors:
    ///      - Returns [`PubkyDataError::NoiseContextNotFound`] if the stack does not know this context.
    pub fn get_context_status(&mut self, link_id: LinkId) -> Result<LinkState, PubkyDataError> {
        if let Some(_context_present) = self.transport_contexts.remove(&link_id) {
            //TODO: check homeserver status

            //Ok(ContextState::generate_from(context_present.get_counter()))
            Err(PubkyDataError::NoiseContextNotFound)
        } else {
            Err(PubkyDataError::NoiseContextNotFound)
        }
    }

    /// Close and clean the context state corresponding to the provided data link context identifier.
    ///
    /// Use this method when there is no more usage of the data link context to be expected. The
    /// internal data link context state is to be selectively clean up.
    ///
    /// # Parameters:
    ///      - `context_id`: the opaque unique identifier of data link context.
    ///
    /// # Errors:
    ///      - Returns [`PubkyDataError::NoiseContextNotFound`] if the stack does not know this context.
    //TODO: make the cleanup more in depth.
    pub fn close_context(&mut self, link_id: &LinkId) -> Result<bool, PubkyDataError> {
        if let Some(mut found) = self.transport_contexts.remove(link_id) {
            found.delete();
            Ok(true)
        } else {
            Err(PubkyDataError::NoiseContextNotFound)
        }
    }

    /// Close and clean the whole Pubky Data encryptor stack.
    ///
    /// Use this method when there is no more usage of the encryptor stack, neither of any of
    /// its data link context. This method is systematically cleaning up all the existing data
    /// link contexts, and it's selecting cleaning up their internal states.
    pub fn clean_encryptor_stack(&mut self) {
        //TODO: KeyPair zeroize root key
        let mut empty_map: Vec<(LinkId, DataLinkContext)> =
            self.transport_contexts.drain().collect();
        for entry in empty_map.iter_mut() {
            entry.1.delete();
        }
    }

    pub async fn generate_context_backup(
        &self,
        link_id: LinkId,
        _commit: bool,
    ) -> Result<(), PubkyDataError> {
        // 1. collect
        // 2. serialize
        // 3. encrypt
        // 4. forward
        // 5. return
        if let Some(_context) = self.transport_contexts.get(&link_id) {
            let backup_formatter = PubkyDataBackupFormatter::new();
            let serialized_backup = backup_formatter.serialize();
            //TODO: encryption step
            let public_key = self.pubky_root_keypair.public_key();
            let formatted_backup_path = format!("pubky/{public_key}/backup");
            let _ = self
                .local_session
                .storage()
                .put(formatted_backup_path, serialized_backup.to_vec())
                .await;
            Ok(())
        } else {
            Err(PubkyDataError::NoiseContextNotFound)
        }
    }

    pub fn load_context_backup(&self, _state: Vec<u8>) {
        //TODO: ChaCha20 + pubky_root_keypair
        // 1. fetch
        // 2. decrypt
        // 3. deserialize
        //let backup_formatter = PubkyDataBackupFormatter::deserialize(vec![]);
    }

    pub fn test_get_last_ciphertext(&self) -> Option<[u8; PUBKY_DATA_MSG_LEN + 2]> {
        self.last_ciphertext
    }
}
