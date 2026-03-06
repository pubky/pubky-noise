use ed25519_dalek::SecretKey;
use pubky::PublicKey;

use snow::Builder;
use snow::{HandshakeState, TransportState};

pub const PUBKY_DATA_MSG_LEN: usize = 1000;

#[derive(PartialEq, Debug)]
enum NoisePhase {
    HandShake,
    Transport,
}

#[derive(PartialEq, Copy, Clone, Debug)]
enum NoiseStep {
    StepOne,
    StepTwo,
    Final,
}

impl NoiseStep {
    fn next_step(&self) -> NoiseStep {
        match self {
            NoiseStep::StepOne => NoiseStep::StepTwo,
            NoiseStep::StepTwo => NoiseStep::Final,
            // if final echo final
            NoiseStep::Final => NoiseStep::Final,
        }
    }
}

#[derive(PartialEq)]
pub enum HandshakeAction {
    Read,
    Write,
    Pending,
    Terminal,
}

/// The source properties are:
/// 0. No authentication. This payload may have been sent by any party, including an active attacker.
/// 1. Sender authentication vulnerable to key-compromise impersonation (KCI). The sender authentication is based on a static-static DH ("ss") involving both parties' static key pairs. If the recipient's long-term private key has been compromised, this authentication can be forged. Note that a future version of Noise might include signatures, which could improve this security property, but brings other trade-offs.
/// 2. Sender authentication resistant to key-compromise impersonation (KCI). The sender authentication is based on an ephemeral-static DH ("es" or "se") between the sender's static key pair and the recipient's ephemeral key pair. Assuming the corresponding private keys are secure, this authentication cannot be forged.
///
/// The destination properties are:
/// 0. No confidentiality. This payload is sent in cleartext.
/// 1. Encryption to an ephemeral recipient. This payload has forward secrecy, since encryption involves an ephemeral-ephemeral DH ("ee"). However, the sender has not authenticated the recipient, so this payload might be sent to any party, including an active attacker.
/// 2. Encryption to a known recipient, forward secrecy for sender compromise only, vulnerable to replay. This payload is encrypted based only on DHs involving the recipient's static key pair. If the recipient's static private key is compromised, even at a later date, this payload can be decrypted. This message can also be replayed, since there's no ephemeral contribution from the recipient.
/// 3. Encryption to a known recipient, weak forward secrecy. This payload is encrypted based on an ephemeral-ephemeral DH and also an ephemeral-static DH involving the recipient's static key pair. However, the binding between the recipient's alleged ephemeral public key and the recipient's static public key hasn't been verified by the sender, so the recipient's alleged ephemeral public key may have been forged by an active attacker. In this case, the attacker could later compromise the recipient's static private key to decrypt the payload. Note that a future version of Noise might include signatures, which could improve this security property, but brings other trade-offs.
/// 4. Encryption to a known recipient, weak forward secrecy if the sender's private key has been compromised. This payload is encrypted based on an ephemeral-ephemeral DH, and also based on an ephemeral-static DH involving the recipient's static key pair. However, the binding between the recipient's alleged ephemeral public and the recipient's static public key has only been verified based on DHs involving both those public keys and the sender's static private key. Thus, if the sender's static private key was previously compromised, the recipient's alleged ephemeral public key may have been forged by an active attacker. In this case, the attacker could later compromise the intended recipient's static private key to decrypt the payload (this is a variant of a "KCI" attack enabling a "weak forward secrecy" attack). Note that a future version of Noise might include signatures, which could improve this security property, but brings other trade-offs.
/// 5. Encryption to a known recipient, strong forward secrecy. This payload is encrypted based on an ephemeral-ephemeral DH as well as an ephemeral-static DH with the recipient's static key pair. Assuming the ephemeral private keys are secure, and the recipient is not being actively impersonated by an attacker that has stolen its static private key, this payload cannot be decrypted.
#[derive(PartialEq, Copy, Clone, Debug)]
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
    // test-only pattern to inject build fault
    TestOnlyPatternAA,
}

pub enum PatternError {
    UnknownLitteralPattern,
}

impl HandshakePattern {
    fn pattern_to_string(&self) -> Result<String, ()> {
        match self {
            HandshakePattern::PatternN => Ok(String::from("N")),
            HandshakePattern::PatternNN => Ok(String::from("NN")),
            HandshakePattern::PatternXX => Ok(String::from("XX")),
            HandshakePattern::PatternIK => Ok(String::from("IK")),
            HandshakePattern::PatternNK => Ok(String::from("NK")),
            HandshakePattern::TestOnlyPatternAA => Ok(String::from("AA")),
        }
    }

    //TODO: fix
    pub fn from_string(pattern_string: String) -> Result<Self, PatternError> {
        match pattern_string.as_str() {
            "N" => Ok(HandshakePattern::PatternN),
            "NN" => Ok(HandshakePattern::PatternNN),
            "XX" => Ok(HandshakePattern::PatternXX),
            "IK" => Ok(HandshakePattern::PatternIK),
            "NK" => Ok(HandshakePattern::PatternNK),
            "AA" => Ok(HandshakePattern::TestOnlyPatternAA),
            _ => Err(PatternError::UnknownLitteralPattern),
        }
    }

    pub fn needs_local_key(&self) -> bool {
        match self {
            HandshakePattern::PatternN => false,
            HandshakePattern::PatternNN => false,
            HandshakePattern::PatternXX => true,
            HandshakePattern::PatternIK => true,
            HandshakePattern::PatternNK => true,
            HandshakePattern::TestOnlyPatternAA => false,
        }
    }
}

fn resolve_pattern_nn(noise_step: NoiseStep, initiator: bool) -> Vec<HandshakeAction> {
    let mut steps_to_be_done: Vec<HandshakeAction> = Vec::new();
    if initiator {
        match noise_step {
            NoiseStep::StepOne => {
                steps_to_be_done.push(HandshakeAction::Write);
                steps_to_be_done.push(HandshakeAction::Pending);
            }
            NoiseStep::StepTwo => {
                steps_to_be_done.push(HandshakeAction::Read);
            }
            NoiseStep::Final => {
                steps_to_be_done.push(HandshakeAction::Terminal);
            }
        }
    } else {
        // == responder
        match noise_step {
            NoiseStep::StepOne => {
                steps_to_be_done.push(HandshakeAction::Read);
                steps_to_be_done.push(HandshakeAction::Write);
            }
            NoiseStep::StepTwo => {
                steps_to_be_done.push(HandshakeAction::Terminal);
            }
            NoiseStep::Final => {
                steps_to_be_done.push(HandshakeAction::Terminal);
            }
        }
    }
    steps_to_be_done
}

fn resolve_pattern_xx(noise_step: NoiseStep, initiator: bool) -> Vec<HandshakeAction> {
    let mut steps_to_be_done: Vec<HandshakeAction> = Vec::new();
    if initiator {
        match noise_step {
            NoiseStep::StepOne => {
                // write -> e
                steps_to_be_done.push(HandshakeAction::Write);
                steps_to_be_done.push(HandshakeAction::Pending);
            }
            NoiseStep::StepTwo => {
                // read <- e, s
                steps_to_be_done.push(HandshakeAction::Read);
                // write -> s
                steps_to_be_done.push(HandshakeAction::Write);
            }
            NoiseStep::Final => {
                steps_to_be_done.push(HandshakeAction::Terminal);
            }
        }
    } else {
        // == responder
        match noise_step {
            NoiseStep::StepOne => {
                // read -> e
                steps_to_be_done.push(HandshakeAction::Read);
                // write <- e, s
                steps_to_be_done.push(HandshakeAction::Write);
                steps_to_be_done.push(HandshakeAction::Pending);
            }
            NoiseStep::StepTwo => {
                // read -> s
                steps_to_be_done.push(HandshakeAction::Read);
            }
            NoiseStep::Final => {
                steps_to_be_done.push(HandshakeAction::Terminal);
            }
        }
    }
    steps_to_be_done
}

fn resolve_pattern_ik(_noise_step: NoiseStep, _initiator: bool) -> Vec<HandshakeAction> {
    vec![]
}

fn resolve_pattern_nk(_noise_step: NoiseStep, _initiator: bool) -> Vec<HandshakeAction> {
    vec![]
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

    noise_step: NoiseStep,
    noise_phase: NoisePhase,

    noise_handshake: Option<HandshakeState>,
    noise_transport: Option<TransportState>,

    endpoint_pubkey: PublicKey,

    counter: u32,
    //TODO: add context creation date ?
    //TODO: already there for identity binding
    #[allow(dead_code)]
    local_pkarr_pubkey: Option<PublicKey>,
}

impl DataLinkContext {
    pub fn new(
        handshake_pattern: HandshakePattern,
        initiator: bool,
        _prologue: Vec<u8>,
        local_static_key: Option<SecretKey>,
        endpoint_pubkey: PublicKey,
        local_pkarr_pubkey: Option<PublicKey>,
    ) -> Result<DataLinkContext, ContextError> {
        // Section 5.3 The Handshake Object
        //
        // Perform the following steps:
        // - Derives a protocol_name byte sequence by combining the names for
        //   the handshake pattern and crypto functions, as specified in Section 8.
        //   Calls InitializeSymmetric(protocol_name).

        let mut protocol_name = String::from("Noise");
        protocol_name.push('_');
        let pattern_string = if let Ok(pattern_string) = handshake_pattern.pattern_to_string() {
            pattern_string
        } else {
            return Err(ContextError::Init);
        };
        protocol_name.push_str(&pattern_string);
        let basic_string = String::from("_25519_ChaChaPoly_SHA256");
        protocol_name.push_str(&basic_string);

        println!("Current Protocol Name {protocol_name}");

        let builder_init = protocol_name.clone().parse();
        if builder_init.is_err() {
            return Err(ContextError::Init);
        }
        let builder_init = builder_init.unwrap();

        let builder = Builder::new(builder_init);

        let noise_stack = if handshake_pattern.needs_local_key() {
            if local_static_key.is_none() {
                return Err(ContextError::Init);
            }
            if initiator {
                builder
                    .local_private_key(&local_static_key.unwrap())
                    .unwrap()
                    .build_initiator()
            } else {
                builder
                    .local_private_key(&local_static_key.unwrap())
                    .unwrap()
                    .build_responder()
            }
        } else if initiator {
            builder.build_initiator()
        } else {
            builder.build_responder()
        };

        println!("build result {noise_stack:?}");
        if noise_stack.is_err() {
            return Err(ContextError::Init);
        }

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

            noise_step: NoiseStep::StepOne,
            noise_phase: NoisePhase::HandShake,

            noise_handshake: Some(noise_stack.unwrap()),
            noise_transport: None,

            endpoint_pubkey,

            counter: 0,

            local_pkarr_pubkey,
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
        //TODO: memorize the cryptographic state by forcing the flush of zeroized
        // memory pages to disk.
        self.local_static_seckey = None;
    }

    pub fn is_handshake(&self) -> bool {
        !self
            .noise_handshake
            .as_ref()
            .unwrap()
            .is_handshake_finished()
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
        println!(
            "TO TRANSPORT HANDSHAKE FINISHED {} INITIATOR {}",
            self.noise_handshake
                .as_ref()
                .unwrap()
                .is_handshake_finished(),
            self.initiator
        );
        if !self
            .noise_handshake
            .as_ref()
            .unwrap()
            .is_handshake_finished()
        {
            return Err(ContextError::OngoingHandshake);
        }
        let transport = self.noise_handshake.take().unwrap().into_transport_mode();
        if let Ok(transport) = transport {
            println!("TRANSPORT OK");
            //TODO: zeroize HandshakeState
            self.noise_transport = Some(transport);
            self.noise_phase = NoisePhase::Transport;
            return Ok(());
        }
        println!("TRANSPORT NOT OK");
        Err(ContextError::InternalSnowTransitionErr)
    }

    pub fn handshake_steps(&mut self, initiator: bool) -> Vec<HandshakeAction> {
        //TODO: write resolve pattern
        assert!(
            self.message_patterns == HandshakePattern::PatternNN
                || self.message_patterns == HandshakePattern::PatternXX
        );
        let steps_to_be_done = match self.message_patterns {
            HandshakePattern::PatternNN => resolve_pattern_nn(self.noise_step, initiator),
            HandshakePattern::PatternXX => resolve_pattern_xx(self.noise_step, initiator),
            HandshakePattern::PatternIK => resolve_pattern_ik(self.noise_step, initiator),
            HandshakePattern::PatternNK => resolve_pattern_nk(self.noise_step, initiator),
            _ => {
                panic!("unsupported handshake pattern for resolution");
            }
        };
        self.noise_step = self.noise_step.next_step();
        steps_to_be_done
    }

    pub fn write_act(
        &mut self,
        payload: Vec<u8>,
        message: &mut [u8; PUBKY_DATA_MSG_LEN],
    ) -> Result<usize, ContextError> {
        //TODO: care better about error
        // Section 5.3 The HandshakeState object
        //
        // For "e": Sets e (which must be empty) to GENERATE_KEYPAIR().
        // Appends e.public_key to the buffer. Calls MixHash(e.public_key).
        //
        // For "ee": Calls MixKey(DH(e, re))
        //
        // For "es": Calls MixKey (DH(e, rs)) if initiator, MixKey(DH(s, re)
        // if responder.
        println!("SNOW WRITE {payload:?}");
        let mut ret = 0;
        if self.noise_phase == NoisePhase::HandShake {
            //TODO: determinate_transition()
            let result = self
                .noise_handshake
                .as_mut()
                .unwrap()
                .write_message(&payload, message.as_mut());
	    match result {
		Ok(write_size) => { return Ok(write_size); },
		Err(e) => { return Err(ContextError::InternalSnowWriteErr); },
	    }
        } else if self.noise_phase == NoisePhase::Transport {
            println!("WRITE TRANSPORT");
            println!(
                "payload size {} message size {}",
                payload.len(),
                message.len()
            );
            let result = self
                .noise_transport
                .as_mut()
                .unwrap()
                .write_message(&payload, message.as_mut());
	    match result {
		Ok(write_size) => { return Ok(write_size); },
		Err(e) => { return Err(ContextError::InternalSnowWriteErr); },
	    }
        }

        Ok(ret)
    }

    pub fn read_act(
        &mut self,
        message: &mut [u8; PUBKY_DATA_MSG_LEN],
        payload: &mut [u8; PUBKY_DATA_MSG_LEN],
        index: usize,
    ) -> Result<(), ContextError> {
        // Section 5.3 The HandshakeState Object
        //
        // For "e": Sets re (which must be empty) to the next DHLEN bytes
        // from the message. Calls MixHash(re.public_keys).
        //
        // For "ee": Calls MixKey (DH(e, re)).
        //
        // For "es": Calls MixKey (DH(e, rs)) if initiator, MixKey(DH(s, re))
        // if responder.
        println!("SNOW READ");
        //TODO: improv ret error management
        if self.noise_phase == NoisePhase::HandShake {
            println!("INDEX {index}");
            let ret = self
                .noise_handshake
                .as_mut()
                .unwrap()
                .read_message(&message[..index], payload);
	    match ret {
		Ok(_) => { return Ok(()); },
		Err(e) => { return Err(ContextError::InternalSnowReadErr); },
	    }
        } else if self.noise_phase == NoisePhase::Transport {
            println!("READ TRANSPORT");
            let ret = self
                .noise_transport
                .as_mut()
                .unwrap()
                .read_message(&message[..index], payload);
	    match ret {
		Ok(_) => { return Ok(()); },
		Err(e) => { return Err(ContextError::InternalSnowReadErr); },
	    }
        }

        Ok(())
    }
}
