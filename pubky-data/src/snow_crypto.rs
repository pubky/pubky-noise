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

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum HandshakePattern {
    /// <- s
    /// ...
    /// -> e, es
    PatternN,
    /// -> e,
    /// <- e, ee
    PatternNN,
    /// -> e
    /// <- e, ee, s, es
    /// -> s, se
    PatternXX,
    /// <- s
    /// ...
    /// -> e, es, s, ss
    /// <- e, ee, se
    /// ->
    /// <-
    PatternIK,
    /// <- s
    /// ...
    /// -> e, es
    /// <- e, ee
    /// ->
    PatternNK,
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

    // Tracks progress within the current step's action list for polling-safe handshake.
    // When a Read fails (peer hasn't written yet), we return Pending without advancing
    // sub_step_index, so the next poll retries from the same action.
    sub_step_index: usize,

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

            sub_step_index: 0,

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

    /// Returns the remaining actions for the current step, starting from sub_step_index.
    /// Uses the stored `initiator` flag — callers no longer need to pass it.
    /// Does NOT advance noise_step — call `complete_step()` for that.
    pub fn remaining_handshake_actions(&self) -> Vec<HandshakeAction> {
        assert!(
            self.message_patterns == HandshakePattern::PatternNN
                || self.message_patterns == HandshakePattern::PatternXX
        );
        let all_actions = match self.message_patterns {
            HandshakePattern::PatternNN => resolve_pattern_nn(self.noise_step, self.initiator),
            HandshakePattern::PatternXX => resolve_pattern_xx(self.noise_step, self.initiator),
            HandshakePattern::PatternIK => resolve_pattern_ik(self.noise_step, self.initiator),
            HandshakePattern::PatternNK => resolve_pattern_nk(self.noise_step, self.initiator),
            _ => {
                panic!("unsupported handshake pattern for resolution");
            }
        };
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
            if result.is_err() {
                panic!("NOISE WRITE FAILED {result:?}");
            }
            ret = result.unwrap();
            println!("HANDLE WRITE RET {ret:?}");
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
            if result.is_err() {
                panic!("NOISE WRITE FAILED {result:?}");
            }
            ret = result.unwrap();
            println!("HANDLE WRITE RET {ret:?}");
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
            println!("HANDLE READ RET {ret:?}");
        } else if self.noise_phase == NoisePhase::Transport {
            println!("READ TRANSPORT");
            let ret = self
                .noise_transport
                .as_mut()
                .unwrap()
                .read_message(&message[..index], payload);
            println!("HANDLE READ RET {ret:?}");
        }

        Ok(())
    }
}
