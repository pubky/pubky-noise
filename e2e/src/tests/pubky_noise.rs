use std::sync::Arc;

use pubky_testnet::{
    pubky::{Keypair, PublicKey},
    EphemeralTestnet,
};

use pubky_noise::serializer::PubkyNoiseSessionState;
use pubky_noise::snow_crypto::{
    HandshakePattern, NoisePhase, NoiseStep, PUBKY_NOISE_CIPHERTEXT_LEN, PUBKY_NOISE_MSG_LEN,
};
use pubky_noise::{HandshakeResult, PubkyNoiseConfig, PubkyNoiseEncryptor, PubkyNoiseError};

fn cipher_check(plaintext: &[u8], ciphertext: &[u8; PUBKY_NOISE_CIPHERTEXT_LEN + 2]) {
    let plaintext_len = plaintext.len();
    let mut match_check = 0;
    for counter in 0..plaintext_len {
        if plaintext[counter] == ciphertext[counter] {
            match_check += 1;
        }
    }
    // i.e plaintext == ciphertext byte-for-byte
    if match_check == plaintext_len {
        panic!("plaintext matches ciphertext byte-for-byte — encryption failed")
    }
}

/// Test fixture: a pair of encryptors with their configs, ready for handshake.
struct EncryptorPair {
    initiator: PubkyNoiseEncryptor,
    responder: PubkyNoiseEncryptor,
    initiator_config: Arc<PubkyNoiseConfig>,
    responder_config: Arc<PubkyNoiseConfig>,
    initiator_public_key: PublicKey,
    responder_public_key: PublicKey,
}

/// Create a pair of encryptors on the same homeserver.
async fn setup_encryptors(testnet: &EphemeralTestnet, pattern: &str) -> EncryptorPair {
    let server = testnet.homeserver_app();
    let initiator_pubky = testnet.sdk().unwrap();
    let responder_pubky = initiator_pubky.clone();

    let initiator_signer = initiator_pubky.signer(Keypair::random());
    let initiator_session = initiator_signer
        .signup(&server.public_key(), None)
        .await
        .unwrap();

    let responder_signer = responder_pubky.signer(Keypair::random());
    let responder_session = responder_signer
        .signup(&server.public_key(), None)
        .await
        .unwrap();

    let server_path_string = "/pub/data".to_string();

    let initiator_keypair = Keypair::random();
    let initiator_config = PubkyNoiseConfig::new(
        initiator_keypair.secret_key(),
        0,
        pattern,
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyNoiseConfig::new(
        responder_keypair.secret_key(),
        0,
        pattern,
        responder_session.clone(),
        server_path_string,
        responder_pubky,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key().clone();
    let responder_public_key = responder_session.info().public_key().clone();

    let initiator = PubkyNoiseEncryptor::new(
        initiator_config.clone(),
        initiator_ephemeral_keypair.secret_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();

    let responder = PubkyNoiseEncryptor::new(
        responder_config.clone(),
        responder_ephemeral_keypair.secret_key(),
        false,
        initiator_public_key.clone(),
    )
    .unwrap();

    EncryptorPair {
        initiator,
        responder,
        initiator_config,
        responder_config,
        initiator_public_key,
        responder_public_key,
    }
}

/// Create a pair of encryptors on separate homeservers.
async fn setup_encryptors_dual_server(testnet: &EphemeralTestnet, pattern: &str) -> EncryptorPair {
    let first_server = testnet.homeserver_app();
    let second_server = testnet.homeserver_app();

    let initiator_pubky = testnet.sdk().unwrap();
    let responder_pubky = testnet.sdk().unwrap();

    let initiator_signer = initiator_pubky.signer(Keypair::random());
    let initiator_session = initiator_signer
        .signup(&first_server.public_key(), None)
        .await
        .unwrap();

    let responder_signer = responder_pubky.signer(Keypair::random());
    let responder_session = responder_signer
        .signup(&second_server.public_key(), None)
        .await
        .unwrap();

    let server_path_string = "/pub/data".to_string();

    let initiator_keypair = Keypair::random();
    let initiator_config = PubkyNoiseConfig::new(
        initiator_keypair.secret_key(),
        0,
        pattern,
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyNoiseConfig::new(
        responder_keypair.secret_key(),
        0,
        pattern,
        responder_session.clone(),
        server_path_string,
        responder_pubky,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key().clone();
    let responder_public_key = responder_session.info().public_key().clone();

    let initiator = PubkyNoiseEncryptor::new(
        initiator_config.clone(),
        initiator_ephemeral_keypair.secret_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();

    let responder = PubkyNoiseEncryptor::new(
        responder_config.clone(),
        responder_ephemeral_keypair.secret_key(),
        false,
        initiator_public_key.clone(),
    )
    .unwrap();

    EncryptorPair {
        initiator,
        responder,
        initiator_config,
        responder_config,
        initiator_public_key,
        responder_public_key,
    }
}

/// Create a pair of encryptors with tampering enabled on both sides.
async fn setup_encryptors_with_tampering(
    testnet: &EphemeralTestnet,
    pattern: &str,
) -> EncryptorPair {
    let mut pair = setup_encryptors(testnet, pattern).await;
    pair.initiator.test_enable_tampering();
    pair.responder.test_enable_tampering();
    pair
}

/// Complete an NN handshake and transition both sides to transport.
async fn complete_nn_handshake(pair: &mut EncryptorPair) {
    let _ = pair.initiator.handle_handshake().await;
    let _ = pair.responder.handle_handshake().await;
    let _ = pair.initiator.handle_handshake().await;

    assert!(pair.initiator.is_handshake_complete());
    assert!(pair.responder.is_handshake_complete());

    pair.initiator.transition_transport().unwrap();
    pair.responder.transition_transport().unwrap();
}

/// Complete an XX handshake and transition both sides to transport.
async fn complete_xx_handshake(pair: &mut EncryptorPair) {
    let _ = pair.initiator.handle_handshake().await;
    let _ = pair.responder.handle_handshake().await;
    let _ = pair.initiator.handle_handshake().await;
    let _ = pair.responder.handle_handshake().await;

    assert!(pair.initiator.is_handshake_complete());
    assert!(pair.responder.is_handshake_complete());

    pair.initiator.transition_transport().unwrap();
    pair.responder.transition_transport().unwrap();
}

/// Send a message from sender to receiver and verify it arrives correctly.
async fn send_and_verify(
    sender: &mut PubkyNoiseEncryptor,
    receiver: &mut PubkyNoiseEncryptor,
    message: &str,
) {
    sender.send_message(message.as_bytes()).await;
    let results = receiver.receive_message().await;
    assert!(!results.is_empty());
    let padded_msg = String::from_utf8(results[0].to_vec()).unwrap();
    let (msg, _) = padded_msg.split_at(message.len());
    assert_eq!(msg, message);
}

/// Send a message and verify the receiver gets tampered (non-UTF8) data.
async fn send_and_verify_tampered(
    sender: &mut PubkyNoiseEncryptor,
    receiver: &mut PubkyNoiseEncryptor,
    message: &str,
) {
    let raw_bytes = message.as_bytes();
    sender.send_message(raw_bytes).await;

    let results = receiver.receive_message().await;
    assert!(!results.is_empty());
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec());
        assert!(padded_msg.is_err());
    }

    let last_ciphertext = sender.test_last_ciphertext();
    if let Some(ct) = last_ciphertext {
        cipher_check(raw_bytes, &ct);
    } else {
        panic!("Expected last_ciphertext to be Some after send");
    }
}

#[tokio::test]
#[should_panic]
async fn cipher_check_utility_positive() {
    let plaintext = [b'A'; PUBKY_NOISE_CIPHERTEXT_LEN + 2];
    let ciphertext = plaintext;
    cipher_check(&plaintext, &ciphertext);
}

#[tokio::test]
async fn cipher_check_utility_negative() {
    let plaintext = [b'A'; PUBKY_NOISE_CIPHERTEXT_LEN + 2];
    let mut ciphertext = plaintext;
    ciphertext[0] = b'B';
    cipher_check(&plaintext, &ciphertext);
}

#[tokio::test]
async fn snow_test_initiator_first() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors(&testnet, "NN").await;
    complete_nn_handshake(&mut pair).await;

    send_and_verify(
        &mut pair.initiator,
        &mut pair.responder,
        "Hello_World_Pubky_Noise",
    )
    .await;
    send_and_verify(
        &mut pair.responder,
        &mut pair.initiator,
        "Pubky_Noise_Rocks",
    )
    .await;
}

#[tokio::test]
async fn snow_test_responder_first() {
    // Start a test homeserver with 1 MB user data limit
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();

    let mut pair = setup_encryptors(&testnet, "NN").await;
    complete_nn_handshake(&mut pair).await;

    // Responder sends first
    send_and_verify(
        &mut pair.responder,
        &mut pair.initiator,
        "Hello World Pubky Noise",
    )
    .await;
    send_and_verify(
        &mut pair.initiator,
        &mut pair.responder,
        "Pubky Noise Rocks",
    )
    .await;
}

#[tokio::test]
async fn snow_test_responder_tampering() {
    // Start a test homeserver with 1 MB user data limit
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors_with_tampering(&testnet, "NN").await;
    complete_nn_handshake(&mut pair).await;

    // Responder sends tampered message, initiator receives garbage
    send_and_verify_tampered(
        &mut pair.responder,
        &mut pair.initiator,
        "Hello World Pubky Noise",
    )
    .await;
}

#[tokio::test]
async fn snow_test_initiator_tampering() {
    // Start a test homeserver with 1 MB user data limit
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors_with_tampering(&testnet, "NN").await;
    complete_nn_handshake(&mut pair).await;

    // Initiator sends tampered message, responder receives garbage
    send_and_verify_tampered(
        &mut pair.initiator,
        &mut pair.responder,
        "Hello World Pubky Noise",
    )
    .await;
}

#[tokio::test]
async fn snow_null_message() {
    // Start a test homeserver with 1 MB user data limit
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors(&testnet, "NN").await;
    complete_nn_handshake(&mut pair).await;

    send_and_verify(&mut pair.responder, &mut pair.initiator, "").await;
}

// //#[tokio::test]
// async fn snow_test_min_max_size_message() {
//     //TODO: fix accordingly dual outbox model
//     let testnet = EphemeralTestnet::builder()
//         .with_embedded_postgres()
//         .build()
//         .await
//         .unwrap();
//     let server = testnet.homeserver_app();
//     let initiator_pubky = testnet.sdk().unwrap();
//     let responder_pubky = testnet.sdk().unwrap();

//     let initiator_signer = initiator_pubky.signer(Keypair::random());
//     let initiator_session = initiator_signer
//         .signup(&server.public_key(), None)
//         .await
//         .unwrap();

//     let responder_signer = responder_pubky.signer(Keypair::random());
//     let responder_session = responder_signer
//         .signup(&server.public_key(), None)
//         .await
//         .unwrap();

//     let server_path_string = format!("/pub/data");

//     let initiator_keypair = Keypair::random();
//     let mut initiator_encryptor = PubkyNoiseEncryptor::init_encryptor_stack(
//         initiator_keypair.secret_key(),
//         0,
//         "NN".to_string(),
//         initiator_session.clone(),
//         server_path_string.clone(),
//         initiator_pubky,
//         false,
//     )
//     .unwrap();

//     let responder_keypair = Keypair::random();
//     let mut responder_encryptor = PubkyNoiseEncryptor::init_encryptor_stack(
//         responder_keypair.secret_key(),
//         0,
//         "NN".to_string(),
//         responder_session.clone(),
//         server_path_string.clone(),
//         responder_pubky,
//         false,
//     )
//     .unwrap();

//     let initiator_ephemeral_keypair = Keypair::random();
//     let responder_ephemeral_keypair = Keypair::random();

//     let initiator_ephemeral_keypair = Keypair::random();
//     let responder_ephemeral_keypair = Keypair::random();

//     let initiator_public_key = initiator_session.info().public_key();
//     let responder_public_key = responder_session.info().public_key();

//     let initiator_key_set = PubkyKeySet::new(
//         Some(initiator_ephemeral_keypair.secret_key()),
//         Some(responder_ephemeral_keypair.public_key()),
//     );
//     let initiator_temporary_link_id = initiator_encryptor
//         .init_context(initiator_key_set, true, responder_public_key.clone())
//         .unwrap();

//     let responder_key_set = PubkyKeySet::new(
//         Some(responder_ephemeral_keypair.secret_key()),
//         Some(initiator_ephemeral_keypair.public_key()),
//     );
//     let responder_temporary_link_id = responder_encryptor
//         .init_context(responder_key_set, false, initiator_public_key.clone())
//         .unwrap();

//     // Initiator sends handshake
//     // -> e
//     // <- e, ee
//     initiator_encryptor
//         .handle_handshake(initiator_temporary_link_id, responder_public_key.clone())
//         .await;
//     responder_encryptor
//         .handle_handshake(responder_temporary_link_id, initiator_public_key.clone())
//         .await;
//     initiator_encryptor
//         .handle_handshake(initiator_temporary_link_id, responder_public_key.clone())
//         .await;

//     // yield Err(PubkyNoiseError::IsTransport)
//     assert!(!initiator_encryptor
//         .is_handshake(&initiator_temporary_link_id)
//         .is_ok());
//     assert!(!responder_encryptor
//         .is_handshake(&responder_temporary_link_id)
//         .is_ok());

//     let initiator_link_id = initiator_encryptor.transition_transport(initiator_temporary_link_id);
//     assert!(initiator_link_id.is_ok());
//     let responder_link_id = responder_encryptor.transition_transport(responder_temporary_link_id);
//     assert!(responder_link_id.is_ok());

//     // Transport
//     let data_payload = ['A' as u8; 985];
//     let raw_bytes = data_payload.to_vec();
//     responder_encryptor
//         .send_message(raw_bytes, initiator_link_id.unwrap())
//         .await;

//     let results = initiator_encryptor
//         .receive_message(responder_link_id.unwrap())
//         .await;

//     assert!(results.len() >= 1);
//     for ret in results {
//         let ref_payload = ['A' as u8; 985];
//         //assert_eq!(ret, ref_payload);
//     }
// }

#[tokio::test]
async fn snow_test_unknown_pattern() {
    // Start a test homeserver with 1 MB user data limit
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let server = testnet.homeserver_app();
    let initiator_pubky = testnet.sdk().unwrap();

    let initiator_signer = initiator_pubky.signer(Keypair::random());
    let initiator_session = initiator_signer
        .signup(&server.public_key(), None)
        .await
        .unwrap();

    let server_path_string = "/pub/data".to_string();

    let initiator_keypair = Keypair::random();
    let init_config_ret = PubkyNoiseConfig::new(
        initiator_keypair.secret_key(),
        0,
        "BA",
        initiator_session,
        server_path_string,
        initiator_pubky,
    );
    assert!(init_config_ret.is_err());
    assert!(init_config_ret.unwrap_err() == PubkyNoiseError::UnknownNoisePattern);
}

#[tokio::test]
async fn snow_test_snow_noise_build_error() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let server = testnet.homeserver_app();
    let initiator_pubky = testnet.sdk().unwrap();
    let responder_pubky = initiator_pubky.clone();

    let initiator_signer = initiator_pubky.signer(Keypair::random());
    let initiator_session = initiator_signer
        .signup(&server.public_key(), None)
        .await
        .unwrap();

    let responder_signer = responder_pubky.signer(Keypair::random());
    let responder_session = responder_signer
        .signup(&server.public_key(), None)
        .await
        .unwrap();

    let server_path_string = "/pub/data".to_string();

    let initiator_keypair = Keypair::random();
    // Create config with NN pattern, then override to TestOnlyPatternAA
    let mut config = PubkyNoiseConfig::new(
        initiator_keypair.secret_key(),
        0,
        "NN",
        initiator_session,
        server_path_string,
        initiator_pubky,
    )
    .unwrap();

    // Mutate the pattern to a non-buildable one
    Arc::get_mut(&mut config).unwrap().default_pattern = HandshakePattern::TestOnlyPatternAA;

    let initiator_ephemeral_keypair = Keypair::random();

    let responder_public_key = responder_session.info().public_key();

    let init_encryptor_ret = PubkyNoiseEncryptor::new(
        config,
        initiator_ephemeral_keypair.secret_key(),
        true,
        responder_public_key.clone(),
    );
    assert!(init_encryptor_ret.is_err());
    assert!(init_encryptor_ret.unwrap_err() == PubkyNoiseError::SnowNoiseBuildError);
}

#[tokio::test]
async fn snow_test_cleaning_sequence() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors(&testnet, "NN").await;
    complete_nn_handshake(&mut pair).await;

    send_and_verify(
        &mut pair.initiator,
        &mut pair.responder,
        "Hello_World_Noise_Data",
    )
    .await;

    // Close both encryptors
    pair.initiator.close();
    pair.responder.close();
}

#[tokio::test]
#[allow(non_snake_case)]
async fn snow_test_XX_pattern_simple() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors(&testnet, "XX").await;
    let initiator_public_key = pair.initiator_public_key.clone();
    let responder_public_key = pair.responder_public_key.clone();
    complete_xx_handshake(&mut pair).await;

    send_and_verify(
        &mut pair.initiator,
        &mut pair.responder,
        "Hello_World_Pubky_Noise",
    )
    .await;

    // ===== Verify what's actually stored on the homeserver using pubky SDK =====
    let verify_client = testnet.sdk().unwrap();

    // -- Verify initiator's handshake message 1 exists at slot 0 --
    let path = format!("{initiator_public_key}/pub/data/0");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Initiator handshake msg 1 should exist at /pub/data/0"
    );
    let slot0_bytes = response.bytes().await.unwrap();
    assert_eq!(
        slot0_bytes.len(),
        PUBKY_NOISE_CIPHERTEXT_LEN + 2,
        "Stored data should be PUBKY_NOISE_CIPHERTEXT_LEN + 2 bytes"
    );
    let len0 = u16::from_be_bytes([slot0_bytes[0], slot0_bytes[1]]) as usize;
    assert!(
        len0 > 0 && len0 <= PUBKY_NOISE_CIPHERTEXT_LEN,
        "Length prefix should be valid, got {len0}"
    );

    // -- Verify responder's handshake message 2 exists at slot 1 --
    let path = format!("{responder_public_key}/pub/data/1");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Responder handshake msg 2 should exist at /pub/data/1"
    );
    let slot1_bytes = response.bytes().await.unwrap();
    assert_eq!(slot1_bytes.len(), PUBKY_NOISE_CIPHERTEXT_LEN + 2);
    let len1 = u16::from_be_bytes([slot1_bytes[0], slot1_bytes[1]]) as usize;
    assert!(
        len1 > 0 && len1 <= PUBKY_NOISE_CIPHERTEXT_LEN,
        "Length prefix should be valid, got {len1}"
    );

    // -- Verify initiator's handshake message 3 exists at slot 2 --
    let path = format!("{initiator_public_key}/pub/data/2");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Initiator handshake msg 3 should exist at /pub/data/2"
    );
    let slot2_bytes = response.bytes().await.unwrap();
    assert_eq!(slot2_bytes.len(), PUBKY_NOISE_CIPHERTEXT_LEN + 2);
    let len2 = u16::from_be_bytes([slot2_bytes[0], slot2_bytes[1]]) as usize;
    assert!(
        len2 > 0 && len2 <= PUBKY_NOISE_CIPHERTEXT_LEN,
        "Length prefix should be valid, got {len2}"
    );

    // -- Verify initiator's transport message exists at slot 3 --
    let path = format!("{initiator_public_key}/pub/data/3");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Transport message should exist at /pub/data/3"
    );
    let slot3_bytes = response.bytes().await.unwrap();
    assert_eq!(slot3_bytes.len(), PUBKY_NOISE_CIPHERTEXT_LEN + 2);
    let len3 = u16::from_be_bytes([slot3_bytes[0], slot3_bytes[1]]) as usize;
    assert!(
        len3 > 0 && len3 <= PUBKY_NOISE_CIPHERTEXT_LEN,
        "Length prefix should be valid, got {len3}"
    );
    // Verify the stored data is actually encrypted (not plaintext)
    let transport_ciphertext = &slot3_bytes[2..len3 + 2];
    let plaintext_bytes = "Hello_World_Pubky_Noise".as_bytes();
    assert_ne!(
        &transport_ciphertext[..plaintext_bytes.len()],
        plaintext_bytes,
        "Stored transport data should be encrypted, not plaintext"
    );

    let _responder_list = verify_client
        .public_storage()
        .list(format!("{responder_public_key}/pub/data/"))
        .unwrap()
        .send()
        .await
        .unwrap();

    let _initiator_list = verify_client
        .public_storage()
        .list(format!("{initiator_public_key}/pub/data/"))
        .unwrap()
        .send()
        .await
        .unwrap();

    // Responder should NOT have data at slot 0
    let path = format!("{responder_public_key}/pub/data/0");
    let response = verify_client.public_storage().get(path).await;
    assert!(
        response.is_err(),
        "Responder should not have data at slot 0"
    );

    // Responder should have data at slot 1
    let path = format!("{responder_public_key}/pub/data/1");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Responder has data at slot 1"
    );

    // Initiator should have data at slot 0
    let path = format!("{initiator_public_key}/pub/data/0");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Initiator should have data at slot 0"
    );

    // Initiator should NOT have data at slot 1
    let path = format!("{initiator_public_key}/pub/data/1");
    let response = verify_client.public_storage().get(path).await;
    assert!(
        response.is_err(),
        "Initiator should not have data at slot 1"
    );

    // Initiator should have data at slot 2
    let path = format!("{initiator_public_key}/pub/data/2");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Initiator should have data at slot 2"
    );

    // Initiator should have data at slot 3
    let path = format!("{initiator_public_key}/pub/data/3");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Initiator should have data at slot 3"
    );

    // No data at slot 4 for either party
    let path = format!("{initiator_public_key}/pub/data/4");
    let response = verify_client.public_storage().get(path).await;
    assert!(
        response.is_err(),
        "No data should exist at slot 4 for initiator"
    );

    let path = format!("{responder_public_key}/pub/data/4");
    let response = verify_client.public_storage().get(path).await;
    assert!(
        response.is_err(),
        "No data should exist at slot 4 for responder"
    );
}

#[tokio::test]
#[allow(non_snake_case)]
async fn snow_test_XX_pattern_tampering() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors_with_tampering(&testnet, "XX").await;
    complete_xx_handshake(&mut pair).await;

    send_and_verify_tampered(
        &mut pair.initiator,
        &mut pair.responder,
        "Hello_World_Pubky_Noise",
    )
    .await;
}

#[tokio::test]
async fn snow_test_simple_backup() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors(&testnet, "XX").await;
    complete_xx_handshake(&mut pair).await;

    send_and_verify(
        &mut pair.initiator,
        &mut pair.responder,
        "Hello_World_Pubky_Noise",
    )
    .await;

    let _ = pair.initiator.persist_snapshot().await;
}

#[tokio::test]
async fn snow_test_dual_outbox() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors_dual_server(&testnet, "NN").await;
    complete_nn_handshake(&mut pair).await;

    //TODO: Alice can write only to her own Homeserver but can read from own
    // and Bob's Homeserver.
    //    => corollary: Bob can write only to his own Homeserver but can read from
    // own and Bob's Homeserver
}

#[tokio::test]
async fn snow_test_identity_commitment() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();

    let mut pair = setup_encryptors_dual_server(&testnet, "NN").await;
    complete_nn_handshake(&mut pair).await;

    //TODO: initiator receive_message -> identity binding
    //TODO: responder receive_message -> identity binding
}

#[tokio::test]
#[allow(non_snake_case)]
async fn snow_test_XX_pattern_simple_out_of_order_handshake() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors(&testnet, "XX").await;
    let initiator_public_key = pair.initiator_public_key.clone();
    let responder_public_key = pair.responder_public_key.clone();

    // Out of order polling — responder polls before initiator has written
    let _ = pair.responder.handle_handshake().await;
    let _ = pair.initiator.handle_handshake().await;
    let _ = pair.initiator.handle_handshake().await;
    let _ = pair.initiator.handle_handshake().await;
    let _ = pair.responder.handle_handshake().await;
    let _ = pair.initiator.handle_handshake().await;
    let _ = pair.responder.handle_handshake().await;
    let _ = pair.responder.handle_handshake().await;

    assert!(pair.initiator.is_handshake_complete());
    assert!(pair.responder.is_handshake_complete());

    pair.initiator.transition_transport().unwrap();
    pair.responder.transition_transport().unwrap();

    send_and_verify(
        &mut pair.initiator,
        &mut pair.responder,
        "Hello_World_Pubky_Noise",
    )
    .await;

    // ===== Verify what's actually stored on the homeserver using pubky SDK =====
    let verify_client = testnet.sdk().unwrap();

    // -- Verify initiator's handshake message 1 exists at slot 0 --
    let path = format!("{initiator_public_key}/pub/data/0");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Initiator handshake msg 1 should exist at /pub/data/0"
    );
    let slot0_bytes = response.bytes().await.unwrap();
    assert_eq!(
        slot0_bytes.len(),
        PUBKY_NOISE_CIPHERTEXT_LEN + 2,
        "Stored data should be PUBKY_NOISE_CIPHERTEXT_LEN + 2 bytes"
    );
    let len0 = u16::from_be_bytes([slot0_bytes[0], slot0_bytes[1]]) as usize;
    assert!(
        len0 > 0 && len0 <= PUBKY_NOISE_CIPHERTEXT_LEN,
        "Length prefix should be valid, got {len0}"
    );

    // -- Verify responder's handshake message 2 exists at slot 1 --
    let path = format!("{responder_public_key}/pub/data/1");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Responder handshake msg 2 should exist at /pub/data/1"
    );
    let slot1_bytes = response.bytes().await.unwrap();
    assert_eq!(slot1_bytes.len(), PUBKY_NOISE_CIPHERTEXT_LEN + 2);
    let len1 = u16::from_be_bytes([slot1_bytes[0], slot1_bytes[1]]) as usize;
    assert!(
        len1 > 0 && len1 <= PUBKY_NOISE_CIPHERTEXT_LEN,
        "Length prefix should be valid, got {len1}"
    );

    // -- Verify initiator's handshake message 3 exists at slot 2 --
    let path = format!("{initiator_public_key}/pub/data/2");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Initiator handshake msg 3 should exist at /pub/data/2"
    );
    let slot2_bytes = response.bytes().await.unwrap();
    assert_eq!(slot2_bytes.len(), PUBKY_NOISE_CIPHERTEXT_LEN + 2);
    let len2 = u16::from_be_bytes([slot2_bytes[0], slot2_bytes[1]]) as usize;
    assert!(
        len2 > 0 && len2 <= PUBKY_NOISE_CIPHERTEXT_LEN,
        "Length prefix should be valid, got {len2}"
    );

    // -- Verify initiator's transport message exists at slot 3 --
    let path = format!("{initiator_public_key}/pub/data/3");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Transport message should exist at /pub/data/3"
    );
    let slot3_bytes = response.bytes().await.unwrap();
    assert_eq!(slot3_bytes.len(), PUBKY_NOISE_CIPHERTEXT_LEN + 2);
    let len3 = u16::from_be_bytes([slot3_bytes[0], slot3_bytes[1]]) as usize;
    assert!(
        len3 > 0 && len3 <= PUBKY_NOISE_CIPHERTEXT_LEN,
        "Length prefix should be valid, got {len3}"
    );
    // Verify the stored data is actually encrypted (not plaintext)
    let transport_ciphertext = &slot3_bytes[2..len3 + 2];
    let plaintext_bytes = "Hello_World_Pubky_Noise".as_bytes();
    assert_ne!(
        &transport_ciphertext[..plaintext_bytes.len()],
        plaintext_bytes,
        "Stored transport data should be encrypted, not plaintext"
    );

    let _responder_list = verify_client
        .public_storage()
        .list(format!("{responder_public_key}/pub/data/"))
        .unwrap()
        .send()
        .await
        .unwrap();

    let _initiator_list = verify_client
        .public_storage()
        .list(format!("{initiator_public_key}/pub/data/"))
        .unwrap()
        .send()
        .await
        .unwrap();

    // Responder should NOT have data at slot 0
    let path = format!("{responder_public_key}/pub/data/0");
    let response = verify_client.public_storage().get(path).await;
    assert!(
        response.is_err(),
        "Responder should not have data at slot 0"
    );

    // Responder should have data at slot 1
    let path = format!("{responder_public_key}/pub/data/1");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Responder has data at slot 1"
    );

    // Initiator should have data at slot 0
    let path = format!("{initiator_public_key}/pub/data/0");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Initiator should have data at slot 0"
    );

    // Initiator should NOT have data at slot 1
    let path = format!("{initiator_public_key}/pub/data/1");
    let response = verify_client.public_storage().get(path).await;
    assert!(
        response.is_err(),
        "Initiator should not have data at slot 1"
    );

    // Initiator should have data at slot 2
    let path = format!("{initiator_public_key}/pub/data/2");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Initiator should have data at slot 2"
    );

    // Initiator should have data at slot 3
    let path = format!("{initiator_public_key}/pub/data/3");
    let response = verify_client.public_storage().get(path).await.unwrap();
    assert!(
        response.status().is_success(),
        "Initiator should have data at slot 3"
    );

    // No data at slot 4 for either party
    let path = format!("{initiator_public_key}/pub/data/4");
    let response = verify_client.public_storage().get(path).await;
    assert!(
        response.is_err(),
        "No data should exist at slot 4 for initiator"
    );

    let path = format!("{responder_public_key}/pub/data/4");
    let response = verify_client.public_storage().get(path).await;
    assert!(
        response.is_err(),
        "No data should exist at slot 4 for responder"
    );
}

#[tokio::test]
#[allow(non_snake_case)]
async fn snow_test_XX_pattern_simple_incomplete_handshake() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors(&testnet, "XX").await;

    // Incomplete handshake — third message never sent
    // -> e
    // <- e, ee, s, es
    // -> s, se  (NOT DONE)
    let _ = pair.initiator.handle_handshake().await;
    let _ = pair.responder.handle_handshake().await;
    let _ = pair.responder.handle_handshake().await;

    assert!(!pair.initiator.is_handshake_complete());
    assert!(!pair.responder.is_handshake_complete());

    assert!(pair.initiator.transition_transport().is_err());
    assert!(pair.responder.transition_transport().is_err());
}

/// Test restore from transport state: complete handshake, exchange messages,
/// snapshot, serialize/deserialize, restore, then continue exchanging messages.
#[tokio::test]
async fn snow_test_restore() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors_dual_server(&testnet, "NN").await;
    let initiator_public_key = pair.initiator_public_key.clone();
    let responder_public_key = pair.responder_public_key.clone();
    complete_nn_handshake(&mut pair).await;

    // Exchange one round of messages before snapshot
    send_and_verify(
        &mut pair.initiator,
        &mut pair.responder,
        "Hello_Before_Restore",
    )
    .await;

    // Snapshot both sides
    let initiator_snapshot = pair.initiator.snapshot();
    let responder_snapshot = pair.responder.snapshot();

    // Serialize and deserialize (round-trip test)
    let initiator_bytes = initiator_snapshot.serialize();
    let responder_bytes = responder_snapshot.serialize();
    assert_eq!(initiator_bytes.len(), 189);
    assert_eq!(responder_bytes.len(), 189);

    let initiator_state = PubkyNoiseSessionState::deserialize(&initiator_bytes).unwrap();
    let responder_state = PubkyNoiseSessionState::deserialize(&responder_bytes).unwrap();

    // Restore both sides from snapshots
    let mut restored_initiator = PubkyNoiseEncryptor::restore(
        pair.initiator_config.clone(),
        initiator_state,
        responder_public_key.clone(),
    )
    .await
    .unwrap();
    let mut restored_responder = PubkyNoiseEncryptor::restore(
        pair.responder_config.clone(),
        responder_state,
        initiator_public_key.clone(),
    )
    .await
    .unwrap();

    // Verify link IDs match
    assert_eq!(
        pair.initiator.get_link_id(),
        restored_initiator.get_link_id()
    );
    assert_eq!(
        pair.responder.get_link_id(),
        restored_responder.get_link_id()
    );

    // Exchange messages using restored encryptors
    send_and_verify(
        &mut restored_initiator,
        &mut restored_responder,
        "Hello_After_Restore",
    )
    .await;
    send_and_verify(
        &mut restored_responder,
        &mut restored_initiator,
        "Restored_Responder_Says_Hi",
    )
    .await;
}

/// Test that snapshot serialization round-trips correctly.
#[tokio::test]
async fn snow_test_restore_serialization_roundtrip() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors(&testnet, "NN").await;
    complete_nn_handshake(&mut pair).await;

    // Exchange a few messages to advance nonces
    for i in 0..3 {
        let msg = format!("message_{i}");
        assert!(pair.initiator.send_message(msg.as_bytes()).await);
        let results = pair.responder.receive_message().await;
        assert!(!results.is_empty());
    }

    // Take snapshot and verify round-trip
    let snapshot = pair.initiator.snapshot();
    let bytes = snapshot.serialize();
    let restored = PubkyNoiseSessionState::deserialize(&bytes).unwrap();

    // Verify all fields match
    assert_eq!(restored.version, snapshot.version);
    assert_eq!(restored.initiator, snapshot.initiator);
    assert_eq!(restored.ephemeral_secret, snapshot.ephemeral_secret);
    assert_eq!(restored.static_secret, snapshot.static_secret);
    assert_eq!(restored.counter, snapshot.counter);
    assert_eq!(restored.sending_nonce, snapshot.sending_nonce);
    assert_eq!(restored.receiving_nonce, snapshot.receiving_nonce);
    assert_eq!(restored.endpoint_pubkey, snapshot.endpoint_pubkey);
    assert_eq!(restored.handshake_hash, snapshot.handshake_hash);
    assert_eq!(restored.link_id, snapshot.link_id);
}

/// Test that restored encryptors produce the same link ID as the originals.
#[tokio::test]
async fn snow_test_restore_link_id_matches() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors_dual_server(&testnet, "NN").await;
    let initiator_public_key = pair.initiator_public_key.clone();
    let responder_public_key = pair.responder_public_key.clone();
    complete_nn_handshake(&mut pair).await;

    let original_init_link = pair.initiator.get_link_id().unwrap();
    let original_resp_link = pair.responder.get_link_id().unwrap();

    // Both sides should agree on the link ID
    assert_eq!(original_init_link, original_resp_link);

    // Snapshot and restore initiator
    let init_snapshot = pair.initiator.snapshot();
    let init_bytes = init_snapshot.serialize();
    let init_state = PubkyNoiseSessionState::deserialize(&init_bytes).unwrap();
    let restored_initiator = PubkyNoiseEncryptor::restore(
        pair.initiator_config.clone(),
        init_state,
        responder_public_key.clone(),
    )
    .await
    .unwrap();

    // Snapshot and restore responder
    let resp_snapshot = pair.responder.snapshot();
    let resp_bytes = resp_snapshot.serialize();
    let resp_state = PubkyNoiseSessionState::deserialize(&resp_bytes).unwrap();
    let restored_responder = PubkyNoiseEncryptor::restore(
        pair.responder_config.clone(),
        resp_state,
        initiator_public_key.clone(),
    )
    .await
    .unwrap();

    // Restored link IDs must match originals
    assert_eq!(
        restored_initiator.get_link_id().unwrap(),
        original_init_link
    );
    assert_eq!(
        restored_responder.get_link_id().unwrap(),
        original_resp_link
    );
    // And each other
    assert_eq!(
        restored_initiator.get_link_id(),
        restored_responder.get_link_id()
    );
}

// =============================================================================
// Handshake interruption tests
//
// In the outbox model, "network is unreliable" manifests as either:
//   (a) Initiator fails to write to her outbox, or
//   (b) Responder fails to read from Initiator's outbox.
//
// Case (b): Responder's step/sub_step must NOT advance on read failure.
//           Retry should succeed once the message appears.
//
// Case (a) has two sub-cases:
//
//   (a1) put() returns an error (network timeout, server rejection):
//        handle_handshake() now returns Err(HomeserverWriteError).
//        Snow's HandshakeState has already advanced irreversibly, so the
//        caller must recover via last_good_snapshot() + restore().
//        See: snow_test_NN_initiator_put_failure_returns_error
//             snow_test_XX_initiator_put_failure_returns_error
//
//   (a2) put() succeeds but data is subsequently lost (e.g. homeserver
//        crash after acknowledgment, storage corruption):
//        handle_handshake() returns Ok(Pending) — the loss is undetectable
//        at the protocol level. The handshake gets stuck. Recovery is
//        possible by restoring from a pre-failure snapshot (simulating
//        "app restart" loading last persisted state), which replays the
//        handshake from the correct position.
//        See: snow_test_NN_initiator_write_failure_and_replay_recovery
//             snow_test_XX_initiator_write_failure_and_replay_recovery
// =============================================================================

/// NN pattern: Responder fails to read from Initiator's outbox.
///
/// Responder polls before Initiator has written anything. Verify that:
/// - Responder's state (step, sub_step, counter) does NOT advance
/// - handle_handshake returns Pending
/// - On retry (after Initiator writes), the handshake completes normally
/// - Transport works after recovery
#[tokio::test]
#[allow(non_snake_case)]
async fn snow_test_NN_responder_read_failure_no_state_advance() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors_dual_server(&testnet, "NN").await;

    // Snapshot responder BEFORE any handshake activity
    let snap_before = pair.responder.snapshot();
    assert_eq!(snap_before.noise_step, NoiseStep::StepOne);
    assert_eq!(snap_before.sub_step_index, 0);
    assert_eq!(snap_before.counter, 0);
    assert_eq!(snap_before.phase, NoisePhase::HandShake);

    // Responder polls — Initiator hasn't written yet, so Read finds nothing
    let result = pair.responder.handle_handshake().await.unwrap();
    assert_eq!(result, HandshakeResult::Pending);

    // Snapshot responder AFTER the failed read
    let snap_after = pair.responder.snapshot();

    // State must NOT have advanced
    assert_eq!(snap_after.noise_step, snap_before.noise_step);
    assert_eq!(snap_after.sub_step_index, snap_before.sub_step_index);
    assert_eq!(snap_after.counter, snap_before.counter);
    assert_eq!(snap_after.phase, snap_before.phase);

    // Poll a few more times — still Pending, still no advance
    for _ in 0..3 {
        let result = pair.responder.handle_handshake().await.unwrap();
        assert_eq!(result, HandshakeResult::Pending);
    }
    let snap_after_retries = pair.responder.snapshot();
    assert_eq!(snap_after_retries.counter, 0);
    assert_eq!(snap_after_retries.noise_step, NoiseStep::StepOne);
    assert_eq!(snap_after_retries.sub_step_index, 0);

    // Now Initiator writes slot 0
    let result = pair.initiator.handle_handshake().await.unwrap();
    assert_eq!(result, HandshakeResult::Pending);

    // Responder retries — this time reads slot 0 and writes slot 1.
    // NN Responder StepOne: [Read, Write] → both succeed, complete_step → StepTwo.
    // After this call Snow has processed both NN messages on the responder side,
    // so is_handshake_complete() becomes true.
    let _ = pair.responder.handle_handshake().await.unwrap();
    assert!(pair.responder.is_handshake_complete());

    // Initiator reads slot 1.
    // NN Initiator StepTwo: [Read] → succeeds, complete_step → Final.
    // Snow has now processed both messages on the initiator side too.
    let _ = pair.initiator.handle_handshake().await.unwrap();
    assert!(pair.initiator.is_handshake_complete());

    pair.initiator.transition_transport().unwrap();
    pair.responder.transition_transport().unwrap();

    // Verify transport works
    send_and_verify(
        &mut pair.initiator,
        &mut pair.responder,
        "NN_read_failure_recovery",
    )
    .await;
    send_and_verify(
        &mut pair.responder,
        &mut pair.initiator,
        "NN_read_failure_reverse",
    )
    .await;
}

/// XX pattern: Responder fails to read from Initiator's outbox.
///
/// Same scenario as the NN variant but with the XX pattern which has more
/// handshake round-trips. Verifies that the polling-safe behavior holds
/// across the longer XX action sequence.
#[tokio::test]
#[allow(non_snake_case)]
async fn snow_test_XX_responder_read_failure_no_state_advance() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors_dual_server(&testnet, "XX").await;

    // Snapshot responder BEFORE any handshake activity
    let snap_before = pair.responder.snapshot();
    assert_eq!(snap_before.noise_step, NoiseStep::StepOne);
    assert_eq!(snap_before.sub_step_index, 0);
    assert_eq!(snap_before.counter, 0);
    assert_eq!(snap_before.phase, NoisePhase::HandShake);

    // Responder polls — Initiator hasn't written yet
    let result = pair.responder.handle_handshake().await.unwrap();
    assert_eq!(result, HandshakeResult::Pending);

    // State must NOT have advanced
    let snap_after = pair.responder.snapshot();
    assert_eq!(snap_after.noise_step, snap_before.noise_step);
    assert_eq!(snap_after.sub_step_index, snap_before.sub_step_index);
    assert_eq!(snap_after.counter, snap_before.counter);

    // Poll a few more times — still no advance
    for _ in 0..3 {
        let result = pair.responder.handle_handshake().await.unwrap();
        assert_eq!(result, HandshakeResult::Pending);
    }
    let snap_after_retries = pair.responder.snapshot();
    assert_eq!(snap_after_retries.counter, 0);
    assert_eq!(snap_after_retries.noise_step, NoiseStep::StepOne);
    assert_eq!(snap_after_retries.sub_step_index, 0);

    // Now run the full XX handshake normally:
    // Initiator StepOne: [Write, Pending] → writes slot 0, returns Pending
    let result = pair.initiator.handle_handshake().await.unwrap();
    assert_eq!(result, HandshakeResult::Pending);

    // Responder StepOne: [Read, Write, Pending] → reads slot 0, writes slot 1, returns Pending
    let result = pair.responder.handle_handshake().await.unwrap();
    assert_eq!(result, HandshakeResult::Pending);

    // Initiator StepTwo: [Read, Write] → reads slot 1, writes slot 2, complete_step → Final
    // Snow finishes after processing all 3 messages.
    let _ = pair.initiator.handle_handshake().await.unwrap();
    assert!(pair.initiator.is_handshake_complete());

    // Responder StepTwo: [Read] → reads slot 2, complete_step → Final
    // Snow finishes on responder side too.
    let _ = pair.responder.handle_handshake().await.unwrap();
    assert!(pair.responder.is_handshake_complete());

    pair.initiator.transition_transport().unwrap();
    pair.responder.transition_transport().unwrap();

    // Verify transport works
    send_and_verify(
        &mut pair.initiator,
        &mut pair.responder,
        "XX_read_failure_recovery",
    )
    .await;
    send_and_verify(
        &mut pair.responder,
        &mut pair.initiator,
        "XX_read_failure_reverse",
    )
    .await;
}

/// NN pattern: Initiator fails to write to her outbox.
///
/// Demonstrates the full scenario:
/// 1. Initiator calls handle_handshake — Snow advances state internally, but
///    the message is "lost" (simulated by deleting it from the homeserver).
/// 2. The handshake is stuck: Responder keeps getting Pending (nothing to read),
///    Initiator waits for Responder's reply that will never come.
/// 3. Recovery via "app restart": restore Initiator from a pre-failure snapshot.
///    The replay mechanism corrects the state (counter=0, step=StepOne).
/// 4. Restored Initiator re-does the write, handshake completes, transport works.
#[tokio::test]
#[allow(non_snake_case)]
async fn snow_test_NN_initiator_write_failure_and_replay_recovery() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors_dual_server(&testnet, "NN").await;
    let initiator_public_key = pair.initiator_public_key.clone();
    let responder_public_key = pair.responder_public_key.clone();

    // ── Phase 1: Initiator writes slot 0, then we "lose" the message ──

    // last_good_snapshot() is None before any handle_handshake call
    assert!(pair.initiator.last_good_snapshot().is_none());

    let result = pair.initiator.handle_handshake().await.unwrap();
    assert_eq!(result, HandshakeResult::Pending);

    // handle_handshake captured the pre-mutation snapshot automatically.
    // It should reflect the state BEFORE the write (counter=0, StepOne).
    let pre_write_snapshot = pair.initiator.last_good_snapshot().unwrap().clone();
    assert_eq!(pre_write_snapshot.counter, 0);
    assert_eq!(pre_write_snapshot.noise_step, NoiseStep::StepOne);
    assert_eq!(pre_write_snapshot.sub_step_index, 0);

    // Verify Initiator's current state IS advanced (this is the erroneous advance)
    let post_write_snapshot = pair.initiator.snapshot();
    assert_eq!(post_write_snapshot.counter, 1);
    assert_eq!(post_write_snapshot.noise_step, NoiseStep::StepTwo);
    assert_eq!(post_write_snapshot.sub_step_index, 0);

    // Delete the message from the homeserver — simulates "write was lost"
    pair.initiator_config
        .local_session
        .storage()
        .delete("/pub/data/0")
        .await
        .unwrap();

    // Verify the message is actually gone
    let verify_client = testnet.sdk().unwrap();
    let path = format!("{initiator_public_key}/pub/data/0");
    let response = verify_client.public_storage().get(path).await;
    assert!(response.is_err(), "Slot 0 should be gone after delete");

    // ── Phase 2: Handshake is stuck ──

    // Responder tries to read slot 0 — nothing there → Pending
    for _ in 0..3 {
        let result = pair.responder.handle_handshake().await.unwrap();
        assert_eq!(result, HandshakeResult::Pending);
    }

    // Initiator is at StepTwo waiting for Responder's message at slot 1,
    // which will never come because Responder never got slot 0.
    for _ in 0..3 {
        let result = pair.initiator.handle_handshake().await.unwrap();
        assert_eq!(result, HandshakeResult::Pending);
    }

    // Neither side has completed the handshake
    assert!(!pair.initiator.is_handshake_complete());
    assert!(!pair.responder.is_handshake_complete());

    // ── Phase 3: Recovery via "app restart" — restore from last_good_snapshot ──

    let pre_write_bytes = pre_write_snapshot.serialize();
    let pre_write_state = PubkyNoiseSessionState::deserialize(&pre_write_bytes).unwrap();

    let mut restored_initiator = PubkyNoiseEncryptor::restore(
        pair.initiator_config.clone(),
        pre_write_state,
        responder_public_key.clone(),
    )
    .await
    .unwrap();

    // Verify restored state is back to the correct initial position
    let restored_snapshot = restored_initiator.snapshot();
    assert_eq!(restored_snapshot.counter, 0);
    assert_eq!(restored_snapshot.noise_step, NoiseStep::StepOne);
    assert_eq!(restored_snapshot.sub_step_index, 0);

    // ── Phase 4: Re-do the handshake from the restored state ──

    // Restored Initiator StepOne: [Write, Pending] → writes slot 0
    // (same ephemeral key → same message), returns Pending
    let result = restored_initiator.handle_handshake().await.unwrap();
    assert_eq!(result, HandshakeResult::Pending);

    // Responder StepOne: [Read, Write] → reads slot 0, writes slot 1.
    // Snow finishes on responder side after processing both NN messages.
    let _ = pair.responder.handle_handshake().await.unwrap();
    assert!(pair.responder.is_handshake_complete());

    // Restored Initiator StepTwo: [Read] → reads slot 1.
    // Snow finishes on initiator side.
    let _ = restored_initiator.handle_handshake().await.unwrap();
    assert!(restored_initiator.is_handshake_complete());

    restored_initiator.transition_transport().unwrap();
    pair.responder.transition_transport().unwrap();

    // ── Phase 5: Verify transport works after recovery ──

    send_and_verify(
        &mut restored_initiator,
        &mut pair.responder,
        "NN_write_failure_recovered",
    )
    .await;
    send_and_verify(
        &mut pair.responder,
        &mut restored_initiator,
        "NN_write_failure_reverse",
    )
    .await;
}

/// XX pattern: Initiator fails to write to her outbox (at slot 2, mid-handshake).
///
/// This tests a more complex scenario where the write failure happens during
/// the Initiator's SECOND write (slot 2) in the XX pattern, after some
/// handshake progress has already been made:
///   - Slot 0: Initiator → e (written successfully)
///   - Slot 1: Responder → e, ee, s, es (written successfully)
///   - Slot 2: Initiator → s, se (LOST)
///
/// Demonstrates:
/// 1. Initiator's state is erroneously advanced to Final after the lost write.
/// 2. Responder is stuck waiting for slot 2.
/// 3. Recovery via restore from pre-second-write snapshot.
/// 4. Restored Initiator re-does the second write, handshake completes.
#[tokio::test]
#[allow(non_snake_case)]
async fn snow_test_XX_initiator_write_failure_and_replay_recovery() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors_dual_server(&testnet, "XX").await;
    let initiator_public_key = pair.initiator_public_key.clone();
    let responder_public_key = pair.responder_public_key.clone();

    // ── Phase 1: Complete the first two steps of the XX handshake ──

    // Initiator writes slot 0 (-> e), returns Pending
    let result = pair.initiator.handle_handshake().await.unwrap();
    assert_eq!(result, HandshakeResult::Pending);

    // Responder reads slot 0, writes slot 1 (<- e, ee, s, es), returns Pending
    let result = pair.responder.handle_handshake().await.unwrap();
    assert_eq!(result, HandshakeResult::Pending);

    // ── Phase 2: Initiator reads slot 1 and writes slot 2, then we lose slot 2 ──

    // Initiator StepTwo: [Read, Write] → reads slot 1, writes slot 2 (-> s, se).
    // complete_step moves to Final. Snow has processed all 3 XX messages.
    let _ = pair.initiator.handle_handshake().await.unwrap();
    assert!(pair.initiator.is_handshake_complete());

    // handle_handshake captured the pre-mutation snapshot automatically.
    // It should reflect the state BEFORE the Read+Write (counter=1, StepTwo).
    let pre_second_write_snapshot = pair.initiator.last_good_snapshot().unwrap().clone();
    assert_eq!(pre_second_write_snapshot.counter, 1);
    assert_eq!(pre_second_write_snapshot.noise_step, NoiseStep::StepTwo);
    assert_eq!(pre_second_write_snapshot.sub_step_index, 0);

    // Verify state advanced: counter=3 (read slot 1 + write slot 2), step=Final
    let post_write_snapshot = pair.initiator.snapshot();
    assert_eq!(post_write_snapshot.counter, 3);
    assert_eq!(post_write_snapshot.noise_step, NoiseStep::Final);

    // Delete slot 2 — simulates "write was lost"
    pair.initiator_config
        .local_session
        .storage()
        .delete("/pub/data/2")
        .await
        .unwrap();

    // Verify slot 2 is gone
    let verify_client = testnet.sdk().unwrap();
    let path = format!("{initiator_public_key}/pub/data/2");
    let response = verify_client.public_storage().get(path).await;
    assert!(response.is_err(), "Slot 2 should be gone after delete");

    // ── Phase 3: Handshake is stuck ──

    // Responder tries to read slot 2 — nothing there → Pending
    for _ in 0..3 {
        let result = pair.responder.handle_handshake().await.unwrap();
        assert_eq!(result, HandshakeResult::Pending);
    }

    // Responder has NOT completed the handshake
    assert!(!pair.responder.is_handshake_complete());

    // ── Phase 4: Recovery via restore from last_good_snapshot ──

    let snapshot_bytes = pre_second_write_snapshot.serialize();
    let snapshot_state = PubkyNoiseSessionState::deserialize(&snapshot_bytes).unwrap();

    let mut restored_initiator = PubkyNoiseEncryptor::restore(
        pair.initiator_config.clone(),
        snapshot_state,
        responder_public_key.clone(),
    )
    .await
    .unwrap();

    // Verify restored state: counter=1, step=StepTwo, sub_step=0
    // (back to before the Read+Write that was lost)
    let restored_snapshot = restored_initiator.snapshot();
    assert_eq!(restored_snapshot.counter, pre_second_write_snapshot.counter);
    assert_eq!(
        restored_snapshot.noise_step,
        pre_second_write_snapshot.noise_step
    );
    assert_eq!(
        restored_snapshot.sub_step_index,
        pre_second_write_snapshot.sub_step_index
    );

    // ── Phase 5: Re-do the handshake from the restored state ──

    // Restored Initiator StepTwo: [Read, Write] → reads slot 1 (still on
    // homeserver), writes slot 2. Snow finishes on initiator side.
    let _ = restored_initiator.handle_handshake().await.unwrap();
    assert!(restored_initiator.is_handshake_complete());

    // Responder StepTwo: [Read] → reads slot 2. Snow finishes on responder side.
    let _ = pair.responder.handle_handshake().await.unwrap();
    assert!(pair.responder.is_handshake_complete());

    restored_initiator.transition_transport().unwrap();
    pair.responder.transition_transport().unwrap();

    // ── Phase 6: Verify transport works after recovery ──

    send_and_verify(
        &mut restored_initiator,
        &mut pair.responder,
        "XX_write_failure_recovered",
    )
    .await;
    send_and_verify(
        &mut pair.responder,
        &mut restored_initiator,
        "XX_write_failure_reverse",
    )
    .await;
}

/// Verify that `last_good_snapshot()` correctly captures pre-mutation state
/// at the start of each `handle_handshake()` call.
///
/// Checks:
/// - Returns `None` before any `handle_handshake` call.
/// - After each call, contains the state from *before* that call.
/// - Updates on every subsequent call (tracks the latest pre-mutation state).
#[tokio::test]
async fn snow_test_last_good_snapshot_tracks_pre_mutation_state() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors_dual_server(&testnet, "NN").await;

    // ── Before any handshake call: last_good_snapshot is None ──

    assert!(pair.initiator.last_good_snapshot().is_none());
    assert!(pair.responder.last_good_snapshot().is_none());

    // ── Initiator call 1: StepOne [Write, Pending] ──

    let _ = pair.initiator.handle_handshake().await.unwrap();

    // last_good_snapshot should reflect the state BEFORE the call
    let snap = pair.initiator.last_good_snapshot().unwrap();
    assert_eq!(snap.counter, 0);
    assert_eq!(snap.noise_step, NoiseStep::StepOne);
    assert_eq!(snap.sub_step_index, 0);
    assert_eq!(snap.phase, NoisePhase::HandShake);

    // Current state should be AFTER the call (advanced)
    let current = pair.initiator.snapshot();
    assert_eq!(current.counter, 1);
    assert_eq!(current.noise_step, NoiseStep::StepTwo);
    assert_eq!(current.sub_step_index, 0);

    // ── Responder call 1: StepOne [Read, Write] ──

    let _ = pair.responder.handle_handshake().await.unwrap();

    let snap = pair.responder.last_good_snapshot().unwrap();
    assert_eq!(snap.counter, 0);
    assert_eq!(snap.noise_step, NoiseStep::StepOne);
    assert_eq!(snap.sub_step_index, 0);

    // Responder advanced: read slot 0 + write slot 1 = counter 2, step StepTwo
    let current = pair.responder.snapshot();
    assert_eq!(current.counter, 2);
    assert_eq!(current.noise_step, NoiseStep::StepTwo);

    // ── Initiator call 2: StepTwo [Read] ──

    let _ = pair.initiator.handle_handshake().await.unwrap();

    // last_good_snapshot updated to reflect state BEFORE this second call
    let snap = pair.initiator.last_good_snapshot().unwrap();
    assert_eq!(snap.counter, 1);
    assert_eq!(snap.noise_step, NoiseStep::StepTwo);
    assert_eq!(snap.sub_step_index, 0);

    // Current state: read slot 1, step advanced to Final
    let current = pair.initiator.snapshot();
    assert_eq!(current.counter, 2);
    assert_eq!(current.noise_step, NoiseStep::Final);

    // Handshake is complete on both sides
    assert!(pair.initiator.is_handshake_complete());
    assert!(pair.responder.is_handshake_complete());
}

/// NN pattern: Initiator's put() fails (Case a1).
///
/// Demonstrates that handle_handshake returns Err(HomeserverWriteError) when
/// the homeserver write fails, and that recovery via last_good_snapshot +
/// restore works correctly.
///
/// Steps:
/// 1. Enable simulated write failure on the initiator.
/// 2. Call handle_handshake — returns Err(HomeserverWriteError).
/// 3. Verify last_good_snapshot captured the pre-mutation state.
/// 4. Disable write failure, restore from snapshot, complete handshake.
/// 5. Verify transport works after recovery.
#[tokio::test]
#[allow(non_snake_case)]
async fn snow_test_NN_initiator_put_failure_returns_error() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors_dual_server(&testnet, "NN").await;
    let responder_public_key = pair.responder_public_key.clone();

    // ── Phase 1: Simulate put() failure on initiator ──

    pair.initiator.test_enable_write_failure();

    let result = pair.initiator.handle_handshake().await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), PubkyNoiseError::HomeserverWriteError);

    // ── Phase 2: Verify last_good_snapshot captured pre-mutation state ──

    let pre_failure_snapshot = pair.initiator.last_good_snapshot().unwrap().clone();
    assert_eq!(pre_failure_snapshot.counter, 0);
    assert_eq!(pre_failure_snapshot.noise_step, NoiseStep::StepOne);
    assert_eq!(pre_failure_snapshot.sub_step_index, 0);
    assert_eq!(pre_failure_snapshot.phase, NoisePhase::HandShake);

    // ── Phase 3: Restore from snapshot (no write failure this time) ──

    let snapshot_bytes = pre_failure_snapshot.serialize();
    let snapshot_state = PubkyNoiseSessionState::deserialize(&snapshot_bytes).unwrap();

    let mut restored_initiator = PubkyNoiseEncryptor::restore(
        pair.initiator_config.clone(),
        snapshot_state,
        responder_public_key.clone(),
    )
    .await
    .unwrap();

    // Verify restored state matches the pre-failure snapshot
    let restored_snapshot = restored_initiator.snapshot();
    assert_eq!(restored_snapshot.counter, 0);
    assert_eq!(restored_snapshot.noise_step, NoiseStep::StepOne);
    assert_eq!(restored_snapshot.sub_step_index, 0);

    // ── Phase 4: Complete the handshake normally ──

    // Restored Initiator StepOne: [Write, Pending] → writes slot 0
    let result = restored_initiator.handle_handshake().await.unwrap();
    assert_eq!(result, HandshakeResult::Pending);

    // Responder StepOne: [Read, Write] → reads slot 0, writes slot 1
    let _ = pair.responder.handle_handshake().await.unwrap();
    assert!(pair.responder.is_handshake_complete());

    // Restored Initiator StepTwo: [Read] → reads slot 1
    let _ = restored_initiator.handle_handshake().await.unwrap();
    assert!(restored_initiator.is_handshake_complete());

    restored_initiator.transition_transport().unwrap();
    pair.responder.transition_transport().unwrap();

    // ── Phase 5: Verify transport works ──

    send_and_verify(
        &mut restored_initiator,
        &mut pair.responder,
        "NN_put_failure_recovered",
    )
    .await;
    send_and_verify(
        &mut pair.responder,
        &mut restored_initiator,
        "NN_put_failure_reverse",
    )
    .await;
}

/// XX pattern: Initiator's put() fails at slot 2 (Case a1, mid-handshake).
///
/// The failure occurs during the Initiator's SECOND write in the XX pattern:
///   - Slot 0: Initiator → e (written successfully)
///   - Slot 1: Responder → e, ee, s, es (written successfully)
///   - Slot 2: Initiator → s, se (put() FAILS → HomeserverWriteError)
///
/// Steps:
/// 1. Complete the first two handshake steps normally.
/// 2. Enable simulated write failure before the third step.
/// 3. Call handle_handshake — returns Err(HomeserverWriteError).
/// 4. Restore from last_good_snapshot, complete handshake, verify transport.
#[tokio::test]
#[allow(non_snake_case)]
async fn snow_test_XX_initiator_put_failure_returns_error() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors_dual_server(&testnet, "XX").await;
    let responder_public_key = pair.responder_public_key.clone();

    // ── Phase 1: Complete the first two steps of the XX handshake ──

    // Initiator writes slot 0 (-> e), returns Pending
    let result = pair.initiator.handle_handshake().await.unwrap();
    assert_eq!(result, HandshakeResult::Pending);

    // Responder reads slot 0, writes slot 1 (<- e, ee, s, es), returns Pending
    let result = pair.responder.handle_handshake().await.unwrap();
    assert_eq!(result, HandshakeResult::Pending);

    // ── Phase 2: Simulate put() failure on initiator's second write ──

    pair.initiator.test_enable_write_failure();

    // Initiator StepTwo: [Read, Write] → reads slot 1 OK, but Write fails
    let result = pair.initiator.handle_handshake().await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), PubkyNoiseError::HomeserverWriteError);

    // ── Phase 3: Verify last_good_snapshot captured pre-StepTwo state ──

    let pre_failure_snapshot = pair.initiator.last_good_snapshot().unwrap().clone();
    assert_eq!(pre_failure_snapshot.counter, 1);
    assert_eq!(pre_failure_snapshot.noise_step, NoiseStep::StepTwo);
    assert_eq!(pre_failure_snapshot.sub_step_index, 0);

    // ── Phase 4: Restore from snapshot ──

    let snapshot_bytes = pre_failure_snapshot.serialize();
    let snapshot_state = PubkyNoiseSessionState::deserialize(&snapshot_bytes).unwrap();

    let mut restored_initiator = PubkyNoiseEncryptor::restore(
        pair.initiator_config.clone(),
        snapshot_state,
        responder_public_key.clone(),
    )
    .await
    .unwrap();

    // Verify restored state
    let restored_snapshot = restored_initiator.snapshot();
    assert_eq!(restored_snapshot.counter, pre_failure_snapshot.counter);
    assert_eq!(
        restored_snapshot.noise_step,
        pre_failure_snapshot.noise_step
    );
    assert_eq!(
        restored_snapshot.sub_step_index,
        pre_failure_snapshot.sub_step_index
    );

    // ── Phase 5: Complete the handshake from restored state ──

    // Restored Initiator StepTwo: [Read, Write] → reads slot 1, writes slot 2
    let _ = restored_initiator.handle_handshake().await.unwrap();
    assert!(restored_initiator.is_handshake_complete());

    // Responder StepTwo: [Read] → reads slot 2
    let _ = pair.responder.handle_handshake().await.unwrap();
    assert!(pair.responder.is_handshake_complete());

    restored_initiator.transition_transport().unwrap();
    pair.responder.transition_transport().unwrap();

    // ── Phase 6: Verify transport works ──

    send_and_verify(
        &mut restored_initiator,
        &mut pair.responder,
        "XX_put_failure_recovered",
    )
    .await;
    send_and_verify(
        &mut pair.responder,
        &mut restored_initiator,
        "XX_put_failure_reverse",
    )
    .await;
}

/// Test message payload sizes around the PUBKY_NOISE_MSG_LEN boundary.
///
/// The maximum plaintext payload is PUBKY_NOISE_MSG_LEN (1000) bytes.
/// The ciphertext buffer is PUBKY_NOISE_CIPHERTEXT_LEN (1016) bytes,
/// which accounts for the 16-byte ChaChaPoly AEAD tag.
///
/// - 999 bytes (MSG_LEN - 1): under the limit, should succeed
/// - 1000 bytes (MSG_LEN):    exactly at the limit, should succeed
/// - 1001 bytes (MSG_LEN + 1): over the limit, should fail
#[tokio::test]
async fn snow_test_message_payload_boundary_sizes() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let mut pair = setup_encryptors(&testnet, "NN").await;
    complete_nn_handshake(&mut pair).await;

    // 999 bytes (PUBKY_NOISE_MSG_LEN - 1): under the limit — succeeds
    let payload_under = [b'A'; PUBKY_NOISE_MSG_LEN - 1];
    assert!(
        pair.initiator.send_message(&payload_under).await,
        "999-byte payload should succeed"
    );
    let results = pair.responder.receive_message().await;
    assert!(
        !results.is_empty(),
        "Responder should receive the 999-byte message"
    );
    assert_eq!(
        &results[0][..PUBKY_NOISE_MSG_LEN - 1],
        &payload_under,
        "Decrypted payload should match the original 999 bytes"
    );

    // 1000 bytes (PUBKY_NOISE_MSG_LEN): exactly at the limit — succeeds
    let payload_exact = [b'B'; PUBKY_NOISE_MSG_LEN];
    assert!(
        pair.initiator.send_message(&payload_exact).await,
        "1000-byte payload should succeed"
    );
    let results = pair.responder.receive_message().await;
    assert!(
        !results.is_empty(),
        "Responder should receive the 1000-byte message"
    );
    assert_eq!(
        &results[0][..],
        &payload_exact,
        "Decrypted payload should match the original 1000 bytes"
    );

    // 1001 bytes (PUBKY_NOISE_MSG_LEN + 1): over the limit — fails
    let payload_over = [b'C'; PUBKY_NOISE_MSG_LEN + 1];
    assert!(
        !pair.initiator.send_message(&payload_over).await,
        "1001-byte payload should fail (exceeds PUBKY_NOISE_MSG_LEN)"
    );
}
