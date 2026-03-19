use std::sync::Arc;

use pubky_testnet::{
    pubky::{Keypair, PublicKey},
    EphemeralTestnet,
};

use pubky_data::serializer::PubkyDataSessionState;
use pubky_data::snow_crypto::{HandshakePattern, PUBKY_DATA_MSG_LEN};
use pubky_data::{PubkyDataConfig, PubkyDataEncryptor, PubkyDataError};

fn cipher_check(plaintext: &[u8], ciphertext: &[u8; PUBKY_DATA_MSG_LEN + 2]) {
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
    initiator: PubkyDataEncryptor,
    responder: PubkyDataEncryptor,
    initiator_config: Arc<PubkyDataConfig>,
    responder_config: Arc<PubkyDataConfig>,
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
    let initiator_config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        pattern,
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyDataConfig::new(
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

    let initiator = PubkyDataEncryptor::new(
        initiator_config.clone(),
        initiator_ephemeral_keypair.secret_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();

    let responder = PubkyDataEncryptor::new(
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
    let initiator_config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        pattern,
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyDataConfig::new(
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

    let initiator = PubkyDataEncryptor::new(
        initiator_config.clone(),
        initiator_ephemeral_keypair.secret_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();

    let responder = PubkyDataEncryptor::new(
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
    sender: &mut PubkyDataEncryptor,
    receiver: &mut PubkyDataEncryptor,
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
    sender: &mut PubkyDataEncryptor,
    receiver: &mut PubkyDataEncryptor,
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
async fn pubky_data_cipher_check_utility_positive() {
    let plaintext = [b'A'; PUBKY_DATA_MSG_LEN + 2];
    let ciphertext = plaintext;
    cipher_check(&plaintext, &ciphertext);
}

#[tokio::test]
async fn pubky_data_cipher_check_utility_negative() {
    let plaintext = [b'A'; PUBKY_DATA_MSG_LEN + 2];
    let mut ciphertext = plaintext;
    ciphertext[0] = b'B';
    cipher_check(&plaintext, &ciphertext);
}

#[tokio::test]
async fn pubky_data_snow_test_initiator_first() {
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
        "Hello_World_Pubky_Data",
    )
    .await;
    send_and_verify(&mut pair.responder, &mut pair.initiator, "Pubky_Data_Rocks").await;
}

#[tokio::test]
async fn pubky_data_snow_test_responder_first() {
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
        "Hello World Pubky Data",
    )
    .await;
    send_and_verify(&mut pair.initiator, &mut pair.responder, "Pubky Data Rocks").await;
}

#[tokio::test]
async fn pubky_data_snow_test_responder_tampering() {
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
        "Hello World Pubky Data",
    )
    .await;
}

#[tokio::test]
async fn pubky_data_snow_test_initiator_tampering() {
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
        "Hello World Pubky Data",
    )
    .await;
}

#[tokio::test]
async fn pubky_data_snow_null_message() {
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
// async fn pubky_data_snow_test_min_max_size_message() {
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
//     let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
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
//     let mut responder_encryptor = PubkyDataEncryptor::init_encryptor_stack(
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

//     // yield Err(PubkyDataError::IsTransport)
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
async fn pubky_data_snow_test_unknown_pattern() {
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
    let init_config_ret = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "BA",
        initiator_session,
        server_path_string,
        initiator_pubky,
    );
    assert!(init_config_ret.is_err());
    assert!(init_config_ret.unwrap_err() == PubkyDataError::UnknownNoisePattern);
}

#[tokio::test]
async fn pubky_data_snow_test_snow_noise_build_error() {
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
    let mut config = PubkyDataConfig::new(
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

    let init_encryptor_ret = PubkyDataEncryptor::new(
        config,
        initiator_ephemeral_keypair.secret_key(),
        true,
        responder_public_key.clone(),
    );
    assert!(init_encryptor_ret.is_err());
    assert!(init_encryptor_ret.unwrap_err() == PubkyDataError::SnowNoiseBuildError);
}

#[tokio::test]
async fn pubky_data_snow_test_cleaning_sequence() {
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
        "Hello_World_Pubky_Data",
    )
    .await;

    // Close both encryptors
    pair.initiator.close();
    pair.responder.close();
}

#[tokio::test]
#[allow(non_snake_case)]
async fn pubky_data_snow_test_XX_pattern_simple() {
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
        "Hello_World_Pubky_Data",
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
        PUBKY_DATA_MSG_LEN + 2,
        "Stored data should be PUBKY_DATA_MSG_LEN + 2 bytes"
    );
    let len0 = u16::from_be_bytes([slot0_bytes[0], slot0_bytes[1]]) as usize;
    assert!(
        len0 > 0 && len0 <= PUBKY_DATA_MSG_LEN,
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
    assert_eq!(slot1_bytes.len(), PUBKY_DATA_MSG_LEN + 2);
    let len1 = u16::from_be_bytes([slot1_bytes[0], slot1_bytes[1]]) as usize;
    assert!(
        len1 > 0 && len1 <= PUBKY_DATA_MSG_LEN,
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
    assert_eq!(slot2_bytes.len(), PUBKY_DATA_MSG_LEN + 2);
    let len2 = u16::from_be_bytes([slot2_bytes[0], slot2_bytes[1]]) as usize;
    assert!(
        len2 > 0 && len2 <= PUBKY_DATA_MSG_LEN,
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
    assert_eq!(slot3_bytes.len(), PUBKY_DATA_MSG_LEN + 2);
    let len3 = u16::from_be_bytes([slot3_bytes[0], slot3_bytes[1]]) as usize;
    assert!(
        len3 > 0 && len3 <= PUBKY_DATA_MSG_LEN,
        "Length prefix should be valid, got {len3}"
    );
    // Verify the stored data is actually encrypted (not plaintext)
    let transport_ciphertext = &slot3_bytes[2..len3 + 2];
    let plaintext_bytes = "Hello_World_Pubky_Data".as_bytes();
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
async fn pubky_data_snow_test_XX_pattern_tampering() {
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
        "Hello_World_Pubky_Data",
    )
    .await;
}

#[tokio::test]
async fn pubky_data_snow_test_simple_backup() {
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
        "Hello_World_Pubky_Data",
    )
    .await;

    let _ = pair.initiator.persist_snapshot().await;
}

#[tokio::test]
async fn pubky_data_snow_test_dual_outbox() {
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
async fn pubky_data_snow_test_identity_commitment() {
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
async fn pubky_data_snow_test_XX_pattern_simple_out_of_order_handshake() {
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
        "Hello_World_Pubky_Data",
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
        PUBKY_DATA_MSG_LEN + 2,
        "Stored data should be PUBKY_DATA_MSG_LEN + 2 bytes"
    );
    let len0 = u16::from_be_bytes([slot0_bytes[0], slot0_bytes[1]]) as usize;
    assert!(
        len0 > 0 && len0 <= PUBKY_DATA_MSG_LEN,
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
    assert_eq!(slot1_bytes.len(), PUBKY_DATA_MSG_LEN + 2);
    let len1 = u16::from_be_bytes([slot1_bytes[0], slot1_bytes[1]]) as usize;
    assert!(
        len1 > 0 && len1 <= PUBKY_DATA_MSG_LEN,
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
    assert_eq!(slot2_bytes.len(), PUBKY_DATA_MSG_LEN + 2);
    let len2 = u16::from_be_bytes([slot2_bytes[0], slot2_bytes[1]]) as usize;
    assert!(
        len2 > 0 && len2 <= PUBKY_DATA_MSG_LEN,
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
    assert_eq!(slot3_bytes.len(), PUBKY_DATA_MSG_LEN + 2);
    let len3 = u16::from_be_bytes([slot3_bytes[0], slot3_bytes[1]]) as usize;
    assert!(
        len3 > 0 && len3 <= PUBKY_DATA_MSG_LEN,
        "Length prefix should be valid, got {len3}"
    );
    // Verify the stored data is actually encrypted (not plaintext)
    let transport_ciphertext = &slot3_bytes[2..len3 + 2];
    let plaintext_bytes = "Hello_World_Pubky_Data".as_bytes();
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
async fn pubky_data_snow_test_XX_pattern_simple_incomplete_handshake() {
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
async fn pubky_data_snow_test_restore() {
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

    let initiator_state = PubkyDataSessionState::deserialize(&initiator_bytes).unwrap();
    let responder_state = PubkyDataSessionState::deserialize(&responder_bytes).unwrap();

    // Restore both sides from snapshots
    let mut restored_initiator = PubkyDataEncryptor::restore(
        pair.initiator_config.clone(),
        initiator_state,
        responder_public_key.clone(),
    )
    .await
    .unwrap();
    let mut restored_responder = PubkyDataEncryptor::restore(
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
async fn pubky_data_snow_test_restore_serialization_roundtrip() {
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
    let restored = PubkyDataSessionState::deserialize(&bytes).unwrap();

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
async fn pubky_data_snow_test_restore_link_id_matches() {
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
    let init_state = PubkyDataSessionState::deserialize(&init_bytes).unwrap();
    let restored_initiator = PubkyDataEncryptor::restore(
        pair.initiator_config.clone(),
        init_state,
        responder_public_key.clone(),
    )
    .await
    .unwrap();

    // Snapshot and restore responder
    let resp_snapshot = pair.responder.snapshot();
    let resp_bytes = resp_snapshot.serialize();
    let resp_state = PubkyDataSessionState::deserialize(&resp_bytes).unwrap();
    let restored_responder = PubkyDataEncryptor::restore(
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
