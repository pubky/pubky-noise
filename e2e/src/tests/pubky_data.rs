use std::sync::Arc;

use pubky_testnet::{pubky::Keypair, EphemeralTestnet};

use pubky_data::snow_crypto::{HandshakePattern, PUBKY_DATA_MSG_LEN};
use pubky_data::{PubkyDataConfig, PubkyDataEncryptor, PubkyDataError};

//TODO:
//	- test max message size limit
//	- test minimal message size
//	- test single-message multiple ciphertexts
//	- test multiple data encryptor parallel
//	- test PubkySession not signed up ?

fn cipher_check(plaintext: Vec<u8>, ciphertext: &[u8; PUBKY_DATA_MSG_LEN + 2]) {
    let plaintext_len = plaintext.len();
    let mut match_check = 0;
    for counter in 0..plaintext_len {
        let ciphered_byte = ciphertext[counter];
        if plaintext[counter] == ciphered_byte {
            match_check += 1;
        }
    }
    // i.e plaintext == ciphertext byte-for-byte
    if match_check == plaintext_len {
        panic!()
    }
}

#[tokio::test]
#[should_panic]
async fn pubky_data_cipher_check_utility_positive() {
    let plaintext = ['A' as u8; PUBKY_DATA_MSG_LEN + 2];
    let ciphertext = plaintext.clone();
    cipher_check(plaintext.to_vec(), &ciphertext);
}

#[tokio::test]
async fn pubky_data_cipher_check_utility_negative() {
    let plaintext = ['A' as u8; PUBKY_DATA_MSG_LEN + 2];
    let mut ciphertext = plaintext.clone();
    ciphertext[0] = b'B';
    cipher_check(plaintext.to_vec(), &ciphertext);
}

#[tokio::test]
async fn pubky_data_snow_test_initiator_first() {
    // Start a test homeserver with 1 MB user data limit
    let testnet = EphemeralTestnet::builder().build().await.unwrap();

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

    let server_path_string = format!("/pub/data");

    let initiator_keypair = Keypair::random();
    let initiator_config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyDataConfig::new(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let mut initiator_encryptor = PubkyDataEncryptor::new(
        initiator_config,
        initiator_ephemeral_keypair.secret_key(),
        responder_ephemeral_keypair.public_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();

    let mut responder_encryptor = PubkyDataEncryptor::new(
        responder_config,
        responder_ephemeral_keypair.secret_key(),
        initiator_ephemeral_keypair.public_key(),
        false,
        initiator_public_key.clone(),
    )
    .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;
    initiator_encryptor.handle_handshake().await;

    assert!(!initiator_encryptor.is_handshake().is_ok());
    assert!(!responder_encryptor.is_handshake().is_ok());

    let initiator_link_id = initiator_encryptor.transition_transport();
    assert!(initiator_link_id.is_ok());
    let responder_link_id = responder_encryptor.transition_transport();
    assert!(responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello_World_Pubky_Data");
    let raw_bytes = data_payload.as_bytes().to_vec();

    initiator_encryptor.send_message(raw_bytes).await;

    let results = responder_encryptor.receive_message().await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec()).unwrap();
        let (msg, _) = padded_msg.split_at(data_payload.len());
        assert_eq!(msg, "Hello_World_Pubky_Data".to_string());
    }

    let data_payload = String::from("Pubky_Data_Rocks");
    let raw_bytes = data_payload.as_bytes().to_vec();
    responder_encryptor.send_message(raw_bytes).await;

    let results = initiator_encryptor.receive_message().await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec()).unwrap();
        let (msg, _) = padded_msg.split_at(data_payload.len());
        assert_eq!(msg, "Pubky_Data_Rocks".to_string());
    }
}

#[tokio::test]
async fn pubky_data_snow_test_responder_first() {
    // Start a test homeserver with 1 MB user data limit
    let testnet = EphemeralTestnet::builder().build().await.unwrap();
    let initiator_pubky = testnet.sdk().unwrap();
    let responder_pubky = testnet.sdk().unwrap();

    let server = testnet.homeserver_app();

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

    let server_path_string = format!("/pub/data");

    let initiator_keypair = Keypair::random();
    let initiator_config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyDataConfig::new(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let mut initiator_encryptor = PubkyDataEncryptor::new(
        initiator_config,
        initiator_ephemeral_keypair.secret_key(),
        responder_ephemeral_keypair.public_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();

    let mut responder_encryptor = PubkyDataEncryptor::new(
        responder_config,
        responder_ephemeral_keypair.secret_key(),
        initiator_ephemeral_keypair.public_key(),
        false,
        initiator_public_key.clone(),
    )
    .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;
    initiator_encryptor.handle_handshake().await;

    assert!(!initiator_encryptor.is_handshake().is_ok());
    assert!(!responder_encryptor.is_handshake().is_ok());

    let _initiator_link_id = initiator_encryptor.transition_transport();
    assert!(_initiator_link_id.is_ok());
    let _responder_link_id = responder_encryptor.transition_transport();
    assert!(_responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello World Pubky Data");
    let raw_bytes = data_payload.as_bytes().to_vec();

    responder_encryptor.send_message(raw_bytes).await;

    let results = initiator_encryptor.receive_message().await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec()).unwrap();
        let (msg, _) = padded_msg.split_at(data_payload.len());
        assert_eq!(msg, "Hello World Pubky Data".to_string());
    }

    let data_payload = String::from("Pubky Data Rocks");
    let raw_bytes = data_payload.as_bytes().to_vec();

    initiator_encryptor.send_message(raw_bytes).await;

    let results = responder_encryptor.receive_message().await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec()).unwrap();
        let (msg, _) = padded_msg.split_at(data_payload.len());
        assert_eq!(msg, "Pubky Data Rocks".to_string());
    }
}

#[tokio::test]
async fn pubky_data_snow_test_responder_tampering() {
    // Start a test homeserver with 1 MB user data limit
    let testnet = EphemeralTestnet::builder().build().await.unwrap();
    let initiator_pubky = testnet.sdk().unwrap();
    let responder_pubky = testnet.sdk().unwrap();

    let server = testnet.homeserver_app();

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

    let server_path_string = format!("/pub/data");

    let initiator_keypair = Keypair::random();
    let initiator_config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyDataConfig::new(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let mut initiator_encryptor = PubkyDataEncryptor::new(
        initiator_config,
        initiator_ephemeral_keypair.secret_key(),
        responder_ephemeral_keypair.public_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();
    initiator_encryptor.test_enable_tampering();

    let mut responder_encryptor = PubkyDataEncryptor::new(
        responder_config,
        responder_ephemeral_keypair.secret_key(),
        initiator_ephemeral_keypair.public_key(),
        false,
        initiator_public_key.clone(),
    )
    .unwrap();
    responder_encryptor.test_enable_tampering();

    // Initiator sends handshake
    // -> e
    // <- e, ee
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;
    initiator_encryptor.handle_handshake().await;

    assert!(!initiator_encryptor.is_handshake().is_ok());
    assert!(!responder_encryptor.is_handshake().is_ok());

    let _initiator_link_id = initiator_encryptor.transition_transport();
    assert!(_initiator_link_id.is_ok());
    let _responder_link_id = responder_encryptor.transition_transport();
    assert!(_responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello World Pubky Data");
    let raw_bytes = data_payload.as_bytes().to_vec();
    println!("RAW BYTES {:?}", raw_bytes);
    responder_encryptor.send_message(raw_bytes.clone()).await;

    let results = initiator_encryptor.receive_message().await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec());
        assert!(padded_msg.is_err());
    }

    let last_ciphertext = responder_encryptor.test_last_ciphertext();
    if last_ciphertext.is_none() {
        panic!();
    } else {
        cipher_check(raw_bytes, &last_ciphertext.unwrap());
    }
}

#[tokio::test]
async fn pubky_data_snow_test_initiator_tampering() {
    // Start a test homeserver with 1 MB user data limit
    let testnet = EphemeralTestnet::builder().build().await.unwrap();
    let initiator_pubky = testnet.sdk().unwrap();
    let responder_pubky = testnet.sdk().unwrap();

    let server = testnet.homeserver_app();

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

    let server_path_string = format!("/pub/data");

    let initiator_keypair = Keypair::random();
    let initiator_config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyDataConfig::new(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let mut initiator_encryptor = PubkyDataEncryptor::new(
        initiator_config,
        initiator_ephemeral_keypair.secret_key(),
        responder_ephemeral_keypair.public_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();
    initiator_encryptor.test_enable_tampering();

    let mut responder_encryptor = PubkyDataEncryptor::new(
        responder_config,
        responder_ephemeral_keypair.secret_key(),
        initiator_ephemeral_keypair.public_key(),
        false,
        initiator_public_key.clone(),
    )
    .unwrap();
    responder_encryptor.test_enable_tampering();

    // Initiator sends handshake
    // -> e
    // <- e, ee
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;
    initiator_encryptor.handle_handshake().await;

    // yield Err(PubkyDataError::IsTransport)
    assert!(!initiator_encryptor.is_handshake().is_ok());
    assert!(!responder_encryptor.is_handshake().is_ok());

    let _initiator_link_id = initiator_encryptor.transition_transport();
    assert!(_initiator_link_id.is_ok());
    let _responder_link_id = responder_encryptor.transition_transport();
    assert!(_responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello World Pubky Data");
    let raw_bytes = data_payload.as_bytes().to_vec();
    println!("RAW BYTES {:?}", raw_bytes);
    initiator_encryptor.send_message(raw_bytes.clone()).await;

    let results = responder_encryptor.receive_message().await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec());
        assert!(padded_msg.is_err());
    }

    let last_ciphertext = initiator_encryptor.test_last_ciphertext();
    if last_ciphertext.is_none() {
        panic!();
    } else {
        cipher_check(raw_bytes, &last_ciphertext.unwrap());
    }
}

#[tokio::test]
async fn pubky_data_snow_null_message() {
    // Start a test homeserver with 1 MB user data limit
    let testnet = EphemeralTestnet::builder().build().await.unwrap();
    let initiator_pubky = testnet.sdk().unwrap();
    let responder_pubky = testnet.sdk().unwrap();

    let server = testnet.homeserver_app();

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

    let server_path_string = format!("/pub/data");

    let initiator_keypair = Keypair::random();
    let initiator_config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyDataConfig::new(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let mut initiator_encryptor = PubkyDataEncryptor::new(
        initiator_config,
        initiator_ephemeral_keypair.secret_key(),
        responder_ephemeral_keypair.public_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();

    let mut responder_encryptor = PubkyDataEncryptor::new(
        responder_config,
        responder_ephemeral_keypair.secret_key(),
        initiator_ephemeral_keypair.public_key(),
        false,
        initiator_public_key.clone(),
    )
    .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;
    initiator_encryptor.handle_handshake().await;

    // yield Err(PubkyDataError::IsTransport)
    assert!(!initiator_encryptor.is_handshake().is_ok());
    assert!(!responder_encryptor.is_handshake().is_ok());

    let _initiator_link_id = initiator_encryptor.transition_transport();
    assert!(_initiator_link_id.is_ok());
    let _responder_link_id = responder_encryptor.transition_transport();
    assert!(_responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("");
    let raw_bytes = data_payload.as_bytes().to_vec();
    responder_encryptor.send_message(raw_bytes).await;

    let results = initiator_encryptor.receive_message().await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec()).unwrap();
        let (msg, _) = padded_msg.split_at(data_payload.len());
        assert_eq!(msg, "".to_string());
    }
}

#[tokio::test]
async fn pubky_data_snow_test_unknown_pattern() {
    // Start a test homeserver with 1 MB user data limit
    let testnet = EphemeralTestnet::builder().build().await.unwrap();
    let server = testnet.homeserver_app();
    let initiator_pubky = testnet.sdk().unwrap();

    let initiator_signer = initiator_pubky.signer(Keypair::random());
    let initiator_session = initiator_signer
        .signup(&server.public_key(), None)
        .await
        .unwrap();

    let server_path_string = format!("/pub/data");

    let initiator_keypair = Keypair::random();
    let init_config_ret = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "BA".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    );
    assert!(init_config_ret.is_err());
    assert!(init_config_ret.unwrap_err() == PubkyDataError::UnknownNoisePattern);
}

#[tokio::test]
async fn pubky_data_snow_test_snow_noise_build_error() {
    let testnet = EphemeralTestnet::builder().build().await.unwrap();
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

    let server_path_string = format!("/pub/data");

    let initiator_keypair = Keypair::random();
    // Create config with NN pattern, then override to TestOnlyPatternAA
    let mut config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    // Mutate the pattern to a non-buildable one
    Arc::get_mut(&mut config).unwrap().default_pattern = HandshakePattern::TestOnlyPatternAA;

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let responder_public_key = responder_session.info().public_key();

    let init_encryptor_ret = PubkyDataEncryptor::new(
        config,
        initiator_ephemeral_keypair.secret_key(),
        responder_ephemeral_keypair.public_key(),
        true,
        responder_public_key.clone(),
    );
    assert!(init_encryptor_ret.is_err());
    assert!(init_encryptor_ret.unwrap_err() == PubkyDataError::SnowNoiseBuildError);
}

#[tokio::test]
async fn pubky_data_snow_test_cleaning_sequence() {
    let testnet = EphemeralTestnet::builder().build().await.unwrap();
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

    let server_path_string = format!("/pub/data");

    let initiator_keypair = Keypair::random();
    let initiator_config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyDataConfig::new(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let mut initiator_encryptor = PubkyDataEncryptor::new(
        initiator_config,
        initiator_ephemeral_keypair.secret_key(),
        responder_ephemeral_keypair.public_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();

    let mut responder_encryptor = PubkyDataEncryptor::new(
        responder_config,
        responder_ephemeral_keypair.secret_key(),
        initiator_ephemeral_keypair.public_key(),
        false,
        initiator_public_key.clone(),
    )
    .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;
    initiator_encryptor.handle_handshake().await;

    assert!(!initiator_encryptor.is_handshake().is_ok());
    assert!(!responder_encryptor.is_handshake().is_ok());

    let _initiator_link_id = initiator_encryptor.transition_transport();
    assert!(_initiator_link_id.is_ok());
    let _responder_link_id = responder_encryptor.transition_transport();
    assert!(_responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello_World_Pubky_Data");
    let raw_bytes = data_payload.as_bytes().to_vec();

    initiator_encryptor.send_message(raw_bytes).await;

    let results = responder_encryptor.receive_message().await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec()).unwrap();
        let (msg, _) = padded_msg.split_at(data_payload.len());
        assert_eq!(msg, "Hello_World_Pubky_Data".to_string());
    }

    // Close both encryptors
    initiator_encryptor.close();
    responder_encryptor.close();
}

#[tokio::test]
async fn pubky_data_snow_test_XX_pattern_simple() {
    let testnet = EphemeralTestnet::builder().build().await.unwrap();
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

    let server_path_string = format!("/pub/data");

    let initiator_keypair = Keypair::random();
    let initiator_config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "XX".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyDataConfig::new(
        responder_keypair.secret_key(),
        0,
        "XX".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let mut initiator_encryptor = PubkyDataEncryptor::new(
        initiator_config,
        initiator_ephemeral_keypair.secret_key(),
        responder_ephemeral_keypair.public_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();

    let mut responder_encryptor = PubkyDataEncryptor::new(
        responder_config,
        responder_ephemeral_keypair.secret_key(),
        initiator_ephemeral_keypair.public_key(),
        false,
        initiator_public_key.clone(),
    )
    .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee, s, es
    // -> s, se
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;

    assert!(!initiator_encryptor.is_handshake().is_ok());
    assert!(!responder_encryptor.is_handshake().is_ok());

    let _initiator_link_id = initiator_encryptor.transition_transport();
    assert!(_initiator_link_id.is_ok());
    let _responder_link_id = responder_encryptor.transition_transport();
    assert!(_responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello_World_Pubky_Data");
    let raw_bytes = data_payload.as_bytes().to_vec();
    initiator_encryptor.send_message(raw_bytes).await;

    let results = responder_encryptor.receive_message().await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec()).unwrap();
        let (msg, _) = padded_msg.split_at(data_payload.len());
        assert_eq!(msg, "Hello_World_Pubky_Data".to_string());
    }

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
async fn pubky_data_snow_test_XX_pattern_tampering() {
    let testnet = EphemeralTestnet::builder().build().await.unwrap();
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

    let server_path_string = format!("/pub/data");

    let initiator_keypair = Keypair::random();
    let initiator_config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "XX".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyDataConfig::new(
        responder_keypair.secret_key(),
        0,
        "XX".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let mut initiator_encryptor = PubkyDataEncryptor::new(
        initiator_config,
        initiator_ephemeral_keypair.secret_key(),
        responder_ephemeral_keypair.public_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();
    initiator_encryptor.test_enable_tampering();

    let mut responder_encryptor = PubkyDataEncryptor::new(
        responder_config,
        responder_ephemeral_keypair.secret_key(),
        initiator_ephemeral_keypair.public_key(),
        false,
        initiator_public_key.clone(),
    )
    .unwrap();
    responder_encryptor.test_enable_tampering();

    // Initiator sends handshake
    // -> e
    // <- e, ee, s, es
    // -> s, se
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;

    assert!(!initiator_encryptor.is_handshake().is_ok());
    assert!(!responder_encryptor.is_handshake().is_ok());

    let _initiator_link_id = initiator_encryptor.transition_transport();
    assert!(_initiator_link_id.is_ok());
    let _responder_link_id = responder_encryptor.transition_transport();
    assert!(_responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello_World_Pubky_Data");
    let raw_bytes = data_payload.as_bytes().to_vec();
    initiator_encryptor.send_message(raw_bytes.clone()).await;

    let results = responder_encryptor.receive_message().await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec());
        assert!(padded_msg.is_err());
    }

    let last_ciphertext = initiator_encryptor.test_last_ciphertext();
    if last_ciphertext.is_none() {
        panic!();
    } else {
        cipher_check(raw_bytes, &last_ciphertext.unwrap());
    }
}

#[tokio::test]
async fn pubky_data_snow_test_simple_backup() {
    let testnet = EphemeralTestnet::builder().build().await.unwrap();
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

    let server_path_string = format!("/pub/data");

    let initiator_keypair = Keypair::random();
    let initiator_config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "XX".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyDataConfig::new(
        responder_keypair.secret_key(),
        0,
        "XX".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let mut initiator_encryptor = PubkyDataEncryptor::new(
        initiator_config,
        initiator_ephemeral_keypair.secret_key(),
        responder_ephemeral_keypair.public_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();

    let mut responder_encryptor = PubkyDataEncryptor::new(
        responder_config,
        responder_ephemeral_keypair.secret_key(),
        initiator_ephemeral_keypair.public_key(),
        false,
        initiator_public_key.clone(),
    )
    .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee, s, es
    // -> s, se
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;

    assert!(!initiator_encryptor.is_handshake().is_ok());
    assert!(!responder_encryptor.is_handshake().is_ok());

    let _initiator_link_id = initiator_encryptor.transition_transport();
    assert!(_initiator_link_id.is_ok());
    let _responder_link_id = responder_encryptor.transition_transport();
    assert!(_responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello_World_Pubky_Data");
    let raw_bytes = data_payload.as_bytes().to_vec();

    initiator_encryptor.send_message(raw_bytes).await;

    let results = responder_encryptor.receive_message().await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec()).unwrap();
        let (msg, _) = padded_msg.split_at(data_payload.len());
        assert_eq!(msg, "Hello_World_Pubky_Data".to_string());
    }

    initiator_encryptor.generate_backup(false).await;
}

#[tokio::test]
async fn pubky_data_snow_test_dual_outbox() {
    let testnet = EphemeralTestnet::builder().build().await.unwrap();
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

    let server_path_string = format!("/pub/data");

    let initiator_keypair = Keypair::random();
    let initiator_config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyDataConfig::new(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let mut initiator_encryptor = PubkyDataEncryptor::new(
        initiator_config,
        initiator_ephemeral_keypair.secret_key(),
        responder_ephemeral_keypair.public_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();

    let mut responder_encryptor = PubkyDataEncryptor::new(
        responder_config,
        responder_ephemeral_keypair.secret_key(),
        initiator_ephemeral_keypair.public_key(),
        false,
        initiator_public_key.clone(),
    )
    .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;

    assert!(!initiator_encryptor.is_handshake().is_ok());
    assert!(!responder_encryptor.is_handshake().is_ok());

    let _initiator_link_id = initiator_encryptor.transition_transport();
    assert!(_initiator_link_id.is_ok());
    let _responder_link_id = responder_encryptor.transition_transport();
    assert!(_responder_link_id.is_ok());

    //TODO: Alice can write only to her own Homeserver but can read from own
    // and Bob's Homeserver.
    //    => corollary: Bob can write only to his own Homeserver but can read from
    // own and Bob's Homeserver
}

#[tokio::test]
async fn pubky_data_snow_test_identity_commitment() {
    let testnet = EphemeralTestnet::builder().build().await.unwrap();

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

    let server_path_string = format!("/pub/data");

    let initiator_keypair = Keypair::random();
    let initiator_config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyDataConfig::new(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let mut initiator_encryptor = PubkyDataEncryptor::new(
        initiator_config,
        initiator_ephemeral_keypair.secret_key(),
        responder_ephemeral_keypair.public_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();

    let mut responder_encryptor = PubkyDataEncryptor::new(
        responder_config,
        responder_ephemeral_keypair.secret_key(),
        initiator_ephemeral_keypair.public_key(),
        false,
        initiator_public_key.clone(),
    )
    .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;

    assert!(!initiator_encryptor.is_handshake().is_ok());
    assert!(!responder_encryptor.is_handshake().is_ok());

    let _initiator_link_id = initiator_encryptor.transition_transport();
    assert!(_initiator_link_id.is_ok());
    let _responder_link_id = responder_encryptor.transition_transport();
    assert!(_responder_link_id.is_ok());

    //TODO: initiator receive_message -> identity binding
    //TODO: responder receive_message -> identity binding
}

#[tokio::test]
async fn pubky_data_snow_test_identifers() {
    //TODO: test no collision between session id, context id and peer fingerprint (3 elements)
}

#[tokio::test]
async fn pubky_data_snow_test_XX_pattern_simple_out_of_order_handshake() {
    let testnet = EphemeralTestnet::builder().build().await.unwrap();
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

    let server_path_string = format!("/pub/data");

    let initiator_keypair = Keypair::random();
    let initiator_config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "XX".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyDataConfig::new(
        responder_keypair.secret_key(),
        0,
        "XX".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let mut initiator_encryptor = PubkyDataEncryptor::new(
        initiator_config,
        initiator_ephemeral_keypair.secret_key(),
        responder_ephemeral_keypair.public_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();

    let mut responder_encryptor = PubkyDataEncryptor::new(
        responder_config,
        responder_ephemeral_keypair.secret_key(),
        initiator_ephemeral_keypair.public_key(),
        false,
        initiator_public_key.clone(),
    )
    .unwrap();

    // Initiator sends handshake (out of order polling)
    // -> e
    // <- e, ee, s, es
    // -> s, se
    responder_encryptor.handle_handshake().await;
    initiator_encryptor.handle_handshake().await;
    initiator_encryptor.handle_handshake().await;
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;

    assert!(!initiator_encryptor.is_handshake().is_ok());
    assert!(!responder_encryptor.is_handshake().is_ok());

    let _initiator_link_id = initiator_encryptor.transition_transport();
    assert!(_initiator_link_id.is_ok());
    let _responder_link_id = responder_encryptor.transition_transport();
    assert!(_responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello_World_Pubky_Data");
    let raw_bytes = data_payload.as_bytes().to_vec();
    initiator_encryptor.send_message(raw_bytes).await;

    let results = responder_encryptor.receive_message().await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec()).unwrap();
        let (msg, _) = padded_msg.split_at(data_payload.len());
        assert_eq!(msg, "Hello_World_Pubky_Data".to_string());
    }

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
async fn pubky_data_snow_test_XX_pattern_simple_incomplete_handshake() {
    let testnet = EphemeralTestnet::builder().build().await.unwrap();
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

    let server_path_string = format!("/pub/data");

    let initiator_keypair = Keypair::random();
    let initiator_config = PubkyDataConfig::new(
        initiator_keypair.secret_key(),
        0,
        "XX".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let responder_config = PubkyDataConfig::new(
        responder_keypair.secret_key(),
        0,
        "XX".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let mut initiator_encryptor = PubkyDataEncryptor::new(
        initiator_config,
        initiator_ephemeral_keypair.secret_key(),
        responder_ephemeral_keypair.public_key(),
        true,
        responder_public_key.clone(),
    )
    .unwrap();

    let mut responder_encryptor = PubkyDataEncryptor::new(
        responder_config,
        responder_ephemeral_keypair.secret_key(),
        initiator_ephemeral_keypair.public_key(),
        false,
        initiator_public_key.clone(),
    )
    .unwrap();

    // Initiator sends handshake (incomplete)
    // -> e
    // <- e, ee, s, es
    // -> s, se  (NOT DONE)
    initiator_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;
    responder_encryptor.handle_handshake().await;

    assert!(initiator_encryptor.is_handshake().is_ok());
    assert!(responder_encryptor.is_handshake().is_ok());

    let initiator_link_id = initiator_encryptor.transition_transport();
    assert!(!initiator_link_id.is_ok());
    let responder_link_id = responder_encryptor.transition_transport();
    assert!(!responder_link_id.is_ok());
}
