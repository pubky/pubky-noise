use pubky_testnet::{pubky::Keypair, EphemeralTestnet};

use pubky_data::snow_crypto::{HandshakePattern, PUBKY_DATA_MSG_LEN};
use pubky_data::{LinkId, PubkyDataEncryptor, PubkyDataError, PubkyKeySet, TemporaryLinkId};

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
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        false,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let mut responder_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
        false,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let initiator_temporary_link_id = initiator_encryptor
        .init_context(initiator_key_set, true, responder_public_key.clone())
        .unwrap();

    let responder_key_set = PubkyKeySet::new(
        Some(responder_ephemeral_keypair.secret_key()),
        Some(initiator_ephemeral_keypair.public_key()),
    );
    let responder_temporary_link_id = responder_encryptor
        .init_context(responder_key_set, false, initiator_public_key.clone())
        .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;

    assert!(!initiator_encryptor
        .is_handshake(&initiator_temporary_link_id)
        .is_ok());
    assert!(!responder_encryptor
        .is_handshake(&responder_temporary_link_id)
        .is_ok());

    let initiator_link_id = initiator_encryptor.transition_transport(initiator_temporary_link_id);
    assert!(initiator_link_id.is_ok());
    let responder_link_id = responder_encryptor.transition_transport(responder_temporary_link_id);
    assert!(responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello_World_Pubky_Data");
    let raw_bytes = data_payload.as_bytes().to_vec();

    let initiator_link_id = initiator_link_id.unwrap();
    initiator_encryptor
        .send_message(raw_bytes, initiator_link_id.clone())
        .await;

    let responder_link_id = responder_link_id.unwrap();
    let results = responder_encryptor
        .receive_message(responder_link_id.clone())
        .await;

    assert!(results.len() >= 1);
    for ret in results {
        //println!("raw bytes to check ciphering {:?}", ret);
        let padded_msg = String::from_utf8(ret.to_vec()).unwrap();
        let (msg, _) = padded_msg.split_at(data_payload.len());
        assert_eq!(msg, "Hello_World_Pubky_Data".to_string());
    }

    let data_payload = String::from("Pubky_Data_Rocks");
    let raw_bytes = data_payload.as_bytes().to_vec();
    responder_encryptor
        .send_message(raw_bytes, responder_link_id)
        .await;

    let results = initiator_encryptor.receive_message(initiator_link_id).await;

    assert!(results.len() >= 1);
    for ret in results {
        //println!("raw bytes to check ciphering {:?}", ret);
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
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        false,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let mut responder_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
        false,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let initiator_temporary_link_id = initiator_encryptor
        .init_context(initiator_key_set, true, responder_public_key.clone())
        .unwrap();

    let responder_key_set = PubkyKeySet::new(
        Some(responder_ephemeral_keypair.secret_key()),
        Some(initiator_ephemeral_keypair.public_key()),
    );
    let responder_temporary_link_id = responder_encryptor
        .init_context(responder_key_set, false, initiator_public_key.clone())
        .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;

    assert!(!initiator_encryptor
        .is_handshake(&initiator_temporary_link_id)
        .is_ok());
    assert!(!responder_encryptor
        .is_handshake(&responder_temporary_link_id)
        .is_ok());

    let initiator_link_id = initiator_encryptor.transition_transport(initiator_temporary_link_id);
    assert!(initiator_link_id.is_ok());
    let responder_link_id = responder_encryptor.transition_transport(responder_temporary_link_id);
    assert!(responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello World Pubky Data");
    let raw_bytes = data_payload.as_bytes().to_vec();

    let responder_link_id = responder_link_id.unwrap();
    responder_encryptor
        .send_message(raw_bytes, responder_link_id.clone())
        .await;

    let initiator_link_id = initiator_link_id.unwrap();
    let results = initiator_encryptor
        .receive_message(initiator_link_id.clone())
        .await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec()).unwrap();
        let (msg, _) = padded_msg.split_at(data_payload.len());
        assert_eq!(msg, "Hello World Pubky Data".to_string());
    }

    let data_payload = String::from("Pubky Data Rocks");
    let raw_bytes = data_payload.as_bytes().to_vec();

    initiator_encryptor
        .send_message(raw_bytes, initiator_link_id)
        .await;

    let results = responder_encryptor.receive_message(responder_link_id).await;

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
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        true,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let mut responder_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
        true,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let initiator_temporary_link_id = initiator_encryptor
        .init_context(initiator_key_set, true, responder_public_key.clone())
        .unwrap();

    let responder_key_set = PubkyKeySet::new(
        Some(responder_ephemeral_keypair.secret_key()),
        Some(initiator_ephemeral_keypair.public_key()),
    );
    let responder_temporary_link_id = responder_encryptor
        .init_context(responder_key_set, false, initiator_public_key.clone())
        .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;

    assert!(!initiator_encryptor
        .is_handshake(&initiator_temporary_link_id)
        .is_ok());
    assert!(!responder_encryptor
        .is_handshake(&responder_temporary_link_id)
        .is_ok());

    let initiator_link_id = initiator_encryptor.transition_transport(initiator_temporary_link_id);
    assert!(initiator_link_id.is_ok());
    let responder_link_id = responder_encryptor.transition_transport(responder_temporary_link_id);
    assert!(responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello World Pubky Data");
    let raw_bytes = data_payload.as_bytes().to_vec();
    println!("RAW BYTES {:?}", raw_bytes);
    responder_encryptor
        .send_message(raw_bytes.clone(), responder_link_id.unwrap())
        .await;

    let results = initiator_encryptor
        .receive_message(initiator_link_id.unwrap())
        .await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec());
        assert!(padded_msg.is_err());
    }

    let last_ciphertext = responder_encryptor.test_get_last_ciphertext();
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
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        true,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let mut responder_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
        true,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let initiator_temporary_link_id = initiator_encryptor
        .init_context(initiator_key_set, true, responder_public_key.clone())
        .unwrap();

    let responder_key_set = PubkyKeySet::new(
        Some(responder_ephemeral_keypair.secret_key()),
        Some(initiator_ephemeral_keypair.public_key()),
    );
    let responder_temporary_link_id = responder_encryptor
        .init_context(responder_key_set, false, initiator_public_key.clone())
        .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;

    // yield Err(PubkyDataError::IsTransport)
    assert!(!initiator_encryptor
        .is_handshake(&initiator_temporary_link_id)
        .is_ok());
    assert!(!responder_encryptor
        .is_handshake(&responder_temporary_link_id)
        .is_ok());

    let initiator_link_id = initiator_encryptor.transition_transport(initiator_temporary_link_id);
    assert!(initiator_link_id.is_ok());
    let responder_link_id = responder_encryptor.transition_transport(responder_temporary_link_id);
    assert!(responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello World Pubky Data");
    let raw_bytes = data_payload.as_bytes().to_vec();
    println!("RAW BYTES {:?}", raw_bytes);
    initiator_encryptor
        .send_message(raw_bytes.clone(), initiator_link_id.unwrap())
        .await;

    let results = responder_encryptor
        .receive_message(responder_link_id.unwrap())
        .await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec());
        assert!(padded_msg.is_err());
    }

    let last_ciphertext = initiator_encryptor.test_get_last_ciphertext();
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
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        false,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let mut responder_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
        false,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let initiator_temporary_link_id = initiator_encryptor
        .init_context(initiator_key_set, true, responder_public_key.clone())
        .unwrap();

    let responder_key_set = PubkyKeySet::new(
        Some(responder_ephemeral_keypair.secret_key()),
        Some(initiator_ephemeral_keypair.public_key()),
    );
    let responder_temporary_link_id = responder_encryptor
        .init_context(responder_key_set, false, initiator_public_key.clone())
        .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;

    // yield Err(PubkyDataError::IsTransport)
    assert!(!initiator_encryptor
        .is_handshake(&initiator_temporary_link_id)
        .is_ok());
    assert!(!responder_encryptor
        .is_handshake(&responder_temporary_link_id)
        .is_ok());

    let initiator_link_id = initiator_encryptor.transition_transport(initiator_temporary_link_id);
    assert!(initiator_link_id.is_ok());
    let responder_link_id = responder_encryptor.transition_transport(responder_temporary_link_id);
    assert!(responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("");
    let raw_bytes = data_payload.as_bytes().to_vec();
    responder_encryptor
        .send_message(raw_bytes, responder_link_id.unwrap())
        .await;

    let results = initiator_encryptor
        .receive_message(initiator_link_id.unwrap())
        .await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec()).unwrap();
        let (msg, _) = padded_msg.split_at(data_payload.len());
        assert_eq!(msg, "".to_string());
    }
}

//#[tokio::test]
async fn pubky_data_snow_test_min_max_size_message() {
    //TODO: fix accordingly dual outbox model
    let testnet = EphemeralTestnet::builder().build().await.unwrap();

    let server = testnet.homeserver_app();
    let initiator_pubky = testnet.sdk().unwrap();
    let responder_pubky = testnet.sdk().unwrap();

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
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        false,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let mut responder_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
        false,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let initiator_temporary_link_id = initiator_encryptor
        .init_context(initiator_key_set, true, responder_public_key.clone())
        .unwrap();

    let responder_key_set = PubkyKeySet::new(
        Some(responder_ephemeral_keypair.secret_key()),
        Some(initiator_ephemeral_keypair.public_key()),
    );
    let responder_temporary_link_id = responder_encryptor
        .init_context(responder_key_set, false, initiator_public_key.clone())
        .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;

    // yield Err(PubkyDataError::IsTransport)
    assert!(!initiator_encryptor
        .is_handshake(&initiator_temporary_link_id)
        .is_ok());
    assert!(!responder_encryptor
        .is_handshake(&responder_temporary_link_id)
        .is_ok());

    let initiator_link_id = initiator_encryptor.transition_transport(initiator_temporary_link_id);
    assert!(initiator_link_id.is_ok());
    let responder_link_id = responder_encryptor.transition_transport(responder_temporary_link_id);
    assert!(responder_link_id.is_ok());

    // Transport
    let data_payload = ['A' as u8; 985];
    let raw_bytes = data_payload.to_vec();
    responder_encryptor
        .send_message(raw_bytes, initiator_link_id.unwrap())
        .await;

    let results = initiator_encryptor
        .receive_message(responder_link_id.unwrap())
        .await;

    assert!(results.len() >= 1);
    for ret in results {
        let ref_payload = ['A' as u8; 985];
        //assert_eq!(ret, ref_payload);
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
    let init_encryptor_ret = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "BA".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        false,
    );
    assert!(init_encryptor_ret.is_err());
    assert!(init_encryptor_ret.unwrap_err() == PubkyDataError::UnknownNoisePattern);
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
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        false,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    // tweak to a non-existent noise pattern
    initiator_encryptor.default_pattern = HandshakePattern::TestOnlyPatternAA;

    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let init_context_ret =
        initiator_encryptor.init_context(initiator_key_set, true, responder_public_key.clone());
    assert!(init_context_ret.is_err());
    assert!(init_context_ret.unwrap_err() == PubkyDataError::SnowNoiseBuildError);
}

#[tokio::test]
async fn pubky_data_snow_test_already_existent() {
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
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        false,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let first_init_context_ret = initiator_encryptor.init_context(
        initiator_key_set.clone(),
        true,
        responder_public_key.clone(),
    );
    assert!(first_init_context_ret.is_ok());
    let second_init_context_ret =
        initiator_encryptor.init_context(initiator_key_set, true, responder_public_key.clone());
    assert!(second_init_context_ret.is_err());
    assert!(second_init_context_ret.unwrap_err() == PubkyDataError::AlreadyExistentContext);
}

#[tokio::test]
async fn pubky_data_snow_test_context_not_found() {
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
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        false,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let zero_temporary_link_id = TemporaryLinkId([0; 32]);
    let zero_link_id = LinkId([0; 32]);

    let is_handshake_ret = initiator_encryptor.is_handshake(&zero_temporary_link_id);
    assert!(is_handshake_ret.is_err());
    assert!(is_handshake_ret.unwrap_err() == PubkyDataError::NoiseContextNotFound);

    let transition_transport_ret = initiator_encryptor.transition_transport(zero_temporary_link_id);
    assert!(transition_transport_ret.is_err());
    assert!(transition_transport_ret.unwrap_err() == PubkyDataError::NoiseContextNotFound);

    let context_state_ret = initiator_encryptor.get_context_status(zero_link_id.clone());
    assert!(context_state_ret.is_err());
    assert!(context_state_ret.unwrap_err() == PubkyDataError::NoiseContextNotFound);

    let close_context_ret = initiator_encryptor.close_context(&zero_link_id);
    assert!(close_context_ret.is_err());
    assert!(close_context_ret.unwrap_err() == PubkyDataError::NoiseContextNotFound);
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
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        false,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let mut responder_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
        false,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let initiator_temporary_link_id = initiator_encryptor
        .init_context(initiator_key_set, true, responder_public_key.clone())
        .unwrap();

    let responder_key_set = PubkyKeySet::new(
        Some(responder_ephemeral_keypair.secret_key()),
        Some(initiator_ephemeral_keypair.public_key()),
    );
    let responder_temporary_link_id = responder_encryptor
        .init_context(responder_key_set, false, initiator_public_key.clone())
        .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;

    assert!(!initiator_encryptor
        .is_handshake(&initiator_temporary_link_id)
        .is_ok());
    assert!(!responder_encryptor
        .is_handshake(&responder_temporary_link_id)
        .is_ok());

    let initiator_link_id = initiator_encryptor.transition_transport(initiator_temporary_link_id);
    assert!(initiator_link_id.is_ok());
    let responder_link_id = responder_encryptor.transition_transport(responder_temporary_link_id);
    assert!(responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello_World_Pubky_Data");
    let raw_bytes = data_payload.as_bytes().to_vec();

    let initiator_link_id = initiator_link_id.unwrap();
    initiator_encryptor
        .send_message(raw_bytes, initiator_link_id.clone())
        .await;

    let responder_link_id = responder_link_id.unwrap();
    let results = responder_encryptor
        .receive_message(responder_link_id.clone())
        .await;

    assert!(results.len() >= 1);
    for ret in results {
        //println!("raw bytes to check ciphering {:?}", ret);
        let padded_msg = String::from_utf8(ret.to_vec()).unwrap();
        let (msg, _) = padded_msg.split_at(data_payload.len());
        assert_eq!(msg, "Hello_World_Pubky_Data".to_string());
    }

    let initiator_ret = initiator_encryptor.close_context(&initiator_link_id);
    assert!(initiator_ret.is_ok());
    let responder_ret = responder_encryptor.close_context(&responder_link_id);
    assert!(responder_ret.is_ok());

    initiator_encryptor.clean_encryptor_stack();
    responder_encryptor.clean_encryptor_stack();
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
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "XX".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        false,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let mut responder_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        responder_keypair.secret_key(),
        0,
        "XX".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
        false,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let initiator_temporary_link_id = initiator_encryptor
        .init_context(initiator_key_set, true, responder_public_key.clone())
        .unwrap();

    let responder_key_set = PubkyKeySet::new(
        Some(responder_ephemeral_keypair.secret_key()),
        Some(initiator_ephemeral_keypair.public_key()),
    );
    let responder_temporary_link_id = responder_encryptor
        .init_context(responder_key_set, false, initiator_public_key.clone())
        .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee, s, es
    // -> s, se
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;

    assert!(!initiator_encryptor
        .is_handshake(&initiator_temporary_link_id)
        .is_ok());
    assert!(!responder_encryptor
        .is_handshake(&responder_temporary_link_id)
        .is_ok());

    let initiator_link_id = initiator_encryptor.transition_transport(initiator_temporary_link_id);
    assert!(initiator_link_id.is_ok());
    let responder_link_id = responder_encryptor.transition_transport(responder_temporary_link_id);
    assert!(responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello_World_Pubky_Data");
    let raw_bytes = data_payload.as_bytes().to_vec();
    initiator_encryptor
        .send_message(raw_bytes, initiator_link_id.unwrap())
        .await;

    let results = responder_encryptor
        .receive_message(responder_link_id.unwrap())
        .await;

    assert!(results.len() >= 1);
    for ret in results {
        //println!("raw bytes to check ciphering {:?}", ret);
        let padded_msg = String::from_utf8(ret.to_vec()).unwrap();
        let (msg, _) = padded_msg.split_at(data_payload.len());
        assert_eq!(msg, "Hello_World_Pubky_Data".to_string());
    }
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
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "XX".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        true,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let mut responder_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        responder_keypair.secret_key(),
        0,
        "XX".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
        true,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let initiator_temporary_link_id = initiator_encryptor
        .init_context(initiator_key_set, true, responder_public_key.clone())
        .unwrap();

    let responder_key_set = PubkyKeySet::new(
        Some(responder_ephemeral_keypair.secret_key()),
        Some(initiator_ephemeral_keypair.public_key()),
    );
    let responder_temporary_link_id = responder_encryptor
        .init_context(responder_key_set, false, initiator_public_key.clone())
        .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee, s, es
    // -> s, se
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;

    //TODO: fix the transition
    assert!(!initiator_encryptor
        .is_handshake(&initiator_temporary_link_id)
        .is_ok());
    assert!(!responder_encryptor
        .is_handshake(&responder_temporary_link_id)
        .is_ok());

    let initiator_link_id = initiator_encryptor.transition_transport(initiator_temporary_link_id);
    assert!(initiator_link_id.is_ok());
    let responder_link_id = responder_encryptor.transition_transport(responder_temporary_link_id);
    assert!(responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello_World_Pubky_Data");
    let raw_bytes = data_payload.as_bytes().to_vec();
    initiator_encryptor
        .send_message(raw_bytes.clone(), initiator_link_id.unwrap())
        .await;

    let results = responder_encryptor
        .receive_message(responder_link_id.unwrap())
        .await;

    assert!(results.len() >= 1);
    for ret in results {
        let padded_msg = String::from_utf8(ret.to_vec());
        assert!(padded_msg.is_err());
    }

    let last_ciphertext = initiator_encryptor.test_get_last_ciphertext();
    if last_ciphertext.is_none() {
        panic!();
    } else {
        cipher_check(raw_bytes, &last_ciphertext.unwrap());
    }
}

//#[tokio::test]
//async fn pubky_data_snow_test_encryptor_parallel() {
//	let mut testnet = EphemeralTestnet::start().await.unwrap();
//	let server = testnet.homeserver();
//	let alice_pubky = testnet.sdk().unwrap();
//	let bob_pubky = alice_pubky.clone();
//	let caroll_pubky = alice_pubky.clone();
//
//	let alice_signer = alice_pubky.signer(Keypair::random());
//	let alice_session = alice_signer.signup(&server.public_key(), None).await.unwrap();
//
//	let bob_signer = bob_pubky.signer(Keypair::random());
//	let bob_session = bob_signer.signup(&server.public_key(), None).await.unwrap();
//
//	let caroll_signer = caroll_pubky.signer(Keypair::random());
//	let caroll_session = caroll_signer.signup(&server.public_key(), None).await.unwrap();
//
//	let server_path_string = format!("/pub/data");
//
//	let alice_keypair = Keypair::random();
//	let mut alice_encryptor = PubkyDataEncryptor::init_encryptor_stack(alice_keypair.secret_key(), 0, "NN".to_string(), alice_session.clone(), server_path_string.clone(), false).unwrap();
//
//	let bob_keypair = Keypair::random();
//	let mut bob_encryptor = PubkyDataEncryptor::init_encryptor_stack(bob_keypair.secret_key(), 0, "NN".to_string(), bob_session.clone(), server_path_string.clone(), false).unwrap();
//
//	let caroll_keypair = Keypair::random();
//	let mut caroll_encryptor = PubkyDataEncryptor::init_encryptor_stack(caroll_keypair.secret_key(), 0, "NN".to_string(), caroll_session.clone(), server_path_string.clone(), false).unwrap();
//
//	let alice_ephemeral_keypair = Keypair::random();
//	let bob_ephemeral_keypair = Keypair::random();
//	let caroll_ephemeral_keypair = Keypair::random();
//
//	let alice_public_key = alice_session.info().public_key();
//	let bob_public_key = bob_session.info().public_key();
//	let caroll_public_key = caroll_session.info().public_key();
//
//	// We set up 3 data links:
//	// 	- Alice - Bob
//	// 	- Alice - Caroll
//	// 	- Bob - Caroll
//
//	// Alice - Bob
//	let ab_key_set = PubkyKeySet::new(Some(alice_ephemeral_keypair.secret_key()), Some(bob_ephemeral_keypair.public_key()));
//	let ab_temporary_link_id = alice_encryptor.init_context(ab_key_set, true, bob_public_key.clone(), alice_pubky.clone()).unwrap();
//
//	let ba_key_set = PubkyKeySet::new(Some(bob_ephemeral_keypair.secret_key()), Some(alice_ephemeral_keypair.public_key()));
//	let ba_temporary_link_id = bob_encryptor.init_context(ba_key_set, false, alice_public_key.clone(), bob_pubky.clone()).unwrap();
//
//	// Alice - Caroll
//	let ac_key_set = PubkyKeySet::new(Some(alice_ephemeral_keypair.secret_key()), Some(caroll_ephemeral_keypair.public_key()));
//	let ac_temporary_link_id = alice_encryptor.init_context(ac_key_set, true, caroll_public_key.clone(), alice_pubky.clone()).unwrap();
//
//	let ca_key_set = PubkyKeySet::new(Some(caroll_ephemeral_keypair.secret_key()), Some(alice_ephemeral_keypair.public_key()));
//	let ca_temporary_link_id = caroll_encryptor.init_context(ca_key_set, false, alice_public_key.clone(), caroll_pubky.clone()).unwrap();
//
//	// Bob - Caroll
//	let bc_key_set = PubkyKeySet::new(Some(bob_ephemeral_keypair.secret_key()), Some(caroll_ephemeral_keypair.public_key()));
//	let bc_temporary_link_id = bob_encryptor.init_context(bc_key_set, true, caroll_public_key.clone(), bob_pubky.clone()).unwrap();
//
//	let cb_key_set = PubkyKeySet::new(Some(caroll_ephemeral_keypair.secret_key()), Some(bob_ephemeral_keypair.public_key()));
//	let cb_temporary_link_id = caroll_encryptor.init_context(cb_key_set, false, bob_public_key.clone(), caroll_pubky.clone()).unwrap();
//}

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
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "XX".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        false,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let mut responder_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        responder_keypair.secret_key(),
        0,
        "XX".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
        false,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let initiator_temporary_link_id = initiator_encryptor
        .init_context(initiator_key_set, true, responder_public_key.clone())
        .unwrap();

    let responder_key_set = PubkyKeySet::new(
        Some(responder_ephemeral_keypair.secret_key()),
        Some(initiator_ephemeral_keypair.public_key()),
    );
    let responder_temporary_link_id = responder_encryptor
        .init_context(responder_key_set, false, initiator_public_key.clone())
        .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee, s, es
    // -> s, se
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;

    assert!(!initiator_encryptor
        .is_handshake(&initiator_temporary_link_id)
        .is_ok());
    assert!(!responder_encryptor
        .is_handshake(&responder_temporary_link_id)
        .is_ok());

    let initiator_link_id = initiator_encryptor.transition_transport(initiator_temporary_link_id);
    assert!(initiator_link_id.is_ok());
    let responder_link_id = responder_encryptor.transition_transport(responder_temporary_link_id);
    assert!(responder_link_id.is_ok());

    // Transport
    let data_payload = String::from("Hello_World_Pubky_Data");
    let raw_bytes = data_payload.as_bytes().to_vec();

    let initiator_link_id = initiator_link_id.unwrap();
    initiator_encryptor
        .send_message(raw_bytes, initiator_link_id.clone())
        .await;

    let results = responder_encryptor
        .receive_message(responder_link_id.unwrap())
        .await;

    assert!(results.len() >= 1);
    for ret in results {
        //println!("raw bytes to check ciphering {:?}", ret);
        let padded_msg = String::from_utf8(ret.to_vec()).unwrap();
        let (msg, _) = padded_msg.split_at(data_payload.len());
        assert_eq!(msg, "Hello_World_Pubky_Data".to_string());
    }

    initiator_encryptor.generate_context_backup(initiator_link_id, false);
    initiator_encryptor.load_context_backup(vec![]);
}

#[tokio::test]
async fn pubky_data_snow_test_context_status() {
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
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "XX".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        false,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    let mut responder_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        responder_keypair.secret_key(),
        0,
        "XX".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
        false,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let initiator_temporary_link_id = initiator_encryptor
        .init_context(initiator_key_set, true, responder_public_key.clone())
        .unwrap();

    let responder_key_set = PubkyKeySet::new(
        Some(responder_ephemeral_keypair.secret_key()),
        Some(initiator_ephemeral_keypair.public_key()),
    );
    let responder_temporary_link_id = responder_encryptor
        .init_context(responder_key_set, false, initiator_public_key.clone())
        .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee, s, es
    // -> s, se
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;

    assert!(!initiator_encryptor
        .is_handshake(&initiator_temporary_link_id)
        .is_ok());
    assert!(!responder_encryptor
        .is_handshake(&responder_temporary_link_id)
        .is_ok());

    let initiator_link_id = initiator_encryptor.transition_transport(initiator_temporary_link_id);
    assert!(initiator_link_id.is_ok());
    let responder_link_id = responder_encryptor.transition_transport(responder_temporary_link_id);
    assert!(responder_link_id.is_ok());

    let context_status_ret = initiator_encryptor.get_context_status(initiator_link_id.unwrap());
}

#[tokio::test]
async fn pubky_data_snow_test_dual_outbox() {
    let testnet = EphemeralTestnet::builder().build().await.unwrap();
    let first_server = testnet.homeserver_app();
    //let second_server = testnet.second_homeserver();
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
    //TODO: change initiator_pubky to a client reading the responder's outbox
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        false,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    //TODO: change initator_pubky to a client reading the initiator's outbox
    let mut responder_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
        false,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let initiator_temporary_link_id = initiator_encryptor
        .init_context(initiator_key_set, true, responder_public_key.clone())
        .unwrap();

    let responder_key_set = PubkyKeySet::new(
        Some(responder_ephemeral_keypair.secret_key()),
        Some(initiator_ephemeral_keypair.public_key()),
    );
    let responder_temporary_link_id = responder_encryptor
        .init_context(responder_key_set, false, initiator_public_key.clone())
        .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee, s, es
    // -> s, se
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;

    assert!(!initiator_encryptor
        .is_handshake(&initiator_temporary_link_id)
        .is_ok());
    assert!(!responder_encryptor
        .is_handshake(&responder_temporary_link_id)
        .is_ok());

    let initiator_link_id = initiator_encryptor.transition_transport(initiator_temporary_link_id);
    assert!(initiator_link_id.is_ok());
    let responder_link_id = responder_encryptor.transition_transport(responder_temporary_link_id);
    assert!(responder_link_id.is_ok());

    //TODO: Alice can write only to her own Homeserver but can read from own
    // and Bob's Homeserver.
    //    => corollary: Bob can write only to his own Homeserver but can read from
    // own and Bob's Homeserver
    //
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
    //TODO: change initiator_pubky to a client reading the responder's outbox
    let mut initiator_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        initiator_keypair.secret_key(),
        0,
        "NN".to_string(),
        initiator_session.clone(),
        server_path_string.clone(),
        initiator_pubky,
        false,
    )
    .unwrap();

    let responder_keypair = Keypair::random();
    //TODO: change initator_pubky to a client reading the initiator's outbox
    let mut responder_encryptor = PubkyDataEncryptor::init_encryptor_stack(
        responder_keypair.secret_key(),
        0,
        "NN".to_string(),
        responder_session.clone(),
        server_path_string.clone(),
        responder_pubky,
        false,
    )
    .unwrap();

    let initiator_ephemeral_keypair = Keypair::random();
    let responder_ephemeral_keypair = Keypair::random();

    let initiator_public_key = initiator_session.info().public_key();
    let responder_public_key = responder_session.info().public_key();

    let initiator_key_set = PubkyKeySet::new(
        Some(initiator_ephemeral_keypair.secret_key()),
        Some(responder_ephemeral_keypair.public_key()),
    );
    let initiator_temporary_link_id = initiator_encryptor
        .init_context(initiator_key_set, true, responder_public_key.clone())
        .unwrap();

    let responder_key_set = PubkyKeySet::new(
        Some(responder_ephemeral_keypair.secret_key()),
        Some(initiator_ephemeral_keypair.public_key()),
    );
    let responder_temporary_link_id = responder_encryptor
        .init_context(responder_key_set, false, initiator_public_key.clone())
        .unwrap();

    // Initiator sends handshake
    // -> e
    // <- e, ee, s, es
    // -> s, se
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;
    initiator_encryptor
        .handle_handshake(
            true,
            initiator_temporary_link_id,
            responder_public_key.clone(),
        )
        .await;
    responder_encryptor
        .handle_handshake(
            false,
            responder_temporary_link_id,
            initiator_public_key.clone(),
        )
        .await;

    assert!(!initiator_encryptor
        .is_handshake(&initiator_temporary_link_id)
        .is_ok());
    assert!(!responder_encryptor
        .is_handshake(&responder_temporary_link_id)
        .is_ok());

    let initiator_link_id = initiator_encryptor.transition_transport(initiator_temporary_link_id);
    assert!(initiator_link_id.is_ok());
    let responder_link_id = responder_encryptor.transition_transport(responder_temporary_link_id);
    assert!(responder_link_id.is_ok());

    //TODO: initiator receive_message -> identity binding
    //TODO: responder receive_message -> identity binding
}

#[tokio::test]
async fn pubky_data_snow_test_identifers() {

    //TODO: test no collision between session id, context id and peer fingerprint (3 elements)
}
