use pubky_testnet::{pubky::Keypair, EphemeralTestnet};

#[tokio::test]
async fn pubky_data_mobile_manager_dual_outbox_simple_test() {
    let testnet = EphemeralTestnet::builder()
        .with_embedded_postgres()
        .build()
        .await
        .unwrap();
    let server = testnet.homeserver_app();
    let alice_pubky = testnet.sdk().unwrap();

    let bob_pubky = testnet.sdk().unwrap();

    let alice_signer = alice_pubky.signer(Keypair::random());
    let alice_session = alice_signer
        .signup(&server.public_key(), None)
        .await
        .unwrap();

    let bob_signer = bob_pubky.signer(Keypair::random());
    let bob_session = bob_signer.signup(&server.public_key(), None).await.unwrap();

    //let mobile_config = MobileConfig::default();
    //let pubky_root_seckey = [0; 32];
    //let alice_noise_manager = NoiseManager::new(mobile_config, pubky_root_seckey, alice_session).unwrap();

    //let mobile_config = MobileConfig::default();
    //let pubky_root_seckey = [0; 32];
    //let bob_noise_manager = NoiseManager::new(mobile_config, pubky_root_seckey, bob_session).unwrap();

    // We assumke the peer static pubkey and its homeserver outbox pubkey is known

    //let alice_conversation_id = alice_noise_manager.open_link();
    //assert!(alice_conversation_id.is_ok());
    //let bob_conversation_id = bob_noise_manager.accept_link();
    //assert!(bob_conversation_id.is_ok());

    //let mut data_payload = String::from("Hello World Pubky Data");
    //let raw_bytes = data_payload.as_bytes().to_vec();

    //alice_noise_manager.encrypt(&alice_conversation_id.unwrap(), raw_bytes);
    //let plaintext_raw_bytes = bob_noise_manager.decrypt(&bob_conversation_id.unwrap());
    //assert_eq!(plaintext_raw_bytes, "Hello World Pubky Data".to_string());
}
