use super::*;
use pubky_noise::RequestPolicy;
use pubky_testnet::pubky_homeserver::{AppContext, ConfigToml, HomeserverApp, MockDataDir};
use std::{net::SocketAddr, num::NonZeroU8, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinSet,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Hold {
    None,
    Request,
    Response,
}

struct FaultServer {
    server: HomeserverApp,
    http: SocketAddr,
    hold: watch::Sender<Hold>,
    _tasks: JoinSet<()>,
}

async fn copy_gated(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    mut hold: watch::Receiver<Hold>,
    direction: Hold,
) -> std::io::Result<()> {
    let mut buffer = [0; 8192];
    loop {
        let length = reader.read(&mut buffer).await?;
        if length == 0 {
            return writer.shutdown().await;
        }
        while *hold.borrow_and_update() == direction {
            if hold.changed().await.is_err() {
                return Ok(());
            }
        }
        writer.write_all(&buffer[..length]).await?;
    }
}

async fn proxy(listener: TcpListener, upstream: SocketAddr, hold: watch::Receiver<Hold>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (incoming, _) = accepted.unwrap();
                let hold = hold.clone();
                connections.spawn(async move {
                    let Ok(outgoing) = TcpStream::connect(upstream).await else { return };
                    let (request, response) = incoming.into_split();
                    let (upstream_response, upstream_request) = outgoing.into_split();
                    let _ = tokio::try_join!(
                        copy_gated(request, upstream_request, hold.clone(), Hold::Request),
                        copy_gated(upstream_response, response, hold, Hold::Response),
                    );
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

impl FaultServer {
    async fn start(testnet: &EphemeralTestnet) -> Self {
        let http = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tls = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let http_address = http.local_addr().unwrap();
        let tls_address = tls.local_addr().unwrap();
        let http_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = ConfigToml::minimal_test_config();
        config.drive.icann_listen_socket = http_address;
        config.drive.pubky_listen_socket = tls_address;
        config.pkdns.public_icann_http_port = Some(http_proxy.local_addr().unwrap().port());
        config.pkdns.public_pubky_tls_port = Some(tls_proxy.local_addr().unwrap().port());
        config.pkdns.dht_bootstrap_nodes = Some(testnet.testnet.dht_bootstrap_nodes());
        let context = AppContext::read_from(MockDataDir::new(config, None).unwrap())
            .await
            .unwrap();
        let (hold, receiver) = watch::channel(Hold::None);
        let mut tasks = JoinSet::new();
        tasks.spawn(proxy(http_proxy, http_address, receiver.clone()));
        tasks.spawn(proxy(tls_proxy, tls_address, receiver));
        drop((http, tls));
        let server = HomeserverApp::start(context).await.unwrap();
        Self {
            server,
            http: http_address,
            hold,
            _tasks: tasks,
        }
    }

    async fn packet(&self, user: &PublicKey, path: &str) -> Option<Vec<u8>> {
        let response = reqwest::Client::new()
            .get(format!(
                "http://{}/storage/{}{}",
                self.http,
                user.z32(),
                path
            ))
            .header("pubky-host", self.server.public_key().z32())
            .send()
            .await
            .unwrap();
        match response.status().as_u16() {
            200 => Some(response.bytes().await.unwrap().to_vec()),
            404 => None,
            status => panic!(
                "unexpected direct read status {status}: {}",
                response.text().await.unwrap()
            ),
        }
    }

    async fn wait_for_packet(&self, user: &PublicKey, path: &str) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(packet) = self.packet(user, path).await {
                    return packet;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("write never reached the homeserver")
    }
}

fn short_policy() -> RequestPolicy {
    RequestPolicy {
        timeout: Duration::from_millis(500),
        max_attempts: NonZeroU8::new(1).unwrap(),
        ..Default::default()
    }
}

#[tokio::test]
async fn cancelled_handshake_retries_the_accepted_packet() {
    let testnet = build_testnet().await;
    let server = FaultServer::start(&testnet).await;
    for pattern in ["NN", "XX"] {
        let mut pair = setup_encryptors_with_policy(
            testnet.sdk().unwrap(),
            server.server.public_key(),
            pattern,
            short_policy(),
        )
        .await;
        pair.initiator_config
            .local_session
            .storage()
            .put("/pub/warmup", Vec::<u8>::new())
            .await
            .unwrap();
        let before = pair.initiator.snapshot().unwrap().serialize();
        server.hold.send(Hold::Response).unwrap();
        let packet = {
            let operation = pair.initiator.handle_handshake();
            tokio::pin!(operation);
            tokio::select! {
                result = &mut operation => panic!("write unexpectedly completed: {result:?}"),
                packet = server.wait_for_packet(&pair.initiator_public_key, "/pub/data/0") => packet,
            }
        };
        assert_eq!(
            pair.initiator.snapshot().unwrap_err(),
            PubkyNoiseError::HandshakeRecoveryRequired
        );
        assert_eq!(
            pair.initiator.transition_transport().unwrap_err(),
            PubkyNoiseError::HandshakeRecoveryRequired
        );
        assert_eq!(
            pair.initiator.last_good_snapshot().unwrap().serialize(),
            before
        );
        server.hold.send(Hold::None).unwrap();
        pair.initiator.handle_handshake().await.unwrap();
        assert_eq!(
            server
                .packet(&pair.initiator_public_key, "/pub/data/0")
                .await
                .unwrap(),
            packet
        );
        pair.responder.handle_handshake().await.unwrap();
        pair.initiator.handle_handshake().await.unwrap();
        if pattern == "XX" {
            pair.responder.handle_handshake().await.unwrap();
        }
        assert_eq!(
            pair.initiator.transition_transport().unwrap(),
            pair.responder.transition_transport().unwrap()
        );
        send_and_verify(
            &mut pair.initiator,
            &mut pair.responder,
            "after cancellation",
        )
        .await;
    }
}

#[tokio::test]
async fn final_xx_write_timeout_cannot_promote_or_replace_checkpoint() {
    let testnet = build_testnet().await;
    let server = FaultServer::start(&testnet).await;
    let mut pair = setup_encryptors_with_policy(
        testnet.sdk().unwrap(),
        server.server.public_key(),
        "XX",
        short_policy(),
    )
    .await;
    pair.initiator.handle_handshake().await.unwrap();
    pair.responder.handle_handshake().await.unwrap();
    // Derive the expected packet independently from the same checkpoint.
    let before = pair.initiator.snapshot().unwrap();
    let peer_packet = server
        .packet(&pair.responder_public_key, "/pub/data/1")
        .await
        .unwrap();
    let prepared = PubkyNoiseEncryptor::restore(
        pair.initiator_config.clone(),
        before.clone(),
        pair.responder_public_key.clone(),
    )
    .await
    .unwrap()
    .prepare_handshake_step(Some(&peer_packet))
    .unwrap();
    let expected = prepared.packet().unwrap();
    pair.initiator.test_enable_write_failure();
    assert_eq!(
        pair.initiator.handle_handshake().await.unwrap_err(),
        PubkyNoiseError::HomeserverWriteError
    );
    pair.initiator.test_disable_write_failure();
    let pre_write = pair.initiator.last_good_snapshot().unwrap().clone();
    assert_eq!(pre_write.counter, 2);
    assert_eq!(pre_write.handshake_messages.len(), 1);
    server.hold.send(Hold::Response).unwrap();
    assert_eq!(
        pair.initiator.handle_handshake().await.unwrap_err(),
        PubkyNoiseError::HomeserverWriteError
    );
    let stored = server
        .packet(&pair.initiator_public_key, "/pub/data/2")
        .await
        .unwrap();
    assert_eq!(stored, expected);
    assert!(!pair.initiator.is_handshake_complete());
    assert_eq!(
        pair.initiator.last_good_snapshot().unwrap().serialize(),
        pre_write.serialize()
    );
    assert_eq!(
        pair.initiator.snapshot().unwrap_err(),
        PubkyNoiseError::HandshakeRecoveryRequired
    );
    assert_eq!(
        pair.initiator.transition_transport().unwrap_err(),
        PubkyNoiseError::HandshakeRecoveryRequired
    );
    server.hold.send(Hold::None).unwrap();
    // A changed peer file must not change the uncertain outgoing packet.
    pair.responder_config
        .local_session
        .storage()
        .put("/pub/data/1", vec![0; 16])
        .await
        .unwrap();
    pair.initiator = PubkyNoiseEncryptor::restore(
        pair.initiator_config.clone(),
        pre_write,
        pair.responder_public_key.clone(),
    )
    .await
    .unwrap();
    pair.initiator.handle_handshake().await.unwrap();
    assert_eq!(
        server
            .packet(&pair.initiator_public_key, "/pub/data/2")
            .await
            .unwrap(),
        stored
    );
    pair.responder.handle_handshake().await.unwrap();
    assert_eq!(
        pair.initiator.transition_transport().unwrap(),
        pair.responder.transition_transport().unwrap()
    );
    send_and_verify(
        &mut pair.responder,
        &mut pair.initiator,
        "final packet acknowledged",
    )
    .await;
}

#[tokio::test]
async fn closing_a_timed_out_handshake_prevents_later_publication() {
    let testnet = build_testnet().await;
    let server = FaultServer::start(&testnet).await;
    let mut pair = setup_encryptors_with_policy(
        testnet.sdk().unwrap(),
        server.server.public_key(),
        "NN",
        short_policy(),
    )
    .await;
    server.hold.send(Hold::Request).unwrap();
    assert_eq!(
        pair.initiator.handle_handshake().await.unwrap_err(),
        PubkyNoiseError::HomeserverWriteError
    );
    assert!(server
        .packet(&pair.initiator_public_key, "/pub/data/0")
        .await
        .is_none());
    pair.initiator.close();
    // Keep the original blocked network request held. Closing cannot retract an
    // already admitted request; this assertion concerns a new retry after close.
    assert_eq!(
        pair.initiator.handle_handshake().await.unwrap_err(),
        PubkyNoiseError::HandshakeRecoveryRequired
    );
}

#[tokio::test]
async fn cancelled_transport_send_keeps_the_exact_pending_ciphertext() {
    let testnet = build_testnet().await;
    let server = FaultServer::start(&testnet).await;
    let mut pair = setup_encryptors_with_policy(
        testnet.sdk().unwrap(),
        server.server.public_key(),
        "NN",
        short_policy(),
    )
    .await;
    complete_nn_handshake(&mut pair).await;
    let before = pair.initiator.snapshot().unwrap();
    let path = format!("/pub/data/{}", before.write_counter);
    server.hold.send(Hold::Response).unwrap();
    let stored = {
        let operation = pair.initiator.send_message(b"exact retry");
        tokio::pin!(operation);
        tokio::select! {
            result = &mut operation => panic!("write unexpectedly completed: {result:?}"),
            packet = server.wait_for_packet(&pair.initiator_public_key, &path) => packet,
        }
    };
    assert_eq!(
        pair.initiator.snapshot().unwrap_err(),
        PubkyNoiseError::UnacknowledgedPreparedTransport
    );
    assert_eq!(
        pair.initiator
            .send_message(b"replacement")
            .await
            .unwrap_err(),
        PubkyNoiseError::UnacknowledgedPreparedTransport
    );
    assert_eq!(
        pair.initiator.retry_pending_send().await.unwrap_err(),
        PubkyNoiseError::HomeserverWriteError
    );
    server.hold.send(Hold::None).unwrap();
    pair.initiator.retry_pending_send().await.unwrap();
    assert_eq!(
        server
            .packet(&pair.initiator_public_key, &path)
            .await
            .unwrap(),
        stored
    );
    assert_eq!(
        pair.responder.receive_message().await.unwrap(),
        vec![b"exact retry".to_vec()]
    );
    assert!(pair.responder.receive_message().await.unwrap().is_empty());
    let after = pair.initiator.snapshot().unwrap();
    assert_eq!(after.sending_nonce, before.sending_nonce + 1);
    send_and_verify(&mut pair.initiator, &mut pair.responder, "next slot").await;
}

#[tokio::test]
async fn timed_out_receive_does_not_advance_the_inbox() {
    let testnet = build_testnet().await;
    let server = FaultServer::start(&testnet).await;
    let mut pair = setup_encryptors_with_policy(
        testnet.sdk().unwrap(),
        server.server.public_key(),
        "NN",
        short_policy(),
    )
    .await;
    complete_nn_handshake(&mut pair).await;
    pair.initiator.send_message(b"unconsumed").await.unwrap();
    let before = pair.responder.snapshot().unwrap().serialize();
    server.hold.send(Hold::Response).unwrap();
    assert_eq!(
        pair.responder.receive_message().await.unwrap_err(),
        PubkyNoiseError::HomeserverResponseError
    );
    assert_eq!(pair.responder.snapshot().unwrap().serialize(), before);
    server.hold.send(Hold::None).unwrap();
    assert_eq!(
        pair.responder.receive_message().await.unwrap(),
        vec![b"unconsumed".to_vec()]
    );
    assert!(pair.responder.receive_message().await.unwrap().is_empty());
}

#[tokio::test]
async fn backup_timeout_preserves_generation_and_authentication_checks() {
    let testnet = build_testnet().await;
    let server = FaultServer::start(&testnet).await;
    let mut pair = setup_encryptors_with_policy(
        testnet.sdk().unwrap(),
        server.server.public_key(),
        "NN",
        short_policy(),
    )
    .await;
    complete_nn_handshake(&mut pair).await;
    let before = pair.initiator.snapshot().unwrap().serialize();
    let backup_key = [91; 32];
    server.hold.send(Hold::Response).unwrap();
    assert_eq!(
        pair.initiator
            .persist_snapshot(&backup_key, 7)
            .await
            .unwrap_err(),
        PubkyNoiseError::HomeserverResponseError
    );
    assert!(server
        .packet(&pair.initiator_public_key, "/pub/data/backup")
        .await
        .is_some());
    assert_eq!(
        PubkyNoiseEncryptor::load_snapshot(&pair.initiator_config, &backup_key, Some(7))
            .await
            .unwrap_err(),
        PubkyNoiseError::HomeserverResponseError
    );
    assert_eq!(pair.initiator.snapshot().unwrap().serialize(), before);
    server.hold.send(Hold::None).unwrap();
    let loaded = PubkyNoiseEncryptor::load_snapshot(&pair.initiator_config, &backup_key, Some(7))
        .await
        .unwrap();
    assert_eq!(loaded.generation, 7);
    assert_eq!(loaded.state.serialize(), before);
    assert_eq!(
        PubkyNoiseEncryptor::load_snapshot(&pair.initiator_config, &backup_key, Some(8))
            .await
            .unwrap_err(),
        PubkyNoiseError::RestoreBackupRollbackError
    );
    assert_eq!(
        PubkyNoiseEncryptor::load_snapshot(&pair.initiator_config, &[92; 32], Some(7))
            .await
            .unwrap_err(),
        PubkyNoiseError::RestoreBackupDecryptError
    );
}
