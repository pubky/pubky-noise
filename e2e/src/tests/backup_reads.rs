//! Controlled HTTP peers verify backup reads without relying on EOF or HEAD.
#![allow(deprecated)] // Exercise the public cookie credential constructor.

use pkarr::{dns::rdata::SVCB, Cache, InMemoryCache, SignedPacket};
use pubky_noise::{PubkyNoiseConfig, PubkyNoiseEncryptor, PubkyNoiseError};
use pubky_testnet::{
    pubky::{
        AuthToken, Capabilities, CookieCredential, Keypair, Pubky, PubkyHttpClient, PubkySession,
    },
    pubky_common::session::CookieSessionRecord,
};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn fixture(
    response: Vec<u8>,
) -> (
    Arc<PubkyNoiseConfig>,
    tokio::task::JoinHandle<tokio_rustls::server::TlsStream<TcpStream>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let user = Keypair::random();
    let server = Keypair::random();
    let cache = Arc::new(InMemoryCache::new(NonZeroUsize::new(4).unwrap()));
    let mut endpoint = SVCB::new(1, ".".try_into().unwrap());
    endpoint.set_port(port);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server.to_rpk_rustls_server_config()));
    let packet = SignedPacket::builder()
        .https(".".try_into().unwrap(), endpoint, 3600)
        .address(".".try_into().unwrap(), "127.0.0.1".parse().unwrap(), 3600)
        .sign(&server)
        .unwrap();
    cache.put(&server.public_key().as_inner().into(), &packet);
    let server_name = server.public_key().z32();
    let alias = SVCB::new(0, server_name.as_str().try_into().unwrap());
    let packet = SignedPacket::builder()
        .https("_pubky".try_into().unwrap(), alias, 3600)
        .sign(&user)
        .unwrap();
    cache.put(&user.public_key().as_inner().into(), &packet);
    let client = PubkyHttpClient::builder()
        .pkarr(|b| {
            b.no_default_network()
                .bootstrap(&["127.0.0.1:1"])
                .cache(cache)
        })
        .build()
        .unwrap();
    let caps = Capabilities::builder().read_write("/").unwrap().finish();
    let record = CookieSessionRecord::new(&user.public_key(), caps.clone(), None).serialize();
    let cookie = format!("{}=test-secret", user.public_key().z32());
    let task = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(socket.read_u8().await.unwrap());
                assert!(headers.len() < 16384);
            }
            let headers = String::from_utf8(headers).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(|value| value.parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            let mut body = vec![0; length];
            socket.read_exact(&mut body).await.unwrap();
            let request = headers.lines().next().unwrap();
            if request.contains("/backup ") {
                assert!(
                    request.starts_with("GET "),
                    "backup must use a single GET: {request}"
                );
                assert!(
                    headers.contains("test-secret"),
                    "backup GET is authenticated"
                );
                socket.write_all(&response).await.unwrap();
                return socket; // Keep EOF withheld in the task result.
            }
            let (body, extra) = if request.contains("/session ") {
                (record.clone(), format!("Set-Cookie: {cookie}\r\n"))
            } else {
                assert!(request.contains("/info "), "unexpected request: {request}");
                (
                    br#"{"features":["path-addressed-storage"]}"#.to_vec(),
                    String::new(),
                )
            };
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n{extra}\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            socket.write_all(&body).await.unwrap();
        }
    });
    let token = AuthToken::sign(&user, caps);
    let credential = CookieCredential::from_auth_token(&token, &client, Some(server.public_key()))
        .await
        .unwrap();
    let session = PubkySession::from_cookie_credential(client.clone(), credential);
    let config = PubkyNoiseConfig::new(
        user.secret(),
        1,
        "XX",
        session,
        "/pub/data".into(),
        Pubky::with_client(client),
    )
    .unwrap();
    (config, task)
}

#[tokio::test]
async fn backup_error_statuses_do_not_wait_for_bodies() {
    for (status, expected) in [
        (404, PubkyNoiseError::RestoreBackupNotFoundError),
        (410, PubkyNoiseError::RestoreBackupNotFoundError),
        (500, PubkyNoiseError::HomeserverResponseError),
    ] {
        for payload in ["".to_owned(), "x".repeat(8192)] {
            // Withheld or oversized body despite the huge declared length: even bounded checked
            // error handling would wait, so this specifically verifies raw GET use.
            let (config, peer) = fixture(
                format!("HTTP/1.1 {status} Test\r\nContent-Length: 1000000000\r\n\r\n{payload}")
                    .into_bytes(),
            )
            .await;
            let error = tokio::time::timeout(
                Duration::from_secs(5),
                PubkyNoiseEncryptor::load_snapshot(&config, &[0; 32], None),
            )
            .await
            .expect("error body must be discarded")
            .unwrap_err();
            assert_eq!(error, expected);
            drop(peer.await.unwrap());
        }
    }
}

#[tokio::test]
async fn backup_success_overflow_stops_without_eof() {
    for chunks in [
        format!("1001\r\n{}\r\n", "x".repeat(4097)),
        format!("1000\r\n{}\r\n1\r\ny\r\n", "x".repeat(4096)),
    ] {
        let (config, peer) = fixture(
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{chunks}").into_bytes(),
        )
        .await;
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            PubkyNoiseEncryptor::load_snapshot(&config, &[0; 32], None),
        )
        .await
        .expect("overflow must not wait for EOF")
        .unwrap_err();
        assert_eq!(error, PubkyNoiseError::HomeserverResponseError);
        drop(peer.await.unwrap());
    }
}

#[tokio::test]
async fn backup_body_transport_failure_preserves_error_mapping() {
    let (config, peer) =
        fixture(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort".to_vec()).await;
    let read = PubkyNoiseEncryptor::load_snapshot(&config, &[0; 32], None);
    let close = async {
        drop(peer.await.unwrap());
    };
    let (result, ()) = tokio::join!(read, close);
    assert_eq!(
        result.unwrap_err(),
        PubkyNoiseError::HomeserverResponseError
    );
}
