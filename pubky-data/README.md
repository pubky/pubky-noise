# Pubky Data

A fully-integrated Noise protocol framework for encrypted peer-to-peer messaging over Pubky homeservers.

Peers use their homeservers as outboxes: each party writes encrypted Noise messages to their own homeserver, and reads from the remote peer's homeserver. The library wraps the [Snow](https://github.com/mcginty/snow) Noise implementation in a clean async interface with built-in session backup and restore.

## Install

```toml
# Cargo.toml
[dependencies]
pubky-data = "0.0.1"
```

### Actual dependencies (for reference)

| Crate | Version | Purpose |
|---|---|---|
| `pubky` | 0.7.0 | Pubky SDK (homeserver client, sessions, keys) |
| `snow` | 0.10.0 | Noise protocol implementation |
| `ed25519-dalek` | 3.0.0-pre.5 | Ed25519 signatures and key conversions |
| `curve25519-dalek` | 5.0.0-pre.5 | X25519 Diffie-Hellman for path derivation |
| `sha2` | 0.11.0-rc.4 | SHA-256 hashing (path derivation, Noise suite) |
| `getrandom` | 0.3 | Cryptographic RNG |
| `hex` | 0.4 | Hex encoding for derived paths |
| `rand` | 0.9.0 | Random key generation |

## Quick Start

```rust,no_run
use std::sync::Arc;
use pubky::prelude::*;
use pubky_data::{PubkyDataConfig, PubkyDataEncryptor, HandshakeResult};

// 1. Create shared configuration
//    (requires an authenticated PubkySession and a Pubky HTTP client)
let config = PubkyDataConfig::new(
    root_secret_key,          // [u8; 32] - root Ed25519 secret key
    0,                        // protocol version
    "XX",                     // Noise handshake pattern
    homeserver_session,       // authenticated PubkySession
    "/pub/data".to_string(),  // storage path prefix
    pubky_client,             // Pubky HTTP client
).unwrap();

// 2. Create encryptors for each side
let mut initiator = PubkyDataEncryptor::new(
    config.clone(),
    ephemeral_secret_key,     // [u8; 32] - per-session key
    true,                     // initiator = true
    responder_public_key,     // remote peer's PublicKey
).unwrap();

// 3. Run the handshake (polling-safe, call repeatedly)
loop {
    match initiator.handle_handshake().await.unwrap() {
        HandshakeResult::Pending => { /* poll again later */ },
        HandshakeResult::Terminal => break,
    }
}

// 4. Transition to transport phase
let link_id = initiator.transition_transport().unwrap();

// 5. Send and receive encrypted messages
initiator.send_message(b"Hello, peer!").await;
let messages = initiator.receive_message().await;

// 6. Clean up
initiator.close();
```

## Architecture

### Outbox Model

Each peer writes to their **own** homeserver and reads from the **remote** peer's homeserver:

```text
Alice's Homeserver          Bob's Homeserver
  /pub/data/0  <-- Alice writes    /pub/data/1  <-- Bob writes
  /pub/data/2  <-- Alice writes    Bob reads from Alice's homeserver
  Alice reads from Bob's homeserver
```

Messages are stored at incrementing slot indices (`/path/{counter}`). The counter advances after each successful read or write.

### Wire Format

Messages use a length-prefixed packet format:

```text
[len_hi, len_lo, payload...]
```

- `len`: big-endian u16 indicating payload length
- `payload`: up to 1000 bytes (`PUBKY_DATA_MSG_LEN`)
- Total packet size: 1002 bytes

### Crypto Primitives

The Noise protocol name is:

```text
Noise_{pattern}_25519_ChaChaPoly_SHA256
```

| Primitive | Algorithm | Purpose |
|---|---|---|
| Key exchange | X25519 | Diffie-Hellman |
| Stream cipher | ChaCha20-Poly1305 | Authenticated encryption |
| Hash | SHA-256 | Handshake transcript hashing |
| Transport mode | Stateless | Explicit nonce per message |

## Mental Model

### Core Types

- **`PubkyDataConfig`** -- Shared configuration and resources for multiple sessions. Holds the HTTP client, authenticated homeserver session, read/write paths, root keypair, and default Noise pattern. Wrap in `Arc` and share across encryptors.

- **`PubkyDataEncryptor`** -- A single-session Noise encryptor. Each instance manages exactly one Noise session (handshake + transport) with a single remote peer. Create multiple instances sharing the same `Arc<PubkyDataConfig>` for concurrent sessions.

- **`LinkId`** -- A 32-byte identifier derived from the Noise handshake transcript hash. Changes after every handshake when ephemeral keys are used. Available after calling `transition_transport()`.

- **`PubkyDataSessionState`** -- Serializable snapshot of a session (189 bytes). Contains everything needed to restore a session by replaying persisted handshake messages through a fresh Noise state.

- **`DataLinkContext`** -- Internal Noise state machine managing the handshake and transport phases. Not used directly by consumers.

### Lifecycle

```text
new() --> handle_handshake() [loop] --> transition_transport() --> send/receive --> close()
                                              |
                                         snapshot() --> persist_snapshot()
                                              |
                                         restore() [on crash recovery]
```

## Noise Handshake Patterns

| Pattern | Status | Auth | Description |
|---|---|---|---|
| `NN` | Implemented | None | No authentication, anonymous ephemeral keys |
| `XX` | Implemented | Mutual | Mutual authentication, both sides reveal static keys |
| `N` | Declared | One-way | Sender authenticates to known recipient |
| `IK` | Declared | Mutual | Initiator knows responder's static key upfront |
| `NK` | Declared | One-way | Initiator authenticates to known responder |

Patterns marked "Declared" are defined in the enum but will panic if used (not yet implemented).

### Handshake Flow (XX Pattern)

```text
Initiator                          Responder
    |                                  |
    |-- Step 1: -> e ----------------->|
    |                                  |
    |<-- Step 2: <- e, ee, s, es ------|
    |                                  |
    |-- Step 3: -> s, se ------------>|
    |                                  |
    [transition_transport()]    [transition_transport()]
    |                                  |
    |<======= encrypted transport ====>|
```

### Polling-Safe Handshake

`handle_handshake()` is designed for polling: it can be called repeatedly by either side in any order. If the peer's message is not yet available, it returns `HandshakeResult::Pending` without advancing state. This makes it safe for use in event loops and async contexts.

## Asymmetric Path Derivation

For per-peer-pair path privacy, use `derive_asymmetric_paths()` to compute distinct write/read paths from a DH shared secret:

```rust,ignore
use pubky_data::path_derivation::derive_asymmetric_paths;

let (write_path, read_path) = derive_asymmetric_paths(
    &my_secret_key,
    &their_pubkey,
    b"paykit-path-v0",                // domain separation
    "/pub/paykit.app/v0/private",     // base path
);
// write_path = "/pub/paykit.app/v0/private/a1b2c3d4...64 hex chars"
// read_path  = "/pub/paykit.app/v0/private/e5f6a7b8...64 hex chars"
```

**Correctness guarantee**: For parties Alice and Bob:
- `derive(alice_sk, bob_pk, ...).write_path == derive(bob_sk, alice_pk, ...).read_path`
- `derive(alice_sk, bob_pk, ...).read_path == derive(bob_sk, alice_pk, ...).write_path`

This holds because `X25519(a, B) == X25519(b, A)` (DH commutativity).

**Derivation formula**:
```text
dh_secret   = X25519(to_scalar_bytes(ed25519_seed), to_montgomery(remote_ed25519_pk))
write_path  = "{base_path}/{hex(SHA-256(domain || dh_secret || local_ed25519_pk))}"
read_path   = "{base_path}/{hex(SHA-256(domain || dh_secret || remote_ed25519_pk))}"
```

Use `PubkyDataConfig::new_with_paths()` to supply separate write/read paths.

## Session Backup & Restore

Sessions can be snapshotted, serialized, and restored to recover from crashes or write failures.

### Snapshot Format

`PubkyDataSessionState` serializes to a compact 189-byte binary format:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version |
| 1 | 1 | phase (0=Handshake, 1=Transport) |
| 2 | 1 | pattern |
| 3 | 1 | initiator flag |
| 4-35 | 32 | ephemeral secret key |
| 36 | 1 | has static secret flag |
| 37-68 | 32 | static secret key |
| 69-72 | 4 | counter (u32 big-endian) |
| 73 | 1 | noise step |
| 74 | 1 | sub-step index |
| 75 | 1 | has handshake hash flag |
| 76-107 | 32 | handshake hash |
| 108 | 1 | has link ID flag |
| 109-140 | 32 | link ID |
| 141-148 | 8 | sending nonce (u64 big-endian) |
| 149-156 | 8 | receiving nonce (u64 big-endian) |
| 157-188 | 32 | endpoint public key |

### Recovery Flow

```rust,ignore
// Take a snapshot (automatic during handle_handshake, or manual)
let snapshot = encryptor.snapshot();
let bytes = snapshot.serialize();
// ... persist bytes to storage ...

// On crash/failure, deserialize and restore
let state = PubkyDataSessionState::deserialize(&bytes).unwrap();
let mut restored = PubkyDataEncryptor::restore(config, state, endpoint_pubkey).await.unwrap();
// Continue from where you left off
```

### Write Failure Recovery

During handshake, if a homeserver write fails:

1. `handle_handshake()` returns `Err(HomeserverWriteError)`.
2. Snow's internal state has already advanced irreversibly.
3. Retrieve the pre-mutation snapshot via `last_good_snapshot()`.
4. Persist it and pass to `restore()` to rebuild the session from the correct position.

The restore mechanism replays all handshake messages from the homeservers through a fresh Noise state built with the same ephemeral key material.

## Error Handling

| Error | Cause | Recovery |
|---|---|---|
| `UnknownNoisePattern` | Invalid pattern string | Use a supported pattern: "NN", "XX" |
| `SnowNoiseBuildError` | Noise stack failed to initialize | Check key material and pattern compatibility |
| `BadLengthCiphertext` | Received message exceeds max size | Discard message, check sender |
| `HomeserverResponseError` | Failed to parse homeserver response | Retry |
| `HomeserverWriteError` | Homeserver write failed | Restore from `last_good_snapshot()` |
| `IsHandshake` | Called `transition_transport()` too early | Wait for `is_handshake_complete()` |
| `RestoreReplayError` | Handshake replay failed during restore | Check that homeserver messages are intact |
| `RestoreHashMismatch` | Replayed handshake produced different hash | Snapshot may be from a different session |
| `RestoreDeserializeError` | Snapshot deserialization failed | Check data integrity |

## Features

| Feature | Description |
|---|---|
| `test-utils` | Enables test-only APIs: ciphertext tampering simulation (`test_enable_tampering`), homeserver write failure simulation (`test_enable_write_failure`), and last ciphertext inspection (`test_last_ciphertext`). |

## Examples

See the [e2e tests](../e2e/src/tests/pubky_data.rs) for complete working examples including:

- NN and XX pattern handshakes
- Bidirectional message exchange
- Ciphertext tampering detection
- Out-of-order polling
- Incomplete handshake handling
- Session backup and restore (transport and handshake phases)
- Write failure recovery (both immediate error and lost-message scenarios)
- Dual homeserver setups
