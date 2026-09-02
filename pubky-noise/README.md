# Pubky Noise

A fully-integrated [Noise protocol](https://noiseprotocol.org/) framework for encrypted peer-to-peer messaging over [Pubky](https://pubky.org) homeservers.

Peers use their homeservers as outboxes: each party writes encrypted Noise messages to their own homeserver, and reads from the remote peer's homeserver. The library wraps the [Snow](https://github.com/mcginty/snow) Noise implementation in a clean async interface with built-in session backup and restore.

## Install

```toml
# Cargo.toml
[dependencies]
pubky-noise = "0.1.0-rc9"
```

### Actual dependencies (for reference)

| Crate | Version | Purpose |
|---|---|---|
| `pubky` | 0.10.0 | Pubky SDK (homeserver client, sessions, keys) |
| `snow` | 0.10.0 | Noise protocol implementation |
| `ed25519-dalek` | 3.0.0 | Ed25519 signatures and key conversions |
| `curve25519-dalek` | 5.0.0 | X25519 Diffie-Hellman for path derivation |
| `sha2` | 0.11.0 | SHA-256 hashing (path derivation, Noise suite) |
| `getrandom` | 0.3 | Cryptographic RNG |
| `hex` | 0.4 | Hex encoding for derived paths |
| `rand` | 0.9.0 | Random key generation |

## Quick Start

```rust,no_run
use std::sync::Arc;
use pubky::prelude::*;
use pubky_noise::{PubkyNoiseConfig, PubkyNoiseEncryptor, HandshakeResult};

// 1. Create shared configuration
//    (requires an authenticated PubkySession and a Pubky HTTP client)
let config = PubkyNoiseConfig::new(
    root_secret_key,          // [u8; 32] - root Ed25519 secret key
    0,                        // protocol version
    "XX",                     // Noise handshake pattern
    homeserver_session,       // authenticated PubkySession
    "/pub/data".to_string(),  // storage path prefix
    pubky_client,             // Pubky HTTP client
).unwrap();

// 2. Create encryptors for each side
let mut initiator = PubkyNoiseEncryptor::new(
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

// 5. Prepare, persist, and publish an encrypted message
let prepared = initiator.prepare_send(b"Hello, peer!")?;
persistent_store.commit_send(
    prepared.destination_path(),
    prepared.ciphertext(),
    prepared.resulting_session_state(),
)?;
initiator.acknowledge_persisted_send(prepared)?;
ordered_publisher.flush_in_order().await?;

// Receive convenience API; use prepare_receive for durable processing.
let messages = initiator.receive_message().await?;

// 6. Clean up
initiator.close();
```

## Architecture

### Outbox Model

Each peer writes to their **own** homeserver and reads from the **remote** peer's homeserver:

```text
Alice's Homeserver                 Bob's Homeserver
  alice.write_path/{n}               bob.write_path/{m}
    ^ Alice writes                     ^ Bob writes
    | Bob reads via bob.read_path      | Alice reads via alice.read_path
```

Messages are stored at incrementing slot indices under each direction's path.
During the handshake, reads and writes follow the Noise pattern's ordered action
sequence and share one slot counter. After `transition_transport()`, that counter
becomes the transport base slot, and each direction advances its own homeserver
slot counter independently. Snow's transport nonces are tracked separately from
homeserver slot selection.

### Wire Format

Messages use a length-prefixed packet format:

```text
[len_hi, len_lo, ciphertext..., zero padding...]
```

- `len`: big-endian u16 indicating ciphertext length
- `ciphertext`: up to 1016 bytes (1000-byte plaintext plus the 16-byte authentication tag)
- Total stored packet size: 1018 bytes

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

- **`PubkyNoiseConfig`** -- Shared configuration and resources for multiple sessions. Holds the HTTP client, authenticated homeserver session, read/write paths, root keypair, and default Noise pattern. Wrap in `Arc` and share across encryptors.

- **`PubkyNoiseEncryptor`** -- A single-session Noise encryptor. Each instance manages exactly one Noise session (handshake + transport) with a single remote peer. Create multiple instances sharing the same `Arc<PubkyNoiseConfig>` for concurrent sessions.

- **`LinkId`** -- A 32-byte identifier derived from the Noise handshake transcript hash. Changes after every handshake when ephemeral keys are used. Available after calling `transition_transport()`.

- **`PubkyNoiseSessionState`** -- Serializable snapshot of a session (197 bytes). Contains everything needed to restore a session by replaying persisted handshake messages through a fresh Noise state. Because it includes the session's secret keys, it is encrypted before homeserver storage (see [Session Backup & Restore](#session-backup--restore)).

- **`PreparedSend` / `PreparedReceive`** -- Staged transport results containing the exact message data and resulting session state. Use these when message publication or processing must be committed atomically with session state.

- **`DataLinkContext`** -- Internal Noise state machine managing the handshake and transport phases. Not used directly by consumers.

### Lifecycle

```text
new() --> handle_handshake() [loop] --> transition_transport() --> send/receive --> close()
        |                                     |
    last_good_snapshot                     snapshot() --> persist_snapshot() [encrypted]
        |                                     |
    restore() [on crash recovery]     load_snapshot() --> restore() [on crash recovery]
```

### Staged Transport Operations

Transport sends use staged state transitions so ambiguous homeserver responses
cannot cause a fresh plaintext to reuse a nonce:

These APIs coordinate an application's durable state with transport processing.
They do not acknowledge that the remote peer received a message.

1. Call `prepare_send()` to obtain the destination path, exact ciphertext, and resulting session state.
2. Atomically persist the exact ciphertext and resulting session state as one outbound record.
3. Call `acknowledge_persisted_send()`. The handle is consumed and the encryptor may prepare the next message.
4. Write persisted outbound records to their homeserver destination paths in order. If a write is uncertain, retry the exact stored ciphertext.
5. For inbound data, fetch `next_receive_path()`, call `prepare_receive()`, atomically persist the resulting state with the application's durable processing result, and call `acknowledge_persisted_receive()`.

If atomic persistence fails, drop the advanced encryptor and restore the previous
persisted state. There is no in-place discard operation. Callers sharing state
across processes must serialize preparation and use conditional state updates.
Do not call `persist_snapshot()` to commit a staged operation: it is rejected
while an operation is awaiting acknowledgement. In the caller's atomic storage
transaction, replace the previous session snapshot with `resulting_session_state`
and persist the matching outbound record or inbound processing result.

`send_message()` is deprecated because it cannot make the exact ciphertext and
resulting state durable atomically. After an ambiguous in-process write failure,
`retry_pending_send()` republishes the exact retained ciphertext. This recovery
does not survive a process crash. `receive_message()` remains available for
callers that do not need atomic application-state processing.

Decrypted plaintext is sensitive application data. Avoid logging it, minimize copies, and protect it at rest whenever the application protocol requires persistence.

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
use pubky_noise::path_derivation::derive_asymmetric_paths;

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

Use `PubkyNoiseConfig::new_with_paths()` to supply separate write/read paths.

## Session Backup & Restore

Sessions can be snapshotted, serialized, and restored to recover from crashes or write failures.

### Snapshot Format

`PubkyNoiseSessionState` serializes to a compact 197-byte binary format:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version |
| 1 | 1 | phase (0=Handshake, 1=Transport) |
| 2 | 1 | pattern |
| 3 | 1 | initiator flag |
| 4-35 | 32 | ephemeral secret key |
| 36 | 1 | has static secret flag |
| 37-68 | 32 | static secret key |
| 69-72 | 4 | handshake/base counter (u32 big-endian) |
| 73 | 1 | noise step |
| 74 | 1 | sub-step index |
| 75 | 1 | has handshake hash flag |
| 76-107 | 32 | handshake hash |
| 108 | 1 | has link ID flag |
| 109-140 | 32 | link ID |
| 141-148 | 8 | sending nonce (u64 big-endian) |
| 149-156 | 8 | receiving nonce (u64 big-endian) |
| 157-160 | 4 | write counter (u32 big-endian) |
| 161-164 | 4 | read counter (u32 big-endian) |
| 165-196 | 32 | endpoint public key |

### Encrypted Homeserver Backup

The serialized snapshot contains the session's ephemeral and static secrets, so it must never
be stored in plaintext. `persist_snapshot()` encrypts it before uploading to
`{write_path}/backup` on the local homeserver, and `load_snapshot()` fetches and decrypts it:

```rust,ignore
use pubky_noise::backup_crypto;

// Obtain the 32-byte backup key. Root-identity callers can derive it from the
// Pubky root secret; delegated apps that do not hold the root secret may
// supply their own key (e.g. derived from a shared Noise/state key).
let backup_key = backup_crypto::derive_backup_key(&root_secret);

// Encrypt and upload the snapshot to the homeserver.
// `generation` is a caller-managed monotonically increasing counter.
// IMPORTANT: advance your trusted local checkpoint to `generation` *before*
// (or atomically with) this call -- see "Rollback protection" below.
encryptor.persist_snapshot(&backup_key, generation).await?;

// Later (e.g. after a crash or on another device): fetch, decrypt and restore
let loaded = PubkyNoiseEncryptor::load_snapshot(&config, &backup_key, local_checkpoint).await?;
let mut restored = PubkyNoiseEncryptor::restore(config, loaded.state, peer_pubkey).await?;
// (`peer_pubkey` is the remote peer you were talking to; it is also stored
//  in `loaded.state.endpoint_pubkey` and can be reconstructed from it via pkarr.)
```

Encryption follows the same convention as Pubky recovery files: XSalsa20Poly1305 with a random
192-bit nonce per write, prepended to the ciphertext (the nonce is not secret -- it only needs
to be unique per write, and decryption requires it). `persist_snapshot()` and `load_snapshot()`
take a caller-provided 32-byte `backup_key`. The optional `backup_crypto::derive_backup_key()`
helper derives it from the Pubky root secret with a domain-separated KDF --
`SHA-256("pubky-noise/session-backup/v0" || root_secret)` -- so the raw root secret is never
used directly; callers that do not hold the root secret supply their own key instead.
The snapshot is not compressed: it is a fixed
197 bytes of mostly high-entropy key material, which does not compress.

The stored record is a closed, versioned envelope:

```text
magic ("PNBK") || envelope_version || algorithm_id || nonce || ciphertext
```

The header is duplicated inside the authenticated plaintext (the NaCl construction has no
AAD) and validated on decryption. Only explicitly supported envelope versions are accepted,
the record must match the exact length of its version, and the response body is read with a
hard size cap -- malformed, truncated, trailing, and oversized records are all rejected.

**Rollback protection.** AEAD authenticates the bytes but provides no freshness: a stale or
malicious homeserver can return an older, still-valid backup after the session has advanced,
which would reinstall old transport nonces and slot counters (nonce reuse, slot overwrites,
peer desynchronization). To detect this, every backup carries a monotonic `generation` in its
authenticated plaintext. Pass your trusted local checkpoint as `min_generation` to
`load_snapshot()`; older backups are rejected with `RestoreBackupRollbackError`. Without a
trusted checkpoint (`None`, e.g. a fresh device) rollback cannot be detected -- a signed or
hash-chained sequence alone is not sufficient either, since the homeserver can simply withhold
the newest element.

**Checkpoint update order matters.** Advance the trusted local checkpoint to the new
`generation` *before* (or atomically with) calling `persist_snapshot()`. If the checkpoint is
advanced only after the upload and the process crashes in between, the checkpoint still holds
`generation - 1`, so a homeserver replaying the previous backup would be accepted. Crashing
with the checkpoint already advanced is safe: the new upload is simply lost and loading then
rejects the older record instead of silently accepting stale state.

If you persist snapshots through your own storage instead of `persist_snapshot()`, you must
encrypt the serialized bytes yourself.

### Snapshot Security

Session snapshots contain static and ephemeral secret key material. Encrypt and
authenticate them at rest (as `persist_snapshot()` does), restrict access to apps
or processes authorized for the same identity, and ensure superseded snapshots are
no longer recoverable. Retaining restorable ephemeral material extends its lifetime
and can expose messages from that Noise session if the snapshot is compromised.
Starting a fresh session does not protect old traffic while older snapshots remain
recoverable.

At-rest encryption protects the stored bytes but does not remove this tradeoff
while a snapshot remains recoverable. The staged transport APIs also do not
provide cross-process authentication, authorization, credential management, or
locking; callers must enforce those requirements.

### Recovery Flow

```rust,ignore
// Persist the encrypted snapshot to the homeserver (the snapshot contains
// session secrets -- never store the serialized bytes in plaintext).
// Advance your trusted local checkpoint to `generation` first.
encryptor.persist_snapshot(&backup_key, generation).await?;

// On crash/failure: fetch, decrypt and restore
let loaded = PubkyNoiseEncryptor::load_snapshot(&config, &backup_key, local_checkpoint).await?;
let mut restored = PubkyNoiseEncryptor::restore(config, loaded.state, endpoint_pubkey).await.unwrap();
// Continue from where you left off
```

### Write Failure Recovery

During handshake, if a homeserver write fails:

1. `handle_handshake()` returns `Err(HomeserverWriteError)`.
2. Snow's internal state has already advanced irreversibly.
3. Retrieve the pre-mutation snapshot via `last_good_snapshot()`.
4. Persist it and pass to `restore()` to rebuild the session from the correct position.

The restore mechanism replays all handshake messages from the homeservers through a fresh Noise state built with the same ephemeral key material.

### Handshake Recovery with `last_good_snapshot`

Every call to `handle_handshake()` automatically captures a pre-mutation snapshot before doing any work. If the call fails (or if a written message is subsequently lost), this snapshot is the recovery point.

#### Why recovery is needed

Snow's `HandshakeState` is a one-way ratchet: once `write_message()` is called, the internal state advances irreversibly. If the homeserver `put()` then fails, the encryptor's Noise state no longer matches what is actually stored on the homeservers. The encryptor cannot simply retry -- it must be rebuilt from scratch.

#### Recovery sequence diagram

```text
                    Initiator                    Homeserver                  Responder
                        |                            |                          |
  [snapshot captured]   |                            |                          |
                        |--- handle_handshake() ---->|                          |
                        |   Snow advances state      |                          |
                        |   put() FAILS              |                          |
                        |<-- Err(HomeserverWrite) ---|                          |
                        |                            |                          |
  [encryptor is now     |                            |                          |
   corrupted -- Snow    |                            |                          |
   advanced but message |                            |                          |
   never reached the    |                            |                          |
   homeserver]          |                            |                          |
                        |                            |                          |
  [get last_good_       |                            |                          |
   snapshot, serialize, |                            |                          |
   persist to storage]  |                            |                          |
                        |                            |                          |
  [discard corrupted    |                            |                          |
   encryptor]           |                            |                          |
                        |                            |                          |
  [restore() from       |                            |                          |
   persisted snapshot:  |                            |                          |
   - builds fresh Snow  |                            |                          |
     with same          |                            |                          |
     ephemeral key      |                            |                          |
   - replays all        |<------ reads existing ---->|                          |
     handshake messages |       messages from        |                          |
     from homeservers   |       homeservers          |                          |
   - state now matches  |                            |                          |
     what is on disk]   |                            |                          |
                        |                            |                          |
  [restored encryptor]  |--- handle_handshake() ---->| (write succeeds)         |
                        |                            |--- message available --->|
                        |                            |                          |
                        |          ... handshake continues normally ...         |
```

#### Code example

```rust,ignore
use pubky_noise::{PubkyNoiseEncryptor, PubkyNoiseConfig, PubkyNoiseError, HandshakeResult};
use pubky_noise::backup_crypto;

// Recover from homeserver write failures *in-process*: the fresh
// `last_good_snapshot()` captured at the start of the failed call is the
// recovery point, so no disk is involved.
async fn handshake_with_recovery(
    encryptor: &mut PubkyNoiseEncryptor,
    config: Arc<PubkyNoiseConfig>,
    endpoint_pubkey: PublicKey,
) -> Result<HandshakeResult, PubkyNoiseError> {
    match encryptor.handle_handshake().await {
        Ok(result) => Ok(result),
        Err(PubkyNoiseError::HomeserverWriteError) => {
            // The encryptor is corrupted, but the snapshot captured at the
            // start of the failed call is still in memory -- restore directly
            // from it. This also works when no prior call ever succeeded.
            let snapshot = encryptor
                .last_good_snapshot()
                .expect("always Some after handle_handshake")
                .clone();

            *encryptor = PubkyNoiseEncryptor::restore(
                config,
                snapshot,
                endpoint_pubkey,
            )
            .await?;

            // The restored encryptor is back to the pre-failure position.
            // The caller can retry handle_handshake() on the next poll.
            Ok(HandshakeResult::Pending)
        }
        Err(e) => Err(e),
    }
}

// Crash coverage additionally requires the recovery point to be durable.
// This helper scopes that to explicit `HomeserverWriteError` failures only:
// it persists the current state before each call, so if the `put()` inside
// that call explicitly fails (returns an error), restoring the persisted
// checkpoint replays correctly and the write can be retried. It does NOT
// cover the lost-message case (Case a2, described below), where `put()`
// succeeded and the server later lost the write: restoring the post-write
// state would skip the lost write rather than republish it. Case a2 recovery
// needs the durable checkpoint to remain at the *pre-write* state until peer
// progress confirms the write actually persisted — call-side persistence
// alone cannot establish that.
async fn handshake_recovery_explicit_write_errors(
    encryptor: &mut PubkyNoiseEncryptor,
    config: Arc<PubkyNoiseConfig>,
    endpoint_pubkey: PublicKey,
    backup_key: &[u8; 32],
    generation: u64,
) -> Result<HandshakeResult, PubkyNoiseError> {
    let snapshot = encryptor.snapshot().unwrap();
    let encrypted =
        backup_crypto::encrypt_backup_with_key(backup_key, generation, &snapshot);
    save_to_disk(&encrypted); // your persistence logic

    handshake_with_recovery(encryptor, config, endpoint_pubkey).await
}
```

#### Lost-message recovery (Case a2)

If `put()` succeeds but the data is subsequently lost (e.g., homeserver crash after acknowledgment), `handle_handshake()` returns `Ok(Pending)` -- the loss is undetectable at the protocol level. The handshake gets stuck: the responder keeps polling but finds nothing to read, and the initiator waits for a reply that will never come.

Recovery follows the same path: load the last persisted snapshot (from before the lost write), call `restore()`, and re-run the handshake. Because `restore()` replays only the messages that are actually present on the homeservers, it rebuilds the correct state and the re-issued write fills the missing slot.

#### Key invariants

- `last_good_snapshot()` returns `None` before the first `handle_handshake()` call.
- Each `handle_handshake()` call overwrites the previous snapshot with the state from the start of *that* call.
- The snapshot contains the ephemeral secret key, which is the critical piece that allows `restore()` to re-derive the same transport keys via replay. Any persisted snapshot must be encrypted (as `persist_snapshot()` does).
- `restore()` verifies the handshake hash matches the saved one (for transport-phase restores), returning `RestoreBackupHashMismatch` on mismatch.

## Error Handling

| Error | Cause | Recovery |
|---|---|---|
| `UnknownNoisePattern` | Invalid pattern string | Use a supported pattern: "NN", "XX" |
| `SnowNoiseBuildError` | Noise stack failed to initialize | Check key material and pattern compatibility |
| `BadLengthCiphertext` | Received message exceeds max size | Discard message, check sender |
| `HomeserverResponseError` | Failed to parse homeserver response | Retry |
| `HomeserverWriteError` | Homeserver write failed | Restore from `last_good_snapshot()` |
| `IsHandshake` | Called a transport operation before transport phase | Wait for `is_handshake_complete()` and `transition_transport()` |
| `EncryptionError` | Noise encryption failed during `send_message()` | Check transport state; session may be corrupted |
| `DecryptionError` | Noise decryption failed during `receive_message()` | Message may be tampered or nonces desynchronized |
| `CounterOverflow` | Message slot counter space is exhausted | Start a new Noise session |
| `NonceOverflow` | Transport nonce space is exhausted | Start a new Noise session |
| `UnacknowledgedPreparedTransport` | A prepared operation has not been durably acknowledged | Persist and acknowledge its handle, or restore the previous durable state if persistence failed |
| `NoPreparedTransport` | An acknowledgement was attempted with no pending operation | Check the caller's operation lifecycle |
| `PreparedTransportMismatch` | A prepared handle belongs to another encryptor or operation | Use the handle returned by the current encryptor |
| `RestoreBackupReplayError` | Handshake replay failed during restore | Check that homeserver messages are intact |
| `RestoreBackupHashMismatch` | Replayed handshake produced different hash | Snapshot may be from a different session |
| `RestoreBackupDeserializeError` | Backup envelope or snapshot deserialization failed | Check data integrity |
| `RestoreBackupDecryptError` | Persisted snapshot decryption failed | Wrong backup key, or tampered/corrupted backup |
| `RestoreBackupRollbackError` | Backup generation is older than the trusted local checkpoint | Restart from a fresh handshake; investigate homeserver |
| `RestoreBackupNotFoundError` | No backup exists at the backup path (distinct from connectivity/server failures) | Persist a snapshot first, or start a new session |

## Features

| Feature | Description |
|---|---|
| `test-utils` | Enables test-only APIs: ciphertext tampering simulation (`test_enable_tampering`), homeserver write failure simulation (`test_enable_write_failure`), and last ciphertext inspection (`test_last_ciphertext`). |

## Examples

See the [e2e tests](../e2e/src/tests/pubky_noise.rs) for complete working examples including:

- NN and XX pattern handshakes
- Bidirectional message exchange
- Ciphertext tampering detection
- Out-of-order polling
- Incomplete handshake handling
- Session backup and restore (transport and handshake phases)
- Write failure recovery (both immediate error and lost-message scenarios)
- Dual homeserver setups
