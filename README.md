# pubky-noise

A Rust workspace for encrypted peer-to-peer communication over [Pubky](https://pubky.org) homeservers using the [Noise protocol](https://noiseprotocol.org/).

## Overview

This library enables two peers to establish an authenticated, encrypted communication channel by exchanging Noise handshake and transport messages through their respective Pubky homeservers (the "outbox model"). Each peer writes to their own homeserver and reads from the remote peer's homeserver.

Key capabilities:

- **Noise protocol handshakes** -- NN (anonymous) and XX (mutually authenticated) patterns, with polling-safe async execution
- **Encrypted transport** -- ChaCha20-Poly1305 authenticated encryption with explicit nonces via `Noise_*_25519_ChaChaPoly_SHA256`
- **Session backup & restore** -- Compact snapshots retain incoming handshake messages for local replay without downloads; snapshots are encrypted at rest (XChaCha20Poly1305 under a caller-provided key, derivable from the Pubky root key) before homeserver upload, with generation-based rollback protection
- **Asymmetric path derivation** -- Per-peer-pair private storage paths derived from DH shared secrets, preventing third-party enumeration of communication relationships
- **Write failure recovery** -- In-memory handshake retries retain the exact pending packet and path; prepared operations support durable save-before-send recovery

## Request Bounds

`PubkyNoiseConfig::new` and `new_with_paths` initialize `request_policy` with a
10-second deadline per attempt, three attempts maximum, and exponential backoff
starting at 250 ms and capped at 2 seconds. Change these values on the newly
created config before sharing it. Set `max_attempts` to one to disable retries.

The deadline includes request preparation and response-body consumption. Noise
retries expired deadlines and HTTP 408, 429, 502, 503 and 504. Other failures return
to the caller without an automatic retry. Packet and backup size limits still
apply; keep Pubky's error-body limit bounded when constructing its clients.
These are per-operation bounds, not a limit on concurrent sessions or on retries
made by an application. Browser suspension can delay deadline delivery.

A failed or cancelled write may already have reached the homeserver. Convenience
handshake and transport retries reuse the pending bytes and path; they do not
encrypt a replacement or acknowledge an uncertain write. Handshake snapshotting
and transport promotion are blocked until publication is acknowledged.
Handshake write errors retain their existing classification. Snapshot-based
recovery uses the checkpoint immediately before encryption, including completed
peer reads, so it regenerates the exact packet without rereading mutable storage.
For process-crash recovery, use the prepared APIs and durably save the resulting
state together with pending output before sending. Prepared APIs do no I/O, so
their callers still own deadlines, retry scheduling, authorization and admission.

Wire packets, saved session states and encrypted backup formats are unchanged.
Released Paykit's transport-error handling remains applicable. Code constructing
`PubkyNoiseConfig` with a struct literal must supply `request_policy`; constructors
provide the defaults. Exhaustive Noise error matches must handle
`HandshakeRecoveryRequired`, which rejects reuse after a failed state transition
or an unacknowledged convenience handshake write.

## Workspace Crates

| Crate | Path | Description |
|---|---|---|
| [`pubky-noise`](./pubky-noise/) | `pubky-noise/` | Core library: Noise handshake, encrypted transport, session management, path derivation |
| [`e2e`](./e2e/) | `e2e/` | End-to-end integration tests against real Pubky testnets |

## Building

```sh
cargo build
```

## Testing

### Unit tests (path derivation, serialization)

```sh
cargo nextest run -p pubky-noise
```

### End-to-end tests (requires Docker)

```sh
cargo nextest run -p e2e
```

The E2E tests start a disposable PostgreSQL container through Testcontainers, spin up ephemeral Pubky testnets in-process, and exercise the full handshake-to-transport lifecycle, including:

- NN and XX pattern handshakes (normal and out-of-order polling)
- Bidirectional encrypted message exchange
- Ciphertext tampering detection
- Session snapshot serialization round-trips
- Transport-phase and handshake-phase restore
- Write failure recovery (immediate error and lost-message scenarios)
- Dual homeserver setups

## License

MIT
