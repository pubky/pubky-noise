# pubky-noise

A Rust workspace for encrypted peer-to-peer communication over [Pubky](https://pubky.org) homeservers using the [Noise protocol](https://noiseprotocol.org/).

## Overview

This library enables two peers to establish an authenticated, encrypted communication channel by exchanging Noise handshake and transport messages through their respective Pubky homeservers (the "outbox model"). Each peer writes to their own homeserver and reads from the remote peer's homeserver.

Key capabilities:

- **Noise protocol handshakes** -- NN (anonymous) and XX (mutually authenticated) patterns, with polling-safe async execution
- **Encrypted transport** -- ChaCha20-Poly1305 authenticated encryption with explicit nonces via `Noise_*_25519_ChaChaPoly_SHA256`
- **Session backup & restore** -- Compact 189-byte snapshots enable crash recovery by replaying handshake messages through a fresh Noise state
- **Asymmetric path derivation** -- Per-peer-pair private storage paths derived from DH shared secrets, preventing third-party enumeration of communication relationships
- **Write failure recovery** -- Automatic pre-mutation snapshots during handshake allow recovery from homeserver write failures

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
cargo nextest -p pubky-noise
```

### End-to-end tests (requires embedded Postgres)

```sh
cargo nextest -p e2e
```

The E2E tests spin up ephemeral Pubky testnets with embedded Postgres and exercise the full handshake-to-transport lifecycle, including:

- NN and XX pattern handshakes (normal and out-of-order polling)
- Bidirectional encrypted message exchange
- Ciphertext tampering detection
- Session snapshot serialization round-trips
- Transport-phase and handshake-phase restore
- Write failure recovery (immediate error and lost-message scenarios)
- Dual homeserver setups

## License

MIT
