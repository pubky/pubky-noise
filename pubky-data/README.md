# Pubky Data

A ready-to-use pubky-sdk integrated A&E communication library, wrapping in a clean interface the Noise snow library.

Peers homeservers are used as outbox from where to read exchanges messages among the 2 peers clients.

## Install

```toml
# Cargo.toml
[dependencies]
pkarr = { path = "../../pkarr/pkarr", features = ["full"] }
pubky = { path = "../../pubky-core/pubky-sdk", version = "0.6.0-rc.6" }
pubky-common = { path = "../../pubky-core/pubky-common", version = "0.6.0-rc.6" }
ed25519-dalek = { version = "2.1.1" }
sha256 = { version = "1.6.0" }
rust-crypto = { version = "0.2.36" }
x25519-dalek = { version = "2.0.0-rc.3", features = ["static_secrets"] }
chacha20poly1305 = { version = "0.10.1" }
curve25519-dalek = { version = "4.1.3" }
snow = { version = "0.10.0", features = ["use-sha2"] }
rand = "0.9.0"
```

## Quick start

```rust no_run
```

## Mental model

- `PubkyDataEncryptor` - facade, start by this one! Owns and manage Noise communication link state
- `LinkId` - 
- `ConversationId` - 
- `PairContextId`

## Examples

