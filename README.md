# ANTFUN Card

A JavaCard applet for a **no-mnemonic NFC cold wallet**, based on [Status Keycard](https://github.com/keycard-tech/status-keycard) (Apache-2.0).

## What this is

ANTFUN Card builds on Keycard's BIP-32 HD wallet applet and takes it in a different direction:

- **No mnemonic.** The master key is generated in-chip and never exists as a BIP-39 phrase. There is nothing for a phishing attack to ask the user to type.
- **Card-set clone as backup.** Instead of a seed phrase, backup is done by cloning the master secret card-to-card: the source card verifies the target is a genuine card (DAK certificate, checked **in-chip**), establishes an ephemeral ECDH key, and transfers the seed under authenticated encryption. Migration to a fresh card set (after NFC damage or loss) is supported by default.
- **Multi-chain.** secp256k1 (BTC / all EVM incl. BSC) first; ed25519 (Solana) pending a secure element with a native EdDSA primitive.
- **Social / attribution layer** (business-card tap, meeting proof) reusing Keycard's Cash/Ident applet patterns.

Design analysis and rationale live in [`docs/`](docs/).

## Relationship to Status Keycard

This repository is a fork of Status Keycard. Upstream is tracked as the `upstream` git remote. The wallet core (in-chip key generation, secp256k1 + Schnorr signing, PIN/PUK, secure channel, device-attestation cert gate, NDEF) is reused; the mnemonic/backup surfaces are being replaced with the card-set clone described above.

Keycard is licensed under Apache-2.0; this project remains Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

## Build

Requires **OpenJDK 11**.

```sh
export JAVA_HOME=/opt/homebrew/opt/openjdk@11   # macOS/Homebrew; adjust to your JDK 11
./gradlew convertJavacard      # build the CAP
./gradlew test                 # run tests (simulator target via gradle.properties)
```

To run tests against the jcardsim simulator instead of a physical card, create `gradle.properties` with:

```
im.status.keycard.test.target=simulator
```

Upstream Keycard build/usage notes: [`docs/KEYCARD-UPSTREAM-README.md`](docs/KEYCARD-UPSTREAM-README.md).
