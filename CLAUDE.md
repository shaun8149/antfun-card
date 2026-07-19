# CLAUDE.md — ANTFUN Card

Guidance for AI agents working in this repo.

## What this is

A JavaCard applet for a **no-mnemonic NFC cold wallet**, forked from
[Status Keycard](https://github.com/keycard-tech/status-keycard) (Apache-2.0).
Upstream is the `upstream` git remote; `origin` is our repo.

Direction (see `docs/` for full analysis):
- **No mnemonic.** Master key generated in-chip, never rendered as BIP-39 words.
  `GENERATE_KEY` is the no-mnemonic path; `GENERATE_MNEMONIC` / `LOAD_KEY(SEED)` /
  `EXPORT_BIP85` / EIP-1581 private export are to be removed on our SKU.
- **Card-set clone as backup** (replaces the seed phrase). Card A verifies card B's
  DAK certificate **in-chip** (against a provisioned CA pubkey), does ephemeral
  ECDH + nonce, and transfers the 512-bit master seed under AEAD. Cross-set
  migration (new card set) is allowed by default; permanent OTP fuse is an
  optional "seal" mode. The **one hard net-new piece is in-chip ECDSA verify** —
  neither Keycard nor SeedKeeper has it.
- **Chains:** secp256k1 (BTC + all EVM/BSC) first. ed25519 (Solana) is deferred —
  needs a secure element with a native EdDSA primitive (verify with JCAlgTest/ECTester).

## Build & test

Requires **OpenJDK 11**. This machine (Homebrew, Apple Silicon):

```sh
export JAVA_HOME=/opt/homebrew/opt/openjdk@11
export PATH="/opt/homebrew/bin:$PATH"
./gradlew convertJavacard      # build the CAP
./gradlew test                 # run tests
```

- Tests run against the **jcardsim simulator** via `gradle.properties`
  (gitignored) containing `im.status.keycard.test.target=simulator`. It's created
  locally; recreate it if missing.
- Submodules `jcardsim` and `sdks` are required: `git submodule update --init --recursive`.
- Current baseline: **16/19 tests pass.** 3 known failures are jcardsim
  status-word quirks (`getDataNdefSegmentationTest`,
  `getChallengeWithSecureChannelTest`, `openSecureChannelTest`), not applet bugs.

### jcardsim gotcha (important)

`build.gradle` uses a **patched jcardsim** at `libs/jcardsim-3.0.5-SNAPSHOT.jar`,
NOT the submodule jar. Upstream jcardsim's `javacard.security.KeyBuilder` lacks
`TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT` (val 31), which the applet needs — without
the patch every test dies at applet install. Do not repoint `build.gradle` back to
the submodule jar. Patch details + reproduction: `libs/README-jcardsim-patch.md`.

## Layout

- `src/main/java/im/status/keycard/` — the applets (KeycardApplet = wallet,
  CashApplet = independent-key signing / business-card template, IdentApplet =
  device cert gate, NDEFApplet, SecureChannelV2, Crypto, SECP256k1).
- `docs/` — design analysis (gap analysis, 3-round adversarial conclusion,
  clone-design detail, threat model, open discussion items).
- `libs/` — vendored patched jcardsim (test only).
- Historical `DUPLICATE KEY` (removed upstream, commit `1b71679`) is the
  card-agnostic clone skeleton to build on: `git show 1b71679^:src/main/java/im/status/keycard/KeycardApplet.java`.

## Reusable primitives already in the codebase

- Ephemeral ECDH: `SecureChannelV2` (`crypto.ecdh` + `SECP256k1.derivePublicKey`).
- HKDF-SHA256: `Crypto.hkdf` (`Crypto.java:518`).
- AEAD: `Crypto.aesCcmEncrypt/Decrypt` (AES-CCM; **no AES-GCM on target cards** — use CCM or AES-CBC+HMAC).
- Device cert: `IdentApplet` (presents cert; **in-chip verify does not exist yet**).

## Conventions

- License Apache-2.0; keep `NOTICE`. Pull upstream fixes via the `upstream` remote.
- Don't commit business/marketing docs to this public repo (kept local by decision).
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
