# Card-Set Clone Protocol — Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the card-set clone spike so a simulator test proves the full protocol: card A authenticates card B in-chip, transfers the master key under authenticated encryption with anti-replay, and card B imports it and controls the same wallet.

**Architecture:** Extend the existing `INS_CLONE` command in `KeycardApplet`. Card A `CLONE_EXPORT` verifies B's DAK cert, does ephemeral ECDH against B's device pubkey, derives keys with HKDF-SHA256 (salted by B's nonce), and AES-CBC-encrypts + HMAC-SHA256-authenticates `masterPrivate‖masterChainCode`. Card B `CLONE_IMPORT` reverses it using its own device private key (`SharedMemory.idPrivate`). Tests play the peer card with BouncyCastle.

**Tech Stack:** JavaCard 3.0.5 applet, jcardsim simulator (patched, in `libs/`), JUnit5, BouncyCastle 1.65, web3j `Numeric`. Build: OpenJDK 11.

## Global Constraints

- Build/test env: `export JAVA_HOME=/opt/homebrew/opt/openjdk@11; export PATH="/opt/homebrew/bin:$PATH"`.
- Run only clone tests for a clean signal: `./gradlew test --console=plain --tests '*clone*'`. Full suite has 3 known jcardsim quirks (`getChallengeWithSecureChannelTest`, `getDataNdefSegmentationTest`, `openSecureChannelTest`) — ignore those.
- **No AES-GCM** (unavailable on target cards). Use AES-CBC + HMAC-SHA256 (both in `Crypto`).
- All new opcodes live under `INS_CLONE = (byte) 0xD6`, dispatched in `KeycardApplet.clone(APDU)`.
- Reuse existing `Crypto` primitives: `crypto.ecdh` (ALG_EC_SVDP_DH_PLAIN, 32-byte X), `crypto.hkdf` (32-byte OKM), `crypto.hmacSHA256`, `secp256k1.derivePublicKey`, `cloneAesCbc`.
- HKDF info label is the constant `CLONE_LABEL = "ANTFUN-CLONE-v1"` (already defined). OKM split: `encKey = OKM[0..16]`, `macKey = OKM[16..32]`.
- TDD: test first, watch it fail, minimal code, commit. Commit trailer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Work on branch `clone-spike`.

## Clone payload format (locked here, used by Tasks 2–4)

```
CLONE_EXPORT input : nonce(16) ‖ peerPubkey(65) ‖ CA_sig(DER)
CLONE_EXPORT output: e_A_pub(65) ‖ ct(64) ‖ tag(16)
  ct  = AES-CBC( encKey, IV=0, masterPrivate(32) ‖ masterChainCode(32) )
  tag = HMAC-SHA256( macKey, ct )[0..16]
CLONE_IMPORT input : nonce(16) ‖ e_A_pub(65) ‖ ct(64) ‖ tag(16)   → loads master key, no output
  B derives shared X via ECDH( SharedMemory.idPrivate, e_A_pub )
```

## File structure

- Modify `src/main/java/im/status/keycard/KeycardApplet.java` — `clone()` handler, constants, fields (Tasks 2–4).
- Modify `src/test/java/im/status/keycard/KeycardTest.java` — `@BeforeEach` (Task 1), clone tests + helpers (Tasks 2–4), expose device keypair (Task 4).

---

### Task 1: Deterministic test isolation (D)

Eliminates cross-test flakiness (`signTest`/`loadKeyTest` intermittently fail) caused by persistent EEPROM surviving the power-cycle-only `@BeforeEach`. Reinstall fresh applets + reprovision per test on the simulator target.

**Files:**
- Modify: `src/test/java/im/status/keycard/KeycardTest.java` (`init()` at ~line 217)

- [ ] **Step 1: Replace the `@BeforeEach init()` body**

```java
  @BeforeEach
  void init() throws Exception {
    if (TARGET == TARGET_SIMULATOR) {
      openSimulatorChannel(); // fresh CardSimulator + reinstall all applets (pristine persistent state)
      initIfNeeded();         // reprovision the DAK cert + init the card (PIN/PUK)
    } else {
      reset();
    }
    cmdSet = new TestKeycardCommandSet(sdkChannel, ((org.bouncycastle.jce.interfaces.ECPublicKey) caKeyPair.getPublic()).getQ().getEncoded(true));
    cmdSet.select().checkOK();
  }
```

- [ ] **Step 2: Run the full suite twice to check determinism**

Run: `./gradlew test --console=plain 2>&1 | grep 'tests completed'` — twice.
Expected: identical result both runs. `signTest`/`loadKeyTest` no longer flake. Only the 3 known jcardsim quirks may remain (they are response-format bugs, not state bleed; if `openSecureChannelTest` now passes deterministically, even better).

- [ ] **Step 3: Confirm clone tests still green**

Run: `./gradlew test --console=plain --tests '*clone*'`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Commit**

```bash
git add src/test/java/im/status/keycard/KeycardTest.java
git commit -m "test: isolate each test on the simulator (fresh applets per @BeforeEach)

Kills cross-test flakiness from persistent EEPROM surviving the power-cycle
reset. signTest/loadKeyTest no longer intermittently fail.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

**Note if a non-quirk test breaks after Step 1:** it had a hidden dependency on a prior test's persistent key. Fix that test to generate/load its own key at its start (open secure channel + verify PIN + generateKey), then re-run. Do not revert the isolation.

---

### Task 2: Authenticate the clone payload (A)

Add an HMAC-SHA256 tag over the ciphertext so tampering is detectable. Export output grows from `e_A_pub‖ct` to `e_A_pub‖ct‖tag`.

**Files:**
- Modify: `KeycardApplet.java` — `CLONE_P1_EXPORT` case in `clone()`, add `CLONE_TAG_LEN`
- Modify: `KeycardTest.java` — extend `cloneExportEndToEndTest` to verify the tag; add `hmacSha256` helper

**Interfaces:**
- Produces: `CLONE_EXPORT` returns `e_A_pub(65) ‖ ct(64) ‖ tag(16)`; `tag = HMAC-SHA256(macKey, ct)[0..16]`, `macKey = OKM[16..32]`.
- Consumes: `crypto.hmacSHA256(byte[] key, short keyOff, short keyLen, byte[] in, short inOff, short inLen, byte[] out, short outOff)` (same method `Crypto.hkdf` uses internally).

- [ ] **Step 1: Extend the test to require and verify the tag**

In `cloneExportEndToEndTest`, replace the length assertion and add tag verification before decryption:

```java
    assertEquals(65 + 64 + 16, out.length); // e_A_pub(65) || ct(64) || tag(16)
    byte[] eaPub = Arrays.copyOfRange(out, 0, 65);
    byte[] ct = Arrays.copyOfRange(out, 65, 129);
    byte[] tag = Arrays.copyOfRange(out, 129, 145);

    org.bouncycastle.math.ec.ECPoint shared = spec.getCurve().decodePoint(eaPub).multiply(bPriv).normalize();
    byte[] x = Numeric.toBytesPadded(shared.getAffineXCoord().toBigInteger(), 32);
    byte[] okm = hkdfSha256(nonce, x, "ANTFUN-CLONE-v1".getBytes(), 32);
    byte[] encKey = Arrays.copyOfRange(okm, 0, 16);
    byte[] macKey = Arrays.copyOfRange(okm, 16, 32);

    // Tag must authenticate the ciphertext
    byte[] expectedTag = Arrays.copyOfRange(hmacSha256(macKey, ct), 0, 16);
    assertArrayEquals(expectedTag, tag, "clone ciphertext tag must verify");

    javax.crypto.Cipher aes = javax.crypto.Cipher.getInstance("AES/CBC/NoPadding", "BC");
    aes.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(encKey, "AES"),
             new javax.crypto.spec.IvParameterSpec(new byte[16]));
    byte[] pt = aes.doFinal(ct);
    byte[] masterPriv = Arrays.copyOfRange(pt, 0, 32);
    byte[] recoveredPub = spec.getG().multiply(new BigInteger(1, masterPriv)).normalize().getEncoded(false);
    assertArrayEquals(keyUID, sha256(recoveredPub), "peer B must recover the same master key as card A");
```

Add the helper next to `hkdfSha256`:

```java
  private static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
    javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
    mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
    return mac.doFinal(data);
  }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./gradlew test --console=plain --tests '*cloneExportEndToEnd*'`
Expected: FAIL at `assertEquals(145, out.length)` — current output is 129 bytes (no tag).

- [ ] **Step 3: Add the tag in the applet**

In `KeycardApplet.java`, add near the clone constants:

```java
  static final short CLONE_TAG_LEN = 16;
```

In the `CLONE_P1_EXPORT` case, `cloneAesKey.setKey` currently uses `cloneScratch[32]` (encKey). Keep it. After computing `ctLen` and before `setOutgoingAndSend`, append the tag over the ciphertext using `macKey = cloneScratch[48..64]` (OKM[16..32]):

```java
        short ctOff = (short) (OFFSET_CDATA + ephLen);
        short ctLen = cloneAesCbc.doFinal(cloneScratch, (short) 64, CLONE_SEED_LEN, apduBuffer, ctOff);
        // tag = HMAC-SHA256(macKey = OKM[16..32], ct)[0..16], written after the ciphertext
        crypto.hmacSHA256(cloneScratch, (short) 48, (short) 16, apduBuffer, ctOff, ctLen, derivationOutput, (short) 0);
        Util.arrayCopyNonAtomic(derivationOutput, (short) 0, apduBuffer, (short) (ctOff + ctLen), CLONE_TAG_LEN);
        apdu.setOutgoingAndSend(OFFSET_CDATA, (short) (ephLen + ctLen + CLONE_TAG_LEN));
```

(Replace the existing `short ctLen = ...; apdu.setOutgoingAndSend(...)` lines with the block above.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `./gradlew test --console=plain --tests '*cloneExportEndToEnd*'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/im/status/keycard/KeycardApplet.java src/test/java/im/status/keycard/KeycardTest.java
git commit -m "spike(clone): authenticate CLONE_EXPORT payload with HMAC-SHA256 tag

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Nonce anti-replay (B)

The card must reject a `CLONE_EXPORT` that reuses a nonce it has already served, so a captured request cannot be replayed to re-derive a key stream. Store the last-used nonce and require strict change.

**Files:**
- Modify: `KeycardApplet.java` — add `lastCloneNonce` field + check in `CLONE_P1_EXPORT`
- Modify: `KeycardTest.java` — add `cloneExportRejectsReusedNonceTest`

**Interfaces:**
- Produces: `CLONE_EXPORT` throws `SW_WRONG_DATA (0x6A80)` when the 16-byte nonce equals the immediately previous one used.

- [ ] **Step 1: Write the failing test**

```java
  @Test
  @DisplayName("CLONE EXPORT: reject a reused nonce (anti-replay)")
  void cloneExportRejectsReusedNonceTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    assertEquals(0x9000, cmdSet.generateKey().getSw());
    byte[] caPubBytes = ((ECPublicKey) caKeyPair.getPublic()).getQ().getEncoded(false);
    assertEquals(0x9000, sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x00, 0x00, caPubBytes)).getSw());

    ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
    BigInteger bPriv = new BigInteger("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", 16);
    byte[] bPubBytes = ((ECPublicKey) kf.generatePublic(
        new org.bouncycastle.jce.spec.ECPublicKeySpec(spec.getG().multiply(bPriv), spec))).getQ().getEncoded(false);
    Signature caSigner = Signature.getInstance("SHA256withECDSA", "BC");
    caSigner.initSign(caKeyPair.getPrivate());
    caSigner.update(bPubBytes);
    byte[] caSig = caSigner.sign();

    byte[] nonce = new byte[16];
    for (int i = 0; i < 16; i++) nonce[i] = (byte) (0xC0 + i);
    byte[] in = new byte[16 + bPubBytes.length + caSig.length];
    System.arraycopy(nonce, 0, in, 0, 16);
    System.arraycopy(bPubBytes, 0, in, 16, bPubBytes.length);
    System.arraycopy(caSig, 0, in, 16 + bPubBytes.length, caSig.length);

    assertEquals(0x9000, sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x02, 0x00, in)).getSw());
    // Same nonce again -> rejected
    assertEquals(0x6A80, sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x02, 0x00, in)).getSw());
  }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew test --console=plain --tests '*cloneExportRejectsReusedNonce*'`
Expected: FAIL — second export returns 0x9000 (no anti-replay yet).

- [ ] **Step 3: Add the nonce check in the applet**

Add field near `caPublicKey`:

```java
  private byte[] lastCloneNonce;
```

In the constructor, after `cloneZeroIv = new byte[16];`:

```java
    lastCloneNonce = new byte[CLONE_NONCE_LEN];
```

In `CLONE_P1_EXPORT`, immediately after the cert verification block (before generating the ephemeral key), add:

```java
        // Anti-replay: reject a nonce equal to the previous one, then record it
        if (Util.arrayCompare(apduBuffer, OFFSET_CDATA, lastCloneNonce, (short) 0, CLONE_NONCE_LEN) == 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        Util.arrayCopy(apduBuffer, OFFSET_CDATA, lastCloneNonce, (short) 0, CLONE_NONCE_LEN);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew test --console=plain --tests '*cloneExportRejectsReusedNonce*'` then `--tests '*clone*'`
Expected: both PASS (the end-to-end test uses a different nonce prefix `0xB0`, so it is unaffected).

- [ ] **Step 5: Commit**

```bash
git add src/main/java/im/status/keycard/KeycardApplet.java src/test/java/im/status/keycard/KeycardTest.java
git commit -m "spike(clone): reject reused nonce on CLONE_EXPORT (anti-replay)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: CLONE_IMPORT + full round-trip (C)

Card B imports the payload: ECDH with its own device private key (`SharedMemory.idPrivate`), HKDF, verify tag, AES-decrypt, `loadKeyPair`. The test plays card A, encrypting a known master key to the applet's own device pubkey (the test knows it from `initIfNeeded`), then imports and confirms the applet now holds that key.

**Files:**
- Modify: `KeycardTest.java` — store `identKeyPair` in a static field so the test can play card A; add `cloneImportRoundTripTest` and `cloneImportRejectsTamperedCtTest`
- Modify: `KeycardApplet.java` — add `CLONE_P1_IMPORT = 0x03` and its handler

**Interfaces:**
- Consumes: `SharedMemory.idPrivate` (the applet's device private key, package-private static ECPrivateKey), `loadKeyPair(byte[] apduBuffer)` (existing; parses a `TLV_KEY_TEMPLATE` with `TLV_PRIV_KEY` + `TLV_CHAIN_CODE` at `OFFSET_CDATA` and sets master key).
- Produces: `CLONE_IMPORT` (P1=0x03) input `nonce(16) ‖ e_A_pub(65) ‖ ct(64) ‖ tag(16)`; on success loads the master key and returns 0x9000 with no data; tampered tag → `SW_WRONG_DATA`.

- [ ] **Step 1: Expose the device keypair to tests**

In `KeycardTest.java`, change `initIfNeeded()` so `identKeyPair` is a static field, not a local:

Add field near `caKeyPair`:
```java
  private static KeyPair identKeyPair;
```
In `initIfNeeded()`, change `KeyPair identKeyPair = Certificate.generateIdentKeyPair();` to `identKeyPair = Certificate.generateIdentKeyPair();`.

- [ ] **Step 2: Write the failing round-trip test**

```java
  @Test
  @DisplayName("CLONE IMPORT round-trip: applet imports a master key sent by peer A")
  void cloneImportRoundTripTest() throws Exception {
    ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");

    // A known master key (masterPriv || chainCode) that peer A will send
    byte[] masterPriv = new byte[32];
    byte[] chainCode = new byte[32];
    for (int i = 0; i < 32; i++) { masterPriv[i] = (byte) (0x11 + i); chainCode[i] = (byte) (0x80 + i); }
    byte[] seed = new byte[64];
    System.arraycopy(masterPriv, 0, seed, 0, 32);
    System.arraycopy(chainCode, 0, seed, 32, 32);

    // Peer A ephemeral key; ECDH against the applet's device PUBLIC key (test knows identKeyPair)
    BigInteger aEph = new BigInteger("0a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00010203040506070809", 16);
    byte[] aEphPub = spec.getG().multiply(aEph).normalize().getEncoded(false);
    org.bouncycastle.jce.interfaces.ECPublicKey devPub = (org.bouncycastle.jce.interfaces.ECPublicKey) identKeyPair.getPublic();
    org.bouncycastle.math.ec.ECPoint shared = devPub.getQ().multiply(aEph).normalize();
    byte[] x = Numeric.toBytesPadded(shared.getAffineXCoord().toBigInteger(), 32);

    byte[] nonce = new byte[16];
    for (int i = 0; i < 16; i++) nonce[i] = (byte) (0xD0 + i);
    byte[] okm = hkdfSha256(nonce, x, "ANTFUN-CLONE-v1".getBytes(), 32);
    byte[] encKey = Arrays.copyOfRange(okm, 0, 16);
    byte[] macKey = Arrays.copyOfRange(okm, 16, 32);

    javax.crypto.Cipher aes = javax.crypto.Cipher.getInstance("AES/CBC/NoPadding", "BC");
    aes.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(encKey, "AES"),
             new javax.crypto.spec.IvParameterSpec(new byte[16]));
    byte[] ct = aes.doFinal(seed);
    byte[] tag = Arrays.copyOfRange(hmacSha256(macKey, ct), 0, 16);

    byte[] in = new byte[16 + 65 + 64 + 16];
    System.arraycopy(nonce, 0, in, 0, 16);
    System.arraycopy(aEphPub, 0, in, 16, 65);
    System.arraycopy(ct, 0, in, 81, 64);
    System.arraycopy(tag, 0, in, 145, 16);

    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    assertEquals(0x9000, sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x03, 0x00, in)).getSw());

    // The applet must now hold that master key: its key UID = sha256(uncompressed master pub)
    byte[] expectedPub = spec.getG().multiply(new BigInteger(1, masterPriv)).normalize().getEncoded(false);
    byte[] keyUID = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION).checkOK().getData();
    // getStatus returns a TLV; instead assert via a fresh SIGN's returned pubkey path is out of scope —
    // simplest: re-select and read key UID from ApplicationInfo
    byte[] info = cmdSet.select().checkOK().getData();
    byte[] uid = new ApplicationInfo(info).getKeyUID();
    assertArrayEquals(sha256(expectedPub), uid, "applet must control the imported master key");
  }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `./gradlew test --console=plain --tests '*cloneImportRoundTrip*'`
Expected: FAIL — `CLONE_IMPORT` (P1=0x03) is unhandled → `clone()` default throws `0x6A86`.

- [ ] **Step 4: Implement CLONE_IMPORT in the applet**

Add constant near the other clone P1s:
```java
  static final byte CLONE_P1_IMPORT = 0x03;
```

Add the case in `clone()` before `default:`:
```java
      case CLONE_P1_IMPORT: {
        // input = nonce(16) || e_A_pub(65) || ct(64) || tag(16)
        short ephOff = (short) (OFFSET_CDATA + CLONE_NONCE_LEN);
        short ctOff = (short) (ephOff + CLONE_PUBKEY_LEN);
        short tagOff = (short) (ctOff + CLONE_SEED_LEN);
        if (len != (short) (CLONE_NONCE_LEN + CLONE_PUBKEY_LEN + CLONE_SEED_LEN + CLONE_TAG_LEN)) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // 1) ECDH(device private key, e_A_pub) -> shared X at cloneScratch[0]
        crypto.ecdh.init(SharedMemory.idPrivate);
        crypto.ecdh.generateSecret(apduBuffer, ephOff, CLONE_PUBKEY_LEN, cloneScratch, (short) 0);
        // 2) HKDF -> OKM(32) at cloneScratch[32]; encKey=OKM[0..16], macKey=OKM[16..32]
        crypto.hkdf(apduBuffer, OFFSET_CDATA, CLONE_NONCE_LEN, cloneScratch, (short) 0, (short) 32,
                    CLONE_LABEL, (short) 0, (short) CLONE_LABEL.length, cloneScratch, (short) 32);
        // 3) verify tag = HMAC-SHA256(macKey, ct)[0..16]
        crypto.hmacSHA256(cloneScratch, (short) 48, (short) 16, apduBuffer, ctOff, CLONE_SEED_LEN, derivationOutput, (short) 0);
        if (Util.arrayCompare(derivationOutput, (short) 0, apduBuffer, tagOff, CLONE_TAG_LEN) != 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // 4) AES-CBC decrypt ct -> masterPriv(32) || chainCode(32) at cloneScratch[64]
        cloneAesKey.setKey(cloneScratch, (short) 32);
        cloneAesCbc.init(cloneAesKey, Cipher.MODE_DECRYPT, cloneZeroIv, (short) 0, (short) 16);
        cloneAesCbc.doFinal(apduBuffer, ctOff, CLONE_SEED_LEN, cloneScratch, (short) 64);
        // 5) build a TLV_KEY_TEMPLATE at OFFSET_CDATA and loadKeyPair (priv + chain code)
        short o = OFFSET_CDATA;
        apduBuffer[o++] = TLV_KEY_TEMPLATE;
        apduBuffer[o++] = (byte) (2 + 32 + 2 + CHAIN_CODE_SIZE);
        apduBuffer[o++] = TLV_PRIV_KEY;
        apduBuffer[o++] = (byte) 32;
        Util.arrayCopyNonAtomic(cloneScratch, (short) 64, apduBuffer, o, (short) 32); o += 32;
        apduBuffer[o++] = TLV_CHAIN_CODE;
        apduBuffer[o++] = (byte) CHAIN_CODE_SIZE;
        Util.arrayCopyNonAtomic(cloneScratch, (short) 96, apduBuffer, o, CHAIN_CODE_SIZE); o += CHAIN_CODE_SIZE;
        loadKeyPair(apduBuffer);
        break;
      }
```

Note: `loadKeyPair` reads its template from `OFFSET_CDATA` and calls `generateKeyUIDAndPrepareResponse`, which writes the key UID to `apduBuffer[OFFSET_CDATA]`. Because `process()` `return`s after `clone()` (no epilogue), the JCRE sends 0x9000 with no body; the test reads the UID by re-selecting. This is acceptable for the spike.

Requires PIN in production; the test opens SC + verifies PIN first. (A PIN guard can be added when clone is productionized.)

- [ ] **Step 5: Run test to verify it passes**

Run: `./gradlew test --console=plain --tests '*cloneImportRoundTrip*'`
Expected: PASS — applet's key UID equals `sha256(pub(masterPriv))`.

If it fails on `getKeyUID()` API: confirm the method name via `ApplicationInfo` (SDK). If absent, read the key UID from the SELECT response TLV `TLV_KEY_UID (0x8E)` manually.

- [ ] **Step 6: Add the tamper-rejection test**

```java
  @Test
  @DisplayName("CLONE IMPORT: reject a tampered ciphertext")
  void cloneImportRejectsTamperedCtTest() throws Exception {
    // Build a valid import payload exactly as in cloneImportRoundTripTest, then flip one ct byte.
    // (Copy the setup from cloneImportRoundTripTest up to building `in`, then:)
    // in[81] ^= 0x01;  // corrupt first ciphertext byte
    // cmdSet.autoOpenSecureChannel(); cmdSet.verifyPIN("000000");
    // assertEquals(0x6A80, sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x03, 0x00, in)).getSw());
  }
```
Fill the body by duplicating the payload-construction lines from Step 2 (do not extract a shared helper yet — keep the test self-contained), corrupt `in[81]`, and assert `0x6A80`.

- [ ] **Step 7: Run tamper test to verify it fails then passes**

The tag check from Step 4 already rejects tampering, so this test should pass immediately once written. Run: `./gradlew test --console=plain --tests '*cloneImportRejectsTampered*'` → PASS. (If it does not reject, the tag check is wrong — fix the applet, not the test.)

- [ ] **Step 8: Run all clone tests + commit**

Run: `./gradlew test --console=plain --tests '*clone*'` → all PASS.
```bash
git add src/main/java/im/status/keycard/KeycardApplet.java src/test/java/im/status/keycard/KeycardTest.java
git commit -m "spike(clone): CLONE_IMPORT (device-key ECDH + tag verify + loadKeyPair)

Completes the card-to-card clone loop: A exports authenticated to B's device
key, B imports using SharedMemory.idPrivate. Tamper-rejection covered.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Exit criteria (Phase 1 done)

- `./gradlew test --console=plain --tests '*clone*'` is green and covers: in-chip cert verify, forged-cert reject, end-to-end authenticated export, nonce anti-replay, import round-trip, tamper reject.
- Full suite is deterministic (no signTest/loadKeyTest flakes); only genuine jcardsim quirks remain.
- The clone protocol (cert-auth + ephemeral ECDH + HKDF + AEAD + anti-replay + import) is proven in the simulator, ready for Phase 2 productionization (CA at perso, PIN gating, optional OTP seal).

## Self-review notes

- Payload format is defined once and referenced by Tasks 2–4; `encKey=OKM[0..16]`, `macKey=OKM[16..32]`, `tag=HMAC-SHA256(macKey,ct)[0..16]` are consistent across export (Task 2) and import (Task 4).
- `SharedMemory.idPrivate` is the device key whose public appears in the DAK cert A verifies — export encrypts to it, import decrypts with it. Consistent.
- Known risk: `ApplicationInfo.getKeyUID()` method name (Task 4 Step 5) — fallback documented (read TLV `0x8E` from SELECT).
- Known risk: `masterPrivate.getS()` assumed to return exactly 32 bytes (already relied on by the passing end-to-end export test), so import's 32-byte private slot matches.
