# CSK Tap-Signature Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Implement the hardware-independent core of the CSK tap signature (the "meeting-proof / anti-sybil" name-card signature) in the simulator: the card signs a domain-separated challenge with its in-chip CSK key and binds a persistent monotonic counter, so a clone cannot replay a static signature.

**Architecture:** Extend `CashApplet` (Keycard's independent-keypair signing applet — it already generates a keypair in-chip, exposes the public key on SELECT, and has `secp256k1.signHash`). We repurpose it as the ANTFUN name-card / CSK applet. Add one command `INS_CSK_TAP_SIGN` and a persistent monotonic counter. Byte formats (challenge length, counter width) are intentionally simple/parameterizable — real-phone NFC (B1) validation will tune them later.

**Tech Stack:** JavaCard 3.0.5 applet, jcardsim (patched, `libs/`), JUnit5, BouncyCastle. Build: OpenJDK 11.

## Global Constraints

- Build/test env: `export JAVA_HOME=/opt/homebrew/opt/openjdk@11; export PATH="/opt/homebrew/bin:$PATH"`.
- Clean signal: `./gradlew test --console=plain --tests '*cashTap*'` (new tests) and `--tests '*cash*'` (must keep the existing `cashTest` green). Full suite has 3 pre-existing jcardsim quirks — ignore.
- CSK tap-sign requires NO PIN (it is a public identity signature, like the existing `CashApplet.sign`).
- Domain-separation prefix constant: `CSK_TAP_DOMAIN = "ANTFUN-TAP-v1"` (13 bytes). The card ALWAYS hashes this prefix first, so a CSK signature is semantically unambiguous and cannot be repurposed.
- New opcode: `INS_CSK_TAP_SIGN = (byte) 0xD7`.
- ECDSA format: mirror the existing `CashApplet.sign` — it calls `secp256k1.signHash(apduBuffer[OFFSET_P2], crypto, privateKey, hashBuf, hashOff, out, outOff)`. The existing `cashTest` in `KeycardTest.java` shows the exact P2 value and how to verify a secp256k1 ECDSA signature against the applet's public key with BouncyCastle — USE `cashTest` AS THE REFERENCE for the sign-format P2 and the verification code.
- Branch: `clone-spike`. TDD. Commit trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

## Reference: existing CashApplet (`src/main/java/im/status/keycard/CashApplet.java`)
- Keypair generated in-chip in the constructor (`keypair.genKeyPair()`); `publicKey`/`privateKey` are the CSK keys.
- `process()` dispatches on INS; `selectApplet()` returns a TLV with `TLV_PUB_KEY` (the CSK public key).
- `sign(apdu)` signs the 32-byte hash at `OFFSET_CDATA` via `secp256k1.signHash(...)`.
- `crypto.sha256` is a `MessageDigest` (ALG_SHA_256) supporting `reset()/update()/doFinal()`.

---

### Task 1: INS_CSK_TAP_SIGN — sign a domain-separated challenge

The card hashes `SHA256(CSK_TAP_DOMAIN ‖ challenge)` and signs it with the CSK key. Returns the ECDSA signature. This proves "a genuine card holding this CSK private key signed this specific challenge" — a clone without the private key cannot produce it.

**Files:**
- Modify: `src/main/java/im/status/keycard/CashApplet.java` — add `INS_CSK_TAP_SIGN` constant, `CSK_TAP_DOMAIN`, a transient hash buffer, dispatch case, and `tapSign()`.
- Modify: `src/test/java/im/status/keycard/KeycardTest.java` — add `cashTapSignTest`.

**Interfaces:**
- Produces: `INS_CSK_TAP_SIGN` (CLA 0x80, INS 0xD7, P2 = same ECDSA format value the existing `cashTest` uses): input = `challenge` (opaque bytes). Output = the ECDSA signature over `SHA256(CSK_TAP_DOMAIN ‖ challenge)`.

- [ ] **Step 1: Write the failing test**

Read the existing `cashTest` in `KeycardTest.java` first to copy its applet-selection, CSK-pubkey extraction, P2 value, and ECDSA-verification pattern. Then add:

```java
  @Test
  @DisplayName("CASH CSK tap-sign: signs SHA256(domain||challenge) with the card's CSK key")
  void cashTapSignTest() throws Exception {
    CashCommandSet cashCmdSet = new CashCommandSet(sdkChannel); // or however cashTest selects the Cash applet
    // Select the Cash applet and extract its CSK public key (mirror cashTest).
    // ... obtain `ecPublicKey` (the CSK pubkey) exactly as cashTest does ...

    byte[] challenge = "hello-antfun-tap".getBytes();
    // domain-separated message the card is expected to hash:
    byte[] domain = "ANTFUN-TAP-v1".getBytes();
    byte[] toHash = new byte[domain.length + challenge.length];
    System.arraycopy(domain, 0, toHash, 0, domain.length);
    System.arraycopy(challenge, 0, toHash, domain.length, challenge.length);
    byte[] expectedHash = sha256(toHash);

    // send tap-sign (use the SAME P2 sign-format value cashTest uses for ECDSA)
    APDUResponse resp = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD7, 0x00, <P2_FROM_cashTest>, challenge));
    assertEquals(0x9000, resp.getSw());
    byte[] sig = resp.getData();

    // verify the ECDSA signature over expectedHash against the CSK pubkey (mirror cashTest's verify)
    assertTrue(verifyEcdsa(ecPublicKey, expectedHash, sig));

    // a different challenge must yield a different signature
    byte[] sig2 = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD7, 0x00, <P2_FROM_cashTest>, "different".getBytes())).getData();
    assertFalse(Arrays.equals(sig, sig2));
  }
```

Fill `<P2_FROM_cashTest>`, the pubkey extraction, and `verifyEcdsa`/`CashCommandSet` usage from the real `cashTest`. If `cashTest` verifies the signature inline (not via a helper), inline the same verification here.

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew test --console=plain --tests '*cashTapSign*'`
Expected: FAIL — INS 0xD7 is unhandled → `CashApplet.process()` default throws `SW_INS_NOT_SUPPORTED` (0x6D00).

- [ ] **Step 3: Implement in CashApplet**

Add fields/constants:
```java
  static final byte INS_CSK_TAP_SIGN = (byte) 0xD7;
  private static final byte[] CSK_TAP_DOMAIN = { 'A','N','T','F','U','N','-','T','A','P','-','v','1' };
  private byte[] tapHash;
```
In the constructor (after `keypair.genKeyPair();`):
```java
    tapHash = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
```
Add the dispatch case in `process()` before `default`:
```java
        case INS_CSK_TAP_SIGN:
          tapSign(apdu);
          break;
```
Add the method:
```java
  private void tapSign(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    short chLen = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xFF);
    // hash = SHA256(CSK_TAP_DOMAIN || challenge)
    crypto.sha256.reset();
    crypto.sha256.update(CSK_TAP_DOMAIN, (short) 0, (short) CSK_TAP_DOMAIN.length);
    crypto.sha256.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, chLen, tapHash, (short) 0);
    // sign the hash with the CSK key; write the signature at OFFSET_CDATA
    short sigLen = secp256k1.signHash(apduBuffer[OFFSET_P2], crypto, privateKey, tapHash, (short) 0, apduBuffer, ISO7816.OFFSET_CDATA);
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, sigLen);
  }
```
Note: confirm `crypto.sha256`, `secp256k1.signHash`, and the `OFFSET_P2` import are accessible in `CashApplet` (the existing `sign()` already uses `secp256k1.signHash` and `OFFSET_P2`). Confirm `signHash` reads the 32-byte hash from `tapHash[0]` and writes the DER signature at the given output offset (it does in the existing `sign()`).

- [ ] **Step 4: Run test + existing cash test**

Run: `./gradlew test --console=plain --tests '*cashTapSign*'` → PASS.
Run: `./gradlew test --console=plain --tests '*cash*'` → BUILD SUCCESSFUL (existing `cashTest` unaffected — it uses INS_SIGN, not 0xD7).

- [ ] **Step 5: Commit**

```bash
git add src/main/java/im/status/keycard/CashApplet.java src/test/java/im/status/keycard/KeycardTest.java
git commit -m "csk: INS_CSK_TAP_SIGN signs SHA256(domain||challenge) with the in-chip CSK key

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Bind a persistent monotonic counter (anti-replay depth)

The card includes a persistent, monotonically-increasing counter in BOTH the signed hash and the response, so each tap is unique and a captured signature cannot be replayed as a fresh tap.

**Files:**
- Modify: `src/main/java/im/status/keycard/CashApplet.java` — add a persistent `short tapCounter` field, increment it per tap, bind it into the hash, prepend it to the response.
- Modify: `src/test/java/im/status/keycard/KeycardTest.java` — add `cashTapCounterTest` and update `cashTapSignTest` for the new response/hash format.

**Interfaces:**
- Produces: `INS_CSK_TAP_SIGN` output becomes `counter(2, big-endian) ‖ sig`; the signed hash becomes `SHA256(CSK_TAP_DOMAIN ‖ challenge ‖ counter(2))`. The counter strictly increases across taps and persists across power cycles.

- [ ] **Step 1: Write the failing test**

```java
  @Test
  @DisplayName("CASH CSK tap-sign: binds a persistent monotonic counter")
  void cashTapCounterTest() throws Exception {
    // Select Cash applet, get CSK pubkey (mirror cashTest).
    byte[] challenge = "meeting-proof".getBytes();

    APDUResponse r1 = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD7, 0x00, <P2_FROM_cashTest>, challenge));
    assertEquals(0x9000, r1.getSw());
    int counter1 = ((r1.getData()[0] & 0xFF) << 8) | (r1.getData()[1] & 0xFF);
    byte[] sig1 = Arrays.copyOfRange(r1.getData(), 2, r1.getData().length);

    APDUResponse r2 = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD7, 0x00, <P2_FROM_cashTest>, challenge));
    int counter2 = ((r2.getData()[0] & 0xFF) << 8) | (r2.getData()[1] & 0xFF);
    assertTrue(counter2 > counter1, "counter must strictly increase");

    // sig1 must verify over SHA256(domain || challenge || counter1) — i.e. the counter is bound into the signature
    byte[] domain = "ANTFUN-TAP-v1".getBytes();
    java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
    bos.write(domain); bos.write(challenge);
    bos.write((counter1 >> 8) & 0xFF); bos.write(counter1 & 0xFF);
    assertTrue(verifyEcdsa(ecPublicKey, sha256(bos.toByteArray()), sig1));
  }
```
Also update `cashTapSignTest` from Task 1: the response is now `counter(2)||sig` and the hash includes the counter — either fold that verification into `cashTapCounterTest` and simplify `cashTapSignTest` to assert basic success, or update its expected hash/parse. Keep both tests self-contained.

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew test --console=plain --tests '*cashTapCounter*'`
Expected: FAIL — no counter in the response yet (response is bare sig; `counter2 > counter1` and the counter-bound verification fail).

- [ ] **Step 3: Implement the counter**

Add field: `private short tapCounter;` (a plain instance field is persistent in EEPROM — it survives power cycles).
Rewrite `tapSign()`:
```java
  private void tapSign(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    short chLen = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xFF);
    JCSystem.beginTransaction();
    tapCounter++;
    JCSystem.commitTransaction();
    // hash = SHA256(CSK_TAP_DOMAIN || challenge || counter(2))
    short ctrOff = (short) (ISO7816.OFFSET_CDATA + chLen);
    Util.setShort(apduBuffer, ctrOff, tapCounter);
    crypto.sha256.reset();
    crypto.sha256.update(CSK_TAP_DOMAIN, (short) 0, (short) CSK_TAP_DOMAIN.length);
    crypto.sha256.update(apduBuffer, ISO7816.OFFSET_CDATA, chLen);
    crypto.sha256.doFinal(apduBuffer, ctrOff, (short) 2, tapHash, (short) 0);
    // response = counter(2) || sig
    Util.setShort(apduBuffer, ISO7816.OFFSET_CDATA, tapCounter);
    short sigLen = secp256k1.signHash(apduBuffer[OFFSET_P2], crypto, privateKey, tapHash, (short) 0, apduBuffer, (short) (ISO7816.OFFSET_CDATA + 2));
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (2 + sigLen));
  }
```
Note: `ctrOff` writes the counter just past the challenge in the APDU buffer (scratch), used only to feed `doFinal`; it is then overwritten by the response counter at `OFFSET_CDATA`. Confirm `chLen + 2` stays within the APDU buffer (challenges are small).

- [ ] **Step 4: Run tests**

Run: `./gradlew test --console=plain --tests '*cashTap*'` → both PASS.
Run: `./gradlew test --console=plain --tests '*cash*'` → BUILD SUCCESSFUL.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/im/status/keycard/CashApplet.java src/test/java/im/status/keycard/KeycardTest.java
git commit -m "csk: bind a persistent monotonic counter into the CSK tap signature

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Exit criteria

- `--tests '*cashTap*'` green: the card signs `SHA256(domain ‖ challenge ‖ counter)` with its in-chip CSK key, the signature verifies against the CSK public key, the counter strictly increases per tap and is bound into the signature, and different challenges yield different signatures.
- Existing `cashTest` still green.
- This is the hardware-independent CSK core. Deferred to after B1 (real-phone NFC): the exact challenge byte-format (nonce/ts/ctx), serial in the payload/response, counter width, NDEF static token (flow B), and the mutual/two-card meeting-proof — see `docs/ANTFUN-Card-CSK碰卡签名协议设计.md` §6.
