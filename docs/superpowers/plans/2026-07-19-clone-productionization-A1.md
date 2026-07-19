# Clone Productionization A1 (PIN gate + getS robustness) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close the two Important findings from the clone-spike whole-branch review: gate CLONE_EXPORT/IMPORT behind PIN verification, and make the exported master-private-key layout robust to `ECPrivateKey.getS()` returning fewer than 32 bytes.

**Architecture:** Small, surgical edits to the `CLONE_P1_EXPORT` and `CLONE_P1_IMPORT` cases in `KeycardApplet.clone()`. No new commands, no format change.

**Tech Stack:** JavaCard 3.0.5 applet, jcardsim (patched, `libs/`), JUnit5, BouncyCastle. Build: OpenJDK 11.

## Global Constraints

- Build/test env: `export JAVA_HOME=/opt/homebrew/opt/openjdk@11; export PATH="/opt/homebrew/bin:$PATH"`.
- Clean signal: `./gradlew test --console=plain --tests '*clone*'` must be BUILD SUCCESSFUL. Full suite has 3 pre-existing jcardsim quirks (`getChallengeWithSecureChannelTest`, `getDataNdefSegmentationTest`, `openSecureChannelTest`) — ignore.
- PIN gate applies ONLY to CLONE_P1_EXPORT and CLONE_P1_IMPORT. Do NOT gate CLONE_P1_SET_CA or CLONE_P1_VERIFY_PEER.
- Existing clone tests already `autoOpenSecureChannel()` + `verifyPIN("000000")` before export/import, so they must keep passing unchanged.
- Branch: `clone-spike`. TDD where possible. Commit trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

---

### Task 1: PIN gate on CLONE_EXPORT and CLONE_IMPORT

**Files:**
- Modify: `src/main/java/im/status/keycard/KeycardApplet.java` — add a `pin.isValidated()` guard at the top of the `CLONE_P1_EXPORT` and `CLONE_P1_IMPORT` cases.
- Modify: `src/test/java/im/status/keycard/KeycardTest.java` — add `cloneExportRequiresPinTest`.

**Interfaces:**
- Consumes: `pin` (the applet's active `OwnerPIN` field, already used by `sign`/`loadKey`/etc.), `ISO7816.SW_CONDITIONS_NOT_SATISFIED` (0x6985).

- [ ] **Step 1: Write the failing test**

Add to `KeycardTest.java` (near the other clone tests):

```java
  @Test
  @DisplayName("CLONE EXPORT: requires PIN verification")
  void cloneExportRequiresPinTest() throws Exception {
    // Fresh applet (per @BeforeEach isolation): PIN is set but NOT verified in this session.
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

    byte[] in = new byte[16 + bPubBytes.length + caSig.length];
    for (int i = 0; i < 16; i++) in[i] = (byte) (0xE0 + i);
    System.arraycopy(bPubBytes, 0, in, 16, bPubBytes.length);
    System.arraycopy(caSig, 0, in, 16 + bPubBytes.length, caSig.length);

    // No verifyPIN in this session -> export must be refused.
    APDUResponse r = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x02, 0x00, in));
    assertEquals(0x6985, r.getSw()); // SW_CONDITIONS_NOT_SATISFIED
  }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew test --console=plain --tests '*cloneExportRequiresPin*'`
Expected: FAIL — without the guard, export proceeds and returns 0x6985 only incidentally or 0x9000 (currently it does NOT check PIN, so it will try to export; since no master key is loaded it will hit the `masterPrivate.isInitialized()` check and return 0x6985 for the WRONG reason, OR proceed — either way confirm the failure/behavior, then add the explicit guard). If it already returns 0x6985 for lack of key, still add the explicit PIN guard so the semantics are correct and ordered before the key check.

- [ ] **Step 3: Add the PIN guard**

In `KeycardApplet.java`, at the very top of the `CLONE_P1_EXPORT` case body (before the length check), add:

```java
        if (!pin.isValidated()) {
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
```

Add the identical guard at the very top of the `CLONE_P1_IMPORT` case body (before its length check).

- [ ] **Step 4: Run test + all clone tests**

Run: `./gradlew test --console=plain --tests '*cloneExportRequiresPin*'` → PASS.
Run: `./gradlew test --console=plain --tests '*clone*'` → BUILD SUCCESSFUL (all existing clone tests already verify PIN, so unaffected).

- [ ] **Step 5: Commit**

```bash
git add src/main/java/im/status/keycard/KeycardApplet.java src/test/java/im/status/keycard/KeycardTest.java
git commit -m "clone: gate CLONE_EXPORT/IMPORT behind PIN verification

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Robust master-private-key length handling in CLONE_EXPORT

`ECPrivateKey.getS()` may return fewer than 32 bytes on some real cards (private scalar with leading zero bytes). The current code assumes exactly 32, which would misalign the chain code and export a wrong key. This is a defensive fix; it is NOT triggerable on jcardsim (which always returns 32), so there is no RED test — correctness of the `< 32` branch is verified by review, and the existing round-trip test confirms the `== 32` path is unchanged.

**Files:**
- Modify: `src/main/java/im/status/keycard/KeycardApplet.java` — the plaintext-assembly step in `CLONE_P1_EXPORT`.

**Interfaces:**
- Consumes: `derivationOutput` (transient scratch, ≥32 bytes, free at this point — its earlier ephemeral-random contents are no longer needed once `ephemeralPriv` is set).

- [ ] **Step 1: Replace the master-private read with a length-robust, right-aligned copy**

In `CLONE_P1_EXPORT`, the current step 5 line is:

```java
        masterPrivate.getS(cloneScratch, (short) 64);
        Util.arrayCopyNonAtomic(masterChainCode, (short) 0, cloneScratch, (short) 96, CHAIN_CODE_SIZE);
```

Replace the `getS` line (keep the chain-code copy line unchanged) with:

```java
        // masterPrivate.getS may return < 32 bytes (leading-zero scalar) on some cards;
        // zero the 32-byte slot and right-align the returned value so the layout is always correct.
        short privLen = masterPrivate.getS(derivationOutput, (short) 0);
        Util.arrayFillNonAtomic(cloneScratch, (short) 64, (short) 32, (byte) 0);
        Util.arrayCopyNonAtomic(derivationOutput, (short) 0, cloneScratch, (short) (96 - privLen), privLen);
```

Note: `96 - privLen` right-aligns into the [64..96) slot; `derivationOutput` and `cloneScratch` are distinct buffers so there is no overlap hazard.

- [ ] **Step 2: Run the clone round-trip test (confirms the == 32 path is unchanged)**

Run: `./gradlew test --console=plain --tests '*cloneExportEndToEnd*'`
Expected: PASS (jcardsim returns privLen==32, so the slot is zeroed then fully overwritten — identical result to before).

- [ ] **Step 3: Run all clone tests**

Run: `./gradlew test --console=plain --tests '*clone*'` → BUILD SUCCESSFUL.

- [ ] **Step 4: Commit**

```bash
git add src/main/java/im/status/keycard/KeycardApplet.java
git commit -m "clone: robust master-private length handling in CLONE_EXPORT (right-align getS)

Defensive fix for real cards where ECPrivateKey.getS() returns < 32 bytes.
Not triggerable on jcardsim (always 32); round-trip test confirms no regression.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Exit criteria

- `--tests '*clone*'` green, including the new `cloneExportRequiresPinTest`.
- CLONE_EXPORT/IMPORT refuse without PIN (0x6985); with PIN, the round-trip still works.
- Master-private export is right-aligned into a zeroed 32-byte slot (robust to short `getS`).
- The two Important review findings are closed.
