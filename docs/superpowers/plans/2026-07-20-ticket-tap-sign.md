# Ticket 碰卡核销核心 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 `CashApplet` 上加一条独立 TSK 密钥的碰卡核销活签名 `INS_TICKET_TAP_SIGN`,证明"真卡本人在场核销某场票",与 CSK/资产/DAK 密钥严格隔离。

**Architecture:** CSK 碰卡签名的孪生——同一挑战-响应骨架,换域前缀 `ANTFUN-TICKET-v1`、换独立 TSK 密钥对、换独立单调计数器 `ticketCounter`。在线权威:卡不存活动数据,eventId 由 App 放进 challenge、随签名绑定;serial(perso 时值)与确切字节格式留到 B1。响应带 TSK 公钥,供服务端登记 TSK↔serial 与验签。

**Tech Stack:** JavaCard 3.0.5 applet(`CashApplet.java`)+ jcardsim 仿真器 + JUnit5(`KeycardTest.java`),secp256k1(`SECP256k1.signHash`)。

## Global Constraints

- 构建/测试环境:`export JAVA_HOME=/opt/homebrew/opt/openjdk@11; export PATH="/opt/homebrew/opt/openjdk@11/bin:$PATH"; ./gradlew test --console=plain`
- **INS**:`INS_TICKET_TAP_SIGN = (byte) 0xD8`(0xD7 是 CSK,勿冲突)。
- **域前缀**:`TICKET_TAP_DOMAIN = "ANTFUN-TICKET-v1"`(与 CSK 的 `ANTFUN-TAP-v1` 不同)。
- **密钥隔离**:TSK 是**独立的新 keypair**,不复用 cash/CSK 的 `keypair`,也不碰资产/DAK。独立持久计数器 `ticketCounter`(≠ `tapCounter`)。
- **签名内容**:`SHA256("ANTFUN-TICKET-v1" ‖ challenge ‖ ticketCounter(2))`,challenge 是 App 送来的原始字节(内含 eventId‖nonce)。
- **响应**:`TSK_pubkey(65) ‖ ticketCounter(2) ‖ sig(DER)`。
- **不得触碰**:CSK `tapSign`/`INS_CSK_TAP_SIGN`、cash `sign`/`INS_SIGN`、钱包 applet、clone、DAK。
- **基线**:改动前 34 测试、恰好 3 个既有 jcardsim 失败(`getDataNdefSegmentationTest`、`getChallengeWithSecureChannelTest`、`openSecureChannelTest`)。每个 Task 结束后除这 3 个外全绿,不要试图修它们。
- Commit trailer:`Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

## File Structure

- `src/main/java/im/status/keycard/CashApplet.java` — 加 TSK keypair 字段 + 构造器内生成 + `INS_TICKET_TAP_SIGN` 常量/域常量 + `process()` 分派 + `ticketSign()`。
- `src/test/java/im/status/keycard/KeycardTest.java` — 加 `ticketTapSignTest`(Task 1)、`ticketTapCounterTest`(Task 2)。

参考既有 CSK 实现:`CashApplet.java` 的 `tapSign()`(约行 151)与字段(`tapHash` 行 21、`tapCounter` 行 22);测试参考 `cashTapSignTest`(约行 1161)、`cashTapCounterTest`(约行 1209)。TSK 公钥常量 `Crypto.KEY_PUB_SIZE`(=65)已存在(cash `sign` 用它)。

---

### Task 1: 独立 TSK 密钥 + INS_TICKET_TAP_SIGN 核销签名

**Files:**
- Modify: `src/main/java/im/status/keycard/CashApplet.java`
- Test: `src/test/java/im/status/keycard/KeycardTest.java`(新增 `ticketTapSignTest`)

**Interfaces:**
- Consumes: `sdkChannel.send(new APDUCommand(0x80, (byte)0xD8, 0x00, KeycardCommandSet.SIGN_P2_ECDSA, challenge))`;`CashCommandSet.select()` → `CashApplicationInfo.getPubKey()`(cash/CSK 公钥,用于隔离对比);`SECP256k1.signHash`、`Crypto.KEY_PUB_SIZE`。
- Produces: `INS_TICKET_TAP_SIGN` 响应 = `TSK_pubkey(65) ‖ ticketCounter(2) ‖ sig`。

- [ ] **Step 1: 写失败测试** — 在 `KeycardTest.java` 新增(放在 `cashTapCounterTest` 之后):

```java
  @Test
  @DisplayName("TICKET tap-sign: independent TSK key signs SHA256(domain||challenge||counter), isolated from CSK/cash key")
  void ticketTapSignTest() throws Exception {
    CashCommandSet cashCmdSet = new CashCommandSet(sdkChannel);
    APDUResponse sel = cashCmdSet.select();
    assertEquals(0x9000, sel.getSw());
    byte[] cashPubData = new CashApplicationInfo(sel.getData()).getPubKey(); // cash/CSK key

    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

    // challenge carries eventId||nonce (opaque bytes to the card in this core version)
    byte[] challenge = "event-BKK2026|nonce-abc123".getBytes();
    byte[] domain = "ANTFUN-TICKET-v1".getBytes();

    APDUResponse resp = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD8, 0x00, KeycardCommandSet.SIGN_P2_ECDSA, challenge));
    assertEquals(0x9000, resp.getSw());
    byte[] data = resp.getData();
    assertTrue(data.length > 67, "response must be pubkey(65)||counter(2)||sig");

    byte[] tskPub = Arrays.copyOfRange(data, 0, 65);
    int counter = ((data[65] & 0xFF) << 8) | (data[66] & 0xFF);
    byte[] sig = Arrays.copyOfRange(data, 67, data.length);

    // TSK pubkey must be a valid secp256k1 point AND different from the cash/CSK pubkey (key isolation)
    assertFalse(Arrays.equals(tskPub, cashPubData), "TSK key must be independent from cash/CSK key");
    ECPublicKey tskKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC")
        .generatePublic(new ECPublicKeySpec(ecSpec.getCurve().decodePoint(tskPub), ecSpec));

    // sig verifies over SHA256(domain||challenge||counter) against the TSK pubkey
    byte[] toHash = new byte[domain.length + challenge.length + 2];
    System.arraycopy(domain, 0, toHash, 0, domain.length);
    System.arraycopy(challenge, 0, toHash, domain.length, challenge.length);
    toHash[domain.length + challenge.length] = (byte) ((counter >> 8) & 0xFF);
    toHash[domain.length + challenge.length + 1] = (byte) (counter & 0xFF);
    Signature v = Signature.getInstance("SHA256withECDSA", "BC");
    v.initVerify(tskKey);
    v.update(toHash);
    assertTrue(v.verify(sig), "ticket sig must verify against the TSK pubkey");

    // isolation: the ticket sig must NOT verify against the cash/CSK pubkey
    ECPublicKey cashKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC")
        .generatePublic(new ECPublicKeySpec(ecSpec.getCurve().decodePoint(cashPubData), ecSpec));
    Signature v2 = Signature.getInstance("SHA256withECDSA", "BC");
    v2.initVerify(cashKey);
    v2.update(toHash);
    assertFalse(v2.verify(sig), "ticket sig must not verify against the cash/CSK key");

    // a different eventId (different challenge) must yield a different signature
    byte[] resp2 = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD8, 0x00, KeycardCommandSet.SIGN_P2_ECDSA, "event-DXB2026|nonce-abc123".getBytes())).getData();
    byte[] sig2 = Arrays.copyOfRange(resp2, 67, resp2.length);
    assertFalse(Arrays.equals(sig, sig2), "different eventId must yield a different signature");
  }
```

- [ ] **Step 2: 跑测试确认失败** — `./gradlew test --tests '*KeycardTest.ticketTapSignTest' --console=plain`
  预期:FAIL(`0xD8` 当前未支持,SELECT/发送返回非 0x9000 或响应无法解析)。

- [ ] **Step 3: 改 applet — 加 TSK 密钥字段与常量** — 在 `CashApplet.java` 中:
  - 常量(挨着 `INS_CSK_TAP_SIGN`/`CSK_TAP_DOMAIN`):
    ```java
    static final byte INS_TICKET_TAP_SIGN = (byte) 0xD8;
    private static final byte[] TICKET_TAP_DOMAIN = { 'A','N','T','F','U','N','-','T','I','C','K','E','T','-','v','1' };
    ```
  - 字段(挨着 `keypair`/`tapCounter`):
    ```java
    private KeyPair ticketKeypair;
    private ECPublicKey ticketPublicKey;
    private ECPrivateKey ticketPrivateKey;
    private short ticketCounter;
    ```

- [ ] **Step 4: 改 applet — 构造器内生成 TSK 密钥** — 在构造器里(现有 `keypair.genKeyPair();` 之后、`tapHash = ...` 附近)加:

```java
    ticketKeypair = new KeyPair(KeyPair.ALG_EC_FP, SECP256k1.SECP256K1_KEY_SIZE);
    ticketPublicKey = (ECPublicKey) ticketKeypair.getPublic();
    ticketPrivateKey = (ECPrivateKey) ticketKeypair.getPrivate();
    SECP256k1.setCurveParameters(ticketPublicKey);
    SECP256k1.setCurveParameters(ticketPrivateKey);
    ticketKeypair.genKeyPair();
```

- [ ] **Step 5: 改 applet — 分派 + ticketSign()** — 在 `process()` 的 switch 里,`case INS_CSK_TAP_SIGN` 之后加:

```java
        case INS_TICKET_TAP_SIGN:
          ticketSign(apdu);
          break;
```

  新增方法(照 `tapSign` 写,换域/密钥/计数器,响应加 TSK 公钥):

```java
  private void ticketSign(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    short chLen = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xFF);
    JCSystem.beginTransaction();
    ticketCounter++;
    JCSystem.commitTransaction();
    // hash = SHA256(TICKET_TAP_DOMAIN || challenge || counter(2))
    short ctrOff = (short) (ISO7816.OFFSET_CDATA + chLen);
    Util.setShort(apduBuffer, ctrOff, ticketCounter);
    crypto.sha256.reset();
    crypto.sha256.update(TICKET_TAP_DOMAIN, (short) 0, (short) TICKET_TAP_DOMAIN.length);
    crypto.sha256.update(apduBuffer, ISO7816.OFFSET_CDATA, chLen);
    crypto.sha256.doFinal(apduBuffer, ctrOff, (short) 2, tapHash, (short) 0);
    // response = TSK_pubkey(65) || counter(2) || sig   (challenge already consumed into the hash)
    short pubLen = ticketPublicKey.getW(apduBuffer, ISO7816.OFFSET_CDATA);
    short ctrRespOff = (short) (ISO7816.OFFSET_CDATA + pubLen);
    Util.setShort(apduBuffer, ctrRespOff, ticketCounter);
    short sigLen = secp256k1.signHash(apduBuffer[OFFSET_P2], crypto, ticketPrivateKey, tapHash, (short) 0, apduBuffer, (short) (ctrRespOff + 2));
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (pubLen + 2 + sigLen));
  }
```

  说明:`tapHash` 是既有的瞬态 32 字节 scratch,单 APDU 内用完即弃,ticket 复用无隔离风险(隔离由**独立密钥**保证)。写 65 字节公钥到 `OFFSET_CDATA` 会覆盖 challenge,但此时 challenge 已被哈希消费,安全。

- [ ] **Step 6: 跑测试确认通过** — `./gradlew test --tests '*KeycardTest.ticketTapSignTest' --console=plain` → PASS。

- [ ] **Step 7: 回归 CSK** — `./gradlew test --tests '*KeycardTest.cashTapSignTest' --tests '*KeycardTest.cashTapCounterTest' --tests '*KeycardTest.cashTest' --console=plain` → 仍 PASS(证明未碰 CSK/cash)。

- [ ] **Step 8: 全量测试** — `./gradlew test --console=plain` → 除 3 个既有失败外全绿。

- [ ] **Step 9: Commit**

```bash
git add -A && git commit -m "feat: ticket tap-sign with independent TSK key (INS_TICKET_TAP_SIGN)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: ticketCounter 单调 + 绑进签名(防重放纵深)

**Files:**
- Test: `src/test/java/im/status/keycard/KeycardTest.java`(新增 `ticketTapCounterTest`)
- (无 applet 改动——Task 1 已实现计数器;本 Task 用负控测试锁死"counter 真进了签名"。)

**Interfaces:**
- Consumes: 同 Task 1 的 `INS_TICKET_TAP_SIGN` 响应 `pubkey(65)‖counter(2)‖sig`。

- [ ] **Step 1: 写测试** — 新增(放在 `ticketTapSignTest` 之后):

```java
  @Test
  @DisplayName("TICKET tap-sign: persistent monotonic counter is bound into the signature")
  void ticketTapCounterTest() throws Exception {
    new CashCommandSet(sdkChannel).select();
    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    byte[] domain = "ANTFUN-TICKET-v1".getBytes();
    byte[] challenge = "event-BKK2026|checkin".getBytes();

    APDUResponse r1 = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD8, 0x00, KeycardCommandSet.SIGN_P2_ECDSA, challenge));
    assertEquals(0x9000, r1.getSw());
    byte[] d1 = r1.getData();
    byte[] tskPub = Arrays.copyOfRange(d1, 0, 65);
    int counter1 = ((d1[65] & 0xFF) << 8) | (d1[66] & 0xFF);
    byte[] sig1 = Arrays.copyOfRange(d1, 67, d1.length);

    APDUResponse r2 = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD8, 0x00, KeycardCommandSet.SIGN_P2_ECDSA, challenge));
    byte[] d2 = r2.getData();
    int counter2 = ((d2[65] & 0xFF) << 8) | (d2[66] & 0xFF);
    assertTrue(counter2 > counter1, "ticket counter must strictly increase");

    ECPublicKey tskKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC")
        .generatePublic(new ECPublicKeySpec(ecSpec.getCurve().decodePoint(tskPub), ecSpec));

    // sig1 verifies over the pre-image bound to counter1
    ByteArrayOutputStream ok = new ByteArrayOutputStream();
    ok.write(domain); ok.write(challenge);
    ok.write((counter1 >> 8) & 0xFF); ok.write(counter1 & 0xFF);
    Signature s1 = Signature.getInstance("SHA256withECDSA", "BC");
    s1.initVerify(tskKey); s1.update(ok.toByteArray());
    assertTrue(s1.verify(sig1), "sig1 must verify against the pre-image bound to counter1");

    // negative control: sig1 must NOT verify against a pre-image using counter2
    ByteArrayOutputStream bad = new ByteArrayOutputStream();
    bad.write(domain); bad.write(challenge);
    bad.write((counter2 >> 8) & 0xFF); bad.write(counter2 & 0xFF);
    Signature s2 = Signature.getInstance("SHA256withECDSA", "BC");
    s2.initVerify(tskKey); s2.update(bad.toByteArray());
    assertFalse(s2.verify(sig1), "sig1 must not verify against a pre-image built with a different counter");
  }
```

- [ ] **Step 2: 跑测试确认通过** — `./gradlew test --tests '*KeycardTest.ticketTapCounterTest' --console=plain` → PASS(Task 1 已实现计数器,应直接通过;若失败说明 counter 未真正进签名,回 Task 1 修)。

- [ ] **Step 3: 全量测试** — `./gradlew test --console=plain` → 除 3 个既有失败外全绿。

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "test: ticket tap-sign monotonic counter bound into signature (negative control)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review 备忘(计划作者)

- 覆盖设计:独立 TSK 密钥 ✓、`INS_TICKET_TAP_SIGN=0xD8` ✓、域 `ANTFUN-TICKET-v1` ✓、独立 `ticketCounter` ✓、响应 `pubkey‖counter‖sig` ✓、eventId 经 challenge 绑定 ✓、密钥隔离测试(TSK≠cash 且 sig 不对 cash 验通)✓、counter 负控 ✓。
- 未误伤:CSK/cash sign/钱包/clone 不改;回归步骤显式跑 CSK ✓。
- 类型一致:`Crypto.KEY_PUB_SIZE`/`SECP256k1.SECP256K1_KEY_SIZE`/`SECP256k1.setCurveParameters`/`secp256k1.signHash` 均照既有 `tapSign`/`sign` 用法 ✓。
- 本版之外(不做):serial 进 payload、eventId/nonce/ctx 字节格式、counter 位宽、tier/权限、离线 blob、服务端、perso —— 已在设计文档 §7 记录。
