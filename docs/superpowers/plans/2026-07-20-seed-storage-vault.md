# 种子存储卡 Vault 核心 Implementation Plan (spike 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 `KeycardApplet` 上加一个 PIN 门 entropy 保险库(写入/卡内生成/读回),受编译期 SKU 常量 `NO_MNEMONIC` 控制——只在种子存储 SKU 生效,冷钱包 SKU 结构上不存在。验证"卡能存 BIP-39 entropy 并 PIN 门读回"这一 make-or-break 能力。

**Architecture:** 编译期 `public static final boolean NO_MNEMONIC`(本分支 = `false` = 存储 SKU)。新增持久 `secretStore` 缓冲 + `INS_STORE_SECRET`(import/generate,PIN 门)+ `INS_EXPORT_SECRET`(PIN 门,经安全通道加密回传)。**不碰红线、不碰签名、不碰 CSK/票/clone**。测试用 `assumeFalse(NO_MNEMONIC)` 按 SKU 分流。

**Tech Stack:** JavaCard 3.0.5 applet(`KeycardApplet.java`)+ jcardsim 仿真器 + JUnit5;secured 命令经 SecureChannelV2 加密。

## Global Constraints

- 构建/测试环境:`export JAVA_HOME=/opt/homebrew/opt/openjdk@11; export PATH="/opt/homebrew/opt/openjdk@11/bin:$PATH"; ./gradlew test --console=plain`
- **INS**:`INS_STORE_SECRET = (byte) 0xDA`、`INS_EXPORT_SECRET = (byte) 0xDB`(均空闲)。
- **SKU 常量**:`public static final boolean NO_MNEMONIC = false;`(本分支构建为存储 SKU)。两条保险库命令在 `NO_MNEMONIC` 为真时 throw `SW_INS_NOT_SUPPORTED`(0x6D00)。
- **PIN 门**:STORE/EXPORT 均要求 `pin.isValidated()`,否则 `SW_CONDITIONS_NOT_SATISFIED`(0x6985)。
- **加密回传**:EXPORT 的响应必须走 `secureChannel.respond(apdu, len, SW_NO_ERROR)`(payload 建在 `OFFSET_CDATA`),**绝不明文 setOutgoingAndSend**。
- **合法 entropy 长度**:16/20/24/28/32(对应 12/15/18/21/24 词)。
- **不得触碰**:红线命令(LOAD/EXPORT_KEY/MNEMONIC 的 throw 保持不动)、`INS_SIGN`、CSK/票(CashApplet)、clone、DAK。
- **基线**:改动前 36 测试、恰好 3 个既有 jcardsim 失败(`getDataNdefSegmentationTest`、`getChallengeWithSecureChannelTest`、`openSecureChannelTest`)。每个 Task 结束后除这 3 个外全绿。
- Commit trailer:`Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

## File Structure

- `src/main/java/im/status/keycard/KeycardApplet.java` — SKU 常量 + INS/P1 常量 + `secretStore`/`secretLen` 字段 + 构造器初始化 + `processSecured` 分派 + `storeSecret()`/`exportSecret()`/`isValidEntropyLen()`。
- `src/test/java/im/status/keycard/TestKeycardCommandSet.java` — 加 `storeSecret(p1,p2,data)`、`exportSecret()` 两个 secured 发送 helper(照 `exportBIP85`/`getDataRaw` 模式)。
- `src/test/java/im/status/keycard/KeycardTest.java` — 加 vault 测试。

参考:`storeData()`(读 `OFFSET_LC`/`OFFSET_CDATA`、事务写)、`exportKey()` 结尾的 `secureChannel.respond`、`TestKeycardCommandSet.exportBIP85`(secured 自定义发送)。

---

### Task 1: SKU 常量 + entropy 保险库(import + PIN 门 + 读回)

**Files:**
- Modify: `src/main/java/im/status/keycard/KeycardApplet.java`
- Modify: `src/test/java/im/status/keycard/TestKeycardCommandSet.java`(加 helper)
- Test: `src/test/java/im/status/keycard/KeycardTest.java`(加 `vaultStoreExportTest`、`vaultPinAndLengthTest`)

**Interfaces:**
- Produces: `INS_STORE_SECRET`(P1=IMPORT,data=entropy;PIN 门)、`INS_EXPORT_SECRET`(PIN 门,加密回 entropy)。
- Consumes(test): `cmdSet.storeSecret(int p1,int p2,byte[] data)`、`cmdSet.exportSecret()`、`cmdSet.verifyPIN("000000")`、`KeycardApplet.NO_MNEMONIC`。

- [ ] **Step 1: 加 test helper** — 在 `TestKeycardCommandSet.java` 加(照 `exportBIP85` 模式):

```java
  public APDUResponse storeSecret(int p1, int p2, byte[] data) throws IOException {
    return this.getSecureChannel().transmit(channel, this.getSecureChannel().protectedCommand(0x80, KeycardApplet.INS_STORE_SECRET, p1, p2, data));
  }

  public APDUResponse exportSecret() throws IOException {
    return this.getSecureChannel().transmit(channel, this.getSecureChannel().protectedCommand(0x80, KeycardApplet.INS_EXPORT_SECRET, 0, 0, new byte[0]));
  }
```

- [ ] **Step 2: 写失败测试** — 在 `KeycardTest.java` 加(需 `import static org.junit.jupiter.api.Assumptions.assumeFalse;`,若未有):

```java
  @Test
  @DisplayName("VAULT: store(import) & export entropy round-trips, PIN-gated (seed-storage SKU)")
  void vaultStoreExportTest() throws Exception {
    assumeFalse(KeycardApplet.NO_MNEMONIC, "seed-storage SKU only");
    cmdSet.autoOpenSecureChannel();

    byte[] entropy = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"); // 32B

    // PIN gate: store before PIN -> 0x6985
    assertEquals(0x6985, cmdSet.storeSecret(KeycardApplet.STORE_SECRET_P1_IMPORT, 0, entropy).getSw());
    // PIN gate: export before PIN -> 0x6985
    assertEquals(0x6985, cmdSet.exportSecret().getSw());

    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());

    // store(import) then export -> identical
    assertEquals(0x9000, cmdSet.storeSecret(KeycardApplet.STORE_SECRET_P1_IMPORT, 0, entropy).getSw());
    APDUResponse exp = cmdSet.exportSecret();
    assertEquals(0x9000, exp.getSw());
    assertArrayEquals(entropy, exp.getData());
  }

  @Test
  @DisplayName("VAULT: invalid entropy length rejected (seed-storage SKU)")
  void vaultPinAndLengthTest() throws Exception {
    assumeFalse(KeycardApplet.NO_MNEMONIC, "seed-storage SKU only");
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());

    // 17 bytes is not a valid BIP-39 entropy length -> 0x6A80
    assertEquals(0x6A80, cmdSet.storeSecret(KeycardApplet.STORE_SECRET_P1_IMPORT, 0, new byte[17]).getSw());
    // 24 bytes IS valid -> 0x9000, and round-trips
    byte[] e24 = new byte[24];
    for (short i = 0; i < 24; i++) e24[i] = (byte) (i + 1);
    assertEquals(0x9000, cmdSet.storeSecret(KeycardApplet.STORE_SECRET_P1_IMPORT, 0, e24).getSw());
    assertArrayEquals(e24, cmdSet.exportSecret().getData());
  }
```

- [ ] **Step 3: 跑测试确认失败** — `./gradlew test --tests '*KeycardTest.vaultStoreExportTest' --console=plain` → FAIL(0xDA/0xDB 当前落到 default，行为非预期)。

- [ ] **Step 4: 改 applet — 常量与字段** — 在 `KeycardApplet.java` 加:
  - SKU 常量(类顶部,和其它 `static final` 常量一起):
    ```java
    public static final boolean NO_MNEMONIC = false; // seed-storage SKU build (true = no-mnemonic cold-wallet)
    ```
  - INS/P1 常量(挨着 INS_CLONE):
    ```java
    static final byte INS_STORE_SECRET = (byte) 0xDA;
    static final byte INS_EXPORT_SECRET = (byte) 0xDB;
    static final byte STORE_SECRET_P1_IMPORT = (byte) 0x00;
    static final byte STORE_SECRET_P1_GENERATE = (byte) 0x01;
    static final short SECRET_MAX_LEN = 32;
    ```
  - 字段(挨着其它 `private byte[]` 字段):
    ```java
    private byte[] secretStore;
    private short secretLen;
    ```

- [ ] **Step 5: 改 applet — 构造器初始化** — 在构造器里(和其它 `new byte[]` 分配一起)加:

```java
    secretStore = new byte[SECRET_MAX_LEN];
    secretLen = 0;
```

- [ ] **Step 6: 改 applet — 分派 + 方法** — 在 `processSecured` 的 switch 里(`default:` 之前)加:

```java
      case INS_STORE_SECRET:
        if (NO_MNEMONIC) ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        storeSecret(apdu);
        break;
      case INS_EXPORT_SECRET:
        if (NO_MNEMONIC) ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        exportSecret(apdu);
        break;
```

  新增方法:

```java
  private void storeSecret(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    if (!pin.isValidated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short len;
    switch (apduBuffer[OFFSET_P1]) {
      case STORE_SECRET_P1_IMPORT:
        len = Util.makeShort((byte) 0x00, apduBuffer[ISO7816.OFFSET_LC]);
        if (!isValidEntropyLen(len)) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        JCSystem.beginTransaction();
        Util.arrayCopy(apduBuffer, ISO7816.OFFSET_CDATA, secretStore, (short) 0, len);
        secretLen = len;
        JCSystem.commitTransaction();
        break;
      case STORE_SECRET_P1_GENERATE:
        len = Util.makeShort((byte) 0x00, apduBuffer[OFFSET_P2]);
        if (!isValidEntropyLen(len)) {
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        JCSystem.beginTransaction();
        crypto.random.generateData(secretStore, (short) 0, len);
        secretLen = len;
        JCSystem.commitTransaction();
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
  }

  private void exportSecret(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    if (!pin.isValidated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (secretLen == 0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    Util.arrayCopyNonAtomic(secretStore, (short) 0, apduBuffer, ISO7816.OFFSET_CDATA, secretLen);
    secureChannel.respond(apdu, secretLen, ISO7816.SW_NO_ERROR);
  }

  private boolean isValidEntropyLen(short len) {
    return len == 16 || len == 20 || len == 24 || len == 28 || len == 32;
  }
```

  说明:`crypto.random` 是既有 `RandomData`(generateMnemonic 曾用);`OFFSET_P1`/`OFFSET_P2` 为已静态导入常量(storeData 直接用)。EXPORT 走 `secureChannel.respond` → 密文回传。

- [ ] **Step 7: 跑测试确认通过** — `./gradlew test --tests '*KeycardTest.vaultStoreExportTest' --tests '*KeycardTest.vaultPinAndLengthTest' --console=plain` → PASS。

- [ ] **Step 8: 回归** — `./gradlew test --tests '*KeycardTest.noMnemonicRedLineTest' --tests '*KeycardTest.cashTapSignTest' --tests '*KeycardTest.cloneImportRoundTripTest' --console=plain` → 仍 PASS(红线/CSK/clone 未受影响)。

- [ ] **Step 9: 全量测试** — `./gradlew test --console=plain` → 除 3 个既有失败外全绿。

- [ ] **Step 10: Commit**

```bash
git add -A && git commit -m "feat: PIN-gated entropy vault (INS_STORE_SECRET/EXPORT_SECRET) + NO_MNEMONIC SKU flag

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: 卡内生成 entropy + 跨 reset 持久

**Files:**
- Test: `src/test/java/im/status/keycard/KeycardTest.java`(加 `vaultGeneratePersistTest`)
- (无 applet 改动——Task 1 已实现 GENERATE 分支;本 Task 验证生成 + 持久。)

**Interfaces:**
- Consumes: `cmdSet.storeSecret(KeycardApplet.STORE_SECRET_P1_GENERATE, 32, new byte[0])`、`resetAndSelectAndOpenSC()`(既有 helper)。

- [ ] **Step 1: 写测试**

```java
  @Test
  @DisplayName("VAULT: on-card generate produces non-zero entropy, persists across reset (seed-storage SKU)")
  void vaultGeneratePersistTest() throws Exception {
    assumeFalse(KeycardApplet.NO_MNEMONIC, "seed-storage SKU only");
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());

    // generate 32B entropy on-card (length in P2)
    assertEquals(0x9000, cmdSet.storeSecret(KeycardApplet.STORE_SECRET_P1_GENERATE, 32, new byte[0]).getSw());
    byte[] gen = cmdSet.exportSecret().getData();
    assertEquals(32, gen.length);
    boolean allZero = true;
    for (byte b : gen) if (b != 0) { allZero = false; break; }
    assertFalse(allZero, "generated entropy must not be all-zero");

    // invalid generate length (P2=17) -> 0x6A86
    assertEquals(0x6A86, cmdSet.storeSecret(KeycardApplet.STORE_SECRET_P1_GENERATE, 17, new byte[0]).getSw());
    // still holds the previous 32B secret (rejected generate did not overwrite)
    assertArrayEquals(gen, cmdSet.exportSecret().getData());

    // persist across power-cycle: reset, re-select, re-auth, export -> same
    resetAndSelectAndOpenSC();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    assertArrayEquals(gen, cmdSet.exportSecret().getData(), "entropy must persist across reset");
  }
```

- [ ] **Step 2: 跑测试确认通过** — `./gradlew test --tests '*KeycardTest.vaultGeneratePersistTest' --console=plain` → PASS(Task 1 已实现生成;若失败说明生成/持久有问题,回 Task 1)。

- [ ] **Step 3: 全量测试** — `./gradlew test --console=plain` → 除 3 个既有失败外全绿。

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "test: vault on-card entropy generation + persistence across reset

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review 备忘(计划作者)

- 覆盖设计:SKU 常量 `NO_MNEMONIC` ✓、`INS_STORE_SECRET`/`INS_EXPORT_SECRET` ✓、PIN 门(store+export)✓、加密回传(secureChannel.respond)✓、合法长度校验 ✓、import 往返 ✓、卡内生成非零 ✓、跨 reset 持久 ✓、SKU 感知(assumeFalse)✓。
- 未误伤:红线/签名/CSK/票/clone 不改;回归步骤显式跑 noMnemonicRedLine/CSK/clone ✓。
- 类型一致:`OFFSET_P1`/`OFFSET_P2`/`crypto.random`/`secureChannel.respond`/`Util.arrayCopy`/`JCSystem` 事务 均照 `storeData`/`exportKey` 既有用法 ✓;test helper 照 `exportBIP85` ✓。
- 本版之外(设计文档 §7):关掉存储 SKU 卡内签名、词表编码、多槽位、恢复 UX、私钥直存、perso、红线其它命令纳入 flag 联动。
