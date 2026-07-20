# 无助记词红线落地 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让"种子在芯片内生成、私钥永不出芯片"从口号变成代码事实——禁用一切外部种子注入 / 私钥导出 APDU 路径,只保留芯片内 `GENERATE_KEY` 与 DAK 认证的 clone import 两条受控入口。

**Architecture:** 保留代码,在命令入口 `throw`(用户决定,便于与上游合并)。4 条整命令入口即拒;`EXPORT_KEY` 保留公钥/xpub、只拒私钥模式。内部函数 `loadKeyPair`(clone import 复用)不动。

**Tech Stack:** JavaCard 3.0.5 applet(`KeycardApplet.java`)+ jcardsim 仿真器 + JUnit5(`KeycardTest.java`),gradle。

## Global Constraints

- 构建/测试环境:`export JAVA_HOME=/opt/homebrew/opt/openjdk@11; export PATH="/opt/homebrew/opt/openjdk@11/bin:$PATH"; ./gradlew test --console=plain`
- **SW 约定**:整命令禁用 → `ISO7816.SW_INS_NOT_SUPPORTED`(0x6D00);`EXPORT_KEY` 私钥模式 → `ISO7816.SW_FUNC_NOT_SUPPORTED`(0x6A81)。
- **保留代码,不物理删除**:方法体保留,只在入口(dispatch case 或方法内分支)加 `throw`。
- **不得触碰**:`GENERATE_KEY`(0xD4)、`SIGN`、`DERIVE_KEY`、`EXPORT_KEY` 公钥/xpub、clone 全套(SET_CA/VERIFY_PEER/EXPORT/IMPORT)、CSK、内部 `loadKeyPair`。
- **基线**:改动前 29 测试 3 失败(`getDataNdefSegmentationTest`、`getChallengeWithSecureChannelTest`、`openSecureChannelTest`——jcardsim 状态字怪癖,与本改动无关,保持这 3 个失败即可,不要试图"修好"它们)。每个 Task 结束后,除这 3 个既有失败外全绿。
- `@Tag("manual")` 的 `mnemonicTest`、`signTransactionTest` 仿真器不执行;不必令其通过。按各 Task 说明加注释即可。
- Commit trailer:`Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

---

### Task 1: 禁用 EXPORT_KEY 私钥导出模式(P2=PRIVATE_AND_PUBLIC)

**背景**:`exportKey` 的 P2 分派中,`EXPORT_KEY_P2_PRIVATE_AND_PUBLIC`(0x00)当前允许在 EIP-1581 路径导出私钥(非 EIP 路径已被 0x6985 拒)。红线要求:**任何路径的私钥导出都拒**,统一返回 0x6A81。公钥(0x01)、xpub(0x02)不变。

**Files:**
- Modify: `src/main/java/im/status/keycard/KeycardApplet.java`(`exportKey` 的 P2 `switch`,约行 1276-1290)
- Test: `src/test/java/im/status/keycard/KeycardTest.java`(新增 `exportKeyPrivateBlockedTest`;改造 `signTest` 内两处私钥导出断言)

**Interfaces:**
- Consumes: `cmdSet.exportKey(byte[] path, int p1, boolean makeCurrent, byte p2)`、常量 `KeycardCommandSet.EXPORT_KEY_P2_PRIVATE_AND_PUBLIC/_PUBLIC_ONLY/_EXTENDED_PUBLIC`、`KeycardApplet.DERIVE_P1_SOURCE_MASTER`。
- Produces: 私钥导出行为 = 恒返回 0x6A81。

- [ ] **Step 1: 写失败测试** — 在 `KeycardTest.java` 现有 `@Test` 之间加入:

```java
  @Test
  @DisplayName("EXPORT KEY private mode is disabled (no-mnemonic red line)")
  void exportKeyPrivateBlockedTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    assertEquals(0x9000, cmdSet.generateKey().getSw());

    byte[] eip1581 = new byte[] {(byte) 0x80,0,0,0x2B,(byte)0x80,0,0,0x3C,(byte)0x80,0,0x06,0x2D,0,0,0,0,0,0,0,0};
    byte[] wallet  = new byte[] {(byte) 0x80,0,0,0x2B,(byte)0x80,0,0,0x3C,(byte)0x80,0,0x06,0x2D,0,0,0,0};

    // Private export blocked on EVERY path -> 0x6A81
    assertEquals(0x6A81, cmdSet.exportKey(eip1581, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false,
        KeycardCommandSet.EXPORT_KEY_P2_PRIVATE_AND_PUBLIC).getSw());
    assertEquals(0x6A81, cmdSet.exportKey(wallet, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false,
        KeycardCommandSet.EXPORT_KEY_P2_PRIVATE_AND_PUBLIC).getSw());

    // Public + xpub still work
    assertEquals(0x9000, cmdSet.exportKey(wallet, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false,
        KeycardCommandSet.EXPORT_KEY_P2_PUBLIC_ONLY).getSw());
    assertEquals(0x9000, cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false,
        KeycardCommandSet.EXPORT_KEY_P2_EXTENDED_PUBLIC).getSw());
  }
```

- [ ] **Step 2: 跑测试确认失败** — `./gradlew test --tests '*KeycardTest.exportKeyPrivateBlockedTest' --console=plain`
  预期:FAIL(EIP-1581 私钥导出当前返回 0x9000,而非 0x6A81)。

- [ ] **Step 3: 改 applet** — 在 `exportKey` 的 P2 `switch` 中,把 `EXPORT_KEY_P2_PRIVATE_AND_PUBLIC` 分支改为直接抛错:

```java
    switch (apduBuffer[OFFSET_P2]) {
      case EXPORT_KEY_P2_PRIVATE_AND_PUBLIC:
        // No-mnemonic red line: private key material must never leave the chip.
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        return;
      case EXPORT_KEY_P2_PUBLIC_ONLY:
        publicOnly = true;
        extendedPublic = false;
        break;
      case EXPORT_KEY_P2_EXTENDED_PUBLIC:
        publicOnly = true;
        extendedPublic = true;
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        return;
    }
```

  (删掉原 `PRIVATE_AND_PUBLIC` 分支里 `publicOnly=false; extendedPublic=false; break;`。`boolean publicOnly; boolean extendedPublic;` 声明保留——两个存活分支都会赋值。)

- [ ] **Step 4: 跑测试确认通过** — `./gradlew test --tests '*KeycardTest.exportKeyPrivateBlockedTest' --console=plain` → PASS。

- [ ] **Step 5: 修被打挂的 signTest** — `signTest` 内两处私钥导出断言现在会变。定位并修改(约行 1022、1026):
  - 「Export derived private key」非 EIP 路径:`assertEquals(0x6985, response.getSw());` → 改 `assertEquals(0x6A81, response.getSw());`
  - 「Export derived private key (EIP-1581 path)」:原为
    ```java
    response = cmdSet.exportKey(new byte[] {...0x00,0x00,0x00,0x00}, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, false);
    assertEquals(0x9000, response.getSw());
    keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[] {...,0x00000000}, false, false);
    ```
    改为(删掉后两行 verifyExportedKey,私钥已导不出):
    ```java
    response = cmdSet.exportKey(new byte[] {(byte) 0x80,0,0,0x2B,(byte)0x80,0,0,0x3C,(byte)0x80,0,0x06,0x2D,0,0,0,0,0,0,0,0}, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, false);
    assertEquals(0x6A81, response.getSw());
    ```

- [ ] **Step 6: 全量测试** — `./gradlew test --console=plain`
  预期:除 3 个既有 jcardsim 失败外全绿(`exportKeyPrivateBlockedTest` 通过,`signTest` 通过)。

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat: block EXPORT KEY private-export mode (no-mnemonic red line)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: 禁用 EXPORT_BIP85(0xC4)

**Files:**
- Modify: `src/main/java/im/status/keycard/KeycardApplet.java`(dispatch `case INS_EXPORT_BIP85`,约行 372)
- Test: `KeycardTest.java`(新增 `exportBip85DisabledTest`;改造 `bip85Test`)

**Interfaces:**
- Consumes: `cmdSet.exportBIP85(int p1, byte[] data)`(定义于 `TestKeycardCommandSet`)、`KeyPath`。

- [ ] **Step 1: 写失败测试**

```java
  @Test
  @DisplayName("EXPORT BIP85 is disabled (no-mnemonic red line)")
  void exportBip85DisabledTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    APDUResponse r = cmdSet.exportBIP85(64, new KeyPath("m/83696968'/0'/0'").getData());
    assertEquals(0x6D00, r.getSw());
  }
```

- [ ] **Step 2: 跑测试确认失败** — `./gradlew test --tests '*KeycardTest.exportBip85DisabledTest' --console=plain` → FAIL(当前会走到 PIN/派生逻辑,返回非 0x6D00)。

- [ ] **Step 3: 改 applet** — dispatch 中把 `case INS_EXPORT_BIP85` 的方法调用替换为抛错(方法体 `exportBIP85` 保留、变为不可达):

```java
      case INS_EXPORT_BIP85:
        // No-mnemonic red line: BIP85 sub-seed export disabled on this SKU.
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        break;
```

- [ ] **Step 4: 跑测试确认通过** → PASS。

- [ ] **Step 5: 改造旧 bip85Test** — 现有 `bip85Test`(装 key 后导出 BIP85 并比对向量)整体作废。替换其方法体为断言禁用(保留 `@Test @DisplayName("BIP85")`):

```java
  void bip85Test() throws Exception {
    cmdSet.autoOpenSecureChannel();
    // BIP85 export is disabled on the no-mnemonic SKU.
    assertEquals(0x6D00, cmdSet.exportBIP85(64, new KeyPath("m/83696968'/0'/0'").getData()).getSw());
  }
```

- [ ] **Step 6: 全量测试** → 除 3 既有失败外全绿。

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat: disable EXPORT BIP85 command (no-mnemonic red line)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: 禁用 GENERATE_MNEMONIC(0xD2)

**Files:**
- Modify: `KeycardApplet.java`(dispatch `case INS_GENERATE_MNEMONIC`,约行 345)
- Test: `KeycardTest.java`(改造 `generateMnemonicTest`)

**Interfaces:**
- Consumes: `cmdSet.generateMnemonic(int checksumSize)`。

- [ ] **Step 1: 写失败测试** — 直接改造现有 `generateMnemonicTest`,整体替换其方法体为:

```java
  void generateMnemonicTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    // GENERATE MNEMONIC is disabled: this SKU never produces BIP-39 words.
    assertEquals(0x6D00, cmdSet.generateMnemonic(4).getSw());
    assertEquals(0x6D00, cmdSet.generateMnemonic(8).getSw());
  }
```

- [ ] **Step 2: 跑测试确认失败** — `./gradlew test --tests '*KeycardTest.generateMnemonicTest' --console=plain` → FAIL(当前 `generateMnemonic(4)` 返回 0x9000)。

- [ ] **Step 3: 改 applet**

```java
      case INS_GENERATE_MNEMONIC:
        // No-mnemonic red line: this SKU never generates BIP-39 mnemonics.
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        break;
```

- [ ] **Step 4: 跑测试确认通过** → PASS。

- [ ] **Step 5: 加注释到 manual mnemonicTest** — 在 `@Tag("manual") mnemonicTest` 方法体首行加注释(不改断言,manual 不跑):
  `// NOTE: GENERATE MNEMONIC / LOAD KEY(seed) are disabled on the no-mnemonic SKU; this manual test no longer reflects shipping behavior.`

- [ ] **Step 6: 全量测试** → 除 3 既有失败外全绿。

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat: disable GENERATE MNEMONIC command (no-mnemonic red line)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: 禁用 EXPORT_LEE(0xC3)

**背景**:`EXPORT_LEE`(EIP-1581 私钥导出)。仿真器下 `leeKeysTest` 的 `exportLEEKey` 调用被 `if (TARGET != TARGET_SIMULATOR)` 跳过,故本 Task 不波及现有仿真器测试,只需新增断言。

**Files:**
- Modify: `KeycardApplet.java`(dispatch `case INS_EXPORT_LEE`,约行 360)
- Test: `KeycardTest.java`(新增 `exportLeeDisabledTest`)

**Interfaces:**
- Consumes: `cmdSet.exportLEEKey(byte[] path, int p1)`。

- [ ] **Step 1: 写失败测试**

```java
  @Test
  @DisplayName("EXPORT LEE is disabled (no-mnemonic red line)")
  void exportLeeDisabledTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    APDUResponse r = cmdSet.exportLEEKey(new byte[] {(byte) 0x80,0,0,0x2B,(byte)0x80,0,0,0x3C}, KeycardApplet.DERIVE_P1_SOURCE_MASTER);
    assertEquals(0x6D00, r.getSw());
  }
```

- [ ] **Step 2: 跑测试确认失败** — `./gradlew test --tests '*KeycardTest.exportLeeDisabledTest' --console=plain` → FAIL。

- [ ] **Step 3: 改 applet**

```java
      case INS_EXPORT_LEE:
        // No-mnemonic red line: EIP-1581 private key export disabled.
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        break;
```

- [ ] **Step 4: 跑测试确认通过** → PASS。

- [ ] **Step 5: 全量测试** → 除 3 既有失败外全绿(`leeKeysTest` 仿真器路径不受影响,仍通过)。

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: disable EXPORT LEE command (no-mnemonic red line)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: 禁用对外 LOAD_KEY(0xD0)—— 保留内部 loadKeyPair 供 clone

**背景**:最大波及面。对外 `INS_LOAD_KEY` 入口即拒;内部 `loadKeyPair`(clone import 于约行 1139 复用)**保留不动**。受影响的仿真器测试:`loadKeyTest`、`removeKeyTest`(用 loadKey 做 setup)、`signTest`(用 loadKey 灌已知向量做导出校验)、`leeKeysTest`(`loadLEEKey` 内部发 INS_LOAD_KEY)。

**Files:**
- Modify: `KeycardApplet.java`(dispatch `case INS_LOAD_KEY`,约行 342)
- Test: `KeycardTest.java`(改造 `loadKeyTest`、`removeKeyTest`、`signTest` 导出段、`leeKeysTest`;新增 `cloneImportStillWorksAfterLoadKeyDisabledTest` 无需——已有 `cloneImportRoundTripTest` 覆盖,作为回归)

**Interfaces:**
- Consumes: `cmdSet.loadKey(...)` 各重载、`cmdSet.generateKey()`、`cmdSet.exportKey(...)`、`cmdSet.signWithPath(hash, path, makeCurrent)`、`cmdSet.getKeyInitializationStatus()`。
- Produces: 对外 LOAD_KEY = 恒 0x6D00;clone import 不受影响。

- [ ] **Step 1: 写失败测试** — 新增:

```java
  @Test
  @DisplayName("LOAD KEY (external) is disabled; clone import path preserved")
  void loadKeyDisabledTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    KeyPair kp = keypairGenerator().generateKeyPair();
    // Every external LOAD KEY entry returns 0x6D00.
    assertEquals(0x6D00, cmdSet.loadKey(kp).getSw());
    assertEquals(0x6D00, cmdSet.loadKey(new byte[]{(byte)0xA1,0x02,(byte)0x80,0x00}, KeycardApplet.LOAD_KEY_P1_EC).getSw());
  }
```

- [ ] **Step 2: 跑测试确认失败** — `./gradlew test --tests '*KeycardTest.loadKeyDisabledTest' --console=plain` → FAIL(当前 loadKey 返回 0x9000)。

- [ ] **Step 3: 改 applet** — dispatch 中把 `case INS_LOAD_KEY` 的方法调用替换为抛错(方法 `loadKey` / `loadKeyPair` 均保留;`loadKeyPair` 仍被 clone import 直接调用):

```java
      case INS_LOAD_KEY:
        // No-mnemonic red line: external key/seed injection disabled.
        // Internal loadKeyPair() is retained for the DAK-authenticated clone import path.
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        break;
```

- [ ] **Step 4: 跑测试确认通过** — `loadKeyDisabledTest` PASS。

- [ ] **Step 5: 回归 clone** — `./gradlew test --tests '*KeycardTest.cloneImportRoundTripTest' --tests '*KeycardTest.cloneExportEndToEndTest' --console=plain` → 仍 PASS(证明内部 `loadKeyPair` 完好)。

- [ ] **Step 6: 改造 loadKeyTest** — 整体替换方法体为断言禁用(保留 `@Test`/`@DisplayName`/`@Capabilities`):

```java
  void loadKeyTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    KeyPair kp = keypairGenerator().generateKeyPair();
    // External LOAD KEY is disabled on the no-mnemonic SKU.
    assertEquals(0x6D00, cmdSet.loadKey(kp).getSw());
  }
```

- [ ] **Step 7: 改造 removeKeyTest** — 把 setup 从 `loadKey(keyPair)` 改为 `generateKey()`,并删掉基于 `keyPair` 的 UID 断言(改用初始化状态判断)。定位约行 767 的 `response = cmdSet.loadKey(keyPair);` 段,替换为:

```java
    response = cmdSet.generateKey();
    assertEquals(0x9000, response.getSw());
```

  删除紧随其后的 `cmdSet.select()` + `verifyKeyUID(info.getKeyUID(), (ECPublicKey) keyPair.getPublic());` 三行(生成的密钥无已知公钥可比对)。保留其余(`getKeyInitializationStatus()==true`、`removeKey()==0x9000`、之后 `==false`、`getKeyUID().length==0`)。如方法内先前有 `KeyPair keyPair = ...` 且此后不再被引用,一并删除以免未使用变量告警。

- [ ] **Step 8: 改造 `exportKey()` 测试方法**(注意:是名为 `exportKey()` 的 EXPORT KEY 测试,**不是** `signTest()`;`signTest()` 是纯 SIGN、用 `generateKey()`、本 Task 不动它)。当前 `exportKey()` 用 `loadKey(keyPair, false, chainCode)` 灌入已知 `keyPair`/`chainCode`,再用 `verifyExportedKey(..., keyPair, chainCode, ...)` 逐条比对导出向量;LOAD_KEY 禁用后无法再注入已知钥,精确向量比对失效。改为 `generateKey()` + **自洽校验**(EXPORT_KEY 公钥 == SIGN 同路径返回的公钥)。**用下面完整方法体整体替换 `exportKey()` 方法**(保留其上的 `@Test @DisplayName("EXPORT KEY command")` 注解):

```java
  void exportKey() throws Exception {
    byte[] hash = sha256("some data to sign".getBytes());
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true);
      assertEquals(0x6985, response.getSw());
      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true);
      assertEquals(0x6985, response.getSw());
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    // No-mnemonic SKU: seed is generated on-chip (external LOAD KEY disabled), so
    // no known vector can be injected. Verify export self-consistently instead.
    assertEquals(0x9000, cmdSet.generateKey().getSw());

    // Master public export == the public key SIGN returns for the same path "m".
    response = cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true);
    assertEquals(0x9000, response.getSw());
    byte[] exportedPub = extractPublicKeyFromExport(response.getData());
    byte[] signedPub = extractPublicKeyFromSignature(cmdSet.signWithPath(hash, "m", false).getData());
    assertArrayEquals(signedPub, exportedPub);

    byte[] walletPath = new byte[] {(byte) 0x80,0,0,0x2B,(byte) 0x80,0,0,0x3C,(byte) 0x80,0,0x06,0x2D,0,0,0,0};

    // Derived public export works.
    assertEquals(0x9000, cmdSet.exportKey(walletPath, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true).getSw());

    // Private export blocked on every path (red line).
    assertEquals(0x6A81, cmdSet.exportKey(walletPath, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, false).getSw());
    assertEquals(0x6A81, cmdSet.exportKey(new byte[] {(byte) 0x80,0,0,0x2B,(byte) 0x80,0,0,0x3C,(byte) 0x80,0,0x06,0x2D,0,0,0,0,0,0,0,0}, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, false).getSw());

    // Extended public (xpub) export works.
    assertEquals(0x9000, cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, KeycardCommandSet.EXPORT_KEY_P2_EXTENDED_PUBLIC).getSw());
  }
```

  这样丢弃了原先的 `verifyExportedKey` 精确比对与 alt-PIN(`"024680"`)派生段——它们依赖 loadKey 注入的已知钥,本 SKU 已不可行。保留了红线关键覆盖:**公钥/xpub 能导 + 私钥全路径拒 + 导出公钥与签名公钥自洽**。

  **新增辅助方法** `extractPublicKeyFromExport`(`extractPublicKeyFromSignature`、`sha256`、`TinyBERTLV`、`TLV_KEY_TEMPLATE`/`TLV_PUB_KEY` 均已存在于测试文件):

```java
  private byte[] extractPublicKeyFromExport(byte[] keyTemplate) {
    TinyBERTLV tlv = new TinyBERTLV(keyTemplate);
    tlv.enterConstructed(KeycardApplet.TLV_KEY_TEMPLATE);
    return tlv.readPrimitive(KeycardApplet.TLV_PUB_KEY);
  }
```

  `verifyExportedKey` 私有方法若因此无人引用,保留即可(勿删)。

- [ ] **Step 9: 改造 leeKeysTest** — `loadLEEKey(seed)` 内部发 INS_LOAD_KEY,现返回 0x6D00。整体替换方法体为断言禁用:

```java
  void leeKeysTest() throws Exception {
    byte[] seed = Mnemonic.toBinarySeed("fan empower output between game genius forest bulk party small arm shuffle", "");
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    // LOAD KEY (incl. LEE variant) is disabled on the no-mnemonic SKU.
    assertEquals(0x6D00, cmdSet.loadLEEKey(seed).getSw());
  }
```

- [ ] **Step 10: 加注释到 manual signTransactionTest** — 首行加:
  `// NOTE: relies on external LOAD KEY, disabled on the no-mnemonic SKU; manual/out-of-scope.`

- [ ] **Step 11: 全量测试** — `./gradlew test --console=plain`
  预期:除 3 个既有 jcardsim 失败外全绿。确认 `loadKeyDisabledTest`、`loadKeyTest`、`removeKeyTest`、`exportKey()`、`leeKeysTest`、所有 clone 测试通过。

- [ ] **Step 12: Commit**

```bash
git add -A && git commit -m "feat: disable external LOAD KEY; retain internal loadKeyPair for clone (no-mnemonic red line)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: 红线总验证 + CLAUDE.md 更新

**Files:**
- Modify: `CLAUDE.md`(把"to be removed"改为"已禁用,返回 SW 及测试位置")
- Test: `KeycardTest.java`(新增 `noMnemonicRedLineTest` 汇总断言,作为回归护栏)

- [ ] **Step 1: 写汇总测试**

```java
  @Test
  @DisplayName("No-mnemonic red line: no APDU path exports private key or injects external seed")
  void noMnemonicRedLineTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    assertEquals(0x9000, cmdSet.generateKey().getSw());
    byte[] p = new byte[] {(byte)0x80,0,0,0x2B,(byte)0x80,0,0,0x3C,(byte)0x80,0,0x06,0x2D,0,0,0,0};
    // Disabled whole-commands -> 0x6D00
    assertEquals(0x6D00, cmdSet.generateMnemonic(4).getSw());
    assertEquals(0x6D00, cmdSet.loadKey(keypairGenerator().generateKeyPair()).getSw());
    assertEquals(0x6D00, cmdSet.exportLEEKey(new byte[]{(byte)0x80,0,0,0x2B,(byte)0x80,0,0,0x3C}, KeycardApplet.DERIVE_P1_SOURCE_MASTER).getSw());
    assertEquals(0x6D00, cmdSet.exportBIP85(64, new KeyPath("m/83696968'/0'/0'").getData()).getSw());
    // Private export blocked -> 0x6A81; public/xpub survive
    assertEquals(0x6A81, cmdSet.exportKey(p, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, KeycardCommandSet.EXPORT_KEY_P2_PRIVATE_AND_PUBLIC).getSw());
    assertEquals(0x9000, cmdSet.exportKey(p, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true).getSw());
    // On-chip generation still works
    assertTrue(cmdSet.getKeyInitializationStatus());
  }
```

- [ ] **Step 2: 跑测试确认通过**(前序 Task 已实现全部行为)— `./gradlew test --tests '*KeycardTest.noMnemonicRedLineTest' --console=plain` → PASS。若某条失败,回到对应 Task 修正。

- [ ] **Step 3: 更新 CLAUDE.md** — 把方向段中 “`GENERATE_MNEMONIC` / `LOAD_KEY(SEED)` / `EXPORT_BIP85` / EIP-1581 private export are to be removed on our SKU” 改为:

```
- **No-mnemonic red line enforced in code.** External seed/private-key export APDUs are
  disabled: GENERATE_MNEMONIC / external LOAD_KEY / EXPORT_LEE / EXPORT_BIP85 return
  0x6D00; EXPORT_KEY private mode returns 0x6A81. Public/xpub export, GENERATE_KEY, and
  the internal loadKeyPair (clone import) are retained. Regression guard:
  KeycardTest.noMnemonicRedLineTest.
```

- [ ] **Step 4: 全量测试** → 除 3 既有失败外全绿。

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "test+docs: no-mnemonic red-line regression guard + CLAUDE.md update

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review 备忘(计划作者)

- 覆盖:5 条红线命令全部处理(GENERATE_MNEMONIC/LOAD_KEY/EXPORT_LEE/EXPORT_BIP85 → 0x6D00;EXPORT_KEY 私钥 → 0x6A81)。✓
- 保留项未被误伤:GENERATE_KEY、SIGN、DERIVE_KEY、EXPORT_KEY 公钥/xpub、clone(内部 loadKeyPair)。✓
- 受影响测试全部有改造步骤:exportKeyPrivate(signTest)、bip85Test、generateMnemonicTest、loadKeyTest、removeKeyTest、signTest 导出段、leeKeysTest。manual 测试仅加注释。✓
- 类型一致:`extractPublicKeyFromExport` 若缺则新增;`extractPublicKeyFromSignature` 复用既有。✓
- 每个 Task 结束"除 3 既有失败外全绿"。✓
