# Clone 防重放加固 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 clone 防重放从"单 nonce 比对"升级为 EXPORT/IMPORT **各自独立的 32-bit 单调计数器门**,堵死双 nonce 交替攻击、补上 IMPORT 侧缺口、消除全零初值误判。

**Architecture:** host 在 16 字节 nonce 的**高 4 字节**放单调递增 counter;卡要求 `incoming > stored`(无符号大端比较),否则拒,通过则覆盖。EXPORT 用 `exportCounter`、IMPORT 用 `importCounter`,各管一方向。完整 16 字节 nonce 仍作 HKDF salt(不变)。

**Tech Stack:** JavaCard 3.0.5(`KeycardApplet.java`)+ jcardsim + JUnit5。

## Global Constraints

- 构建/测试:`export JAVA_HOME=/opt/homebrew/opt/openjdk@11; export PATH="/opt/homebrew/opt/openjdk@11/bin:$PATH"; ./gradlew test --console=plain`
- **计数器**:`byte[4]`,无符号大端,**严格递增**(`incoming > stored`);不做加法,只"比较 + 覆盖"(事务内)。
- **HKDF/AEAD/CA 验签/ECDH/loadKeyPair/PIN 门 全不动**,只在 EXPORT/IMPORT 入口加计数器门。
- **IMPORT 计数器门放在 tag 验证成功之后**(伪造/损坏包先被 tag 拒,不推进计数器)。
- 移除 `lastCloneNonce` 字段(被 `exportCounter` 取代)。
- **不得触碰**:CSK/票(CashApplet)、红线、钱包签名。
- **基线**:改动前 36 测试、恰好 3 个既有 jcardsim 失败(`getDataNdefSegmentationTest`、`getChallengeWithSecureChannelTest`、`openSecureChannelTest`)。每 Task 结束后除这 3 个外全绿。
- Commit trailer:`Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

## File Structure

- `src/main/java/im/status/keycard/KeycardApplet.java` — 替换 `lastCloneNonce` 为 `exportCounter`/`importCounter`;加 `counterStrictlyGreater()` 辅助;EXPORT 替换比对逻辑、IMPORT 新增门。
- `src/test/java/im/status/keycard/KeycardTest.java` — 新增/更新 clone 防重放测试。

参考现有测试的 clone 输入构造(证书/CA/ECDH):`cloneExportRejectsReusedNonceTest`(约行 1834)、`cloneImportRoundTripTest`(约行 1865)。nonce 为 `byte[16]`,高 4 字节即 counter。

---

### Task 1: EXPORT 侧单调计数器门

**Files:**
- Modify: `src/main/java/im/status/keycard/KeycardApplet.java`
- Test: `src/test/java/im/status/keycard/KeycardTest.java`

**Interfaces:**
- Produces: EXPORT 要求 nonce 高 4 字节 counter 严格递增,否则 `SW_WRONG_DATA`。

- [ ] **Step 1: 写失败测试** — 新增(模仿 `cloneExportRejectsReusedNonceTest` 的证书/CA/输入构造,只改 nonce 高 4 字节 counter;把复用的构造抽成本地小工具或直接复制该测试的 setup):

```java
  @Test
  @DisplayName("CLONE EXPORT: reject a non-increasing counter (blocks alternating-nonce replay)")
  void cloneExportRejectsNonMonotonicCounterTest() throws Exception {
    // --- reuse the exact peer-cert + CA + CLONE_P1_SET_CA setup from cloneExportRejectsReusedNonceTest ---
    // (provision CA, build peerPub + CA signature `cert`)
    // helper: build a 16-byte nonce whose high 4 bytes encode `c` (big-endian), low 12 bytes fixed.
    // byte[] nonce = cloneNonce(c);
    // byte[] in = nonce(16) || peerPub(65) || CA-sig

    // counter = 5 -> OK
    assertEquals(0x9000, cloneExport(cloneNonce(5), peerPub, caSig).getSw());
    // counter = 10 -> OK (strictly greater)
    assertEquals(0x9000, cloneExport(cloneNonce(10), peerPub, caSig).getSw());
    // counter = 7 (between, but < 10) -> rejected: this is exactly the alternating-nonce attack
    assertEquals(0x6A80, cloneExport(cloneNonce(7), peerPub, caSig).getSw());
    // counter = 10 again (equal) -> rejected
    assertEquals(0x6A80, cloneExport(cloneNonce(10), peerPub, caSig).getSw());
  }
```

  其中 `cloneNonce(int c)` 与 `cloneExport(...)` 是本测试类内的小工具:
```java
  private byte[] cloneNonce(int c) {
    byte[] n = new byte[16];
    n[0] = (byte) ((c >> 24) & 0xFF); n[1] = (byte) ((c >> 16) & 0xFF);
    n[2] = (byte) ((c >> 8) & 0xFF);  n[3] = (byte) (c & 0xFF);
    for (int i = 4; i < 16; i++) n[i] = (byte) i; // fixed low bytes
    return n;
  }
  private APDUResponse cloneExport(byte[] nonce, byte[] peerPub, byte[] caSig) throws Exception {
    byte[] in = new byte[16 + peerPub.length + caSig.length];
    System.arraycopy(nonce, 0, in, 0, 16);
    System.arraycopy(peerPub, 0, in, 16, peerPub.length);
    System.arraycopy(caSig, 0, in, 16 + peerPub.length, caSig.length);
    return sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x02, 0x00, in));
  }
```
  注:`SW_WRONG_DATA` = 0x6A80(clone 用它表示拒绝)。`0x02` = `CLONE_P1_EXPORT`。CA 供应与 peerPub/caSig 生成照 `cloneExportRejectsReusedNonceTest` 的前半段(需先 `verifyPIN` + 供应 CA)。

- [ ] **Step 2: 跑测试确认失败** — `./gradlew test --tests '*KeycardTest.cloneExportRejectsNonMonotonicCounterTest' --console=plain`
  预期:FAIL(旧逻辑只比"上一个 nonce",counter=7 与上一个(10-nonce)不同 → 旧逻辑放行,得 0x9000 而非 0x6A80)。

- [ ] **Step 3: 改 applet — 字段** — 把 `private byte[] lastCloneNonce;` 替换为:
```java
  private byte[] exportCounter;
  private byte[] importCounter;
```
  构造器里把 `lastCloneNonce = new byte[CLONE_NONCE_LEN];` 替换为:
```java
    exportCounter = new byte[4];
    importCounter = new byte[4];
```
  (`new byte[4]` 零填充 = 初值 0。)

- [ ] **Step 4: 改 applet — 辅助方法** — 加(放在 clone 相关方法附近):
```java
  private boolean counterStrictlyGreater(byte[] buf, short off, byte[] stored) {
    for (short i = 0; i < 4; i++) {
      short a = (short) (buf[(short) (off + i)] & 0xFF);
      short b = (short) (stored[i] & 0xFF);
      if (a > b) return true;
      if (a < b) return false;
    }
    return false; // equal -> not strictly greater
  }
```

- [ ] **Step 5: 改 applet — EXPORT 门** — 在 `CLONE_P1_EXPORT` 里,把现有:
```java
        // Anti-replay: reject a nonce equal to the previous one, then record it
        if (Util.arrayCompare(apduBuffer, OFFSET_CDATA, lastCloneNonce, (short) 0, CLONE_NONCE_LEN) == 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        Util.arrayCopy(apduBuffer, OFFSET_CDATA, lastCloneNonce, (short) 0, CLONE_NONCE_LEN);
```
  替换为:
```java
        // Anti-replay: require a strictly increasing 32-bit counter in the nonce's high 4 bytes.
        if (!counterStrictlyGreater(apduBuffer, OFFSET_CDATA, exportCounter)) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        JCSystem.beginTransaction();
        Util.arrayCopy(apduBuffer, OFFSET_CDATA, exportCounter, (short) 0, (short) 4);
        JCSystem.commitTransaction();
```

- [ ] **Step 6: 跑测试确认通过** — Step 1 测试 → PASS。

- [ ] **Step 7: 更新既有 EXPORT 测试** — 确认 `cloneExportRejectsReusedNonceTest`(同 nonce 两次 → 第二次 counter 不递增 → 仍 0x6A80)与 `cloneExportEndToEndTest`(单次或递增 counter)仍通过;若某测试做**多次成功 EXPORT 且高 4 字节非递增**,把其 nonce 高 4 字节改成递增。运行 `./gradlew test --tests '*KeycardTest.clone*' --console=plain` 核对。

- [ ] **Step 8: 全量测试** — `./gradlew test --console=plain` → 除 3 个既有失败外全绿。

- [ ] **Step 9: Commit**
```bash
git add -A && git commit -m "feat: clone EXPORT monotonic counter (blocks alternating-nonce replay)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: IMPORT 侧单调计数器门 + 持久性验证

**Files:**
- Modify: `src/main/java/im/status/keycard/KeycardApplet.java`(IMPORT 门)
- Test: `src/test/java/im/status/keycard/KeycardTest.java`

**Interfaces:**
- Produces: IMPORT 要求 nonce 高 4 字节 counter 严格递增(独立于 export),tag 验证之后判定。

- [ ] **Step 1: 写失败测试** — 新增(模仿 `cloneImportRoundTripTest` 构造有效密文包;counter 在 nonce 高 4 字节):

```java
  @Test
  @DisplayName("CLONE IMPORT: reject replay of a valid package; accept a higher-counter package")
  void cloneImportRejectsReplayTest() throws Exception {
    // reuse cloneImportRoundTripTest's package construction (ECDH with device key, HKDF, AES-CBC, HMAC tag),
    // parameterized by a nonce built via cloneNonce(c).
    // pkgA uses cloneNonce(3); pkgB uses cloneNonce(4). Both are cryptographically valid.

    assertEquals(0x9000, cloneImport(pkgA_counter3).getSw());     // first import OK
    assertEquals(0x6A80, cloneImport(pkgA_counter3).getSw());     // same package again -> replay rejected
    assertEquals(0x9000, cloneImport(pkgB_counter4).getSw());     // higher counter -> OK
  }

  @Test
  @DisplayName("CLONE IMPORT: counter persists across reset")
  void cloneImportCounterPersistsTest() throws Exception {
    assertEquals(0x9000, cloneImport(pkg_counter7).getSw());
    resetAndSelectAndOpenSC();
    verifyPIN("000000");
    assertEquals(0x6A80, cloneImport(pkg_counter7).getSw());      // same counter after reset -> rejected (persisted)
    assertEquals(0x9000, cloneImport(pkg_counter8).getSw());      // higher -> OK
  }
```
  实现者据 `cloneImportRoundTripTest` 抽一个 `buildImportPackage(int counter)` 本地工具(用 `cloneNonce(counter)` 作 nonce,其余按现有 HKDF/AES/HMAC 构造),`cloneImport(pkg)` = `sdkChannel.send(new APDUCommand(0x80,(byte)0xD6,0x03,0x00,pkg))`(`0x03`=`CLONE_P1_IMPORT`)。

- [ ] **Step 2: 跑测试确认失败** — `./gradlew test --tests '*KeycardTest.cloneImportRejectsReplayTest' --console=plain`
  预期:FAIL(IMPORT 侧当前无防重放,同包第二次导入返回 0x9000 而非 0x6A80)。

- [ ] **Step 3: 改 applet — IMPORT 门** — 在 `CLONE_P1_IMPORT` 中,**tag 验证成功之后、构建 TLV / `loadKeyPair` 之前**加:
```java
        // Anti-replay: require a strictly increasing 32-bit counter (independent of export).
        if (!counterStrictlyGreater(apduBuffer, OFFSET_CDATA, importCounter)) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        JCSystem.beginTransaction();
        Util.arrayCopy(apduBuffer, OFFSET_CDATA, importCounter, (short) 0, (short) 4);
        JCSystem.commitTransaction();
```
  (紧接在 `if (Util.arrayCompare(derivationOutput, ..., tagOff, CLONE_TAG_LEN) != 0) throwIt` 那段之后。)

- [ ] **Step 4: 跑测试确认通过** — Step 1 两个测试 → PASS。

- [ ] **Step 5: 回归** — `./gradlew test --tests '*KeycardTest.cloneImportRoundTripTest' --tests '*KeycardTest.cloneImportRejectsTamperedCtTest' --tests '*KeycardTest.cloneExportEndToEndTest' --console=plain` → 仍 PASS(注:`cloneImportRoundTripTest` 单次导入,counter>0,通过)。

- [ ] **Step 6: 全量测试** — `./gradlew test --console=plain` → 除 3 个既有失败外全绿。

- [ ] **Step 7: Commit**
```bash
git add -A && git commit -m "feat: clone IMPORT monotonic counter (anti-replay, post-tag)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review 备忘(计划作者)

- 覆盖设计:独立 exportCounter/importCounter ✓、严格递增无符号大端比较 ✓、EXPORT 替换旧比对 ✓、IMPORT 新增门(tag 之后)✓、移除 lastCloneNonce ✓、持久性测试 ✓、交替攻击被拒(核心)✓。
- 未误伤:CA/ECDH/HKDF/AEAD/tag/loadKeyPair/PIN 不改;回归步骤显式跑既有 clone 测试 ✓。
- 类型一致:`counterStrictlyGreater` 无 int 运算(逐字节 short 比较);`JCSystem` 事务、`Util.arrayCopy` 照既有用法 ✓。
- 本版之外:clone 频率上限 / OTP fuse、服务端 clone 审计对账。
