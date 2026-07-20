# Clone 防重放加固 — 设计文档

> 2026-07-20 · 分支 `clone-antireplay-hardening`。把 clone 的防重放从"单 nonce 比对"升级为"独立单调计数器门",堵住双 nonce 交替攻击并补上 IMPORT 侧缺口。final/early review 记录的三个 Minor 一并关闭。

## 一、问题(现状)

`KeycardApplet.java` 的 clone 防重放当前:

1. **EXPORT 侧只比"上一个 nonce"**:`nonce != lastCloneNonce` 即放行。攻击者(clone 本就假设物理持卡 + PIN)用 **A、B 两个 nonce 交替**,每次都 `!= last`,可无限次抽取加密种子包。
2. **IMPORT 侧完全无防重放**:同一密文包可被重复导入,与 EXPORT 侧不对称。
3. **全零初值误判**:`lastCloneNonce` 初值全零,首个全零 nonce 被误判为"重放"。

## 二、决策

- **方案 A(已定)**:EXPORT / IMPORT **各自独立**的持久单调计数器(`exportCounter` / `importCounter`),各管各方向。防的是"同一张卡在某方向被重复抽取/灌入"。
- **语义 = 严格递增**:host 在 nonce 高 4 字节放一个单调递增的 32-bit counter;卡要求 `incoming > stored`,否则拒;通过则 `stored = incoming`。gap 允许(host 只需保证单调,不必连续)。
- **位宽 = 32-bit**,存为 `byte[4]`,**无符号大端比较**——避开 JavaCard 整数运算;不做加法,只"比较 + 覆盖"。
- **HKDF 不变**:完整 16 字节 nonce 仍作 HKDF salt(密钥新鲜性不变);counter 只是额外读 nonce[0..4] 做门控。

## 三、卡侧改动

**字段**(替换现有 `lastCloneNonce`):
```
private byte[] exportCounter;  // 4 bytes, big-endian, init {0,0,0,0}
private byte[] importCounter;  // 4 bytes, big-endian, init {0,0,0,0}
```

**EXPORT 侧**(替换现有 `lastCloneNonce` 比对逻辑):
```
在 CA 验签通过之后、生成临时密钥之前:
  if (!counterStrictlyGreater(apduBuffer[OFFSET_CDATA .. +4], exportCounter))
      throwIt(SW_WRONG_DATA);
  JCSystem.beginTransaction();
  Util.arrayCopy(apduBuffer, OFFSET_CDATA, exportCounter, 0, 4);
  JCSystem.commitTransaction();
```

**IMPORT 侧**(新增,tag 验证通过之后、loadKeyPair 之前):
```
  if (!counterStrictlyGreater(apduBuffer[OFFSET_CDATA .. +4], importCounter))
      throwIt(SW_WRONG_DATA);
  JCSystem.beginTransaction();
  Util.arrayCopy(apduBuffer, OFFSET_CDATA, importCounter, 0, 4);
  JCSystem.commitTransaction();
```
> IMPORT 侧计数器门放在 **tag 验证成功之后**——只有真实来自授权对端的包才推进计数器,伪造/损坏包(tag 不过)先被挡,不消耗计数器空间。

**辅助**:
```
private boolean counterStrictlyGreater(byte[] buf, short off, byte[] stored)
  // 无符号大端 4 字节比较,返回 buf[off..off+4] > stored
```

## 四、安全性质 ↔ 威胁

| 威胁 | 现状 | 加固后 |
|---|---|---|
| 双 nonce 交替重放(EXPORT) | ❌ 可无限抽取 | ✅ counter 前进后旧值被拒 |
| IMPORT 重复导入同一包 | ❌ 无防护 | ✅ importCounter 门 |
| 全零初值误判首个 nonce | ⚠️ 误拒 | ✅ counter 从 0 起,host 从 1 发号 |
| 伪造包消耗计数器 | — | ✅ IMPORT 门在 tag 验证之后 |

**不变的前提**:clone 仍要求物理持卡 + PIN + CA 验证书 + ECDH + AEAD;本加固只收紧"同一方向的重放次数"。

> **注意(计数器不是限频)**:EXPORT 计数器是纵深防御,不是抽取上限——已持卡 + PIN + 有效 CA 验证书的攻击者仍可用**递增** counter 重复导出(每次 ephemeral 不同、包也不同)。EXPORT 的真正边界仍是 **PIN + 在片证书验证**;计数器只杀"重放旧值"(交替攻击)。IMPORT 计数器在 `loadKeyPair` 之前推进——若之后失败会烧掉该值(合法方需用更高 counter 重发),不启用任何重放,仅为可用性细节。

## 五、共存 / 不碰

不动:CA 在片验证、ECDH、HKDF、AEAD、tag、`loadKeyPair`、PIN 门;CSK/票/红线全不动。仅在 EXPORT/IMPORT 两处入口加计数器门 + 替换 `lastCloneNonce` 字段。

## 六、测试(仿真器 TDD)

1. **交替 nonce 攻击被拒**(核心):EXPORT counter=5 成功后,counter=3(或旧值)→ SW_WRONG_DATA。
2. **严格递增放行**:counter 1→2→10 依次成功;重复同值 → 拒。
3. **counter 跨 reset 持久**:EXPORT counter=7 后 reset+重连+验 PIN,counter=7 再来 → 拒(证明持久),counter=8 → 成功。
4. **IMPORT 侧防重放**:同一有效包(same counter)第二次导入 → 拒;更高 counter 的新包 → 成功。
5. **IMPORT 门在 tag 之后**:tag 损坏的包 → 先被 tag 拒(SW_WRONG_DATA),且**不推进 importCounter**(之后合法低值仍可…注:此处只验证 tag 失败不改 counter)。
6. **回归**:现有 `cloneExportEndToEndTest` / `cloneImportRoundTripTest` 更新为携带递增 counter 后仍通过。

## 七、本版之外

- clone 频率上限 / 永久 OTP fuse(seal 模式)——独立项。
- counter 与服务端 clone 审计日志的对账。
