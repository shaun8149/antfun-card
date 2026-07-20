# 种子存储卡(Vault)— 设计文档(seed-storage SKU · spike 1)

> 2026-07-20 · 分支 `seed-storage-spike`。探索 OneKey/imKey/KeyPal 式"卡作助记词/私钥存储器"的可能性,与 master 的"无助记词冷钱包"并行,其余功能(CSK/票/clone/DAK)不变。

## 一、定位:两个 SKU,一套源码

| | master(无助记词冷钱包) | 本分支(种子存储卡 Vault) |
|---|---|---|
| 种子 | 芯片内生成,**永不出** | 可**写入**、可**读回**(PIN 门) |
| 签名 | 卡内 | **不签名**(纯储存,App 用读回的助记词自行签) |
| 备份 | clone | 直接读回 entropy → 还原助记词 |
| ⑦红包卡 | ✅ | ❌(种子不再"激活自生成") |
| 共享 | CSK②见面证明、票④核销、clone、DAK、NDEF、社交/归因层 —— **两 SKU 完全一致** | 同左 |

**机制 = 编译期 SKU 常量**:`public static final boolean NO_MNEMONIC`。产出两个 CAP:
- `NO_MNEMONIC = true` → 冷钱包卡(master 行为)。
- `NO_MNEMONIC = false` → 种子存储卡(**本分支构建值**)。

编译期定死,单张卡行为**不可运行时翻转**(安全)。测试用 `assumeTrue/assumeFalse(KeycardApplet.NO_MNEMONIC)` 按 SKU 分流。

## 二、关键设计:用新"entropy 保险库",不反转红线

纯储存备份靠一个**新的 PIN 门 entropy 保险库**,与老的钱包密钥管理(LOAD/EXPORT_KEY/SIGN)无关:

- **红线不动**:禁 LOAD/EXPORT 钱包密钥在两个 SKU 里都保留。存储卡备份走**新命令**,不是老的 LOAD/EXPORT_KEY。→ spike 不打扰现有测试。
- **保险库存的是 BIP-39 entropy**(128–256bit):App 拿 entropy 自行还原成 12/24 个助记词并派生 seed。卡不需要词表。

## 三、卡侧接口(spike 1 净新增)

新增持久缓冲 `secretStore`(≤32 字节)+ `secretLen`。两条命令**仅在 `!NO_MNEMONIC`(存储 SKU)生效**,否则 throw `SW_INS_NOT_SUPPORTED`(0x6D00)——冷钱包卡永不暴露 entropy。

```
INS_STORE_SECRET:                (PIN 门)
  P1 = STORE_P1_IMPORT   : data = 外部 entropy(16/20/24/28/32 字节)→ 持久化
  P1 = STORE_P1_GENERATE : P2 = 目标长度 → 卡内 RNG 生成该长度 entropy → 持久化(不回显)
INS_EXPORT_SECRET:               (PIN 门)
  → 返回 secretStore[0..secretLen]  (App 还原助记词)
```

要点:
- 两条命令都要求 `pin.isValidated()`,否则 `SW_CONDITIONS_NOT_SATISFIED`(0x6985)。
- 长度必须是合法 BIP-39 entropy 长度(16/20/24/28/32),否则 `SW_WRONG_DATA` / `SW_INCORRECT_P1P2`。
- 覆写允许(PIN 门内可重新 STORE)。
- GENERATE 不回显 entropy(只存);读回一律走 EXPORT_SECRET。

## 四、安全性质 ↔ 威胁

| 威胁 | 对策 |
|---|---|
| 无 PIN 读走助记词 | EXPORT/STORE 均 PIN 门;PIN 错误计数/锁定沿用 Keycard 既有机制 |
| 冷钱包 SKU 被诱导导出种子 | 保险库命令在 `NO_MNEMONIC=true` 时结构上不存在(throw);编译期定死 |
| 运行时把冷钱包卡"翻转"成存储卡 | SKU 是编译常量,非运行时可选 |
| 保险库 entropy 与 CSK/票/资产混用 | 保险库是独立缓冲,不参与任何签名;CSK/票用各自独立密钥 |

**接受的固有权衡(产品叙事)**:存储卡"种子可出芯片"是它的定义特征(和 KeyPal/OneKey 一致),这正是 master 无助记词 SKU 要避免的。两个 SKU 在产品命名/文档上清楚隔开(如 `ANTFUN Vault` vs `ANTFUN Card`),工程上共用一套源码。

## 五、借什么 / 净新增

**借**:Keycard 既有 PIN 机制(`pin.isValidated()`、错误锁定)、`crypto.random`(卡内生成 entropy)、安全通道、持久存储模式。

**净新增(小)**:
1. `NO_MNEMONIC` 编译常量 + 冷钱包默认 true。
2. 持久 `secretStore` + `secretLen`。
3. `INS_STORE_SECRET`(import/generate,PIN 门)、`INS_EXPORT_SECRET`(PIN 门)。
4. SKU 感知测试(assumeFalse(NO_MNEMONIC))。

## 六、测试(仿真器 TDD · 存储 SKU)

1. STORE(import 32 字节)→ EXPORT → **读回与写入一致**。
2. **PIN 门**:未验 PIN 时 STORE/EXPORT → 0x6985。
3. STORE(generate,P2=32)→ EXPORT → **非全零**;reset+重连+验 PIN → EXPORT 再读 → **与首次一致(持久)**。
4. 非法长度(如 17)→ 拒。
5. 冷钱包 SKU 下(若 `NO_MNEMONIC=true`)两命令 → 0x6D00(用 assume 分流;本分支构建为存储 SKU,该断言归属另一 SKU 的测试)。

## 七、本版之外(后续)

- **关掉存储 SKU 的卡内签名**(真·纯储存:`if(!NO_MNEMONIC) INS_SIGN→throw`)——会动 signTest,单独一步。
- 助记词**词表编码/校验**在 App 侧(卡只存 entropy)。
- **多槽位**(存多套助记词)、命名、恢复 UX。
- **私钥直存**(除助记词外存任意私钥)。
- perso:存储卡的 PIN 初始化、卡种。
- 收敛:把 master 的红线其它命令也纳入 `NO_MNEMONIC` 联动(目前仅保险库两命令受 flag 控)。

*本设计与 master 的《无助记词红线》互为镜像:master 禁一切种子出芯片;本 SKU 用受 PIN 保护的独立保险库,专门支持种子出芯片。两者共用 CSK/票/clone/DAK。*
