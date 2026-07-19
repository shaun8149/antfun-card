# 无助记词红线落地 — 设计文档

> 2026-07-19 · 目标:把"种子在芯片内生成、永不出芯片"从产品口号变成代码事实。

## 背景

CLAUDE.md 已定方向:本 SKU 移除助记词/私钥导出能力。但代码现状是——这些命令**全部还在 applet 里、还在被 dispatch**,产品对外的核心安全宣称此刻**名实不符**:`EXPORT_KEY(PRIVATE)` / `EXPORT_BIP85` / `EXPORT_LEE` 字面上就能把密钥材料导出芯片,`GENERATE_MNEMONIC` + `LOAD_KEY(seed)` 允许"卡外产生种子"的助记词模式。

现状核实(`KeycardApplet.java`):
- 五个方法均**仅由各自 dispatch case 调用**,无其它内部调用者。
- 例外:内部函数 `loadKeyPair` 被 `loadKey`(对外命令,行 698)**和 clone import(行 1139)共用**。
- `exportKey` 的 P2 模式:私钥导出(0x00,现已被限制在 EIP-1581 路径)、公钥(0x01)、扩展公钥/xpub(0x02)。

## 决策

- **方式**:保留代码,在命令入口返回错误(不物理删除)。理由:与上游合并更容易;安全保证由"入口即拒"提供。(用户拍板。)
- **私钥零导出**:任何 APDU 路径都不得导出私钥/种子。

## 变更规格

在每个红线命令的入口处、做任何工作之前 `throw`:

| 命令 | INS | 处理 | 返回 SW |
|---|---|---|---|
| `GENERATE_MNEMONIC` | 0xD2 | 入口即拒 | `SW_INS_NOT_SUPPORTED` (0x6D00) |
| `LOAD_KEY`(对外) | 0xD0 | 入口即拒;**内部 `loadKeyPair` 保留**给 clone | 0x6D00 |
| `EXPORT_LEE`(EIP-1581 私钥) | 0xC3 | 入口即拒 | 0x6D00 |
| `EXPORT_BIP85` | 0xC4 | 入口即拒 | 0x6D00 |
| `EXPORT_KEY` | 0xC2 | **保留**公钥(P2=0x01)、xpub(P2=0x02);**私钥模式(P2=0x00)拒** | 私钥模式 → `SW_FUNC_NOT_SUPPORTED` (0x6A81) |

**保留不动**:`GENERATE_KEY`(0xD4,芯片内产种子——正路)、`SIGN`、`DERIVE_KEY`、`EXPORT_KEY` 公钥/xpub、clone 全套(SET_CA / VERIFY_PEER / EXPORT / IMPORT)。

### EXPORT_KEY 私钥模式的拒绝点

`exportKey` 内 P2 分派:`case EXPORT_KEY_P2_PRIVATE_AND_PUBLIC` 分支改为直接 `throwIt(SW_FUNC_NOT_SUPPORTED)`,不再进入派生/导出逻辑。公钥(0x01)、xpub(0x02)分支不变。这样既堵死私钥导出,又保留钱包取地址/xpub 所需的公钥导出。

## 达成的安全保证

改完后:
- **没有任何 APDU 路径能导出私钥或种子。**
- 种子只能通过两条受控路径进入卡:①芯片内 `GENERATE_KEY`;②clone import(需 DAK 认证的对端 + PIN + nonce 防重放)。
- 助记词模式(卡外产种子 / BIP-39 词)在本 SKU 不可达。

## 测试(TDD)

**新增:**
1. `GENERATE_MNEMONIC` 返回 0x6D00。
2. 对外 `LOAD_KEY` 返回 0x6D00。
3. `EXPORT_LEE` 返回 0x6D00。
4. `EXPORT_BIP85` 返回 0x6D00。
5. `EXPORT_KEY` 私钥模式(P2=0x00)返回 0x6A81。
6. `EXPORT_KEY` 公钥模式(P2=0x01)**仍成功**返回公钥。
7. `EXPORT_KEY` xpub 模式(P2=0x02)**仍成功**返回扩展公钥。
8. **clone import 往返仍通过**(回归,证明内部 `loadKeyPair` 完好)。
9. `GENERATE_KEY`(芯片内产种子)**仍正常**(回归,证明正路未被误伤)。

**改造旧测试**(它们断言的正是被禁行为):
- `loadKeyTest`、`generateMnemonicTest`、`mnemonicTest` → 改为断言现在返回 0x6D00。
- 排查是否存在断言 `EXPORT_KEY` 私钥导出的旧测试;若有,改为断言 0x6A81。

## 非目标(YAGNI)

- 不物理删除代码。
- 不改 `GET_STATUS` capabilities 位(可选后续;宿主 App 感知能力下线用,本次不做)。
- 不动 clone / CSK / ticket 等其它工作线。
