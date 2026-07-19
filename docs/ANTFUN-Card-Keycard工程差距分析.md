# ANTFUN Card × Status Keycard 工程差距分析

> 技术评估 · 2026-07 · 机密
> 评估对象:`github.com/keycard-tech/status-keycard`(提交 `074a041`,2026-07-08,含 bip85)
> 代码规模:约 4,578 行 Java(applet 主体 ~3,000 行 + 测试 1,537 行)
> 配套文档:《ANTFUN Card 业务构想》《安全威胁模型》

---

## 一句话结论

Keycard 是我们能拿到的最好的起点——**「卡即冷钱包 + 名片签名 + 设备验真 + NDEF」四块它已有成熟实现,许可证 Apache-2.0(可改可闭源,非 copyleft)**。但我们两条主支柱——**卡组克隆备份(1.5)** 和 **多链含 SOL(ed25519)**——它一个都没有:前者要新写核心密码学模块,后者是芯片选型的硬约束。

距离可用大致是「**改造 30% + 净新增 70% 的关键代码,但骨架与测试链全部省下**」。

---

## 需求逐条对照

| 我们的需求(文档出处) | Keycard 现状 | 结论 |
|---|---|---|
| 卡内生成 HD 主密钥、私钥不出芯片(0.1) | `GENERATE_KEY` 卡内生成 64B 随机种子 → BIP32 master,私钥无导出指令(`KeycardApplet.java:1016`) | ✅ 直接可用 |
| secp256k1 签名(BTC/ETH)(5) | `SIGN` 带路径派生(`KeycardApplet.java:1040`) | ✅ 直接可用 |
| BTC Taproot | Schnorr 已实现(`SECP256k1.java:149`) | ✅ 意外之喜 |
| 私钥不可导出(红线) | 私钥导出被闸死在 EIP-1581 子树,普通钱包路径只能导公钥(`KeycardApplet.java:1122`) | ✅ 花钱包私钥本就导不出 |
| PIN 3 次 / PUK 5 次锁死(0.1) | `OwnerPIN`,默认 PIN 3 / PUK 5(`KeycardApplet.java:46-48`) | ✅ 直接可用 |
| App↔卡加密通道 + 验真(1.2) | ECDHE(secp256k1)+ HKDF 安全通道(`SecureChannelV2.java`) | ✅ 直接可用 |
| 设备认证密钥 DAK / 出厂验真 / 一卡一次(0.2, 1.2) | `IdentApplet` = 写一次的设备私钥 + CA 签名证书;钱包 applet 一进门就校验证书,无效即拒绝一切操作(`KeycardApplet.java:218`);证书 = 压缩公钥 + CA 签名 r,s,v(`SharedMemory.java:19`) | ✅ 模型完全吻合,只需把 CA 换成我们的 HSM |
| 名片签名密钥 CSK / 见面证明(0.2, 2.1) | `CashApplet` = 独立卡内密钥对 + 公开数据文件 + `SIGN`(`CashApplet.java`) | 🟡 绝佳模板,需加挑战-响应 |
| NDEF 碰即拉起 App(5) | `NDEFApplet` + 可写 NDEF 文件(512B)(`NDEFApplet.java`) | ✅ 直接可用 |
| 卡上存序列号 / 元数据 | `STORE_DATA` 三个数据文件 public/ndef/cash(`KeycardApplet.java:1309`) | ✅ 直接可用 |
| 仿真器 + 测试 + 主机 SDK | jcardsim 子模块 + Java/Swift SDK + CLI(README) | ✅ 整条开发测试链白拿 |
| 无助记词红线(1.5 红线) | `GENERATE_MNEMONIC` 会把助记词词表下标吐给客户端(`KeycardApplet.java:876`);`LOAD_KEY` 可导入外部种子 | 🟡 要砍掉这几条指令 |
| 卡组克隆备份 + 激活期一次性熔断(1.5) | **完全没有**。备份靠 `GENERATE_MNEMONIC`(给用户抄词)或 `LOAD_KEY`(导回种子) | 🔴 净新增,核心工程 |
| 多链含 SOL(ed25519 EdDSA)(讨论确认) | **只有 secp256k1**,无 ed25519 | 🔴 芯片选型硬约束 |
| 碰卡防重放:nonce + 单调计数器(2.1) | CashApplet 只签任意 hash,无计数器 | 🟡 小改动 |

**图例**:✅ 直接可用 / 🟡 改造(中等) / 🔴 净新增或阻塞

---

## 三个真正要解决的问题

### ① 卡组克隆 + 熔断(1.5)——唯一从零写的核心密码学

Keycard 没有任何「卡到卡」的密钥转移。但积木全在:`Crypto.java`(616 行)里 ECDH、AES、SHA-256/512、HMAC 都有,**ECIES 是可以拼出来的**。要新增:

- `CLONE_EXPORT`(A 卡):用目标卡 B 的公钥 ECIES 加密 512-bit 种子;
- `CLONE_IMPORT`(B 卡):卡内解密并装载为 master;
- **一次性熔断标志位**——直接复用 `IdentApplet` 那个「写一次即锁死」模式(`idCert[0]==CERT_VALID` 就是现成范式),激活完成后永久禁用两条克隆指令。

这块正是《安全威胁模型》点名的**首要审计项**,也是产品安全叙事的本体。工程量不小,但有现成密码学积木 + 现成写一次范式托底,不是从白纸开始。

### ② ed25519 / SOL——这是选型问题,不是写代码问题

Keycard 跑在 **JavaCard 3.0.5**,只做 secp256k1。ed25519 的 EdDSA 需要 **JavaCard 3.1** 的原生 `ALG_EDDSA`,而很多在产的 EAL6+ 卡(3.0.5 世代)不暴露它。三条路:

- **(a) 选一张原生支持 Ed25519 的 JavaCard 3.1 EAL6+ 卡(推荐,一劳永逸);**
- (b) 用 applet 软实现 ed25519——在 JavaCard 上性能 / 安全都很难接受,基本不现实;
- (c) 首发只上 secp256k1 系(BTC / ETH / BSC / 所有 EVM),SOL 排到选定 3.1 卡之后。

这直接决定芯片选型,应立刻并进「量产前必办清单」的芯片评估里。

### ③ 无助记词化——做减法

默认 SKU 里砍掉 `GENERATE_MNEMONIC`、`LOAD_KEY(SEED/EC)`、`EXPORT_BIP85`、EIP-1581 私钥导出这几条「种子可搬运」面。

注意:**`GENERATE_KEY` 本身就是无助记词路径**(卡内随机种子,从不产生词)——Keycard 自己这条路的唯一缺陷就是「没有备份」,而我们的卡组克隆恰好就是补这个缺。叙事很干净:

> Keycard 的 `GENERATE_KEY` 已经给你一个无助记词钱包,它唯一的问题是没法备份;**卡组克隆就是那个备份。**

---

## 工程量与风险读数

- **能白拿的(约省 60–70% 骨架)**:HD 钱包、签名、PIN/PUK、安全通道、设备证书闸门、名片签名模板、NDEF、STORE_DATA、仿真器 + 测试 + SDK。
- **改造(中等)**:CA 换成我们的 HSM;CashApplet 加 nonce + 计数器变成 CSK tap;做无助记词减法;PIN 在卡组模式强制。
- **净新增(重)**:卡组克隆 + 熔断(核心)。
- **卡在选型上的(阻塞)**:JavaCard 3.1 + Ed25519 的卡源;以及必须先确认紫光同芯 / 华大的 EAL6+ 卡 OS 真能跑 Keycard 要求的算法集(`ALG_EC_SVDP_DH_PLAIN_XY`、`HMAC_SHA512` 等,README 有列)。
- **许可证**:Apache-2.0,改动**不强制开源**(与 GPL/MPL 不同),解掉了必办清单第 1 条的一半;我们自己的安全模型愿意开源是另一回事。

---

## 建议的下一步(两件事按顺序钉死)

1. **芯片 / 卡选型先行**,因为它同时锁死两件事:能不能跑 Keycard 算法集、能不能原生 Ed25519(决定 SOL 首发与否)。这是唯一能让后面全部工作作废的单点。
2. **卡组克隆 + 熔断做成第一个自研 spike**:在 jcardsim 仿真器上先把 `CLONE_EXPORT/IMPORT + 熔断标志` 跑通,不碰真卡就能验证协议与熔断逻辑——这是风险最高、最该早验的一块。

---

## 附:Keycard 命令集速查(`KeycardApplet.java:18-36`)

| INS | 名称 | 我们的处置 |
|---|---|---|
| `0xF2` | GET_STATUS | 保留 |
| `0xFE` | INIT | 保留 |
| `0xFD` | FACTORY_RESET | 保留 |
| `0x20/21/22` | VERIFY / CHANGE / UNBLOCK PIN | 保留;卡组模式 PIN 强制 |
| `0xD0` | LOAD_KEY | 默认 SKU 砍掉(可搬运种子面) |
| `0xD1` | DERIVE_KEY | 保留 |
| `0xD2` | GENERATE_MNEMONIC | **砍掉**(无助记词红线) |
| `0xD3` | REMOVE_KEY | 保留 |
| `0xD4` | GENERATE_KEY | **保留 = 无助记词生成主路径** |
| `0xC0` | SIGN | 保留(secp256k1 + Schnorr) |
| `0xC1` | SET_PINLESS_PATH | 保留 |
| `0xC2` | EXPORT_KEY | 收紧:仅公钥,私钥面砍掉 |
| `0xC3` | EXPORT_LEE | 评估后多半砍掉 |
| `0xC4` | EXPORT_BIP85 | 砍掉(派生别的种子) |
| `0xCA` | GET_DATA | 保留 |
| `0xE2` | STORE_DATA | 保留(序列号 / NDEF / 名片数据) |
| `0x84` | GET_CHALLENGE | 保留 |
| **新增** | `CLONE_EXPORT` | 🔴 卡组克隆(净新增) |
| **新增** | `CLONE_IMPORT` | 🔴 卡组克隆(净新增) |
| **新增** | `CSK_TAP_SIGN` | 🟡 名片挑战-响应(CashApplet 改造) |

## 附:源码文件清单

| 文件 | 行数 | 作用 | 对我们 |
|---|---|---|---|
| `KeycardApplet.java` | 1,400 | 钱包主 applet | 核心复用 + 改造 |
| `Crypto.java` | 616 | ECDH / AES / SHA / HMAC / BIP32 | ECIES 积木来源 |
| `SecureChannelV2.java` | 224 | App↔卡安全通道 | 直接复用 |
| `SECP256k1.java` | 212 | secp256k1 + Schnorr | 直接复用 |
| `NDEFApplet.java` | 153 | NDEF 标签 | 直接复用 |
| `CashApplet.java` | 140 | 独立签名 applet | CSK 名片模板 |
| `IdentApplet.java` | 96 | 设备证书(写一次) | DAK 模型 + 熔断范式 |
| `SharedMemory.java` | 23 | 跨 applet 共享数据 | 参考 |
