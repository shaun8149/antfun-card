# ANTFUN Card 固件选型 —— 三轮对抗工程结论

> 技术评估 · 2026-07 · 机密
> 方法:本地克隆 6 个仓库全源码 + 5 个子代理并行一手分析 + 三轮对抗
> 前置文档:《ANTFUN-Card-Keycard工程差距分析.md》(本文件是它的对抗修订版,凡冲突以本文件为准)

---

## 0. 方法与被测对象

**克隆到本地精读的仓库**(全部开源,License 已非约束):

| 仓库 | 作用定位 | License |
|---|---|---|
| `status-keycard`(含 git 全历史) | 钱包核心主基座 | Apache-2.0 |
| `Seedkeeper-Applet` | 卡到卡加密备份参考 | GPLv3 |
| `Satodime-Applet` | 熔断状态机 / 红包卡参考 | GPLv3 |
| `SatochipApplet` | 钱包核心第二意见 | AGPLv3 |
| `T2OpenPGP` | ed25519 on SE 参考 | GPLv2(25519 部分闭源) |
| `JCEd25519` + `JCMathLib` | 软件 ed25519 可行性 | MIT / MIT |
| `javacard-curated-list` | 选型索引 | — |

**流程**:第一轮建立各仓库源码地面真相(5 代理并行);第二轮用一手证据交叉攻击《差距分析 v1》的结论;第三轮收敛、steelman、出决断。

---

## 1. 对抗推翻/修正了 v1 的哪些结论(本文件最重要的部分)

| v1 的结论 | 三轮对抗后的裁决 | 证据 |
|---|---|---|
| "卡组克隆 Keycard **完全没有**,纯净新增" | **部分错误**。Keycard **历史上实现过** `INS_DUPLICATE_KEY`(卡到卡复制),2019-10-15 提交 `1b71679` 移除,Apache-2.0 仍在历史里 | 见 §2.1 |
| "ECIES 卡到卡是新写,但有积木托底" | **对,但更关键的是:两个现成实现都栽在同一处——不在卡内认证接收方**。这才是真正的净新增核心 | 见 §3(收敛点) |
| Satodime 密封/揭封 = 熔断参考 | **危险的误读**。seal/unseal 是**可重置的环**,照抄会让"已禁用"的克隆通道被 reset 重新打开。真正的熔断范式是它的 `personalizationDone` 单向闩 | 见 §2.3 |
| "选张 JavaCard 3.1 卡,SOL 就搞定(选型问题非编码问题)" | **过于乐观**。ed25519 既是选型**也是**芯片专有编码问题;通用 Weierstrass ECC 数学上做不了;软实现不安全。国产 EAL6+ 芯片大概率走**厂商 NDA 库** | 见 §2.4 + §2.5 |
| "Satochip 只是交叉验证,无决定性补充" | **基本对,但一处过头**:Satochip 的 **2FA 金额门限协签**是 Keycard 缺失的、对"恶意 App 篡改交易"有实质意义的加分项 | 见 §2.6 |

---

## 2. 各仓库一手裁定(借什么 / 缺什么)

### 2.1 Keycard 的历史 DUPLICATE KEY(Apache-2.0)

协议(`INS_DUPLICATE_KEY=0xD5`,四子命令):`START` 下发初始 32B 密钥 + 参与方数;`ADD_ENTROPY` 各方贡献 32B,卡内 **XOR** 进 `duplicationEncKey`;`EXPORT`(源卡)用该共享密钥 **AES-256-CBC 加密主私钥+链码**导出;`IMPORT`(目标卡)同密钥解密 → `loadKeyPair` 装载。产出 = 一组内容相同的卡。

- **借**:证明卡到卡复制在 Keycard 骨架里可行且合规;`loadKeyPair` 装载路径可复用。
- **致命缺陷(不可照抄)**:对称密钥由各方**经手机中转的明文熵** XOR 而成 → **被木马控制的编排手机能重建密钥、解出主私钥**。直接违反我们"安卓手机默认不可信"红线。
- 它当年为换 BIP39 mnemonic 而被删——而我们正因 **no-mnemonic** 该复活它的思路,但**换掉其密钥协商模型**。

### 2.2 SeedKeeper 的卡间加密导出(ECDH)

`INS_EXPORT_SECRET=0xA2` / `INS_IMPORT_SECRET=0xA1`;secp256k1 `ALG_EC_SVDP_DH_PLAIN_XY` ECDH;HMAC-SHA1 派生 AES-128 会话密钥;AES-128-CBC + 随机 IV + 加密后 HMAC-SHA1(20B)。

- **借**:一套可用的 **ECIES 卡到卡信封骨架**(encrypt-then-MAC);卡内随机 authentikey(装机生成)= "私钥卡内生成不导出";通用加密对象库(ObjectManager)。
- **三个安全关键缺陷(全是我们要新写的)**:
  1. **静态-静态 ECDH**,同一对卡密钥恒定 → **可重放**、无新鲜性;
  2. **目标公钥不被卡内验证** → 恶意手机替换成攻击者公钥,卡就把主密钥加密给攻击者(`PUBKEY_AUTHENTICATED`/`EXPORT_AUTHENTICATED` 声明了但是 **RFU 未实现**);
  3. **导出无上限、无熔断**,`resetToFactory` 还会重新打开克隆。
- 用的是 **HMAC-SHA1**,弱于我们该定的 SHA-256/HKDF。

### 2.3 Satodime(熔断范式 + 红包卡)

- **熔断**:`STATE_UNINIT→SEALED→UNSEALED→(reset)→UNINIT` 是**可循环重置的环**,`resetSatodimeKey` 会擦槽重新封印。**别拿它当熔断**。真正的一次性闩是 `personalizationDone`(单向 boolean,`setup()`/`lock_PKI()` 置 true,全代码无处复位)——**这才是熔断范式**,但须用 **OTP/fuse 硬化**且**独立于 factory-reset**(Satodime 的 reset 不清它,但也不封克隆通道)。
- **红包卡**:强契合。**commit-reveal 熵方案**——封印时只返回公钥(对 `SHA256(用户熵‖authentikey‖卡内熵)` 的承诺),揭封时才揭示私钥+全部熵,使收礼人可验证"**送礼人无法预知/留副本**",这正是可信红包所需。缺:无接收方身份绑定(纯持票人)、揭封后私钥可反复读(需补"领取后自毁/清扫")。

### 2.4 T2OpenPGP(ed25519 on SE)

- **开源码里根本没有 25519**:`src/` 全 grep 零命中,只有 NIST/brainpool 短 Weierstrass ECDSA。真正的 ed25519/x25519 是 **NXP JCOP 片上库 / THD89 的 TMCOS**,**NDA 专有、芯片特定、不可移植**("would not compile or run on any other chip")。
- 通用短 Weierstrass ECC 引擎**数学上无法表达** Curve25519(Montgomery/Edwards,cofactor 8)。
- **裁定**:生产级 ed25519 只有两条路——(a) 真正原生 `ALG_EDDSA`/`ALG_XDH` 的 JavaCard 3.1 卡(可移植代码);(b) 芯片厂 NDA 库(Token2 走的路)。**国产 EAL6+(紫光同芯/华大)大概率是 (b)**(THD89 本身即国产 SE)。

### 2.5 JCEd25519 + JCMathLib(软件 ed25519)

- 作者与底层库作者**双双加粗声明 "NOT for production"**,具体威胁:**计时侧信道提取私钥**。它是混合式(原生 ECDH 引擎在 Wei25519 上做标量乘,但周边域运算是软件非恒定时间)。
- **裁定**:软件 ed25519 **不能守高价值密钥**。JCMathLib 可留作**非机密关键**的拼装件(某原生原语缺失时补 ECIES 流程的点/大数运算),不用于守密钥。

### 2.6 Satochip(钱包核心第二意见)

| 子系统 | 更优基座 | 说明 |
|---|---|---|
| 密钥生成 | **Keycard(决定性)** | Satochip 只能**导入**主机生成的种子,**不能卡内生成** → 种子必在主机侧存在过,对"密钥不出芯片"是硬伤 |
| BIP32 派生 | Keycard | Satochip 有加密的卡内节点缓存(性能),但更多状态/攻击面 |
| 安全通道 | **Keycard** | Satochip 无配对/客户端认证,KDF/MAC 是 SHA-1;Keycard 有配对密钥 + HKDF |
| 交易解析 | Satochip(部分) | 卡内流式解析 BTC 交易 + 提取金额,但**不校验目标地址/脚本**(防篡额、不防换址),且是 BTC 专用 |
| **2FA 金额协签** | **Satochip(独有)** | 卡内累加输出金额,超 `2FA_limit` 必须第二设备对 `doubleSHA256(tx)` 的 HMAC 协签才肯签——**Keycard 没有** |

- **借**:2FA 金额门限协签的**概念**(screenless 卡抗恶意主机大额盗签的唯一机制);交易解析器可作地基,但须**扩展为真正检查输出地址**才能防换址,且 EVM 要重写(RLP)。

---

## 3. 收敛点(第三轮的核心洞见)

**两个现成的卡到卡克隆实现,以完全相同的方式失败:**

| | Keycard DUPLICATE(XOR 对称) | SeedKeeper EXPORT(静态 ECDH) |
|---|---|---|
| 主密钥如何泄给恶意手机 | 手机重建 XOR 共享密钥 | 手机替换目标公钥,密文加密给攻击者 |
| **共同根因** | **都不在卡内认证接收方** | 同左 |

**因此我们真正的净新增核心 = 卡内接收方认证 + 新鲜性 + 真熔断**。这三件恰好都是安全关键、也是审计中心,而两个开源实现一件都没做。好消息:三个仓库正好各出一块拼图,能拼成正确的设计。

---

## 4. 最终架构建议(合成,而非从零)

**钱包核心**:直接用 **Keycard**(卡内生成 HD 主密钥、secp256k1+Schnorr 签名、私钥不导出、PIN/PUK、ECDHE+HKDF 安全通道、IdentApplet 设备证书闸门)。

**卡组克隆备份(1.5)—— 合成三家之长 + 补新写的安全核心**

> **本轮修订(用户反馈)**:原设计把克隆绑死在「同一 set-id + 激活后永久熔断」,这会消灭一个刚需——NFC 消磁 / 卡丢失后,**用户把私钥迁到一套全新卡组(set#1 → set#2)**。故 **set-id 绑定去掉、永久熔断从「强制」降为「可选封印模式」**。这一改**主动推翻了原《安全威胁模型》1.5「完成即熔断」红线**,是自觉的产品取舍(可替换性 > 密封性),1.5 已同步改写。

1. **信封**:借 SeedKeeper 的 ECIES 骨架(encrypt-then-MAC),但 **SHA-1→SHA-256/HKDF**,**静态-静态 → 临时 ECDH + 目标卡 nonce**(补新鲜性/防重放)。SeedKeeper「任意点对点导出、无卡组语义」这一点,在旧设计里被我当缺陷,**在新逻辑下恰恰是我们要的**(支持跨组迁移)。
2. **接收方认证(净新增·核心,且是这套逻辑的关键)**:ECDH 之前,**卡 A 在卡内验证卡 B 的 DAK 证书**签名到我们的 CA——**Keycard 的 IdentApplet 已签发这种设备证书,复用作接收方认证根**。不再要求同 set-id,**任何一张我们出厂的真卡都是合法目标**(这才允许跨组迁移)。
   - **为什么这步不能省**:纯 SeedKeeper(不认证接收方)的攻击是**全程远程**——木马把目标换成攻击者随手生成的野公钥、联网把密文传出去、远程解密,**不需要任何实体卡**。加上 DAK 校验后,攻击者只能用**一张自己买的真卡**当目标、且导入后要用必须**物理持卡**——攻击这才退化成「需实体卡 + 劫持你那次克隆时刻」,即可接受档。**是这步校验让「残余风险要求实体卡」成立。**
3. **封印模式(可选,非默认)**:借 Satodime 的 `personalizationDone` 单向闩形状(OTP 硬化 + 独立于 factory-reset),提供给「我已备份完、要极致安全、再也不迁移」的高阶用户**自选启用**;默认不启用,以保住换卡刚需。
4. **克隆须 PIN**;装载复用 Keycard 历史 `loadKeyPair`。

**第二次三轮对抗(新逻辑)对各仓库原语的实清点 —— 收敛为「单一基座 = Keycard」**:

两个代理各自建议"在自己那个仓库上起手",交叉核对**实际原语库存**后修正为:**整套都建在 Keycard(Apache)上,SeedKeeper 只当设计参考**。理由是 Keycard 该有的更全:

| 需要的原语 | Keycard | SeedKeeper | 结论 |
|---|---|---|---|
| **卡内 ECDSA 验签**(验对方 DAK 证书) | ❌ 无(全 MODE_SIGN) | ❌ 无(唯一 verify 是自检) | **两边都无 → 唯一的硬核净新增** |
| HKDF-SHA256 | ✅ 现成(`Crypto.java:518`) | ❌ 只有 HMAC-SHA1/512 | Keycard 胜 |
| AEAD | ✅ 手搓 AES-CCM(`aesCcm*`) | ⚠️ 仅 AES-CBC+HMAC-**SHA1** | Keycard 胜;**均无 AES-GCM,别用 GCM** |
| 临时 ECDH | ✅(SecureChannelV2,~15 行可抽) | ✅(InitiateSecureChannel + 计数器 IV) | 都行 |
| 卡到卡克隆骨架 | ✅ 历史 DUPLICATE,**本就跨卡通用**、Apache | ✅ exportSecret,跨卡通用、但 GPLv3 | Keycard 胜(许可证 + 已是基座) |
| DAK 证书基础设施 | ✅ IdentApplet | 部分(存不验) | Keycard 胜 |

- **唯一的硬核净新增 = 卡内验对方 DAK 证书**:两个实现都没有(只有 MODE_SIGN;IdentApplet 的证书只是 SELECT 时吐出给主机验)。要新加:`MODE_VERIFY` 实例 + perso 注入的 CA 公钥 + 证书解析 + 验签闸门。**整套设计的安全地基就压在这一件零现成代码的功能上**——它是审计中心,也是 spike 首验对象。
- **规格修正**:原文的 **AES-256-GCM 改为复用 Keycard 的 AES-CCM(`aesCcm*`)**——目标级 EAL6+ 卡普遍无原生 GCM。
- **补强**:目标卡加**挑战-响应**(用 DAK 私钥现签 nonce)确保在场;主种子**强制安全导出、禁明文路径**。
- **许可证**(我们全开源,非阻塞):建在 Keycard 上还顺带避开 GPLv3 混入问题——SeedKeeper 仅作设计参考、不抄源码。

**红包卡(3.3⑦)**:借 Satodime 的 **commit-reveal 熵方案 + 持票人/unlock-code 模型**,补"领取后自毁"。

**无助记词**:砍 `GENERATE_MNEMONIC` / `LOAD_KEY(SEED)` / `EXPORT_BIP85` / EIP-1581 私钥导出;`GENERATE_KEY`(卡内随机种子、无词)即无助记词主路径,卡组克隆做其备份。

**抗换址/大额(可选,分层)**:卡片款小额走盲签哈希;**大额走带屏旗舰的屏上地址确认**。Satochip 的 2FA 金额协签作为"若要做无屏高价值路径"的参考概念,非首发阻塞。

---

## 5. 修订后的工程量与风险

- **白拿(Keycard)**:钱包核心、签名、PIN/PUK、安全通道、设备证书闸门、名片签名模板(CashApplet)、NDEF、测试链。
- **合成 + 新写(核心·最高审计权重)**:**卡内验接收方 DAK 证书 + 临时 ECDH/nonce 的 ECIES 克隆**。比 v1 估计的"纯从零"轻——有三份参考;安全关键胶水(**卡内认证接收方、新鲜性**)是真新写,是审计中心。OTP 熔断降为**可选封印模式**,不再是核心必做项。
- **选型阻塞(未解)**:① 确认所选 EAL6+ 卡的算法集(`ALG_EC_SVDP_DH_PLAIN_XY`、`HMAC_SHA512`);② ed25519 是否原生——**必须用 JCAlgTest/ECTester 实测该常量真跑通,不是仅声明**。
- **SOL 决断**:**首发只上 secp256k1 系(BTC + 全 EVM/BSC),SOL 延后**——等选定 JCAlgTest 验证过原生 `ALG_EDDSA` 的 3.1 卡,或走芯片厂 NDA。不因 SOL 阻塞首发(与文档"首发 BSC/EVM"一致)。

---

## 6. 下一步(按顺序)

1. **芯片/卡选型 + JCAlgTest/ECTester 实测**:一次锁死"能否跑 Keycard 算法集"与"ed25519 是否原生(决定 SOL)"。唯一能让后续全部作废的单点。
2. **在 jcardsim 仿真器上做克隆 spike**:先把"卡内验证接收方 DAK 证书 → 临时 ECDH+nonce → ECIES 传输 → 卡内装载"跑通,不碰真卡即验协议;可选封印模式的 OTP 逻辑作为附加项。这是风险最高、最该早验的一块。
3. spike 通过后,产出正式的《卡组克隆 applet 技术规格》(APDU 定义、消息格式、熔断状态机、与 SecureChannel/PIN/IdentApplet 挂接),进入实卡开发。

---

## 附:关键源码坐标

- Keycard DUPLICATE 历史实现:`status-keycard` @ `1b71679^` — `KeycardApplet.java:1105-1215`(`duplicateKey`/`startDuplication`/`addEntropy`/`exportDuplicate`/`importDuplicate`)
- Keycard 设备证书闸门:`KeycardApplet.java:218`;`IdentApplet.java`;`SharedMemory.java:19`
- SeedKeeper 导出信封:`SeedKeeper.java:2249-2257`(ECDH+KDF+AES),`1932-1946/2075-2099`(导入验签);RFU 认证:`:340,:361`
- Satodime 熔断闩:`Satodime.java:309,724,1769`(`personalizationDone`);commit-reveal:`:1224-1250`(封印),`:1324-1346`(揭封)
- Satochip 2FA 协签:`CardEdge.java:2326-2341`;交易解析:`Transaction.java:104-264`
- T2OpenPGP 25519 缺位证据:`TOKEN2.md:58,116-132`;`ECConstants.java`(仅 6 条 Weierstrass)
- JCEd25519 生产警告:`README.md:9`;`JCMathLib/README.md:55-57`
