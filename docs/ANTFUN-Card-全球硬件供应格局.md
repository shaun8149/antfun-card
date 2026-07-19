# 全球硬件供应格局(SE 芯片 / 采购渠道 / 量产伙伴 / perso)

> 2026-07 · 12+ 路并行研究综合(SE 芯片、NXP P71、卡片型/设备型钱包基准、CAP 可移植性、发卡局、创业公司可及渠道、MOQ/价格、perso 安全、印卡)。核心证据:直读 JCAlgTest 294 张卡原始 CSV、各厂官网/CC 证书、社区采购指南。
> 前提:已选 NXP JCOP4 P71,无国产要求,首发 secp256k1,SOL 延后。

---

## 0. 决策级结论(先看这个)

1. **NXP JCOP4 P71(J3R200)选对了**:secp256k1 实测确认、EAL6+、开放非捆绑、在产不 EOL、交期 ~12–20 周;是**卡片型 JavaCard 钱包的事实标准**。
2. **我们的路子是卡片型主流**:所有开放卡钱包(Keycard/Satochip/GridPlus/Cryptnox/Arculus/Coinkite/KeyPal/imKey)都是 JavaCard/GlobalPlatform、多在 NXP;设备型(Ledger/Trezor/Keystone/OneKey/Tangem)全是专有 SE 固件。
3. **量产路径清晰、门槛低**:开发自装 → 小批发卡局代装 → 量产找 **Cryptnox(瑞士,专为我们这套栈做)** 或 Kona I(韩国,有加密卡产品)。
4. **成本落地**:blank SE 卡量产 **$1.5–5/张**(量越大越低,10 万+ 可到 ~$1.5),开发单张 ~€12–30。BOM 个位数美元成立。
5. **二供只有 Infineon,且不免费**:换卡厂≠换芯片;真二供要重移植 + JCAlgTest/ECTester 实测。首发不双供。
6. **perso 红线**:钱包种子**卡内生成、绝不注入**;发卡局只做 SCP03 装 applet + DAK 密文注入(不见明文)。

---

## 1. 市场分两层

| 层 | 谁 | 二供在哪 |
|---|---|---|
| **芯片(SE 硅片)** | NXP、Infineon、ST、Samsung、Renesas(边缘) | 真正的芯片二供在这层 |
| **卡 / JavaCard-OS / 成品 / 发卡局** | G+D、Thales、IDEMIA、Kona I、Cryptnox、Feitian、CardLogix、深圳厂 | 装 OS/applet + perso + 印卡 |
| **垂直整合** | NXP(JCOP on P71)、Infineon(SECORA)、ST(ST4SIM/STPay) | 芯片+OS 一体 |

**关键**:Feitian、Cryptnox、Kona I 等都是"卡/OS 层",跑在别人硅片上(Feitian 底层是 Infineon SLE)。**换卡厂不换芯片。**

---

## 2. 芯片:NXP JCOP4 P71 确认 + 二供现实

| 芯片 | JavaCard | EAL | secp256k1 | 开发卡 | ed25519 |
|---|---|---|---|---|---|
| **NXP JCOP4 P71**(J3R200/J3R180) | 3.0.5 | **6+**(NSCIB;FIPS 140-3) | ✅ 实测(ALG_EC_FP+自设域参,Keycard 在跑) | ✅ 开放 unfused | ❌ |
| Infineon SECORA Blockchain | — | 6+(宣称) | ✅ 官方列 | ⚠️ 评估 kit 需联系 | ❌ |
| ST31/ST33 | 有 JavaCard SKU(ST4SIM/STPay,JC3.0.4) | 5+/6+ | 需实测 | 裸片走 NDA | ❌ |
| Samsung S3 | 无一方 JavaCard 产品(第三方 OS) | 6+ | — | NDA | ❌ |

- **ed25519/SOL 延后(确定)**:JCAlgTest 现代真卡**零原生 EdDSA**,与国别无关。
- **二供的真实候选与关键未知**:
  - **可买来自装的 JCOP4 同构替代 = G+D Sm@rtCafé Expert**(JavaCard 3.1、EAL6+、smartcardfocus 小量零售)或 Infineon SECORA ID/Pay(开放 JavaCard,但整合商/NDA 渠道、小量难买)。
  - Infineon **SECORA Blockchain** 虽原生 secp256k1 + EAL6+,但是**闭源固定 applet**,不能跑我们自己的 applet → **不是二供载体**。OPTIGA 非 JavaCard,出局。
  - ⚠️ **最关键的未知**:secp256k1 是 k1(Koblitz)曲线,**不在** G+D/Infineon 开放卡的 CC 认证曲线表里(只有 NIST/Brainpool r1)。**它们的 EC 协处理器是否接受"自定义域参数"来注入 secp256k1,公开文档无法确认**——部分硬化 SE 只认固定命名曲线、对自定义域参直接抛异常。**NXP JCOP 已知接受(Keycard 实证);Infineon/G+D 未验证。** → 真要二供,必须先拿样卡实测 secp256k1 自定义域参,或找厂商工程确认。
  - CAP 移植其余坑:各家算法支持差异(运行时 `NO_SUCH_ALGORITHM`)、专有 API 锁死、GP 密钥/锁态。**不是零成本,首发不双供。**

---

## 3. 同行基准:车道对不对

**卡片型(和我们同类)——几乎都是 JavaCard、多在 NXP:**

| 产品 | SE | JavaCard? | 卡谁造 |
|---|---|---|---|
| Status Keycard | NXP J3R200(JCOP4 P71) | ✅(基座) | 未公开(生产锁 GP 密钥+真伪证书) |
| Satochip | NXP JCOP4 P71 SECID | ✅ 开源 | **自装**在现货 blank 卡上(MOQ=1) |
| GridPlus SafeCard | 近乎确定 NXP JCOP | ✅(Keycard 分支) | 自家 perso |
| Cryptnox | NXP JCOP4.5 P71 | ✅ | 自营(见下,turnkey) |
| Arculus | EAL6+(推断 NXP JCOP) | ✅(推断) | **CompoSecure**(金属卡厂,自造) |
| Coinkite SATSCARD/TAPSIGNER | 未披露 EAL6 SE | 版本化 applet,像 JavaCard | 自营激光刻卡 |
| KeyPal Card | EAL6+(用 SCP11) | JavaCard 级 | 未披露 |
| imKey | Infineon SLE78 | ✅(大概率) | — |
| Burner | NXP HaLo(Arx,**原生 secp256k1**) | ❌ 专有固件 | Arx 自造 |

**设备型——全专有 SE 固件(非 JavaCard)**:Ledger(ST33+BOLOS)、Trezor(Infineon OPTIGA 固定功能)、Keystone(Microchip/Maxim)、OneKey Pro(4×THD89 专有)、Tangem(Samsung S3,工厂锁死单一 app)。

→ **JavaCard 是卡片型的路。NXP JCOP 是开放卡钱包的事实标准。我们完全在主流。**

---

## 4. 采购与量产路径(重点)

三档,从现在到量产:

### Tier 1 — 开发/试点(几十~几百张):自己买 blank + GlobalPlatformPro 自装
Keycard/Satochip/Cryptnox 全走这条,**不需要发卡局**。
- **首选:Keycard 自家 unfused 开发卡**(NXP J3R200,和量产 Keycard 芯片一模一样,€30/张,MOQ 1,可装任意 applet)——**我们最该先买的原型卡**。
- J3R180 blank 现货:**United Access**(10 张 €120=€12/张,带 GP 默认密钥)、**MoTechno / CardLogix / SmartcardFocus / CryptoShop**。
- 用 `gp.jar --install xxx.cap` 装(默认测试密钥 `404142…4E4F`)。
- 中国厂 blank(Alibaba):MOQ 10–100,单价 ~$4–5(百张级)。

### Tier 2 — 小批(几百~千级):发卡局代装 applet
- **CardLogix**(美):已扩展支持 NXP JCOP4 applet 加载,提供编程/perso 服务;创业公司准入与 MOQ 需直接询价。

### Tier 3 — 量产(千级+,品牌卡、密钥注入、锁死):turnkey 发卡局
- **⭐ Cryptnox(瑞士)—— 最贴我们这套栈的 turnkey**:就做 **NXP JCOP4.5 P71** 上的自研 applet(JavaCard 和原生 C via NXP SecureBox);提供**生产密钥注入 + 卡面 perso + 预装 applet + 发行后锁死**;有 **Card-Wallet-as-a-Service(C-WAAS)** 白标加密卡产品;打样 50–100,量产 MOQ 1k–5k,开发周期 6–12 月。**首谈对象。**
- **Kona I(韩国)**:已有 **CryptoKona** 加密卡产品(自家 applet + 卡内生成),定位全球 OEM/白标芯片-OS 供应商,最可能替第三方共装 applet。
- **IDEMIA(B.CHAIN 加密卡)/ G+D(Convego TruSafe)**:有加密卡产品但银行导向、MOQ 大(万级)、要 NDA。
- **深圳金融 IC 卡厂 / Feitian 级**:也能采购 NXP 芯片 + 封卡 + SCP03 装 applet + perso + 印卡;Feitian 甚至单张零售 NXP JCOP4 P71(Alibaba MOQ 10,$5.69–10.99)。

**大三家(Thales/IDEMIA/G+D)现实**:标准业务是装**自家认证 applet**,给第三方装**未认证 CAP**属定制、需 NDA 谈判——不是下单表能搞定的。**Cryptnox / Kona I 才是创业公司的自然入口。**

---

## 5. MOQ / 价格 / 交期(公开参考,以实际报价为准)

| 量级 | blank SE 卡单价 | 渠道 |
|---|---|---|
| 开发(10s) | ~€12–30/张 | Keycard 开发卡 / United Access / MoTechno |
| 试点(100s) | ~$4–5/张 | 中国厂 MOQ 100 |
| 小批(1k–10k) | ~$2.1–3.6/张 | 中国厂分档 |
| 量产(50k–100k+) | ~$1.5–2.1/张 | 中国厂 100k+ |

- **成品含印卡 perso**:再加 perso + 印刷,量产整卡仍在个位数美元。
- **限定卡面(每场 500–2000)**:用**数字印刷(HP Indigo/热转印/UV)**,MOQ 10–500、单价近乎平(无制版费),换图零成本;>5000 的稳定旗舰款才用胶印。
- **交期**:开发卡多现货(数天~2 周);首批量产(含印卡)艺术稿定后 **7–15 天**;**SE 芯片本身的分配/交期是唯一硬风险,公开无 2026 硬数字,须问 NXP 代理**。

---

## 6. perso 红线(外部研究反证了我们的设计对)

EMV/发卡局那套(HSM、SCP03、TR-31 密钥块、PCI-CP)是为"发卡方注入密钥、认证卡"设计的——**与自托管钱包相反**。所以:
- **钱包种子必须卡内 TRNG 生成、不出芯片**;出厂预置种子 = 行业公认诈骗信号(攻击者已握副本)。CryptoKona/B.CHAIN 都是卡内生成。
- 发卡局对我们只做:①**SCP03**(AES;不是废弃的 3DES SCP02)加载 applet;②若注入 **DAK/设备认证密钥**,用 **TR-31/DEK 密文包**,卡厂**全程不见明文**。
- 与我们威胁模型 §0.2/1.4/1.5 完全一致。

---

## 7. 采购避坑(社区反复踩的)

1. **必须 SECID 变体,不是 EMV**:EMV 版 JCOP4 P71 装不了钱包 applet(报 0x6444/0x6F00)。买时点名 **SECID**。
2. **必须拿到 GP 测试密钥**:卡若锁了厂商 GP 密钥,你装不进 applet。下单前**明确要默认/测试密钥**。
3. **别暴力试密钥**:JCOP 卡管理器 ~10 次错误认证即**永久锁死**(applet 还能跑但无法再管理)——可能**变砖**。
4. **别买来路不明的"unfused"神秘卡**:AliExpress/eBay 便宜卡常未熔断、fuse 指令 NDA、乱试会不可逆损坏。
5. **裸片/完整 datasheet/fusing 指令 = NXP NDA**;applet 级开发在成品开发卡上不需要。

---

## 8. 一句话给决策

**芯片 NXP JCOP4 P71 定,Infineon SECORA 作书面二供(不免费,要重测);首发 secp256k1、不上 SOL;开发买 Keycard 自家 J3R200 开发卡自装,量产首谈 Cryptnox(同栈 turnkey)、备选 Kona I;perso 守"种子卡内生、DAK 密文注入、SCP03、卡厂不见明文";买卡认准 SECID + 要测试密钥。全球供应对我们不是瓶颈——真正要花力气的是安全审计 + 真卡验证 + 谈一家 turnkey 发卡局(Cryptnox 是最贴的)。**

---

## 9. 还需实际接触/报价的开放项

- **Cryptnox**:C-WAAS 的确切 MOQ/价、能否 <1000 小批。
- **Kona I / IDEMIA**:最小试点量 + NRE、是否给第三方 CAP 装载、密钥模型。
- **NXP 代理**:P71 当前交期/MOQ/裸片 NDA 条款。
- 各 blank 卡渠道:确认发默认测试密钥 + J3R180/P71 现货与价。
- Infineon SECORA:secp256k1 实测 + 评估 kit 获取(若要坐实二供)。
