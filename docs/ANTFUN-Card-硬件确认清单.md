# ANTFUN Card 硬件确认清单

> 用途:B 轨(需实体卡)的采购 + 待定决策 + 验证矩阵。A 轨(代码/纸面)不依赖本单。
> 采购是两个最高价值验证(真机 NFC / 芯片算法)的**共同瓶颈**,建议立即启动。

---

## 一、采购清单(要买的东西)

| 项 | 规格 / 说明 | 数量 |
|---|---|---|
| **空白 JavaCard** | JavaCard **3.0.5 以上**(Keycard 底线);若要 SOL,优先带**原生 ed25519(JC 3.1)**的卡;必须支持 **GlobalPlatform**(用于装 applet)且卡片默认密钥可知或可改 | 每候选芯片 5–10 张 |
| **接触式/双界面读卡器** | PC/SC 标准;做 GP 装载与 JCAlgTest 用接触式;做 NFC 碰卡实验用非接读卡器(如 ACR122U / ACR1252U) | 各 1 |
| **iPhone** | **iPhone XS 或更新**(CoreNFC + ISO7816 会话) | 1 |
| **Android** | 支持 NFC 的主流机型(HCE + reader mode) | 1 |
| **软件工具**(免费) | GlobalPlatformPro(装/删 applet)、JCAlgTest、ECTester、pcsc 工具链 | — |

---

## 二、待定决策(采购前要拍板)

1. **候选芯片家族**——两条路线,建议各选 1 张打样对比:
   - **国产 EAL6+**:紫光同芯 THD89、华大 CIU98xx 系(合规/供应链主线)。**强信号:国产的 ed25519 大概率走芯片厂 NDA 专有库,不是可移植 JavaCard**(A2 纸面研究会坐实)。
   - **国际**:NXP JCOP、Infineon SECORA——用于交叉验证算法支持与性能,尤其原生 ed25519 是否更省事。
2. **JavaCard 版本**:确认 ≥3.0.5;要 SOL 则确认卡 OS 暴露 **JC 3.1 `ALG_EDDSA`/`ALG_XDH`**(而非仅 datasheet 声明)。
3. **SOL/ed25519 走向**(依赖 A2):(a) 选原生 3.1 卡走可移植代码;(b) 为国产芯片签 NDA 用专有库;(c) 首发不上 SOL,只 secp256k1(BTC+全 EVM/BSC)。
4. **制造伙伴**:金融 IC 卡产线 + GP 装载 + perso(密钥个人化)+ 防拆封装能力;支持小批量数码印卡(每场大会印当场限定卡面)。

---

## 三、卡必须支持的算法(JCAlgTest 要逐一实测)

Keycard 底座 + 我们的 clone 新增,缺一不可:

**secp256k1 钱包 + clone 需要:**
- `KeyBuilder.TYPE_EC_FP_PRIVATE`(持久)+ **`TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT`**(瞬态——**jcardsim 当初就缺这个**,真卡务必确认)
- `KeyPair.ALG_EC_FP` 256-bit 生成;可设**任意 EC 域参数**(secp256k1 非标准曲线)
- `KeyAgreement.ALG_EC_SVDP_DH_PLAIN` 与 `ALG_EC_SVDP_DH_PLAIN_XY`(常量 6)
- `Signature.ALG_ECDSA_SHA_256`(签名 **且 MODE_VERIFY**——clone 卡内验证书要用)
- `Signature.ALG_HMAC_SHA_512` **和 `ALG_HMAC_SHA_256`**(HKDF + clone tag;最好原生,否则软回退)
- `Cipher.ALG_AES_BLOCK_128_CBC_NOPAD`、`ALG_AES_BLOCK_128_ECB_NOPAD`、`ALG_AES_CBC_ISO9797_M2`
- `Signature.ALG_AES_MAC_128_NOPAD`(Keycard 的 CCM 用)
- `MessageDigest.ALG_SHA_256`、`ALG_SHA_512`;`RandomData.ALG_SECURE_RANDOM`

**SOL(可选,make-or-break):**
- `Signature ALG_EDDSA`(JC 3.1)/ `KeyAgreement.ALG_XDH` / `TYPE_XDH` 或厂商 25519 原语——**必须真机实测跑出一笔 ed25519,不认 datasheet**

**容量与认证:**
- 足够 EEPROM(多 applet)+ RAM(瞬态缓冲);CC **EAL6+**(或 EAL5+ high)证书核验

---

## 四、B1 真机 NFC 验证矩阵(卡到货即做,解锁 CSK 设计)

这是 CSK 碰卡签名设计的**前置**,重点验 iOS 的边界:

| 项 | iOS(iPhone XS+) | Android |
|---|---|---|
| **碰卡拉起 App**(读 NDEF URL) | 后台标签读取能否自动拉起 App/App Store?延迟? | reader/HCE 能否? |
| **碰卡做 APDU 签名**(CSK 挑战-响应) | 必须 **App 已装 + 前台 + CoreNFC 权限 + Info.plist 声明 AID**——**能不能做活签名?** | HCE/reader mode 应可,验证之 |
| **预绑定"关系先于 App"** | **装 App 前那一碰只能读静态 NDEF**——预绑定靠**静态签名令牌**还是别的?令牌可被复制吗?怎么防? | 同样验证 |
| 工程指标 | 碰卡延迟、成功率、有效距离、连续碰卡稳定性 | 同 |

**核心待解**:iOS 上"关系先于 App"与"不可伪造"如何两全——定死机制后 CSK applet 才动代码。

---

## 五、B2 JCAlgTest / ECTester 步骤(卡到货即做)

1. GlobalPlatformPro 连卡,确认能装/删 applet(GP 默认密钥或开发密钥)。
2. 跑 **JCAlgTest** 全量,对照第三节逐项打勾;特别标注:瞬态 EC 私钥、HMAC-SHA256、任意 EC 域参数、(若要 SOL)ALG_EDDSA。
3. 跑 **ECTester** 确认 secp256k1 与(若要)Curve25519 的曲线行为与抗无效曲线。
4. 把我们的 applet(clone 分支)装上真卡,跑一遍 clone 往返 + 签名,验证仿真器结论在真卡成立(尤其 `getS` 返回长度是否真为 32——这是审查点名的可移植性风险)。
5. 记录每张候选卡的性能(EC 标量乘、ECDSA、HMAC 耗时)与内存占用。

---

## 六、给采购的一句话

先各买 1–2 张**紫光同芯 THD89 / 华大** + 1 张**带原生 ed25519 的 NXP/Infineon JC 3.1** 空白卡,加一台非接读卡器 + iPhone/Android 各一。目标是两周内出:①算法支持对照表(含 ed25519 有无),②真机 NFC 边界结论(含 iOS 预绑定机制)。这两张表出来,SOL 走向和 CSK 设计就都能定。
