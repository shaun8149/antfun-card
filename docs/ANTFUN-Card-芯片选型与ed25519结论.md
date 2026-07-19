# 芯片选型 与 ed25519/SOL 结论(A2 纸面研究)

> 2026-07 · 依据 5 路并行研究(国产/国际芯片、ed25519 全景、JCAlgTest 原始库、采购渠道)。JCAlgTest 部分直读 crocs-muni 的 294 张卡原始 CSV(网站表格的数据源),是最硬的证据。

## 一句话结论

1. **ed25519 / SOL:确定性延后。** 公开数据里**没有任何一张在售真卡**被证实原生支持 EdDSA;软件实现不安全。**首发只做 secp256k1(BTC + 全 EVM/BSC)。**
2. **secp256k1 两条卡路都能跑**:**NXP JCOP4 P71**(开发基线,开放、便宜、已被 Keycard 生产验证)与 **紫光同芯 THD89**(国产合规、JC3.1、OneKey Pro 在用,但 secp256k1 稳定性要实测、文档需 NDA)。

---

## 二、ed25519 为什么必须延后(证据很硬)

- JavaCard 3.1 **有** `ALG_EDDSA`/`ALG_XDH` 这套 API,但**实现是可选的**——合规的 3.1 卡允许对这些常量抛 `NO_SUCH_ALGORITHM`。"datasheet 写 3.1"≠ 能签 ed25519。
- **JCAlgTest 原始库(294 张卡 CSV)直查**:用新版测试 applet(jc304/jc305)跑过的**每一张现代真卡**——NXP JCOP4 P71D321/P71D600、Infineon SECORA、Feitian、THD89 等——`ALG_EDDSA=no`、`ALG_XDH=no`,**零例外**。仅有的 3 个 "yes" 是老版测试 applet 的伪命中(pre-3.1 芯片、猜算法 ID)。只有 **jcardsim 软件模拟器**报 yes。
- **软件 ed25519**(JCEd25519):作者明说**仅 PoC、不可生产**(非恒定时间,可计时侧信道提取私钥)。
- 连 **Status Keycard 自己的 ed25519 issue(#96)至今 open**。
- 旁证:Ledger/Trezor 的 ed25519 都**不在 JavaCard 上**做(Ledger 用 C/汇编专有固件,Trezor 用 MCU 软件库);Tangem 用三星 SE 支持 SOL,但是否走 JavaCard `ALG_EDDSA` 未公开。

**含义**:SOL 不是"选张 3.1 卡就行",而是**当前无可验证的原生路径**。要么等将来出现 JCAlgTest 实测过原生 EdDSA 的卡,要么走某芯片厂的专有/NDA 方案。**首发不碰。**

---

## 三、secp256k1 卡选型:两条路对比

| | **NXP JCOP4 P71**(J3R200) | **紫光同芯 THD89** |
|---|---|---|
| JavaCard | 3.0.5 | **3.1**(Open Config) |
| CC 认证 | **EAL6+**(NSCIB-CC-180212-CR5) | EAL5+ 复合(JCOS)/ EAL6+(硬件单独) |
| secp256k1(任意域参数 EC) | ✅ **生产验证**(Keycard 就跑在它上;JCAlgTest:瞬态 EC 私钥 + EC_SVDP_DH_PLAIN/_XY = yes) | ⚠️ JCAlgTest 显示 EC-DH 原语在(yes),**但 Satochip-DIY 反馈 stock 固件 secp256k1 不稳、需 patched build → 必须实测** |
| `TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT` | ✅ yes | 需实测(库里未见该项明确数据) |
| HMAC-SHA256(HKDF+clone tag) | ⚠️ **原生 no**(走软件回退——Keycard 的 Crypto 已内置 native-with-fallback,我们不受影响,仅性能) | ✅ yes(旧提交);新提交报 error,需实测 |
| ed25519 | no | no |
| 域文档 | 公开 | **NDA** |
| 小批量打样 | ✅ **开放**:Keycard 自家开发卡(J3R200,€30,不锁、可 NFC、无 NDA)、Satochip DIY 卡 | ⚠️ 第三方(THETAKey/CodeWav 等)有小量成品卡、GP 可加载;但完整文档/SDK 需 NDA |
| 合规定位 | 国际大厂 | **国产**(业务构想偏好) |
| 已被谁用 | Status Keycard | **OneKey Pro(4 颗)** |

**关键权衡**:国产合规(THD89)vs secp256k1 即插即用(NXP)。我们整条钱包是 secp256k1,所以 **THD89 的 secp256k1 稳定性是它能不能当产品芯片的先决条件,必须先实测**;NXP 是零风险的开发基线与后备。

---

## 四、建议(去风险最快)

1. **现在就买 NXP JCOP4 P71 开发卡**(Keycard 自家 €30 那张 + 1 张 Satochip DIY 做第二数据点)。同源、开放、已验证——**立刻解锁 B1(真机 NFC)+ B2(把我们的 clone 分支装真卡跑一遍,含 getS 长度真机验证)**。不等任何人。
2. **并行接触紫光同芯(THD89)**:要样卡 + 签 NDA 拿 SDK/文档,**第一件事就是实测 secp256k1 能不能稳定跑我们的 SECP256k1 + clone**。跑通 → THD89 就是合规产品芯片;跑不通 → 老实用 NXP 或换国产候选(华大 CIU9872B_01 是 EAL6+ 但公开信息几乎为零,也得 NDA 实测)。
3. **SOL 从首发范围移除**,写进产品说明;未来单独立项(等原生卡或谈专有方案)。
4. HMAC-SHA256 在 JCOP4 上走软件回退不影响功能(Keycard 已处理),只做性能记录。

---

## 五、给采购的一句话(更新版)

先买 **NXP JCOP4 P71(J3R200)开发卡 2–3 张 + 非接读卡器 + iPhone/Android 各一**,一周内就能把真机 NFC 与真卡算法两张表跑出来。同时启动**紫光同芯 THD89 的样卡 + NDA**流程(周期长,越早越好),目标是实测它的 secp256k1。两条线并行,产品芯片在"NXP 兜底、THD89 争取"之间两周内可定。

*来源见各研究子报告;核心证据:JCAlgTest 原始 CSV 库(crocs-muni/jcalgtest_results)、THD89 NSCIB-CC-2400175-01 ST-Lite、Keycard 开发卡商店、OneKey 帮助中心。*
