# NDEF 深链令牌设计 v1(场景①⑧⑩ · 纸面草案,B1 真机后定稿)

> 2026-07-20 · 覆盖十场景中的 ①碰一碰加好友/绑邀请/进群(冷启动流)、⑧群会员卡、⑩碰卡收款。
> **状态**:格式草案已定;**最终行为等 B1(真机 NFC,尤其 iOS)实测后定稿再落码**。卡侧零代码改动。

## 一、结论先行

- **一条短 URL 承载全部三个场景**;NDEF 只放**一条 URI 记录**;服务端按 serial 分流。
- **卡侧现状即够用**:`NDEFApplet` 已是标准 Type-4 标签(512B 数据文件),钱包 applet 的 `STORE_DATA(P1_NDEF)` 已支持写入。本设计只定义"写什么"。
- **设计锚点(iOS 硬约束)**:iPhone 后台碰卡只认 **universal link(https:// URI 记录)**,自定义 scheme 不触发;一切冷启动信息必须塞进一条 URL。

## 二、URL 结构(唯一载体)

```
https://ant.fun/c/{serial}?t={token}
```

| 字段 | 内容 | 说明 |
|---|---|---|
| `serial` | 卡序列号 | 本来就印在卡上,公开信息 |
| `t` | 平台签发令牌 | `base64url( ver(1B) ‖ serial绑定 ‖ 签发时间(4B) ‖ HMAC-SHA256截断(16B) )`,对客户端不透明 |

- 令牌由**平台密钥签发**(激活时服务端出),服务端验签、可吊销。
- 目标全 URL **≤120 字符**(顺便可印成二维码兜底)。
- URL 中**无任何秘密**。

**已决策**:令牌走平台签发,不用 CSK 芯片签发(静态令牌反正可复制,芯片签不多一分防复制;平台签链路最短、可吊销)。业务构想中"凭证经芯片签名"的强证明由**流 A 的 CSK 活签名**承担,不由静态令牌承担。

## 三、NDEF 布局(512B 文件)

单条 **URI 记录**(NFC Forum well-known type `U`,URI 前缀码 `0x04` = `https://`):

```
[NLEN 2B] [NDEF record: MB=1 ME=1 SR=1 TNF=0x01 | type len 1 | payload len | 'U' | 0x04 | "ant.fun/c/{serial}?t={token}"]
```

约 7B 头 + URL 正文,总占用 <135B(512B 用不到 1/4)。**不放第二条记录**(iOS 后台只认 URL;Android 同一条即可;YAGNI)。

**写入路径**(激活时 App 执行,复用现有命令):`STORE_DATA(P1_NDEF)`,P2 为 4 字节页偏移,数据含 2B 长度前缀(与 `NDEFApplet.processReadBinary` 的 `NLEN` 读法一致)。

## 四、三场景同一入口,服务端分流

| 场景 | 碰卡后 | 服务端 |
|---|---|---|
| **① 冷启动邀请** | iOS 后台读 URL → universal link → 落地页/App Store(deferred deep-link);Android 同理 | 验令牌 → serial 查**库存链** → 预绑定邀请关系(归因权威是库存链,令牌只是兜底/UX) |
| **⑧ 群会员卡** | 同一 URL | 按 serial 的卡种把落地页开到群入口 |
| **⑩ 碰卡收款** | 同一 URL → 对方打开持卡人主页 → 点"转账" | serial → **实时查当前收款地址**(永远最新、天然多链;不在 NDEF 存地址) |
| **流 A(双方已装 App)** | App 拦截 universal link,或直接做 CSK 活签名(0xD7) | URL 只是兜底 |

**落地页 `/c/{serial}` 行为**:已装 App → universal link 直接进 App;未装 → 智能横幅 → App Store/Play + deferred deep-link;页面显示持卡人主页 + 动作(加好友/转账)。令牌无效或已吊销 → 仍可看主页,但不计归因。

## 五、安全边界(与《CSK 碰卡签名协议设计》一致)

| 威胁 | 对策 |
|---|---|
| 复制静态令牌(一元贴纸) | **接受**:流 B 权重最低,归因权威是库存链;不可伪造性由流 A 的 CSK 活签名承担 |
| 伪造任意 serial 的邀请 URL 刷归属/钓鱼 | 平台 HMAC 令牌,服务端验签;无令牌/假令牌不计归因 |
| 令牌泄露滥用 | 服务端限频 + 首激活绑定 + 吊销表;令牌不含秘密 |
| 收款地址被篡改 | 地址不在 NDEF/URL 里,服务端实时下发(TLS + App 内确认) |

## 六、B1 真机后定稿项(落码前置条件)

1. iOS 后台标签读取 → App Store 跳转链路实测(延迟、成功率)。
2. deferred deep-link 具体机制(剪贴板 / 归因 API / 服务端指纹)选型实测。
3. universal link 域名关联(apple-app-site-association)与 Android App Links 配置。
4. 连续碰卡稳定性、有效距离(工程指标)。
5. 令牌确切字段长度冻结(与服务端联调)。

## 七、分工

- **卡侧**:无新代码;激活时写 NDEF 的字节序列由 App 侧按本设计第三节构造。
- **服务端**:令牌签发/验签/吊销、`/c/{serial}` 落地页与分流、收款地址实时解析。
- **App**:激活流程写 NDEF(STORE_DATA)、universal link 拦截、流 A 的 CSK 活签名调用。

*与《CSK 碰卡签名协议设计》互补:流 A(活签名)已落码,本设计补流 B(静态 URL)。合到一起,场景①②⑧⑩的卡侧与格式层就齐了。*
