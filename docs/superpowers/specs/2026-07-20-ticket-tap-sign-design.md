# Ticket 碰卡核销核心 — 设计文档(卡侧 · 待 B1/服务端集成)

> 2026-07-20 · 场景④(卡即门票,入场碰卡核销)的卡侧基石。CSK 碰卡签名的孪生:同一挑战-响应骨架,换域 + 独立密钥 + 独立计数器。
> **状态**:卡侧协议已定;服务端票务/权限、闸机集成、印卡在本版之外。

## 一、定位与范围

**Ticket 核销 = 卡向场馆/服务端证明"这张真卡本人在场、要核销某场活动的票"。** 与另三把密钥严格隔离:

| 密钥 | 面向 | 用途 |
|---|---|---|
| 资产私钥 | 链 | 签交易 |
| DAK 设备认证 | 平台 | 证明"我方真卡"(激活验真、clone 接收方认证) |
| CSK 名片签名 | 他人 | 碰卡加好友、见面证明 |
| **TSK 票据签名** | **场馆/服务端** | **入场核销 + 在场证明** |

**本版卡侧范围**:一把独立 TSK 密钥 + 一条核销活签名 + 一个独立单调计数器。**不含**:tier/VIP 权限判定、年卡/多日次数上限、卡内票据 blob、闸机离线验证、数码印卡——这些是服务端 / perso / 硬件的活。

## 二、已定决策

- **核销权威 = 在线**:卡只出一次活签名,"已用/未用"由服务端权威判定。卡上**不存任何活动数据**(event/tier 都不存)——票 = 服务端里 `serial × event` 的权益记录。
- **独立票据密钥 TSK**:票据专用密钥对,与资产/DAK/CSK 严格隔离;核销签名结构上不能被挪作名片或转账用。
- **计数器只记次数**:卡内持久单调计数器,每次核销 +1 并绑进签名(防重放纵深);**卡不设硬上限**,单次/多日/年卡由服务端权限判定。
- **放 `CashApplet`**:复用其 CSK 碰卡签名骨架(挑战-响应 + 域分隔 + 持久单调计数器);TSK 作为独立 key 对象 + 独立计数器与 CSK 并存。密钥隔离靠独立 key 对象保证(同 applet 不影响隔离;AID 隔离≠密钥隔离,首版核心用不上)。未来需独立 AID 再拆出 `TicketApplet`。

## 三、卡侧接口(净新增)

独立 TSK 密钥对在 install/perso 时卡内生成;TSK 公钥导出 → 随 serial 登记入平台(核销验签只认注册公钥)。

```
INS_TICKET_TAP_SIGN:
  App → 卡 : eventId(定长) ‖ nonce(服务端随机) ‖ (可选 ctx 变长)
  卡      : ticketCounter += 1   (卡内持久单调,独立于 CSK 计数器)
            sig = ECDSA_TSK( SHA256( "ANTFUN-TICKET-v1" ‖ eventId ‖ nonce ‖ serial ‖ ticketCounter ) )
  卡 → App: serial ‖ ticketCounter ‖ sig
  App → 服务端: 用 serial 查注册 TSK 公钥 → 验签
              + 校验 serial×eventId 权益(有票/tier/是否已用按策略)
              + nonce 查重(时间窗内一次性)
              + counter 单调校验
              → 标记已用 / 放行
```

要点:
- **卡对完整挑战哈希签名**,把**域前缀 `ANTFUN-TICKET-v1` + eventId + serial + ticketCounter** 一起纳入 → 一条核销签名语义唯一。
- `eventId` 进签名 → A 场票的签名不能被拿去核 B 场。
- 域前缀 + 独立密钥 → 与 CSK(`ANTFUN-TAP-v1`)、资产密钥不同域,票据签名对名片/钱包无意义。
- `ticketCounter` 独立于 CSK 计数器(核销次数 ≠ 社交碰卡次数)。

## 四、安全性质 ↔ 威胁

| 威胁 | 对策 |
|---|---|
| 复制卡 / 拍照卡面伪造票 | 活挑战-响应:私钥不出芯片,复制品签不出 |
| 重放旧核销 | nonce 一次性 + ticketCounter 单调 |
| 跨活动挪用签名 | eventId 纳入签名哈希,服务端核对签名内 eventId == 闸机活动 |
| 一票多刷 | 服务端标记已用(在线权威);策略层判单次/多日/年卡 |
| 伪造"官方核销" | TSK 公钥在平台注册,验签只认注册公钥 |
| 票据签名触发转账/冒充名片 | 独立密钥 + `ANTFUN-TICKET-v1` 域前缀,结构上不可能 |

## 五、借什么 / 净新增

**借(CashApplet 现成)**:挑战-响应活签名骨架、`SECP256k1.signHash`、持久单调计数器模式(JCSystem 事务)、公开数据文件形态。

**净新增(小)**:
1. 独立 **TSK 密钥对**(install 时卡内生成;公钥可导出登记)。
2. **`INS_TICKET_TAP_SIGN`**:卡内 `SHA256("ANTFUN-TICKET-v1" ‖ eventId ‖ nonce ‖ serial ‖ ticketCounter)` 用 TSK 私钥签,响应带 serial + counter。
3. 独立持久单调 **ticketCounter**(每核销 +1,事务内递增)。
4. 域前缀常量 `ANTFUN-TICKET-v1`。

## 六、测试(仿真器 TDD,照 CSK 测试形态)

1. 核销签名对 **TSK 公钥验通**;对 CSK/资产公钥验不通(密钥隔离)。
2. 不同 `eventId` / `nonce` 出**不同签名**。
3. **ticketCounter 每签 +1 且绑进签名**:同一 (eventId,nonce) 两次核销得到不同签名(counter 不同)——负控证明 counter 真进了签名、不可挪用。
4. TSK 签名与 CSK 签名、资产签名**互不干扰**(并存、各自独立计数器)。

## 七、本版之外(后续线)

- **服务端**:TSK 公钥注册表、核销验签 + `serial×event` 权益校验 + nonce 查重 + counter 单调、tier/年卡权限系统、已用标记。
- **perso**:install 时登记 TSK 公钥入平台;卡种↔票种映射。
- **B1 真机**:闸机碰卡核销 UX/延迟;eventId/nonce/ctx 确切字节格式与长度上限;counter 位宽与溢出策略。
- **进阶**:离线核销(卡内票据 blob + 剩余次数 + 抗回滚);POAP 出席徽章。

*本设计与《CSK 碰卡签名协议设计》同源,是场景④的 applet 级展开;与 clone/CSK 一样,先写先测、后接真机。*
