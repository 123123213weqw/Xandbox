# 有界创建阶段观测（开发候选，完整负载未通过）

后续[固定基数活动 gauges 候选](CREATION_ACTIVITY.md)在拿不到响应头时仍可观察
尚未返回的聚合边界，区分 permit acquire 与节点复核；不是单 actor 的根因记录。
它不改变本文 13 个 timing/actor version2，也不宣称已修复原长测失败。

后续普通链路的稠密复制/分段回写候选见 [ASSET_COPY.md](ASSET_COPY.md)；无条件
零写入消除已撤回，当前也不是已证实的超时修复。下文保留阶段设计及其历史来源，不为后续普通 ELF 代签。

**本候选没有完整 Linux/KVM、负载或 cold 合格证据。** 这是普通路径的可观测性改动，
不是调度/性能修复，改变后的普通 ELF 不能继承旧 `c2e7ffed…` 的运行报告。

## 当前 31ae 程序的失败样本与解释边界

冻结源 `65ddde8`（普通实现 `49f7651`）的完整 Linux 软件/CI 已通过，真实基线与 OOM
各两启动有限正例已独立核对；第十批固定负载仍失败。公开脱敏投影见
[原始失败报告](validation/kvm-open-arrival-attempt10-failed-2026-10-27.json)。

该次已完成 open HTTP 21.720 秒，`xa_core_admission` 9.373 秒、`xa_driver_slot`
9.221 秒，合计约 85.6%。**两者都是复合边界，不能解释成 85.6% 纯排队**：
前者包含锁/检查等；后者的普通 `nodeEnvelope.acquirePrepare` 在获得 permit 后还执行
`n.check(true)`，校验节点/祖先 cgroup、FD/挂载、控制器位置、CPU/内存与磁盘余量。
本样本未分别计量 permit 等待及这段复核。早期“slot 等待”措辞不能代替这项缺失测量。

随后 switch 在共同 35 秒预算剩余约 12.659 秒耗尽；没有响应/头，其内部阶段未知而非零。
不能把成功 open 的分解转嫁给失败 switch，也不能由两个独立原始运行的时差宣称因果提速。
原 13 槽位、schema2、192 KiB/1 MiB、调用/预算/验收全部不变；本次只修正解释，
没有修改或重签旧 raw，也未把复合阶段改名为某个已证明根因。

## 动机与历史失败

`74d4507` 的原始第八批 KVM 运行仍失败：约 11 分 15 秒发生原 35 秒 actor 超时。
已捕获轮换 close 约 1.116 秒、open HTTP 约 20.093 秒、核对/guest 命令/busy 约
0.529 秒、switch HTTP 约 13.263 秒后 deadline。这是原客户端调用阶段，**不是内部
capacity/Prepare/提交/IO 的直接分解**。非事务 queue gauge 也不是该请求的等待证明。

该批仅 166 行/68 样本/155 条仅内存 inventory，无完整 40 分钟、100 tail、同步
inventory/checkpoint 或原盘 cold。预算和单实例 OOM 各两启动正例不覆盖 load 失败。
含七批历史失败共 40 个唯一外层代际/24 scope 已独立只读确认消失，无补充清理；
原始失败保留。这些结论不为本候选代签。

## 普通响应头

认证后的原 create/session open/switch 调用返回后，可用
[`Server-Timing`](https://www.w3.org/TR/server-timing/) 输出闭集名、单调 elapsed
毫秒及次数。以下仅为语法示例，**不是实测值**：

```http
Server-Timing: xa_core_admission;dur=12.345;desc="n1", xa_core_driver;dur=8.125;desc="n1"
```

JSON body、鉴权、错误码与操作返回值不变；不反射输入头、不接受 trace selector，
不增加 CORS/Timing-Allow-Origin 授权。未执行创建的 health/ready/解码失败不伪造阶段。

| 闭集 metric | 原调用边界 |
| --- | --- |
| `xa_core_admission` | Core 准入循环：锁/检查、容量或幂等 prepared 等待；不是纯队列等待 |
| `xa_core_owner_commit` / `xa_core_ready_commit` | ownership Save / READY saveLocked |
| `xa_core_driver` | driver Prepare 整体调用 |
| `xa_driver_slot` | node acquirePrepare：permit acquire **及其后的节点复核**，不是纯队列等待 |
| `xa_driver_owner` | registry reserveContext，含自身等待/提交 |
| `xa_driver_quota_reserve` | quota reserve，含原 markQuotaAttempt 回调 |
| `xa_driver_copy` | 原资产复制循环；错误返回也结束观测 |
| `xa_driver_quota_verify` | quota verifyPrepared |
| `xa_driver_activation` | 核对后的 pipe/warden/VMM/guest 激活至 Prepare 返回，不是仅进程启动 |
| `xa_session_intent_commit` | 原 Preparing intent persist |
| `xa_session_prepared_commit` | 原 Prepared candidate persist |
| `xa_session_active_commit` | 原 Active/COMMITTED binding persist |

父子区间重叠：core_driver 包含 driver 子阶段，**不得全部相加**。未覆盖区间仍未测量；
未执行/未完成阶段缺席而不是零。已结束的调用也可能失败，不证明成功、持久、Stop
或完整回收。客户端超时可能收不到响应头；不能由此推断服务端没有工作、在哪个内部
阶段或耗时为零。

每请求固定 13 个聚合槽位，无全局历史、动态 label、原始错误、墙钟时间戳、token、
tenant/Ref/session/boot ID、key/hash、路径、argv 或 guest 输出。span 结束幂等；
只使用独立有界内存锁，不持有该锁执行生命周期操作、IO 或回调。原 Registry 仍用
原子计数；响应头不是可靠审计日志，也不是新增管理接口。

只将专用 observer value 转入**原有**生命周期 context，不转移 caller 的 deadline、
取消或其他 values。原 caller 取消传播、post-fence 事务、关闭语义、Prepare deadline、
FIFO、配额、资源及调用次数不变。未观察的内部调用保持原 context，span 路径无分配。

## TEST 私有负载记录

fixture 只在同一个原 HTTP Do 返回点读取响应头，不增加请求/重试/资源/身份特判，
保留原 HTTP/Go 错误。actor 子协议为 **version 2**：每 actor 至多一个 raw 或两个
canary HTTP 观测，各至多 13 项。原 10 worker 槽位、16 actor phase、192 KiB capsule、
1 MiB frame 不变；不保存原头字符串。首失败的嵌套数值也深拷贝，后续复用不能覆盖。

分别记录“未见响应”“见响应但无 timing”“有 timing”；未知/重复/错序字段、非有限/
越界时长、错误次数拒绝为新 schema 证据，不将它们改写成任务成功。通过的新 wire
须保留真实 HTTP phase 的响应观测；公开前随私有 sidecar detach，不加 measured row。
旧 wire 必须使用其冻结验证器，不能改签为 version 2。

机制测试覆盖接线、取消/失败、binding/永久失败 key、并发与隐私；合成 HTTP、Mock、
AST/交叉编译不是 KVM 或真实耗时证据。原 40 分钟/6360 raw/240 canary/100 tail、
35 秒 actor、N4/prepare1、IO/pids/TTL/history、allowlist、公平性、checkpoint/cold
以及完整生产 Goal 均不放宽。
