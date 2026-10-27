# 有界活动创建观测（候选，不是超时修复）

后续 f286/DA42 的[第十一批原始负载](validation/kvm-open-arrival-attempt11-failed-2026-10-27.json)
也未通过。活动 capsule version1 的 8slow+1failure 均严格观测成功；失败快照中
switch 类别的 request/CoreAdmission 计数各1，但独立聚合数仍不能标识失败 actor、
其阶段时长或唯一根因。新[quiet 冷启动候选](QUIET_COLD_BOOT.md)改变普通 ELF，
不继承这些旧版本的软件、CI 或硬件正例。

旧 `31ae3175…` 的[原始第十批长测](validation/kvm-open-arrival-attempt10-failed-2026-10-27.json)
仍失败。失败 switch 没有响应，不能从缺席的 Server-Timing 推断内部阶段或零耗时。
本候选为普通程序增加**当前活动**的固定基数 gauges，不是调度/性能改动；新 ELF
需要自己的完整软件、原生 Linux/CI、KVM/40 分钟/cold 与受影响运行矩阵验收。
未合并、未部署，不继承旧程序报告，不因此完成任何生产里程碑。

## 只描述实际进入但尚未返回的边界

认证后的原 raw create、session open、session switch handler 以编译期枚举绑定
Manager 自己的 Registry。没有输入 header、身份、key、路径或任意 label 选择器，
JSON body、错误码、业务调用、取消传播、post-fence 事务及队列政策不变。

现有受限 metrics 通道新增固定 **50 条**数值序列：

| metric | 固定维度 | 含义 |
| --- | --- | --- |
| `xandbox_creation_activity_enabled` | 1 | 本进程已有 handler 激活观测；0 不是已观察到零工作 |
| `xandbox_creation_activity_invalid` | 1 | 计数溢出/不平衡等无效状态的 sticky 标志，不自动清零 |
| `xandbox_creation_requests_active` | 3 operation | handler 作用域，包含响应处理，不是执行资源/任务数 |
| `xandbox_creation_phases_active` | 3 operation × 15 phase | 进入实际边界、尚未 End 的调用数，父子区间重叠 |

operation 顺序固定为 `raw_create`、`session_open`、`session_switch`。前 13 个 phase
与[原创建 timing 词表](CREATION_TIMING.md)相同；另外两个**仅是 gauges**：

- `xa_driver_permit_wait`：实际 `prepareGate.acquire(ctx)` 调用，包括 select 与返回前
  的取消检查；不是精确的内核睡眠、channel 线性化或“必定正在等待”证明。
- `xa_driver_node_check`：获准后的实际 `n.check(true)` 节点/祖先资源复核。

原 `xa_driver_slot` **仍覆盖二者及其间的代码**，没有偷偷缩窄旧指标定义。
Server-Timing 仍只有原 13 个槽位；新增 gauges 不进入该响应头，也不在其中伪造时长。
新增计数 bookkeeping 放在原 response span 的时钟采样之外；整个请求和原 35 秒 actor
墙钟预算仍包含全部实际开销。观测不是免费操作，也不宣称改善吞吐或延迟。

调用取消不结束 span；必须等真实调用返回。handler 结束也不替后续 carried lifecycle
span 宣告完成。因此 requests 与 phases 可以跨过不同瞬间，不能要求 phase ≤ requests。
仅读取原子量，不取生命周期/trace 锁，不增加 worker、队列、时钟、重试或历史。
计数不会包绕；错误只标记观测无效，不改变业务准入、返回值或资源归属。

**不可推断**：这些是独立采样的聚合数，不是某一个请求、tenant 或 Ref 的记录。
即使某类当前只有一个调用，也不能把采样自动归因到已超时的 actor；零也不证明
该阶段未发生、耗时为零、所有内部调用均被观测、执行已停或资源已回收。
既有未安装 observer 的内部调用不计入这些 gauges。它们不是可靠审计日志。

## TEST 私有捕获，不增加管理请求

fixture 在原来 slow/failure 观测的**同一次 metrics GET** 中读取这些数值；最多仍是
8 个 slow 加 1 个 failure。没有新 timer、请求、重试、console/文件写入或测量结果行。
原 actor version **2**、13 个响应项、192 KiB 私有 capsule、1 MiB frame 均不放宽。

私有 capsule 必须携带 `creation_activity_version: 1`；每个 observation 另有：

- `creation_activity_status`：仅 `observed/missing/disabled/invalid/malformed`。
- `creation_activity`：未知状态必须为 `null`，不是零数组；observed 时为严格的
  `{version:1, requests:[3], phases:[3][15]}`，每项为有界整数，不含身份或原文本。

phase 数组前 13 项依次为 Core admission/owner/driver/ready、driver slot/owner/
quota reserve/copy/quota verify/activation、session intent/prepared/active；最后两项为
permit acquire 与 node check。序列来自固定枚举，不接受任意 Prometheus label。
快照深拷贝；未知/重复/错序 label、部分字段、坏版本、非整数或过大值不得成为零观测。
数据仍随私有 sidecar detach，不进入公开的成功/失败业务行。

最初仅给 observation 中的新对象加版本号，**不能区分没有 slow/failure 行的旧
capsule**。同一冻结合成输入三次暴露这个漏洞；补上 capsule 必需 discriminator 后
三次拒绝。它是软件协议反例，不是 KVM 故障。旧 wire 必须使用自己的冻结验证器，
不能借新 schema 重新签发旧报告。

## 验证范围与仍未完成的工作

源码 `59205036eb6636c4124472526384215081da6cdf` 的[有限软件证据](validation/creation-activity-mechanisms-2026-10-27.json)
已逐文件绑定到原生工作快照：15 个机制父测试各 race ×100 / CGO0 ×100、零 skip；
完整 fixture 153 个父测试各两构建 ×3、零 skip（固定9点 ELF 指纹检查生效，非 live
trace）；root Python 308 项零 skip、vet/mod 通过。旧 HTTP/node 的实际编译负例与
旧物理接线 guard 各两构建 ×3 明确失败，33 份原始软件文件已独立重验 hash。
这些不是完整 Linux 默认43包/24工件、新头 CI、真实KVM或新长测的合格证书。


机制测试覆盖断连后真实未返回调用、三类 handler 的同 Registry/固定枚举连接、
实际 permit 取消/节点拒绝、首错/并发 End/溢出/禁用、完整 producer/consumer 序号、
复制及严格 Python schema。合成阻塞 driver、AST 和 ELF 指纹不是实机根因、磁盘、
KVM 或性能证据；fixed uprobes 也需要按新普通 ELF 重新校准并实测。

保持原 N4/prepare1、35 秒 actor、40 分钟/6360 raw/240 canary/100 tail、
checkpoint/原盘 cold、配额/TTL/history、allowlist/FIFO/公平性与全部失败历史。
没有更短的“成功模式”、保留 canary 容量或宿主执行回退；完整生产 Goal 不缩减。
