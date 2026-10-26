# 有界容量等待与 FIFO 准入（开发候选，未实机验收）

这是普通 `sandbox.Manager` 的生产路径改动，不是测试客户端的重试或身份优先级。
**当前没有新程序的 Linux/KVM 长测、原盘 cold 或完整运行矩阵合格证据。**
旧 ELF 的报告不能给本改动代签；不因此完成 M2/M4 或认定生产就绪。

## 为什么需要改变

旧 Core 在没有可用实例容量时立即拒绝；释放后的名额由下一次调用竞争。
即使新请求的回复均为合法过载拒绝，也不能据此证明已有会话取得切换进展。

冻结源 `b370de1` 的第六次原始 KVM 尝试已经失败退出，未重跑：完整 40 分钟
offered window、6360 raw / 240 canary / 100 串行 tail 均有行，240 个资源采样；
没有失败行或 generator drop，两个租户各 50 次 quota tail 完成。
但四相位双 canary 成功切换数为 `[30,26]`、`[1,8]`、`[0,0]`、`[0,0]`。
后两相位均为普通 `503 UNAVAILABLE`，违反预声明的逐相位进展条件，仍判失败。
709 条内存 accepted inventory 不是已同步 inventory 或 cold 合格证据。

该次首失败只投影为 `load_setup_or_finalization`，精确内部返回错误未捕获。
上述验收违例有独立数值证据，但不能冒充直接捕获的唯一内部返回原因。
预算与单实例 OOM 各两启动正例已独立核对；包含五批旧失败，共 30 个唯一外层
代际 / 18 个 scope 均只读确认不存在、outer OOM/pids-limit 事件零，无补充清理。
原始 wire、诊断、身份、key、console 和清理收据保持私有，不随仓库发布。

## 设计约束

**等待入口的兼容性**：没有已有等待需求时，raw-only 满容量仍按原协议立即拒绝。
managed 候选可以发起有界等待；一旦存在队列，raw 可以加入同一 FIFO，防止持续
managed 请求反向饿死 raw。已入队的 raw 不会因 managed 后来离开就失去位置。
这不是给 managed 保留 VM 名额或允许它插队。

最初“所有 raw 都等待”的未提交设计虽然通过13组机制 race100，却违反这一兼容边界；
新增 raw-only 公共 API 控制三次明确失败，未送去 KVM 刷绿。旧 prepare-cancel 实验
有18秒 critical 协议，而原 Prepare 仍30秒，不能靠扩大旧实验 deadline 迁就新队列。
本候选保留该边界；实际旧运行矩阵仍须由新程序重新验收。

1. **不增加实际容量**：全节点及租户配额不变；仅持久 `DESTROYED` 提交成功后
   才释放实例预留。Stop、物理 Cleanup 返回、入队、HTTP 回复都不等于容量归还。
2. **raw / managed 同优先级**：所有已入队且当前配额允许的调用按 FIFO 获得未来
   名额。后到请求不能抢先；头部租户自身配额/元数据已满、取消或被 drain 的调用
   不阻塞其他符合条件的租户。没有 canary、租户名、到达相位或请求 key 特判。
3. **独立且对称的等待边界**：每类最多 `min(N,128)` 个等待位置，两类合计最多
   `2×min(N,128)`；每租户每类最多 `min(租户实例配额,min(N,128))`。
   raw 与 managed 不能占满对方的等待位置，但没有任何保留 VM 名额：没有 managed
   需求时，raw 可以使用全部 N 个实例。满队列正常拒绝，不隐藏排队、不无限积累。
4. **只等待，不重试分配**：等待期间不进入 Core 账本、不占 project/实例资源、不
   发布 Ref；容量分配后只执行一次原 Prepare。分配后错误仍走原来的持久 fence / 回收，
   不把不确定写入或已分配失败改成普通容量拒绝。
5. **不叠加超时**：容量等待与实际 Prepare 共用原 `PrepareTimeout` 的同一个
   deadline。可选内部 `CapacityWaitTimeout` 仅能缩短等待，默认等于 PrepareTimeout，
   禁止负值或超过后者；获准后不重新启动完整计时器。TTL 原截止时间也不延长。
6. **退出与恢复**：调用取消会撤销等待；Close 唤醒未分配调用并拒绝新资源；drain
   唤醒无 ticket 的等待调用。drain 前已经接受的单次 session ticket 可继续等待并完成
   一次预留；已用、归还、异 gate 的 ticket 不得等待或分配。队列不持久化、ticket
   不跨进程；原 session journal 的永久失败 key / 重启关闭规则保持不变。
7. **锁内只有有界内存操作**：队列及容量归属在 `Manager.mu` 下判断/修改；gate
   inspection 与 notification 配对，最终仍由 gate reserve 与 drain 线性化。
   不持有全局锁做 journal I/O、driver RPC、等待、Stop 或 Cleanup。

这不是加权租户调度、资源抢占、跨节点调度或过载下所有请求必被接受的保证。
队列本身满时仍可拒绝；FIFO 保证针对已进入队列且配额允许的请求。
不宣称确定性时延、最大吞吐量、任意恶意流量下的服务公平性或生产 SLO。

## 可观测性和测试边界

新增固定基数 gauges：`xandbox_create_queued`、`xandbox_create_queue_capacity`、
`xandbox_create_queue_capacity_per_class`。仅读取 atomic / 不变边界，不获取生命周期锁；
是进程内独立观察，不是事务快照或资源释放证明。`create_call` 耗时包含容量等待。

FIFO 顺序与 deadline 同一性测试使用明确的无资源/无持久化 stub，
不让磁盘吞吐决定纯顺序或 deadline 身份证明；仍要求创建成功且精确比较 deadline，
不延长原2秒/3秒机制测试边界，也不把 fenced timeout 改成普通拒绝或通过。
另一个持久 DESTROYED 失败测试仍使用真实本地账本与 Mock 文件资源。
二者分别覆盖同租户 raw 洪峰下 managed 等待不被抢位、
raw 已入队后先于后到 managed 获得名额、raw-only 快速拒绝、两类对称等待上限、
租户等待上限、阻塞租户不拖累邻居、取消、
Close、drain / 单次 ticket、幂等重放/并发重复、失败的 DESTROYED 提交不释放容量，
以及排队/Prepare deadline 精确相同。它们不是真实 KVM、掉电或生产性能证据。

新程序仍需独立交叉/原生构建、完整软件/CI、固定 ELF 探针重新校准与真实预算/OOM/
完整持续负载及 cold 回归。保持原 40 分钟、到达率、worker、client queue、actor、
N4、prepare worker 1、Stop/GC/TTL/history 和所有错误 allowlist 不变。

后续 TEST fixture 为真实收尾检查添加闭集阶段投影：offered clock、post-offer 空状态、
quota tail、post-tail 空状态、acceptance、FD drain、最终采样、采样校验、inventory
与 checkpoint。仍返回原始错误、只保留第一个失败；已存在的 worker/tail 行不被通用
defer 覆盖。只公开固定阶段名，不导出私有错误文本、不添加 measured result 行，
不改变通过条件、请求数、预算或成功报告。机制测试与静态 wiring guard 不是实机故障证据；
不能借此改写 b370de1 原始报告或宣称已捕获其精确内部返回原因。
