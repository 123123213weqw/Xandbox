# 未完成控制写入跨关闭与实际退出的状态锁

**一个新的有限实机窗口和三项共享代码回归通过，不是生产就绪。** 冻结 TEST 源 `10eb001ab48b4fa886bf23fb4a34ec66632ac816`，归档 SHA-256 `cae14d44…`，fixture `48401ba5…`。普通 daemon 仍为 `4ee09d0a…`，五个普通产物与此前4ee集合逐字节相同；生产 Go、依赖与CI工作流没有改。[4份新报告、失败前序与完整来源](validation/operator-shutdown-provenance-v3.json)单独绑定本轮，不给旧报告换名或改 false。

## 为什么这不是前轮重复

此前 [Store EIO](NODE_OPERATOR_STORE.md) 和 [session pre-Core ticket](SESSION_TICKET_DRAIN.md) 都在关闭 daemon **之前**解决了挂起写入，不能证明 `run()` 返回后的锁保留。本例保持原始控制 Store 写入未完成，经过真实 SIGTERM、独立生命周期关闭、真实 `control.Close` 五秒超时、`run` 全部 defer 和主函数错误路径，才在实际 `EXIT_GROUP(1)` 入口设置 TEST 观察屏障。

普通源的 `releaseStateLock` 在 unfinished 时保留 unlock closure，直到内核真正结束进程。验证重点是这个精确窗口能否拒绝第二个控制器，而不是只在 HTTP handler 未返回时检查锁，也不是用微秒轮询猜测退出时点。

## 实际执行顺序

[新 shutdown 报告](validation/kvm-operator-shutdown-lock-v3.json)证明：

1. 健康普通启动自然建立 open/revision1，再干净停止；同一普通 ELF 加独立 TEST 层启动。固定层只选择 FSYNC 和 EXIT_GROUP，保留 amd64/x32 拒绝前序、CAP_SYS_RESOURCE drop、NNP/TSYNC 和普通 VMM 安全检查。无任意 path/syscall/errno/argv RPC。
2. 两个真实 raw/session guest 分别检查 KVM、UID、boot、干净 workspace 和执行；raw 中有实际 RUNNING writer。真实 CAS drain 的完整 `.state-N` payload已写入，但其精确 FD/inode/private directory/进程 incarnation/TGID/control 身份确认后的 **文件 Sync 尚未执行**。status 为 pending，新建拒绝，无 drain ACK。
3. 目标通知仍有效时发送真实 SIGTERM。其他 FSYNC 实际 CONTINUE，两个旧 guest 的执行域停止，owner/jail/cgroup 消失、真实账本 DESTROYED、全部四个 project归零。这发生在控制写入仍挂起时，不用释放目标来换取回收。
4. 真正经过生命周期 defer 与 `control.Close` 原有5s超时，要求私有错误日志精确包含未完成控制写入/deadline，且没有 lifecycle/session unfinished 错误。捕获同一普通进程实际 `EXIT_GROUP(1)`，**原 FSYNC 和退出两个通知ID同时有效**。
5. PID1启动第二个同一普通 ELF、同一 state/config/auth/budgets 的 daemon，不传通知FD，也不继承第一进程的 TEST 层。它必须真实退出1，诊断为 kernel `controller.lock` 争用；检查原锁 inode/mode、精确 metadata字节/名称/backend inventory不变，API/operator/metrics socket未重新出现。第二进程被实际reap后，第一进程的两个通知仍有效。
6. 仅发一次 EXIT_GROUP CONTINUE，不合成成功退出或 errno，**始终不给原 FSYNC 任何回复**。第一进程实际退出1并reap，再在仍打开的listener上确认两个ID均ENOENT；不能用已关闭FD的EBADF冒充通知失效。独立 serve 保持FD跨POLLHUP存活，显式关闭前无busy-spin。
7. 确认原盘仍为 old open1、旧两代持久销毁/配额0，才写私有receipt并进行自己的L1冷启动。普通daemon启动前先读回原盘authority/config/空资源/配额；无额外TEST观察层的普通恢复仍open/pending0，旧创建键410、旧route不复活，原拒绝key可创建第三个独立真实guest并完整回收，最后整个NodeRoot子树移除。

**未ACK的 pre-file drain 不保证跨进程保存为drained。** 本例目标Sync从未执行，旧open1是正确的原盘事实；没有伪造持久fence、自动resume、恢复旧owner或手改准入元数据。private receipt不是控制账本修复。

## 独立观测，不是SLO

| 从同一次SIGTERM起，N=1 | ms |
|---|---:|
| 两个已知host执行域empty/已删除 | 63.044 |
| 两代private/owner/jail/cgroup消失、实际DESTROYED与全部quota0 | 171.054 |
| 观察到真实EXIT_GROUP入口 | 5166.787 |
| 锁竞争的第二个普通daemon被reap | 5182.374 |

后两项包含固定5s控制关闭等待，绝不是退出/回收提速指标。观测包含轮询、读回与调度开销，不能回填为内部阶段时刻、百分位、物理擦除或生产SLO。20s持有上限、5s control Close、原 node-budget-v1 的8GiB/12GiB/CPU8/noNIC资源均未增加。

目标FSYNC回复0次，目标EXIT_GROUP CONTINUE 1次；另提交22个FSYNC和3个其他EXIT_GROUP CONTINUE回复，均不是已完成syscall次数。其他EXIT_GROUP允许合法为0：`cgroup.kill` 的SIGKILL无需经过退出syscall。本例观察到3，不将其硬编码为通用最低值。

## 三项实机回归与失败前序

共享wrapper/start和固定cold receipt helper有改，因而以同一新fixture重新实际执行 [ticket](validation/kvm-operator-shutdown-ticket-v3.json)、[pre-file](validation/kvm-operator-shutdown-store-pre-v3.json)、[post-root](validation/kvm-operator-shutdown-store-post-v3.json)，各2次L1启动。新ticket仍是最初既有active2，旧raw GC后最终CONTINUE前active1/pending1/records2，Ready后active2/pending0/records3；保留此前字段的阶段口径，不改raw JSON。两个Store回归仍各一次EIO、分别cold oldopen1/newdrained2。加新shutdown共4个通过scope、8个外层代际，不重复宣称为全套25scope生产复验。

完整native race×3/vet、fixture race×10/vet、root Python103零skip、CGO-free实际kernel filter×3、make mock6、Darwin race×3/vet均实际通过；六个native与独立cross相同。[mock6](validation/operator-shutdown-mock-derived-v3.json)只是原make日志六个JSON对象的明确derived副本，不是硬件证据。

保留两项真实前序失败：

- 第一个runner把已上传的source-v1误写为source-v2文件名，[原输出](validation/operator-shutdown-input-failed-v1.txt)在校验输入阶段立即退出1；未解压/原生构建/启动L1。流式上传曾超时，已用同一授权严格SSH路径读回完整SHA/大小恢复，未盲目重写或称网络硬阻塞。
- 冻结 `fe1fb6e…` 的全部原生gates/native6通过，但第一次真实shutdown checkpoint在测试inventory复用了“仅JSON journal”的helper，错误拒绝正在持有的 `.state-N`，在启动第二控制器之前失败。[原报告仍false](validation/kvm-operator-shutdown-lock-failed-v2.json)，仅1次L1启动、无cold、无三项回归；[原诊断的精确单行derived摘录](validation/operator-shutdown-failure-diagnostic-v2.json)保留私有console SHA，其他console不公开。

修正只把TEST inventory约束到固定目录、精确held临时名及state.json、两条ledger/一条session/backend config、空jail和无generation子cgroup，并加入正反例。没有放宽生产锁、NodePolicy、预算或超时；同时代码审查修正“其他EXIT_GROUP可为0”的计数契约，原失败发生在输出计数校验之前，raw报告没有改写。新源重新冻结、重新完成全部gates与新实机，没有把旧失败改成成功。

[最终独立只读审计](validation/operator-shutdown-independent-cleanup-v3.txt)确认通过8代及失败1代的精确root/control/parent/all groups均不存在，3个runner全部terminal/gone，无补救清理。live配额证据来自L1内，不从外层删盘推断。30个白名单regular原始成员保留两轮构建、失败报告和3个runner；audit stdout另存。身份/请求ID/epoch、私有receipt/token/key、console/controller日志、镜像均不公开。

## 仍未完成

本例只关闭一个未完成control pre-file写入跨shutdown/run返回的窗口，不代表所有metadata/catalog提交或关闭故障、实际filesystem D/物理介质故障。最坏RAM/ancestor/affinity/uniqueRAM/全资源压力、open-loop/fairness/长期SLO、生产TLS/凭证生命周期/networking、真实operator/systemd、持久审计/告警/日志与archive/rotation预算、备份/升级/回滚、双supervisor/预热/完整初始化及原完整M1–M4仍未完成。Goal ACTIVE，PR19 Draft，main和主分支ZIP不变，`production_ready=false`。
