# 停止与清理分池：实验性生命周期调度

**不是实时系统或生产 SLO。** 本页补充 [Firecracker 驱动](FIRECRACKER.md) 的控制面机制，不改变 `202 ≠ 已停止 ≠ 已回收` 的契约。

## 执行顺序和背压

```text
准入栅栏/取消 Prepare 与任务
  → 有界 Stop 队列 → 固定 Stop workers → host 停止证明 + 持久 STOPPED
  → 有界 Cleanup 队列 → 固定 Cleanup workers → 私有清理 + 持久 DESTROYED
  → 返还实例配额
```

- reconcile 扫描不执行存储或阻塞式 driver I/O；driver IPC 仅有 [guardian](GUARDIAN.md) 的有界、非阻塞续租和已拥有租约的撤销。对每代 mutex 使用 TryLock，跳过被自身存储操作卡住的记录。每个池使用轮转游标，不一直从固定最小 ID 抢队列位置。
- 一个 generation 最多有一项后台工作处于排队/执行状态；同代 Prepare/Stop/Cleanup 仍串行。等待同代操作的显式 Stop 可被请求 context 中止；后台 worker 不停车等待 Prepare/GC 占用的同代 gate。
- 每池队列独立、有界。队列满时保留账本/内存意图，后续扫描继续调度，不丢 ownership，不启动“一请求一后台 goroutine”，不提前归还配额。清理堵塞会使新建最终得到 capacity/tenant quota 背压，而不是积累无限实例。
- DELETE 的同步持久化仍决定能否返回 202，不依赖队列空闲。TTL/Close 的内部栅栏先在内存取消任务，worker 随后持久化。进程丢失后，非终态账本全部栅栏并重建队列；队列本身不是另一份持久真相。
- STOPPED 只在 driver 已确认整个执行域停止、已接受调用全部退出且账本提交成功后发布。已停止确认有一次性的通知，显式 Stop 无需排在随后的同代慢 GC 后面；这不是复用旧实例或重新打开执行准入。
- 停止栅栏的存储调用**已返回错误**时，仍以独立、受StopTimeout限制的context尝试停止当前已归属Ref；始终保留原始存储错误，driver.Stop错误也不丢弃。该分支不写STOPPED、不发布停止确认、不做Cleanup或返还容量。存储调用本身卡住尚未返回时，这个分支无法执行，独立guardian仍是后备；不能因此宣称不可中断I/O有了毫秒级上界。[新二进制有限故障与全矩阵回归](EMERGENCY_STOP.md) 已完成；旧报告不自动覆盖新程序，实验时延不是生产上界。
- Cleanup worker **不负责 Stop**，仅处理已停止且要求删除的记录。大规模文件删除与停止证明不会占用同一池。

实例数上限仍包含 READY、STOPPED、排队、重试和清理中的全部未回收记录。历史 tombstone/幂等 key 的保留容量治理尚未完成，不能将队列有界当成整个存储已经有界。

## 配置和观察

`sandboxd` 新增三个操作员参数：

| 参数 | 0 / 默认自动值 | 有效显式范围 |
|---|---|---|
| `-stop-workers` | min(4, max-instances) | 1..64 |
| `-cleanup-workers` | min(2, max-instances) | 1..64 |
| `-work-queue-size` | min(32, max-instances)，**每池** | 1..10000 |

`Stats` 暴露 stop/cleanup queued、running、worker 数及每池队列容量；排队数不包含保留意图但尚未入队的记录，不能据此计算全部待处理资源。recovering 是单代状态的原子派生值，避免 Stats 等待别代 fsync。多字段观测不是跨线程原子快照，也不是完整 Prometheus/审计实现。带鉴权的公共 health 仍不泄露全节点统计。

增加 worker 不等于增加物理容量或提高停止延迟上界，可能让磁盘竞争更严重。控制器规格、实例配额和磁盘/内存预算仍需独立设置。

## 归属与关闭不变量

Firecracker 的 owner/UID 内存表由短 RWMutex 保护；fsync 不在该锁或 procs 锁内执行。不同 generation 可并发持久化；同代操作由生命周期 gate 串行。新 UID 在持久保存完成前不可启动资源，删除归属的 fsync 完成前仍保留 UID。一个实例慢 fsync 不能让另一台 VM 的 Stop 仅因等待全局 driver mutex 而停住。

`Close(ctx)` 先关闭全局准入并唤醒 reconcile，不逐个同步持久化后才检查关闭期限。超时返回错误，旧 worker 可能仍在不可中断的文件系统调用里，**不等同于它们已经退出或资源已回收**。daemon 在这种情况下保持独占状态锁直至进程退出；不能让新进程与旧写入者同时操作账本。嵌入方需自行保持独占所有权；`LifecycleDone()` 只表明 lifecycle 池退出，不能证明恶意/不合约 Driver.Exec/Prepare 也已结束。

## 验证范围

普通 CI 使用可控 barrier 检查：单 worker/单队列饱和、TTL 与显式 Stop 仍推进、正在 GC 的同代 Stop 快速取得既有确认、配额保留、跳过别代记录锁、Close 截止与重启恢复、Prepare 取消及 gate 等待取消、UID 在删除 fsync 内仍被预留、归属读取不等待别代持久化、未结束 worker 的进程状态锁仍保留。它们是确定性故障测试，不是磁盘性能测量。

真实 KVM 额外入口为 Linux test binary 中的 `TestKVMQueueIsolation`：默认跳过，必须由私有 root fixture 显式启用。生产 daemon 没有故障注入环境变量或 RPC。将一代私有资源删除后的 ownership-directory fsync 人为阻塞，观察另一代的 TTL host cgroup 停止、任务退出、队列背压和失败 Close 后新 controller/driver 的恢复。该 barrier 是**受控慢 I/O 模型，不是实际损坏磁盘**，不覆盖全节点文件系统失效。

```sh
CGO_ENABLED=0 go test -c -trimpath -buildvcs=false \
  -o bin/firecracker-queue.test ./internal/firecracker
sudo -n python3 scripts/kvm_driver_smoke.py \
  --daemon bin/sandboxd --warden bin/xandbox-warden \
  --queue-test bin/firecracker-queue.test \
  --firecracker work/kvm-assets/bin/firecracker --jailer work/kvm-assets/bin/jailer \
  --kernel work/kvm-assets/vmlinux-6.1.188 --initrd work/guest.cpio.gz \
  --source-revision "$(git rev-parse HEAD)" \
  --report work/kvm-queues.json --log-dir work/kvm-queues-private-logs
```

它复用真实服务基础验收，并单独输出 `*-queue.json`；不能把标准 CI 的 skip 当成 KVM 通过。

## 仍缺少的门槛

整节点磁盘故障与宿主重启、所有 Stop worker 同时卡死、持续到达负载下的公平性/资源曲线、物理/加密擦除、完整元数据保留期、快照/预热池和原子会话切换仍未完成。独立 BOOTTIME 租约已增加 [实际暂停控制器的证据](GUARDIAN.md)，并在记录锁前撤销停止意图的续租；它不让不可中断账本 I/O 变得可取消。同代 HTTP 确认、持久状态和最终回收仍可能被延迟，双监督失效/内核饥饿也无生产上界保证。真实故障策略仍需 M2/M4 补齐。

## 2026-10-22 实机证据

[服务回归报告](validation/kvm-queues-2026-10-22.json) 的 17 项为原 16 项真实服务检查加一个独立受控阻塞用例；后者的 [9 项详细断言](validation/kvm-queues-fsync-2026-10-22.json) 单独保存。两份原始脱敏 JSON 来自同一次源码 `1f42115` 验收，分别记录真实 daemon 和 Linux test binary 摘要。服务报告中的 `queue_acceptance_report` 保留测试节点的原文件名；公开对应文件为此处第二个链接。

Go 1.27.3、真实 KVM/VMM/guest-agent；使用一个 Stop worker、一个 Cleanup worker、每池队列容量 1、两个 VM、20 秒 TTL，**测试扫描间隔为 10 ms，不是 daemon 默认 100 ms**。在 A 的归属删除 fsync 阻塞时，B 从 TTL 到观测 STOPPED 的单次样本约 52.8 ms，且实际 host cgroup 已空、任务已退出。A 的 UID 与两个实例配额一直保留到清理/持久提交；已确认的 Stop 不等待 A 的慢 GC。Close 在期限返回错误后，继续保持独占 fixture 锁，等旧池退出再创建新 controller/driver，并完成账本恢复与全部资源回收。

这是受控故障证据，**不是磁盘性能、百分位、持续吞吐或生产最坏延迟承诺**。CI 常规编译/skip 不能代替这次手动实机运行，且两个 VM 不是多租户大规模压测。

guardian 版本源码 `2f7ac5d` 已重跑同一 [服务回归](validation/kvm-guardian-2026-10-22.json) 和 [受控 fsync 断言](validation/kvm-guardian-fsync-2026-10-22.json)：B 的 TTL 到 STOPPED 单样本约 50.7 ms。本次改用实际 BOOTTIME 截止计算样本并拒绝提前停止；仍不是生产延迟承诺。前一组历史报告原样保留。

## 整状态盘卡住的后续专项

[STATE_IO.md](STATE_IO.md) 在停止/清理池之外增加有界 `RevokeLease`，先按原子intent关闭已经拥有的活pipe，不等待record I/O、代际gate或worker。原子intent对应的新Exec也不再排在该record mutex之后才返回409。普通Stop/调用drain、持久STOPPED、Cleanup及DESTROYED仍必须完成，物理停止不释放配额；本轮四场景不证明所有worker/监督者失效或内核不可中断I/O的上界。

## 会话撤销的直接租约信号（待实机重新验收）

`RevokeScoped` 先核对不可变租户/Ref，再单调设置内存删除意图、撤销执行准入和续租资格，并唤醒 reconcile；随后直接调用同一个有界 `Driver.RevokeLease`，不必等下一次扫描才尝试关闭该 Ref 已拥有的 live pipe。它不读归属文件、扫描 PID/cgroup、执行 Stop 或 Cleanup，也不创建新 goroutine。驱动 TryLock 争用、尚未发布的 Prepare 仍由原有 reconcile 反复尝试；直接信号失败只保留失效标记，不抹掉意图或改变原有返回语义。

这是消除一次控制面调度依赖，不是提前发布 STOPPED/DESTROYED、返还容量或跳过持久化。普通测试在不启动 reaper、持有 record/generation/worker 锁的条件下检查直接信号、错租户/旧代隔离、失败保留和并发幂等；这些确定性检查不是 KVM、压力吞吐或停止时延证据。原有高负载失败和所有预算、FIFO、公平性、资源/配额及回收门槛不变；该改动尚不能证明解决创建路径的排队或服务成本。
