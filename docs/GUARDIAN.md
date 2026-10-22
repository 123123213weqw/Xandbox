# 宿主独立租约与 BOOTTIME 截止：实验性 guardian

**不是生产 SLO 或远程证明。** 这层补足“控制器进程还活着但不再推进”的停止路径；不能据此把整个项目改称生产就绪。

## 两个截止，不依赖 civil time

1. 每个实例在准入创建时、首次 ownership fsync 之前采样宿主 `CLOCK_BOOTTIME`，计算不可延长的绝对生命周期截止。Driver 接收可信 `Preparation.DeadlineNS`；请求 JSON 不能设置它。
2. 控制器 reconcile 的推进产生短租约，窗口固定 5 秒、每代最多每秒发送一次。没有脱离控制面无条件发送的后台心跳线程。停止/删除意图先原子撤销续租和执行准入，再等待该代的记录 I/O；READY fsync 返回后也重新检查撤销，不能因迟到写入重新开放实例。
3. warden 在自己的进程里以 `timerfd(CLOCK_BOOTTIME, TFD_TIMER_ABSTIME)` 监控 `min(短租约截止, 硬 TTL)`。控制器 SIGSTOP、reconcile 卡死或无续租，不需要它再执行 Stop 才能触发整代 `cgroup.kill`。

[Linux timerfd 文档](https://man7.org/linux/man-pages/man2/timerfd_create.2.html) 说明 BOOTTIME 是非 civil clock 且计入宿主 suspend 的时长；普通 MONOTONIC 不计入 suspend。本实现不使用可被人工/NTP 跳变的 REALTIME 来授权存活，也不使用 Go `time.Time` 序列化后的值在另一个进程重建安全截止。`Record.ExpiresAt` 仍为客户端展示/审计的 UTC 投影；单独修改这个投影不会延长或提前运行时期限。

这不是唤醒宿主的 ALARM 时钟。宿主 suspend 时 VM 也不执行；恢复后需由内核和 warden 获得调度来处理过期事件。未在共享验收节点上主动 suspend 或修改系统时钟，不能把接口性质当成已经做过整机 suspend 故障实验。

跨重启不复活旧 generation，不从旧的 UTC 日期恢复 BOOTTIME 截止；非 Linux 仅有进程内 mock 时钟，绝不作为 Linux guardian 的时钟域使用。

## 私有管道协议

- fd 3 只给 warden 读；写端只由控制器持有。fd 4 是已校验所属 cgroup 的 kill writer。所有额外 FD 及 timerfd 均不传给 jailer/VMM。
- guardian 先验证当前 cgroup 成员关系、kill FD、64 字符 generation key，再启动内核 timer；收到首个有效租约之前不启动 jailer。
- 固定 56 字节 `XBL1` 帧：magic、保留位 0、32 字节 ID+generation binding、递增 uint64 sequence、绝对 BOOTTIME deadline。整帧远小于 PIPE_BUF；控制器以 O_NONBLOCK 单次原子写入，不等待读者或存储锁。
- 队列积压/短写/EAGAIN/发送失败会关闭 lease writer 并栅栏实例，而不是阻塞全部控制 reconciliation。关闭与写入在短内存锁内协调，避免 FD 关闭复用后误写另一个资源。
- reader 不按“读取时刻 + 5 秒”续期。消息带发送方绝对截止；重复 sequence、错 binding、非法帧、已过期帧、超过 5 秒窗口或硬 TTL 的消息均拒绝。
- 已过期的 lease 不能复活，即使 timer 回调暂未获得 CPU、一个更新消息先到达 reader。timer 事件与续租竞争时也复查当前截止，避免旧的 timer 通知误杀已及时续租的实例。
- 部分帧读入不会阻塞另一条 timer 监控路径；EOF、协议错误、时钟/定时器失败、lease 或硬 TTL 到期都采取 fail-closed。

Binding 是防止串线的标识，不是身份凭证或密码学证明。信任边界仍是可信宿主内核/控制器/固定摘要的 warden 与其私有 FD，不能防护恶意宿主 root。

## 资源与状态不能混为一谈

warden 的 `cgroup.kill` 包含它自己和 VMM，仍不依赖 jailer 降权时会清除的 PDEATHSIG。若 warden 意外退出而控制器还能推进，控制器的子进程退出监控会停止同一 immutable cgroup。

guardian 可能已经独立停止 VM，而暂停控制器的账本仍显示 READY；它不意味着允许恢复旧 VM。控制器恢复后通过失效 lease/进程退出/调用失败栅栏，重新证明停止、清理私有资源、提交 DESTROYED 后才返还配额。进程退出、已停止、完整回收仍是分开的事实。

公开启动仍需 root 配置与固定资产摘要，新版 warden 的摘要必须与配置一致。旧状态目录的资产绑定不会自动升级；当前没有在线 guardian/配置迁移流程。

## 记录I/O卡住时的主动EOF撤销

后续 [整状态盘专项](STATE_IO.md) 增加 `Driver.RevokeLease`：reconcile在record/op/worker锁之前，反复关闭准确Ref已经拥有的活pipe capability；TryLock争用稍后重试，覆盖Prepare迟到发布，不查询磁盘归属或收养未知资源。它避免健康进程因单个fsync卡住只能等待约5秒短租约。root warden/帧协议/硬TTL不变，EOF仍不等于已证明Stop、持久STOPPED或DESTROYED；新原生4场景与完整回归的角色、失败对照和限制见专项。控制器整体暂停时仍依赖独立timer，而不是这条主动路径。

## 验证方式与边界

普通 CI 检查：绝对期限/不复活、重放和错 Ref、窗口/TTL/溢出校验、时钟不倒退、记录 I/O 不阻塞正常续租、续租失败触发恢复、civil-time 展示值不能左右运行截止、READY fsync 期间撤销不能重新发布可用实例。Linux CI 另实际使用 timerfd 测部分帧不抑制过期、连续合法续租不能突破硬截止，以及无人读取的 pipe 饱和时发送不阻塞。帧 fuzz 测试不能代替真实 VM 故障验收。

`scripts/kvm_driver_smoke.py` 的新场景包括：健康控制器跨多个 lease 窗口、SIGSTOP 整个控制器后的短租约失效、在硬 TTL 前暂停控制器，以及定点 SIGKILL guardian 后的控制器监控回收。使用 pidfd 绑定信号目标，不按历史 PID 或 UID 批量杀进程。测试只暂停本次创建的控制器，不改宿主时间、路由或其它任务。

CPU 饥饿、不可中断 kernel I/O、warden 与控制器同时失效或被同时暂停、宿主内核故障、整机重启/损坏磁盘、恶意 guest 的正常完成回包真实性及持续负载下延迟上界仍需独立处理。定时器到期不等于在该纳秒已完成所有停止/物理擦除；同代账本 I/O 仍可能延迟 HTTP 确认与最终回收。

## 2026-10-22 真实 KVM 结果

源码 `2f7ac5d4354531dbb37692e218cfdeadb8bb4582`，控制器、warden 与 Linux 测试二进制均为 Go 1.27.3、`CGO_ENABLED=0`、`-trimpath -buildvcs=false`；[原始脱敏服务报告](validation/kvm-guardian-2026-10-22.json) 保存确切 SHA-256。21 项服务检查是原 16 项、4 项 guardian 场景和 1 项独立受控 fsync 集成；后者的 [9 项断言](validation/kvm-guardian-fsync-2026-10-22.json) 单独展开，不合并宣传为 30 个独立场景。

| 场景 | 单次观测 |
|---|---|
| 健康控制器 | guest 持续 12 秒跨多个短租约窗口，仍可用并随后完整回收 |
| 暂停整个控制器、管道仍打开 | SIGSTOP 到 host cgroup 空约 4336.7 ms |
| 硬 TTL 前约 1.5 秒暂停控制器 | 暂停到 host cgroup 空约 1531.5 ms；实际硬截止后约 37.6 ms 观测为空，未提前停止 |
| SIGKILL guardian | 信号到 host cgroup 空约 343.0 ms，由存活控制器监控停止 |
| 别代 ownership fsync 阻塞 | 单 Stop/GC worker、队列 1 下，另一 VM TTL 到 STOPPED 约 50.7 ms |

暂停控制器时，验证其账本仍为 READY、ownership 文件仍在，而实际 host cgroup 已空；恢复控制器后再确认持久回收与配额释放。最后没有本次所有的 VMM、cgroup、jail 或 UID manifest 残留。该检查只操作本次 fixture 的资源，不按 UID 扫杀其它进程。

同一节点为 Xeon Silver 4216、64 逻辑 CPU、约 251.5 GiB RAM，runtime ext4；guest 512 MiB/2 vCPU/128 MiB 盘，guest 无 NIC。创建 READY 的 8 次样本约 1.42–1.62 秒；运行态 DELETE 两次接受约 2.6–2.9 ms、观测停止约 46.2–50.9 ms、持久回收约 103.5–144.5 ms。SIGKILL 控制器停止单样本约 39.1 ms，重启到持久回收约 726.2 ms。

以上是**小样本正确性验收，不是百分位、生产 SLO、快照切换时间或物理擦除时间**；包含观测开销、缓存与宿主负载未控制、RSS 未测、只写少量文件。受控 fsync 测试扫描间隔 10 ms，而 daemon 默认 100 ms；barrier 不是实际损坏磁盘。主报告 `queue_acceptance_report` 保留测试节点原文件名，公开对应文件为上面的第二个链接。
