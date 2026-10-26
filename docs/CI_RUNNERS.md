# CI runner 镜像维护

## 容量 FIFO 新候选的固定 ELF 绑定（尚待原生/实机验证）

普通 Manager 的[有界容量准入](CAPACITY_ADMISSION.md)改变普通 daemon。
Go1.27.3 linux/amd64、CGO0、`-trimpath -buildvcs=false` 独立交叉产物为
`c2e7ffed…`；仅有交叉编译证据，不能代替 Linux 原生或 KVM 验收。
三组原目标函数的 source-relative/normalized 指令与长度逐项相同，九个固定点的
opcode/寄存器、符号范围与可执行 file-backed segment 字节已离线核对。
Go 与 Python 的唯一固定 hash 同步更新，未开放 hash/offset 选择器或跳过闸门。
新源码仍须独立原生重建、核对普通 ELF 逐字节一致并完整跑对应软件/CI/运行门槛。
下文7ccb及更早报告保持原来源，不给新候选代签。

容量顺序/deadline 身份机制的本地重复曾遇到原2秒预算内真实 fsync 延迟，
修正为明确无 I/O stub 的纯机制证明，保留实际账本持久回收测试；不放宽2秒/3秒、
不接受 fenced timeout 冒充成功。原共享300ms catalog 测试另改为每操作各自同300ms
锁隔离检查，整个 quota release barrier 仍保持；生产 registry 未改。
全量本地门槛及两组相反方向的负对照均保留来源，但这些不是 Linux/KVM 证据。

## macOS 14 → 15（2026-10-26）

冻结源码 `701e144a42aa5d03a702838de78fa6ae0366ec7f` 的原始 push/PR CI
`40303000139` / `40303005658` 均保留为 **failure / attempt1**：各 5 个非 macOS
job 成功；唯一未通过的 `macos-14 / Go 1.27.x` 标记为 `cancelled`，没有分配到
runner，也没有执行测试步骤（整个 run 为 `failure`）。
其原始 check 注解报告 hosted runner 未能获取，并提示 macOS ARM64 容量不足。
这不是代码测试通过，也不能把整个失败的 run 重标为成功。

GitHub 的[官方退役公告](https://github.blog/changelog/2026-10-01-github-actions-macos-14-runner-image-retirement/)
说明 macOS 14 镜像将于 2026-11-02 退役，提前存在 brownout 和容量缩减；
推荐迁移到 `macos-15` 或当前受支持的其他标签。
本次失败发生在当天预告 brownout 开始前，**不据此声称是该 brownout 导致**。
实际容量失败以原始 job 注解为证，退役公告说明持续依赖旧镜像不可取。

因此仅将固定 macOS job 标签改为 `macos-15`，仍为 ARM64 标准托管 runner，
见[官方 runner 规格](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)。
不改为浮动 `latest`、付费 larger runner 或自托管 runner，不申请额外账户权限。
保留六个 job、两个 Linux Go 矩阵、macOS Go 版本、所有静态/race/故障/秘密/依赖
检查及原有超时；不删除失败测试、不重跑旧 run 来覆盖原始原因。
新提交的两个原始事件必须分别取得新 CI 证据；在取得前不宣称六项全绿。

这次是 CI 镜像维护，不改变普通生产 Go、测试 fixture、harness、依赖、资源策略或
负载门槛。正在运行的原生/KVM 实验仍绑定原冻结源码与产物，后续报告必须注明该
运行来源与新 PR head 的区别；只允许通过明确的 CI/本文档差异证明运行代码相同，
不能把旧硬件结果无条件代签给新源码。

macOS CI 验证控制面/模拟后端的跨平台行为，不证明 macOS 支持 Linux/KVM 隔离。
本次迁移也不认证 macOS 14 兼容性、硬件长稳或完整生产验收。

## 后续真实单测失败：等待 relay 完成，而不是延长客户端期限

`ce677b932e91ba189bf06743ec87d7d2fa5fc04b` 的
[PR run](https://github.com/123123213weqw/Xandbox/actions/runs/40311634592)
六项成功；[push run](https://github.com/123123213weqw/Xandbox/actions/runs/40311629701)
保留为失败/attempt1，其他五项成功。唯一失败是 Linux/Go1.27 的普通 race 测试，
不是 runner 容量，也不是只读 PID1 census 的测试。

原始日志为 `TestInitializationFaultRelayModesSyntheticOnly/after_sealed_before_ready`
读取尚不存在的 `barrier.json`。合成 relay 在实际完成文件提交前已增加 sealed-response
计数；客户端的200ms deadline返回也不保证后台 writer 已完成。测试把早期计数/客户端结束
误当作 barrier 发布完成，存在观察顺序竞态。

修正仅在 `_test.go`：合成测试在读错误和 receipt 前明确关闭并 join relay writers；
新增受控“发布前挂起”，先验证 receipt 尚未发布，再放行并等待真实 writer 完成。
所有原有故障断言和200ms客户端期限不变，没有加入 sleep 来掩盖竞态。
真实 KVM 调用仍使用默认构造器、没有这个合成 gate；普通生产程序不变。
临时路径遵守调用者的短私有 TMPDIR，便于验证测试退出后无残留。

同一未提交 overlay 已在 Linux 非特权环境定向跑过 race/CGO-free各100遍、五种模式每种
每构建100遍，无失败、data race或skip，临时目录仅剩自有marker。它是明确的合成开发证据，
不是新冻结源码的完整CI、实际KVM或生产认证；新源码仍须另跑完整对应门槛。
原始失败不重标成功、不重跑覆盖，也不将此独立单测问题混作测试PID1孤儿回收的修复。

## 2cec原始PR：独立的cleanup指标观察竞态

2cec原始push六项成功；原PR的Linux/Go1.25.14默认race步骤在
`TestMetricsDoNotAcquireAnyLifecycleLock`失败：缺少cleanup_attempt success1。
其余五项成功，Linux新fixture步骤因前序失败跳过；不是新的fixture测试失败或runner容量。
原失败保留，不重跑覆盖。

源码中Allocated在cleanupLocked内部先减为0，CleanupAttempt histogram在函数defer中
稍后发布；旧测试只等DESTROYED/Allocated0就读取histogram，并非合法完成屏障。
新候选仅改测试：额外等该独占单实例的cleanup worker返回/队列空，再保留原有全部
histogram和无生命周期锁读取断言；新增“Allocated0但worker仍running”合成拒绝控制。
原一秒无锁检查与三秒eventually预算不变，不增加sleep或改生产telemetry。
该测试修正与真实session初始拒绝故障是两个问题，须分别验证，不用CI绿灯替代KVM。


## 新broker首次冻结原生回归：旧ELF pin按设计拒绝新程序

冻结060f3ed的24个产物均重建：按实际Go依赖图，sandboxd、host fixture、session.test
三项改变且独立amd64 cross/native逐字节一致，其余21项与native6相同。随后完整fixture
race三遍仅固定旧ELF测试三次拒绝新daemon，native原始状态1，其余步骤尚未执行；
不把这次失败改成通过、指向旧daemon、跳过测试或重跑不变源码。

旧prepareTraceELFSHA绑定5bfb，新的普通daemon为7ccb2720…；只在验证新ELF与原生构建
相同后更新**唯一固定hash**。Go1.27.3 objdump逐个核对九个原instruction地址/字节/
寄存器，全部未变；原whole-ELF、符号包含关系、可执行segment字节和owned L1身份闸门
保持不变，没有通用hash/offset环境选择器。通知类fixture也必须匹配同一新固定daemon。

这只是离线重新绑定，不是新live trace、KVM或全部生产验收。旧12/15事件和5bfb报告仍只
证明各自旧程序；修正fixture须再次冻结/原生/CI，并为新普通程序另取真实验收证据。

## 默认仓库回归：ring 有界读取不等于两秒磁盘排空

冻结 91bfb12 的新会话/metrics 机制、完整 tagged fixture 及 root Python295 均通过，
但完整默认 race 三遍的 `TestLiveReadHasBoundedRetryDuringWrap` 有一遍在收尾
`Close` 返回 `ErrPending`，原始失败保留；后续 CGO-free/vet 未执行，整轮不算通过。
旧测试把 lossy `Emit` 循环后的两秒排空当作 ring 读取保证，且没有保证实际发生 wrap。
`Close` 的原契约允许调用者超时返回 pending 并保留 writer/FD/锁，不是磁盘吞吐 SLO。

修正仅限测试：真实 ring 的单 writer 并发写入三个保留窗口和 terminal record，
3000 次原有 live read 检查不变，随后 join writer 并核对精确窗口/覆盖计数。
不放宽生产读取的三次重试、不改 Close 的截止时间/队列容量/fsync/锁或普通程序。
另以合成 append gate 验证已取消调用者收到 pending、FD 与排他锁仍归原 writer、
Read 不等待或虚构未提交记录、释放后正常终态和精确计数。它不是 kernel fsync 故障实测。
原有 blocked-store/超时 Close 测试保留；新冻结源须重新完整验收，不能把失败改签为通过。

## 19470de 原始 PR：启动恢复加载器不是在线观察器

同一源码的 [原 push](https://github.com/123123213weqw/Xandbox/actions/runs/40361397287)
六项通过；[原 PR](https://github.com/123123213weqw/Xandbox/actions/runs/40361406793)
Linux/Go1.27 的初始容量拒绝测试在 `Load()` 删除 `.session-*` 临时文件时遇到 ENOENT。
PR 的 macOS 项为 cancelled，原因未确认；没有重跑或主动取消原运行，不能将其视为成功。

`Broker.New` 在启动 journal worker 之前调用 `FileStore.Load`；该恢复加载器会验证目录、
删除临时文件并同步目录，不是给存活 journal 使用的只读快照。新测试在普通回复后调用它，
可能与合法后台终态重写/rename 竞争；这次报错不是“磁盘缺少 CLOSED”的直接证明。

修正仅限测试观察：按 fixture 的不可变 ID 打开已原子发布的 JSON，限制读取字节并严格
解码，所有被断言的状态/Ref/history 都来自该 FD，而非内存。不会调用恢复 Load、
删除 staging、同步目录或替 journal 提交；普通容量回复后的检查仍是立即读取，不改成
eventually。原 CLOSED Save 暂停屏障、三秒预算、journal 不确定性及旧 key410 控制均保留。

新增独立观察器控制保留 owned staging 的同一 inode/字节，并把内存状态故意设成与
已提交文件不同，防止“只看内存”假阳性。恢复原 Load 观察方式的 overlay 三次确定失败，
证明它会删除这个受控 staging；该控制没有并发 writer，也不是真实 KVM/磁盘故障。
生产 broker/Store、唯一 ELF pin、错误 allowlist 和所有运行预算不变。测试产物
`session.test` 需要独立重编译并重新冻结；CI、Linux 整轮及新普通 daemon 的实机门槛
仍须单独通过，不沿用此前失败或旧普通 ELF 报告代签。
