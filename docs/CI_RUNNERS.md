# CI runner 镜像维护

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
