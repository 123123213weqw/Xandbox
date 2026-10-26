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
