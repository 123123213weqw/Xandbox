# 单实例真实 host-cgroup OOM 验证候选（TEST ONLY，尚未实机验收）

本项补充[节点预算](NODE_BUDGET.md)中的内存故障缺口。已有四 guest 各 8MiB
及父限制收紧 4KiB 的报告不是 OOM 证据；不会修改或重签那些历史报告。
当前只是新增固定测试流程及拒绝检查，实际 Linux/KVM 结果必须另行取得。
生产服务代码、API、资源预算不变，`production_ready` 仍为 false。

## 固定边界

- 仅 opt-in `xandbox_host_fixture` 构建；默认生产构建不含该命令。
- `scripts/kvm_nested_host.py --node-budget --node-oom`，拒绝混用其他 modifier。
- 沿用 node-budget-v1：L1 RAM 8GiB、磁盘 12GiB、外层 cgroup 10GiB、CPU8、
  pids256、无业务 NIC、900s 硬边界。NodeRoot 7GiB、control 1GiB，
  每 VM 768MiB / swap0 / memory.oom.group=1。不修改共享 L0 配置或施加 L0 压力。
- `node-oom-pressure` 无路径、PID、UID、大小、预算等运行参数，必须是带固定
  marker 的独占 L1 中 PID1 的 root 子进程，出生即进入已存在的精确 VM cgroup。
  核对 marker FD、cgroup2 FD/目录 inode、既有 owner 和真实 self membership 后，
  清空所有线程的 bounding capabilities、组、UID/GID 权限并设置 NNP。
  PID1 通过固定 pipe 握手独立核对所有线程 UID/caps/NNP/cgroup/oom_score_adj 后才释放。
- 压力来自受信 TEST helper 的固定 1GiB 匿名映射请求与 4096B 页触碰，
  **不是 guest 发起的 OOM，也不是宣称已驻留 1GiB 或耗尽整个节点 RAM**。

## 必须实际观察的条件

1. 四个真实 KVM guest 的 UID/ref/boot 独立；每个普通 API 忙任务保留固定
   96MiB 逻辑 awk 数据，host `memory.stat anon` 相对实际基线至少增加 64MiB。
   第五个 Create503；压力释放前四个任务均仍 RUNNING 且未到原始 60s deadline。
2. 持有目标 `memory.events` FD 的外部观察者实际读到 max、oom、oom_kill、
   oom_group_kill 增量；helper 在固定 20s guard 前由 SIGKILL 退出并被 reap。
   ENOMEM、手工 kill、guard 超时、读错误/丢失计数都失败，不视为 OOM 通过。
3. 独立读目标 execution domain 为空；普通任务转为 FAILED/CANCELLED，
   不能成功或自然超时。祖先 local、control 和三个邻居的 OOM 计数不变；
   L1 `/proc/vmstat oom_kill` 增量与节点 hierarchical oom_kill 相等。
4. 三个邻居忙任务继续 RUNNING，并能执行新的普通 guest 命令。
   再通过普通 Stop 请求，在各自原始执行 timeout 前独立观察 execution domain 为空。
   不把 API202 或 durable 状态替代物理停止。
5. 四代普通 DELETE/DESTROYED、owner/jail/cgroup 缺失、四个 project quota0、
   旧 key410，然后复用容量得到新 boot 与干净 workspace。
6. 新 guest 的健康同步检查点使用独立闭集 receipt phase；原盘 cold 在 daemon
   前检查 policy/owner/namespace/quota，随后普通恢复回收、旧 key410、新 guest、
   最终全部 quota0 和整个节点子树移除。它不是 OOM 在途掉电或介质持久性测试。

公开 validator 拒绝缺字段、false/数字冒充 bool、计数缺失/溢出、NaN/Infinity、
稀疏虚拟分配冒充实际 anon 增量，以及原始 PID/UID/boot/path/凭证等额外字段。
原始 console、receipt 和资源身份只留私有；发布结果须绑定实际源码、所有输入摘要、
失败前序与独立两代资源清理复核。

## 尚未完成

真实新流程和重构后的原 node-budget 基线尚需独立执行，不能从单测/交叉构建推断通过。
完整节点 RAM 饱和、guest-origin OOM、开放到达/公平性/持续负载、所有故障窗口、
升级回滚、独立操作员及完整生产验收仍未完成。三个时间观测分别报告 OOM 释放到
目标停止、邻居 Stop 到执行域为空、Stop 到全部私有资源回收，不作生产 SLO。

内核语义依据：[cgroup v2 文档](https://docs.kernel.org/admin-guide/cgroup-v2.html)
的 memory.oom.group / memory.events(.local) 和
[Linux v6.1 OOM 实现](https://github.com/torvalds/linux/blob/v6.1/mm/oom_kill.c)。
