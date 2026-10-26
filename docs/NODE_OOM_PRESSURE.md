# 单实例真实 host-cgroup OOM 有限门槛（TEST ONLY，仍未生产就绪）

本项补充[节点预算](NODE_BUDGET.md)中的内存故障缺口。已有四 guest 各 8MiB
及父限制收紧 4KiB 的报告不是 OOM 证据；不会修改或重签那些历史报告。
修正后的冻结源码 `d5daa22e3441a5986d2d514489f1079d6a1c1fdf` 已另取真实 Linux/KVM 证据：
原节点预算基线与新 OOM 用例各两次启动通过。含失败前序共四个 scope、七个唯一外层
执行代际，已独立只读复核无残留、无补充清理；不是把失败前序计为通过用例。
生产服务代码、API、资源预算不变，`production_ready` 仍为 false。

[原节点预算报告](validation/node-oom-baseline-v1.json)、
[新 OOM 报告](validation/node-oom-host-cgroup-v1.json)为经过隐私核对的原 producer 字节；
[来源与独立复核](validation/node-oom-provenance-v1.json)绑定源码、归档、24 个实际构建物、
9 个实机输入、82 个脚本输入摘要及失败前序。原始 console/receipt/资源身份保持私有。

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

## 软件与实机证据边界

Go 1.27.3 原生 Linux：完整 TEST fixture race×3、vet、CGO-free×3、依赖验证、
root Python279 零 skip；七个新 Go 测试 parent 在两个完整 suite 中各通过三次。
旧 opt-in ELF 校准必须显式传入独立核对的普通 daemon 文件，未把缺输入的 skip 当通过。
24 个程序实际重新构建，除 TEST fixture 外，其余23个与各自已有原生组件逐字节一致；
新 fixture 的独立 amd64 交叉构建与原生字节一致，arm64 仅编译。
CI 增加明确 CGO-free OOM guard/Stop 契约及 Python validator 回归，**CI 不运行真实 KVM**。

实机新 OOM 用例中，四个 guest 的 host anon 增量均超过64MiB；固定 helper 触发真实
group OOM，目标 API job 非自然超时失败，三个邻居继续运行并执行新命令，随后普通
Stop、独立 execution-domain 空、durable Destroyed、quota0、key410、复用与原盘 cold 均通过。
计数的早期目标 FD 样本与最终节点/global 计数不同：前者可能在组内全部 victim 计数
发布前取得，不伪称完整最终 target 计数。最终 L1 global/node OOM kill 均为4。
两个 Stop 时间值是一次实验内**三个邻居的聚合观察上界**，不是单实例分布或 SLO。

固定输入就绪后，用原生 CGO-free fixture 与实际构建的普通 daemon/warden 复现：

```sh
sudo python3 scripts/kvm_nested_host.py --node-budget --node-oom \
  --fixture /private/artifacts/fixture --daemon /private/artifacts/sandboxd \
  --warden /private/artifacts/xandbox-warden \
  --firecracker /private/artifacts/firecracker --jailer /private/artifacts/jailer \
  --kernel /private/artifacts/vmlinux --initrd /private/artifacts/guest.cpio.gz \
  --workspace /private/artifacts/workspace.ext4 --alpine /private/artifacts/alpine.tar.gz \
  --source-revision d5daa22e3441a5986d2d514489f1079d6a1c1fdf \
  --report /private/results/oom.json --log-dir /private/results/oom-logs
```

这要求当前工作树的 Go/脚本字节与具名冻结源一致、所有输入与固定清单相符，且结果路径
不存在。普通基线另起全新 report/log-dir，只去掉 `--node-oom`。输入准备和共享宿主前提
沿用现有 nested-host 说明；不是在任意物理宿主直接启动压力 helper。

## 失败前序与尚未完成

首个实机候选的原节点预算基线两次启动通过，但新 OOM 流程在邻居 Stop 阶段失败：
测试错误地要求 HTTP202，普通 Stop 实际契约为 HTTP200（DELETE 才是 202）。
保留失败原件和三个外层执行代际的独立无残留复核；不是生产 Stop 缺陷或 OOM 全流程通过。
修正测试为精确 200 + 同代 STOPPED/StoppedAt 回复，并仍独立检查内核 execution domain，
新增契约回归。新源码须重新构建、软件验证与实机执行，不能继承旧候选的通过结论。

后续新源码的两条具名流程已独立通过；不是修复 validator 后把旧失败报告改为成功。
完整节点 RAM 饱和、guest-origin OOM、开放到达/公平性/持续负载、所有故障窗口、
升级回滚、独立操作员及完整生产验收仍未完成。三个时间观测分别报告 OOM 释放到
目标停止、邻居 Stop 到执行域为空、Stop 到全部私有资源回收，不作生产 SLO。

内核语义依据：[cgroup v2 文档](https://docs.kernel.org/admin-guide/cgroup-v2.html)
的 memory.oom.group / memory.events(.local) 和
[Linux v6.1 OOM 实现](https://github.com/torvalds/linux/blob/v6.1/mm/oom_kill.c)。
