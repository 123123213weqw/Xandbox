# 节点准入控制的有限 KVM 与冷恢复验收

**新生产程序 `4ee09d0a…` 的 operator 协议已有有限实机证据，但完整生产验收仍未完成。** 本页验证同 UID 管理入口、真正连接后的异 UID 内核拒绝、drain 期间真实 guest 运行与回收，以及已确认 drain 的同盘冷恢复；不把健康检查、模拟 Store、目录消失或旧 `3ea1e247…` 报告当作新程序证明。

冻结源 `e5ba602e7bbf0292ffed2e0c306dd3d53697652b`，归档 SHA-256 `295ced8c…`；只修改 TEST fixture/harness，普通 daemon/admin/warden/node CLI/builder 五个 ELF 与[原生预验收](validation/node-control-prequalification-v1.json)逐字节相同。TEST fixture 为 `3bfead6f…`，六产物独立交叉/原生构建完全相同。[来源清单](validation/node-operator-provenance-v4b.json)绑定六个修改输入、四份通过/失败报告及 40 个私有原始结果成员摘要。

## 固定资源和权限边界

沿用 `node-budget-v1`：L1 8GiB RAM、12GiB raw disk、8 vCPU、外层 cgroup 10GiB/pids256、无业务 NIC、900 秒硬上界。L1 内采用原 schema3 NodePolicy，N4/records1024/sessions32/prepare1、NodeRoot 7GiB/control1GiB、每代 192MiB/128inodes project quota 与既有 IO 限制。没有扩大预算、降低阈值、改 VMM seccomp 或回退宿主执行。

新增 `--node-budget --node-operator` 仅选择固定 TEST 操作；管理 RPC 由可信 L1 PID1 使用生产 `nodecontrol.Client` 发起。CLI 已在原生进程预验收中执行，本次没有把 CLI 二进制装入 L1，也不声称已通过生产安装器/systemd 验收。

异 UID 检查在**尚无任何 guest**、节点 drained 时进行：

1. 核验 instances 没有子执行域且父 `cgroup.procs` 为空；内核自带 control 文件不被当作 VM。
2. 仅在自有 L1 中临时放宽既知路径的 DAC，并做同 UID HTTP 正对照；此举用于排除“只是路径权限阻止连接”的伪证据，不修改生产权限逻辑。
3. 固定子进程真实降为 UID/GID400003、清空补充组并核验 effective/permitted/ambient capabilities 为零。仅继承只读 root marker FD；不继承已连接管理 socket、tenant token 或任意执行能力。
4. 子进程降 UID 后新建 Unix 连接，读回服务端 peer UID/PID，与真实普通 daemon 一致；发送格式有效的 resume 命令，必须在收到任何 HTTP 字节前得到 EOF/reset。连接失败、超时或 HTTP403 都不能通过。
5. 回收该子进程，按原 inode 恢复准确权限，再由私有生产 client 查询，确认 committed revision/mode 未变且准入仍关闭。

这证明有限用例中的 Linux peer-credential 过滤，而非每请求实时身份、对恶意 root/同 UID 的隔离或防止管理员主动委托已建立 FD。[Linux unix 手册](https://man7.org/linux/man-pages/man7/unix.7.html)定义了 SO_PEERCRED 的 connect-time 语义。

## 实际执行和冷恢复

[operator 报告](validation/kvm-node-operator-admission-v4b.json)记录一个两次 L1 启动的用例：

- 创建独立 raw VM 和 session VM，逐代核验真实 KVM FD、UID、boot ID、干净 workspace 与 quota/过滤边界。session 命令必须走 session 路由，不能绕过生产 managed-VM 的 raw-exec 拒绝。
- 启动 raw VM 内持续推进的任务，随后 drain。三个新 raw/session/Switch 请求均为 `503 NODE_DRAINING`；ledger 名称集合与 session 文件字节/历史不变，已有 raw/session 幂等请求仍 replay。
- raw 的已接受任务继续推进，旧 session 命令实际执行且输出正确。drain 期间 DELETE raw，独立观察其执行域为空，再确认持久 DESTROYED、owner/jail/cgroup 缺失及该 project quota 为零。
- 陈旧 resume 冲突；有效 resume 后，先前拒绝的 raw/session/Switch keys 均可使用。五个实际 cold guest 的 boot ID 独立。清理其中四代，核验仅最后切换代存活、其他 projects 为零、后台池回到相应基线。
- 将预期 revision6/drained 与当前 owner、quota/namespace、boot/配置绑定写入私有 receipt 并 fsync，**然后**取得最终 drain ACK；ACK 后不再由观察器 quota-sync、syncfs、写 receipt 或运行 catalog 管理命令。这里不是卡在提交中间的故障注入。
- 只切断自己的 L1，并用原磁盘冷启动。启动普通 daemon **之前**，读回原 epoch/revision6/drained，以及未变的绑定/owner/quota/namespace，确认旧执行域不存活。
- 普通恢复保持 drained、回收所有旧代、拒绝旧 keys 并关闭旧 session route。新的 create 仍503，最近 drain 命令可精确 replay，陈旧 resume 仍冲突。显式 resume 后再创建第六个真实新 guest，核验 UID/boot/workspace，最后销毁、清零四个 projects、确认池 idle、回收 daemon 并移除整个 NodeRoot。

另以**同一新生产 ELF**独立执行[原 node-budget 兼容用例](validation/kvm-node-operator-node-v4b.json)：四个同时真实 KVM、第5拒绝、安全的父限制漂移下 Stop/Cleanup/旧 Exec、同盘 cold 恢复均通过。它不是 DEFAULT/IO、quota240/双活cold 或 prepare/cancel 矩阵的替代。

## 分开的单次观测

| 起点与终点 | 本次观测 |
|---|---:|
| DELETE 开始 → 实际 raw 执行域为空或已移除 | 16.045 ms |
| DELETE 开始 → 私有资源缺失、持久 DESTROYED 且 project quota 为零 | 370.160 ms |

两者均为 N=1 的观察上界，不是精确内核停止时刻、物理擦除、p99 或 SLO。allocated 信用及后台池 idle 在后续另查，不能倒填进 370ms；其他 session 仍存活，也不是全节点空闲证书。

## 保留失败与独立清理审计

- v1 只做源码/交叉构建预检，发现把 cgroup 自带文件误当作执行域；增加测试并修正，未启动硬件用例。
- [v2 原始 false](validation/kvm-node-operator-admission-v2.json)：1 次 L1 启动，辅助子进程 guard 在管理连接前失败。root0600 marker 不能直接由降 UID 的子进程打开，后续改为只读 marker FD，不传递管理连接。
- [v3 原始 false](validation/kvm-node-operator-admission-v3.json)：1 次 L1 启动，raw/session 组合检查失败。源码审查发现 managed guest helper 误用 raw execution API，随后改为 session API。旧诊断未保留底层错误细节，因此不事后重建唯一的精确运行失败原因；生产 managed guard 没有放宽。
- v4 的原生测试及六产物校验先通过，私有 runner 的 suffix 替换却误改 seed locator，在创建外层资源前退出1；随后一个只读摘要预检因原 seed 的私有权限退出1。恢复原固定资产位置，并使用已有授权 sudo **只读**摘要路径；未改资产、权限、源码、阈值或超时。原 exit1 均保留，硬件 runner 最终独立 exit0。

4 个真实运行 scope 共 **6 个外层执行代际＝4 个通过＋2 个失败**，不是6个通过。独立只读审计逐项检查实际 receipt 所指 root/control/cgroup parent/全部执行代际均不存在；不执行补清理，也不从目录删除推断 quota 为零。原 quota/namespace 检查发生在 L1 仍运行且磁盘尚未删除时。原始 console、私有 receipt、命令 ID、keys、PID 与运行路径均未公开。

## 当前仍未完成

本次是 ACK 后的虚拟宿主 cold cut，不是 operator 的真实 fsync/rename 提交窗口、filesystem D/EIO 或物理介质故障。已接受但阻塞在 Core 预留之前的 session ticket，目前仍只有 unit/race 证据。新程序完整 DEFAULT/IO、quota240/双活cold/故障及 node snapshot/prepare/cancel 等矩阵仍需逐项复验；独立部署、审计告警、备份升级回滚、持续开放到达/公平性/完整资源计费等生产门槛也没有完成。Goal 与 Draft PR 继续保持未完成状态。
