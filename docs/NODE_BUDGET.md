# Version 3 节点总资源准入（有限实机门槛通过，仍未生产就绪）

当前分支新增了生产代码的节点策略，**不是只新增 TEST hook**。新 ELF 已通过本文限定的 Linux/KVM 节点基础门槛及相关故障回归，[默认路径/IO的新运行时复验](RUNTIME_REQUALIFICATION.md)已另完成，[quota240/双活cold及故障矩阵](QUOTA_REQUALIFICATION.md)也已另完成；历史 daemon `522da68e…` 只能证明它自己的冻结基线。本文不是生产就绪声明，PR19/Goal的完整门槛仍未完成。

## 不再把单实例上限当成节点预算

Version 1/2 保持实验性兼容格式，不自动扩容、迁移或获得生产资格。Version 3 必须提供完整 `node` 策略、project quota 和 IO policy；cold与snapshot均支持。新增策略参与原有 registry/config/catalog 指纹，在线修改预算或路径必须拒绝，不能默默覆盖binding。

策略把 `max_instances`、`max_records`、`max_sessions` 与服务启动参数严格绑定；默认32实例/10000记录/1000会话不能绕过更小的节点声明。Manager和Session broker也通过纯内存接口复核，启动导入计入Creating/Ready/Stopping/Stopped/Reclaiming及永久tombstone，不能只数正在RUNNING的VM。底层registry按同一个节点上限保留owner，直到owner删除得到持久确认；即使UID slots更多或目录fsync失败，也不能提前复用节点容量。

## 层级与内核边界

固定结构为操作员预先委派的节点root，其下仅允许 `control` 与 `instances` 两类子树：

- 控制器及catalog publisher必须处于control或其子目录，不能在root外写盘准备后声称受节点限制。
- 节点root和instances本身无直接进程，并委派memory/pids/cpu/io；必须是cgroup-v2 domain。
- root memory.max/swap0/pids.max/cpu.max/io.max及control memory.max/swap0/pids.max/oom.group均精确读回；拒绝被替换的目录inode、祖先/instances更小的限制、错误控制器位置或不够的实际CPU affinity/物理RAM。
- root硬限制涵盖控制器、准备复制、VMM和warden所在后代；每代仍保持768MiB memory.max、swap0、pids64、CPU2以及固定guest规格。
- state/runtime必须位于同一直接支持quota的ext4文件系统，IO queue、filesystem UUID及原有quota能力边界仍须成立。不会修改共享宿主委派或回退执行到宿主。

只读检查使用FD anchor、NOFOLLOW和有界读取；不会把普通文件伪装成cgroup接口。操作员负责建立这些子树和正确放置进程，daemon不替操作员调整宿主全局资源。

## 保守准入，不伪造物理内存记账

预算包含：全部已分配/准备/回收槽的单代上限、control运行与记录/会话/job缓冲规划、catalog全额潜在cache/backing、metadata/目录/临时文件、准备缓冲、pids/CPU/IO及宿主余量。catalog cache与实例memory上限可能重叠，故意保守相加；**不是unique-RAM、PSS或可计费的实际占用**。实际硬上限由内核cgroup另行执行。

磁盘/inode同时保留“最大managed分配”与“同等大小仍空闲”的准入余量，再加外部assets/export/logs预算和最小空闲余量。这样不从互不原子的quota/statfs样本减去已用量，避免并发清理造成双重credit。每次Prepare及catalog Publish前重新核验空闲空间和策略读回。

这是保守的**准入规则**，不是给整个节点套了一个可嵌套的ext4 project quota；private project硬配额和catalog预算仍各自执行。操作员必须约束外部日志/导出/其他写入；介质错误、外部消耗或内存OOM下的可用性不能靠一次statfs保证。相关实际压力、长期曲线、日志轮换与独立操作员验收仍待完成。

## 准备并发与回收隔离

`prepare_workers`只包围真实backend准备过程，等待者受请求context约束，取消不泄漏permit。前端先保留该代际，故排队准备也计入已分配容量。Stop与Cleanup不会获取准备permit，也不调用新增的空闲空间准入检查，避免“磁盘紧张导致无法清理”或队列耗尽阻止停止。重启时允许低空闲空间进入回收，但不允许实际总容量/绑定/导入记录超出声明。

## 当前测试边界

另有[单实例真实 host-cgroup OOM 验证候选](NODE_OOM_PRESSURE.md)，仅 TEST ONLY，
尚未取得新实机证据；不改变下述历史报告，也不勾选完整 RAM/节点或生产门槛。

已有边界/溢出/逐资源拒绝、schema与binding漂移、服务参数/导入计数、owner未确认时容量保留、CPU/RAM/层级输入、磁盘/inode压力边界、准备并发/取消及读接口安全测试。新增固定8GiB L1 RAM/12GiB disk/10GiB outer cgroup/CPU8测试规格，不修改旧2GiB/3GiB规格。下列有限实机证据仍不能替代完整节点压力与生产验收。

## 首轮有限实机证据

冻结源码 `2e514fe9d0b0ce8097b4baca67c9761afdfdbf48`；新普通daemon `3ea1e247…`、admin `19bbd460…`，没有生产故障开关、假guest或宿主执行回退。[原始节点报告](validation/kvm-node-budget-node-v2.json)与[精确来源/16个输入文件hash](validation/node-budget-provenance-v2.json)已保留。

- 启动参数与节点声明不匹配、控制器不在control子树，均在创建API/binding前按明确原因拒绝。
- 4个真实嵌套KVM guest同时存在并检查UID/boot/数据/过滤器，第5个Create503；每guest只触碰8MiB内存，**不是512MiB满载或OOM实验**。
- 先完整回收一代，再仅安全收紧父级memory.max 4KiB；新Prepare500、不回退执行。限制漂移期间，另一个guest的Stop/Cleanup及存活guest的Exec仍正常；恢复原声明后失败key410、同slot新guest正常。
- 健康Q_SYNC+syncfs及私有receipt完成后切断自己的L1，原盘cold首先核对精确policy/已知owner/namespace/project quota，再由普通daemon回收；旧key410、4个project全零、新guest UID/新boot/干净workspace、控制器与整个节点子树移除均通过。**这是健康同步检查点，不是在途提交掉电窗口。**
- 外层执行域停止88.638ms只是一例观测，不是生产销毁时延、物理介质断电或SLO。

本次另跑owner目录提交cut、未同步partial-copy cut、稳定partial write EIO、真正L1-built snapshot、clear-owner-pin、6个固定syscall errno相关回归。7个通过scope/17个外层执行代际已独立只读核验全部资源消失；quota/namespace证据在删盘前从L1读取，不从删盘推断quota清零。原生完整race×3/vet、fixture race×10/vet、root Python72、CGO-free实际内核/exec过滤×3及5个ELF独立交叉构建比对通过。Darwin测试实际源码为`8b951bb…`，与最终Go代码完全一致，仅Python producer修复不同；日志没有冒充执行过另一源码。

[失败前序](validation/kvm-node-budget-node-failed-v1.json)也保留：Python还设置CPU4/pids128，新Go launcher按CPU8/pids256严格拒绝，**QEMU启动前即失败，实际L1 boot=0**。修复producer而非放宽guard；单个attempted cgroup已独立核验清理，不计为VM执行代际。原始报告的计划资源/limitations字段不是那些阶段已执行的证据。

## 仍未完成

[新程序完整DEFAULT/IO复验](RUNTIME_REQUALIFICATION.md)已另通过，[quota240/双活cold/已命名故障矩阵](QUOTA_REQUALIFICATION.md)也已另完成；均为新2e/3ea实际执行，不沿用历史522的通过结论。当前Version3 cold与[snapshot/inode/字节压力及低free cold](NODE_SNAPSHOT_PRESSURE.md)已有有限实机正例；完整节点资源压力、真实并发copy permit轨迹、独立共享页归属、开放到达/公平性/长期曲线、外部日志/导出约束、其他元数据故障/可靠catalog锁及完整M1–M4仍待验收。`production_ready`维持false。


## schema3 snapshot与空间压力补充

[新冻结d432实机报告与边界](NODE_SNAPSHOT_PRESSURE.md)已验证相同N4/1024/32/prepare1节点策略下，daemon和所有admin实际处于control、独立inode/bytes准入拒绝、低free仍能普通startup/reclaim及仅移除自有filler后恢复Publish。生产3ea/19bb/b290/243字节未改；新fixture及相关8scope/19代际另有来源。两live guest各8MiB、离线builder在NodeRoot外和外部TEST filler均明确限定，不冒充完整RAM/并发permit/外部写入预算验收。
