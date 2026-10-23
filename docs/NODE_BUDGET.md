# Version 3 节点总资源准入（实现中，尚未完成实机验收）

当前分支新增了生产代码的节点策略，**不是只新增 TEST hook**。新 ELF 必须重新进行 Linux/KVM、默认路径、quota240/双活cold及相关故障回归；历史 daemon `522da68e…` 只能证明它自己的冻结基线。本文不是生产就绪声明，PR19/Goal的完整门槛仍未完成。

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

已有边界/溢出/逐资源拒绝、schema与binding漂移、服务参数/导入计数、owner未确认时容量保留、CPU/RAM/层级输入、磁盘/inode压力边界、准备并发/取消及读接口安全测试。新增固定8GiB L1 RAM/12GiB disk/10GiB outer cgroup/CPU8测试规格，不修改旧2GiB/3GiB规格。实机证据完成前不要把这些单元测试当作完整节点生产验收。

待验收：新程序全部相关native回归、新Version3正负实机/原盘cold/资源压力、实际并行copy与共享页归属测量、开放到达/公平性/长期资源曲线、其他元数据故障/可靠catalog锁协议及完整M1–M4。`production_ready`维持false。
