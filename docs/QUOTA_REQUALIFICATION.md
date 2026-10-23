# 新3ea运行时：quota忙切换、双活cold与故障矩阵复验

> 本页保留3ea程序的历史冻结证据。准入控制变更后的4ee程序已另行完成[新命名矩阵复验](RUNTIME4EE_REQUALIFICATION.md)，没有重标本页报告。

**有限冻结源码复验通过，不是完整节点或生产验收。** 冻结`2e514fe9d0b0ce8097b4baca67c9761afdfdbf48`、普通daemon `3ea1e247…`；没有生产故障开关、假guest、宿主执行回退或历史522结果改名。[完整来源/16个公开输入SHA](validation/node-quota-provenance-v1.json)绑定本次新原始报告。当前quota规格使用schema2/nilNode，不替代schema3 snapshot/节点压力；[节点基础](NODE_BUDGET.md)与[默认/IO复验](RUNTIME_REQUALIFICATION.md)分别保留自己的证据。

## 完整工作负载，四个不同的观测点

[新原始busy报告](validation/kvm-node-quota-mixed-v1.json)：两个租户各120次，实际603.283463879秒，1196个资源样本、150对跨tenant重叠switch区间。每轮先用第二条guest命令确认旧writer真实写入进度，再要求其仍RUNNING；独立host-empty必须早于原guest job最早可能deadline。没有把controller RUNNING、历史404或成功返回的binding当作停止证明。

| 从客户端switch请求开始的P95 / ms | alpha（N=120） | beta（N=120） |
|---|---:|---:|
| 新binding响应 | 1349.119 | 1373.308 |
| 首条新命令成功 | 1456.998 | 1463.184 |
| 旧host执行域停止 | 1365.663 | 1407.148 |
| 旧代持久DESTROYED | 1600.994 | 1626.076 |

全部原始行保留并逐条重算nearest-rank。第一条新命令和旧host-stop的观测顺序不保证每轮相同；这些是从switch开始的不同观测，不是单独Stop调用的耗时。无跨轮次拼接、失败行过滤、quota观察器强制同步或不受控加速比。paced closed-loop、每轮等待旧GC、500ms目标非事务采样不能证明open-loop/fairness/长期尾部或SLO；RSS/cgroup/quota视图不能相加做uniqueRAM计费。

固定实验资源未放宽：L1 3GiB/4GiB盘、outerCG4GiB、CPU4/pids128/swap0/noNIC/hard900s；run budget720/control770/回复2MiB/样本1452。node容量4/tenant3、UID/project slots8、每代192MiB/128inodes；有headroom不等于生产NodePolicy。guest只按工作负载触碰部分内存，不是每台完整512MiB饱和。

## 实际双活cold与剩余11个profile

负载后先完全drain，再单独创建两个租户的live sessions及实际推进中的writer。两者Ready/pins2之后才采样两份完整receipt；共享inode身份、属性、link count精确相同。健康同步checkpoint后只切断自有L1；原盘第二次启动，在普通daemon前核对原HostABI/UNASSIGNED export、精确owner/策略/quota/完整namespace/pins，普通daemon随后回收。旧session关闭/旧key410/no old job恢复、新两租户真实guest/干净workspace/新boot、最终8project与pins全零、controller和根子树消失均通过。这不是在途commit或物理L0介质断电。

同一新程序还实际通过：

- reserve/release最后TEST listener失效，各2次外层启动；实际ENOSYS不变成成功或提前还容量。
- 六种固定syscall errno、重复clear及3个后续cold，共4次启动。
- 实际syncfs EIO、release preclear/postclear真实内核挂起、reserve syncfs挂起，各2次启动。
- clear已完成但owner/pin仍持有的精确窗口2次启动；真正L1-built snapshot的3个cold检查点4次启动。
- quota启用和nil-quota的整state I/O EIO/held-D、busy/idle各4场景，各5次启动。guest/控制器撤权、host停止、持久确认/容量保留与恢复分别检查。

共12个passing scope/34个外层执行代际；[独立只读审计](validation/node-quota-independent-cleanup-v1.txt)逐一确认自己的root/control/cgroup父子和编排进程消失，未采取额外清理动作。整个编排与quota子runner均退出0。quota/namespace证据在删盘前从L1内核读取，不从外层删盘推断。

## 一处离线核验修正，原始数据不改

首次**离线**复核把旧轮次的物理分配量189911040字节/冷后189906944当固定golden，因本次stopped例实际189915136/189911040而断言失败。硬件runner本身已按既有严格合约通过：quota charge必须等于独立walk的private inode blocks/inodes，硬限额/namespace/逻辑inode身份不变；当前物理allocation本来就不是不可变policy。Go夹具及该合约与历史3f9完全相同。

[明确标为DERIVED的修正记录](validation/node-quota-verifier-correction-v1.json)保留原核验器/失败trace的SHA、旧值与本次实际值及来源。离线条件改为原有128..192MiB硬边界、4096对齐、严格int/16inodes、同一saved receipt-before、namespace与PID flags；34个坏类型/越界/错inodes/错receipt/false flags负例已执行。snapshot/IO/故障/真实deadline/冷恢复identity等其他断言不变，**没有改硬件判据、报告、资源规格或重跑/筛样**。

本次冷后aggregate少4KiB且诊断PID文件为空，但公开数据没有逐条导出所有物理block变化，不能声称全部差异唯一由PID文件造成。不能依赖该未fsync诊断PID作为恢复/kill authority。含本机私有路径的原始trace不公开，仅公开其摘要；这不是隐去一个硬件false前序。

## 构建与证据边界

5个执行ELF与节点foundation/默认矩阵完全相同、重新校验SHA并对照独立cross。native full race3/vet、fixture race10/vet、root Python72、CGO-free实际kernel/exec filter3来自同冻结源foundation实际执行，未冒充quota runner重跑；Darwin实际8b源与最终Go路径完全一致。builder在真实L1生成UNASSIGNED HostABI-compatible模板，未重标L0导出或复用已分配guest。

白名单原始归档15个regular成员（12 JSON+pipeline/status/artifacts），独立audit stdout单独捕获。公开12份原始JSON、3份安全文本、1份明确derived的离线修正记录及provenance；私有receipt、身份、console、镜像和凭证排除。旧522时代四个false及其历史修复在[原provenance](validation/quota-switch-provenance-v5.json)原样保留、按SHA引用，不计为本次新3ea前序，也不把其中行拼入新测量。

新3ea默认/IO与quota240/双活cold/已命名故障子矩阵至此完成复验。schema3 snapshot/完整节点free bytes/inodes/真实prepare并发、uniqueRAM、长期open-loop/fairness、其他持久窗口/可靠catalog锁、双监督/物理介质/擦除、预热/完整初始化、持久审计/告警/外部日志与export预算、备份/升级/回滚、独立操作员和SLO仍未完成。PR19继续Draft，Goal/M1–M4/生产发布不标完成。
