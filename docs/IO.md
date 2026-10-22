# 双层实验性 I/O 预算与有限真实 KVM 验收

**仍非生产就绪或SLO认证。** operator配置 `io` 同时约束Firecracker workspace请求与每代cgroup的块设备I/O。下文已有新原生程序的有限实机证据，不能将其升级为节点总I/O、controller准备阶段复制、物理空间quota或完整M2验收。

## 设计

`io` 是与state永久绑定的操作员策略，不是tenant字段；默认缺省保持旧实验行为。配置后缺少io委派、设备/文件系统不匹配、写入或读回失败，都应拒绝创建，不能忽略限制继续运行。不存在在线策略重绑，旧state不能直接加/删/改此字段来绕过恢复。

```json
"io": {
  "version": 1,
  "filesystem_device": "8:3",
  "device": "8:0",
  "bytes_per_second": 8388608,
  "operations_per_second": 4096
}
```

这些设备号仅作示例，不能照抄：启动及每次Prepare需核对runtime的实际st_dev和sysfs backing queue。v1仅接受直接块设备上的ext4/xfs（可含普通partition），拒绝loop/dm/MD/虚拟队列/其他文件系统/未知拓扑，不猜测多层映射。只对自己新建、持久Ref归属的cgroup写 `io.max`；不修改系统级controller或共享设备配置，实例出生仍用CLONE_INTO_CGROUP。

- cgroup层：对应queue的rbps/wbps各为bytes_per_second，riops/wiops各为operations_per_second。全部方向写入后严格读回，缺失io.max不能被创建成普通文件。
- VMM层：workspace的读写请求**合用**bandwidth及ops token bucket，1秒refill、容量等于配置每秒量，没有额外one-time burst。cold在InstanceStart前设置并读回；snapshot在load为PAUSED后覆盖序列化的bucket并读回，成功后才Resume/Initialize。
- bytes_per_second范围1MiB..1GiB，operations_per_second范围128..65536，均必须有界正数。稳定桶自身允许burst，不是任意1秒滑窗的物理硬上界或时延SLO。

为什么需要两层：Linux缓冲写回按inode归属，初始复制镜像的controller可能仍是该inode/page的归属，不能仅凭VM的io.max就宣称所有guest缓冲写都计入该组；缓存命中也不是块设备I/O。VMM请求限流在host page cache之前提供另一道边界，不靠错误的writeback归属假设。依据 [cgroup v2 Writeback与io.max](https://docs.kernel.org/admin-guide/cgroup-v2.html#io) 和固定版本 [Firecracker Drive API](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/src/firecracker/swagger/firecracker.yaml)。

## 已执行的有限探针

`scripts/kvm_storage_faults.py --io-budget` 及 `scripts/kvm_snapshot_smoke.py --io-budget` 选用固定8MiB/s、4096ops/s，要求实际KVM而非mock：

1. 两层读回、实际设备归属、真实VM fd。
2. 固定32MiB全零O_DIRECT**可信操作员探针**进入自己已拥有的cgroup后才写数据，核对该组io.stat和完成时间；它不是tenant命令、生产执行或VM出生路径，宿主没有租户shell fallback。
3. guest UID65534的64MiB direct写/读、正在写盘时的物理Stop与持久DESTROYED分别计时。不能将读回配置、缓存快、单样本或粗实验guard当生产带宽/尾界认证。
4. 默认未配置IO的冷/快照/初始化/只读故障矩阵已用本次新native程序重新验收，范围见下表；旧D2dc报告没有冒充这次新Go程序的证明。

原始controller日志、Ref、argv/输出、receipt、磁盘和内存不公开。即使本轮小实验已通过，宿主准备复制/共享快照page fault的完整归属、controller/节点总预算、IOPS实际压力、物理quota/掉电/擦除、持续公平性/恶意load、独立操作员和完整生产Goal仍未完成。

## 来源、构建与可核对材料

[精确provenance/全部文件SHA](validation/dual-io-provenance-v2.json) 分开三个角色：

- **host运行时及完整baseline源码** `3fed5766b0d8ae0513e5ad19b0ecaf748ab5ba88`。Linux原生Go1.27.3 / CGO0 / trimpath / buildvcs=false的新daemon SHA256 `9670b1886acb3a08ca5652d58b1fc546e4f72f7d37bf1832e91625e62579bbe8`，admin `4e663c367905905252ccb3958fce75a19d16e8dd58883237b9009bd4b50770ee`；均与独立Mac→Linux重编译逐字节相同。Linux全量race×3/vet/五套process smoke/root31通过，见 [实际native race](validation/io-native-race-v1.txt) 和 [baseline阶段转录](validation/io-baseline-pipeline-transcript-v1.txt)。
- **增强压力/拒绝探针源码** `345b991f91b981e3ccfdd6eefc8268c1a48e9df5`，之后所有Go源码/go.mod/go.sum与3fed完全一致，没有冒称新native构建。Linux root32项Python全部通过；Darwin同32项跳过4个Linux/root项。[目标阶段转录](validation/io-target-pipeline-transcript-v2.txt) 与11份JSON均原样复制，未改写数值/失败为成功。
- **guest资产**保持既有pinned v10/initrd/agent与从未分配的原始export。默认故障回归另使用明确标记的历史TEST镜像；没有部署make-smoke产生的新agent ELF，历史before-marker overlay也不是未修改生产ELF的崩溃证明。固定Firecracker/jailer1.17.0、kernel6.1.188，所有工件摘要见报告。

增强源码的 [push CI](https://github.com/123123213weqw/Xandbox/actions/runs/39847708777) / [PR CI](https://github.com/123123213weqw/Xandbox/actions/runs/39847714728) 各5个实际job与所有步骤completed/success；后续文档头CI另核对，不拿旧CI或原生结果冒充它。

实现接受ext4/xfs，但本轮实际只测ext4；XFS/其他受支持设备拓扑需要另验。

测试宿主为Linux6.8.0-136、Xeon Silver4216、64逻辑CPU/约251.5GiB可见内存、runtime ext4；guest512MiB/2vCPU/128MiB私有盘、无业务NIC。宿主背景负载/缓存不控制，不drop_caches或重挂共享盘；两个外层runner严格顺序运行，不把额外压力探针叠到默认双租户采样中。所有当前/恢复进程umask077，只有明确的历史legacy setup为0022。

## 实际压力与停止：不是只读回配置

每个suite中压力段的账本都**健康可写**；之后才在另一新VM上注入元数据ENOSPC/EROFS。下表的RO/ENOSPC名称表示所属suite，不表示同时发生高写压和元数据故障。

| 健康账本压力段 | 可信operator 32MiB O_DIRECT | guest 64MiB direct写 / 读 | 开始DELETE前VMM wchar推进 | DELETE到host cgroup空 / 持久DESTROYED |
|---|---:|---:|---:|---:|
| [cold + ENOSPC suite](validation/kvm-io-cold-v2.json) | 4006.580ms | 6065.939 / 8026.751ms | 4,735,425bytes | 47.395 / 143.547ms |
| [PAUSED snapshot + catalog suite](validation/kvm-io-snapshot-v2.json) | 4011.274ms | 6066.683 / 8083.669ms | 4,375,050bytes | 29.220 / 66.868ms |
| [cold + ledger只读 suite](validation/kvm-io-readonly-v2.json) | 4010.514ms | 6063.610 / 8032.543ms | 4,686,265bytes | 46.639 / 134.814ms |

各scope N=1，不合并成百分位/最坏界/加速比。32MiB操作员探针的own cgroup `io.stat` 每次都精确增加33,554,432写bytes、128次write IO；没有把它伪装成guest执行或生产出生实现。guest请求与kernel读回都核对，两层不是同一单位：VMM读写合用bucket，kernel分读/写方向、按块设备请求计数，不能把4096 virtio ops直接等同4096物理IOPS。

busy段不只检查ready文件：先确认同一代cgroup membership、KVM fd、PID start-time身份，读取私有/proc/io，等待该VMM `wchar` 至少推进4MiB，再复查job RUNNING和host populated后开始DELETE。公开的只有数值advance，不泄漏PID/Ref/路径；`wchar`表示包括缓冲写在内的写系统调用字节，**不表示介质持久化**。host空与持久DESTROYED分别观测；GC可能已经清掉job历史，不要求销毁后还能查询旧输出。

不能把上述transfer时间当精确滑窗硬带宽：steady bucket有自身burst，内核也允许临时burst，另有观测/FS/调度开销。32MiB至少2秒、64MiB至少5秒和故障stop最多1500ms，仅是此有限实验防止明显绕过/慢路径的guard，不是生产速率或实时SLO；没有做独立IOPS饱和测试。

### 特别保留缓存/归属差异

三组guest写/读阶段都是64MiB，但同期own cgroup的 `io.stat` 都只增加3,682,304写bytes、16次write IO，read bytes为0。**没有将64MiB全部算作VM物理charge或将cached读当物理盘读吞吐。** 缓存、写回时机和inode/page归属都能造成不同口径，不能只凭本次差额就断言其余流量全部计在controller。Linux writeback的归属规则是需要双层策略的设计原因；这一观察进一步表明不能拿单一io.stat做完整计费。

controller准备阶段复制、共享快照page fault、节点聚合预算、dirty writeback的完整归属和真正唯一RAM仍未完成；本轮没有通过给controller统一限流来阻塞Stop/GC权威路径。

## 真实拒绝与故障交叉检查

每个增强suite都用普通daemon验证3项：

1. 错误backing queue在启动拓扑校验被拒绝，不向未知设备写配置、不创建VM。
2. 只在自己新建且空的cgroup子树暂时去掉io委派，启动被拒绝；finally恢复自己子树的委派，不改变全局controller。
3. 全部VM已经回收后，只SIGKILL自己的controller，尝试在**同state**移除已绑定IO策略，因backend binding changed拒绝；原配置普通重启仍可用。不是清空账本/重绑策略来假装恢复。

这些是每种模式的重复交叉检查，3×3不是9个独立新故障类型。cold7/snapshot12/RO5是各自检查组数量，包含原有检查及共享guest工作盘限容，也不能相加宣传为24个独立压力故障。

启用预算后的后续存储故障仍保持原边界：

| 元数据故障（busy为原sleep工作负载，不是同时高写压） | busy到host空 | idle到host空 |
|---|---:|---:|
| 数据块ENOSPC | 39.190ms | 44.596ms |
| inode ENOSPC | 47.860ms | 50.278ms |
| ledger EROFS | 33.758ms | 41.828ms |

每组DELETE仍500、新Exec409、API保持STOPPING/无停止或销毁时间戳，ledger字节不变/owner+jail保留、allocated1/新Create503。故障持续时普通重启拒绝；只释放自己的filler/恢复自己的loop RW后，同state恢复回收、旧key410、新实际KVM创建/执行/销毁。

128MiB host工作盘镜像没有增长。cold+ENOSPC suite的guest写入99,549,184bytes后ENOSPC，RO及默认RO各99,553,280bytes；精确数据保留，不套用历史固定99,553,280的假设，也不宣称128MiB都是可用负载。删除guest文件后执行恢复。

## 默认IO-nil的新运行时完整回归

| 范围 | 新9670原始结果 |
|---|---|
| ledger只读 | [3检查组](validation/kvm-io-default-readonly-v1.json) |
| schema2 catalog | [10检查组](validation/kvm-io-default-snapshot-v1.json)，含5次基线切换 |
| 同报告有限混合闭环 | 两租户各120次、244.427秒、403资源样本、97对切换区间重叠；不是IO预算开启的负载或开放到达公平性 |
| 普通初始化故障 | [6例](validation/kvm-io-default-initialization-v1.json) |
| 历史TEST guest部分失败 / overlay标记前崩溃 | [1例](validation/kvm-io-default-machine-id-v1.json) / [1例](validation/kvm-io-default-before-marker-v1.json)，角色限制不变 |
| 独立cold服务 | [30检查组](validation/kvm-io-default-cold-v1.json)，另含5次兼容烟测 |
| 既有cold场景展开 | [queue9](validation/kvm-io-default-cold-v1-queue.json) / [binding9](validation/kvm-io-default-cold-v1-session.json)，不额外加18个故障 |

外层baseline/增强runner均退出0。各snapshot/init/storage格式有passed/cleanup布尔值；cold/detail格式没有统一的这些字段，依据30/9清单、Go子进程和strict finally及parent退出0，不能虚构JSON字段。另按私有receipt/自己日志独立复核10组root/cgroup、4份自己loop backing均不存在、无挂载传播；cold root另确认不存在，其runtime/cgroup清理依赖成功strict finally，不冒称额外路径独立重查。原始未分配export/历史测试资产在fixture外，故意保留，未上传public。

默认闭环的经验nearest-rank（每租户120）：alpha首新命令P50/P95/P99为704.629/794.056/852.147ms，beta为721.339/778.729/815.784ms；旧host停止P95/P99为818.638/856.625及784.405/832.993ms，旧持久销毁887.612/928.773及865.954/896.772ms。已独立从全部240行重算；未与开启IO的三次样本混算。有限、显式pacing、等待旧GC的闭环与PSS/cgroup/mincore重叠视图，仍不证明公平性、长期稳定或唯一RAM，口径沿用 [MIXED_LOAD.md](MIXED_LOAD.md)。

## 复现

在专用Linux/amd64 KVM节点检出增强harness源码345，使用固定资产与Go1.27.3；源码中的host Go与native source3fed完全相同。至少需要操作员已委派memory/pids/cpu/io的专属空子树；测试工具仅给自己独占新建的子树追加io，不替用户修改全局设置。

```sh
umask 077
GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -o /absolute/private/bin/sandboxd ./cmd/sandboxd
GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -o /absolute/private/bin/xandbox-template ./cmd/xandbox-template
```

使用 [STORAGE.md](STORAGE.md) 的完整输入加 `--io-budget`，source-revision填345的完整40位SHA，另用全新report/log目录，即cold+ENOSPC压力验收；再加 `--fault-suite ledger-readonly` 是RO交叉检查。使用 [CATALOG.md](CATALOG.md) 的完整snapshot输入加 `--io-budget` 则是PAUSED恢复及catalog验收，仍需原始未分配export。不要复用目录或未核对同一runner终态就重复启动；默认完整回归还需分别运行上表工具，不能用三个IO probe代替它。

整个 [生产Goal](PRODUCTION.md) 继续保持开发状态，节点/准备IO预算、物理quota、整机/掉电/介质、完整init窗口、预热、长期归档/擦除、持续公平性/唯一RAM、可靠审计/告警/回滚及独立操作员仍未验收。
