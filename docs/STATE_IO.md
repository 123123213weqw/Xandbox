# 整状态盘 EIO / fsync 卡住时的独立撤权

**生产化开发中，不是生产SLO或完整M2验收。** 本专项把真实普通daemon的持久化I/O与撤权、物理停止、持久确认分开：不能因为账本卡住就继续执行，也不能因为VM已经停了就谎报持久销毁或归还配额。

## 实际发现与修正

原生旧daemon `9670b188…` 已通过此前ENOSPC/EROFS、IO预算与宿主恢复测试，但这些没有证明Save尚未返回的情形。本次[四场景旧基线](validation/kvm-state-io-v1.json)保留为 **passed=false**：

- 整状态盘EIO已返回时，busy/idle停止均较快，没有假确认，容量保留。
- Save真正卡在内核fsync时，busy任务取消仍可带来物理Stop，但新Exec排在同一record mutex之后；idle VM只能等待guardian短租约消耗完。
- 不能拿busy的快速结果替代idle，也不能把“拒绝最终返回409”当作拒绝不依赖账本I/O。

修正只增加一条独立撤销路径，不改变持久化承诺：

```text
校验租户与不可变Ref → 原子intent撤权、停止续租
                         ├─ reaper不取record/op/worker锁
                         │    → RevokeLease只关闭已拥有的活pipe capability
                         │    → 原root warden收到EOF → 请求停止准确执行域
                         └─ 普通STOPPING Save → Stop及调用退出证明
                                → 持久STOPPED → Cleanup → 持久DESTROYED → 还容量

新Exec先检查不可变generation/原子intent；取得record锁后仍重新检查。
```

`Driver.RevokeLease(Ref)` 是新的后端接口契约，必须有界、非阻塞、无磁盘/RPC等待。Firecracker实现只查询活进程map并以TryLock关闭该代lease writer：不读取registry/catalog、不打开cgroup路径、不查杀PID、不收养未知资源，也不保存永久撤销map。reaper反复调用，覆盖Prepare稍后才发布活capability的竞争；未发布时不猜测/杀资源。独立硬期限、普通Stop的执行域与调用drain证明保持原样。

RevokeLease返回nil不证明停止、持久状态或清理。原子intent与所有权检查仍先于这条路径；错误generation/其他租户不能借此撤销别人的实例。Mock实现为no-op，它没有真实隔离承诺。外部Driver实现需明确实现这个契约，不能依赖阻塞Stop或默默忽略安全语义。

## 故障限定在独占 L1

沿用[三层KVM夹具](NESTED_HOST.md)。Go ioctl控制器只有在marker、root与**L1 PID1**都满足后，才把该L1固定2GiB `/dev/vda` 映射成固定名字的device-mapper设备，`/srv`挂载在其上。包括ledger、owner、runtime、assets与已有FD，没有通过替换目录或用户态Store错误假装介质故障。

- **EIO**：固定完整长度的`error` target，核对内核表读回。故障前已打开的O_DIRECT **只读**mapper FD必须实际返回EIO；普通DELETE返回500，不能假认STOPPED/DESTROYED。
- **held IO**：`DM_DEV_SUSPEND` 配合NOFLUSH/SKIP_LOCKFS。预先打开的direct read不能完成，并且还要观测**普通daemon**原PID/startticks对应的线程实际为D-state，停在state FD的fsync/fdatasync。仅等待sleep/client timeout不算证据。恢复前再次核对suspended表、held fsync及probe未完成，resume后probe才能结束。

Linux6.8 UAPI说明了suspend会延后新I/O直到resume，见[固定内核dm-ioctl定义](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/dm-ioctl.h)。夹具只允许固定linear/error表与必要ioctl；禁止REMOVE_ALL、任意设备/target/路径参数。没有在L0加载模块、建立DM设备、挂载/重挂共享盘、写原始物理块设备或改路由。L1的DM core是已固定内核的builtin，不新增外部dmsetup二进制或库。

控制、串口和buffer留在L1 tmpfs；先恢复自己的mapper，再等待阻塞probe退出、清零/解除映射。整个L1仍受L0独占cgroup、原warden、短租约与硬期限约束。原始Ref、PID、FD路径、日志、receipt、盘/内存与令牌不公开。

## 实际有限观测

[新原生程序四场景](validation/kvm-state-io-v2.json)全部通过，旧报告未重写；每场景各N=1，无百分位/通用加速比/实时界承诺。

| 场景 | 旧程序DELETE到执行域空 | 新程序DELETE到执行域空 | 旧 / 新 Exec409观测 |
|---|---:|---:|---:|
| EIO busy | 43.374ms | 39.475ms | 3.994 / 0.664ms |
| EIO idle | 50.572ms | 40.079ms | 5.447 / 0.901ms |
| held fsync busy | 39.395ms | 39.518ms | 1510.111 / 1.484ms |
| held fsync idle | 4381.622ms | 43.555ms | 4388.358 / 1.843ms |

旧busy的1510.111ms发生在夹具保留约1.5秒故障再主动解除之后，**不是程序自身承诺1.5秒内恢复**；若底层I/O继续不返回，record锁等待可以继续。idle旧样本则消耗了剩余guardian租约。新样本中的40ms级数字只是执行域停止，不是持久销毁；500/1500ms仅用于本轮识别明显慢路径的实验guard，不是线上政策或SLO。

四场景均检查新Create503、配额仍占用、真实VM FD/guest UID65534。EIO没有虚假停止/销毁确认；held fsync没有提前确认DELETE，解除后普通路径才完成持久化。每例先恢复底层linear映射，**之后**才切断自己的L1、原盘冷启动、普通daemon回收旧代/拒绝旧key410，并完成新KVM执行和销毁。不是“EIO持续期间恢复成功”或“同时物理掉电”的证明。

fast拒绝只证明本轮显式Stop/Destroy已经置intent的场景；其他查询、创建及租约失败路径不能因此一概称为无I/O等待。

busy特指带sleep子进程的已运行guest任务，不是持续写盘或VMM线程本身卡在不可中断I/O。guest业务NIC为0，512MiB/2vCPU/128MiB工作盘。外层宿主与规格、独立停止/回收计时边界沿用NESTED_HOST；不控制共享L0背景负载，不drop_caches。

## 构建与完整新运行时回归

源码 `c9b52ef21db3789234ff9488554a7918d175c0f3`，生产实现原始提交 `b1eff8521fe57a68697b37c5dae08cfe32bb2091`，其后仅Linux测试处理允许多个完整lease packet的合法调度。Linux原生Go1.27.3 / CGO0 / trimpath / buildvcs=false：

- daemon `b8d2e5b9b5b312841c7287871ee073017d46044592b447736fdf6d39f139a8af`
- admin `634d71c8d711ef6d5a1ad195536c51b911cd49030312841859bbc8c8cc92566a`
- test-only fixture `0b54a2df3cb8d744ca85ad5c196575d877fbc3b4c21ee0fb926590d5c6aa264d`

三者均与独立Mac→Linux编译逐字节相同；没有沿用旧9670冒称新程序。root warden仍是原B810，guest仍是原始pinned v10/initrd/agent及明确标记的历史TEST镜像。process-smoke构建的新guest ELF没有部署到KVM。

完整新运行时runner已退出0，原始脱敏材料与全部SHA见 [精确provenance](validation/state-io-provenance-v2.json)。[native race×3](validation/state-io-native-race-v2.txt)、vet、[fixture race×10](validation/state-io-fixture-native-race-v2.txt)/vet、五套process smoke与root Python37项通过；process smoke不是microVM证据，其带私有构建路径的原始make日志不公开，不伪装成原样脱敏日志。[实际阶段转录](validation/state-io-pipeline-transcript-v2.txt)保持原字节。两个新回归在改实现前的[真实失败输出](validation/state-io-before-fix-unit.txt)另存，来源为旧production Go加后来提交的新测试，不是另一轮KVM。

| 同一新原生daemon范围 | 原始报告 / 有限结果 |
|---|---|
| 整状态盘 / held fsync | [4例](validation/kvm-state-io-v2.json)，5次L1冷启动 |
| 健康L1掉电 | [3检查点](validation/kvm-stall-power-v2.json)，4次L1冷启动 |
| IO启用cold / snapshot / ledgerRO | [7组](validation/kvm-stall-cold-v2.json) / [12组](validation/kvm-stall-snapshot-v2.json) / [5组](validation/kvm-stall-io-readonly-v2.json) |
| 默认nil-IO ledger只读 | [3组](validation/kvm-stall-default-readonly-v2.json) |
| 默认快照catalog及双租户混合闭环 | [10组与各120次](validation/kvm-stall-default-snapshot-v2.json)，249.602秒、408个资源样本、94对跨租户切换区间重叠 |
| 默认初始化故障 | [6例](validation/kvm-stall-default-initialization-v2.json) |
| 历史TEST镜像 | [machine-id部分失败1例](validation/kvm-stall-default-machine-id-v2.json)、[compiler-overlay标记前崩溃1例](validation/kvm-stall-default-before-marker-v2.json) |
| 冷路径 / queue / binding展开 | [30组](validation/kvm-stall-default-cold-v2.json) / [9断言](validation/kvm-stall-default-cold-v2-queue.json) / [9断言](validation/kvm-stall-default-cold-v2-session.json) |

queue/binding是30组中已有场景的展开，不额外加18个独立故障；240次是有限闭环，不是开放到达/公平性/生产持续负载。mixed经验nearest-rank统计已按原始120行/租户重算，不把PSS、cgroup charge和mincore重叠口径相加成唯一RAM。cold/细项格式无统一passed/cleanup布尔值，结论依据成功检查列表、Go test子进程和strict finally/parent0，不编造字段。

[独立清理复核](validation/state-io-independent-cleanup-v2.txt)覆盖12个夹具scope：3组L1的全部5/5/4个执行代际与私有根、3个storage的own loop绑定/parent挂载/根与cgroup、5个snapshot/init的准确日志归属根与cgroup、cold准确私有根均不存在。cold的runtime/cgroup精确随机后缀未从保留材料恢复，停止/回收依赖strict finally和parent0，不冒称独立路径复查。原始未分配模板及历史TEST资产有意留在夹具外。

源码 [push CI](https://github.com/123123213weqw/Xandbox/actions/runs/39860023515) / [PR CI](https://github.com/123123213weqw/Xandbox/actions/runs/39860029927) 各5个实际job及所有步骤completed/success、attempt1；后续文档头CI另验。所有新阶段umask077，只有显式legacy升级setup为0022。旧程序/旧报告、当前新native与历史guest TEST角色不混用。

## 尚未覆盖

- VMM/内核自身不可中断I/O、全部监督者失效、极端调度饥饿；关闭lease不能强制抢占内核D-state或制造停止证明。
- 各种部分写入/丢失flush/静默损坏、介质错误全部窗口、物理L0掉电/擦除、快照共享引用与多盘故障组合。
- 此state-IO矩阵的operator IO策略为nil；IO预算回归另在L0直接块设备ext4运行，不能声称受限IO策略支持DM拓扑。
- 节点准备/总资源预算、长期元数据归档、开放到达公平性、审计/告警/备份回滚、独立操作员、生产SLO及完整M1–M4。
