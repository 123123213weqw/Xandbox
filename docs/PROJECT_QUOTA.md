# ext4 project quota：前置证据与实现中的驱动协议

**开发中，不能按生产能力启用。** 本分支已接入实验性普通驱动quota，并打通cold及snapshot的有限恢复与共享pin检查，quota清零已移出catalog pin锁；block/inode耗尽与启动拒绝已有有限实测；quota启用的整state I/O故障也已有有限实测；逐quota syscall、崩溃/并发窗口和完整新运行时回归仍在验收。以下先区分当前实现与PR18已合并的历史前置证据，再列出未完成协议要求。M2完整磁盘/节点预算仍未完成。

## 为什么不能只设一个 hard limit

Linux6.8 的 `ignore_hardlimit()` 对持有 `CAP_SYS_RESOURCE` 的进程允许绕过硬限制；project quota 不天然约束拥有该能力的 root 准备进程。检查来源是[固定内核 dquot.c](https://github.com/torvalds/linux/blob/v6.8/fs/quota/dquot.c)，不是根据“root 应该不受限制”猜测。仅 Q_GETQUOTA 读回正确，不代表实际写入会受限。

同时，带 PROJINHERIT 的 ext4 目录会拒绝跨 project 的 hardlink（EXDEV），见[固定内核 namei.c](https://github.com/torvalds/linux/blob/v6.8/fs/ext4/namei.c)。当前快照路径以硬链接共享只读 memory/state inode，因此给新 jail 目录加继承标记后直接套用现有链接流程并不成立。不能靠只支持 cold、默默复制大快照，或给已运行 VM 临时取消限制来掩盖这个问题。

## 当前分支的实验性接入（PR19，未完成验收）

- `Config.Quota` 为操作员不可变策略：完整ext4 UUID、独占project范围、block/inode硬上限；mount-ID、实际enforcement与所有controller线程的capability均检查。旧state不可直接加/删/改策略，缺省仍是原有无quota实验规格。
- projectID与既有durable UID slot一一对应，owner v3/v4分别支持cold/snapshot；`quota_attempted`必须持久化后才允许设置限额。未知或未attempt的非空quota记录不能收养；准备失败也保留owner直到准确清理。
- 全部私有jail/root在复制前设置project/继承，快照共享链接仅在可信pre-fork区间进入并reseal，fork前读回。cold与snapshot均已有有限实机检查；**全部quota I/O/崩溃、并发与初始化窗口仍未完成**。
- Root无CAP_SYS_RESOURCE不是全部边界：init user namespace内文件owner可修改project属性，见[固定内核fileattr权限检查](https://github.com/torvalds/linux/blob/v6.8/fs/ioctl.c)。quota模式warden额外继承seccomp，阻止后代quotactl/quotactl_fd、FSSETXATTR及SETFLAGS，保留Firecracker默认filter；READY前检查NNP与过滤器。Go race/cgo不能同步all-thread prctl时严格拒绝，实际kernel/exec继承证明另在CGO0运行，不单线程回退。
- Stop/drain、文件清理、quota清零/Q_SYNC/读回、owner删除/目录fsync与容量归还是不同阶段；quota I/O或用量不归零就不能提前释放UID/project。恢复不把jailer的PID文件当成身份或kill依据。

上一轮历史有限实测使用原生普通daemon `1d66fc40…`、warden `b290a5ed…` 与原始pinned guest：running/stopped/destroyed三检查点、四次L1实际开机的同盘普通恢复、旧key410、新真实KVM执行销毁通过。running/stopped各N=1观察到非fsync PID文件在重启后为空，quota charge与独立命名inode分配同时由189,911,040变为189,906,944字节；192MiB hard、128 inode hard、归属/继承/不可变资产均保持，并在GC后清零。不是百分位、SLO或全部quota故障验收。已公开[本轮有限证据与精确SHA](validation/project-driver-basic-provenance-v7.json)：[cold三例](validation/kvm-project-driver-v7.json)、[默认健康掉电三例](validation/kvm-project-driver-default-power-v7.json)、[默认EIO/held-fsync四例](validation/kvm-project-driver-default-state-io-v7.json)，以及五份保持passed=false的原始前序；全部是部分验收，不是最终PR19通过。

验收不能把live物理用量错误当成不可变policy：初版fixture要求整个quota record完全相等而失败；后来独立核对namespace，定位到pinned jailer的`firecracker.pid`有3字节未同步内容，重启后为空。上游[PID文件写入代码](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/src/jailer/src/env.rs)没有fsync；修正只允许这个固定非权威文件的有界size变化，仍严格检查同inode/owner/mode/link、所有其他文件尺寸、实际块/inode计数和硬限额，没有用保存PID回收或先停止VM来绕过running掉电。

Linux full race×3/vet、fixture race×10/vet、root Python40和[CGO0实际kernel/exec过滤器证明×3](validation/project-driver-cgo0-kernel-filter-v7.txt)通过；[原样阶段转录](validation/project-driver-basic-pipeline-v7.txt)的runner退出0。[独立只读清理](validation/project-driver-independent-cleanup-v7.txt)复核8个scope、23个执行代际全部不存在；不是在已经删除的盘上虚构quota读回。上述数量只覆盖列出的cold/默认宿主profile，不包括后续所有旧服务矩阵。

### 新锁修正与真正的L1快照配额检查

生产源码 `181e6ef…` 将慢quota清零/Q_SYNC放在catalog pin flock之外，旧owner/pin/UID/project保持保留；进入锁后必须复核完全相同的owner证明，才能删除所有权。使用最终测试函数和[旧registry重新复现](validation/quota-lock-before-finaltest-v1.txt)确实超时，[修正后race×10](validation/quota-lock-after-finaltest-v1.txt)通过。它证明受控quota hook阻塞不再占住catalog锁，不是实际held-quota-syscall的延迟验收；**owner删除/目录fsync仍在catalog锁内**，任意元数据阻塞与全部持久窗口没有因此被证明有界。

源码/夹具冻结在 `61d88cfe…`，新普通daemon `ab547783…`、原warden `b290a5ed…`、admin、fixture和builder test共五个Linux原生ELF均与独立Mac→Linux构建逐字节相同。原guest/initrd未改。新[精确provenance与所有SHA](validation/project-snapshot-provenance-v1.json)明确区分旧daemon证据，不将旧报告冒充此次完整回归。

| 新运行时有限检查 | 实际范围 |
|---|---|
| [真正L1-built快照与普通quota路径](validation/kvm-project-snapshot-v1.json) | L1内新建未分配creator，当前L1 HostABI；两个component clone核对后仅导出从未分配的creator；普通catalog发布/激活 |
| 同时存活的两个普通snapshot实例 | 私有project不同；只读memory/state确为共享project0 inode、完整512MiB内容hash不变；独立namespace核对，不重复计入clone |
| 活pin退役与GC | pins 2→1，GC均不能删；第一个实例销毁后另一个真实VM仍可读取自己的数据和执行；最后pin释放后GC恰好删除该模板 |
| snapshot同盘冷恢复 | running/stopped/destroyed各N=1，共4次L1开机；owner v4/quotaattempt/initialization、硬限额、共享文件、旧key410与新真实KVM执行销毁均检查 |
| [cold quota同盘恢复](validation/kvm-project-snapshot-cold-v1.json) | 3检查点/4次L1开机，使用新锁修正daemon；不是沿用旧1d66运行结果 |
| [默认健康掉电](validation/kvm-project-snapshot-default-power-v1.json) / [默认EIO与held-fsync](validation/kvm-project-snapshot-default-state-io-v1.json) | 3/4例，分别4/5次L1开机；原停止/拒绝新执行闸门保持，**尚非全部旧服务矩阵重跑** |

snapshot running/stopped各观察到私有charge为137,920,512字节/14 inode，冷启动后137,916,416字节；4KiB差仍来自同一非权威PID文件，实际quota与独立namespace一致，192MiB/128 inode硬限额不变。此数值不包括共享catalog inode，也不是完整节点磁盘预算、加速比或SLO。活pin GC后为后续冷恢复发布的是**同一从未分配creator导出的新时间戳声明**，不是从已分配clone生成新模板，也不宣称做了第二次base build。

[新native full race×3](validation/project-snapshot-native-race-v1.txt)/vet、[fixture race×10](validation/project-snapshot-fixture-native-race-v1.txt)/vet、root Python41、[CGO0实际过滤器证明×3](validation/project-snapshot-cgo0-kernel-filter-v1.txt)通过；Darwin full race×3/vet通过。[原样pipeline](validation/project-snapshot-pipeline-v1.txt)退出0；[独立只读清理](validation/project-snapshot-independent-cleanup-v1.txt)复核4个scope、17个执行代际全部不存在。quota清零来自删除测试盘前的L1实际读回，不能由事后路径检查替代。未公开私有console/receipt/UUID/身份或盘镜像。

原始报告limitations中“snapshot save/restore”一词指**外层QEMU/L1故障注入没有保存/恢复快照**；L2 Firecracker的完整create/load确实执行。保留原报告原样，在provenance说明这个容易混淆的旧措辞，不改写原始结果。旧v7与其失败前序也全部保留。

### 普通daemon的EDQUOT与启动拒绝（新有限证据）

[本轮精确provenance、SHA与未完成清单](validation/quota-negative-provenance-v3.json)覆盖源码 `100a155…` / `c7e0026…`。变化仅为TEST ONLY夹具/测试：普通daemon仍为 `ab547783…`、warden仍 `b290a5ed…`，原guest未改；两轮各五个native ELF均与独立交叉构建精确匹配。不是把PR18的内核worker实验当成普通驱动集成。

每个场景有独立的新state/runtime/cgroup/backend binding；负向场景全部结束且固定测试project记录清零后，才启动同盘正向普通服务。没有在线改已绑定实例的策略。

| 普通daemon场景 | 实际检查 |
|---|---|
| CAP_SYS_RESOURCE仍在root能力集合 | 明确的capability构造器错误；拒绝启动且无API socket |
| 错filesystem UUID | 明确的UUID错误；不能降级或忽略配置 |
| 未知非空quota记录 | 普通驱动拒绝，独立读回记录完全不变；reap后仅由PID1清理**夹具自己注入的固定记录**，不是驱动收养或批量清外部ID |
| 已绑定策略变化 | 健康空daemon正常退出，再把其测试输入策略加4096字节；新构造器拒绝，原durable binding完整hash不变 |
| block hard=16MiB、inode hard=128 | 普通API Create500，实际Prepare私有日志确认EDQUOT；正常GC后durable DESTROYED、精确资源消失、旧key410 |
| block hard=192MiB、inode hard=1 | 同样实际EDQUOT及回收；限制的是host私有jail inode，不是guest内文件数量 |

[首轮普通负向/冷恢复](validation/kvm-quota-negative-v1.json)与[加入独立无enforcement场景后的重跑](validation/kvm-quota-negative-v3.json)都通过。每轮block/inode各做两次实际Prepare耗尽：第一次回收后重启同一binding的普通daemon，确认旧账本仍DESTROYED/旧key410；再用新key取得容量并再次500/EDQUOT，而不是残留容量503，第二代也完整回收。这里验证的是**pre-fork准备耗尽**，不是guest文件系统满、持续租户压力或所有运行中增长窗口；错误原文/Ref/路径仅在私有日志中核对，不投射到tenant API或公开报告。

另用一个全新的普通ext4文件盘、匹配的实际UUID、无quota格式化/初始挂载选项，验证[缺少enforcement明确拒绝](validation/kvm-quota-negative-unenforced-v3.json)。没有quotaon/off、在线改挂载策略或改共享L0。此profile只有1次L1开机、**0个L2 VM**：检查具体的mount enforcement构造器错误、child reaped、无API/owner/代际执行域；不把它计作guest执行、冷恢复或quota清零证明。

两轮分别另通过真实[cold恢复](validation/kvm-quota-negative-v3.json)、[真正L1-built snapshot/shared-pin检查与cold恢复](validation/kvm-quota-negative-snapshot-v3.json)、[默认健康掉电3例](validation/kvm-quota-negative-default-power-v3.json)和[默认EIO/held-fsync4例](validation/kvm-quota-negative-default-state-io-v3.json)；首轮同类原始报告也保留。每轮Linux full race×3/vet、fixture race×10/vet、实际CGO0过滤器proof×3通过，root Python分别42/43项；最终冻结源码Darwin race×3/vet通过。[独立只读复核](validation/quota-negative-independent-cleanup-v3.txt)确认9个scope、35个外层L1执行代际/root/control全部不存在。enforced profile中的quota零值来自销盘前的L1实际读回，独立路径复核和unenforced profile不替代它。

中间一次[私有runner预检失败原文](validation/quota-negative-preflight-failed-v2.txt)原样保留：文件名替换误把已固定的initrd-v10写成不存在的v20，SHA预检在源码解压/native测试/L1分配前退出1，0次开机、无KVM报告；新v3只修正runner文件名，源码仍是相同 `c7e0026…`，guest和生产代码未改。两轮实际runner均退出0；旧冷路径失败前序、旧部分验收清单仍按历史源码保留，不改写成当前结果。

### quota启用时的整state真实I/O故障

[新原始报告](validation/kvm-quota-io-v1.json)通过busy/idle各一次EIO与挂起I/O，共4例、5次L1开机。与之前默认nil-quota场景不同，这轮**普通daemon实际启用quota**，仍为未修改的 `ab547783…`/warden `b290a5ed…` 与原guest；测试源码冻结 `e13a3eb…`。[精确provenance与SHA](validation/quota-io-provenance-v1.json)记录五个native ELF与独立交叉构建匹配、范围和未完成清单。

新固定profile只在自己的L1中建立dm-linear/error/suspend并挂载fresh ext4/prjquota。PID1观察器必须核对本进程创建的mapper对象、名称、设备、完整linear表、固定vda backing、block-node身份和实际rw ext4/prjquota/format，不能传入任意device/table/project。普通daemon仍通过独立子进程移除CAP_SYS_RESOURCE，VMM继承quota额外filter及默认seccomp；不改共享L0的模块、挂载、能力或device-mapper。

故障前对READY状态的私有资产、quota/receipt和整个文件系统做同步baseline，再对包含ledger/owner/runtime/assets/已打开FD的**整个state盘**施加故障；控制面留在tmpfs/串口。并非先证明了每个quota设置窗口的持久性。

| 故障阶段 | 实际结果 |
|---|---|
| EIO busy/idle | 预打开O_DIRECT读确实EIO；DELETE500且无durable STOPPED/DESTROYED假确认，new exec409、new create503；恢复linear后原quota owner字节不变，保留到冷启动 |
| 冷启动后的EIO恢复 | 读回192MiB/128 inode硬限制、project/继承及不可变资产；实际quota与独立namespace都为189,911,040字节/16 host inode；旧key410、新真实VM执行销毁、全部四个project记录清零 |
| 挂起I/O busy/idle | 预打开direct read阻塞，普通daemon真实线程在`/srv/state`的fsync/fdatasync中处于D；无DELETE ACK且容量503，停止执行和拒绝新执行独立观察 |
| 恢复挂起的I/O后 | direct read才完成；随后确认durable DESTROYED、精确资源消失及quota零值，再切断自己的L1并冷启动；不是在阻塞期间假认回收 |

四个有限样本中，DELETE发起到host执行域空为34.495–45.114ms，新exec拒绝为0.669–6.118ms，均通过既有1500/500ms夹具闸门；这是各场景N=1的观测，不是百分位、最坏延迟或SLO，也不把DELETE错误响应当作物理停止证明。本轮同步baseline使两例EIO后非权威PID文件内容保留，charge无4KiB下降；恢复仍不根据PID文件选择进程。此前未同步cold测试的有效4KiB下降另行回归，不能强迫两种前提给出相同PID现象。

原始字段`quota_and_ownership_released_only_after_io_resumed`表示恢复I/O后的零值/owner消失确认，加上held-fsync/无ACK/容量保留的证据；**没有在设备挂起期间独立读quota**，不能只靠这个字段证明所有中间syscall状态。实际观察到的阻塞syscall是ledger fsync，而不是Q_SET/Q_SYNC。精确quota syscall/clear-before-owner-delete等窗口仍待单独故障注入和崩溃检查，不能把本轮整盘故障替代它们。

同一新fixture还通过[普通quota cold3](validation/kvm-quota-io-cold-v1.json)、[真正L1-built snapshot/shared2与cold3](validation/kvm-quota-io-snapshot-v1.json)、[默认nil-quota I/O4](validation/kvm-quota-io-default-state-io-v1.json)回归；共享观察器的重构没有把旧profile放宽为任选设备。[native full race×3](validation/quota-io-native-race-v1.txt)/vet、[fixture race×10](validation/quota-io-fixture-native-race-v1.txt)/vet、root Python44、[CGO0实际filter proof×3](validation/quota-io-cgo0-kernel-filter-v1.txt)、Darwin race×3/vet通过。[runner原文](validation/quota-io-pipeline-v1.txt)退出0；[独立只读清理](validation/quota-io-independent-cleanup-v1.txt)复核4个scope、18个外层执行代际/root/control全部不存在。quota零值来自销盘前L1实际读回，不由事后路径消失冒充。

### 精确的quota已清、owner/pin仍保留的掉电窗口

[新原始报告](validation/kvm-quota-clear-v1.json)通过一个明确窗口、两次L1开机；[完整provenance和SHA](validation/quota-clear-provenance-v1.json)固定测试源码 `ab8b21e…`。普通daemon/warden/guest均未改，没有生产fault hook、ptrace或syscall overlay；五个native ELF与独立交叉构建匹配。真正的L1未分配模板、初始共享/退役GC检查完成后，再创建两个普通snapshot VM作为victim/keeper。

仅观察“quota为0”不能说明驱动已经完成Q_SYNC。该夹具先确认普通daemon没有打开catalog lock FD，由L1 PID1持有原来的私有`.lock` inode；删除victim后，观测这个**直接子进程新打开了指向同一kernel inode的独立FD**，前后检查proc start身份。固定源码中`registry.releaseContext`先执行`quota.release`（Q_SYNC/readback完成）再进入`catalog.withLock`打开此FD，因此将位置限定到clear返回后、owner删除前。这里是**FD观测加经SHA固定的源码顺序**，不是直接trace到了Q_SYNC返回事件。

| 持锁后、掉电前 | 实际证据 |
|---|---|
| victim | durable RECLAIMING，已有停止确认、无销毁确认；精确jail/cgroup不存在，quota usage/limits/times全部为0，但原initialized v4 owner字节不变 |
| 容量与保留 | victim和keeper占用两份实例容量；victim quota为0仍拒绝新key503，不把0当成可丢弃的owner/UID/project/pin reservation；不是在持锁时另调用allocator完成了一次分配 |
| keeper | 真实VM仍能读取自己的marker并执行；只允许两个已知共享inode各少一个victim hardlink，其他名字/identity/metadata和独立quota统计仍核对，不整体忽略link变化 |
| 崩溃定位 | clear边界后观察器只读quota，不再Q_SYNC/set/clear；PID1把原FD留在node字段，**成功RPC返回不释放锁**，直到外层切断自己的整个L1才由VM死亡释放 |

同盘冷启动、普通daemon尚未启动前，独立读回victim quota仍为0且namespace仍不存在，**两份原owner字节与两个catalog pin均保留**；keeper硬限额/归属/继承、namespace实际用量及只读共享内容hash正确。随后普通daemon把两个旧Ref都恢复为durable DESTROYED，精确旧资源消失、两个旧key410；新实际VM有新boot并执行/销毁，四个private project记录清零，两个旧pin释放，原active pristine template仍在。不会恢复已分配guest，也不因quota空记录收养外部身份。

这轮人为持有全局catalog锁是为了定位崩溃点，**不宣称锁内Prepare/switch延迟或SLO**。它覆盖这个post-clear/pre-owner-delete窗口，不替代任意Q_SET/Q_SYNC/readback错误、全部owner目录fsync或shared-reference崩溃场景。

同一fixture还通过[普通snapshot/shared2与cold3](validation/kvm-quota-clear-snapshot-v1.json)、[quota整state I/O4](validation/kvm-quota-clear-io-v1.json)、[普通quota cold3](validation/kvm-quota-clear-cold-v1.json)、[默认nil-quota I/O4](validation/kvm-quota-clear-default-io-v1.json)；[native race×3](validation/quota-clear-native-race-v1.txt)/vet、[fixture race×10](validation/quota-clear-fixture-native-race-v1.txt)/vet、root Python45、[实际CGO0 filter proof×3](validation/quota-clear-cgo0-kernel-filter-v1.txt)及Darwin race×3/vet通过。[原样runner](validation/quota-clear-pipeline-v1.txt)退出0，首轮物理检查即通过；[独立只读复核](validation/quota-clear-independent-cleanup-v1.txt)确认5个scope、20个外层L1执行代际/root/control全部不存在。配额/owner/pin证据来自销盘前L1实际观察，不由最终路径消失推导。

**合并前还必须完成**：其他Q_SET/Q_SYNC/readback/clear确切窗口的EIO/EROFS/held syscall、partial prepare及其余owner/pin/fsync崩溃与并发；全部新native默认冷路径/快照/初始化/IO/故障服务回归、完整独立清理和最终CI。这个精确窗口及有限整state I/O、EDQUOT/拒绝/snapshot/cold通过，不等于M2完整物理预算或生产验收完成。

### 精确quota syscall errno注入（有限、非介质故障）

[原始6例及普通cold三检查点](validation/kvm-quota-syscall-v1.json)与[精确来源/构建/边界清单](validation/quota-syscall-provenance-v1.json)另验了下列固定窗口。普通daemon仍为 `ab547783…`、warden/guest未变；**该profile的启动环境额外继承TEST ONLY seccomp通知和NNP，不能称为完全相同的生产启动环境**。

| 固定注入位置 | errno | 注入时独立内核读回 |
|---|---|---|
| 持久attempt owner之后、reserve SET | EIO | quota记录全空，尚无执行namespace |
| reserve SET之后的GET | EROFS | 已安装192MiB/128 inode硬限制，usage为0 |
| reserve SET/GET之后的SYNC | EIO | 同上 |
| Stop/私有namespace清理后的clear SET | EIO | 已知硬限制仍在，usage为0 |
| clear SET之后的SYNC | EROFS | quota记录全空，但owner/容量尚不能释放 |
| clear SET/SYNC之后的GET | EIO | 同上 |

三个reserve失败实际Create500；每例均等到普通持久DESTROYED、精确owner/jail/cgroup不存在、三个固定project全清零、旧key410，再以新key创建真实KVM/UID65534 guest、执行并销毁。三个clear失败在errno仍armed时检查RECLAIMING、有StoppedAt而无DestroyedAt、原owner字节不变、新Create503；解除注入后才等待正常销毁/清零并复验新真实VM。**每例仅观察到一次实际注入，不据此宣称已经验收反复重试**。

通知器只由独占L1的PID1启动其固定直接子进程，经私有SCM_RIGHTS接收listener；核对immutable进程身份、通知线程的Tgid、固定runtime anchor inode、固定命令与project范围。Linux6.8的尺寸先查询再严格核对；all-thread `NEW_LISTENER|TSYNC|TSYNC_ESRCH|WAIT_KILLABLE_RECV`不支持即失败，不做单线程回退。成功路径必须发CONTINUE，让**原syscall真正进入内核**，不能用返回0伪造quota成功；指定失败才返回负errno。原warden的quota deny和Firecracker默认filter没有替换，成功guest另检查真实VM FD、全部线程能力/NNP及新增observer层。

实现依据为[Linux6.8通知接口](https://docs.kernel.org/6.8/userspace-api/seccomp_filter.html)、[固定UAPI与CONTINUE限制](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/seccomp.h)、[固定内核flag/通知实现](https://github.com/torvalds/linux/blob/v6.8/kernel/seccomp.c)。通知器**不是安全策略**，不读取tracee指针；独立quota读回只是该时刻的内核状态，不是介质持久性证明。这里没有让设备实际返回EIO/EROFS，也没有卡住真实Q_SYNC或在其内部掉电。

源码冻结 `9e0ddc910a2933893bd47df806744117497ac48d`；Linux原生fixture `995903f6…` 与独立Mac→Linux构建精确一致，另四个原生ELF同样匹配。native full race×3/vet、fixture race×10/vet、root Python46项、实际CGO0 kernel/exec filter×3与Darwin race×3/vet通过。同一夹具还回归[清零后owner/pin精确掉电](validation/kvm-quota-syscall-clear-v1.json)、[真正L1快照共享及cold](validation/kvm-quota-syscall-snapshot-v1.json)、[quota整state I/O](validation/kvm-quota-syscall-io-v1.json)、[默认nil-quota I/O](validation/kvm-quota-syscall-default-io-v1.json)。[只读独立审计](validation/quota-syscall-independent-cleanup-v1.txt)复核5个scope、20个实际L1执行代际全部不存在；quota证据来自盘删除前的L1实际读回，不由路径消失推断。

仍未覆盖held-quota、listener失效、重复clear错误、逐syscall崩溃/重启、partial-copy Prepare与snapshot pin故障组合；owner unlink/目录fsync、完整新运行时回归、节点总预算、最终PR19 CI与M1–M4门槛也未完成。PR19继续Draft，不因此宣称生产就绪。

以下TEST ONLY部分是PR18已合并的内核前置实验，不是上述普通驱动验收的替代品。

## TEST ONLY 夹具的边界

测试沿用[独占 L1 / 真实 L2 KVM](NESTED_HOST.md)，显式 `--quota-probe`，与 state-IO profile 互斥：

- L0 只创建自己新分配的 2GiB raw 文件；mkfs 不挂载、不改共享盘。e2fsprogs1.46.5 用 `-O project,quota -E quotatype=prjquota -I 256 -b 4096`，不是不存在的 `-Q` 开关，见 [mke2fs 手册](https://man7.org/linux/man-pages/man8/mke2fs.8.html)。
- 两个固定 SHA 的 quota_tree/quota_v2 module 只复制到自己的 initrd 并在 L1 加载；不在共享 L0 insmod、quotaon/off、remount 或修改能力。
- L1 PID1 必须是 root 并带固定 marker，使用固定 `/dev/vda` 上 `/srv` 的 ext4/prjquota mount；根据 mountinfo 与设备身份核对 enforcement，不只看 accounting。所有 quota 请求走已经打开的目录 FD，使用 [quotactl_fd](https://man7.org/linux/man-pages/man2/quotactl.2.html)，不解析宿主 block-device 路径。
- 只支持三个固定测试 project，首次要求 usage/limits/times 全空；不收养非空记录。无任意 project/路径/命令参数，不提供 tenant host exec。
- root PID1 先做带 CAP_SYS_RESOURCE 的负对照。之后只对其固定子进程进行 all-thread `PR_CAPBSET_DROP`，固定自重执行；核对每个 worker 线程 effective/permitted/bounding/inheritable/ambient 均无该能力，root UID 保持不变。
- 受限 root 子进程实际分配文件触发 block/inode EDQUOT；共享 project0 inode 的跨 project 链接先确认 EXDEV，再在可信准备区间取消继承、链接、恢复/读回继承；共享 inode 不换 project、不重复 charge，新可写文件必须继承新 project。
- 留下一个已知小 project，文件、目录、receipt 与 quota 同步后切断**自己的 L1**；原盘冷启动必须读回相同 usage/limits/project/继承标记，删除已知文件后核对三个记录全清零。
- 普通 daemon、原 warden、原 guest 不改；另外验证真实 VM FD、guest UID、旧键410、冷启动新代执行/销毁。这些 KVM 检查不代表普通驱动已执行 quota 协议。

此夹具是受信任操作员代码，不抵御已经控制 L1 root 的攻击者。去掉 CAP_SYS_RESOURCE 只解决本次硬限制绕过，不撤销 root 的所有管理权限，也不是完整宿主防护或生产 capability allowlist。空 quota record 不等于物理介质擦除。

## 实测记录

本轮[原始前置报告](validation/kvm-quota-v2.json)通过，N=1，共2次实际L1开机；所有 quota syscall 在 L1 内执行：

| 固定检查 | 实际结果 |
|---|---|
| root + CAP_SYS_RESOURCE，8MiB block hard | 9MiB fallocate成功，quota space为9,441,280字节，**确实越界**（含目录块） |
| root，无该能力的固定worker | 实际EDQUOT，usage为8,388,608字节，未越过8MiB hard；失败的fallocate可部分分配，不承诺失败即零写入 |
| inode hard=16 | 目录占1个，成功创建15个文件后实际EDQUOT |
| PROJINHERIT与共享inode | 跨project链接EXDEV；可信区间链接并reseal后共享inode仍project0且不重复charge，新mutable文件继承新project |
| 原盘冷启动 | quota usage/limits/project/inheritance精确保留；清理后全部三个fixture记录usage/limits/times为0 |
| 普通daemon | 原代持久回收/旧键410、新真实KVM执行销毁；**没有**生产驱动quota集成 |

整个probe做完才建立KVM checkpoint，quota分配并不与guest写盘并发。这里不是多租户隔离、持续压力或生产停止延迟测试。

### 失败前序、构建与回归口径

[首轮原始失败报告](validation/kvm-quota-v1.json)保持 `passed=false`：mkfs不支持初版误用的`-Q`，在任何L1启动前失败，0次开机，清理成功。是fixture参数错误，不是内核quota不支持；没有改写失败或绕过enforcement。改用安装版手册的extended option后运行新报告。

Go源码在 `ca8cfa6995fef3e6360ba6e917082d872d3e1689` 冻结；后续测试头 `7db7b3561f3c6c6c394629a205c1264766296dbf` 仅修改Python格式化选项与回归测试。Linux原生 Go1.27.3 / CGO0 / trimpath / buildvcs=false 的fixture `6c2f78e07b6836b1227cc0d8ce6c08c0cb3361ba31a1827115231cfbfca2c7e5` 与独立Mac→Linux构建逐字节一致。

普通daemon重新原生构建的SHA仍为 `b8d2e5b9b5b312841c7287871ee073017d46044592b447736fdf6d39f139a8af`，与[上轮完整新运行时](STATE_IO.md)相同；production Go/warden/guest没有变化，不冒称新生产功能或重跑全部上一轮矩阵。本轮另跑新fixture的默认[健康掉电3检查点](validation/kvm-quota-default-power-v2.json)、[EIO/held-fsync4场景](validation/kvm-quota-default-state-io-v2.json)，检验共同node/builder改动没有破坏原profile。

最终runner退出0：[Linux full race×3](validation/project-quota-native-race-v2.txt)/vet、[fixture race×10](validation/project-quota-fixture-native-race-v2.txt)/vet、root Python39项通过；Darwin race×3/vet、Python39项（4项平台skip）通过。[原样阶段转录](validation/project-quota-pipeline-transcript-v2.txt)与[精确provenance及所有文件SHA](validation/project-quota-provenance-v2.json)可核对，没有公开原始私有console/receipt/盘或ELF。

[独立只读清理复核](validation/project-quota-independent-cleanup-v2.txt)覆盖失败前序及三轮成功夹具：4个scope、实际2/4/5共11个L1执行代际、专属root/control/cgroup全部不存在；首轮失败在创建执行代际前发生，不虚增开机数。额外的quota记录清零证明来自第二次L1开机内核读回，不能在已删除的文件盘上伪造独立读回。

测试源码 [push CI](https://github.com/123123213weqw/Xandbox/actions/runs/39865136998) / [PR CI](https://github.com/123123213weqw/Xandbox/actions/runs/39865156844) 共10个实际job和全部步骤completed/success，attempt1；最终文档头另验，不将这个SHA的CI当成后续提交CI。

## 协议检查清单（部分已实现，完整验收未完成）

### 1. 不可变策略与启动前置条件

操作员显式绑定 runtime 所在 mount、受管 projectID 范围、每代 block/inode 硬上限与节点准备预算。绑定进已有 backend identity，旧 state 不可直接加/删/改策略；缺省不能被解释为已有限额。非受支持 ext4/未启用 enforcement/错误 mount、未知 quota 记录、能力可绕过或 quota I/O 错误时 fail closed，不能回退宿主执行或忽略限制。

生产 daemon 的所有线程、准备子进程、jailer 都必须不可重新获得 CAP_SYS_RESOURCE；要核对至少 effective/permitted/bounding，不能只在某个 Go 线程上清 effective bit。由明确的 service 启动策略提供 capability boundary，不在服务内改共享宿主全局设置；本次固定 worker 重执行不是生产 launcher 的替代品。允许的其他管理能力需要逐项审计，tenant 不能接触 quota syscall/owner/runtime。

### 2. 持久所有权先于限额和文件创建

```text
预留容量与唯一 generation
  → 持久化专属 projectID / ownership（QUOTA_PENDING）
  → 核对该 ID 为已知归属且初始为空
  → 设置限额并读回
  → 创建并标记所有每代可写目录，设置 PROJINHERIT
  → 受限进程准备复制/分配资源
  → 封闭共享链接准备区间，读回 project/inheritance
  → 后续普通 warden / VMM 出生与健康闸门
  → READY
```

当前以owner v3/v4扩展ownership/registry，而不是在文件创建后随机挑一个ID；完整并发与每个崩溃窗口仍需实际验证。allocator 必须有 durable reservation、并发互斥和重启一致性；外部未知非空 project 不可当作空闲 ID。projectID 耗尽应保留背压/容量，而不是绕回重用。准备失败也必须能从精确 owner/ref 恢复清理。

### 3. 共享模板与每代文件分开记账

共享只读 inode 归 catalog / pin 管理，不把同一 inode 虚构成每 clone 各自占用一次；每代 workspace、复制的 ELF/镜像、日志和未来可写文件归其 project。原型验证的是固定 hardlink 与新建文件的内核行为，不是完整 catalog 协议。

若采用临时清 PROJINHERIT 的方案，仅可发生在私有、尚无 warden/VMM/tenant writer 的准备区间。取消继承并不移除目录 projectID。只允许链接固定、已验证、不可写的共享 inode；任何失败都不得 fork 或 READY，必须走恢复清理。恢复继承后核对所有 mutable 子目录/文件，覆盖 snapshot/cold 全路径。还需验证高并发 Prepare、各 fsync/复制/链接/封存窗口崩溃及活 pin 退役。

### 4. 退出、清理与释放 ID

撤权/物理 Stop、持久 STOPPED、目录清理、quota 使用量归零与限额清零是不同阶段。只有准确执行域已空、调用/打开 FD drained、全部已知资源清理、quota usage=0/limits=0 且同步确认后，才删除该代 owner、允许 ID 重用与归还容量。不能先丢 ownership 再清 quota；不能因 usage 暂时0就删除活 pin；任何错误保留 ownership 和配额，不假认 DESTROYED。

重启必须识别 quota 配置成功但后续准备未完成、文件删除但 quota 清零未确认、owner 删除未确认等窗口。非空未知 ID、限额漂移、mount 改变需要隔离/操作员处理，不能扫描后批量清理共享 quota。还需实际 quota I/O EIO/EROFS/held-fsync 与 daemon/warden 故障组合验收。

### 5. quota 不是全部节点预算

project quota 不提供嵌套层级总量限制；受管 project 总量、catalog、ledger、journal/其他文件系统元数据、节点 free-space reserve、准备并发和 inode 余量要另外计入节点 admission。块用量不等于完整物理介质写入/计费；现有 [I/O 请求桶与 cgroup 预算](IO.md)、缓存/writeback attribution、IOPS、空间 quota 是不同约束。仍需真实持续压力、容量耗尽、唯一归属、延迟分布和独立操作员验收，不能用本轮一个小文件实验替代。
