# ext4 project quota：前置证据与实现中的驱动协议

**开发中，不能按生产能力启用。** 本分支已接入实验性普通驱动quota，并打通cold有限恢复；snapshot、耗尽/故障矩阵、catalog锁和完整新运行时回归仍在验收。以下先区分当前实现与PR18已合并的历史前置证据，再列出未完成协议要求。M2完整磁盘/节点预算仍未完成。

## 为什么不能只设一个 hard limit

Linux6.8 的 `ignore_hardlimit()` 对持有 `CAP_SYS_RESOURCE` 的进程允许绕过硬限制；project quota 不天然约束拥有该能力的 root 准备进程。检查来源是[固定内核 dquot.c](https://github.com/torvalds/linux/blob/v6.8/fs/quota/dquot.c)，不是根据“root 应该不受限制”猜测。仅 Q_GETQUOTA 读回正确，不代表实际写入会受限。

同时，带 PROJINHERIT 的 ext4 目录会拒绝跨 project 的 hardlink（EXDEV），见[固定内核 namei.c](https://github.com/torvalds/linux/blob/v6.8/fs/ext4/namei.c)。当前快照路径以硬链接共享只读 memory/state inode，因此给新 jail 目录加继承标记后直接套用现有链接流程并不成立。不能靠只支持 cold、默默复制大快照，或给已运行 VM 临时取消限制来掩盖这个问题。

## 当前分支的实验性接入（PR19，未完成验收）

- `Config.Quota` 为操作员不可变策略：完整ext4 UUID、独占project范围、block/inode硬上限；mount-ID、实际enforcement与所有controller线程的capability均检查。旧state不可直接加/删/改策略，缺省仍是原有无quota实验规格。
- projectID与既有durable UID slot一一对应，owner v3/v4分别支持cold/snapshot；`quota_attempted`必须持久化后才允许设置限额。未知或未attempt的非空quota记录不能收养；准备失败也保留owner直到准确清理。
- 全部私有jail/root在复制前设置project/继承，快照共享链接仅在可信pre-fork区间进入并reseal，fork前读回。代码包含两条路径，**quota启用的snapshot实际矩阵尚未完成**。
- Root无CAP_SYS_RESOURCE不是全部边界：init user namespace内文件owner可修改project属性，见[固定内核fileattr权限检查](https://github.com/torvalds/linux/blob/v6.8/fs/ioctl.c)。quota模式warden额外继承seccomp，阻止后代quotactl/quotactl_fd、FSSETXATTR及SETFLAGS，保留Firecracker默认filter；READY前检查NNP与过滤器。Go race/cgo不能同步all-thread prctl时严格拒绝，实际kernel/exec继承证明另在CGO0运行，不单线程回退。
- Stop/drain、文件清理、quota清零/Q_SYNC/读回、owner删除/目录fsync与容量归还是不同阶段；quota I/O或用量不归零就不能提前释放UID/project。恢复不把jailer的PID文件当成身份或kill依据。

当前有限实测使用新原生普通daemon `1d66fc40…`、warden `b290a5ed…` 与原始pinned guest：running/stopped/destroyed三检查点、四次L1实际开机的同盘普通恢复、旧key410、新真实KVM执行销毁通过。running/stopped各N=1观察到非fsync PID文件在重启后为空，quota charge与独立命名inode分配同时由189,911,040变为189,906,944字节；192MiB hard、128 inode hard、归属/继承/不可变资产均保持，并在GC后清零。不是百分位、SLO或全部quota故障验收。原始失败前序和新成功材料暂存于私有验收目录，将在完整PR验收后按准确来源/原字节SHA公开，不改写旧失败。

验收不能把live物理用量错误当成不可变policy：初版fixture要求整个quota record完全相等而失败；后来独立核对namespace，定位到pinned jailer的`firecracker.pid`有3字节未同步内容，重启后为空。上游[PID文件写入代码](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/src/jailer/src/env.rs)没有fsync；修正只允许这个固定非权威文件的有界size变化，仍严格检查同inode/owner/mode/link、所有其他文件尺寸、实际块/inode计数和硬限额，没有用保存PID回收或先停止VM来绕过running掉电。

**合并前还必须完成**：quota清零阶段移出catalog全局pin锁并验证并发；quota启用的snapshot/pin/初始化与block/inode耗尽、拒绝/崩溃/存储错误；全部新native默认冷路径/快照/初始化/IO/故障回归、独立清理和最终CI。当前实现与三例cold通过不等于完成这些要求。

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
