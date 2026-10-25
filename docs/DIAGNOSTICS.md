# 有界进程诊断（有限故障窗口通过，完整验收未完成）

本组件是 **best-effort diagnostics，不是逐请求、逐租户可靠审计**。
本次改变了 daemon、operator CLI 及其依赖；旧 `4ee` daemon 的硬件报告
不能证明新版本。历史 `29fe` 版本已有两个固定日志写入挂起窗口及四个共享路径的真实 owned-L1 回归；
新增闭集原因与 producer 计数已完成下述独立的新 ELF 有限回归，不能沿用历史通过结果。
完整 DEFAULT / IO / quota240 / dual-cold / failure / trace / TLS+metadata
重验仍未完成，不能据此宣称生产就绪。

## 生产路径

`sandboxd` 默认启用，不提供关闭隐私约束或无界文本输出的配置：

- 应用 `slog` 只映射已知固定消息为事件枚举。除下述唯一闭集 primitive 外，所有 attributes、groups、
  未识别消息正文及原始 `error` 值均不进入记录；不记录 tenant、token、
  request ID、argv、执行输出、任意路径或错误字符串。未知消息只产生 `unknown`。
- 仅已知 `PrepareFailed` 消息可以携带一个直接的 `xandbox_reason` 整数枚举；
  最多检查四个直接 attributes，重复、越界、非整数、嵌套或超出数量均归为 `other`。
  Handler 不调用任意 `Error/Is/As/Unwrap/LogValue`，也不解析文本猜测 errno。
  原因由 backend 的封闭 policy 类型或最多32层具体 OS wrapper 字段产生；
  未知 wrapper（包括 `fmt` wrapper）保留 `other`，不是完整异常链诊断。
- producer 只进行短互斥区、时间/原子计数和非阻塞入队；不做磁盘 I/O，
  不等待消费者。队列固定 **64** 条；另有至多一条正在写的记录。
- 一个独立 goroutine 写入 `state-dir/diagnostics/events.ring`；每个记录 128 bytes，
  保留最近 **128** 条，加一个 staging slot、两个 128-byte header，
  文件固定 **16,768 logical bytes**；另有一个零长度 `logger.lock`。
  这不是整个 state-dir / filesystem 的物理分配配额，也不包括 runtime 内存或外部日志系统。
- ring 跨重启继续序列号，不创建轮转段或无限增长的日志文件。
  writer 返回写入错误后停止、拒绝新记录、统计丢失，不退回 stderr。
- metrics.sock 上 `xandbox_diagnostics_{enqueued,dropped,written,write_errors}_total`、
  `xandbox_diagnostics_queued` 和 `xandbox_diagnostics_queue_capacity` 只有固定名称。
  计数是本进程内独立原子采样，重启重置，不是事务快照。
  `dropped` 包含拒绝及失败 writer 丢弃的待写记录；`written` 含关闭记录，
  `enqueued` 不含 writer 自己生成的关闭记录，不能直接视为一组守恒账本。
- `xandbox_prepare_failed_total{reason="io"|"quota"|"other"}` 恰有三个固定 label 值。
  它们在入队前计数有效的 `PrepareFailed` producer，包括队列满、writer 已失败、
  Close 后丢弃的观察；不依赖 ring 落盘，不是新请求数、成功 ACK、持久化审计或故障根因证明。
  `io` 只计具体 EIO，`quota` 只计 EDQUOT；EROFS、ENOSPC 和其他闭集原因计入 `other`。
  各项独立采样、进程重启归零，三个计数不构成事务快照。

成功 `Emit` 只表示入队，不表示落盘。每条记录携带此前观察到的 loss watermark；
最新丢失尚未被下一条记录反映、进程突然死亡时，无法恢复完整 loss 计数。
覆盖数量来自序列号与保留容量；不能据此推导未入队、未落盘或所有历史操作数量。

普通应用诊断启动后不再写继承的 stdout/stderr；`net/http` 的原始错误/堆栈输出被丢弃。
初始化之前的应用失败最多输出一行闭集 bootstrap 类别；显式 `-h` 输出固定用法，
离线 `-migrate-ledger` 保持 JSON stdout 且不创建诊断目录。
这些启动/帮助/迁移输出仍可能被操作员的阻塞 pipe 阻塞；不声称取消了 Go runtime
fatal/panic、外部程序、内核或第三方服务的全部输出。

## 文件与恢复边界

私有祖先路径校验、caller-owned 0600 regular single-link 文件、NOFOLLOW/NONBLOCK、
inode 校验和独占 `logger.lock`。只允许 lock 和 ring 两个名字；有界读取最多三个目录项。
现有 lock 缺 ring、异常大小/权限/类型、未知文件、CRC/格式/枚举/序列损坏均拒绝启动；
**不自动清空、重建、删除探针或修复现有日志**。初始化中断可能因此需要人工分析。
原因枚举只追加，旧 ordinal 0..6 不变；当前 reader 能读取旧记录。
旧 binary 不能识别新增 ordinal 时会拒绝现有 ring，不能把回滚等同于透明格式兼容，
也不能删除 ring 来绕过拒绝。安全的升级/回滚流程仍待独立验收。

header 含版本、容量、序列和配置绝对目录路径的 SHA-256 binding（不是明文路径）；
须使用同一绝对路径，改名/别名迁移会拒绝，不属于备份迁移工具。
CRC 是撕裂/损坏检测，不是抗恶意同 UID/root 修改的认证。

写入顺序：在不覆盖当前已提交窗口的 staging slot `WriteAt` → checked file `Sync`
→ 交替 header `WriteAt` → checked file `Sync`。初始化另检查 directory `Sync`。
重启选择最高有效 header，并检查其整个保留窗口；窗口损坏不会静默回退/重置。
前一未发布 data stage 不授权新记录；仅一个 header 损坏可使用另一个有效 header。
这不是无条件抵抗任意介质故障的事务系统，unit 人工写入中间状态不是真实断电测试。

文件 `fsync` 与目录同步是不同操作，可能阻塞；上下文超时不会取消正在进行的
文件系统 syscall。[Linux fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html)

## 退出和只读观察

生命周期 / session / control 的独立清理机会 **先于**诊断 drain。
随后 daemon 给诊断 Close 自己的 **250 ms 等待预算**；这不是磁盘 syscall 截止时间。
超时或错误则退出失败并保留 controller state-lock 的可达引用到进程实际退出，
不在正在写的 goroutine 下方强制关闭 FD，不在 Stop/GC 之前等待日志。
本轮已在下述两个固定窗口验证 held-fsync / 实际 exit-group / 原锁竞争 / cold，
但不能把 seccomp syscall hold 当作实际 filesystem D 或物理介质故障。

```sh
xandbox-node -state-dir /absolute/private/state diagnostics
```

命令只打开独立 read-only ring FD，可在 daemon 运行或停止时观察；不启动 writer、
不创建目录、不取得 controller lock、不调用 tenant API、不修改 authority。
最多三次稳定 header 重读，最多 128 条记录；忙碌/损坏会返回闭集错误，不返回虚构成功。
显式 RPC `-timeout` 和 mutation 字段被拒绝：有界尝试次数不是文件 I/O deadline。
JSON 的 `observed_sequence` 与 `records` 是当前可见视图，不证明可见 header 已获
介质持久化确认，也不证明没有丢失或覆盖。该私有 stdout 输出本身由操作员负责处理。

后续需要独立定义可靠审计的 ACK、故障、容量及不可用策略；不得把本 ring
当作控制面状态、租户计费或安全裁决的权威日志。

## 历史有限实测证据（不覆盖新增原因/计数代码）

冻结源码 `0482ce2`，普通 Linux daemon `29fe145a…`、测试 fixture `9ecc86e3…`。
[源、原始归档、9 个 native/cross ELF 与历史绑定](validation/diagnostics-provenance-v5.json)
明确标注 `production_ready=false` / `goal_complete=false`；十份旧 manifest 保持原字节。
脱敏器实际拒绝了 130 个错误 source、ELF、资源、窗口、计数或隐私变体。

两个真实窗口均使用未修改的普通 daemon，仅在 owned-L1 的测试启动层观察固定
`FSYNC` + `EXIT_GROUP`。目标 ring 同步没有收到 CONTINUE、合成成功或 errno：

- [record-data](validation/kvm-diagnostics-data-v5.json)：记录5写入后、header5发布前，
  挂起第一轮同步；可见/冷启动有效 prefix 均为4。
- [header-publish](validation/kvm-diagnostics-header-v5.json)：第一轮 data Sync 已返回成功，
  写入 header5 后挂起第二轮同步。可见5 **不是**该 header Sync 的持久化 ACK；
  冷启动允许有效4或5，本次实际观察到5，不据此承诺每次都保留5。

每组先有两个独立的真实 KVM guest：一个已接受的 raw writer 和一个 session。
仅把 owned-L1 的 kernel/initrd/workspace **INPUT 文件 mode** 从0444变为0666，
让普通 `Prepare` 的可信路径校验拒绝；未改字节、宿主机原资产、活动 guest 私有副本
或 ledger/owner/control authority。80 次真实 Create500/普通 GC 后，**发 SIGTERM 之前**
独立私有 metrics 观察：enqueued66、written1、queued64、dropped15。
这是当时的进程采样，不表示退出后的最终丢失总数；更不是80条可靠审计记录。
raw guest 继续推进、session route 不变，两者普通停止及完整私有 GC/quota0 均在
日志目标仍挂起时完成。仅恢复 INPUT mode/检查原字节，不修补权威元数据。

| 单次窗口 | DELETE前→执行域空 | DELETE前→私有 GC/quota0 | SIGTERM前→EXIT_GROUP入口 |
|---|---:|---:|---:|
| record-data | 69.440 ms | 170.531 ms | 256.564 ms |
| header-publish | 80.180 ms | 174.081 ms | 254.880 ms |

这是 N1、不同时间起点的观测，不是速度提升、尾延迟或 SLO。
原20s hold、250ms日志等待、30s Prepare、40s HTTP、8GiB/12GiB/CPU8资源未放宽。
实际 EXIT_GROUP(1) 入口处原 ring syscall ID 仍有效，第二个**同一普通 daemon**
确实被原 controller.lock 拒绝，已稳定的 metadata/ring 无变化。
只继续 EXIT_GROUP，实际退出1并 reap 后，在监听 FD 仍打开时检查两个 ID 为 ENOENT。
原盘普通、未加额外 observer 的 cold restart 不重置 ring、不复活旧 key/route，
并完成第三个新 KVM guest 的正常 GC。清理/receipt 可能同步文件系统，
所以不是未同步介质断电试验。

另外四组共享路径也分别完成两次 L1 启动：
[退出锁](validation/kvm-diagnostics-shutdown-v5.json)、
[session ticket](validation/kvm-diagnostics-ticket-v5.json)、
[control pre-file](validation/kvm-diagnostics-pre-v5.json)、
[control post-root](validation/kvm-diagnostics-post-v5.json)。
共6组/12次 L1启动；独立只读复核确认所有对应 root/control/parent/12个执行代际
均不存在，无补充清理。Linux full race×3、fixture race×10、特定基线 race×100、
vet、114项 root Python（零skip）、CGO0 kernel quota×3、7组进程测试、
9个 native/cross 产物一致，见[门禁](validation/diagnostics-native-gates-v5.json)。
mock 包含45次继承输出 pipe 满且不读取的真实进程重启，但它不是隔离/性能证明。

[保留的失败与修正](validation/diagnostics-preserved-failures-v5.json)：
首次真实窗口错误地拿 SIGTERM 前的 session 摘要检查退出后的竞争进程；普通
session.Close 会重写 CLOSED.UpdatedAt。修正是在真正 EXIT_GROUP 入口、正常清理
完成后、竞争进程运行前采样，而非放宽预算或允许竞争写入。
新增单测曾错误地在 live writer 旁调用会回收临时文件的 startup Load；随后改为
只读精确 named file，并实际通过100次 race 重复。旧失败未被改写成通过。

## 新闭集原因与计数的有限回归

冻结源码 `b462946`，普通 daemon `d163a628…`、fixture `98ae70a9…`；
[脱敏摘要与原始归档指纹](validation/diagnostics-cause-v1.json)只包含固定名称、计数、
已检查的摘要和有限观察，不发布原始错误、路径、进程/guest 身份或私有日志。
新 ELF 的 3 个完整函数、132 条规范化指令与源相对行号已比较，9 个固定入口探针重新校准；
随后在新 ELF 上实际通过并发准备及取消的两类 trace，而非仅替换 ELF hash。

本次 12 组实测均通过，独立只读复核未使用补充清理：

- 8 组 nested 共 **16 次 L1 启动**：配额6类负向及普通 cold、未启用 quota 的拒绝、
  真实 kernel SYNCFS 返回 EIO、partial-copy 注入 WRITE EIO 与 live keeper、
  schema3 node、实际准备/取消 trace、两个日志 FSYNC 挂起窗口。
- EIO 测试在故障前打开唯一 metrics 连接，该观测连接在故障后禁止重新连接或查找 socket 路径；
  独立的真实 syscall 返回与进程内 `io=1` 合用，不要求失败文件系统能落盘日志。
  EDQUOT 两类各自首次及同绑定重启后均观察独立进程 `quota=1`。
  启动负向要求 exit1 加精确闭集单行，不能用任意非零退出或诊断子串通过。
- 4 组 DEFAULT/IO × ENOSPC/ledger-only EROFS，共12个故障恢复对：
  restart 前后均探测实际 errno，原 authority inode/mode/bytes 不变、无 live tenant listener；
  只释放同一个 owned 故障后，原 binary/config 正常恢复旧资源并完成新 KVM guest。
  这是受控故障与同输入恢复的**因果推断**，不是已持久化的错误审计或 syscall 归因证书。
- 独立复核确认全部16个 nested 执行代际和12组对应 root/cgroup（nested 另含 control/parent）、
  4个 fault image/mountpoint/loop binding 均不存在。

Linux full race×3、fixture race×10、5项特定回归 race×100、vet、116项 root Python
（零 skip）、kernel quota×3、7组进程测试、9个 native/cross 逐字节一致；Darwin full
race×3/vet 亦通过。源码提交的 push/PR 两组 CI 各5 jobs 全绿。
首次 Linux 单测的两处测试期望错误及后续脚本把 v10 路径误改 v20 的失败均保留指纹；
后者在错误资产检查处、任何 KVM 阶段前拒绝，随后只恢复原 SHA 校验的 v10 路径，
未修改源码、资源或时间预算。摘要发布器实际拒绝了72个 source/ELF/状态/范围变体。

后续已另完成同源新 ELF 的[DEFAULT/IO/quota240命名兼容矩阵](D163_RUNTIME.md)：
18个新scope与前批同源7个scope分别保留来源，共25个scope/43个外层执行代际，
不将不同来源的原始报告重标为一次新执行。

后续另完成[十个命名边界复验](D163_BOUNDARIES.md)，含 owner/inflight、operator/shutdown/
session ticket、control pre/post 及 TLS/policy 三组，保留 7+3 原始来源。
**剩余门禁**：以上具名场景通过不是全部 failure/持久化窗口或完整生产验收。
可靠租户审计、全局磁盘与内存压力、operator/systemd/恢复、PKI、长时 open-loop/fairness、
备份升级回滚等仍属原 Goal 的未完成范围。
