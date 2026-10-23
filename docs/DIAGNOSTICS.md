# 有界进程诊断（新版本待真实 KVM 验收）

本组件是 **best-effort diagnostics，不是逐请求、逐租户可靠审计**。
本次改变了 daemon、operator CLI 及其依赖；旧 `4ee` daemon 的硬件报告
不能证明新版本。完整 DEFAULT / IO / quota / cold / operator / session
回归，以及新诊断写入被挂起的真实 owned-L1 验证，仍待完成；不能据此宣称生产就绪。

## 生产路径

`sandboxd` 默认启用，不提供关闭隐私约束或无界文本输出的配置：

- 应用 `slog` 只映射已知固定消息为事件枚举。所有 attributes、groups、
  未识别消息正文及原始 `error` 值均不进入记录；不记录 tenant、token、
  request ID、argv、执行输出、任意路径或错误字符串。未知消息只产生 `unknown`。
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
仍需新的真实 held-fsync / exit-group / 竞争 controller / cold 验证，
不能把 seccomp syscall hold 当作实际 filesystem D 或物理介质故障。

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
