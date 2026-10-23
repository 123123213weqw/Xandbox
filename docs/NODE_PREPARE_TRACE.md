# 准备许可的固定指令入口校准（TEST ONLY）

**本页仅记录两个真实并发创建的跟踪校准，不是排队取消、blocked-copy 下回收隔离、满载或生产验收。** 冻结源码 `1e7650af7ea031b13ef370ccaa9b8915156d94db`；普通 daemon/admin/warden/builder 与已验收 2e 的四个 ELF 字节完全一致，fixture 变为 `9297f982…`。来源及实际结果以[校准报告](validation/kvm-node-prepare-admission-v3.json)和[来源清单](validation/node-prepare-provenance-v3.json)为准，不重标旧 DEFAULT/quota240 测量。

## 为什么先校准，而不是从 503 或目录缺失推断

frontend 在真实 backend staging 之前保留 generation。排队中的 Creating 可以尚无 backend owner、project 或 jail；503 只证明 frontend 容量用尽。Ready 也不是准备许可释放的精确时刻。因此需要直接观察相同生产程序执行到实际 gate 的位置，再开展取消与独立清理实验。

本次保留 `--node-snapshot` 的原 schema3 策略与资源规格，只把最初两个 guest 改为依据第一个实际 selected-token 事件再发起第二个的独立并发创建。两者均经过普通 API、真实 snapshot/KVM、UID/namespace/boot/干净 workspace 检查，各触碰 8MiB 内存。没有修改准备超时、HTTP 预算、生产源码、编译选项或 syscall 行为。

## 固定而非通用的跟踪器

- 只允许 PID1 管理的独占 L1，固定内核 `6.8.0-136-generic`。不在共享 L0 加载模块、挂载 tracefs、修改 tracing 或进程内存。
- 注册前核对整个普通 daemon ELF 的 SHA256 `3ea1e247d0d32ede5ac0f33fb1284bbeb367f9717c49f06a08a7733d22af2af2`、amd64 ET_EXEC、符号范围、可执行 segment 的文件偏移及每个指令字节。不接受租户路径、PID、任意 symbol/offset 或环境变量注入。
- 9 个固定 **instruction-entry** uprobes，覆盖 acquire 入口、select 返回、context 检查后成功、node 检查后成功、正常 release 的前后边界，以及校准中不应出现的取消/拒绝路径。即使探针位于 CALL 后的指令，也不是 uretprobe；不改写返回地址、不读取用户栈、上下文对象、tenant buffer 或 Go runtime 内存。
- 实际 objdump 显示正常释放被编译器内联到 `(*driver).Prepare.deferwrap1`，不能盲目跟踪 out-of-line `prepareGate.release`。前边界取 CX 中的 gate，其他点取 AX；用 R14 的当前 goroutine 指针关联跨 OS 线程迁移，不把 TID 当成 goroutine ID。
- 目标必须保持同一 PID incarnation、executable inode、实际 `control` cgroup；所有事件 TID 再检查属于该活 daemon。固定 PID 过滤和 event-fork 追踪后续线程；无法核验、缺事件或未知路径均失败。
- 独占 tracefs instance，每 CPU 64KiB、8 CPU，单次读取最多 1MiB/64 events。8 份 overrun/commit-overrun/dropped 计数必须全零，9 份 kernel uprobe hit count 必须与实际 trace 每点事件数逐一相等。
- 正常及失败路径均关闭 instance、逐条注销自己注册的固定 probe、核验 registry 空、移除 instance 并卸载自己挂载的 tracefs。不清空或接管未知 registry。

格式、偏移计算和 entry probe 机制参照 [Linux 6.8 uprobes](https://www.kernel.org/doc/html/v6.8/trace/uprobetracer.html)、[ftrace PID/clock/loss 语义](https://www.kernel.org/doc/html/v6.8/trace/ftrace.html)；O_TRUNC 会清除 probe registry，所以固定命令使用 append，参见 [内核实现](https://github.com/torvalds/linux/blob/v6.8/kernel/trace/trace_uprobe.c)。Go register 语义结合本机实际 go1.27.3 工具链 ABI 文档和冻结 ELF 反汇编核对，而不是假定 ABI 永久稳定；[Go ABIInternal](https://github.com/golang/go/blob/master/src/cmd/compile/abi-internal.md)说明 amd64 R14 的当前 goroutine 约定。

## 有限通过条件与不能推出的结论

只接受两个不同 goroutine、同一个 gate 的完整 12 事件链；第二次实际入口必须出现在前一次已选中 token、尚未到 release 前边界的区间内。随后两次成功的 node 检查和 release 前后链完整，不允许重叠的已观察许可区间。正常 release 前探针位于 channel receive **之前**：下一个 acquire 可以早于前一个 release 后探针，不能据此报假重叠或宣称精确 channel 线性化时刻。

这证明实际入口/分支/释放观察点可用于下一阶段；**没有证明 waiter 已被 scheduler park、取消释放 token、Stop/Cleanup 在另一代 copy held 时完成、workspace copy 全阶段无重叠或公平调度**。探针会引入开销，时间戳不是生产延迟 SLO。`prepare_permit_hardware_trace_claim` 及新增取消/清理、精确线性化/SLO claim 仍为 false。原始寄存器/TID trace 只留在 L1 root0600 私有文件，不导出或作为 tenant telemetry。公共报告保留完整 12 条 point + goroutine_index 转换；index 只是本窗口首次出现顺序 1/2，没有原始指针、线程/租户身份或时间戳，Python 独立复核同一状态机。

## 回归与前序失败

本次改变 fixture 后，已重新执行并通过 schema3 space/cold 及 7 个相关旧 fixture scope（共 19 个外层代际），以及原生 full race×3/vet、fixture race×10/vet、root Python78、CGO-free 实际 kernel/exec filter×3、独立 cross/native 5 个 ELF、实际冻结 1e765 的 Darwin full race×3/vet。[独立只读审计](validation/node-prepare-independent-cleanup-v3.txt)按精确 owned receipt 确认 19 个通过代际及前序 1 个失败代际的所有 root/control/cgroup 与 runner 均已不存在；共 20 个执行代际，但不是 20 个 passing。不从删盘推断 quota 已清零。

首个 `9e5a25e…` revision 在原生 fixture unit gate **失败**：负例仍查找旧 `ax=` 字段，没有真正改坏已重命名为 `value=` 的样本。修复仅改 `_test.go` 的负例字符串，并新增“负例确实变更输入”的断言；没有放宽 parser、预算或通过条件。此前 full race/vet 已过，但 fixture gate 后停止，未构建 ELF、未启动 QEMU/L1；保留退出 1 与原始失败日志，不包装成硬件故障或删去前序失败。

第二个 `f7ea4f6…` revision 通过原生单测及构建，真实硬件校准却返回失败（没有完整满足 contended-entry 条件），在首次 checkpoint 之前停止，共 **1 个失败的外层代际**。原始 false 报告和独立清理审计保留，不计入后续通过样本。原始寄存器 trace 位于随后按正常清理删除的自有 L1 磁盘，未导出，因此不声称能事后重建具体失败顺序。源码审查发现 simultaneous HTTP barrier 不能保证第二次 entry 晚于第一次实际取得 token；最终 producer 改为先读到实际 selected-token 再派发第二个请求，原验收条件、超时和预算不变，并新增公开的去身份转换链。这里的调度顺序问题是设计审查结论，不包装为已由前序 trace 证实的唯一根因。

离线汇总生成脚本另修正了 profile/audit 标题的机械重命名错误；早先 Darwin 运行缺来源/版本 header，未拿来冒充完整可发布证据，而是按真实 frozen HEAD 检查、实际 toolchain header 重跑 race×3/vet 并确认退出 0。原始失败 checker/log SHA 及修正范围在来源清单中保留；不改实机源码/输入/配额/namespace/超时或通过条件，不重新采样硬件。

**下一步仍是**相同生产 ELF 的真实排队取消、持有 workspace WRITE 时独立 Stop/Cleanup 与后续许可恢复。更广的完整物理内存/祖先/affinity、外部日志上界、可靠 metadata/catalog 锁、archive/rotation、部署/backup/upgrade/rollback、长期 open-loop/fairness/SLO 和完整 M1–M4 依然未验收；Goal 不因此完成。
