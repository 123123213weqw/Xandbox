# TEST ONLY：配额 filesystem commit 故障夹具

以下是新增夹具的设计契约，**不是实测通过报告或生产就绪声明**。生产 `sandboxd` 不新增故障开关、BPF、租户命令或设备控制接口。

| 固定 profile | 普通 daemon 的边界 | 检查点 |
| --- | --- | --- |
| `--quota-commit-eio` | reserve 的首个 `syncfs` | 先验证 durable attempted owner、实际 limits、已返回的 Q_SYNC；仅自己的 L1 mapper 切 dm-error，再 CONTINUE 真 syscall；固定 eBPF 观察精确 TGID/TID 的首个 syncfs 返回必须是 `-EIO`；Create500、无假 READY/STOP/DESTROY、owner 保留、admission503 |
| `--quota-release-preclear-hang` | reserve 后第二个 `syncfs`，clear 前 | 先真实 KVM guest UID/exec；DELETE 前存 receipt；namespace/cgroup 已移除，已知限额仍在；CONTINUE 后真实 filesystem D（不是 seccomp 等待），RECLAIMING/StoppedAt、无 DestroyedAt、容量不返还 |
| `--quota-release-postclear-hang` | 第三个 `syncfs`，clear 后 | 与上面相同，但独立 quota readback 必须已全零；不能用 quota 零值代替 owner/capacity 的持久释放 |

每次 CLI 独占一个新 2GiB L1 disk，检查点后仅 power-cut 自有 L1，第二次冷启动复用 disk 而非执行 generation。原 `--quota-barrier-hang` 首个 syncfs 挂起回归保留。没有任意 ordinal、PID、设备、errno、BPF 程序或 tenant 参数。

- 观察层额外 seccomp/NNP 只定位入口，成功路径全部 CONTINUE；不得把入口 errno 注入说成真实存储错误。
- EIO 的 raw sys_exit BPF 只在带固定 marker 的 L1 PID1 安装，精确 owned daemon 身份复核后生效；仅记录首个返回码，FD 生命周期结束即卸载，不 pin、不在 L0 安装。纯指令解释器测试不能替代真实 L1 verifier/load 和内核返回证据。
- 预创建 project-zero 文件的固定 4MiB dirty write 保证有 filesystem writeback 工作；这是测试负载，不是 per-project flush 或物理 L0 磁盘故障。
- receipt 的 fsync 在 reserve SET 或 release DELETE **之前**。选中边界以后不做 observer fsync；挂起后不读 `/srv`/quota。preclear 入口允许尚未由该 syncfs 排空的已知 quota 用量，不能从 namespace 不在就推断计数已零。
- EIO 后只恢复自有 mapper 的 linear table 以核对 owner，绝不把 aborted ext4 强行 RW remount；必须自有 L1 冷启动重放。
- 冷启动须核对同一 owner bytes、policy、namespace 缺席和 quota；普通未注入 daemon 回收旧 ref、旧 key410，再启动/执行/销毁新真实 KVM guest，最后独立查全部固定 project 零值。release 的新旧 guest boot 必须不同；reserve 检查点未生 guest，不能虚构旧 guest 比较。
- DELETE 可以被接收；本测试禁止的是过早宣称完整销毁或释放容量，不是假定所有 DELETE ACK 都应延迟。
- Linux `syncfs` 的只读文件系统路径不保证返回 EROFS，不能把只读 noop 成功当作 durability 证明。实际挂载 RW 预检、ledger EROFS 和 syscall errno 单测是不同边界。

尚需真实固定版本 native/cross、真实 EIO/两个 release hold 冷启动、原 hold 和 shared notifier 的兼容回归、独立资源审计以及脱敏原始证据；不能以本文件代替这些验收。整体 roadmap 和 PR #19 仍未完成。
