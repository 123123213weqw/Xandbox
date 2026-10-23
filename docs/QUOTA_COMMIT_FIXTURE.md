# TEST ONLY：配额 filesystem commit 故障夹具

以下先说明夹具的设计契约；2026-10-23 已完成下述有限实测，见[原始证据与精确SHA](validation/quota-commit-provenance-v2.json)，**不是生产就绪声明**。生产 `sandboxd` 不新增故障开关、BPF、租户命令或设备控制接口。

| 固定 profile | 普通 daemon 的边界 | 检查点 |
| --- | --- | --- |
| `--quota-commit-eio` | reserve 的首个 `syncfs` | 先验证 durable attempted owner、实际 limits、已返回的 Q_SYNC；仅自己的 L1 mapper 切 dm-error，再 CONTINUE 真 syscall；固定 eBPF 观察精确 TGID/TID 的首个 syncfs 返回必须是 `-EIO`；Create500、无假 READY/STOP/DESTROY、admission503；故障期间不读 aborted FS，冷启动后核对 exact owner 保留 |
| `--quota-release-preclear-hang` | reserve 后第二个 `syncfs`，clear 前 | 先真实 KVM guest UID/exec；DELETE 前存 receipt；namespace/cgroup 已移除，已知限额仍在；CONTINUE 后真实 filesystem D（不是 seccomp 等待），RECLAIMING/StoppedAt、无 DestroyedAt、容量不返还 |
| `--quota-release-postclear-hang` | 第三个 `syncfs`，clear 后 | 与上面相同，但独立 quota readback 必须已全零；不能用 quota 零值代替 owner/capacity 的持久释放 |

每次 CLI 独占一个新 2GiB L1 disk，检查点后仅 power-cut 自有 L1，第二次冷启动复用 disk 而非执行 generation。原 `--quota-barrier-hang` 首个 syncfs 挂起回归保留。没有任意 ordinal、PID、设备、errno、BPF 程序或 tenant 参数。

- 观察层额外 seccomp/NNP 只定位入口，成功路径全部 CONTINUE；不得把入口 errno 注入说成真实存储错误。
- EIO 的 raw sys_exit BPF 只在带固定 marker 的 L1 PID1 安装，精确 owned daemon 身份复核后生效；仅记录首个返回码，FD 生命周期结束即卸载，不 pin、不在 L0 安装。纯指令解释器测试不能替代真实 L1 verifier/load 和内核返回证据。
- 预创建 project-zero 文件的固定 4MiB dirty write 保证有 filesystem writeback 工作；这是测试负载，不是 per-project flush 或物理 L0 磁盘故障。
- receipt 的 fsync 在 reserve SET 或 release DELETE **之前**。选中边界以后不做 observer fsync；挂起后不读 `/srv`/quota。preclear 入口允许尚未由该 syncfs 排空的已知 quota 用量，不能从 namespace 不在就推断计数已零。
- EIO 后自有 mapper 保持 error，故障期间不再读 `/srv` 或 observer quota。即使恢复 linear table，aborted ext4 的缓存 metadata 仍可能读取失败，不能据此判断 durable owner 丢失；绝不强行 RW remount，必须自有 L1 冷启动重放后核对 exact owner。
- 冷启动须核对同一 owner bytes、policy、namespace 缺席和 quota；普通未注入 daemon 回收旧 ref、旧 key410，再启动/执行/销毁新真实 KVM guest，最后独立查全部固定 project 零值。release 的新旧 guest boot 必须不同；reserve 检查点未生 guest，不能虚构旧 guest 比较。
- DELETE 可以被接收；本测试禁止的是过早宣称完整销毁或释放容量，不是假定所有 DELETE ACK 都应延迟。
- Linux `syncfs` 的只读文件系统路径不保证返回 EROFS，不能把只读 noop 成功当作 durability 证明。实际挂载 RW 预检、ledger EROFS 和 syscall errno 单测是不同边界。

## 2026-10-23 有限实测

普通 daemon 仍为 `522da68e…`，production Go与已验证a57完全相同；新TEST fixture源为 `f89492c…`。Go1.27.3 Linux原生五种artifact与独立cross字节一致。三种新profile各N=1/2次L1开机均通过：[真实EIO](validation/kvm-quota-commit-eio-v2.json)、[preclear hold](validation/kvm-quota-commit-preclear-v2.json)、[postclear hold](validation/kvm-quota-commit-postclear-v2.json)。真实EIO由实际L1加载的固定BPF捕获精确 `-EIO`；first-return latch的Seen1不是“整个daemon只调用一次syncfs”的证明。

实际cold readback：reserve EIO和原reserve hold的quota记录均空；preclear和postclear均恢复为精确已知hard limits、usage0。尤其postclear在故障前已独立读回全零，但**未返回的syncfs后掉电，清零不保证持久化**。同一owner bytes始终在冷恢复前核对；普通daemon完成旧ref销毁/旧key410、新实际guest执行销毁与全部project清零，再释放ownership。并非已确认DESTROYED后限额复活的证据。release新旧guest boot不同；reserve不虚构旧guest。

原reserve hold、六固定errno+cold3、postclear owner/pin窗口、真正L1-built snapshot shared2/cold3、quota整state IO4、默认nil-quota IO4亦通过。9个新scope共28次L1开机；另保留失败v1的1次，共10scope/29执行代际经独立只读审计全部不存在。v1在aborted FS上活读owner失败，原始passed=false保留，不能推断durable owner丢失或追认通过。另有private runner误写不存在的v20输入，SHA preflight在任何VM/源码解包前拒绝；修正的独立v2r1仅使用原始pinned v10，未生成替代guest。

Native full race×3/vet、fixture race×10/vet、root Python52、CGO0实际kernel/exec filter×3、Darwin race×3/vet通过。503只证明新请求在frontend admission被拒绝，不是另行直接尝试backend UID/project分配；owner与释放顺序单独核对。

仍需quota完整切换/并发、重复clear/listener-loss/partial-copy、snapshot shared-pin组合、owner unlink/dirfsync与其余catalog持久窗口、节点总预算及独立操作员验收。整体roadmap和PR #19仍未完成/Draft，不因这个子门槛勾选完整M2。
