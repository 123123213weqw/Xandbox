# 独占虚拟宿主的掉电恢复验收

**实验工具，不是生产部署器；整体仍未生产就绪。** 此专项用有界、无业务网络的独占 L1 Linux/KVM 虚拟机承载普通 Xandbox daemon，再运行真实 L2 Firecracker 沙箱。强制终止的是自己的 L1 执行域，绝不重启共享 L0、卸载其 KVM 模块或修改共享挂载/路由。

## 三层边界

- **L0**：现有 Linux/KVM 测试机。QEMU 固定为 KVM 加速，无 TCG 回退；QMP 核对 enabled/present/running。QEMU 使用未分配的保留 UID，仅保留访问 `/dev/kvm` 的附加组，无 NIC，并出生即进入独占 cgroup/newnet；沿用原有 root warden 的 Ref-bound 短租约与不可延长硬期限。
- **L1**：本次服务宿主，2GiB RAM、4 vCPU、2GiB 独占 raw ext4 状态盘。每次冷启动使用新的 L0 cgroup/租约代际，**只复用同一私有磁盘**。L1 PID1 还必须通过 `/dev/kvm` API12 探针；不是容器或宿主命令模拟。
- **L2**：普通 daemon 创建的 jailed Firecracker，512MiB/2 vCPU/128MiB 工作盘，guest UID65534，无业务 NIC。检查实际归属 cgroup 内的 KVM VM FD，并通过普通 API 执行固定命令。

嵌套 KVM 的 L0/L1/L2 定义见 [Linux KVM 文档](https://www.kernel.org/doc/html/latest/virt/kvm/x86/running-nested-guests.html)。外层 raw 盘显式使用 `cache=none,aio=native,werror=report,rerror=report`；这不等于底层 SSD 断电或介质持久性保证，参见 [QEMU 参数语义](https://www.qemu.org/docs/master/system/invocation.html)。

L1 测试镜像使用固定 SHA 的 Alpine、现有 Ubuntu 6.8 内核及四个固定 SHA 模块；模块只在 L1 启动后加载，L0 不执行 insmod/modprobe。普通 jailer 保持原样：Linux 6.8 的特殊 initramfs rootfs 不能直接 pivot_root，必须先在 L1 以 switch_root 进入有界 256MiB 普通 tmpfs，再启动服务。依据是 [Linux v6.8 的 rootfs 说明](https://raw.githubusercontent.com/torvalds/linux/v6.8/Documentation/filesystems/ramfs-rootfs-initramfs.rst) 与 [固定 v1.17.0 jailer 实现](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/src/jailer/src/chroot.rs)，不能将新版 nullfs 文档套到旧内核。

## 固定检查点

每个检查点先创建真实 L2、核对 UID/VM FD/boot identity，启动有子进程的忙碌任务，然后执行：

| 检查点 | 掉电前要求 |
|---|---|
| running | guest 任务仍为 RUNNING |
| stopped | 普通 Stop 已确认持久 STOPPED 与 StoppedAt |
| destroyed | 普通 Destroy 已确认持久 DESTROYED，旧 jail/cgroup/owner 已消失 |

L1 将检查点 receipt 写入同一磁盘并完成文件、rename、父目录 fsync；L0 再确认 QMP 仍运行，写**准确归属**的 cgroup.kill，等待 populated=0。没有 guest shutdown、QMP quit、保存内存或快照恢复。重新启动同一磁盘后：

1. L1 boot identity 必须变化，L0 boot identity 不得变化。
2. 普通、未打补丁 daemon 用原绑定配置/state 启动并回收旧代。
3. 旧代持久 DESTROYED，旧 jail/cgroup/owner 不存在，旧创建 key 必须返回410。
4. 新 key 获得新代真实 KVM，guest UID仍为65534、guest boot identity 改变，实际执行成功，最后正常销毁并回收。

UART 控制只有 probe、固定三类 checkpoint、recover，没有任意宿主 argv/RPC。令牌、Ref、boot identity、原始控制器日志与磁盘均留在私有夹具目录；公开报告只输出布尔检查、摘要、规格和计时。默认 Go build 不包含该命令，必须显式使用 `xandbox_host_fixture` tag。

## 计时不能混淆

[最终原始报告](validation/kvm-nested-host-v8.json) 与 [完整来源/文件SHA/失败前序](validation/nested-host-provenance-v8.json) 已通过3个检查点、4次真实L1 KVM开机及新L2执行/销毁，parent exit0，所有外层资源另按私有receipt独立复核不存在。

| 检查点（各N=1） | 切断L1到L0执行域空 | 新L1内daemon启动到旧代回收/旧键拒绝 |
|---|---:|---:|
| running | 88.983ms | 900.717ms |
| stopped | 83.398ms | 899.309ms |
| destroyed | 68.224ms | 924.498ms |

- `power_cut_to_l0_cgroup_empty_ms`：外层强制终止 L1 到其执行域为空；**不是**生产 Stop API 的响应延迟。
- `daemon_start_to_old_reclaimed_ms`：新 L1 内启动普通 daemon 到旧代持久回收、旧 key 拒绝；不含 L1 开机和后续新 VM 创建时间。
- 各检查点只有有限样本，不合成 P95/P99、最坏上界、切换加速比或生产 SLO。

### 精确来源与失败前序

最终harness源码 `10e1d450aecb4ad3ded3a87017110a654c3e5c1a`；test-only Go fixture原始源码 `94b42a6fd5817d1f7ecdbf47eb77817ee94dc308`，此后该Go源码未改变。原生Linux Go1.27.3 / CGO0 / trimpath / buildvcs=false的fixture SHA256 `9ce849081e65a60115055c0dc231049b4b5698edc18d6dc6c67014a366cdb06f`，与独立Mac→Linux重编译完全一致。tagged native race×10/vet、root Python36项通过；[默认native race×3](validation/nested-default-native-race-v8.txt)/vet及[五套进程烟测](validation/nested-default-process-smoke-v8.txt)通过，进程烟测为mock，不作为嵌套KVM或性能证据。

源码的 [push CI](https://github.com/123123213weqw/Xandbox/actions/runs/39856147434) / [PR CI](https://github.com/123123213weqw/Xandbox/actions/runs/39856158740) 各5个实际job及所有步骤均completed/success（attempt1）；后续文档头CI另外核对，不拿旧CI充当它。

实际daemon仍是[上轮原生运行时](IO.md) `9670b188…`（原始源码 `3fed5766b0d8ae0513e5ad19b0ecaf748ab5ba88`），warden仍为 `b810afc5…`，原始pinned guest镜像/agent不变。生产Go代码、普通commands、go.mod/go.sum与合并主分支相同；没有将新fixture或make smoke产物冒称新生产daemon/guest部署。

失败没有改写成成功：[v1](validation/kvm-nested-host-v1.json)/[v2](validation/kvm-nested-host-v2.json)在L2创建时被原样jailer拒绝，后修正L1特殊rootfs。[v3](validation/kvm-nested-host-v3.json)/[v5](validation/kvm-nested-host-v5.json)/[v6](validation/kvm-nested-host-v6.json)到达首次running检查点与强制终止，但复用外层执行域的下一次启动失败；v5无cgroup OOM/pids耗尽，精确guardian退出原因未查明，不能声称修复了生产warden缺陷。最终改为每次冷启动新代际，三个恢复场景才通过。[v7](validation/kvm-nested-host-v7.json)则在第一台VM启动前遇到私有receipt独占创建错误，改为经过回归测试的fsync+atomic replace。v4是私有wrapper的输入名错误，无VM/cgroup/报告，两个空目录逐一复核后删除；没有编造原始报告。

## 复现前提与运行

使用预先具备嵌套 Intel KVM、cgroup v2 委派、匹配测试资产的专用 Linux 测试环境。固定系统 QEMU/内核/模块摘要见 [资产清单](../scripts/nested_host_assets.json)；清单只是本轮测试环境钉扎，不声称当前上游最新、所有系统依赖逐字节可复现或全部 CVE 已排除。资产不匹配必须失败，不自动安装软件、换内核、重载模块或启用 TCG。

```sh
GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 go build -tags=xandbox_host_fixture \
  -trimpath -buildvcs=false -o /private/test/host-fixture ./cmd/xandbox-host-fixture
GOTOOLCHAIN=go1.27.3 go test -race -tags=xandbox_host_fixture ./cmd/xandbox-host-fixture
python3 -m unittest discover -s scripts -p 'test_*.py'
```

随后以 Linux root 运行 `scripts/kvm_nested_host.py --help` 列出的明确资产参数；必须使用新 report/log-dir，不能覆盖失败前序。需为独占2GiB盘预留足够空间。脚本先检查输入，再分配自己的资源；构造 ext4 使用 `mkfs.ext4 -d`，不在 L0 挂载它。私有 receipt 记录所有外层执行代际，finally 严格终止并回收自己的 cgroup、raw盘及控制目录；清理失败不能假称通过。

## 尚未覆盖

物理 L0 掉电/SSD flush或擦除、所有未完成 fsync/rename/Prepare 窗口、快照 catalog/shared-pin 跨宿主恢复、全 state EIO/挂死I/O、双监督失效、节点总配额、开放到达持续负载、独立操作员复现和生产 SLO 均不由本专项完成。有限 L1 掉电恢复不能勾选完整 M2 或整个 Goal。
