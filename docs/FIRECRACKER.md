# 实验性 sandboxd Firecracker 后端

**生产验收未完成。** 本后端把真实 VM 接入现有鉴权、租户配额、代际栅栏与持久生命周期；不是快照池、集群调度器或生产就绪认证。默认运行仍需显式选择后端，macOS 不提供真实执行回退。

## 归属和停止协议

1. Manager 先持久化 `CREATING` 账本，再调用 Driver。
2. Driver 在独立的 root 私有目录持久化后端配置绑定和每代 `{Ref, UID}` 归属；fsync 成功前不创建该代 cgroup、磁盘或进程。写后 fsync 出错也保留 UID 预留，等待安全回收。
3. 配置并读回 host cgroup 限额；私有复制校验过的 kernel、initrd 和空白 ext4 模板。没有共享可写硬链接。
4. 用 `clone3(CLONE_INTO_CGROUP)` 启动可信 Go warden，**出生即在该代的资源组内**，同时进入新的 host 网络 namespace。clone3 不支持时失败，不以“先 fork 后移动 PID”降级。
5. warden 启动 jailer。jailer 使用相同已存在的 cgroup、chroot、专用 UID/GID 和默认 seccomp；不配置 virtio-net。特权控制 socket 不放到 guest 工作盘。
6. Firecracker API 配置完成并收到 Ref/boot ID 正确的 guest READY 后，Manager 还要持久化 READY 才返回 201。
7. Stop 先拒绝新任务、取消在途调用，再 `cgroup.kill`、等待 kernel `populated 0`，并回收控制器的直接子进程；完成后才持久化 STOPPED。恢复不依赖旧 PID，也不按 UID 批量杀进程。
8. Cleanup 仅在停止证明之后删除该代 jail/cgroup/归属文件；确认归属文件删除已持久化才释放 UID，最后 Manager 持久化 DESTROYED 才返还实例配额。

可信 warden 只接收 root 控制器传入的固定启动策略和两个继承 FD，没有租户 RPC。fd 3 是生命周期管道的读端，fd 4 是该代 cgroup.kill。**写端只在控制器内保留，不传给 warden/VMM**；控制器退出或 SIGKILL 后，EOF 触发整个 cgroup 的 kill（包括 warden 自身）。监督进程意外退出时，仍存活的控制器也会 kill 同一 cgroup。单纯依赖 jailer 的 `Pdeathsig` 不成立：[Linux 凭证变更会清除该信号设定](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html)，本实现不把它当作保障。

已存在但无法对应持久归属/账本的资源导致启动失败，不能“看到新目录为空就宣称旧 VM 已销毁”。runtime/cgroup 根、UID 范围或任一资产摘要与状态目录绑定不同，也会拒绝启动。当前尚无在线配置迁移/升级流程，即使资源已空也不自动重绑；不要删除账本或绑定文件来绕过恢复。

## 执行与异常

- 命令仅作为受限 argv 经私有 vsock bridge 发往 VM；没有宿主 shell 或容器 fallback。
- host 验证 Ref、execution ID、boot ID、响应状态和输出上限。并发 bridge 调用最多 2 个，与 guest 组数一致；额外已接收任务等待本代 slot，等待时间也计入任务期限。
- **一旦已发往 guest 的任务遇到 host 期限、取消、传输/协议错误或非正常完成状态，整台 VM 被停止并栅栏。** 不依赖不可信 guest 宣称“已杀干净”。这意味着超时会失去本实例工作区，调用方需要新建实例，而不是继续在旧 VM 上执行。
- 正常 EXITED 回包的真实性依赖镜像内的 guest 内核/agent；被攻陷的 guest 可以伪造完成，host 不能据此证明其内部没有后台执行。安全停止证明以整 VM 的 host cgroup 为单位，不承诺同代命令间隔离；需要强单命令边界时仍需一命令一代 VM。host 超时是未完成 RPC 的宿主截止机制，不是对恶意 guest 回包的远程证明。
- `ErrBackendFenced` 只表示禁止再准入并需要恢复，不代表已证明停止；Stop 和持久状态仍分开确认。普通 API 不回传底层路径和原始错误。
- 显式 Stop 正在进行时，在途执行返回错误不能把 STOPPED 意图悄悄变成 DELETE。DELETE/TTL/故障回收则按原生命周期继续。
- 创建预算 30 秒，Stop 5 秒，Cleanup 10 秒；HTTP 写预算 40 秒。CLI 创建请使用 `-deadline 40s`（默认客户端预算仍为 10 秒）。预算到期不是资源已经清理完毕的证明。
- 服务不保留任务 console；仅在 READY 前暂存最多 4 KiB 初始化 stderr，启动失败时可进入私有账本错误及操作员日志，绝不经普通 API 回传，READY 前会清空并禁用；执行结果仍为内存历史，销毁/重启后不保证可查询。执行不会因响应丢失而自动重试。

## 固定规格与操作员准备

仅在隔离的 Linux/KVM 节点试验。要求 root、可用 `/dev/kvm`、cgroup v2、clone3/newnet、足够磁盘与内存。真实驱动状态目录、配置、资产及所有父路径必须 root 所有、不可由 group/other 写入且不含 symlink；私有目录 0700，配置 0600。不支持直接从用户可写工作目录或 `/tmp` 启动特权资产。

操作员需预先准备**独立空 cgroup 根**并委派 `memory pids cpu`，不能把控制器或其他业务进程移进去。驱动只管理其下的 64 位十六进制 ID+generation 子目录，不修改路由/iptables，不创建 guest NIC。UID/GID 范围必须由操作员专门保留，不得与宿主账户、其他执行器或彼此重叠；配置中需显式确认，驱动还会拒绝已知宿主账户冲突。

固定规格：guest 512 MiB / 2 vCPU / 128 MiB 私有工作盘；host cgroup memory 768 MiB、swap 0、OOM 整组、pids 64、CPU 2 核预算。guest 任务规格见 [GUEST.md](GUEST.md)。实例数配额不是物理内存的自动容量规划；操作员必须限制总数，当前不提供磁盘项目 quota 或节点资源自动调度。

配置结构（占位路径和摘要不能直接运行）：

```json
{
  "version": 1,
  "runtime_root": "/srv/xandbox",
  "cgroup_root": "/sys/fs/cgroup/xandbox",
  "uid_start": 400000,
  "uid_count": 32,
  "reserved_uid_range": true,
  "firecracker": {"path": "/opt/xandbox/firecracker", "sha256": "<64 lowercase hex>"},
  "jailer": {"path": "/opt/xandbox/jailer", "sha256": "<64 lowercase hex>"},
  "warden": {"path": "/opt/xandbox/xandbox-warden", "sha256": "<64 lowercase hex>"},
  "kernel": {"path": "/opt/xandbox/kernel", "sha256": "<64 lowercase hex>"},
  "initrd": {"path": "/opt/xandbox/initrd", "sha256": "<64 lowercase hex>"},
  "workspace": {"path": "/opt/xandbox/empty.ext4", "sha256": "<64 lowercase hex>"}
}
```

`runtime_root` 必须位于 `/run/` 或 `/srv/` 的专属目录，所在文件系统允许执行，且足够短以容纳完整的 64 字符代际路径并满足 Unix socket 的 107 字节上限。`firecracker` 的 basename 固定，jailer 与它必须为同一受支持版本。某些发行版的 `/run` 是 `noexec`；驱动会在启动时拒绝，不会改动宿主挂载参数，需选择专属可执行文件系统（验收使用 `/srv/`）。工作盘模板必须恰为 128 MiB 的空白 ext4；不要把秘密或租户数据写入模板。镜像下载与 guest 构建见 [GUEST.md](GUEST.md)，实验用 CI kernel 不等于生产供应链。

Linux 上使用已打补丁工具链构建（本轮 Go 1.27.3）：

```sh
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/sandboxd ./cmd/sandboxd
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/xandbox-warden ./cmd/xandbox-warden
# 安装到 root 所有的专用路径、核对摘要并写好私有配置后：
sudo -n /opt/xandbox/sandboxd -backend firecracker \
  -state-dir /var/lib/xandbox -auth-file /etc/xandbox/auth.json \
  -firecracker-config /etc/xandbox/backend.json -max-instances 32
```

daemon 不会自动创建/修改系统级 cgroup 委派或保留 UID。`-insecure-mock` 与 Firecracker 不兼容。服务重启仍是全部停止回收，不恢复旧会话。

## 真实验收入口与仍缺少的门槛

`scripts/kvm_driver_smoke.py` 在 `/var/lib`、`/srv` 和专属 cgroup 子树内临时安装 root 所有的测试资产，退出时只清理自身资源；日志保持私有，输出报告不含令牌、Ref、boot ID、主机路径或任务输出。例：

```sh
sudo -n python3 scripts/kvm_driver_smoke.py \
  --daemon bin/sandboxd --warden bin/xandbox-warden \
  --firecracker work/kvm-assets/bin/firecracker --jailer work/kvm-assets/bin/jailer \
  --kernel work/kvm-assets/vmlinux-6.1.188 --initrd work/guest.cpio.gz \
  --source-revision "$(git rev-parse HEAD)" \
  --report work/kvm-driver-report.json --log-dir work/kvm-driver-logs
```

普通 CI 不具备此 KVM/root 环境；编译、单元测试和 mock smoke 不能代替它。完整服务验收仍需：宿主重启/磁盘故障、监督进程与控制器同时失效、guest 回收故障注入、只停不 GC 的优先队列、metadata 容量/保留期、磁盘 quota、生产镜像更新链、持续负载/SLO、快照/预热/原子切换、可观测性和独立操作员复现。DESTROYED 目前表示逻辑资源回收，不代表物理介质安全擦除；加密擦除/存储擦除策略尚未验收。生命周期管道检测控制器死亡，不检测仍保留写端的控制器死锁；独立租约/看门狗仍是开放门槛。

参考：[jailer v1.17.0 已存在 cgroup 的精确行为](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/jailer.md)、[cgroup v2 内核契约](https://docs.kernel.org/admin-guide/cgroup-v2.html)。

## 2026-10-22 服务实测

[脱敏报告](validation/kvm-driver-2026-10-22.json) 来自源码 `6c4b947`，控制器/warden 均用 Go 1.27.3 构建并在真实 Linux/KVM 节点运行，16 项通过。机器为 Xeon Silver 4216、64 逻辑 CPU、约 251.5 GiB 系统内存，runtime 使用 ext4；只顺序测试单 VM，三个已接受任务在两个执行 slot 上排队。

创建 READY 的 4 次样本约 1.41–1.51 秒。单次运行态 DELETE：接受约 1.8 ms、观测执行停止约 49.5 ms、持久 DESTROYED 约 141.6 ms；显式 Stop 的一个样本约 45.4 ms。控制器 SIGKILL 到 kernel cgroup 归零约 49.5 ms，重启到持久回收约 779 ms。这些是**顺序小样本验收，绝不是 P50/P95/P99、快照切换时间或 SLO**。缓存/负载未控制，驻留内存未测，磁盘仅写少量文件，未压满 128 MiB；具体观测点与原始精度见报告。

初始化期间真实遇到 `/run` noexec 的失败，已增加前置拒绝并改用专属 `/srv` 目录，没有改变宿主挂载策略。另修复验收脚本把 Job 的字符串 error 当成 HTTP error 对象的断言错误；失败运行没有被计为通过。控制器及监督二进制摘要、镜像摘要均在报告中，重建修复脚本后的提交得到完全相同的控制器摘要。
