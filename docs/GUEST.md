# 实验性 guest-agent / vsock 路径

**尚未集成到 sandboxd，不是可部署的 Firecracker 后端。** 守护进程目前仍只提供 mock。本目录对应 M2 的独立组件与真实 KVM 验收脚本；不能把协议单元测试或交叉编译当成真实隔离验收。

## 边界

```text
host: xandbox-guestctl → 私有 AF_UNIX bridge → Firecracker virtio-vsock
guest: CID 2 → 特权端口 900 → agent → 每任务 cgroup → UID/GID 65534
```

遵循固定版本的 [Firecracker vsock 协议](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/vsock.md)。host 只连接私有 UDS；连接确认中的端口是 host 临时端口，不要求等于 guest 监听端口。agent 仅接受 AF_VSOCK sockaddr 显示为 host CID 2 的连接，不信任请求自报的身份；没有 TCP 或宿主机执行回退。

agent 启动要求专用镜像标记、guest 启动参数中的 ID/generation、root 初始化身份和 guest vsock CID。真实执行器无法在普通宿主环境初始化；命令子进程还有单独的 guest/cgroup/UID 检查。这是防止误运行的工程约束，不是针对恶意宿主 root 或 guest 内核的远程证明。

独立验收还将 VMM 放进只有 loopback 的宿主网络 namespace，并确认实际 KVM VM fd 存在；不是仅凭进程名判断使用了 KVM。

guest 使用 BusyBox init 作为 PID 1，负责回收孤儿进程；没有登录终端、SSH 服务或业务网络配置。agent 不以 PID 1 身份兼任 Go 子进程 wait/reaper，避免抢走 `exec.Cmd` 的退出状态。

## 执行与取消

- 命令以 argv 传递，不自动拼接 shell。需要 shell 时显式执行 guest 的 `sh -c`，并始终在 VM 内运行。
- 工作目录固定 `/workspace`，环境变量为固定白名单，不继承宿主环境或凭证。
- 每任务创建 root 所有的 cgroup，使用 `clone3(CLONE_INTO_CGROUP)` 从出生即加入；配置 128 个进程、128 MiB 内存、禁用交换与一核 CPU 预算。实例规格暂固定，尚未成为控制面可配置资源策略。
- 任务 UID/GID 为 65534，无附加组。可信子进程 helper 在锁定的 OS 线程上设置 `no_new_privs`，之后直接 exec；只在 Go 父进程的某个线程设置 prctl 并不能保证所有子进程继承。
- stdout/stderr 合计最多 64 KiB；超量仍消费管道数据，但不继续保存。argv 最多 128 项、合计 32 KiB；单任务时限最多 60 秒。
- 超时或 host 连接关闭都会取消整个任务 cgroup，包括自行 `setsid()` 的后代。正常退出后也清理同组后台进程；不提供跨执行保活的后台服务。
- 回收等待 `cgroup.events` 的 populated 变为 0，然后删除任务 cgroup。回收失败时执行器被栅栏，健康检查不再 READY。未来宿主驱动还必须在无法确认 guest 停止时终止整个 VMM；**这一层尚未集成**。
- 一 VM 内的多个执行共享同一租户工作区和 UID，不承诺这些执行之间的安全隔离。

## 协议

每连接一个请求：4 字节大端长度 + 一个严格 JSON 对象。请求帧最多 256 KiB，响应帧最多 512 KiB；先检查长度再分配内存，JSON 拒绝重复键、未知字段和超深嵌套。输出响应预留了 JSON 转义膨胀空间。

版本固定为 1，支持 `health` 和 `exec`。健康检查中的 `active_execution_groups` 来自 kernel cgroup 目录观察，而非仅靠内存任务计数。请求携带 Ref；exec 还带独立的 32 位十六进制 execution ID。响应回显版本、Ref、execution ID、boot ID 和状态。host 校验身份、状态及输出界限，不因收到任意合法 JSON 就认为 guest 已就绪。当前没有请求重放缓存或执行响应丢失后的 exactly-once 承诺，客户端不自动重试执行。

## 在独立 Linux/KVM 节点复现

需要：可读写 `/dev/kvm`、非交互 root、cgroup v2、Go 1.25+、Python（含 `tarfile.data_filter` 安全补丁）、`cpio`、`mkfs.ext4`、`unshare`、`nsenter`、`ip` 和 `curl`。不修改路由、转发、iptables 或已有 cgroup；验收只创建自己命名的临时 cgroup。

Go 1.25 是源码兼容下限，不是生产安全基线。本轮漏洞扫描在 Go 1.27.1 上发现标准库安全更新未包含；使用 Go 1.27.3 后重新扫描。构建部署镜像应使用仍受维护且已打补丁的工具链，不能把旧版本兼容性 CI 当成安全认证。修复版本可核对 [Go 发布记录](https://go.dev/doc/devel/release#go1.27.3) 和 [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809)。

`scripts/kvm_assets.json` 固定下载 URL 和 SHA-256。Firecracker/jailer 为相同版本的官方 release 二进制；测试 kernel 来自固定路径的上游 CI artifact，Alpine 来自固定 release。**这些是实验镜像输入，不是经过安全维护认证的生产镜像供应链。** 上游也将 [快速入门资源](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/getting-started.md) 定位为演示材料。

```sh
mkdir -p work/kvm-assets bin
python3 - <<'PY'
import hashlib, json, pathlib, subprocess
root = pathlib.Path('work/kvm-assets')
lock = json.load(open('scripts/kvm_assets.json'))
for name, asset in lock['artifacts'].items():
    path = root / name
    subprocess.run(['curl', '-fL', '--retry', '2', '--connect-timeout', '10',
                    '--max-time', '600', asset['url'], '-o', str(path)], check=True)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == asset['sha256'], name
PY
tar -xzf work/kvm-assets/firecracker-v1.17.0-x86_64.tgz -C work/kvm-assets
mkdir -p work/kvm-assets/bin
cp work/kvm-assets/release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64 work/kvm-assets/bin/firecracker
cp work/kvm-assets/release-v1.17.0-x86_64/jailer-v1.17.0-x86_64 work/kvm-assets/bin/jailer

CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/xandbox-agent ./cmd/xandbox-agent
go build -trimpath -buildvcs=false -o bin/xandbox-guestctl ./cmd/xandbox-guestctl

sudo -n python3 scripts/build_guest_image.py \
  --alpine-tar work/kvm-assets/alpine-minirootfs-3.24.3-x86_64.tar.gz \
  --agent bin/xandbox-agent --output work/guest.cpio.gz
sudo -n python3 scripts/kvm_guest_smoke.py \
  --firecracker work/kvm-assets/bin/firecracker --jailer work/kvm-assets/bin/jailer \
  --kernel work/kvm-assets/vmlinux-6.1.188 --initrd work/guest.cpio.gz \
  --guestctl bin/xandbox-guestctl --agent bin/xandbox-agent \
  --report work/kvm-report.json --log-dir work/kvm-private-logs
```

构建脚本安全解包固定摘要的 Alpine 包，改写绝对符号链接为 guest 内等价的相对链接，拒绝越界与特殊文件，最后生成包含 agent 的 initramfs。它**从不在宿主机 chroot 执行下载的 guest 程序**。输出文件和报告拒绝覆盖；重跑时换新输出名，保留原始诊断证据。

KVM 脚本要求 x86_64，顺序启动两个使用新私有盘的 VM；通过 [jailer](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/jailer.md) 降权并配置 host cgroup，保留默认 seccomp，检查特权降低、工作区、输出上限、超时逃逸进程树及回收。普通 CI 只运行 mock/协议测试和 Linux amd64/arm64 编译，**不会伪造 KVM 测试通过**。

报告中的准备、终止和文件回收耗时是独立实验样本，不是服务 API 的 P50/P95/P99，也不是会话切换或快照恢复性能。详细的生产门槛仍见 [PRODUCTION.md](PRODUCTION.md)。


## 本轮实测证据

[2026-10-22 独立 KVM 报告](validation/kvm-guest-2026-10-22.json) 已通过，包括 Go 1.27.3 agent、两次全新 guest/工作盘、真实 KVM fd、任务 UID/GID/附加组与 no_new_privs、旧 generation 拒绝、setsid 超时回收、host 客户端死亡后的取消及 kernel cgroup 归零、VMM/guest 网络和环境边界，以及停止后再回收。

报告对文件/磁盘准备、jailer 启动至 agent READY、VMM 退出、私有文件/cgroup 删除分别计时。退出使用 pidfd 事件观察，避免 Python `Popen.wait(timeout)` 的轮询回退制造 32/64 ms 的观测下限。

这些仅为组件验收的两次样本：宿主负载与冷热缓存未控制，512 MiB 是配置规格而非已测驻留内存，磁盘只写入少量测试文件，未压满 128 MiB。报告不包含服务请求接收/撤权、账本提交、调度、完整生产日志保留成本或切换，不能推导 API 延迟百分位或吞吐 SLO。

Linux 目标的 govulncheck v1.8.0 / Go 1.27.3 扫描未发现可达漏洞，但仍报告 6 条未被当前调用的依赖模块级记录。它们需要在生产发布前逐项升级/评估；不能把“0 可达”改写成“所有依赖没有任何已知问题”。
