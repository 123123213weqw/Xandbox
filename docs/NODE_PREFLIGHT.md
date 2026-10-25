# 只读节点预检：xandbox-doctor

`xandbox-doctor` 用于在准备安装材料之前，观察当前节点是否满足
**现有 systemd 安装组合**的基本前置条件。它不是安装器、KVM canary、
完整部署验证或生产认证，也不替代普通启动器/后端的真实准入检查。

```sh
GOTOOLCHAIN=go1.27.3 make build
./bin/xandbox-doctor
```

直接使用当前普通用户运行，不要求 sudo。输出为 JSON；不要把不满足条件时的
退出码 1 当作程序崩溃。macOS 可以构建工具，但会报告该安装组合需要 Linux。

## 检查什么

| 检查 | 实际观察 | 不代表什么 |
| --- | --- | --- |
| Linux / 架构 | 当前进程平台；amd64 为现有具名实机 fixture 的架构 | arm64 编译成功不等于已实机验收 |
| systemd PID1 | 真实 procfs 的固定 `/proc/1/comm` | 不是 systemd 包是否安装 |
| 运行中 manager 版本 | 固定本机 system manager 的 `Version` 属性 | 不用磁盘上 `systemctl --version` 冒充运行中版本 |
| cgroup v2 | 固定 cgroup 根的实际文件系统类型 | 不证明目标 unit 已委派或预算已落实 |
| controllers | 根上 cpu/io/memory/pids 是否存在 | 不启用 controller，不创建或移动进程组 |
| KVM 设备 | `/dev/kvm` 的字符设备类型、Linux 设备号和名称身份复核 | 不打开 KVM，不创建 VM，不检查硬件运行能力 |
| 当前调用者权限 | 实际 effective-access 查询 | 不证明 device-cgroup、LSM 或 KVM ioctl 会允许真实操作 |

`DelegateSubgroup=` 从 systemd 254 引入，因此本安装组合采用明确的 254
版本下限；它不是所有 Firecracker 用法的通用版本要求。
参考：[systemd 资源控制契约](https://www.freedesktop.org/software/systemd/man/255/systemd.resource-control.html)、
[systemctl manager 属性查询](https://www.freedesktop.org/software/systemd/man/251/systemctl.html)。
Linux KVM 设备号参考：[内核 miscdevice 定义](https://github.com/torvalds/linux/blob/master/include/linux/miscdevice.h)。

如果宿主仍运行 systemd 249，即便已安装更高版本的工具，预检也不能因此通过。
可选择满足前置条件的专用节点或专用现代 Linux 虚拟机；不要为了试用自动升级共享宿主，
也不要在检查失败后偷偷改成 mock、宿主执行或不受预算约束的启动方式。

## 返回值和成熟度

- **0**：本次观察的八项基本条件全部通过；**不是可安装、可上线或生产就绪的授权**。
- **1**：至少一项失败或无法确认。输出仍是完整 JSON，检查 `checks` 中的闭集 `code`。
- **2**：参数或输出失败。错误不包含原始路径、调用参数、manager 输出或 OS 错误。

报告固定包含：

- `profile="systemd-install-v1"`，报告格式 `version=1`。
- `basic_prerequisites_met` 只概括当前基本观察。
- `read_only=true`、`vm_created=false`、`isolation_validated=false`、`production_ready=false`。
- `deferred_checks` 列出仍需单独验证的 KVM 创建、clone3/namespace/capabilities、
  真实 unit 委派和预算读回、镜像摘要与 guest 健康、磁盘/quota/backing、保留 UID/可信路径、
  节点容量压力、网络/TLS，以及完整故障矩阵/SLO。

例如 `dedicated_newer_systemd_node_required` 表示该组合版本前置条件不满足；
`running_manager_version_unconfirmed` 则可能是 manager 不可达、查询被拒绝、
工具路径不可信或输出无法确认，不能伪装成已经确认版本过低。

## 只读和进程边界

工具不接受路径、命令、unit、远程 host、profile 替换或 `--install/--force`。
没有配置修复、文件生成、包安装、服务启停、daemon-reload、cgroup 写入、KVM open/ioctl、
挂载或 GPU 透传操作。它不会读取租户凭证、业务账本、镜像或任务输出。

唯一的外部命令为已校验 root 所有、祖先可信、非 symlink 的 `/usr/bin/systemctl`，
通过持有的 FD 执行固定 **本地 system manager 只读属性查询**：

```text
systemctl --system --no-pager --no-ask-password show --property=Version --value
```

子进程使用固定环境，不继承 PATH、LD_*、SYSTEMD_HOST、SYSTEMD_BUS_ADDRESS、
DBUS_SYSTEM_BUS_ADDRESS 或 SYSTEMD_OFFLINE 等调用者选择。
stdout/stderr 各最多保存 1024 bytes，原始输出不进入报告；命令最多等待两秒，
异常/超量/非空 stderr 均报告无法确认，不作为通过。
这些界限不是对宿主内核停滞或文件系统 D-state 的停止 SLO。

这是可信 OS/root 前提下的 best-effort 观察，不是对恶意宿主管理员的安全边界，
也不是所有检查在同一瞬间完成的原子快照。检查通过后，正式启动仍必须重新验证全部原有契约。

## 测试范围

Go 单元测试覆盖版本/控制器闭集解析、每类缺项/unknown 拒绝、隐私投影、退出码、
限量输出，以及只属于测试自身的子进程错误/超时/reap。
`make smoke` 额外执行真实 doctor 进程，并检查调用者的假 PATH 命令、远程 manager
环境及秘密字符串不进入查询或输出。这些测试不是 KVM 或生产部署验收。
