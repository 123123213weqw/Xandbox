# 真实 systemd L1 委派地基（不是生产部署）

**通过的是 TEST ONLY 管理器原语，不是 sandboxd 安装或真实租户任务验收。**
冻结 harness 源 `97753b1`，使用固定 Ubuntu 24.04 minimal rootfs，实际在自己拥有的 KVM L1
中启动 systemd 255，完成两次原盘启动。[脱敏摘要](validation/systemd-host-v1.json)保留源归档、
原始报告及工具指纹；不公开 rootfs、私有 receipt/其摘要、console、运行态身份或凭证。

## 已实际验证

独立 operator service 通过私有串口控制另一个 delegated service，不在共享 L0 调用 systemctl。

```text
systemd 管理的 unit root（本实验 1 GiB / CPU4 / pids128 / swap0）
├── bootstrap                  # DelegateSubgroup；main 初始位置
├── .control                   # 实际 ExecReload helper，仅位于 node 外
└── node                       # 对应拟采用的 NodeRoot 层级
    ├── control                # main 只移动自己；含受控的 heartbeat child
    └── instances              # 此原语试验不运行 sandboxd 或 L2 任务
```

- 独立核对 manager MainPID 与 PID start-time 身份、PID1/systemd、四项 controller 委派、
  root/node/instances 无直属进程、node 下只有 control/instances，以及精确 memory/swap/pids/CPU/IO 读回。
  NodeRoot 在本实验为 512 MiB/CPU2/pids64，control128 MiB/pids16，读/写各64MiB/s、各1024ops/s；
  这些**不是生产 NodePolicy 或完整节点资源预算**，只验证层级机制。
- main 的五项 capability sets 均无 CAP_SYS_RESOURCE，NNP=1；实际打开 `/dev/kvm`，
  验证 API12 并创建/关闭一个 VM FD。没有 vCPU 或 L2 命令，不能冒充 Firecracker 执行。
- 实际 ExecReload helper 处于 unit 的 `.control`，而非 node 内；main/child 继续推进，
  严格 node 库存不被放宽。不是任意 Exec* hooks、auth reload 或生产 TLS 轮换验收。
- child 在 L1 内忽略 TERM；独立 operator 执行 systemctl stop，核对两个旧进程身份消失，
  **unit cgroup 由管理器移除、没有 fixture rmdir 补救**，再 start，核对新 main 身份与 child 进度。
  stop 命令返回的单次观测为 123.531ms，不是任意 D-state、生产停止或 GC 的时间保证。
- 健康 checkpoint 的文件与目录 fsync 后切断自己的 L1 执行域，复用同一磁盘、换新的外层代际。
  第二次 systemd 启动核对 boot 改变、machine-id 保留，重复委派/reload 检查。
  不等于普通 daemon 的 ledger/owner/quota/pin 恢复或物理介质掉电。

L1 为 2GiB RAM/CPU4/2GiB disk；外层沿用既有 UID/netns/cgroup/lease 受限 launcher，
固定 3GiB memory.max、swap0、CPU4、pids128、无 NIC。两次 QMP 均核对 KVM enabled。
新 10 项纯控制、既有 3 项安全提取控制及 Linux 全部 136 项 Python 测试实际通过，零 skip。
macOS 本地旧 Python 缺 data_filter 而跳过的提取用例不作为这些 Linux 通过的证据。

独立只读复核覆盖本批 2 个成功外层代际和前序 3 个失败代际：4 个 scope 的声明
root/control/parent/所有 generation cgroup 均不存在，4 个 runner 均消失，没有补充清理。
这不是全机进程清单或绝对 escape 证明，也不以最终删盘倒推 live L1 的节点性质。

## 失败来源与修正

- v3 在真实 systemd readiness 后失败，但当时一整个 case 成功才保存结果，不能补造其已完成步骤。
- v4 改为逐步留存，原件确认 probe/reload 通过，失败发生在 stop-restart；不回写 v3。
- v5 在 error reply 前保存私有 traceback/journal，精确定位为 `systemctl reset-failed`。
  源码顺序显示它发生在旧身份和 unit cgroup 消失检查之后。
- v6 删除干净 unit 的多余 reset，直接由 StartUnit 加载声明的 unit；新增 unloaded-unit 回归。
  不改 stop/kill 预算、不去掉旧身份或 cgroup 消失检查、不放宽库存/capabilities。

systemd v255 的 ResetFailedUnit 本来就不会加载已卸载 unit；StartUnit 的职责不同，见
[官方固定版 manager 源码](https://github.com/systemd/systemd/blob/v255/src/core/dbus-manager.c)。
管理器的 prune/empty 处理见[固定版 cgroup 源码](https://github.com/systemd/systemd/blob/v255/src/core/cgroup.c)。
本实验实际失败和后续两次启动仍是验收依据，不以源码分析替代执行证据。

## 可复现边界

`scripts/systemd_host_assets.json` 固定 Ubuntu 原始 archive SHA-256；可变 `/release/` URL
只用于取文件，摘要变化必须拒绝，不自动接受 latest。官方
[SHA256SUMS](https://cloud-images.ubuntu.com/minimal/releases/noble/release/SHA256SUMS)
与[包清单](https://cloud-images.ubuntu.com/minimal/releases/noble/release/ubuntu-24.04-minimal-cloudimg-amd64-root.manifest)
是当时 pin 的来源，不是独立签名/可复现构建证明。
旧 `nested_host_assets.json` 的 QEMU、kernel、KVM/quota modules 不变，不修改 cv3/v10 原资产。

builder 只组装私有文件，**从不在 L0 mount/chroot/执行 guest 用户态或包安装脚本**。
官方 archive 有 8 个标准 `/dev` 字符设备头，逐项核对 major/minor 后直接省略，未知 special 一律拒绝；
不让 tarfile 在 L0 创建设备。绝对 guest symlink 经既有安全 filter 转成树内相对链接，拒绝逃逸。
使用 mke2fs -d 离线构造盘；Alpine initrd 仅在 L1 加载固定模块、挂载该盘并 switch_root 到 systemd。

在匹配固定资产的隔离 Linux/KVM 测试节点，冻结 clean 源码/归档与 launcher 构建后，显式运行
`scripts/kvm_systemd_host.py --help` 所列完整参数。需要 root 建立**自己的**文件/cgroup；
不要把 helper 放进生产节点或在 L0 执行 `systemd_delegate_probe.py`。缺少专用 guest marker/PID1 时它拒绝执行。
CI 只跑纯控制及语法检查；这些并不自动赋予 hosted runner KVM/systemd 集成认证。

## 下一步（尚未完成）

采用上述 nested node 层级实现真正 Go launcher：核验不可变发布清单、真实委派/预算与配置，
只搬自身，进入 node/control 后 exec 固定 daemon，保持没有宿主执行 fallback。
还需实际安装/启动普通 TLS→Firecracker 服务、catalog 管理位置、busy drain/崩溃/原盘恢复、
凭证与权限、升级/备份回滚及独立操作员复现。可靠审计/背压、全局资源饱和、长期 SLO 等
仍属[完整生产门槛](PRODUCTION.md)。现有 Python probe/unit 不能当成生产 launcher 或安装器。
