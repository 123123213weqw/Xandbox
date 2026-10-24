# 固定清单 Go 启动器（实验性，非生产安装器）

`cmd/xandbox-launch` / `internal/launch` 新增真实 Linux 启动路径，不再由 Python probe
代替普通 daemon。它只接受 `xandbox-launch -manifest /absolute/root-owned/launch.json`；
不接受租户命令、不启动 mock、不提供宿主执行 fallback。非 Linux、非 root、PID1 不是
systemd、任何预检失败都直接退出。完整生产门槛仍未完成。

## 单一 writer 的层级

```text
systemd: unit 父预算 / RuntimeDirectory / 停止与最终清场
└── /sys/fs/cgroup/system.slice/<name>.service
    ├── bootstrap                 # DelegateSubgroup；launcher 初始位置
    ├── .control                  # 管理器 helper，不能混入 NodeRoot
    └── node                      # launcher 创建；普通 schema3 严格核验
        ├── control               # launcher 仅迁移自己，再同 PID exec sandboxd
        └── instances             # 普通 daemon 创建各代际 cgroup
```

unit root 直属进程必须为空，bootstrap 只能有当前 PID；已有 node 或其他未知子组一律拒绝，
不收养、删改或猜测旧树。launcher 核对父预算，启用委派的 cpu/io/memory/pids，建立全新的
node/control/instances 并精确读回限制，最后才写自己到 control/cgroup.procs。
该写入迁移整个线程组，不逐个搬动其他进程。Go launcher exec 后 manager MainPID 不变。
任何中途失败都不自行递归清理；管理器必须清场，不能对残存 node 盲目重试。

## manifest v1：无自动默认策略

JSON 顶层仅有 `version/unit_root/input_dir/state_dir/daemon/backend/auth/frontend/parent`，
重复键、未知键、非规范绝对路径、非法边界都拒绝。版本必须为 1。

| 字段 | 契约 |
|---|---|
| `unit_root` | 直属 system.slice 的受限 ASCII `.service` 名 |
| `input_dir` | 恰好 `/run/<unit名称去掉.service>-inputs`，由 manager 创建的空 root 私有目录 |
| `state_dir` | `/srv/` 下已存在的规范 root 私有目录 |
| `daemon` | `{path, sha256}`；basename 为 sandboxd，固定本机架构的静态 ELF64 ET_EXEC |
| `backend` / `auth` | 各 `{path, sha256}`；不同的 root 私有文件，不在 state_dir 内 |
| `frontend` | 显式实例/账本/租户账本/执行历史及并发、会话、Stop/GC workers、队列和 metrics 策略 |
| `parent` | 显式 memory_max、pids_max、cpu_quota、单方向 IO bytes/s 和 ops/s |

准确字段和数值上限见 `internal/launch/manifest.go` 的类型及 Decode；没有硬编码生产租户或
预设容量。`frontend` 使用现有普通 daemon 参数名的下划线 JSON 形式；`parent.cpu_quota`
以微秒计，周期固定 100000 微秒。父 memory/pids 至少比 NodePolicy 多 64MiB/16，父 CPU/IO
不得小于 node。它不是完整主机容量规划或 helper 公平性证明。

backend 必须是现有 schema3，包含 NodePolicy、IO 与 project quota；NodeRoot 精确等于
`unit_root/node`，实例根为其 `/instances`。启动器调用原有
`firecracker.ValidateAdmissionConfig` 和 `access.Load`，不维护第二套准入或认证解析器。
state/runtime 必须互不嵌套、均 root 私有、位于同一 ext4 设备；其他 quota、UID、资产、路径、
磁盘余量与节点库存条件仍由既有普通后端验证，不能用启动器绕过。

## 固定字节、能力和 FD 边界

- manifest/backend 各至多16KiB、auth 至多64KiB、daemon 至多64MiB；验证 SHA-256、
  root 所有者、无 group/other 写、普通单链接文件。逐级 directory FD + openat/NOFOLLOW，
  不跟随路径别名；state/runtime/input 的叶目录另外要求无 group/other 权限。
- 在空 RuntimeDirectory 内独占创建0400 backend/auth 副本并同步文件和目录。
  daemon argv 只引用这些副本，不重新打开可被替换的原策略文件名。
- daemon 不允许 PT_INTERP；以已核验 ELF FD 的 `/proc/self/fd/N` 路径直接 unix.Exec，
  而不是再通过原文件名执行。执行时 CLOEXEC 关闭该 FD；没有 shell、命令拼接或参数透传。
- 启动前与 exec 前均核对所有实际观察到的 Go 线程：UID0、NNP=1，五个 capability sets
  都不包含 CAP_SYS_RESOURCE；FD>2 不得可继承。exec 使用固定 PATH/HOME/LANG。
  不输出原始路径、策略或底层错误，仅输出闭集失败阶段。

这些措施以可信 root/manager/发布流程为前提：root 仍可原地改写 ELF 或0400策略副本，
manifest 本身也不是独立签名或远程证明。没有宣称抵御恶意特权管理员、任意 mount 注入，
也没有因移除 CAP_SYS_RESOURCE 就宣称剩余 capabilities 最小化完成。
FD 执行的名称竞态与文件内容限制可参阅 [fexecve 文档](https://man7.org/linux/man-pages/man3/fexecve.3.html)；
这里实际使用 procfd + unix.Exec，并非调用 libc fexecve。

## 管理器与实验验证边界

实验 unit 由 `scripts/build_systemd_deployment.py` 生成，仅用于专用 owned L1，不能复制为
生产安装器。它配置 DelegateSubgroup=bootstrap、四项委派、RuntimeDirectory、NNP、排除
CAP_SYS_RESOURCE、父预算、KillMode=mixed、Restart=no。RuntimeDirectory 的创建/移除职责
见 [systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)。
Type=exec 只表明 manager 执行了 launcher；普通 `/healthz` 和实机 guest 执行必须另行核验。

新增显式 deployment profile 使用8GiB/CPU8/12GiB L1，外层10GiB memory.max、swap0、
CPU8、pids256、无 NIC；原2GiB primitive profile不变。九项资产逐项固定摘要与大小，
不在 L0 mount/chroot/执行 guest。实际结果及失败前序另记，不以代码/纯控制替代 KVM 证据。
普通 daemon 的 SIGTERM 注册已独立前移至启动 Serve goroutine 之前，新增旧顺序必失败的
结构回归；Go 的默认 SIGTERM 行为见 [os/signal](https://pkg.go.dev/os/signal#hdr-Default_behavior_of_signals_in_Go_programs)。
这项修正改变 sandboxd ELF；旧 d163 的完整实机矩阵不能直接继承到新程序。

仍需：新 ELF 全量运行/故障矩阵、真实 systemd TLS/catalog 接入、安装/升级/备份恢复、
独立操作员、负载与资源饱和、可靠审计/保留策略和生产 SLO。
历史 a161 push CI 的 auth-smoke 非零退出原因尚未证明；信号顺序修正不是它的已证实归因。
测试现保留原退出码断言与超时，失败时只提供整数退出状态及受限闭集诊断，未放宽通过标准。
