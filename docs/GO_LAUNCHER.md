# 固定清单 Go 启动器（实验性，非生产安装器）

`cmd/xandbox-launch` / `internal/launch` 新增真实 Linux 启动路径，不再由 Python probe
代替普通 daemon。它只接受 `xandbox-launch -manifest /absolute/root-owned/launch.json`；
不接受租户命令、不启动 mock、不提供宿主执行 fallback。真实普通 UDS→KVM 的有限验收已通过，
见[脱敏摘要](validation/go-launcher-uds-v1.json)；不是完整生产部署。非 Linux、非 root、PID1 不是
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

## 首轮实机失败：能力集合 oracle 校准

v1（e1aec85）真实普通 daemon/guest 启动后，新的测试把五个 capability sets 全部要求为0，
在 VMM 检查失败。v2（0200a19）**保留该断言，只增加闭集诊断**，实测确认
CapInh/CapPrm/CapEff/CapAmb 为0，唯独 CapBnd 非0，五组均无 CAP_SYS_RESOURCE。
两个失败原件与独立只读资源消失复核保留，不能改写成通过或完成后续回收/冷恢复。

这不是把 bounding 忽略：新 oracle 要求四个实际/可继承集合为0，五组及已验证 main 的
bounding 均无 CAP_SYS_RESOURCE，且 VMM CapBnd **精确等于**普通 main 的继承上限；
缺字段、坏编码、额外/丢失 bounding 位、任一活动能力都拒绝。UID、NNP、双 seccomp、
固定 ELF 与进程身份检查仍在。生产 Go 后端和九个资产未因该测试校准而修改。
bounding 与活动集合的含义不同，见 [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)；
固定 [jailer v1.17.0 源码](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/src/jailer/src/env.rs)
通过 uid/gid 配置 exec，并未承诺 bounding 全清零。后续结果必须来自新的实际运行，
不能仅凭上述解释宣布通过。

v3（83f205a）通过 capability 检查后，在启动45秒 heartbeat writer 的 API 请求处失败；
原创建请求使用普通默认 max_exec_ms=5000，超出该实例限额的执行本来就应被拒绝。
v4 测试创建时显式请求现有上限60000，所有旧 key 重放共用相同 spec；新增纯控制确认
参数一致性，不扩大生产默认值、不提高执行/Stop/GC 超时。API失败信息现区分整数
actual/expected状态与frame越界，不回显响应体或凭证。v3原件和清理审计继续保留。

## v4 实际通过的有限普通 UDS 部署

冻结 harness 源 **921508d**，不是把失败报告回写为通过。Go源码与原生构建源 e1aec85 的
cmd/internal/go.mod/go.sum 逐字相同，十个 Linux amd64 产物的原生/交叉 SHA-256 完全一致。
新 sandboxd 为 `5bfb2394…`，新 launcher 为 `26f35a3d…`；其余八个产物与前序对应字节相同。
原生完整 Go race×3、vet、fixture race×3、quota filter×3、七个 mock 进程烟测通过；
初始147、后续148/149/150个 Linux Python 控制全部通过，零 skip。

真实 systemd 255 管理 Type=exec unit，独立 operator 核对 MainPID 的实际 ELF 就是普通
sandboxd，且位于 node/control，backend/auth 为清单固定字节的 RuntimeDirectory 副本。
实际通过以下闭集流程：

1. 两租户共四个同时存活的真实 KVM guest；guest UID65534、四个不同启动身份、
   精确 VMM ELF、reserved UID、能力/NNP/双 seccomp 以及 live kernel project quota 均核对。
   验证租户满额429发生时 node 仍有空位，再验证全节点503、跨租户404、未鉴权401。
2. heartbeat writer 实际推进时 Stop，确认 STOPPED 与 cgroup 空；仍满额503。
   DELETE202 后只有 durable DESTROYED、私有cgroup/jail/owner消失且 kernel quota八字段全0，
   才进行新实例复用；新 guest 启动身份不同且没有旧 heartbeat。
3. 只对 manager MainPID 发 SIGKILL。unit cgroup 与 RuntimeDirectory 由 manager 清除，
   没有 operator rmdir 补救；重新启动真实 Go launcher，同策略普通 daemon 回收四个旧 guest，
   核对旧 key410及各私有资源/quota归零，再创建新的真实 guest。
4. 新 guest 保持 writer 实际运行，健康 checkpoint 与 guest marker 同步；外层切断自己的
   L1 执行域，原盘第二次启动。核对 L1 boot变化/machine-id保留、旧 guest持久销毁与旧key410，
   新 guest可执行且没有旧 marker，最终四个 kernel project全0、无私有代际cgroup/jail。

修改后的默认2GiB primitive profile另以原源 e1aec85通过两次启动，组件文件摘要与 v4 相同，
仍保持它不是 L2 任务验收的原范围，不给历史977报告换标签。
本批独立只读复核覆盖 **5 scopes / 7个外层代际**：默认通过2、普通部署通过2、失败前序3，
所有声明root/control/parent/代际cgroup和五个runner均消失，无补充清理。
前置原生 runner 也已退出；它的首次非特权资产读取失败发生在任何KVM/资源创建之前，
随后只用既有授权 sudo 路径读取固定资产，不重跑或伪装原生测试。

本次只经认证的私有 UDS，不经 TLS gateway、不含 snapshot/catalog、生产安装器、
升级/备份或独立人类操作员。没有以该有限流程替代新 ELF 的25组运行/10组边界/TLS矩阵，
没有切换时延分位、Stop/GC SLO或任意D-state回收保证。所有原始失败/成功报告与console
留在私有证据目录；公开摘要只有源/程序摘要、闭集断言和计数，不含凭证或运行态身份。

## 后续 source21bb 重建的8f launcher

独立[ingress启动组件](INGRESS_LAUNCHER.md)复用launch的root FD读取与只读资源校验，新增
导出入口使普通launcher重建字节改为 `8f612a9d…`，虽然原Run/嵌套创建流程未修改，也不能
沿用26f3的ELF验收。8f已另完成同一普通UDS/四KVM/Stop-GC/SIGKILL/cold两启动闭集回归，
独立1 scope/2外层代际全部消失、无补充清理；[新摘要](validation/ingress-component-v1.json)
明确该profile没有启动新ingressguard或TLS。daemon/gateway等九个既有产物逐字相同；
此前37个scope仍保留各自原始source/ELF绑定，不重新贴成source21bb的硬件报告。
