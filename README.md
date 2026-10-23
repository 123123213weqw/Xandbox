# Xandbox

[![CI](https://github.com/123123213weqw/Xandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/123123213weqw/Xandbox/actions/workflows/ci.yml)

Go 实现的云端短生命周期沙箱基础设施，采用 MIT 许可证。

**状态：生产化开发中，尚未生产就绪。**

新增 [持久化错误后的独立物理Stop](docs/EMERGENCY_STOP.md)：新Go1.27.3原生daemon通过5项ENOSPC故障及完整新运行时回归；idle故障停止两次观测为43.814/48.630ms，旧c577负对照约5016ms并按预期未过实验guard。仍返回存储错误、不假称持久STOPPED或提前清理/还容量；这不是线上SLO，也不覆盖尚未返回的卡死I/O。

新增 [独立ledger只读/EROFS实机验收](docs/READONLY.md)：busy/idle两组分别39.017/47.907ms观察到host停止，DELETE仍500、无持久停止/销毁确认、容量保留；RO持续时普通重启拒绝，恢复自身小卷RW后同state回收。预先打开的directoryFD也验证真实EROFS；仅ledger只读，不代表介质EIO、整个state故障或生产SLO。

新增 [双层I/O预算](docs/IO.md)：操作员绑定的Firecracker请求桶与每代cgroup块设备限制，cold/PAUSED快照均先设置、验证后才准入。新原生运行时及真实压力/拒绝/存储交叉回归通过；健康账本下活跃写盘的host停止观测29–47ms，持久销毁另测。缓冲写回与缓存口径不同，不把io.stat当完整计费；不是节点总预算、物理quota或生产SLO。

新增 [独占虚拟宿主掉电恢复](docs/NESTED_HOST.md)：真实嵌套KVM的running/stopped/destroyed三个检查点通过；切断自己的L1服务宿主后，原磁盘冷启动、普通daemon回收旧代/旧key拒绝及新L2执行销毁均成功。共享L0从未重启；仅为各N=1的虚拟宿主故障实验，不代表物理SSD掉电、完整M2或生产SLO。

新增 [整状态盘EIO与fsync卡住时的独立撤权](docs/STATE_IO.md)：新原生daemon四场景通过，并完成健康宿主/IO预算/只读/快照双租户240次/初始化及冷路径回归。held-fsync idle的执行域停止观测从旧4381.622ms变为新43.555ms，新Exec拒绝1.843ms；均为各N=1，不是持久销毁或生产SLO。旧失败基线保留，仍需等待存储恢复后完成持久确认、清理与还容量。

新增 [ext4 project quota 内核前置证据](docs/PROJECT_QUOTA.md)：真实root能力绕过、受限root的EDQUOT、共享硬链接及原盘冷启动检查通过。本分支另有普通驱动quota的实验性接入，cold与真正L1-built snapshot的有限恢复、双实例共享pin/配额检查已通过；quota清零已移出catalog pin锁，普通daemon实际EDQUOT和启动拒绝亦已有有限检查；quota启用时的整state I/O及quota清零后owner/pin仍保留的精确掉电窗口也已有限通过；另有6个固定quota syscall errno注入例通过（额外TEST ONLY启动层，非物理介质故障）；其余完整逐syscall崩溃窗口及quota并发验收尚未完成，不能按生产能力启用。

新增quota显式filesystem提交屏障：普通daemon已更新为 `522da68e…`，真实syncfs内核挂起/pre-fork掉电恢复及有限回归通过；Q_SYNC返回不再被当作独立提交屏障。默认服务兼容矩阵已另完成新原生复验（cold30、双租户各120次snapshot切换、初始化/存储/I/O）；quota模式完整故障/并发验收仍未完成，见[配额证据边界](docs/PROJECT_QUOTA.md)。

新增 [真实quota提交故障证据](docs/QUOTA_COMMIT_FIXTURE.md)：同一普通daemon下，实际syncfs EIO及release前/后clear的真实内核挂起与冷恢复各N=1通过；postclear入口quota虽为零，未完成提交的掉电后仍回到已知限额，因此owner不能提前释放。生产ELF不变；29个执行代际（含失败前序）独立审计已清理。仍是TEST ONLY有限实验，不是完整quota并发、介质或生产验收。

新增 [重复clear与TEST通知器失效检查](docs/QUOTA_LISTENER_FIXTURE.md)：三个clear errno子例各3次后才解除注入；两个最后listener关闭场景实际捕获内核ENOSYS并完成冷恢复。生产ELF不变，生产并不依赖该TEST listener；本轮32个执行代际已独立核验清理，仍不是完整quota并发或生产验收。

新增 [quota双租户忙任务切换夹具与失败证据](docs/QUOTA_SWITCH_FIXTURE.md)：新固定3GiB/4GiB规格、实际旧guest写入进度与独立Stop/持久回收分离。最新720秒有界实验的测量阶段已完成240/240行，但随后同盘cold inode元数据核对失败，整体仍为false。已修正两clone共享inode检查点的采样时序并开始新冻结源重跑；原始失败/分阶段证据保留，不能当作完整冷恢复或生产通过。

目前提供 `mock` 生命周期模拟，以及实验性 Linux/KVM `firecracker` 后端，均需显式选择。mock 没有 CPU、内存或网络隔离，不能执行不可信原生代码；真实后端的生产验收尚未完成。

停止/GC 分池、背压及关闭不变量见 [生命周期调度](docs/LIFECYCLE.md)；控制器暂停时的独立停止路径见 [guardian 租约](docs/GUARDIAN.md)。

生产化范围与验收门槛见 [生产化计划](docs/PRODUCTION.md)。实验性 [guest-agent/vsock](docs/GUEST.md) 组件已通过独立的 jailed KVM 验收，见 [实测报告](docs/validation/kvm-guest-2026-10-22.json)。真实后端的归属、监督与使用限制见 [Firecracker 驱动](docs/FIRECRACKER.md)。独立组件报告不是服务级生产认证，mock 接口始终不提供 VM 隔离。

[前一轮真实后端验收](docs/validation/kvm-observability-2026-10-22.json) 已通过 30 项 KVM 检查：基础服务、控制器 SIGKILL/暂停、硬 TTL、guardian 失效、真实旧 VM 的账本升级恢复、root 创建前归属拒绝、会话冷切换/CAS/崩溃恢复、受控 fsync 阻塞、独立管理指标，以及40次新VM切换闭环。[绑定 fsync 专项](docs/validation/kvm-observability-binding-fsync-2026-10-22.json) 与 [停止/GC 分池专项](docs/validation/kvm-observability-queues-2026-10-22.json) 各9项断言是对应服务用例的展开，不再额外加18个独立场景。尚未覆盖完整生产故障矩阵或切换性能。

[已验收基线源码的冷路径回归](docs/validation/kvm-pristine-cold-service-2026-10-22.json) 使用新agent/镜像再次通过30项服务检查，闭环缩为5次兼容性烟测；不是新的40次负载样本，也未启用服务端快照。对应停止/GC、绑定fsync的各9条断言只是现有用例展开，不额外计数。

目标是先验证：资源归属、停止与销毁的区别、异步回收、失败重试、并发栅栏，以及管理进程崩溃后的回收。

新增实验性 [会话绑定与冷切换](docs/SESSIONS.md)：候选 READY 后以 revision 条件切换，旧环境撤权/停止/回收分离，普通 per-VM 执行接口不能绕过会话准入。已通过真实 KVM 冷路径验收；该历史报告不包含快照/预热，约1.45s到新命令首次成功的冷切换单样本不是生产百分位或SLO。

实验性 [独立管理指标](docs/OBSERVABILITY.md) 使用显式开启的私有Unix socket、固定基数直方图与原子gauges；不作为可靠审计或停止/销毁证明。40次实机闭环的首命令成功P50/P95为1.53/1.62s；67秒有限测试不是长期稳定性或生产SLO。

实验性 [干净模板初始化闸门](docs/PRISTINE.md) 将未分配模板与正常执行端口分离，恢复后必须重新注入身份/熵并完成封存健康检查。已通过真实KVM双克隆组件验证及新agent冷启动15项回归；该报告不覆盖新schema2 catalog/服务接入；新服务路径的有限同机验收见下文，仍无预热池，默认schema1仍为冷启动，不构成生产验收。

开发分支新增 [schema2快照catalog/服务接入](docs/CATALOG.md)，[私有umask修正后真实服务报告](docs/validation/kvm-umask-service-v1.json) 已通过10条有限检查，含5次实际恢复切换、锁下Stop/阻塞GC、活引用退役、SIGKILL恢复与丢失ownership拒删。新首命令成功626–742ms、旧执行停止648–761ms、旧代持久销毁725–812ms，仅为这5次同机观测，不是百分位、加速比或SLO；独立Create的3个样本为662–2579ms，不应只挑暖路径。默认schema1仍冷启动，[修正后新源码冷路径](docs/validation/kvm-umask-cold-v1.json) 另通过30项回归；另有[修正后初始化故障实机报告](docs/validation/kvm-umask-initialization-v1.json)：两个精确宿主崩溃屏障及三类ACK/epoch故障通过，均验证普通daemon恢复、旧创建键拒绝和完整私有回收。另有[guest内部故障测试镜像证据](docs/CATALOG.md)：未修改agent的部分初始化失败，以及明确标记为compiler-overlay的认领后标记前崩溃，均拒绝候选并回收。它们不代表完整故障矩阵；共享内存记账、持续负载与生产验收仍未完成。

新增 [双租户快照负载与资源曲线](docs/MIXED_LOAD.md)：两租户各120次、246.267秒的有限混合闭环通过，分别观测首次新命令、旧host停止和持久回收；保留404个PSS/cgroup/mincore/私有盘样本及前次失败记录。共享驻留、映射和cgroup charge不能相加；这不是开放到达压测、公平调度、完整RAM计费或生产SLO，完整M4仍未完成。

## 已实现

历史 [c577真实ext4 ENOSPC基线](docs/STORAGE.md)：guest写满128MiB工作盘，以及小卷数据块/inode耗尽×忙碌/空闲VM共5场景通过。小卷只在独占mount namespace内填充，未填满共享宿主盘；持久删除失败不假称成功、不提前还容量，释放空间后同state恢复并拒绝旧key。旧daemon空闲VM约4.3–5.0秒停止，不是当前D2dc的时延；当前程序的新回归见上方[物理Stop](docs/EMERGENCY_STOP.md)和[EROFS](docs/READONLY.md)。EIO、掉电、宿主配额和完整M2仍未完成。

- HTTP 控制面使用 Go 标准库；Linux 宿主时钟/guardian 和实验性 guest 使用固定版本的 vsock/x/sys 依赖。要求 Go 1.25+，守护进程支持 macOS/Linux。
- HTTP over Unix socket，不监听 TCP；私有状态目录 `0700`、socket `0600`。
- 状态目录单进程锁；账本按实例原子写入，写文件和父目录均执行 fsync。
- `CREATING → READY → STOPPING → STOPPED → RECLAIMING → DESTROYED`。
- `generation` 栅栏；销毁接受后拒绝新执行。generation **不是用户认证凭证**。
- 异步执行、超时、总输出字节上限、执行历史数量上限、实例 TTL。
- 令牌摘要鉴权、服务端租户归属、节点与租户实例配额；见 [身份与幂等契约](docs/AUTH.md)。
- 创建幂等 key：并发重试共享同一实例，冲突参数拒绝，重启后保留 tombstone。
- 删除幂等、部分创建失败回滚、清理失败退避重试。
- 未回收实例仍占用容量；账本确认 `DESTROYED` 后才归还容量。
- 重启后不复活旧实例：所有非终态实例被栅栏并回收。
- Linux guardian 独立监控 Ref-bound 5 秒短租约与不可延长的 BOOTTIME 硬截止；UTC 到期时间仅供展示。
- 模拟工作区读写使用 `os.Root`，限制路径及符号链接越界。

源码兼容最低 Go 1.25；涉及镜像/部署应使用已打补丁的受维护工具链，本轮安全扫描基线为 Go 1.27.3。旧版本兼容性 CI 不代表生产安全认证。

## 第一轮运行

```sh
go test -race ./...
go vet ./...
make build

# 使用独立的临时目录，不要放入宿主机秘密或已有业务数据。
STATE_DIR="$(mktemp -d)"
./bin/sandboxd -backend mock -insecure-mock -state-dir "$STATE_DIR"
```

上面的 `-insecure-mock` 是显式的无鉴权本地模拟模式。带令牌的启动方式见 [鉴权指南](docs/AUTH.md)，默认不指定鉴权模式会拒绝启动。

在另一个终端操作（将路径替换成刚才的 STATE_DIR）：

```sh
SOCKET=/absolute/path/to/state/api.sock
./bin/sandboxctl -socket "$SOCKET" health
./bin/sandboxctl -socket "$SOCKET" create -ttl 1m

# 从 create 返回的 JSON 中取得 ID 与 GENERATION。
ID=replace-with-id
GENERATION=replace-with-generation

./bin/sandboxctl -socket "$SOCKET" exec -wait "$ID" "$GENERATION" echo hello
./bin/sandboxctl -socket "$SOCKET" exec -wait "$ID" "$GENERATION" write note.txt hello
./bin/sandboxctl -socket "$SOCKET" exec -wait "$ID" "$GENERATION" read note.txt
./bin/sandboxctl -socket "$SOCKET" exec -wait -timeout 50ms "$ID" "$GENERATION" sleep 1s
./bin/sandboxctl -socket "$SOCKET" stop "$ID" "$GENERATION"
./bin/sandboxctl -socket "$SOCKET" destroy -wait "$ID" "$GENERATION"
```

mock 仅实现 `echo`、`sleep <Go duration>`、`write <相对文件路径> <内容>`、`read <相对文件路径>`、`fail`。没有 shell 展开，`bash`、`sh` 等命令会失败。文件工具暂不创建父目录。执行结果保存在内存，销毁后不保留；控制器重启也不会恢复执行历史。

## HTTP 契约

| 操作 | 接口 | 语义 |
|---|---|---|
| 创建 | `POST /v1/sandboxes` | 返回 201 READY；准备失败则安排清理 |
| 查询 | `GET /v1/sandboxes/{id}` | 查询当前阶段与时间戳 |
| 执行 | `POST /v1/sandboxes/{id}/exec` | 返回 202 与 execution id，结果通过查询获取 |
| 执行结果 | `GET /v1/sandboxes/{id}/executions/{job}` | 返回状态、退出码、输出与截断标记 |
| 停止 | `POST /v1/sandboxes/{id}/stop` | 成功返回时驱动已确认停止，已登记执行已退出 |
| 销毁 | `DELETE /v1/sandboxes/{id}` | 202 只表示接受；轮询直到 DESTROYED |

执行请求示例：

```json
{
  "generation": "create-returned-generation",
  "argv": ["echo", "hello"],
  "timeout_ms": 1000
}
```

停止、销毁的 JSON 请求体为 `{"generation":"..."}`。实例级执行限制在创建时设置：

```json
{
  "ttl_ms": 300000,
  "limits": {
    "max_exec_ms": 5000,
    "max_output_bytes": 16384,
    "max_jobs": 64
  }
}
```

鉴权模式下创建必须带 `Idempotency-Key`，其他接口均按令牌对应租户授权，跨租户资源返回 404。参数和状态契约见 [AUTH.md](docs/AUTH.md)。

单次请求体最大 64 KiB，argv 总大小最大 32 KiB；执行历史达到上限后拒绝新增，避免无限增长。`max_output_bytes` 是 stdout 与 stderr 合计的字节上限。执行错误、超时等也占用一条历史。

`sandboxctl` 默认输出 JSON。未加 `-wait` 的执行只表示任务被接受；执行是否成功请检查最终 `status` 和 `output.exit_code`，不能把 HTTP 202 当成执行成功。

## 自动验收

```sh
make smoke

# 更多循环；可把测试临时目录放到自己的 work 目录。
python3 scripts/smoke.py \
  --daemon bin/sandboxd --cli bin/sandboxctl \
  --work-dir /absolute/path/to/work --cycles 200
```

测试会启动真实守护进程、通过 Unix socket 调用接口，并测试：第二个控制器抢锁失败、超时、旧 generation 拒绝、命令停止、重复销毁、SIGKILL 后重启清理，以及重复创建/执行/销毁后的私有工作区回收；还会以真实进程验收令牌鉴权、租户隔离、配额和重启后的创建幂等性。**所有这些仍是 mock 测试，不是 microVM 性能测试。**

## 为什么暂时用文件账本，而不是 SQLite

账本实现暂不引入数据库依赖，当前使用一个实例一个 JSON 记录，采用 `fsync → rename → fsync(directory)`。它只允许一个控制器写入，不是多节点数据库。文件系统必须提供相应的本地文件系统语义，不应直接放在语义不明的网络挂载上。

销毁后的 tombstone 永久保留；当前有节点/租户累计记录准入预算、严格版本化读取和离线迁移，但没有自动归档/过期删除。创建幂等 key 与归属会随账本保留，同 key 不会在销毁/重启后悄悄创建新实例，详见 [契约](docs/AUTH.md)。容量参数、v0 升级和保留政策见 [账本治理](docs/LEDGER.md)。长期归档/轮换、持续负载容量证据及请求限流仍未完成。

## 接入真实 Firecracker 的边界

核心接口在 `internal/sandbox/types.go` 的 `Driver`，后端实现如下职责：

1. **Prepare**：按 Ref 登记资源，再准备私有工作盘、cgroup、jailer、Unix socket，并启动 VM；资源限制落实、guest-agent 健康检查通过后才成功。
2. **Exec**：通过 vsock 调用 guest-agent，保持命令、文件读写位于同一 guest 工作区；不得回退为宿主机执行。
3. **Stop**：终止实例所属执行单元和专属辅助进程，并确认退出；不能只发送信号后返回成功。驱动必须配合 context 的有界操作约定。
4. **Cleanup**：幂等回收该 Ref 的私有资源，不能删除仍被其他实例使用的基础镜像、快照或全局共享服务。

实验性 Firecracker 驱动已经接入鉴权与生命周期，采用持久归属、出生即入 cgroup 的 warden、EOF/短租约/硬截止整组停止和私有复制工作盘。仍缺少完整故障/重启/负载验收、业务网络策略、快照恢复、预热池、会话原子切换与多节点调度；详见生产门槛和驱动限制。

重启策略当前是“全部回收”，不是“自动恢复会话”。后端名不匹配时拒绝恢复。管理服务收到 SIGINT/SIGTERM 后停止接受请求并尝试回收；超时则非零退出，下次使用同一状态目录继续恢复。

## 结构

```text
cmd/sandboxd          宿主机管理服务（mock / 实验性 Firecracker）
cmd/sandboxctl        Unix-socket 客户端
cmd/xandbox-keygen    私有令牌与摘要配置生成器
cmd/xandbox-agent     Linux guest 专用执行组件
cmd/xandbox-guestctl  Firecracker vsock 诊断客户端
cmd/xandbox-warden    Linux 可信租约/硬截止监督进程
internal/hostclock    Linux BOOTTIME / 非 Linux mock 时钟
internal/lease        私有 Ref-bound 续租协议
internal/firecracker 实验性真实驱动、持久归属与 UID 租约
internal/guest*      guest 执行、受限协议与 bridge 传输
internal/access      令牌摘要校验与服务端租户策略
internal/sandbox     生命周期、账本、驱动接口、mock 与故障测试
internal/httpapi     JSON 接口与契约测试
internal/client      Unix-socket HTTP 传输
scripts/smoke.py      真实进程级验收
```

参考：[Firecracker 运行要求](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md)、[生产宿主配置](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)、[vsock 协议](https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md)。
