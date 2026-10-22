# Xandbox

[![CI](https://github.com/123123213weqw/Xandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/123123213weqw/Xandbox/actions/workflows/ci.yml)

Go 实现的云端短生命周期沙箱基础设施，采用 MIT 许可证。

**状态：生产化开发中，尚未生产就绪。**

目前提供 `mock` 生命周期模拟，以及实验性 Linux/KVM `firecracker` 后端，均需显式选择。mock 没有 CPU、内存或网络隔离，不能执行不可信原生代码；真实后端的生产验收尚未完成。

停止/GC 分池、背压及关闭不变量见 [生命周期调度](docs/LIFECYCLE.md)；控制器暂停时的独立停止路径见 [guardian 租约](docs/GUARDIAN.md)。

生产化范围与验收门槛见 [生产化计划](docs/PRODUCTION.md)。实验性 [guest-agent/vsock](docs/GUEST.md) 组件已通过独立的 jailed KVM 验收，见 [实测报告](docs/validation/kvm-guest-2026-10-22.json)。真实后端的归属、监督与使用限制见 [Firecracker 驱动](docs/FIRECRACKER.md)。独立组件报告不是服务级生产认证，mock 接口始终不提供 VM 隔离。

[最新真实后端验收](docs/validation/kvm-session-phases-2026-10-22.json) 已通过 27 项 KVM 检查：基础服务、控制器 SIGKILL/暂停、硬 TTL、guardian 失效、真实旧 VM 的账本升级恢复、root 创建前归属拒绝、会话冷切换/CAS/崩溃恢复及受控 fsync 阻塞用例。[绑定 fsync 专项](docs/validation/kvm-session-phases-binding-fsync-2026-10-22.json) 与 [停止/GC 分池专项](docs/validation/kvm-session-phases-queues-2026-10-22.json) 各9项断言是对应服务用例的展开，不再额外加18个独立场景。尚未覆盖完整生产故障矩阵或切换性能。

目标是先验证：资源归属、停止与销毁的区别、异步回收、失败重试、并发栅栏，以及管理进程崩溃后的回收。

新增实验性 [会话绑定与冷切换](docs/SESSIONS.md)：候选 READY 后以 revision 条件切换，旧环境撤权/停止/回收分离，普通 per-VM 执行接口不能绕过会话准入。已通过真实 KVM 新路径验收；仍无快照/预热加速，约1.45s到新命令首次成功的冷切换单样本不是生产百分位或SLO。

## 已实现

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
