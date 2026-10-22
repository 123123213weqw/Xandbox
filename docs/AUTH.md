# 控制面身份、配额和幂等创建

本页描述已实现的控制面契约，**不是虚拟机隔离验收**。当前驱动仍是 mock，服务仍只监听私有 Unix socket，不直接监听公网 TCP。

## 生成凭证并运行

```sh
make build
PRIVATE_DIR="$(mktemp -d)"
./bin/xandbox-keygen -tenant demo -max-instances 4 \
  -token-file "$PRIVATE_DIR/demo.token" \
  -config-file "$PRIVATE_DIR/auth.json"

./bin/sandboxd -backend mock -state-dir "$PRIVATE_DIR/state" \
  -auth-file "$PRIVATE_DIR/auth.json" -max-instances 32
```

另一个终端中，将 `PRIVATE_DIR` 替换为上面生成的绝对路径：

```sh
PRIVATE_DIR=/absolute/path/to/private-directory
./bin/sandboxctl -socket "$PRIVATE_DIR/state/api.sock" \
  -token-file "$PRIVATE_DIR/demo.token" \
  create -ttl 1m -idempotency-key example-request-1
```

keygen 使用操作系统随机源生成 256 位随机令牌。原始令牌仅写入客户端文件；服务端配置仅包含 SHA-256 摘要、租户 ID 和实例配额。两个文件均以 `0600` 新建，拒绝覆盖已有文件。不要使用可猜测密码代替生成的令牌，也不要把令牌放进命令行参数、Git 或日志。

配置格式为 `version: 1`，`keys` 是具有 `token_sha256`、`tenant_id`、`max_instances` 字段的对象数组。支持 1–256 个摘要；同一租户的所有 key 必须配置相同配额。租户 ID 为 1–64 位 ASCII 字母、数字、`_` 或 `-`，首位为字母或数字；配额范围为 1–10000。

鉴权配置在启动时读取，不支持热更新。需要多个租户或轮换时，由操作员在私有目录中合并摘要配置；同时列出同租户的新旧摘要可在下一次启动时接受两者。移除旧摘要需要再次重启。**当前重启策略会回收所有现有实例**，并非无损凭证轮换。客户端文件和配置均必须为私有普通文件，不能是符号链接；父目录也必须由可信操作员控制。

## 权限边界

- 除 `GET /healthz` 外，请求均需要一个 `Authorization: Bearer <token>` 请求头；重复鉴权头、无效令牌和未知令牌均返回统一的 401。
- 健康检查只公开后端名、认证是否启用以及未完成真实隔离验收的声明；鉴权模式不公开全节点实例数量。
- 租户身份和实例配额只来自服务端配置；`X-Tenant-ID` 不参与授权，JSON 中的 `tenant_id` 是未知字段，返回 400。
- 实例查询、执行、执行结果、停止和销毁均检查归属。即使知道 ID、generation 和 execution ID，跨租户请求仍返回与不存在资源相同的 404。
- generation 只负责防止代际误操作，不能替代身份认证。
- 节点总配额与每租户配额原子预留。`STOPPED`、`STOPPING`、`RECLAIMING` 仍占容量，只有持久化 `DESTROYED` 后才归还。租户配额耗尽返回 429，节点容量不足或服务关闭返回 503；同时耗尽时可先返回节点级 503。

这是面向 API 调用者的授权边界，**不抵御已拥有守护进程 UID 或宿主机权限的进程**。Unix socket 的 `0600` 和状态目录的 `0700` 仍是必要条件。不要把任意宿主程序当成安全租户，也不要简单将 UDS 暴露为公网反向代理；公网入口的 TLS、请求限流、凭证分发和独立身份系统尚未实现。

若只是本地模拟，可以显式指定 `-insecure-mock`。它与 `-auth-file` 互斥，只允许 mock 驱动；不指定任何模式时启动失败，不会静默关闭鉴权。

## 创建幂等性

鉴权模式下，`POST /v1/sandboxes` 必须带唯一的 `Idempotency-Key`。key 是 1–128 字节、无空格的可打印 ASCII；建议使用随机值。它不是认证凭证。

| 条件 | 结果 |
|---|---|
| 同租户、同 key、相同规范化参数，实例仍 READY 且未过期 | 201，返回同一 ID 和 generation，不再次 Prepare、不再占配额 |
| 同租户、同 key、参数不同 | 409 `IDEMPOTENCY_CONFLICT` |
| 同 key 正在 Prepare | 等待首次准备完成；等待者遵守自己的请求 context |
| 原创建失败、已停止、到期、正在删除或已销毁 | 410 `IDEMPOTENCY_GONE`；只有显式换新 key 才会创建新实例 |
| 不同租户使用相同 key | 两个独立的创建请求 |
| 未提供 key / 重复请求头 / key 不合法 | 400 |

TTL 和执行限制先补默认值，再计算请求摘要。因此省略默认值与显式填写相同默认值等价。账本仅存 key 与规范化参数的摘要，不存原始 key；普通 API 也不暴露这些摘要。

幂等检查先于配额检查，所以首次创建已经用完配额时，合法重试仍可以取回原实例。并发请求共享首次 Prepare 的结果，不会创建多个实例。若首次账本写入报错，可能已经完成原子替换；控制器保留并栅栏该 key，安排清理，不能直接释放记录或继续准备资源。

`sandboxctl create` 未指定 key 时会生成随机 key，并在发请求**之前**把 key 写到 stderr；出现丢失响应等情况时，使用同一个 `-idempotency-key` 和相同参数重试。客户端不自动跟随 HTTP 重定向，避免将认证请求转发至其他地址。

当前 tombstone 和 key 摘要没有到期删除：重启后也不会因重试而复活旧 generation。旧版本没有租户字段的记录按 `local` 迁移为内存归属，非终态仍按原规则全部回收。**账本版本升级协议、元数据保留/压缩、累计记录容量限制和创建速率限制仍未完成**；实例配额不能替代这些上限。

## 错误和数据

普通 API 使用显式字段投影；账本内部错误及 driver 错误不原样返回，避免泄露宿主机路径或操作员配置。任务合法执行产生的 stdout/stderr 则仅通过所属租户的执行结果接口返回，并受输出字节上限约束。当前没有完整审计系统；守护进程不记录请求头、argv 或任务输出。

请求/配置拒绝未知字段、重复 JSON 字段（包括 Unicode 大小写等价）和多个顶层对象；请求最大 64 KiB。JSON 严格解析不是限流或运行时资源隔离的替代品。

## 复现测试

```sh
go test -race -count=10 ./...
go vet ./...
make smoke
```

`make smoke` 包含原有生命周期验收和独立的鉴权进程验收：临时生成凭证、启动拒绝策略、跨租户所有资源操作、配额、创建重试/冲突、CLI、SIGKILL 后的幂等与归属恢复。所有凭证和状态放在临时私有目录，测试后删除；仍不包含真实 KVM 执行。
