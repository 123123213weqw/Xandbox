# 开始使用 Xandbox

当前是**可受控试用的单节点实现，尚未生产就绪**。主分支合并功能不等于
所有功能通过同一版本的完整生产验收。历史实机报告只证明各自固定的源码、
二进制、规格和命名场景；不要把它们累计成当前版本的整体认证。

## 选哪条路径

| 需求 | 入口 | 边界 |
| --- | --- | --- |
| macOS/Linux 先接通 API、鉴权和生命周期 | 下方本地 mock 示例 | **不执行任意代码，不提供 VM 隔离** |
| 安装前判断节点的基本缺项 | [只读节点预检](NODE_PREFLIGHT.md) | 不修复宿主，不创建 VM，不代表已具备部署条件 |
| Linux 上真实隔离运行命令 | [Firecracker 后端](FIRECRACKER.md)、[guest 构建](GUEST.md) | 需要操作员准备专用 Linux/KVM 节点、镜像和资源域 |
| 会话切换、快照恢复 | [会话协议](SESSIONS.md)、[快照 catalog](CATALOG.md) | 实验性；不是热迁移，也没有预热池 |
| systemd/TLS/固定安装事务 | [初始安装](INITIAL_INSTALL.md)、[部署恢复](OPERATIONS.md) | 实验性；不是通用一键安装或原地升级工具 |

真实后端没有宿主执行 fallback。macOS 的 mock 成功不代表 macOS 能运行
Firecracker，也不代表已经通过 Linux/KVM 验收。

## 1. 获取与构建

```sh
git clone https://github.com/123123213weqw/Xandbox.git
cd Xandbox
git switch main
git pull --ff-only
GOTOOLCHAIN=go1.27.3 make build
```

需要 Git、Go，以及 smoke 测试所需的 Python 3。`make build` 在 Linux 额外构建
agent、warden 和 gateway；macOS 只构建该平台支持的程序。
此处工具链版本对应仓库已记录的构建基线，不代表未来无需维护更新。

## 2. 本地有鉴权 mock：先跑通调用链

终端 A，使用当前用户执行，**不需要 sudo**：

```sh
umask 077
PRIVATE_DIR="$(mktemp -d /tmp/xb.XXXXXX)"
./bin/xandbox-keygen -tenant demo -max-instances 4 \
  -token-file "$PRIVATE_DIR/demo.token" \
  -config-file "$PRIVATE_DIR/auth.json"
printf '另一个终端请设置 PRIVATE_DIR=%s\n' "$PRIVATE_DIR"
./bin/sandboxd -backend mock -state-dir "$PRIVATE_DIR/state" \
  -auth-file "$PRIVATE_DIR/auth.json" -max-instances 4
```

终端 B，进入同一仓库，把路径替换成终端 A 打印的**实际路径**：

```sh
PRIVATE_DIR=/tmp/xb.REPLACE_ME
./bin/sandboxctl -socket "$PRIVATE_DIR/state/api.sock" health

CREATED="$(./bin/sandboxctl -socket "$PRIVATE_DIR/state/api.sock" \
  -token-file "$PRIVATE_DIR/demo.token" create -ttl 5m \
  -idempotency-key first-demo-1)"
ID="$(printf '%s' "$CREATED" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
GENERATION="$(printf '%s' "$CREATED" | python3 -c 'import json,sys; print(json.load(sys.stdin)["generation"])')"

./bin/sandboxctl -socket "$PRIVATE_DIR/state/api.sock" \
  -token-file "$PRIVATE_DIR/demo.token" exec -wait "$ID" "$GENERATION" echo hello
./bin/sandboxctl -socket "$PRIVATE_DIR/state/api.sock" \
  -token-file "$PRIVATE_DIR/demo.token" exec -wait "$ID" "$GENERATION" write note.txt hello
./bin/sandboxctl -socket "$PRIVATE_DIR/state/api.sock" \
  -token-file "$PRIVATE_DIR/demo.token" exec -wait "$ID" "$GENERATION" read note.txt
./bin/sandboxctl -socket "$PRIVATE_DIR/state/api.sock" \
  -token-file "$PRIVATE_DIR/demo.token" destroy -wait "$ID" "$GENERATION"
```

检查执行结果的 `status` 和 `output.exit_code`，以及最后的 `DESTROYED`；
HTTP 202 或请求返回成功不等于任务成功、执行停止或持久回收全部完成。
销毁后重建请换新幂等 key。停止 daemon 可在终端 A 按 Ctrl-C。

mock 只支持 `echo`、`sleep`、`write`、`read`、`fail` 等固定模拟命令；
`sh`、Python、任意上传程序不会在 mock 中执行。上述 `/tmp` 路径仅用于本地
mock，不能作为 root Firecracker 部署目录。不要把 token、auth 配置或运行态数据提交到 Git。

## 3. 真正运行隔离代码：Linux/KVM

先在目标节点以普通用户执行：

```sh
./bin/xandbox-doctor
```

它会给出固定格式的基本缺项，包括运行中的 systemd 版本，而不是自动更改宿主。
当前 systemd 组合需要 254+；版本过低应选择专用兼容环境，不能默默升级共享节点。
退出 0 也只表示所检查的基本条件满足，仍需完成下面各项。详见[预检边界](NODE_PREFLIGHT.md)。

真实后端需要单独准备，不能只把上例 `mock` 改成 `firecracker`：

1. 专用 Linux 节点，可读写 `/dev/kvm`，cgroup v2 与所需控制器、
   `clone3`/namespace 能力满足[后端要求](FIRECRACKER.md)。
2. root 所有、不可由其他用户写入的短路径资产目录、专用 UID/GID 范围、
   状态与 runtime 目录，以及操作员委派的 cgroup 根。不要使用共享业务资源域。
3. 按 [guest 指南](GUEST.md) 准备固定摘要的 Firecracker/jailer、kernel、
   agent/initrd 与空白 ext4 工作盘。Python 等语言运行时必须包含在 guest 镜像中。
4. 按 [Firecracker 配置](FIRECRACKER.md) 绑定**实际**路径、摘要与预算；
   schema3、项目 quota、IO 与 systemd 组合另有前置条件，不能混用不同 schema 的配置。
5. 按目标部署形态完成受控验收，再接入业务。仓库的 TEST fixture/helper 不是
   生产入口，不应把 owned-L1 故障脚本直接作为共享宿主的安装命令。

初次部署只使用新状态目录；daemon 重启会栅栏并回收旧实例，不恢复旧会话。
不要在已有部署上直接覆盖二进制、删除绑定/账本或改配置绕过检查；当前不提供
完整原地升级、回滚和迁移承诺。尚未配置 guest 业务网络，也没有多节点调度或热迁移。

## 4. 验证与限制

```sh
GOTOOLCHAIN=go1.27.3 make smoke
```

这验证本地进程/API/mock 集成，**不是 KVM 性能或隔离验收**。
完整软件回归、Linux/KVM 场景和未完成门槛见 [生产化计划](PRODUCTION.md)。
运行中错误需要保留同一状态目录和原请求用于排查，不要用清空目录冒充恢复。

销毁表示逻辑资源回收，不代表 SSD 物理擦除。快切换、物理 Stop 和持久回收
是三个独立指标，当前没有生产 P99 或最坏延迟承诺。
