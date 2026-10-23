# 节点持久准入控制与操作员边界

本分支增加 `xandbox-node status|drain|resume`，让受信任的同宿主服务 UID 停止或恢复**新资源预留**，而不以 `Manager.Close`、修改不可变 NodePolicy 或停止已有任务来冒充 drain。该生产代码变更需要新的 Linux/KVM 回归；此前 `3ea1e247…` 的报告仍只证明历史程序，不能认证本程序。当前不是生产发布。

## 操作命令

`make build` 生成 `bin/xandbox-node`。服务与客户端使用同一个私有 state 目录；客户端不创建目录、不接受 TCP 地址或租户令牌。

```sh
./bin/xandbox-node -state-dir "$STATE_DIR" status
# 从 status.control.committed 读取 epoch 和 revision，再指定新的 request-id。
./bin/xandbox-node -state-dir "$STATE_DIR" \
  -epoch "$EPOCH" -revision "$REVISION" -request-id "$REQUEST_ID" drain
```

`REQUEST_ID` 是新的 32 位小写十六进制随机标识。可省略 `-request-id` 让 CLI 生成；CLI 在发送前将实际 ID、epoch、expected revision 写到私有 stderr，保存它们用于不确定结果的精确重试。它们不是认证凭证。`resume` 使用同样字段，但必须根据最新 status 的 revision 生成新命令。不要把旧 revision 改成新值而继续沿用旧请求 ID。

| 结果 | 精确含义 |
|---|---|
| drain 成功响应 | 新预留已关闭；drained 状态完成文件和两个目录的提交屏障 |
| resume 成功响应 | open 状态先提交，再开放新预留；后端预算、鉴权、容量等仍可拒绝创建 |
| 最近一次命令的相同 ID、epoch、expected revision、目标模式 | 幂等返回已提交状态；不再次推进 revision |
| 旧 epoch/revision、相同最近 ID 但不同目标或 expected revision | CONFLICT；不开放准入、不改状态 |
| 另一个 mutation 正在提交 | BUSY；不排队，status 仍可查询 |
| PERSISTENCE_FENCED | 提交结果不确定；本进程保持关闭准入，拒绝后续 mutation，须独占重启读取实际持久状态 |
| EOF、超时、客户端取消 | 不能推断已取消；先查 status，或用原命令完整字段精确重试 |

只保留**最后一次已提交命令**的 replay 信息，不是无限请求日志。revision 到 `uint64` 上限时只允许最终 drained 状态，不回绕到旧 revision。

## drain 的线性化与已有请求

准入 gate 在同一短内存临界区与 Core 实例预留、session Open/Switch 的初始预留排序。gate 锁内没有文件 I/O、等待或后端调用。controller 在持久化前关闭 gate；文件提交、status、Stop/Cleanup 分别使用不同同步域。

- drain 之后的新直接创建、新 session、新 Switch 返回 `503 NODE_DRAINING`，不消耗新实例记录、session 记录或切换历史。
- drain 之前已经预留的直接创建仍可完成。已接受的 session 操作持有一次性、仅进程内 `CreationTicket`，允许其随后预留 Core 候选；不能把 ticket 序列化或用于第二个候选。
- 已存在的幂等请求仍按原契约 replay。drain 不是撤回旧请求，也不覆盖会话自己的 revision、容量或 closing 检查。
- 已有 Exec、Stop、Destroy、GC、租约撤权不获取 operator 的持久化锁，也不等待新 prepare 许可。drain 不停止这些操作，不主动停止已有 VM。
- `pending_session_reservations` 只计已接受但还没消费或释放的 session ticket，不计所有后台任务，也不是节点空闲证明。ticket 不跨重启；既有恢复流程继续栅栏和回收旧代，不复活 guest。

`GET /readyz` 在新准入关闭或 manager closing 时返回 503，否则 200。它只表示**准入开关**，不认证磁盘、容量、catalog、KVM 或整体健康。`/healthz` 仍返回 200 并增加 `admission_open`。tenant API 没有 `/v1/node` 管理路由。

## 提交、重启与错误

状态位于 `admission/state.json`，根目录的 `admission.identity` 绑定同一个随机 epoch。采用私有临时文件、文件 fsync、rename、admission 目录及根目录 fsync；Load/Save 核验目录 inode、owner/mode、文件单链接和严格 JSON。Save 还逐字段比较上一提交状态，拒绝运行期间的带外修改。最多容忍 32 个符合命名及私有文件约束的残余临时文件；它们不作为 committed 状态读取，未知目录项拒绝。

**已确认成功的 drain** 在正常同盘重启后保持 drained。未确认命令如果 Save 报错或中途崩溃，磁盘可能仍是旧 open，也可能已是新 drained；本进程的临时 fence 不能被说成已持久提交。独占重启只加载真实有效的已提交命名空间，不发明回滚或“失败的 drain 一定持久”保证。这不是经过介质掉电验收的证明。

真正全新的未使用 state 首次默认 open；存在 sessions、instances、firecracker 或非空 ledger 的旧根，在两份准入元数据都缺失时默认 **drained 且生成新 epoch**。已有 identity 而 state 丢失、epoch 不符或文件损坏则拒绝启动。初始化若只完成 state 提交而未完成 identity，保留 state 的 epoch/mode 并完成 identity 初始化。上述规则不是通用备份恢复协议，不支持删除文件来修复故障。

status 使用内存中最后已知提交状态，不持续重读磁盘；直接编辑文件不受支持。`resource_observation` 是另取的非事务内存观测，不是与控制状态原子的停机、完整回收或备份证书。drain 后仍需另外证明执行停止、持久销毁与执行域/配额/pins 释放；数值全零也不能独自证明这些事实。

退出先关闭 listener、fence 管理入口，让生命周期停止/回收获得独立机会，再有界等待 operator writer。若 writer 仍未返回，必须和未结束的 lifecycle writer 一样保留 `controller.lock` 至进程退出，不能让第二个 controller 与旧提交者同时写根目录。

## 管理权限与资源边界

`operator.sock` 固定在 state 目录，服务端及客户端都校验私有目录和调用者所有权、socket `0600`/单链接，客户端固定根 inode 且每次新连接重验。连接进入 HTTP 之前验证服务 EUID；Linux 使用 SO_PEERCRED，macOS 使用 LOCAL_PEERCRED。租户 bearer 无管理权，即使内容有效也被拒绝。管理 HTTP 只接受固定三条路由、严格命令结构及枚举，禁 query/转义路径/Authorization/Origin；最多 16 个连接、一个在途 mutation，限制 header/body/reply 和网络读写时间。

Linux SO_PEERCRED 是**连接建立时**的身份，不是每个请求当前执行者的身份；同 UID/root 可以主动委托已建立的 FD。本设计不防恶意宿主管理员，也不把一个 UID 内的不同进程隔离成不同管理员。[Linux unix 手册](https://man7.org/linux/man-pages/man7/unix.7.html)定义这一凭证语义；macOS 凭证版本对照 [Apple ucred 定义](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ucred.h)。不要让不可信代理与服务共享管理 UID、转交管理 FD 或转发 root socket。guest 不继承这个管理连接。

这些限制只限制协议内的输入与连接，不是全节点 CPU/磁盘硬预算；本地文件 I/O 仍可能无限阻塞。独立持久审计、云网关 TLS/身份代理/限流、备份回滚、systemd 安装器、全节点持续压力与故障尾部验收尚未完成。

## 可重复的当前验证

```sh
GOTOOLCHAIN=go1.27.3 go test -race -count=3 ./...
GOTOOLCHAIN=go1.27.3 go vet ./...
GOTOOLCHAIN=go1.27.3 make smoke
# 也可只跑实际 daemon 和 CLI 的 MOCK 进程验收。
python3 scripts/node_control_smoke.py \
  --daemon bin/sandboxd --node bin/xandbox-node --report /private/new-result.json
```

单测覆盖 gate 排序、已接受 session ticket、阻塞 Save 时 status/Exec/Destroy 继续、提交前后报错的不同重启结果、取消/冲突/精确重试、关闭后迟到 resume 不重开、未返回控制 writer 保留 state 锁、socket/根替换及协议负例。模拟 Store 的错误不是实际 filesystem D、EIO 或掉电注入；同 UID 内核正例加 UID 比较单测也不是另 UID 的内核拒绝验收。

进程脚本使用两个实际 mock daemon 启动和 CLI 子进程，验证 drain 后旧 raw/session 命令执行成功、新预留不写元数据、Stop/Destroy 完成、重启保留已确认 drain、陈旧 resume 拒绝、恢复后原拒绝 key 可用，最后五个 mock 代际均持久销毁。它**没有隔离能力，也不是 KVM、真实故障窗口或性能报告**。新生产 ELF 的独立交叉/原生构建及全部 DEFAULT/IO、quota240/双活cold/故障与节点取消矩阵必须另行绑定，不能复用旧 ELF 结论。

### 冻结源码的预验收结果

以下是当时冻结源的预验收范围；后续新生产 ELF 的有限实机结果见[operator KVM 与同盘冷恢复](NODE_OPERATOR_KVM.md)，不回写这份历史预验收报告的 false 字段。

冻结源 `b2afd3e1dd6e84d56001f77098fe4cdd474f0cad`，归档 SHA-256 `6574c3bf…`。[来源与未完成门槛](validation/node-control-prequalification-v1.json)绑定全部 43 个本次变更输入及六个 Linux 产物；独立冻结归档交叉构建与 Linux 原生构建逐字节相同。新 daemon 为 `4ee09d0a…`，新 node CLI 为 `fd700c39…`，不能继续沿用旧 `3ea1e247…` 的硬件结论。

该冻结源的 Darwin/Linux 全量 race×3、vet 通过；Linux opt-in fixture race×10/vet、CGO-free 内核 quota filter×3、root Python 82 项（零跳过）与完整 make smoke 通过。[Darwin](validation/node-control-darwin-process-v1.json)和[Linux](validation/node-control-linux-process-v1.json)的实际 daemon/CLI 报告均明确 `hardware_qualification=false`。固定 probe 的 whole-ELF、符号与九处指令字节已离线核验，但尚未运行新程序的实机 probe。

开发阶段的 umask 负例构造、首版脚本执行状态枚举及旧根 metadata 测试预期曾失败，原因与修正保留在来源清单；未将失败改写为通过，也未放宽旧根 drained 默认。冻结源上述测试没有失败；这批预验收没有启动新的 L1/KVM 用例。当时尚未验证 operator 的异 UID 内核拒绝、实际状态盘故障/掉电及新 KVM 矩阵；后续有限实机证据按上方链接单独绑定，真实提交故障窗口与完整矩阵仍未完成。

后续[实际 FileStore 的两个 fsync TEST errno 窗口](NODE_OPERATOR_STORE.md)已单独验证 pre-rename 与 post-admission-directory 的 pending、caller 取消、一次 EIO、内存 fence 与不同 cold namespace 结果。它执行真实 Store 而非模拟对象，但不是实际 filesystem D/介质故障或全部提交窗口验收；旧预验收与前轮健康 ACK 报告仍保持冻结范围。

后续[新4ee默认/IO与quota240、双活cold和命名故障复验](RUNTIME4EE_REQUALIFICATION.md)已实际完成25个scope，并独立核验43个外层执行代际和4个专属loop绑定无残留。它另绑冻结源及新原始报告，不回写本页旧预验收false字段；新4ee schema3 prepare/cancel/trace/完整节点压力、pre-Core reservation与未完成control writer的shutdown锁窗口仍未完成。
