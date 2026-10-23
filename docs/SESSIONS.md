# 实验性会话绑定与冷切换

**不是快照/预热加速，也不是生产就绪。** 此页定义会话 `revision` 与 VM `Ref` 的关系。当前每次新建独立 VM/工作盘，不恢复使用过的 guest。原 [生产门槛](PRODUCTION.md) 完整保留。

## 切换顺序

```text
持久 PREPARING（保留原绑定与请求摘要）
 → Core 按独立命名空间预留新 Ref，归属 fsync 后才分配 VM
 → 候选 VM READY，持久 PREPARED
 → 原子撤销旧会话路由 + Core 非阻塞删除意图
 → 持久新 revision/Ref 绑定
 → 检查候选仍可用，发布新路由
 → 旧 VM 的 host Stop / 私有 Cleanup / 持久 DESTROYED 独立推进
```

准备候选和写 PREPARED 时，原版本仍可执行。旧路由撤销后，不回滚或重新开放旧 generation。最后绑定写入错误/不确定提交会关闭整个会话并栅栏旧/新 VM，等待回收；不把“可能成功”伪装成已提交路由。

切换可以在旧 VM 尚未完整回收时返回，因此**新绑定 ≠ 旧执行已停止 ≠ 旧资源已回收**。使用返回的 `previous` Ref 查询原有 per-VM 生命周期；旧资源在持久 DESTROYED 前仍占节点/租户实例与 UID 容量。需要至少两个实例的明确配额和物理余量；连续切换可能被尚未完成的 GC 背压拒绝，不临时绕过配额。

## 不能绕过版本准入

- `expected_revision` 用于 switch 的比较条件，exec 也必须提供 revision。过时请求不重新解析到最新 VM。
- 同一会话一次只有一个变更准备候选；同 key/相同参数并发共享结果，不同 key 的并发变更得到 BUSY 或 STALE，不创建两个赢家。
- Core 在真正登记任务前再次检查会话 capability/version/Ref；解析到旧绑定后等候记录锁的请求也不能迟到准入。
- 会话管理的 VM 禁止通过普通 `/sandboxes/{id}/exec` 执行。Ref/generation/revision 都不是身份凭证；仍检查服务端租户。
- managed 创建 key 在 Core 内额外做包含 NUL 的域分离哈希；普通可打印 ASCII 创建 key 不能预占会话候选，避免把已使用 VM 伪装成新候选。
- Core 在 ownership fsync **之前**把新 Ref 仅在内存交给可信控制器回调。即使随后记录 I/O 卡住，关闭会话/取消准备也能原子撤销该 Ref 的续租与准入。该回调不是租户 RPC，不执行 I/O。

## HTTP 契约

所有接口适用现有令牌租户授权；请求/响应 JSON 有大小边界。普通错误不回传底层路径、账本摘要或原始驱动错误。

| 操作 | 接口 | 主要请求/结果 |
|---|---|---|
| 打开会话 | `POST /v1/sessions` | 必须 Idempotency-Key；body 同 CreateRequest；201 返回 id/revision=1/current Ref |
| 查询 | `GET /v1/sessions/{id}` | 当前计划、has_binding、阶段、retired 与 discarded_candidates Ref |
| 切换 | `POST /v1/sessions/{id}/switch` | 必须 Idempotency-Key；`{"expected_revision":1,"create":{"ttl_ms":60000}}` |
| 执行 | `POST /v1/sessions/{id}/exec` | `{"revision":2,"argv":["echo","hello"],"timeout_ms":1000}`；202 返回 revision、sandbox Ref、job |
| 撤销会话 | `POST /v1/sessions/{id}/revoke` | `{"expected_revision":2}`；只确认准入撤销，durable/stop_confirmed/reclamation_confirmed 均为 false |

执行结果使用返回的**具体 sandbox Ref + job.id**查询既有 execution 接口，不能查询会话最新 VM 来猜旧任务归属。202 不是任务成功。GET 的 `has_binding` 只是存在选定路由，不是对 guest 存活/TTL 的授权证明；执行仍重新验证 Core 期限。COMMITTING 时没有可执行路由，观察到的计划 revision/Ref 不等于发布确认。

同 key 重试只有当前绑定仍是该次成功结果时才返回它；不会把历史 key 重定向到更新 revision。冲突参数 409；失败、已被后续切换或已关闭的尝试 410。准备前/中失败保留原路由（若原来仍活着），但该次尝试 key 仍被保留，需要显式换 key；简单重复被拒绝的 key 不会创建另一个候选。

取消在旧路由撤销前中止候选、保留旧路由；取消与撤销点由短内存锁仲裁。旧路由一旦被撤销，请求连接取消不能撤销提交或复活旧 VM，事务继续提交或关闭。响应丢失后用同 key/相同参数查明结果，不假设网络超时就是停止/回收。

## 崩溃与关闭

会话账本不是资源分配的唯一真相；Core 的持久 VM 账本/driver ownership 才是执行资源权威。**任何控制器重启都关闭全部旧会话路由**，不复活先前 revision，不自动恢复会话或脏 VM。Core 同时回收全部旧非终态 VM；哪怕崩溃发生在候选已创建但 Session 尚未写入其 Ref 的窗口，也不遗失该资源的权威账本。

加载会话时先验证全目录、版本、修订链和不可变 Core 归属，再写恢复栅栏。存在不一致的已绑定 Ref 时拒绝启动，而不是操作别的租户资源。失败候选可能尚无持久 Core 记录，其缺失也不被宣传为物理销毁证明。

关闭先原子关闭路由/撤销所有已预留 Ref，不等待 Session fsync。单个有界 journal worker 重试 CLOSED；不同会话的前台写入不持有全局 I/O 锁。关闭期限返回错误不表示写入者已退出：daemon 保持同一 controller.lock，直到进程退出；嵌入者必须保持独占，等待 Broker.Done 与 Core 的调用/生命周期真正收敛。迟到写入不能重新开放 CLOSED 路由。

## 元数据预算与格式

- `-max-sessions` 默认1000，范围1..10000；包含 CLOSED/tombstone。
- `-max-tenant-sessions` 默认 min(100,max-sessions)，包含关闭和不确定提交。
- `-session-history` 默认64，范围1..64，**包含初次打开**；失败尝试也占历史预算，不静默丢弃旧 key。
- 独立 `sessions/` v1 envelope；单记录128KiB，分批目录读取，最多10000条、21024目录条目；未知版本/字段、重复 key、坏修订链、重复目标及非私有文件拒绝。
- 总 Session 预算不替代 Core 累计记录/实例预算、物理内存/磁盘 quota 或请求限流。永久保留与长期归档/轮换的缺口仍见 [LEDGER.md](LEDGER.md)。

## 指标语义与验证状态

响应 timings 使用进程内宿主单调时钟：candidate_ready_ms、admission_revoked_ms 是从操作进入到阶段边界的偏移；fence_to_commit_ms 是撤销到持久绑定写入完成；total_ms 截止路由发布，不含 HTTP 传输。measured=false 不是零延迟证据。它们是过程观测，可能在后续 journal 写入时保留；没有为保存“自己的 fsync 时长”再添加一次 fsync，也不承诺最后一组观测在崩溃后仍在。

本地 mock 进程入口 `scripts/session_smoke.py` 验证鉴权、CAS、独立新工作区、普通执行绕过拒绝和真实 SIGKILL/重启；**不是 microVM 性能**。普通 race/故障测试覆盖同 key 并发、迟到准入、准备取消、不可撤销点后的取消、绑定 fsync 卡住、失败 Close、迟到提交和永久 key/容量。

真实 KVM 入口为 `scripts/kvm_driver_smoke.py --session-test <patched Linux test binary>`。它增加真实 HTTP 会话与 `TestKVMSessionCommitIOIsolation`：两个 VM 已 READY 而原会话仍可用、不可发布候选、绑定 fsync 阻塞下的独立旧 VM 停止、关闭时候选停止及状态锁保持。该测试只存在测试二进制，不是 production daemon 的故障注入参数。常规 CI skip 不能当作实际 KVM 通过；历史 23 项报告也不覆盖这些新路径。实际新证据见下节。

快照恢复、干净预热池、共享镜像引用管理、持续负载/公平性/RSS、物理坏盘、生产 SLO 和完整审计/告警仍未完成。


后续独立指标与40次闭环的新集成证据见 [OBSERVABILITY.md](OBSERVABILITY.md)。下节保留会话功能首轮源码/样本的历史，不能代替后续源码验收。

## 2026-10-22 实机证据：仍是冷 VM，不是快照

最新验收源码 `ed25bf0d77861b9b73b85b447bce10f501db8868`，Go1.27.3。运行时 Go 代码为 `f538b55263065244b17ffef381f92111ad458bba`；其后提交仅强化 Python 验收断言/观测，以下相同二进制摘要可复核。

- [最新真实 KVM 服务报告](validation/kvm-session-phases-2026-10-22.json) 通过27项：前版23项 + 冷会话/新工作区与版本准入 + 并发CAS + 会话控制器SIGKILL恢复 + 独立绑定fsync阻塞用例。
- [绑定 fsync 专项](validation/kvm-session-phases-binding-fsync-2026-10-22.json) 的9项断言展开上述最后一个新用例；[原停止/GC分池](validation/kvm-session-phases-queues-2026-10-22.json) 另9项展开原有用例。不能再额外加18个独立场景。
- [首轮服务](validation/kvm-session-2026-10-22.json)、[绑定fsync](validation/kvm-session-binding-fsync-2026-10-22.json) 与 [队列](validation/kvm-session-queues-2026-10-22.json) 报告保留原样，源自 `8a6c07f5449774e0d9754346383bfd7db817a816`，亦为27项通过。首轮1495.857ms测量的是**两条**新VM验证命令均完成，不是第一条成功；最新脚本先测无副作用命令成功，再做工作区新鲜度验证，并完整重跑KVM，而非重新解释首轮数字。
- [最新Darwin真实进程报告](validation/session-process-phases-2026-10-22.json) 是5项mock回归，不是VM性能。[先前报告](validation/session-process-2026-10-22.json) 修复等待全部旧 generation 的观察条件后重复3次通过；早期一次只等各会话最新Ref便断言工作区空，漏了仍在恢复队列的旧Ref，失败不计作通过。脚本现在逐代等待持久DESTROYED。
- 新Linux daemon SHA-256 `3b57d09f11c329d3841f1cbe89cf3b1360734792d32f62718e54163bed9e7cca`；session测试二进制 `1e6cd2e94bbfca75c045f9a2f23c574b151ec57058df395fc6f2f4086bb82181`。其他精确二进制/镜像摘要在报告内。
- 最新验收源码 [CI #39779082894](https://github.com/123123213weqw/Xandbox/actions/runs/39779082894) 与 [#39779074851](https://github.com/123123213weqw/Xandbox/actions/runs/39779074851) 全绿。full race×3、Session重点race×10、取消/提交/不确定窗口race×20、vet、四套process smoke通过；decoder fuzz5秒约8万次。Linux govulncheck仍有6个未调用required-module findings，0reachable/0imported，不是依赖完全无漏洞。

最新服务同次**单样本**如下（新建guest，不命中快照/预热；宿主cache不受控）：

| 观测点 | 单样本 |
|---|---|
| 服务端操作进入 → 候选 READY | 1440.510 ms |
| 服务端操作进入 → 旧准入撤销阶段边界 | 1441.569 ms |
| 旧撤销 → 新绑定持久写入完成 | 1.137 ms |
| 服务端操作进入 → 新路由发布 | 1442.708 ms |
| 客户端请求发起 → switch响应 | 1444.962 ms |
| 客户端请求发起 → 新VM第一条命令成功 | 1452.165 ms |
| 客户端请求发起 → 新VM两条验证命令均完成 | 1458.727 ms |
| 客户端请求发起 → 并行观察旧host cgroup空 | 1493.882 ms |
| 客户端请求发起 → 观察旧持久DESTROYED | 1557.920 ms |

服务端与客户端观测起点不同，不能简单相减当作精确撤销→停止时延；最后回收样本也含查询/观察开销。**不能把1.137ms宣传为完整切换耗时**：本轮大部分时间在准备新VM，用户请求到第一条新命令成功约1.45s。新命令可以先成功、旧VM随后才停止，这正是需要分开报告的边界，而不是把绑定响应当作停止确认。

专项测试在两个实际VM均READY、旧路由仍可执行时冻结PREPARED写入，确认普通接口无法执行候选；继续到最终绑定Save的受控barrier后，旧VM仍独立停止（最新barrier到观测停止约47.6ms）。Close100ms返回未完成，候选也被独立停止，状态flock持续保留到旧写入者收敛；释放barrier后，迟到写入没有恢复路由，新controller/driver/broker也没有复活会话。barrier仅为测试代码，不是实际坏盘，不是生产RPC/环境开关。

环境沿用 [guardian硬件说明](GUARDIAN.md)：Xeon Silver4216/64逻辑CPU、约251.5GiB系统RAM、runtime ext4，guest512MiB/2vCPU/128MiB私有盘，无NIC；只写少量文件。RSS未测、缓存/负载未控制、无持续吞吐/百分位/最坏延迟/物理擦除或生产SLO声明。两轮Runner均退出0，最终无本次VMM/cgroup/jail/UID manifest残留。SSH复用断开/临时端口超时期间使用有界重试，保留主机密钥校验，不关闭共享连接，也未重复启动或把未运行的尝试计为通过。

## 实际已接受ticket跨节点drain

[新的有限实机窗口](SESSION_TICKET_DRAIN.md)在初始真实session journal Sync、进入Core之前持有请求，确认pending1/既有两实例且无新增backend/配额；实际drain ACK后旧执行与独立回收继续，放行后原始请求用先前ticket完成一次Core创建，新的预留仍503。它不是取消原请求（取消会在Save后正确abort），不是先前raw排队取消的替代推断。原盘cold保持ACKdrained/旧key410等另有实际检查，详见命名来源和边界；未完成control writer的shutdown锁窗口仍未验收。
