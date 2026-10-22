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

真实 KVM 入口为 `scripts/kvm_driver_smoke.py --session-test <patched Linux test binary>`。它增加真实 HTTP 会话与 `TestKVMSessionCommitIOIsolation`：两个 VM 已 READY 而原会话仍可用、不可发布候选、绑定 fsync 阻塞下的独立旧 VM 停止、关闭时候选停止及状态锁保持。该测试只存在测试二进制，不是 production daemon 的故障注入参数。常规 CI skip 不能当作实际 KVM 通过；新运行时的报告发布前，历史 23 项报告也不覆盖这些新路径。

快照恢复、干净预热池、共享镜像引用管理、持续负载/公平性/RSS、物理坏盘、生产 SLO 和完整审计/告警仍未完成。
