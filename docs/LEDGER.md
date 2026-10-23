# 版本化账本、容量与永久 tombstone：实验性治理

本页描述单控制器本地文件账本，不是数据库、生产容量认证或无限运行承诺。状态目录必须由同一个控制器独占，不能放在语义不明的网络文件系统上。整体仍未生产就绪。

## 两层容量，不混淆实例与历史

| 参数/边界 | 默认 | 含义 |
|---|---|---|
| `-max-instances` | 32 | 尚未持久回收的实例，包括 STOPPED/排队/失败重试 |
| `-max-records` | 10000 | 新创建准入允许的累计记录数，包含 DESTROYED 和不确定写入 |
| `-max-tenant-records` | min(1000, max-records) | 每个租户的累计记录预算；显式值 1..max-records |
| 格式/加载硬上限 | 100000 条 | 不是自动扩容目标，也不是启动 RSS 预算 |
| 单文件 | 64 KiB | 写入和加载均检查；读取先限流量，不用无界 ReadFile |
| 私有 LastError | 4096 字节 | 保存前 UTF-8 规范化并截断；不经公共 API 回传 |

合法同 key 重试在这些配额之前检查：READY 返回原实例，参数冲突仍为 409，旧创建已不可用仍为 410。达到累计节点预算时，新 key 返回 503 `METADATA_CAPACITY`；仅租户累计预算满时返回 429 `TENANT_METADATA_QUOTA`。同时耗尽可先返回节点级 503。不能通过销毁后换 key 绕过历史预算。

准入计数在短内存锁里原子预留，不在全局锁内 fsync。首次 Save 返回错误可能已经完成 rename，因此保留记录、key 和累计预算，绝不在错误后分配 VM。Stop/更新/Cleanup 对已有记录仍可持久化；回收只返还实例容量，不返还历史容量。FileStore 另有硬索引上限及 immutable Ref/租户/后端/key 保护。

降低软预算不会抹掉超额记录或阻止启动恢复。只要仍在加载硬边界内，所有旧非终态记录都先栅栏回收；新创建继续拒绝，直到操作员提高预算。不能删除旧记录“腾容量”。Stats 提供 records、record_capacity、tenant_record_capacity；带鉴权 health 不公开全节点计数，多字段也不是事务快照。

这些计数不是物理磁盘 quota、全局请求限流或执行输出 RAM 预算。硬上限下的内存峰值、持续吞吐、磁盘满及长期容量曲线仍需测量；不能把 100000 当成任意规格节点的安全实例数。

## 格式与严格读取

```json
{"version": 1, "record": {"id": "...", "generation": "...", "state": "..."}}
```

示例省略了必需字段，不可直接写入状态目录。普通 HTTP 投影保持原状，不暴露 envelope、key/spec 摘要或内部错误。version 不是 guest 协议版本或后端资产绑定版本。

创建前先逐层验证目录 owner/写权限，再逐层 mkdir；不会先 MkdirAll 后才发现进入了别人的可写父目录。私有叶目录、配置与已提交的账本文件必须由当前 daemon UID 所有；root 不遍历目录符号链接。非 root 的 mock 可使用 root 所有且目标祖先验证通过的系统别名（例如 macOS /var），但私有叶目录不允许是链接。受信 sticky 目录仅允许创建/使用自有私有子目录。

整个目录全部验证通过、目录 fsync 完成后，才发布索引/启动恢复。拒绝未知版本/字段、重复键、缺失的关键字段、不合法状态/时间戳/限额、重复租户 key、文件名身份不匹配、符号链接、非普通/非私有文件和过大文件。读取使用分批 ReadDir，并限制条数与目录条目总数，不先无界加载目录。时间戳只校验必要存在性，不以可跳变 civil clock 的先后顺序授权存活；实时 TTL 仍见 [guardian](GUARDIAN.md)。

专用 ledger 目录只能放记录和实现生成的临时文件。重启遗留的 `.record-<数字>` 从不作为已提交真相，只在完整验证后删除并 fsync 目录；未知文件不静默忽略。不要在里面放备份、编辑器文件或诊断报告。Saves 不同 Ref 可并发，同 Ref 必须串行；嵌入方也必须遵守独占所有权和 Load 不与 Save 并发的契约。

## 旧 v0 的显式离线迁移

PR #5 及以前的平铺 JSON 是 v0。正常启动遇到它会失败，不会默默当成 v1，也不提前启动 Firecracker 来分配新资源。使用**新版本**的 sandboxd：

```sh
# 停止并禁用该服务的自动重启/新请求，保留原状态目录与后端资产。
# 根据运维策略先在私有位置备份完整状态；备份也含私有归属和 key 摘要。
/opt/xandbox/sandboxd -state-dir /var/lib/xandbox -migrate-ledger
# 成功输出示例：{"version":1,"records":42,"upgraded":42}
# 然后使用原后端/鉴权/资产配置启动新版本。
```

该模式要求已有 ledger 和正常的 controller.lock 独占锁；不允许同时传 backend/auth/insecure 选项，不启动 API、驱动、VM 或后台回收。已有进程仍占锁时失败。root Firecracker 状态仍需 root 操作；它不是租户 API。

先验证所有 v0/v1 文件，再逐条 `fsync(file) → rename → fsync(directory)` 升级，最后再 fsync 目录。旧空租户按此前契约迁为 local；私有错误按新字节边界截断；Ref、后端、key/spec 摘要、阶段和生命周期时间戳保留。离线迁移不把 READY 改成 DESTROYED，不虚构停止/回收。下一次正常启动仍按“旧非终态全部回收”执行。

被 SIGKILL、断电或中途 I/O 错误打断可能留下 v0/v1 混合目录；正常启动仍拒绝，修复原因后用同一模式继续，不分配新 ID。重复执行只升级剩余 v0。实际物理断电/坏盘尚未验收。升级是前向操作，没有自动降级或资产在线迁移；旧 binary 无法读取 v1。**不得把旧备份覆盖已经接受新请求后的账本**，否则会丢失归属/幂等记录；回滚恢复需独立运维设计。

## 保留政策与尚未实现的长期方案

当前明确选择**永久保留终态 Ref、租户与幂等摘要，达到容量后拒绝新建**。销毁后释放任务输出，停止/回收错误不保留无限字节，但不按 TTL、墙上时钟或 LRU 删除创建 key。这样旧请求不会因为 tombstone 过期意外重建 VM。

这不是自动 retention/归档服务。任意永久 key 的“永不复用”承诺不能靠静默删除哈希实现。长期有限保留仍需明确的过期 key/命名空间协议或经验证的归档/轮换流程，以及容量告警、独立操作员复现和持续负载证据；本轮不改写原契约，也不宣称这些门槛已完成。

## 验证入口

`make smoke` 运行 `scripts/metadata_smoke.py --daemon bin/sandboxd --node bin/xandbox-node`：节点/租户容量、同 key 重试、降低预算恢复、SIGKILL、拒绝未知格式、迁移锁、2048 条记录迁移中真实 SIGKILL 和继续迁移。导入的旧根先保持 drained，随后由同 UID 操作员显式 CAS resume，再检查独立 metadata 容量；不放宽服务的默认拒绝。默认旧格式来自显式测试副本，不冒充旧 binary 验收。可额外传 `--legacy-daemon /private/path/to/old/sandboxd` 验证实际旧进程创建/崩溃后的升级。

真实 KVM harness 另支持 `--legacy-daemon`、`--legacy-source-revision` 和配套必需的 `--node bin/xandbox-node`，检查旧 VM 运行、控制器死亡后宿主停止、未迁移拒绝启动、离线升级不虚构回收，以及新控制器在累计容量满时回收旧 VM/保持 key 为 410。导入根先保持 drained；仅这个独立测试根经同 UID CLI 显式 CAS resume 后，再检查 metadata 容量，通用启动和 cold recovery 不自动 resume。node CLI 与其它可信输入一样校验摘要并复制为0555，epoch/命令ID只进私有诊断。普通 CI 与 mock 仍不能替代它。新证据如下；历史 [guardian 证据](GUARDIAN.md) 保留不变，不冒充本次升级路径验收。


## 2026-10-22 实测证据

源码 `cb66d784ab90553a5d888b0146787748d27471e7`、Go 1.27.3：

- [真实进程报告](validation/ledger-process-2026-10-22.json)：Darwin/arm64 的 7 项检查，含从真实旧版本 `97196a5` 构建的控制器创建/崩溃后升级恢复；默认 CI 的 6 项不包含额外旧 binary。2048 条记录迁移中途定点 SIGKILL，确实留下混合目录，正常启动拒绝，继续迁移后全部身份保留且孤立 temp 清理。
- [真实 KVM 服务报告](validation/kvm-ledger-2026-10-22.json)：22 项为基础 16 + guardian 4 + 旧 VM 账本升级 1 + 受控 fsync 集成 1。后者 [9 项断言](validation/kvm-ledger-fsync-2026-10-22.json) 是一项的展开，不合并宣传为额外 9 个独立场景。
- Linux/amd64 新控制器 SHA-256 `c763533eaf1184ee8d6ca713488c2a646f3aa88d85067d0fd56569c9bb2e4eb1`；旧控制器 `6405f59fbd7a8e65793ba2bc8bb3b543ffe135add527e10a336ed0246239a783`，与旧主分支重建一致。精确 warden/test/image 摘要在原始报告内。
- 真实旧 VM 已启动 guest 任务再杀控制器。迁移前新版启动不改动旧账本；离线升级保留 READY 和 key（不虚构已回收）；新版随后用 host 停止证明、私有清理和持久 DESTROYED 回收，在累计容量 1 已满时仍保持原 key 410，新 key 503。最终无本次 VMM/cgroup/jail/UID manifest 残留。
- full race×3、重点账本/配额 race×10、vet、依赖校验和 mock/auth/metadata smoke 通过；decoder fuzz5秒约 47 万次。源码 [CI #39757343251](https://github.com/123123213weqw/Xandbox/actions/runs/39757343251) 与 [#39757199135](https://github.com/123123213weqw/Xandbox/actions/runs/39757199135) 全绿，包含 Linux 旧/新 Go 兼容测试和真实内核 timerfd 测试。Linux 目标 govulncheck 仍有 6 项未调用 required-module findings，0 reachable/0 imported-package，不是依赖完全无漏洞。

同一 KVM 节点的硬件/VM 规格与 [guardian 报告](GUARDIAN.md) 相同。新控制器的 8 次 READY 样本约 1.41–1.56 秒；原始数组第 9 次约 1.43 秒是迁移场景的**旧 binary**，不能混入新版性能统计。运行态 DELETE 两次观测停止约 33.7–49.3 ms，持久回收约 147.5–168.1 ms；单次受控 fsync 阻塞中的别代 TTL 到 STOPPED 约 42.3 ms（测试 reconcile10ms，非默认100ms）。只作小样本正确性证据，不是 RSS/持续负载、生产百分位、物理故障、擦除或切换 SLO。


### 路径归属补强后的重验

最新源码 `dc864660d74b25e1fa26d8aad70b768314b1202a` 的 [23 项真实 KVM 报告](validation/kvm-ledger-hardened-2026-10-22.json)、[9 项受控 fsync 断言](validation/kvm-ledger-hardened-fsync-2026-10-22.json) 和 [7 项实际旧 binary 进程验收](validation/ledger-process-hardened-2026-10-22.json) 均通过。前述 `cb66d78` 报告原样保留，不能替代本节新检查。

新增的一项服务场景由真实 root 进程验证四个私有 fixture：不受信可写父目录、其他 UID 所有的父目录、其他 UID 的 auth 文件，以及其他 UID 状态目录的离线迁移，都必须在创建状态子目录/控制器锁前拒绝。没有对其他用户的实际目录做操作。该场景是一项展开，不额外宣传为四个独立 KVM 场景。启动失败的 harness 子进程也显式终止并等待，避免验收程序自身遗留控制器。

新 Linux daemon SHA-256 `11447499f199a7763a0af1b007f753efb5ec1d605b7856ee6973643dc6bc4064`，对应 queue binary `a84678f4d3c14663491b33cda2f1d7cc59c1487528df35ff18a9c692cd318a15`。全部基础/guardian/旧 VM 升级和 fsync 回归重跑，runner 退出 0、最终无本次资源残留。源码 [CI #39761889227](https://github.com/123123213weqw/Xandbox/actions/runs/39761889227) 与 [#39761883420](https://github.com/123123213weqw/Xandbox/actions/runs/39761883420) 全绿；本地 full race×3、privatefile race×10、vet、三套 process smoke 通过，decoder fuzz5秒约55万次。root 专用单元测试在非 root CI 会跳过，上述真实 root 场景不是用 skip 冒充通过。

私有文件 owner/mode 检查不等于完整的部署目录/ACL/锁文件策略审计；auth 文件的父目录仍须受可信操作员控制。完整部署、备份/回滚、ACL 和独立操作员复现仍是后续门槛，不因本轮拒绝检查通过而宣称生产就绪。
