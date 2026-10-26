# 固定到达率双租户持续负载门槛（候选，未验收）

**当前没有本场景的 Linux 原生、完整 40 分钟 KVM 或原盘 cold 合格证据。**
单元测试中的合成报告不是运行结果；旧 OOM/240 次切换报告不能为新 fixture 代签。
本改动仅在 `xandbox_host_fixture` 测试构建中启用，不改变普通服务、依赖或默认配置，
不宣称生产就绪，也不据此完成整个 M2/M4。

## 为什么不再只跑固定次数的闭环

完成一轮才开始下一轮，会让慢响应自动降低请求到达率，掩盖过载。
本测试采用独立的 offered clock，迭代完成不能移动后续 due time。这与
[开放/闭合模型的区别](https://grafana.com/docs/k6/latest/using-k6/scenarios/concepts/open-vs-closed/)
一致。固定预分配 worker；资源不足时显式记录生成器 drop，而不是运行中追加客户端，
参考[到达率执行器的预分配与 dropped iterations](https://grafana.com/docs/k6/latest/using-k6/scenarios/concepts/arrival-rate-vu-allocation/)。
这是自有 Go 生成器，不使用 k6，也不声称实现了无限负载源。

## 新的具名实验，不扩大旧实验

仅 `scripts/kvm_nested_host.py --node-load` 选择闭集 `node-load-v1`。
它与 `--node-budget`、`--node-oom`、snapshot、operator、gateway 和其他 profile 互斥。
没有租户脚本、任意目标、持续时间、频率、worker 数或预算调参入口。

| 层级 | 固定值 |
| --- | --- |
| L1 | 8 GiB RAM、12 GiB 自有磁盘、8 vCPU、无 NIC |
| L0 外层自有 cgroup | 10 GiB、swap 0、pids 256、CPU 8 核、OOM group |
| 新 profile 最大存活 | 1 小时；run RPC 55 分钟；cold RPC 200 秒 |
| NodeRoot | 7 GiB、最多 4 实例、prepare worker 1 |
| 每 VM | 768 MiB、swap 0、独立 OOM group、独立 UID/project/代际 |
| control | 3840 MiB，普通 daemon 及其资源保持原隔离规则 |
| 元数据上限 | 总 records 10000 / 每租户 5000；sessions 512 / 每租户 256 |
| 既有任务约束 | TTL 300 秒、exec 60 秒、session history 64，不延长 |
| 身份 | 独立 token 的两个固定租户，各最多 3 实例；全局仍是 4 |

所有旧 profile 的硬上限仍为 **15 分钟**。control 增量不是内存性能结论：
现有生产保守预留公式为 `128 MiB + 10000×256 KiB + 512×1 MiB + 4×128 MiB + 2 MiB
= 3654 MiB`，故新实验预声明 3840 MiB，不能在运行失败后偷偷放大旧 1 GiB。
VM 与 control 的预留仍装入 NodeRoot 7 GiB。不是全节点 RAM 饱和试验。

## 时钟、负载和分母

先做 8 次串行真实生命周期预检，确认普通 API、guest、Stop 和 quota wire contract；
预检不计入 offered 窗口或其百分位。两个 canary 各在同一 guest 上先做三次 busy/普通 release/重复启动心跳预检（不算 Stop），确认旧序号不会污染下一轮，再设测量原点。

| 相位 | 独立 offered 时长 | 全局 raw 到达率 | raw intents | 每租户 |
| --- | --- | --- | --- | --- |
| 0 | 10 分钟 | 0.1/s | 60 | 30 |
| 1 | 10 分钟 | 0.5/s | 300 | 150 |
| 2 | 10 分钟 | 2/s | 1200 | 600 |
| 3 | 10 分钟 | 8/s | 4800 | 2400 |

共 **6360 raw intents**，固定交替租户。每租户 4 个预分配 worker、队列 16，
actor 35 秒；入队时间不改变下一个计划到达时刻。调度迟到超过该相位一个 interval
记 `generator_late_drop`；队列满记 `generator_queue_drop`。不追赶、不重试、不静默丢失。

另外每租户独立单 worker/队列 16，20 秒一次 session canary，各 120 intents，
第二租户偏移 5 秒；共 240。每 8 次 switch 尝试或当前 guest 年龄 200 秒轮换 session，
不通过加大 TTL/history 掩盖长期运行的账本问题。成功 switch 更新当前 guest 年龄。
所有 producer 都等满 40 分钟，随后最多 180 秒 drain；不把最后一个 due 当窗口结束。

raw 与 canary 各相位、各租户分别统计：

- `completed`：完整真实生命周期或 switch 及其所有核对成功。
- `tenant_quota`：普通 HTTP 429 / `TENANT_QUOTA`，不是完成。
- `service_unavailable503`：HTTP 503 / `UNAVAILABLE` 的线协议观察。
  **不能仅凭此 code 断言具体容量根因**；实验不主动关闭/重启控制器。
- 两种 generator drop：不是服务拒绝，更不是零时延成功。
- 其他鉴权、元数据/history、journal fence、job、内部错误均失败，保留第一个实际原因，
  不被伴随取消覆盖。失败 partial 只保存在私有日志，不能当通过报告公开。

每相位预声明粗粒度进展条件：两个等 offered 租户各占该相位成功 raw 完成数至少 1/5，
且各至少成功一次；每个 canary 在每相位至少成功 switch 一次；最高速相位须出现
至少一次实际服务 admission refusal。不是通用公平调度保证、最大吞吐量或生产 SLO。
完成率/drop/refusal 的分母必须保留全部 planned intents，不能只报告成功请求。

## 真实工作与独立停止/回收证据

raw 走普通鉴权 create，核对实际 KVM/owner/Ready/租户；guest 新 boot、非 root、
干净 workspace。guest 内写 16 MiB tmpfs 和 1 MiB ext4、sync/hash，随后运行有
递增序号的忙任务。先用普通同步 guest exec 清除并核对旧心跳文件不存在，再启动异步忙任务；忙任务不再删除进度文件，之后只原子替换序号。另一个 guest exec 观察序号增加并核对 job 仍 RUNNING，再发 Stop。

Stop 必须是现有同步 **HTTP 200 + 同一 Ref + STOPPED + StoppedAt**。
独立内核 observer 从 Stop 发起时刻等待旧执行域为空，必须早于该任务原始 60 秒预算。
DELETE 202 与 durable Destroyed、旧 jail/owner/cgroup 消失、旧 create key 410 分开核对。

canary 通过普通 session API 执行：先证明旧 guest 忙任务在推进，再 switch；核对新
boot/干净 workspace/revision/previous、已提交 key 精确 replay、不允许旧 revision exec。
独立观察旧执行域为空和 namespace 销毁。拒绝 switch 时普通 guest release 只结束本测试
忙任务，**不算 Stop，也不算成功 switch**；session revoke 200 仅表示 admission revoked，
仍须独立等待 durable Destroyed 和旧资源消失。

活跃并发会立即复用固定 UID/project。旧 project 的 quota GET 可能已属于新 guest，
因此不能把活跃阶段的 namespace 销毁冒充完整 project GC；也不能加全局分配锁来伪造归因。
窗口内 observer 只做 quota GET，不额外 Q_SYNC/syncfs。**普通生产 fsync、quota-clear
屏障及 guest sync 保持原样**，不是关闭耐久性以换速度。

所有 producer drain、canary revoke、全部池/namespace 为空且四 project 为零后，另跑
**100 次串行 quiescent tail**，两租户各 50 次，逐代核对 exact project 零使用。
这组完整 quota 回收分布与活跃负载分开，不能混算为并发 GC P99。

## 时延与资源报告的口径

最近秩 p50/p95/p99/max 保留全部相应样本，不删慢样本：

- client queue：worker 开始减计划 due；drop 不进入 API/成功百分位。
- API reply：raw create、canary switch（open 被拒绝时为 open）调用起点到返回；
  scheduled-due-to-reply 另外包含 client queue/轮换/前置 guest 工作。
- first fresh guest command：raw 从 create 发起、canary 从 switch 发起计时。
- Stop/switch reply、独立 execution-domain empty、旧 namespace destroyed：
  raw 从 Stop 发起，canary 从 switch 发起。**不同指标不能因名字相近混用起点。**
- server revocation：仅 canary 的普通服务内部 measured 字段。
- quiescent full project clear：仅串行 tail，从 Stop 发起到 exact project 零观察。
- total iteration：worker 开始到该轮全部证明/幂等 replay 完成。

每组列出 observed/outcomes/窗口后结束的 intent 数（包括拒绝/drop）；迟完成仍归原计划相位。生成器不足本身必须
展示，不能声称全部 offered 都已发给服务。tail 的时钟/分母独立于 40 分钟计划。

baseline + 每 10 秒 + final 的数值系列必须覆盖窗口：240..244 点，offered 相邻间隔
至多 20 秒，末点至少到窗口结束前 20 秒；final 必须窗口后且 pool/quota 零。
采样记录观察耗时（至多 5 秒）、Node/control memory current/peak 与真实 OOM/max
计数、同一 controller incarnation 的 RSS/FD、records、Stop/cleanup queue/worker、
quota GET 与剩余磁盘。非 OOM 本场景的 OOM/kill/group-kill 必须为零；观察 FD 至多 128，
final 在 drain 后 10 秒内回到 baseline+4。不是配置了 RLIMIT_NOFILE=128 的声明。

采样会漏掉峰值，RSS/cgroup charge 不等于唯一物理 RAM，observer PID1 在 NodeRoot
之外但仍在受限 L1 内。永久 tombstone 按 10000 预算保留，不是完成审计/归档/压缩。

## 原盘 cold 与剩余验收

把预检、完成 raw、成功 session open/switch 的已接受 key 存入最多 7200 项/2 MiB
私有 fsynced inventory；结果不得输出 token/key/Ref/boot/PID/cgroup/raw guest/error。
另写独立 `node-open-arrival-healthy-checkpoint` 的健康同步真实 guest checkpoint。
只切断自己的 L1，原盘冷启动先核对原 owner/quota/config，再让普通恢复回收，所有已接受
raw/session key 必须在新 guest 之前 replay 410；fresh guest 和最终四 project 零、整个
NodeRoot 移除另证。inventory 不恢复任务或修补生产元数据。

这是健康同步 checkpoint，**不是** unsynced/in-flight crash、全内存/磁盘耗尽、物理介质
故障、升级回滚、独立操作员或完整生产故障矩阵。实际门槛需冻结源码、24 个原生产物、
原生全套 race/CGO0 三遍与 root Python 零 skip；旧预算/OOM 兼容及新完整 40 分钟/cold
分别实测，所有外层代际/资源独立只读无残留复核后，才能新增脱敏合格证据。


## 保留的实际失败（不是合格长稳证据）

2026-10-26，候选源码 `99c6d8a53e95e1c2762fc68c6ea2219b98142a38` 的原始运行：
同一 fixture 的旧预算和真实 OOM 场景各两次启动通过；新 load 首次启动在测量原点后
**685035.997 ms**（约 11 分 25 秒）失败，尚在相位 1。首个失败为第二租户 canary
第 69 号 intent 的 busy/progress 阶段，普通 helper 仅返回固定 guest workload failure；
不是 companion cancellation。保留 173 个结果行、155 个已接受 key 的内存计数、
69 个资源采样及私有 partial/console/report/receipt/counters，不把它补齐为 40 分钟。

独立只读审计确认该批 **5 个唯一外层代际**（2+2+1）的声明目录/cgroup 全部不存在，
无需补充清理；84 个脚本及 9 个实际输入重新校验。没有新 load 合格报告或 cold 通过声明。

源码中可识别一个相关竞态：拒绝 switch 后复用同一 guest，旧序号可能先满足 progress
的存在性检查，随后异步 busy 的 `rm` 删除该序号，再次 `cat` 失败。**这是源码推断**；
旧 helper 未保留 guest exit/stderr，不能断言它就是全部实测根因，更不是生产内核故障证明。

后续修正将清理/不存在证明移到异步 busy 启动前的普通同步 guest exec，并在 raw/session
两条 API 路径增加 reset-completed-before-launch 的合约及失败负例。新增同 guest 三轮
实际预检；progress 读失败保留独立退出码，私有诊断保留 exit/truncated/输出字节数，
不输出 guest 内容。不重试丢失序号来凑进展，不缩短窗口、改相位/worker/预算或放宽门槛。
修正源码仍须重新原生编译验证、完整真实运行/cold 和独立清理审计；旧软件/运行结果
只为各自原始源码作证。
