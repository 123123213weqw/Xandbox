# 固定到达率双租户持续负载门槛（候选，未验收）

**当前没有本场景完整 40 分钟 KVM 及原盘 cold 合格证据。**
软件验证按实际冻结源码单独记录，不能为后续修正源码代签。
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

### 第二次原始运行：创建返回 500，根因尚未确定

源码 `b5c198d4b71156c0416623a4ef5c5a8bdfd72405` 的第二次完整尝试中，
同批旧预算/OOM 各两次启动通过；新 load 在 **1363507.797 ms**（约 22 分 43 秒）
失败。首个失败为相位 2、第二租户 raw intent 627 的 create：普通 API 返回 HTTP 500，
该请求观察耗时 **30007.487 ms**。保留 825 个结果行、330 个已接受 key 的内存计数、
137 个资源采样及私有原始证据；没有完成 40 分钟、串行 tail 或 cold 验收。

该批 5 个唯一外层代际/3 个场景 scope 均经独立只读无残留核对；两次失败合计
**10 个唯一外层代际/6 个 scope** 全部不存在，无补充清理，外层 OOM/pids-limit 事件为零。
这些是失败后的清理证据，不是长稳成功、容量或 SLO 证据。

这个失败不同于第一次心跳失败。耗时接近现有 30 秒 prepare deadline，
但旧 helper 没有保留解析后的 API error code，daemon 的私有日志/诊断环留在已清理的 L1
磁盘中，**不能仅凭耗时断言是 IO、排队或 guest 启动根因，也不能声称心跳修正解决了它**。

## 候选有界诊断，不以重试或调参代替修复

新增诊断仍只存在于 opt-in 测试构建中，普通生产 Go/依赖不变，尚须新的源码绑定验证。
HTTP 500 仍是失败；仅保留普通 API 的闭集 code，未知值记 `UNCLASSIFIED`，不把原始
message/code、凭证或 guest 输出写入公共指标。30 秒 prepare、35 秒 actor、40 分钟窗口、
各到达率、worker、预算和公平/回收门槛均未放宽。

- 原有 10 秒采样增加 Node/control 的真实 pids/current/max-events、CPU usage/throttle、
  **仅配置的 L1 虚拟块设备** IO 计数、controller thread 数及三个现有 prepare-failure
  producer 计数。设备行缺失有独立 `observed=0`，不是测得零 IO；不叠加映射层/底层设备，
  不声称唯一物理 IO 或已退出子组计数单调。通过报告要求非故障负载的 pids-limit/prepare-failure
  计数为零，错误不能成为吞掉内部故障的“正常背压”。
- 单次 raw create 仍在等待时，20 秒触发只读观察；整次实验最多 8 次，有显式 omitted 数，
  每次使用 2 秒协作式 context budget。底层文件读并非可强制中断的 syscall deadline，
  外层硬存活上限保持不变。覆盖 8 次串行预检、offered raw 和串行 tail；预检只用私有
  kind3，`offered_origin_known=false`，不伪造 offered elapsed、不加入 6700 个测量结果行。
  API reply/due-to-reply 在等待观察器退出**之前**记录；total iteration 仍包含实际观察开销。
- 绑定同一 controller incarnation，只读现有 CRC 校验诊断环的末 16 条数值记录；最多检查
  最近 40 秒、64 个有界 ledger 文件，按租户和 create-key hash 查找正在创建的实例，
  观察 owner/cgroup/jail/workspace/socket 是否存在和 workspace 逻辑大小。没有锁定生产 store、
  启动第二个控制器、ptrace、重试工作、quota sync 或 `syncfs`。首个 fatal error 在清理前另作
  有界快照，原始 ledger error 最多 4 条/每条约 512 字节且**只留私有通道**。
  非原子、截断或缺失的观察必须显式标记，不能当作确切故障阶段或根因证明。
- 整个私有诊断 capsule 至多 192 KiB。L0 在公共投影/成功校验前分离成独占创建的 0600
  sidecar；另先保留最多 1 MiB 输入帧的私有解码副本（ASCII 重编码上限 6 MiB），即使后续
  schema 校验失败也不丢原始原因。仅回包后写入 L0 私有日志目录，不在 offered 窗口主动刷
  L1 磁盘。失败 partial、raw frame 和诊断 sidecar 不得作为公共合格报告上传。

后续必须冻结新源码、重跑完整原生软件门槛、旧场景兼容和完整 40 分钟/cold。
若某次复测偶然通过但没有确定/修复第二次失败的实际原因，也不能据此宣称该 500 已根治。

### 第三次原始运行：prepare deadline 已取证，PID 累积原因仍待直接核查

冻结运行源码 `701e144a42aa5d03a702838de78fa6ae0366ec7f` 的新尝试仍失败：
相位 2、第二租户 raw intent629 在 **1364508.922 ms** 返回 HTTP500/`INTERNAL`，
reply **30008.311 ms**。827 行、137 采样、330 个已接受 key 的内存计数均保留；
没有完成 offered 窗口、tail 或 cold。后续 CI-only 镜像维护提交不改变这个运行来源。

两个在途探针及首 fatal 私有快照实际取回：一个候选已存在 owner/cgroup/jail/
完整逻辑大小 workspace/API/vsock，后一个尚无 backend owner；真实 producer 诊断为
`PrepareFailed / Deadline`，私有错误为 context deadline，prepare-other 计数1、IO/quota0。
这些证明准备超时类别，不证明究竟是哪一等待阶段。

Node `pids.current` 从原点49随 records10→332 累积到预算值384，control仅15→18。
Node/control pids max-event仍为0，**不能仅凭这些值证明或排除某个后代的 fork 限制**。
源码可识别测试PID1未做通用孤儿回收，但旧运行没有 proc state/parent/comm/UID 记录，
不能现在宣称已观察到僵尸、已确认根因，或生产 daemon 已有同样缺陷。

本批 baseline/OOM各两启动通过、新load一次失败；本批5个代际、三批合计
**15个唯一外层代际/9个scope** 全部独立只读确认不存在，无补充清理。
当前24产物/84脚本/9实际输入及归档/runner重新校验。所有外层OOM/pids-limit事件为0，
不与内部 Node 的 PID 预算观测混用。原始 wire/capsule/partial/console 保持私有。

## 取证阶段：现有预检前后的只读 PID1 census

仍使用同一个固定 `--node-load` 协议，不增加短跑成功模式，也没有新目标/时长选择器。
在原有8次串行真实生命周期预检前、后，以及20秒/首fatal诊断中做有界 proc census：

- 只在已验证的自有L1 PID1、同一普通controller incarnation下读取；最多4096个目录项，
  单文件最多8KiB，与原有2秒协作式观察budget相同。解析明确绑定该proc目录的PID，
  处理comm中的空格/右括号，单独验证有效UID和末次controller state/start ticks。
- 仅统计实际 `PPid=1`、`state=Z`；已知由 `exec.Cmd.Wait` 管理的controller单独标记，
  不冒充被收养的后代。comm只投影成VMM/warden/jailer/other闭集计数；reserved UID、
  精确实例cgroup、deleted或不可判定membership分别计数。空membership不伪造归属。
- PID、parent、comm、UID、cgroup、start ticks不序列化。census只在私有capsule中保存，
  原有192KiB/1MiB frame和L0私有detach边界不变；公共成功报告仅增加
  `pid1_preflight_census_clean`。完整性、消失进程、读错和截断显式报告，失败证据不被补成零。
- 如果预检后仍有实际收养的僵尸，或观察不完整/受管controller已死，则**预检失败**，
  不声称完成40分钟或cold。这是提前拒绝已观察到的资源回收缺口，不是缩短通过门槛。
  通过该预检后仍必须执行原40分钟/6360 raw/240canary/100tail/cold全部原条件。

该取证提交 `ce677b9` **没有**wait/reap、signal、ptrace、cgroup移动或任何生产行为修补；尤其不运行
会与 `exec.Cmd.Wait` 争抢退出状态的 `wait4(-1)`。不增加PID预算、不延长prepare timeout、
不改负载来避开失败。它需要新的冻结源码/原生回归/真实L1证据后，才能讨论具体的init回收修正。


### 第四次实际运行：直接确认测试 PID1 的孤儿 VMM 泄漏

取证源码 `ce677b932e91ba189bf06743ec87d7d2fa5fc04b` 的旧预算/OOM 各两启动通过；
原8次串行 raw 预检的真实 guest/Stop/Destroy/quota 契约完成，但随后 census 直接确认
**8 个 PPid1 / Z / Firecracker / 保留 UID / 精确实例 deleted cgroup 的孤儿僵尸**。
预检前为0，预检后 Node/control `pids.current` 差8，controller仍存活。
因此在 offered 原点之前如实失败，测量行0，没有40分钟、tail或cold成功。

该批5个外层代际/3scope，四批合计**20个唯一外层代际/12scope**均独立只读确认不存在，
无补充清理。这确认了**自制测试 init 的收养进程回收缺陷**，不能倒推它是所有历史500
的唯一原因，也不能据此断言正常 systemd 部署有同一生产缺陷。

## 新修正候选：只回收精确归属的已死孤儿，尚未实测验收

仅在固定 `node-load` 自有L1 PID1中绑定本次controller/start ticks；不改变父子结构或
放宽 `requireNode` / `requireQuotaChild`。自制init以250ms周期、有界4096目录/8KiB文件/
2秒协作budget扫描。只对 `PPid1 + Z + firecracker + 有效UID400000..400003 +
精确64hex实例deleted cgroup` 的候选再次验证完整PID/start/UID/membership和controller后，
调用 **`Wait4(精确PID, WNOHANG)`**。永不wait(-1)、signal活进程、移动cgroup、修补生产
owner/ledger/jail/quota，或重试失败工作。已知controller PID明确排除，其他固定受管root
helper不满足保留UID/VMM/deleted域谓词；普通`exec.Cmd.Wait`继续独占其直接子进程退出状态。

reaper与只读census共享可取消gate，避免census读取一半时自身wait删除proc；census本身仍
不做wait。内部身份不序列化，私有census仅增加active/sweeps/reaped/errors闭集计数。
错误锁存并停止，不自动重启或偷偷重试成成功。旧负例仍可读取；新通过报告必须同时保留
两个干净census、原8次预检至少8次精确回收、Node/control PID charge相等，不能省略机制证据。

窗口后、100次tail后和cold fresh guest销毁后均独立检查真正quiescence；cold退出前取消并
join reaper，再由原`Cmd.Wait`收取controller状态、移除整个NodeRoot。PID384/control128、
prepare30秒及原40分钟/6360raw/240canary/100tail/cold门槛均不变。

**这里描述候选实现，不是合格证据。** 合成机制负例、冻结原生软件验证及新的完整真实KVM
运行仍需分别完成；不能用旧8僵尸负例或旧native/CI报告为修正后的fixture代签。

### 第五次实际运行：八孤儿机制已修复，新的初始 session 失败仍阻断长测

冻结源码 `2cec9052554b500c777804adf845d86aadf63a47` 的预算/OOM各两启动通过。
原8轮生命周期前后census都完整/无读错/无僵尸；reaped从0到8，预检后Node/control
PID charge同为14。测量中至首fatal累计精确回收352次、错误0，fatal census仍无收养僵尸；
145次采样中Node PID为32..59，而不是此前随records增长到384。这证明本次测试init的
八孤儿机制修正及这段观测效果，不能宣称所有历史500或整个40分钟已经根治。

原完整尝试在 **1441011.256ms（约24分1秒）** 失败：相位2、第一租户canary144的
session open收到 **HTTP503/SESSION_UNAVAILABLE**；该码是fenced session错误，仍必须
失败，**不能放宽成普通UNAVAILABLE背压**。保留988结果行、354已接受key的内存计数和
145采样，没有tail/cold通过。首fatal时prepare IO/quota/other均0；旧观察器没有保留
session journal/内部abort cause，因此不能仅凭并发数和3.608ms reply确定实际内因。

SSH观察连接退出255后，独立重连确认原runner已退出，远程原始状态为120，报告为false，
不把传输退出误当测试结果或重跑理由。gzip/fresh verified SSH恢复同一原件；该批5代际、
五批合计**25个唯一外层代际/15scope**均独立只读确认不存在，无补充清理。
所有原始wire/capsule/partial保持私有且已严格detach逐字节匹配。

源码检查发现一个可独立复现的生产broker错误分类问题：首次session attempt在Core尚未
分配任何VM时遇到节点/租户实例容量拒绝，也被旧abort路径转成SESSION_UNAVAILABLE。
合成Core容量/租户容量负例各三遍稳定复现此分类，**与真实canary错误类别相关，但旧原件
没有足够证据证明它就是该次实测的唯一内因**。

新候选只对精确Core实例容量sentinel、首次attempt、无Ref/无fence/未cancel/未关闭时，
先撤销内存准入并持久提交CLOSED/FAILED，才保留普通容量错误；持久化不确定、已有
candidate、wrapped/compound错误及其余故障继续fenced失败。永久key不重试、不回收既有
实例容量；fixture允许的两个正常code和全部原40分钟/预算/公平/回收门槛不变。
这改变普通broker，须新的冻结原生/CI及真实KVM、原盘cold和受影响普通程序复验；
**旧5bfb或2cec的报告不能代签新程序**。
