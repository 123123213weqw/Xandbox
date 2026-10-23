# TEST ONLY：quota 双租户切换与有界 headroom

下文保留历史522/3f9冻结基线；新生产3ea的[quota240/双活cold/故障矩阵复验](QUOTA_REQUALIFICATION.md)已另完成，不重标历史结果。

2026-10-23 已完成下述有限实测，见[新冻结源与全部原始证据](validation/quota-switch-provenance-v5.json)；**不是完整生产验收**。生产 Go/daemon 不增加测试接口或故障开关；不把历史默认 nil-quota 的240次切换当作 quota 验收。

首次固定源 `fb836bf` 的真实 L1 已完成 setup/preflight，但负载在 initial 阶段失败、零次切换；原始 false 报告及单个执行域的清理证据保留。原因是 TEST 客户端误把 public Job JSON 中未携带的 sandbox ID 当成完整 Ref：Job 的显式任务 `id` 会遮蔽嵌入 Ref 的 `id`。修订夹具先校验独立 session envelope 的 revision/ref 和 job 的 generation/id，再从已校验 envelope/lookup path 恢复完整内存 Ref；坏绑定继续拒绝。私有 crash receipt v2 改用独立 JobID/JobRef 字段，防止同一 JSON 遮蔽问题；不改生产 wire/API。这是夹具错误修复，不把失败改写成通过或据此推断配额错误。

第二次固定源 `5bda138` 仍为 false：两租户都进入第一轮，但零行完整完成。夹具在旧代 durable DESTROYED 后错误要求 ephemeral job GET200，而普通 manager 按既有契约已丢弃该代 job history，实际404；同伴被取消。修订不把404伪造为CANCELLED或Stop证明：另用第二条普通guest执行观察旧writer两次实际写入进度，再确认其API仍RUNNING；要求独立host-empty观测早于从POST前本地时钟推导的最早60秒job deadline，且普通durable DESTROYED及资源消失已通过，才允许将404标为 `HISTORY_DROPPED_AFTER_RECLAIM`。若仍能读到job则实际终态仍须非timeout、非成功退出。失败的原始partial rows保留，不能拼接进新运行。

第三次固定源 `4653b08` 在601.837秒返回false：beta120行完整、alpha119行完整，第120行在最后replay/CAS检查被夹具600秒总deadline取消。原始240行（含未完成行）及1189条资源样本全部保留；**239行完成不是完整通过**。前三次false与各自独立清理审计见[待验收provenance](validation/quota-switch-pending-provenance-v4.json)。新修订仅将该固定实验run budget明确增加到720秒、控制读取770秒、资源采样上限1452及回复上限2MiB；120次/租户、实际writer进度、最少180秒、原guest60秒job timeout及独立早于timeout的Stop判据不降低。外层900秒hard lifetime与原有资源边界不变；720秒是实验总运行上限，不是单次切换SLO。当时尚待新固定源重跑；原239行未拼入后续运行。

第四次固定源 `599a6de` 的[原始false与load-only复核](validation/quota-switch-pending-provenance-v5.json)：测量阶段已全部完成240行、601.477秒，完整量化结果可独立复核；但第二次开机的cold inode元数据严格比较失败，**整体仍是false**，旧11个兼容profile尚未执行。检查点代码存在确定的基线时序错误：第二个clone创建前就保存了第一个clone的共享inode link count，而新clone正常增加共享link。新夹具在两者都Ready且pins2之后重新精确采样两份完整receipt，并要求共享inode身份/属性/link count逐项一致；冷恢复严格比较仍保留，绝不归一化或忽略link count。私有receipt语义版本升为3；增加错误时的私有字段差异诊断。旧失败未导出具体差异条目，不能声称该时序错误已被证明是唯一差异或提前宣布修复实机通过。该修订随后在下述3f9c冻结源完整重跑；旧240行未拼接。

## 独立且明确的新规格

固定 `--quota-switch` / launch profile `quota-switch-v1`：L1 RAM **3GiB**、raw disk **4GiB**、外层自有 cgroup memory.max **4GiB**，CPU4、pids128、swap0、无NIC、hard15min不变。启动前要求L0 MemAvailable≥8GiB及测试目录free≥12GiB；这只是有界实验前置检查，不是生产全局 admission。旧 profile 的2GiB RAM/2GiB盘/3GiB cgroup和固定dm 2GiB guard不放宽。未知profile拒绝。

普通daemon `max-instances=4`，两租户各quota3，独占UID/project slots8，每代192MiB/128 inode。两旧VM+两候选有明确global headroom；UID slots不等于同时运行容量。更大规格不能与旧2GiB profile做不受控加速比或成本比较。启动校验实际cgroup controls、4GiB盘；独立QMP确认3GiB base-memory（[QMP接口](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#command-query-memory-size-summary)）。

模板只能由本L1真实KVM builder创建、保持UNASSIGNED且HostABI实际一致；不能重标L0导出或从已分配clone再导出。先继承原shared2/pin/GC检查，再做四个同时Ready的真实quota guest、独立private project/readonly共享inode及精确st_blocks记账。alpha达到tenant3时第四次429而beta仍能创建执行；node4满后第五次503；401/跨租户404独立检查。

受控顺序回收alpha旧代，核对owner/jail/cgroup不存在、其project全零、旧创建key410，再证明同UID/project只能以新ref/boot/干净workspace复用；beta继续执行且数据不变。这是单独的严格slot-reuse证据，不把并发时已被新owner重用的project读数冒充旧代清零。

## 固定完整负载，而非缩小目标的 smoke

固定两个Go并发worker，各 **120次**、最少 **180秒**paced closed-loop，session每48次轮换以保留history上限。两租户初始相同create key必须隔离。alpha guest分配24MiB tmpfs/8MiB ext4/4轮hash，beta为4MiB/1MiB/1轮hash；全部argv经普通session guest API，不在host执行。

每次切换请求前，都有旧guest循环writer；并发第二条guest命令确认其写完1MiB且单调序号实际前进，之后再次检查job仍RUNNING，不把尚未dispatch的控制器状态当真实guest进度。进度探针与工作负载都在switch计时起点之前，额外开销仍计入完整负载wall time。切换后要求新ref/revision、干净workspace/tmpfs、新UID65534/boot，独立监测旧cgroup实际empty、普通durable DESTROYED及私有资源消失；host-empty必须早于保守最早job deadline。已回收代际的job history404按上文单独分类，不能虚构终态或只凭404证明停止。重放同switch key不得创建额外候选；旧revision exec/switch与普通per-VM绕过均409。保留未完成/慢/错误行，不过滤掉失败。cgroup.events的ENODEV只在精确同一路径再次确认已不存在时允许，不吞掉现存group/其他错误。

分别记录请求到binding响应、首条新命令成功、旧执行域实际停止观测、旧代durable销毁观测，外加server各phase；nearest-rank P50/P95/P99/P100从全部完成行计算，外部复核器逐项重算。两个worker实际switch interval必须重叠。**不是open-loop、scheduler公平性、线上SLO或极端尾部界限**。

500ms目标采样：五种queue/allocated gauges、owner/cgroup数量、8个quota读数、instance parent memory.current、controller RSS/FD及L1 free。非事务采样可能漏峰；quota不同slot读数来自不同时刻，memory/RSS也重叠，不能加总为unique RAM。观察器不在测量切换中强制quota sync，避免替普通daemon提交；精确inode记账的preflight/稳定掉电checkpoint在测量外允许同步。

## 测量后的双活session宿主掉电

全部负载revoke/GC后，先确认metrics/owner/cgroup/project8全空，再另建两租户live sessions及RUNNING jobs，保存私有binding/owner/策略/boot/quota/inode receipt并核对两个pin。该checkpoint在测量结束之后，明确是健康同步检查点，不是新的in-flight commit故障证明。

只power-cut自有L1。同盘冷启动，普通daemon启动前核对精确两个owner/策略/共享backing/inode记账、旧执行域不存在、两个pin仍在；再普通启动（无额外通知器）回收旧代，session CLOSED/no binding、旧exec及创建key410、旧job不恢复。新两租户真实guest必须干净且boot不同，最终8 projects全零、pin0、daemon reaped/owned cgroup root移除。

只有该profile允许2MiB有界控制回复，保留完整240行/采样；旧回复64KiB和所有请求8KiB不变。失败的sanitized partial rows也保留，私有ref、token、UID/project/inode/boot、argv/输出和receipt不公开。

本轮固定源native/cross、完整profile及旧launch/harness有限回归、独立只读清理与脱敏证据已完成。quota/node总预算、partial-copy、owner unlink/dirfsync/shared-pin故障组合、独立操作员和完整M1–M4仍未完成；PR19继续Draft。

## 冻结599a的load-only观测（整体cold恢复未通过）

1193条资源样本、151对跨租户switch区间重叠；以下均为各N=120、从相同switch请求起点计的nearest-rank P95，不是SLO或完整profile通过。独立host-empty必须早于最早可能job timeout，durable回收则另查完整资源/配额。

| 租户 | binding ms | 首命令成功 ms | 旧host空观测 ms | 旧代durable回收观测 ms |
|---|---:|---:|---:|---:|
| alpha | 1316.575 | 1441.675 | 1317.010 | 1571.851 |
| beta | 1408.124 | 1493.650 | 1436.606 | 1635.054 |

全部240行、完整P50/P95/P99/max、server phase和资源时间序列保留在raw，非事务采样可能漏峰，不能加总为unique RAM或从相等完成次数推导公平性。测量结束时实际检查8 projects/owner/cgroup/queue全零，但随后另建crash sessions后cold失败，不能宣称crash session已完成普通回收；其外层2个自有执行代际只读核验已不存在。

## 冻结3f9c的完整有限profile与兼容回归

最终运行源 `3f9c4b07e85f756c15b721bbd3554ffadbd09ddc`，普通daemon仍 `522da68e…`，production Go/warden/原guest未改。原生五种CGO0/trimpath/buildvcs=false ELF与独立cross逐字节一致；native full race×3/vet、fixture race×10/vet、root Python59、实际CGO0 kernel/exec filter×3和专属冻结源Darwin race×3/vet通过。CI不是KVM或完整生产证明。

[新完整raw](validation/kvm-quota-switch-mixed-v5.json)中，两租户各120行完整，共 **606.720秒**、1203条资源样本、151对跨租户switch区间重叠；随后另建两租户actual writer sessions，receipt v3在两者Ready/pins2后采样完整身份/配额/共享inode metadata/link，保持严格cold比较并通过第二次开机的普通恢复。不是旧599a测量与新的独立cold片段拼接，是本冻结源同一完整profile。

| 租户 / 从switch请求起点到 | P50 ms | P95 ms | P99 ms | max ms |
|---|---:|---:|---:|---:|
| alpha / 绑定响应 | 968.170 | 1397.247 | 1529.591 | 1542.487 |
| alpha / 首条新命令成功 | 1033.209 | 1466.448 | 1640.659 | 1643.986 |
| alpha / 旧host空观测 | 997.840 | 1368.302 | 1549.804 | 1574.253 |
| alpha / 旧代durable回收且资源消失观测 | 1360.253 | 1615.621 | 1680.549 | 1714.822 |
| beta / 绑定响应 | 966.559 | 1462.961 | 1616.930 | 1718.069 |
| beta / 首条新命令成功 | 1038.433 | 1507.839 | 1722.376 | 1835.831 |
| beta / 旧host空观测 | 985.486 | 1478.447 | 1587.375 | 1588.968 |
| beta / 旧代durable回收且资源消失观测 | 1348.298 | 1639.843 | 1848.372 | 1964.781 |

每组N=120、nearest-rank；P99是排序第119项，不是置信界、跨硬件加速比或SLO。switch计时不含前置workload与writer进度探针；完整wall包含它们及显式pacing。两个闭环不证明公平性或开放到达饱和，暖缓存与共享宿主背景负载未控制。完整server phases/逐行/非事务资源采样保留，绝不筛掉慢样本。

| 不相加的采样视图 | 本轮观测峰值 | 测量阶段末 |
|---|---:|---:|
| allocated | 4 | 0 |
| owned generation cgroups | 4 | 0 |
| durable owner files | 4 | 0 |
| 非空project slots | 4 | 0 |
| quota用量 MiB（非事务合计） | 526.129 | 0.000 |
| instance parent memory.current MiB | 100.617 | 8.652 |
| controller RSS MiB | 15.750 | 15.211 |
| controller FD | 35 | 10 |

L1 free最小2176.047MiB，单次扫描最长194.859ms。会漏峰且多列重叠，不能相加为unique RAM或租户计费；没有触碰每VM全部512MiB。四个同时Ready guest/tenant3/global4另有preflight，不从采样峰值倒推。

测量末parent memory.current仍为8.652MiB，controller RSS/FD也不为零；当时服务与active catalog仍在。剩余charge页种类没有导出，不能编造具体缓存/泄漏归因，更不能把owner/cgroup/quota零值说成整个服务物理RAM归零。随后最终controller/owned cgroup root移除另有检查，但不是unique RAM或安全擦除证明。

本轮cold普通恢复前精确owner/策略/HostABI/UNASSIGNED export/共享namespace/独立quota/pins2均核对；普通daemon随后旧session CLOSED/旧exec和create410/旧job404不恢复，旧代durable回收、新实际KVM guest干净且boot不同，最终8 projects/pins全零、controller reaped/owned cgroup root移除均通过。健康checkpoint同步发生在测量后，不能充当新的in-flight commit或物理介质故障证据。

同冻结源另11个legacy profile通过：两种最后listener loss、6 errno含clear各3次、实际syncfs EIO/三个hold窗口、quota-clear owner/pin窗口、真正L1 snapshot shared2/cold3、quota IO4和nil-quota IO4。旧2GiB RAM/2GiB盘/3GiB cgroup边界未改变。共12个passing scope/34个外层L1执行代际，[独立只读审计](validation/quota-switch-independent-cleanup-v5.txt)全部自有root/control/cgroup不存在。四个false前序另5个代际也已核验，合计16 scope/39代际；配额零值来自L1内实际读回，不从事后删盘推断。四份false和先前pending provenance均保留；3f9完整profile不补写它们的结果。

完成的是有限quota并发切换/双活cold子门槛，不是完整M1–M4。partial-copy、owner unlink/dirfsync/catalog锁内持久窗口、keeper/shared-pin故障组合、节点总预算、持续开放到达压力、公平性/独立操作员/SLO仍未完成。PR19继续Draft，Goal仍active。
