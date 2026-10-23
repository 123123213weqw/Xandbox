# TEST ONLY：quota 双租户切换与有界 headroom

新增夹具尚在验收，**本文件不是通过报告**。生产 Go/daemon 不增加测试接口或故障开关；不把历史默认 nil-quota 的240次切换当作 quota 验收。

## 独立且明确的新规格

固定 `--quota-switch` / launch profile `quota-switch-v1`：L1 RAM **3GiB**、raw disk **4GiB**、外层自有 cgroup memory.max **4GiB**，CPU4、pids128、swap0、无NIC、hard15min不变。启动前要求L0 MemAvailable≥8GiB及测试目录free≥12GiB；这只是有界实验前置检查，不是生产全局 admission。旧 profile 的2GiB RAM/2GiB盘/3GiB cgroup和固定dm 2GiB guard不放宽。未知profile拒绝。

普通daemon `max-instances=4`，两租户各quota3，独占UID/project slots8，每代192MiB/128 inode。两旧VM+两候选有明确global headroom；UID slots不等于同时运行容量。更大规格不能与旧2GiB profile做不受控加速比或成本比较。启动校验实际cgroup controls、4GiB盘；独立QMP确认3GiB base-memory（[QMP接口](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#command-query-memory-size-summary)）。

模板只能由本L1真实KVM builder创建、保持UNASSIGNED且HostABI实际一致；不能重标L0导出或从已分配clone再导出。先继承原shared2/pin/GC检查，再做四个同时Ready的真实quota guest、独立private project/readonly共享inode及精确st_blocks记账。alpha达到tenant3时第四次429而beta仍能创建执行；node4满后第五次503；401/跨租户404独立检查。

受控顺序回收alpha旧代，核对owner/jail/cgroup不存在、其project全零、旧创建key410，再证明同UID/project只能以新ref/boot/干净workspace复用；beta继续执行且数据不变。这是单独的严格slot-reuse证据，不把并发时已被新owner重用的project读数冒充旧代清零。

## 固定完整负载，而非缩小目标的 smoke

固定两个Go并发worker，各 **120次**、最少 **180秒**paced closed-loop，session每48次轮换以保留history上限。两租户初始相同create key必须隔离。alpha guest分配24MiB tmpfs/8MiB ext4/4轮hash，beta为4MiB/1MiB/1轮hash；全部argv经普通session guest API，不在host执行。

每次切换请求前，都有已确认RUNNING的旧guest循环writer。切换后要求新ref/revision、干净workspace/tmpfs、新UID65534/boot，独立监测旧cgroup实际empty、普通durable DESTROYED及私有资源消失，旧writer终止且不是等待job timeout。重放同switch key不得创建额外候选；旧revision exec/switch与普通per-VM绕过均409。保留未完成/慢/错误行，不过滤掉失败。

分别记录请求到binding响应、首条新命令成功、旧执行域实际停止观测、旧代durable销毁观测，外加server各phase；nearest-rank P50/P95/P99/P100从全部完成行计算，外部复核器逐项重算。两个worker实际switch interval必须重叠。**不是open-loop、scheduler公平性、线上SLO或极端尾部界限**。

500ms目标采样：五种queue/allocated gauges、owner/cgroup数量、8个quota读数、instance parent memory.current、controller RSS/FD及L1 free。非事务采样可能漏峰；quota不同slot读数来自不同时刻，memory/RSS也重叠，不能加总为unique RAM。观察器不在测量切换中强制quota sync，避免替普通daemon提交；精确inode记账的preflight/稳定掉电checkpoint在测量外允许同步。

## 测量后的双活session宿主掉电

全部负载revoke/GC后，先确认metrics/owner/cgroup/project8全空，再另建两租户live sessions及RUNNING jobs，保存私有binding/owner/策略/boot/quota/inode receipt并核对两个pin。该checkpoint在测量结束之后，明确是健康同步检查点，不是新的in-flight commit故障证明。

只power-cut自有L1。同盘冷启动，普通daemon启动前核对精确两个owner/策略/共享backing/inode记账、旧执行域不存在、两个pin仍在；再普通启动（无额外通知器）回收旧代，session CLOSED/no binding、旧exec及创建key410、旧job不恢复。新两租户真实guest必须干净且boot不同，最终8 projects全零、pin0、daemon reaped/owned cgroup root移除。

只有该profile允许1MiB有界控制回复，保留完整240行/采样；旧回复64KiB和所有请求8KiB不变。失败的sanitized partial rows也保留，私有ref、token、UID/project/inode/boot、argv/输出和receipt不公开。

尚需固定源native/cross、真实完整profile、旧launch/harness兼容回归、独立只读清理及脱敏raw证据。quota/node总预算、partial-copy、owner unlink/dirfsync/shared-pin故障组合、独立操作员和完整M1–M4仍未完成；PR19继续Draft。
