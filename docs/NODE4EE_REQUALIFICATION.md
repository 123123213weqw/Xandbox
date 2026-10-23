# 新4ee：节点空间压力、真实排队取消与复制/owner窗口复验

**四个命名scope实际通过，不是完整节点饱和、生产就绪或Goal完成。** 普通daemon `4ee09d0a…`、admin `ff05652e…` 和TEST fixture `f7c712bb…` 使用同一冻结源 `ab048ed65b12fc806cba9d16eecd1c830c37fa93`；[新来源清单](validation/node4ee-provenance-v1.json)绑定4份原始JSON、3份安全文本、8个私有白名单regular归档成员和此前精确原生/交叉构建依据。此次没有改生产或测试源码，也没有重跑/重标旧3ea结果。

## 实际执行的四个scope

| 用例 | 新的实际检查 | 外层L1执行代际 |
|---|---|---:|
| [schema3 admission](validation/kvm-node4ee-admission-v1.json) | 原始排队HTTP取消、held-copy下keeper独立回收、固定指令校准、inode/byte压力与低free原盘cold | 2 |
| [owner unlink](validation/kvm-node4ee-owner-v1.json) | quota已清零且owner已unlink，真实目录fsync入口挂起，原盘cold和keeper恢复 | 2 |
| [unsynced copy cut](validation/kvm-node4ee-inflight-v1.json) | 实际16MiB复制前缀/下一WRITE挂起，外层只读receipt后切自己L1，未主动同步前缀 | 2 |
| [partial WRITE errno](validation/kvm-node4ee-partial-v1.json) | 16MiB实际前缀后一次TEST EIO，失败候选回收、keeper继续与新真实KVM创建 | 1 |

runner实际终止0并消失。[独立只读审计](validation/node4ee-independent-cleanup-v1.txt)逐个检查4个scope的root/control/cgroup parent及全部7个代际均消失；没有补救清理动作。两份外层私有cut receipt仍0600/singlelink，不公开。quota/namespace/pin/owner是在live L1内核对，不能从外层删盘推断。

node profile仍固定8GiB RAM/12GiB盘/10GiB外层cgroup/CPU8/noNIC；schema3 N4/records1024/sessions32/prepare1、每代192MiB/128inode、IO16MiB/s/1024ops不变。其他三个copy profile仍是其原固定3GiB/4GiB/4GiB/CPU4规格，不能混为同一资源压力或性能样本。

## 取消的是真正排队的原始请求

实际keeper、持有prepare许可且WRITE被挂起的holder、两个已经进入普通prepare gate的原始创建请求，共消耗4个frontend slot；第5个503。两个等待者尚无backend owner/jail/cgroup。取消其中一个**原始HTTP请求**，客户端实际得到context canceled；普通daemon trace明确走`selected_case=1 → cancel`，没有取得token、没有node_ok/release。其key410、真实持久DESTROYED、无backend资源且credits/pools恢复到该时刻基线。

在同一个WRITE通知仍有效、未发CONTINUE时，DELETE keeper并观察：

| 从DELETE开始的N=1观测 | ms |
|---|---:|
| 已知host执行域kernel-empty或已删除 | 36.348 |
| 本代quota0、owner/jail/group消失且实际持久DESTROYED | 161.646 |

随后再次核验目标通知仍挂起、survivor仍排队；期间另有27个**其他WRITE的CONTINUE回复**，不是27次已完成I/O。只发1次目标CONTINUE，holder与survivor原始请求才分别Ready，并实际执行独立boot/干净workspace命令；最终4个project/pin/credits/pools均零，旧daemon实际reap后重启继续压力/cold用例。固定hold20s、Prepare30s、HTTP40s未增加。

上述时延含HTTP、轮询和readback开销，是单例上界，不是SLO/介质擦除/全部kernel cache释放；credits/pools的后续检查不回填为更早的时间点。keeper是真实Ready VM，但先前marker/8MiB内存任务已完成，不是CPU饱和busy guest。通知等待不是filesystem D；本例的raw创建取消也**不证明session的pre-Core ticket跨operator drain**。

## 新程序上的两段实际指令trace

9个固定普通ENTRY probe先核验整个4ee ELF、符号范围、指令字节，再只在自己的L1 tracefs注册；绑定真实进程incarnation/exe inode/control cgroup/TGID，8CPU loss counter为0、9项kernel hit计数与trace相等。无Go uretprobe、无栈/用户内存读取、无共享L0 tracing。原始寄存器、地址、TID和私有trace不公开，只输出按R14 goroutine关联的本地ordinal：

- **12事件校准**：两个创建完整enter/selected/ok/node_ok/release/released；第一个实际selected后才派发第二个，第二个实际entry在第一个持有许可期间。
- **15事件取消序列**：holder完整6事件；取消者enter/selected(case1)/cancel共3事件；survivor等待取消之后取得许可再完整6事件。已对本次原始结果执行16个反例，丢事件、乱序、错误ELF/计数/selected及缺失witness均拒绝。

release probe在普通`Prepare.deferwrap1`的内联channel receive前，released在其后；前者不是channel的精确线性化时间。原压力报告`prepare_permit_hardware_trace_claim=false`保持原值，不补写成true；独立的calibration/cancel对象只证明这两个有限实验的命名事件，不等于完整复制阶段跟踪、scheduler park、公平性或通用prepare并发上界。

## 空间与原盘冷恢复的实际观察

本次inode filler 126592个；普通DELETE前/后free inode为5152/5166，都仍低于guard 5776，所以后续create/Switch/catalog仍拒绝。移除自己filler后再恢复准入，没有让生产planner给当前占用提前还空间。byte filler实际分配8330145792 bytes；checkpoint free 2825740288低于guard 3362619392。原盘cold先检查两份原owner/quota/shared namespace/pin与未分配export，再由普通daemon回收，低free下旧key410/GC和新KVM路径按固定规则通过。guest每台只触碰8MiB，不是512MiB满RAM或完整OOM验收。

owner窗口cold本次实际owner存在 `True`、durable owner pins `2`；不把这种自然持久化结果规定为所有切断的唯一结果。它只证明当前dir-fsync入口挂起、真实catalog锁及quota/owner状态；不是filesystem D，也没有给keeper发新的guest命令来冒充该窗口内进度，DELETE202仅是意图确认。

未主动同步copy的cold实际只剩2个entry，workspace size 0、project charge 8192 bytes/2 inodes；live阶段16MiB写入返回不等于掉电持久。fixture只读取、验证允许的原始子集，不restore owner/clone、不伪造完整前缀，不改HostABI或恢复已分配guest。两类cut最终旧owner/key资源回收、keeper边界、新guest和quota/pins归零分别验证；这些数字不是跨轮物理allocation金标准。

## 来源、历史与剩余工作

[上一轮ab源码实际native/cross及全量测试](RUNTIME4EE_REQUALIFICATION.md)被精确SHA复核复用，**不是本轮又编译/测试一遍**：原生/交叉8产物逐字节相同，race×3/vet、fixture×10/vet、rootPython95零skip、实际kernel filter×3、mock6和Darwin race×3/vet仍属其原执行。当前4个scope全是新的实际KVM执行；本批没有硬件或离线核验失败前序，旧项目失败报告/来源清单原样按SHA引用，未拼入本轮数据。

仍需实际session已接受pre-Core ticket跨drain、未完成control writer在shutdown期间保持state lock、最坏RAM/ancestor/affinity/uniqueRAM/全资源节点压力、open-loop/fairness/长期SLO，以及生产TLS网关/凭证生命周期、独立operator/systemd、持久审计/告警/日志预算、archive/rotation/备份/升级/回滚及其余M1–M4。PR19保持Draft、main和主分支ZIP不变，Goal ACTIVE且`production_ready=false`。
