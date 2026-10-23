# 新3ea运行时的默认路径与IO兼容复验

**有限冻结源码验收，不是生产认证。** schema3节点策略改变了生产代码，不能用旧daemon `522da68e…` 的报告证明新程序。本文记录新daemon `3ea1e247…`、admin `19bbd460…` 对已有默认路径/IO/有限quota拒绝恢复的重新运行；[quota240忙任务/双活cold/故障矩阵](QUOTA_REQUALIFICATION.md)现已另完成；不由本页的默认路径报告替代证明。

冻结源码`2e514fe9d0b0ce8097b4baca67c9761afdfdbf48`；完整来源、19个公开输入文件SHA与范围见[provenance](validation/node-runtime-provenance-v1.json)。[节点schema3基础门槛](NODE_BUDGET.md)是另一个独立报告；这里的默认snapshot/IO配置仍是schema1/2、nilNode，不能替代schema3 snapshot或完整节点压力。

## 实际覆盖

| 测试组 | 此次实际检查 |
|---|---|
| 默认cold | 30项服务检查、5次新VM闭环；queue与session/binding各9条为既有用例展开，不另算18个故障 |
| 默认snapshot | catalog服务10项；两个租户各120次closed-loop切换 |
| 初始化 | 6个初始化/协议故障；2个单独固定的历史TEST guest镜像各1例，不是普通生产镜像 |
| 双层IO | cold 7项、snapshot/catalog 12项；实际operator32MiB与guest64MiB直接读写、忙writer停止、配置/绑定拒绝 |
| 存储 | IO模式ledger只读5项、默认ledger只读3项、默认ENOSPC 5项；只填/挂自己的64MiB loop小卷 |
| 外层宿主故障 | healthy running/stopped/destroyed三检查点/4次L1启动；quota负例6种及3次后续cold/4次L1启动；独立缺enforcement启动拒绝/1次L1启动（无L2） |

所有组退出成功并走实际finally清理。cold主报告及queue/session展开报告没有顶层`passed`或`cleanup_confirmed`字段，不能补写成功布尔：证明由严格检查清单、成功的Go子测试、runner退出0和独立资源审计组合构成。

[独立只读审计](validation/node-runtime-independent-cleanup-v1.txt)逐个核对早期私有receipt及真实controller路径：13个自己的root/runtime/cgroup域、4个自己的loop backing绑定、9个外层L1执行代际均已消失；未清理/修改其他PID、UID、cgroup、mount或loop。quota/namespace证明先从实际L1读出，不从外层删盘推断。单独quota子任务和总编排进程可以仍在运行，不属于这个默认子矩阵的完成声明。

## 分开观察切换、停止与回收

本次默认snapshot混合负载实际247.812秒，两个tenant各120次，404个资源样本，93对跨tenant重叠switch区间。[原始报告](validation/kvm-node-runtime-default-snapshot-v1.json)保留逐条样本和各视图；quantile由逐条数据独立重算，nearest-rank，未与历史轮次合并。

| 从客户端请求开始的P95 / ms | alpha（N=120） | beta（N=120） |
|---|---:|---:|
| 新绑定响应 | 759.264 | 782.506 |
| 第一条新命令成功 | 777.935 | 804.577 |
| 旧host执行域停止 | 800.450 | 810.962 |
| 旧代持久DESTROYED | 875.017 | 886.894 |

这些观测点不同，不把“新绑定返回”当作旧执行已停止，也不把host停止当作quota/owner/pin和账本都已回收。此默认负载在切换前完成任务、每轮等待旧GC且显式节拍；不是quota忙writer终止压力、开放到达饱和、公平性或长期SLO。宿主背景负载/缓存不受控，扫描含观测开销；PSS、cgroup charge、file residency有重叠，不能相加做uniqueRAM计费。与旧522或别的规格/镜像不能据此宣称加速比。

## 构建、来源和秘密边界

- 本默认runner在Linux原生重建daemon/admin及两个Go测试ELF，mock process smoke重建的daemon也精确等于实际KVM daemon；与独立交叉构建SHA逐项一致。普通guest initrd仍为原v10摘要`2cf3a83a…`，smoke构建出的guest没有被偷偷部署。
- warden、fixture、snapshot builder复用同一冻结2e节点基础runner的精确原生ELF并重新校验。完整native race×3/vet、fixture race×10/vet、root Python72、CGO-free实际kernel/exec filter×3在[foundation provenance](validation/node-budget-provenance-v2.json)绑定，**没有冒充在默认runner中重跑**。Darwin实际执行的8b源码与最终Go路径完全一致，亦未改写执行标签。
- [5套mock进程结果](validation/node-runtime-process-smoke-derived-v1.json)是从私有make日志解码出的原始JSON对象，明确标为derived；内部字段（包括null source_revision）未补写。它们不提供KVM隔离或时延证据。原始make/controller日志、路径/身份、令牌、私有receipt和镜像不公开。
- 旧pre-ledger daemon只建立明确标记的历史升级输入，随后由当前普通daemon恢复，不把旧程序的执行结果冒充新程序。另两个TEST guest镜像及其export只用于固定故障，无HostABI重标记或已分配guest恢复。

此兼容子矩阵自身没有失败前序；[节点基础规格CPU/pids失败前序](validation/kvm-node-budget-node-failed-v1.json)仍保留，不从整个项目历史中删除失败。原始归档仅白名单19个regular文件，审计stdout单独捕获；公开15份原始JSON、1份明确derived的mock JSON、3份安全文本及本子矩阵provenance。

## 仍未验收

[quota240/busy-writer/双活cold及已命名故障的新程序复验](QUOTA_REQUALIFICATION.md)已另完成；schema3 snapshot、全节点free bytes/inodes和实际准备并发压力、uniqueRAM归属、开放到达/公平性/长期资源、双监督失效/物理介质、可靠catalog锁协议、预热/完整初始化、结构化审计/告警/日志与export约束、备份/升级/回滚、独立操作员及SLO仍需完成。[部署恢复契约](OPERATIONS.md)明确区分实现、操作员输入与尚不存在的工具。PR19继续Draft，Goal/M1–M4与`production_ready`不标完成。
