# 新4ee运行时：默认、IO及quota240完整命名矩阵复验

**本页命名的有限兼容矩阵通过，不是生产就绪或完整 Goal 验收。** [原3ea默认](RUNTIME_REQUALIFICATION.md)和[quota](QUOTA_REQUALIFICATION.md)报告保持原样；它们没有改名作为新程序证据。新增准入控制后的普通 daemon `4ee09d0a…` 本次实际重新执行全部这些路径；仍没有 host fallback 或生产故障开关。

冻结源 `ab048ed65b12fc806cba9d16eecd1c830c37fa93`，归档 SHA-256 `6c733ba3…`。[来源清单](validation/runtime4ee-provenance-v1.json)绑定两处 TEST Python 修改、8 个新原生/独立交叉逐字节相同产物、27 份原始 JSON 和私有白名单归档 38 个 regular 成员。普通 daemon/admin/warden/node CLI/fixture/builder 与上一轮相同；两个 Go 测试 ELF 也从此次冻结源新建。没有将旧源的硬件成功重标为本次成功。

## 升级测试的显式授权

旧 daemon 只负责建立明确标记的历史 v0 ownership。其死亡后，新程序拒绝未迁移账本，并为已经使用的根持久创建 drained/revision1；迁移仍不虚构资源回收。新程序回收旧 KVM、旧 key 保持410；新 distinct key 先503 NODE_DRAINING。测试用已哈希、复制为0555的同 UID node CLI 核对原 epoch、drained1、1条已销毁记录和0 active，显式 CAS resume2，再核对持久状态及 status；同一 distinct key 仍503 METADATA_CAPACITY。没有删除准入元数据、通用 start 自动恢复、扩大预算或生产 fail-open。epoch/请求ID和CLI诊断只留私有日志。新增5项正反例；这段真实 KVM 迁移也实际通过。

## 实际范围

| 组 | 本次重新执行 |
|---|---|
| 默认 cold | 30项服务检查、5轮新VM闭环；queue与session/binding各9条为展开检查，不另算18个故障 |
| 默认 snapshot | catalog10项；两租户各120次 paced closed-loop，实际 245.468s |
| 初始化 | 6个协议/初始化故障；固定历史TEST guest镜像各1例，共2例，不是普通生产镜像 |
| 双层 IO | cold7项、snapshot/catalog12项；host32MiB和guest64MiB真实直接读写、限流readback、忙writer停止 |
| 存储 | IO ledger只读5项、默认ledger只读3项、默认ENOSPC5项；只挂载/填自己的64MiB loop卷 |
| 健康/拒绝 cold | healthy三检查点、quota负例与cold、缺enforcement拒绝；9个外层L1执行代际 |
| quota busy240 | 两租户各120次切换，实际 602.086s；每轮验证真实writer推进且host停止先于最早可能任务deadline |
| quota cold/fault | 双活两租户原盘cold；listener丢失、固定syscall errno、真实syncfs EIO、reserve/preclear/postclear窗口、owner/pin清理、snapshot及quota/default whole-state IO；34个外层代际 |

默认/IO13个scope与quota12个scope均成功退出。[独立只读审计](validation/runtime4ee-independent-cleanup-v1.txt)实际核对25个scope、4个自己loop绑定、43个外层执行代际和精确root/runtime/control/cgroup全部消失；没有补救清理动作。quota/namespace/owner/pin证明在live L1内读取，不能从外层删盘推断。cold主报告和queue/session展开没有顶层passed/cleanup字段，仍由实际检查清单、Go子测试、runner退出0及独立审计组合证明，不补造布尔。

## 切换、停止与回收不是同一指标

以下均从各自客户端请求开始，N=120/tenant，nearest-rank，已从逐条原始数据独立重算；未跨规格或历史轮次混合。

| 观测点 / P95 ms | 默认 alpha | 默认 beta | quota busy alpha | quota busy beta |
|---|---:|---:|---:|---:|
| 新绑定响应 | 759.838 | 762.864 | 1421.456 | 1355.835 |
| 第一条新命令成功 | 774.260 | 775.937 | 1496.470 | 1427.218 |
| 旧 host 执行域停止 | 796.836 | 795.039 | 1450.889 | 1373.752 |
| 旧代持久 DESTROYED | 870.771 | 883.203 | 1594.335 | 1639.176 |

默认 mixed 资源样本 407 条、跨租户switch重叠 89 对；quota busy分别为 1194 条和 150 对。默认切换前任务已完成；quota每轮旧writer仍在运行且有实际进度，两者不当成同一负载或加速比。新绑定返回不证明旧guest已经停止；旧host停止也不等于owner/quota/pin和持久账本全部回收。资源采样非事务性且会漏峰，RSS/PSS/file-residency/cgroup charge有重叠，不能相加当unique RAM或计费。这里只是同宿主有限节拍闭环，不是开放到达、公平性、长期稳定性或线上SLO。

## 存储与证据边界

whole-state IO在**自己的L1**使用dm suspend/error，实际观察普通daemon fsync的filesystem D、独立host停止和存储恢复；不是用seccomp通知等待冒充D。它也不是物理介质故障或所有operator FileStore提交窗口的证明；[前轮FileStore](NODE_OPERATOR_STORE.md)仍仅证明其明确命名的TEST errno窗口。readonly/ENOSPC只作用于自己的private mount namespace和精确autoclear loop，未改共享宿主mount、内核模块、sysctl或quota设置。

离线核验在quota结果出现前已执行136个反例：保留128..192MiB边界、4096对齐、固定namespace shape、receipt绑定及非权威PID语义，不把前轮物理extent数当不变策略。冻结L1仍将**当前**kernel quota与**当前**独立namespace计量及精确持久逻辑身份比较，硬限制/owner校验没有放宽；jailer未fsync的诊断PID文件允许为空或非空，不作为kill/recovery权威。

离线汇总首版曾将“mapper恢复后已实际销毁”的hang用例也当成仍有live owner的cold，用不存在的charge字段导致KeyError；[修正记录](validation/runtime4ee-offline-correction-v1.json)保留原核验器及失败stdout摘要。修正仅区分live/EIO与已clear的hang路径，另8个live反例通过，并明确拒绝在已clear recovery中伪造charge/PID字段。冻结实机源码、硬件规则和38个原始成员未改，未重跑硬件或把失败改写为通过。

Linux native full race×3/vet、fixture race×10/vet、root Python95（0 skip）、CGO-free实际kernel filter×3及mock进程smoke均实际重跑；Darwin冻结源race×3/vet亦实际完成。[6套mock结果](validation/runtime4ee-process-smoke-derived-v1.json)只从私有make日志解码原始JSON，不改内部字段，明确derived，不提供KVM隔离或时延证据。raw console/controller/receipt、身份、operator epoch/请求ID、令牌和镜像不公开。本矩阵无硬件失败前序；项目历史失败报告完整保留，不拼入本轮测量。

## 尚未完成

新4ee命名的schema3 snapshot空间/prepare entry trace/原始排队取消与owner、复制窗口已另行[实际复验](NODE4EE_REQUALIFICATION.md)，其原始报告和有限范围不回写本页测量；仍需完整最坏节点资源压力、实际drain跨已接受pre-Core session reservation、shutdown期间未完成control writer保持锁窗口、unique RAM/open-loop/fairness/长期SLO、生产TLS网关与凭证生命周期、独立operator/systemd安装恢复、持久审计/告警/外部日志预算、archive/rotation/备份/升级/回滚及其余M1–M4。PR19保持Draft，main和主分支ZIP不变；`production_ready`与Goal不标完成。
