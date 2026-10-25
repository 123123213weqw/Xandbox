# 5bfb：25个全新命名运行 scope 通过

**完成的是具名兼容/故障矩阵，不是完整生产验收或Goal完成。** 冻结 harness 源37a862a，
普通daemon `5bfb2394…`；[脱敏摘要](validation/fiveb-runtime-v1.json)按原始文件名记录全部27份
报告指纹（25 scopes及两份Go展开报告），不改旧d163报告、来源或测量行。
原生构建源e1aec85的cmd/internal/go.mod/go.sum与37逐字一致；实际程序仍绑定原native/cross集合。
此矩阵使用原fixture b02。后续fixture320的live trace/10边界及真实systemd部署另有独立来源，
**不是这25组都经由Go launcher/systemd启动**。

## 全部重新执行，不复用旧ELF测量

- DEFAULT cold30、真实旧binary/KVM账本导入、5次新guest切换闭环；queue与session各9条
  是已有用例的展开报告，不额外计作18个独立场景。
- DEFAULT snapshot10及两租户各120次切换；初始化6例、两类明确标记的历史TEST guest故障；IO snapshot12。
- 健康原盘cold；quota两租户各120次忙writer切换/双活cold、listener两例、重复syscall错误、
  reserve/pre-clear/post-clear窗口、owner/pin清零、quota snapshot与DEFAULT/quota整状态盘IO。
- 旧d163矩阵曾复用的7个cause scope，本次全部对5bfb**新执行**：DEFAULT/IO ×
  ENOSPC/ledger-only EROFS四组，quota negative、unenforced拒绝与真实SYNCFS-EIO。
- 独立只读原始receipt复核覆盖25 scopes；43个嵌套外层执行代际、全部声明root/control/parent/
  cgroup和4个owned loop绑定确认不存在，没有补充资源清理。不以最后删盘推断live L1中的
  quota/owner/pin/guest状态，不冒充全机进程清单或绝对escape证明。

核验按原始source/harness/helper/ELF、数字/状态合同和逐条数据执行；物理分配沿用冻结代码的
独立CURRENT kernel-vs-inode核账，不把前一轮extent数量或未fsync PID诊断文件当不变策略。
136个recovered及8个live-IO分配反例再次运行；额外拒绝布尔冒充数字、非有限数及将20份旧来源
报告当作新测量的输入。这里复用的是审阅过的**验证代码合同**，不是历史数据。

离线核验器首轮因子串分类把logical io-cold当成default-cold，错误要求legacy/queue/session
输入，正确的原始io-enospc报告只有workspace及实际生产资产。修正为精确匹配default-cold
类别；保留IO全部资产/类型/内核读回/压力要求。首次拒绝留在私有证据中，未改原始数据、
未重跑硬件、未改数字/超时来通过。

## 四个时刻分别计量

下表是各组N=120的nearest-rank P95（ms），由本批原始逐条数据独立重算。

| 起点到观测点 | DEFAULT alpha | DEFAULT beta | quota busy alpha | quota busy beta |
|---|---:|---:|---:|---:|
| 新binding响应 | 797.858 | 787.590 | 1453.852 | 1371.401 |
| 首条新命令成功 | 814.398 | 813.789 | 1547.736 | 1436.582 |
| 旧host执行域停止 | 834.724 | 822.737 | 1488.238 | 1382.955 |
| 旧代持久DESTROYED | 908.563 | 893.195 | 1607.443 | 1655.495 |

DEFAULT持续246.352s，quota busy持续604.492s。前者切换前任务已完成；后者每次都有真实
运行的旧writer且观察其推进，host停止早于最早可能任务deadline。它们资源与负载不同，
不是加速比。部分DEFAULT阶段同共享L0上的有界native校准build重叠，负载/暖缓存不受控。
绑定成功不证明旧执行停止，停止也不证明持久账本、owner/quota/pin完整回收。
有限paced closed-loop及非事务采样，不是open-loop、公平性、长时稳定性、unique RAM计费或生产SLO。

## 仍未完成

另一个冻结7fc/fixture320的[12组实际trace/压力/取消及命名边界](FIVEB_BOUNDARIES.md)
也已取得独立新来源与24代际复核，但不混入本矩阵或重写本矩阵的原始来源。真实systemd TLS/catalog组合、安装升级/备份、独立操作员、
可靠租户审计/保留、节点饱和/open-loop/生产SLO仍在[完整门槛](PRODUCTION.md)内。
指定notification、mapper、syscall、ENOSPC/EROFS场景不等于任意物理介质掉电、D-state限时回收或安全擦除。
所有raw console、receipt/其摘要、凭证及运行态身份保持私有。
