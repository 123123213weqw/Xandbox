# d163：DEFAULT / IO / quota240 命名兼容矩阵

**有限兼容矩阵通过，不是完整 M1–M4、生产就绪或 Goal 完成。**
冻结源 `b462946`、普通 daemon `d163a628…`，9个产物与先前 native/cross 逐字节相同。
[脱敏摘要与原始归档指纹](validation/d163-runtime-v1.json)保留每个原始报告的来源、文件名与摘要。

## 证据组成

- 本批18个新 scope：DEFAULT cold30/load5、queue与session/binding各9项展开检查；
  DEFAULT snapshot10及双租户各120次切换；初始化6例、两个明确的历史 TEST guest 故障；
  IO snapshot12；健康原盘cold；quota240/双活cold、listener两例、重复syscall错误、
  reserve/pre-clear/post-clear窗口、owner/pin清零、quota snapshot及DEFAULT/quota整状态盘IO。
- 同一个冻结源、同一批普通ELF的7个[前批cause回归](DIAGNOSTICS.md)复用：
  DEFAULT/IO × ENOSPC/ledger-only EROFS四组，以及quota负向、unenforced拒绝和真实SYNCFS-EIO。
  它们不是历史ELF的测量，未重命名、重构或伪装成这次runner的新执行。
- 共25个命名兼容scope；18个新scope的36个外层执行代际独立只读确认不存在，
  加前批7个代际为43，四个前批loop绑定亦已有独立复核。没有补充清理动作。
  guest/quota/owner/pin证据在live L1中取得，不能从最后删盘推断这些性质。
- 23个本批白名单regular原始成员归档指纹及15个前批归档指纹分别保留。
  私有receipt、controller/inner console、运行态身份、token和镜像不公开。

当前普通诊断不再输出原始路径，所以独立复核**不**依赖controller日志中的路径子串，
也不恢复该泄露。它读取有界、原始fsynced、0600/root-owned/single-link/NOFOLLOW的私有
receipt，核对冻结harness的精确scope构造及这些声明路径的缺失；不冒充全机进程清单或
任意escape证明。raw receipt摘要也只留私有审计结果。

冷路径和两个Go展开报告本来没有顶层 `passed/cleanup`，本次未补造字段：由精确检查清单、
实际Go子测试、runner退出0和独立资源复核组合证明。离线核验保留原有数字/状态合同，
另实际执行136个recovered及8个live-IO反例；不把前次物理extent数量或未fsync PID文件
内容当不变策略。冻结L1仍核对当前kernel charge、当前namespace和精确逻辑身份。
发布器实际拒绝81个source/范围/报告缺失变体。

## 四类时刻分别测量

以下是N=120/tenant、从各自客户端请求开始的nearest-rank P95（ms），从本批逐条数据独立重算。

| 观测点 | DEFAULT alpha | DEFAULT beta | quota busy alpha | quota busy beta |
|---|---:|---:|---:|---:|
| 新绑定响应 | 759.529 | 769.341 | 1369.804 | 1372.045 |
| 第一条新命令成功 | 785.053 | 790.784 | 1471.644 | 1464.024 |
| 旧 host 执行域停止 | 789.286 | 806.193 | 1398.415 | 1397.383 |
| 旧代持久 DESTROYED | 871.462 | 875.778 | 1599.916 | 1637.530 |

DEFAULT实际混合负载 246.985s；quota busy
602.698s。前者在切换前任务已完成；后者每次都有
真实运行旧writer，且验证其推进及host停止先于最早可能任务deadline。两种负载/资源规格不同，
不是加速比。绑定成功不证明旧执行已停止，执行停止不证明owner/quota/pin和持久账本已回收。
有限paced closed-loop、非事务资源采样及这些P95不是开放到达、公平性、长期稳定性、
unique RAM计费或线上SLO。

## 仍待完成

新d163/41e9的owner unlink、在途partial-copy、operator/session ticket/未完成writer退出/
control提交，以及TLS/policy metadata为独立门禁，只有其自身新实测与独立复核才可通过。
节点级磁盘/RAM/CPU饱和、可靠租户审计/告警、独立operator/systemd安装恢复、PKI分发、
open-loop/fairness/长时负载和备份/升级/回滚仍未完成。既不以通知挂起冒充filesystem D，
也不把owned-L1的mapper错误等同于真实物理介质故障或安全擦除。
