# 实际 session pre-Core ticket 跨持久 drain

**一个新的有限实机窗口及两项共享观察器回归通过，不是生产就绪或 Goal 完成。** 普通 daemon 仍为 `4ee09d0a…`，生产 Go、mod/sum 和工作流没有改。冻结TEST源 `98e957661f18344a8482692828b6305a0d28bea3`，归档 SHA-256 `884317cb…`；新fixture `c54a212f…`。来源以[3份原始报告及完整清单](validation/session-ticket-provenance-v2.json)为准，不重标[此前25scope兼容矩阵](RUNTIME4EE_REQUALIFICATION.md)和[节点/cancel4scope](NODE4EE_REQUALIFICATION.md)。

## 实际卡在哪一条路径

`Broker.Open` 先用 `ReserveSessionAttempt` 取得一个进程内一次性 ticket、安装内存记录，再进入 `mutate`。后者首先调用真实session `FileStore.Save`，**返回后**才检查caller取消、建立opCtx并调用 `Core.CreateReservedManagedScoped(...,ticket)`。本次在这个初始 `.session-*` 文件的实际 Sync 入口挂起，而不是模拟 Store 或已进入Core的raw请求。

固定TEST层先核验整个普通ELF、incarnation、exe inode、实际TGID/control cgroup、有效通知ID、固定sessions目录、原样规范数字临时名、root owner/0600/singlelink/同FD inode及0700父目录身份。完整canonical envelope必须是version1、正确tenant/key/spec hash、CREATING/revision0/zero current、唯一PREPARING attempt/expected0/result1/zero target和未进入ready/fence/commit的时间字段。测试还用先前真实session日志交叉核对请求hash推导；final ID文件在Sync前必须不存在。

这只是额外TEST inherited fsync notification层；CAP_SYS_RESOURCE被丢弃、NNP和普通VMM原有过滤器仍核对。只允许exclusive `--node-budget --node-session-ticket`，无任意target/path/argv/errno/RPC phase。初始健康普通启动建立open1后独占干净停止，再启动同一普通ELF加观察层；没有手改准入元数据、used-root自动open或通用start自动resume。

## held → ACK drain → 独立回收 → 原ticket继续

[实际报告](validation/kvm-session-ticket-admission-v2.json)的顺序是：

1. 既有raw VM与session VM分别通过真实KVM/UID/过滤器/boot/干净workspace检查；raw中有实际推进的writer。
2. 原始新session HTTP保持连接，预算40s，不主动cancel。其初始journal Sync被精确持有；pendingSessionReservations=1、既有active=2/Core records=2，没有新Core ledger/backend owner/jail/group/quota slot。初始session只有内存ticket和临时日志，没有已发布final文件。
3. **在同一个目标仍挂起时**，独立operator真实CAS drain获得持久ACK revision2；disk/state与status都确认drained。新raw、新session、既有session Switch全部503 NODE_DRAINING，原ledger名称、既有session字节和history不变。既有raw writer实际进度、RUNNING和旧session实际命令继续。
4. DELETE旧raw，目标Sync仍未放行。分别观察已知kernel执行域empty/删除，以及quota0、owner/jail/cgroup消失和真实持久DESTROYED；之后另查active=1/pending=1/records=2及空闲work pools，不能把后查的credit/pool时间回填到更早时间点。
5. 再核验目标通知有效、原HTTP未结束/取消，仅发**一次CONTINUE**。普通初始Save随后实际成功推进；旧ticket让Core在gate已closed时仍只预留一次，原HTTP返回session绑定，真实第三个guest执行成功，boot独立/干净workspace。pending=0、active=2/records=3；相同session key replay不再预留Core，新的不同key仍拒绝。
6. 保持drained，两个session均实际关闭、全部3代销毁、4个project归零、pools idle、ordinary daemon实际reap后才保存私有receipt。原盘第二次L1启动在普通daemon前先读回ACK drained2；普通无观察器重启仍drained/pending0，旧3个key410/无route/ticket复活，精确drain retry不增rev，显式resume3后原拒绝key可创建新的第四个真实guest并全部清理。

**计数字段口径：** 原始 `existing_active_before_continue=2` 指最初held点及ACK后、旧raw删除前的既有两实例基线，**不是最终CONTINUE前瞬时active**。同一冻结程序在raw已GC后、目标仍有效时另强制核对active1/pending1/records2，才允许发CONTINUE。原始JSON未改字段或回填时间；来源清单将这两个阶段分开标明。

## 分开观察停止与回收

| 本例N=1观测点 | ms |
|---|---:|
| 从旧raw DELETE到host执行域empty/已删除 | 46.773 |
| 从同一次DELETE到本代private/quota0/持久DESTROYED | 539.708 |
| 从原session请求发出到观察Ready响应 | 3565.184 |

第三项包含持有窗口与整个创建，不是CONTINUE到ready或精确内部阶段时间。它们含API/readback/轮询开销、只各一个样本，不是线上SLO、擦除或全部kernel cache释放。hold20s、原HTTP40s、普通Prepare30s未增加。目标得到1次CONTINUE、0次合成errno/成功flush；另有15个其他FSYNC CONTINUE回复，**不是15次已完成I/O**。Ready、后续持久日志及代码检查顺序共同证明初始Save已推进，不把通知回复本身当Sync完成。通知等待不是filesystem D/介质故障。

## 共享观察器的独立回归

由于TEST观察器新增固定session selector/CONTINUE分支，使用同一新fixture和普通4ee，重新实际执行 [pre-file](validation/kvm-session-ticket-store-pre-v2.json) 与 [post-root](validation/kvm-session-ticket-store-post-v2.json) 两项真实operator Store窗口。它们仍各一次TEST EIO，分别cold读回old open1/new drained2，保留caller取消后writer不撤销、内存fence、status/BUSY/old进度和独立回收边界；没有把旧[c49报告](NODE_OPERATOR_STORE.md)换名冒充新运行。两个回归各2次L1启动，加本例2次共6个外层代际。

[最终独立只读审计](validation/session-ticket-independent-cleanup-v2.txt)核对3个scope的精确root/control/cgroup-parent及全部6个代际均不存在；无补救清理。quota/namespace证明在live L1读取，不从外层删盘推断。raw console/controller/身份/epoch/请求ID、私有receipt/token/key及镜像均不公开。

## 冻结失败前序与构建

首版冻结 `9ecc3c6…` 在native fixture unit gate发现 `filepath.Dir` 会清理 `..`，使别名路径通过只期待原样规范路径的selector。完整ordinary race×3/vet已过，但fixture10次重复均在同一反例失败；pipeline退出1，在六个部署用原生artifact构建及任何QEMU/KVM前停止。不是10次硬件失败，也不把整条pipeline改写为成功。[原失败输出](validation/session-ticket-unit-failed-v1.txt)和原source/archive/status/runner摘要保留。

修正仅在TEST selector加 `filepath.Clean(path)==path`，保留原反例并增加重复slash/dot-segment反例，不放宽生产/NodePolicy/ownership规则。最终冻结源实际native race×3/vet、fixture×10/vet、rootPython99（0skip）、CGO-free实际kernel filter×3、make mock6、Darwin race×3/vet全部完成，六个native/独立cross逐字节相同；普通五个产物仍等于先前4ee集合。[mock6](validation/session-ticket-mock-derived-v2.json)是私有make日志中六个原始JSON的明确derived副本，不改内部字段，也不是KVM/性能证据。白名单raw归档20个regular成员同时保留失败前序，audit stdout另外捕获。

## 尚未完成

本例最终完成原始request及writer后才干净Stop，**尚未证明未完成control writer在shutdown/run返回后保持state lock直到真正进程退出**；这与本例是不同窗口。其余metadata/catalog持久窗口、最坏RAM/ancestor/affinity/uniqueRAM/全资源压力、open-loop/fairness/长期SLO、生产TLS/凭证生命周期、真实operator/systemd、持久审计/告警/日志预算、archive/rotation/备份/升级/回滚及完整M1–M4仍未完成。PR19保持Draft、main/主分支ZIP不变、Goal ACTIVE且`production_ready=false`。


后续[未完成control writer跨真实shutdown/run返回/进程退出的锁窗口](OPERATOR_SHUTDOWN.md)已另绑新冻结TEST源与实机证据：两个通知同时有效时第二个同普通daemon仍被kernel锁拒绝，仅CONTINUE退出、实际reap1后旧写入通知失效；原盘oldopen1恢复和三项共享回归完成。4个通过scope/8代及失败1代均独立只读审计无残留。上述历史scope/false字段不回写；这不代表其他metadata窗口、生产operator/TLS/凭证/networking、资源压力或完整Goal验收。
