# 准入状态实际 FileStore 的提交错误窗口

**普通 daemon `4ee09d0a…` 的两个有限实机窗口通过，仍不是生产就绪或物理存储故障验收。** 本次不再使用模拟 Store：请求经过真实 operator socket、Controller、FileStore、临时文件和目录提交路径；TEST listener 仅让一个已精确识别的 fsync 入口等待，再返回一次合成 EIO。生产 ELF、准入协议、预算及 VMM 原有过滤器未改。

冻结源 `c49cb9e04e1e824e05a9e8216769e1e509f7c3c5`，归档 SHA-256 `688149a2…`，TEST fixture `f7c712bb…`。普通 daemon/admin/warden/node CLI/builder 五个 ELF 与[原生预验收](validation/node-control-prequalification-v1.json)相同，六产物独立交叉/原生构建逐字节相同。[来源清单](validation/operator-store-provenance-v1.json)绑定 7 个 TEST 修改输入、两份报告和 12 个私有原始成员摘要。先前失败与健康 operator 报告保持原样，没有回写或重标。

## 选择的是哪个真实调用

使用原 `node-budget-v1` 的 L1 8GiB/12GiB/CPU8/noNIC、schema3 N4/records1024/sessions32/prepare1、原 quota/IO 和 NodePolicy。一次健康普通启动先初始化控制状态，再独占干净退出；随后固定 TEST wrapper 降 CAP_SYS_RESOURCE、安装 inherited fsync notification 层，并 exec **同一个普通 daemon**。没有手工初始化、恢复或编辑准入元数据。

目标校验包括：普通 ELF 整体 SHA 与运行 inode、进程 incarnation、通知 TID 的 TGID、实际 control cgroup、通知 ID、固定 fd 范围、路径/owner/mode/同 inode，以及下一状态的完整 payload。`/proc/PID/cgroup` 使用 hierarchy-relative path，而非挂载路径。只允许两种预置窗口，不接收任意 PID、fd、errno、路径或命令：

| 用例 | 实际观察到的顺序 | 返回 EIO 的目标 |
|---|---|---|
| [pre-file](validation/kvm-operator-store-pre-v1.json) | 临时文件已写入，payload 是精确 revision2/drained；现有 state 仍为 revision1/open | 临时 `.state-*` 的第一个 file fsync，尚未 rename |
| [post-root](validation/kvm-operator-store-post-v1.json) | file fsync 入口放行后，观察到 admission 目录 fsync；临时名已消失，state 是同一个临时 inode 与精确新 payload；再观察到 root 目录 fsync | admission 目录同步返回以后、根目录的 fsync |

`CONTINUE` 本身不证明调用完成。post-root 中，后续普通目录调用、同一被 rename 的 inode 和已冻结代码的检查顺序，共同证明前序 Sync/Close/rename 已成功推进，而不是只从“发出了 CONTINUE”推断提交。

通知等待表示该调用尚未执行；响应可指定结果，或让内核继续执行。因此它不等于 filesystem D，也不能把通知回复数当作成功 I/O 数。[Linux seccomp_unotify 手册](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)定义了这些接口语义。该层是 TEST 工具，不是生产安全策略或生产依赖。

## 目标仍挂起时的行为

每个用例先建立独立 raw VM 和 session VM，核验真实 KVM FD、过滤边界、UID、boot ID 与干净 workspace。raw 内启动持续推进的任务，然后提交 drain。

实际目标入口被持有后，客户端主动取消等待：

- 通知 ID 仍有效，Controller 仍为 pending，gate 关闭；客户端断开没有撤销已接受写入。
- 私有 status 与另一 mutation 的 BUSY 响应均通过独立 1 秒实验 guard。它不是线上延迟 SLO。
- 新 raw/session/Switch 均返回 `503 NODE_DRAINING`，ledger 名称集合、session 文件字节和记录数量不变。
- 已接受 raw 任务继续推进，旧 session 命令实际完成且输出正确。DELETE raw 后，执行域停止、私有回收、持久 DESTROYED、quota0 和相应后台池基线都在目标仍挂起时核验。
- listener 持续处理其他 fsync，而非把全局 listener 卡住；每例目标持有期间各有 12 个其他 CONTINUE 回复。这个数字不是12个已完成 flush。

随后仅向原目标返回一次 `error=-EIO`，不合成成功返回值；目标 ID 失效，普通 FileStore/Controller 进入 fenced。新的管理 mutation 被 `PERSISTENCE_FENCED` 拒绝，新资源预留仍关闭；已有 session 执行和其后回收继续。缓存 committed 状态仍是旧值，即使 post-root 的磁盘已是新值；status 不是磁盘持续读取或备份证书。

## 错误后的冷恢复结果

两个旧 guest 均完整回收、四个 projects 为零、观测 daemon 干净退出后，才保存私有 receipt 并切断自己的 L1。因此这是**错误之后的同盘 cold**，不是在 held syscall 内断电，也不验证“未结束 writer 退出时保留 state-lock”的真实窗口。

| 用例 | 进程内错误栅栏 | 普通 cold 启动前的磁盘与恢复后模式 |
|---|---|---|
| pre-file | pending → EIO → fenced，不能在原进程 resume | 原 epoch 的 revision1/open；普通重启可重新开放 |
| post-root | pending → EIO → fenced，内存 committed 仍旧 | revision2/drained；最近原命令可精确 replay，显式 resume 后才开放 |

**失败且未 ACK 的 drain，不保证重启后仍然 drained。** pre-file 正是旧 open 合法回来的证据；不能将临时内存 fence 说成已持久化意图。post-root 则证明返回错误也可能已经提交，恢复必须以实际有效 namespace 为准，不能发明回滚。两例均在普通 daemon 启动前读回精确状态，未修复或还原 control 文件。

恢复后旧 raw/session keys 均410；之前拒绝的 raw key 可创建真正新 guest，其 UID、boot、干净 workspace 另验，最后再次销毁、清零 quota、确认池 idle、回收普通 daemon 并移除整个 NodeRoot。

## 单次观测与边界

均从 DELETE 开始计时，且发生在控制目标 fsync 仍未获得回复时：

| 目标窗口 | 实际执行域为空 | 私有资源缺失、持久 DESTROYED 与 quota0 |
|---|---:|---:|
| pre-file | 54.039 ms | 375.964 ms |
| post-root | 59.776 ms | 395.506 ms |

每格 N=1，是独立观察上界；不是内核精确停止时刻、完整信用返还时刻、物理擦除、性能改善或生产 SLO。信用/池基线另行核验，不能倒填到私有回收时间。

冻结源 Darwin/Linux 全量 race×3、vet，Linux fixture race×10/vet、CGO-free 内核 quota filter×3、root Python90项零跳过均通过。冻结后这两个 hardware 用例没有失败前序或重采样。开发编译时的缺 import、源码审查中的 cgroup path 修正均发生在冻结与硬件运行前，来源清单已注明。

2 个 scope/4 个外层执行代际全部通过，并由独立只读审计确认实际 root/control/cgroup parent/全部代际不存在。审计不补清理，quota0 与 namespace 由 L1 内、磁盘删除前的检查证明。原始 console、私有 receipt、ID、keys、epoch、运行路径不公开。

**仍待完成：** 真正的 filesystem D/介质 EIO、新程序完整 DEFAULT/IO、quota240/双活cold/故障及 snapshot/prepare/cancel 矩阵、实际 drain 下 pre-Core session ticket、更多提交/中断/关闭窗口与长期尾部，以及独立部署/网关/审计/备份回滚等生产门槛。健康 ACK 的持久性另见[前轮有限 operator KVM](NODE_OPERATOR_KVM.md)，不与本页的未 ACK 错误结果混用。Goal 与 Draft PR 保持未完成。

后续[实际session pre-Core ticket](SESSION_TICKET_DRAIN.md)扩展了TEST观察器的固定selector，并用新fixture实际重跑本页pre-file/post-root两组窗口，原始报告另绑98e9576冻结源；本页c49冻结结果和计数保持不变。新增CONTINUE分支只用于session目标，原operator目标仍各一次TEST EIO；都不冒充未完成writer的shutdown锁证明。


后续[未完成control writer跨真实shutdown/run返回/进程退出的锁窗口](OPERATOR_SHUTDOWN.md)已另绑新冻结TEST源与实机证据：两个通知同时有效时第二个同普通daemon仍被kernel锁拒绝，仅CONTINUE退出、实际reap1后旧写入通知失效；原盘oldopen1恢复和三项共享回归完成。4个通过scope/8代及失败1代均独立只读审计无残留。上述历史scope/false字段不回写；这不代表其他metadata窗口、生产operator/TLS/凭证/networking、资源压力或完整Goal验收。
