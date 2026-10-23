# schema3快照与节点空间准入压力（有限实机验收）

**不是完整生产或节点饱和验收。** 冻结源码`d432e091c3110c069efa0bf44839f958c97c81aa`新增TEST-only路径；普通生产daemon/admin/warden/builder与已验收2e源的`3ea1e247…/19bbd460…/b290a5ed…/243dedf1…`字节完全一致，只有fixture变为`597b0d59…`。新[原始报告](validation/kvm-node-snapshot-admission-v2.json)和[来源/15个输入SHA](validation/node-snapshot-provenance-v2.json)不重标旧DEFAULT/quota240测量。

## 相同节点策略，明确的新实验规格

`--node-snapshot`与其他profile互斥；L1仍8GiB RAM/12GiB raw disk、outerCG10GiB、CPU8/pids256/swap0/noNIC/hard900s。此次单独声明ext4请求131072个inode，允许既定格式化取整范围131072..135168，避免为inode故障在共享宿主创建大量文件。旧2GiB/3GiB和cold-node规格未改，不能比较不受控加速比。

schema3 NodePolicy保持实例4/records1024/sessions32/prepare1、root7GiB/control1GiB、每代192MiB/128inodes、catalog4条/2GiB、disk10GiB/inodes100000等原声明；frontend计数和实际parent/control/instances内核边界必须匹配。生产planner、TEST helper、Python独立断言共同核对固定full-free guard：**3362619392字节、5776个inode**，不减去已有使用量或临时返还racy credit。

真实L1 builder生成UNASSIGNED模板并验证两个独立克隆；只在首次binding前替换workspace定位。builder是NodeRoot之外的可信离线设置阶段，**不作为全部节点物理内存受控的证明**。普通daemon与所有catalog管理命令（包括status/gc）均用实际control cgroup启动，由未修改的NodeEnvelope再次核验位置。不能从root shell身份推断已在预算内。

## 分开制造inode与字节压力

所有填充均在自有L1的ext4；未填满、重挂载或修改共享L0文件系统。填充者是TEST可信外部消费者，刻意超过正常external budget以模拟故障，不是已准入租户用量、外部预算已强制执行或node-wide project hard quota。

| 本轮实际观测 | 数值 |
|---|---:|
| 专属树内空文件数 | 126592 |
| 完成Stop/Cleanup前可用inode | 5163 |
| 普通daemon完整回收一代后可用inode | 5177 |
| inode full-free guard | 5776 |
| FALLOCATE实际预留长度 / bytes | 8330301440 |
| 字节压力检查点可用字节 | 2825740288 |
| byte full-free guard / bytes | 3362619392 |

inode阶段仍有足够字节空间，free inode在完成普通DELETE/host停止/quota清零/owner删除/持久DESTROYED之后**仍低于5776**。Prepare500、publisher返回明确的node reserve错误、catalog index未变、失败key410；随后等待失败Prepare的allocated/Stop/GC池恢复基线，不把410单独当作异步回收已结束。只按固定生成名、inode/owner/单链接/空文件条件清理，不用RemoveAll/adopt；恢复headroom并检查keeper仍能执行。

字节阶段先创建两个新的真实snapshot guest，两者都Ready/pins2后才采样两份完整quota/namespace/shared-inode基线。排他0600填充文件使用FALLOCATE实际预留块（stat_blocks×512验证**至少**该长度）；长度不是包含ext4元数据和额外开销的精确物理计费总量。两guest各触碰8MiB而非完整512MiB。低空间时新Prepare和新manifest Publish均拒绝、index不变，已有Exec仍成功；不把重复ID拒绝或容量503冒充空间判据。

## 低空闲空间原盘cold与普通回收

1. 健康Q_SYNC+syncfs及私有receipt完成后切断自有L1；这是**同步的低空闲检查点，不是在途元数据提交故障**。外层执行域停止98.603ms仅N1观测，不是生产destroy、物理SSD断电或SLO。
2. 原盘第二次L1启动，普通daemon之前核对精确config/index/真实HostABI与UNASSIGNED export、两份已知initialized owner、quota与完整named inode逻辑身份/共享backing；旧执行域必须消失，低空间guard仍不满足。没有fixture恢复owner、预清quota或重标绑定。
3. 未修改的普通daemon在填充文件**仍保留、free仍低于guard**时成功启动并完成旧代回收；旧key410、4个project全零、pins0。证明startup的capacity/identity检查没有被错误升级为free-space准入，从而阻止恢复。
4. 只核验并unlink精确自有填充文件inode/size/mode/UID/nlink，headroom恢复。此前被空间拒绝的同一份新声明随后可Publish：仅改变原NEVER-assigned export的CreatedAt以得到新declaration ID，不从已分配guest导出或复活退休ID。
5. 两个新的真实guest验证UID/新boot（彼此及相对旧boot均不同）/干净workspace；retire后pins2→1、GC0、survivor Exec、最后GC1逐项核对。最终4个project全零，controller reaped，整个NodeRoot/control/instances移除。

## 回归、来源与尚未完成项

新case加上旧cold-node、owner-unlink pending fsync、unsynced partial-copy、稳定partial EIO、legacy genuine snapshot、clear-owner-pin和六errno/cold，共8个passing scope/19个外层执行代际。[独立只读审计](validation/node-snapshot-independent-cleanup-v2.txt)确认精确root/control/cgroup父子及runner均不存在，没有额外cleanup动作；quota证据来自L1内核，不能从外层删盘推断。

Linux原生full race×3/vet、fixture race×10/vet、root Python76、CGO-free实际kernel/exec filter×3、5个ELF独立cross，以及实际冻结d432的Darwin full race×3/vet通过。公开8原始JSON、7安全文本与provenance；原始归档白名单16个regular成员，audit stdout单独捕获。私有L1 filler/session/owner-cut receipts、身份、console、镜像与凭证不公开。

前置7c revision只完成本地cross/单测，未在服务器执行或启动VM，不伪造一个hardware false记录；代码审查在实机前增加了失败Prepare异步GC栅栏，最终仅d432运行。相关旧scope原有strict inode/keeper/pins/cold比较未放宽。

**还缺**硬件prepare-permit并发/取消等待及blocked-copy下清理轨迹、全部祖先/affinity/最坏物理内存和4个guest完整驻留/OOM、uniqueRAM计费、长期open-loop/fairness/operator/SLO。其他metadata/可靠catalog锁、双监督/物理介质/擦除、预热/完整初始化、archive/rotation、持久审计/告警/外部日志export约束、backup/upgrade/rollback及完整M1–M4仍需实现/验收。`prepare_permit_hardware_trace_claim`明确为false；不从本页有限成功勾选完整节点或生产发布。
