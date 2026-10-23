# owner unlink 后、目录 fsync 未返回的原盘冷恢复

> 本页保持原冻结程序的历史证据；准入控制变更后的4ee程序已另行完成[对应有限节点/复制/owner实机复验](NODE4EE_REQUALIFICATION.md)，没有重标本页报告或推断生产就绪。

2026-10-23 固定有限验收通过，见[精确SHA/原始报告/失败前序](validation/owner-cut-provenance-v2.json)。冻结源 `2cbf074ab690faa3c7a67d705dfc51d97f073729`，普通生产Go/daemon522/warden/builder/原guest未改；不是完整元数据故障或生产验收。

## 为什么 quota 清零还不能确认 DESTROYED

普通清理顺序：停止并reap执行域 → 删除私有jail并同步父目录 → 删除cgroup → quota已知记录清零并完成提交 → 在catalog锁内unlink owner、同步owner目录 → 释放内存owner → 持久DESTROYED与返还容量。此处只冻结 **unlink已可见，但owner目录fsync尚未执行/返回** 的一个窗口；不能从文件暂时不可见或quota0推断owner删除已持久化。

实际实测先有两个初始化完成的真实KVM guest，各自验证UID65534、不同boot、marker写入及sync，双方Ready基线在DELETE前同步。随后普通DELETE202仅表示接受意图，不是一个仍pending的同步DELETE HTTP。后台cleanup进入上述目录提交时，TEST观察器核验直接daemon incarnation/TGID:TID/exe、有限FD及精确私有目录inode；确认victim owner名已无、jail/cgroup已无、quota限额/用量/时间均零，再持有该FSYNC而不发送EIO/CONTINUE。

`Valid` 是quota UAPI字段选择位，不宣称整个结构体字节全零。暂停是 **seccomp notification wait，不是filesystem D-state或物理介质故障**。其他FSYNC仍由观察器CONTINUE，避免额外制造全局listener堵塞；本例50次是成功提交回复数，不是所有调用完成数或时延。

## 切点必须不被观测动作悄悄刷盘

选中unlink之后不做观察器quota-sync/syncfs/fsync、catalog admin或L1凭据写入。admin status/GC会调用scanOwners同步目录，不能在此当作只读探针。keeper全树是在victim链接清理后重新**只读**采样，不沿用两个Ready时的共享link计数，也不为稳定计数额外sync。只核验keeper实际KVM执行域仍在；**不在切点后新发keeper guest命令**，因为其job ledger可能fsync同一文件系统。guest数据/UID/boot命令的证据明确发生在DELETE前。

现场API及原子ledger仍RECLAIMING、有StoppedAt、无DestroyedAt，旧Exec409、第三次Create503；503是前端容量证据，不冒充直接backend allocator探针。catalog锁仍被持有，由独立精确inode的LOCK_EX|NB返回EWOULDBLOCK验证；不是声称该锁内慢元数据I/O已移出或其他catalog操作全局不阻塞。

私有凭据只经控制通道保存到外层L0独占0600文件，包含两个已知owner、确切index/RECLAIMING ledger摘要和keeper全metadata；不写入故障L1盘，也不进入公开报告/归档。凭据≤7000字节，compact完整请求仍小于原8192 scanner。target hold60秒，控制回复至外层停止观察必须<15秒。raw/cache.none/aio.native原盘重启，无外层VM快照保存/恢复。自然后台持久化允许发生，不声称任意unlink都丢失。

## 实际冷结果与普通恢复

新case N=1/两次L1启动：断电前owner文件名不可见，**冷启动后victim owner重新出现，字节与原始凭据完全相同，durable pins=2**。victim jail/cgroup仍不存在，先前已提交quota清零仍保留。只证明本次owner重新出现的结果；未把代码允许的owner已不存在分支冒充另一场实测。

启动普通daemon之前核验不同host boot、原配置/export/HostABI UNASSIGNED/index、精确RECLAIMING ledger摘要、已知owner字节、keeper完整metadata/共享backing及实际quota核账。没有fixture重建owner、未知quota收养或一键清零。随后普通**无通知观察器**daemon完成两旧代际DESTROYED/资源消失/旧key410/exec409/all4quota0/pins0；再创建两个新真实guest，UID65534、boot与两个旧guest均不同、无旧marker。retire pins2→1时GC0且survivor可执行，最后pin释放才精确GC1；最后四project0、controller reap、父cgroup删除。

本次外层cgroup停止观察68.003ms，控制回复→停止观察75.681ms，均为N=1外层测试切点，不是单sandbox生产销毁、WRITE/FSYNC提交、物理掉电时延或P95/SLO。

## 失败前序、回归与限制

V1 `e8fbe5e…` 在checkpoint失败，一次L1开机，未返回私有receipt或执行该切点的host cut/cold恢复；[原始passed=false](validation/kvm-owner-cut-owner-failed-v1.json)保留。私有console只有通用resource-temporarily-unavailable，并非完整syscall trace。新fixture错误复用了会主动获取锁的openClearLock；V2改为独立inode核验/非阻塞busy探针，并新增纯测试区分busy/unheld/其他错误。没有放宽owner/keeper/quota冷检查。失败范围的外层退出/路径清理已独立核验，但不是该失败场景普通GC或quota0证明。

原生full race3/vet、fixture race10/vet、rootPython69、实际CGO0内核quota与exec继承过滤各3次、五种native/cross ELF一致、Darwin full race3/vet通过。共享TEST helper只抽取初始化owner校验、稳定或只读keeper采样、普通cold恢复尾段；原partial-copy规则保留、两种receipt跨profile拒绝，相关旧unsynced-cut、稳定EIO/keeper、snapshot shared2/cold3、clear-owner-pin/cold、6errno含clear各3次/cold3均回归通过。共6个passing scope/15个外层执行代际，加失败前序1scope/1代际，合计7scope/16代际独立只读核验清理。

取回归档仅14个白名单普通文件；独立审计stdout单独捕获，私有两份receipt/inner console/运行标识/镜像不取回或公开。证据清单绑定15个公开输入及SHA。quota检查在L1删盘前完成，不从外层路径消失倒推quota清零。旧quota240保持3f9原标签，不重新贴本轮新源码。

仍未完成：其他owner unlink/dirfsync错误及持久结果、其他keeper/pin组合；将慢目录提交移出catalog锁的可靠协议；真实介质/D-state窗口；节点physical/uniqueRAM/IO/catalog/ledger/journal/preparation总准入、开放到达/公平性/长期压力、独立操作员/SLO与完整M1–M4。PR19继续Draft、Goal继续，不能据此生产就绪。
