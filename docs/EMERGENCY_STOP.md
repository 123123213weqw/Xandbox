# 停止栅栏写入返回错误后的物理 Stop

**仍非生产就绪或实时SLO。** 本轮修正已实测慢路径，同时保留准入、执行域停止、持久状态、私有资源清理和配额归还的独立边界。[精确角色/工件/报告摘要](validation/emergency-stop-provenance-v1.json) 将旧负对照与新运行时分开。

## 为什么改

历史daemon `c57760c8…` 的 `Manager.stopLocked` 在STOPPING栅栏Save返回错误后直接return，没有请求driver.Stop。busy任务的取消/模糊Exec另会调用driver.Stop，所以很快；idle VM没有这条路径，只停止续约，等待guardian约5秒。不能从busy结果推导所有VM的停止时延。

新实现仅在**同代gate已取得、Save调用已返回错误**后，用独立于caller取消、带配置StopTimeout的context尝试停止精确Ref的已归属执行域；返回 `errors.Join(原存储错误, driver.Stop错误)`。Ref不可变，driver仍只操作自己归属的cgroup，不查询/杀任意PID、不获取catalog GC锁，也不采用未知资源。

```text
内存准入栅栏、取消准备/任务、停止续租
  → 尝试持久化STOPPING
    → 成功：既有driver.Stop → 调用全部退出 → 持久STOPPED
    → 已返回错误：独立context尝试物理Stop → 仍返回错误
                   不写STOPPED / 不发布停止确认
                   不做Cleanup / 不归还容量
```

一次Save可能在rename之后、fsync确认之前报错：即使磁盘上已能看见STOPPING，也不把错误当成持久成功。即使物理Stop成功，也不把它当作调用已全部退出或私有清理完成。后续存储恢复后，普通路径仍需完成driver停止、call-drain和持久STOPPED，再由独立清理池写RECLAIMING、回收、持久DESTROYED后归还容量。

调用者在等待同代gate**之前**就取消，仍服从既有等待取消契约，不能用此补丁声称该前台调用必然执行了这个分支。API错误也不表示毫无副作用：可能已撤权/停止，客户端须按原Ref和持久状态重试，不能重用已失效创建key。

## 新二进制，而非沿用旧报告

运行源码 `35548f67c2ae5a45549e7ecfc312c77c6b6473b0`，Linux原生Go1.27.3 / CGO0 / trimpath / buildvcs=false：

| 工件 | SHA-256 |
|---|---|
| 新daemon | `d2dc5358d0e8adc98847fa6611e6fff6d7e2a48bd28a38b35bed8dca8cbcb7c6` |
| 新admin | `de9114762db85ab635c58880418df75b616a08d3b2111e2e0619ec4fc87e5e74` |

两者均与独立Mac→Linux重编译逐字节相同。原生Linux全量race×3、vet、五套process smoke、全部20个root Python单测通过；[实际native race日志](validation/emergency-native-race-v1.txt) 与 [完整阶段转录](validation/emergency-pipeline-transcript-v1.txt) 已检查无令牌、运行态身份和宿主私有路径后原样公开。原始controller日志、私有receipt和镜像不公开。

先补测试时原实现确实失败；新回归覆盖：before-replace/uncertain-after-replace、caller取消后的独立有界context、存储+driver双错误、StopTimeout、未退出调用不能被物理Stop替代，以及HTTP仍500、不泄露原始存储错误、Exec409、配额保留。传入超时context不是强制抢占：不合约driver或不可中断系统调用不能因此获得硬时间上界。

[源码push CI](https://github.com/123123213weqw/Xandbox/actions/runs/39838834109) 与 [源码PR CI](https://github.com/123123213weqw/Xandbox/actions/runs/39839422404) 各5个实际job/全部步骤成功；它们与实机、后续文档提交CI是不同范围的证据。

## 真实ENOSPC与旧负对照

新的 [5场景报告](validation/kvm-emergency-storage-v1.json) 使用独占private namespace中的64MiB ext4，而不是填满宿主盘。包括guest工作盘满，以及block/inode耗尽×busy/idle；详细故障边界见 [历史存储基线](STORAGE.md)。填充后重新确认host populated、READY及busy任务RUNNING，避免拿已停的VM冒充快速停止。

| 故障 | VM | 请求到删除错误500 | 请求到host cgroup空 |
|---|---|---:|---:|
| blocks | busy | 1.251ms | 43.012ms |
| blocks | idle | 1.364ms | 43.814ms |
| inodes | busy | 1.503ms | 39.604ms |
| inodes | idle | 1.097ms | 48.630ms |

这4个单样本是观测，不是P50/P95/P99、最坏界或生产SLO。全部仍验证：DELETE不返回虚假202；新Exec409；旧持久ledger字节不变、owner/jail保留，未假称DESTROYED；allocated=1且新Create503。仅SIGKILL自己的controller，在空间仍满时普通重启因真实ENOSPC失败；释放本次filler后，同state普通恢复回收旧代、旧key410、新key能创建真实KVM/执行/销毁。**43–49ms不是持久回收时间**，持久回收仍在恢复可写后的阶段。

同一新探针另用旧c577 daemon作 [负对照](validation/kvm-emergency-old-control-v1.json)：block/busy48.318ms，随后block/idle5016.328ms超过1500ms实验guard，预期退出1、passed=false且清理确认；没把失败改写为通过，也没拼进新5场景。此JSON的 `source_revision` 是**新harness/pipeline源码355，不是旧daemon源码**；旧daemon实际来自547cd79a/c577，精确角色在provenance中明确列出。

1500ms只用于此有限实验识别慢路径，非线上超时政策或SLO；正常探针默认不启用该额外guard。参数拒绝NaN/无穷/越界。早期故障的私有resource-receipt在挂载前写到故障卷外，并加入gitignore；它帮助操作员确认自己资源，不授予按任意PID或loop编号清理的权限。

## 新运行时全矩阵回归

| 新daemon范围 | 结果与原始报告 |
|---|---|
| schema2 catalog服务 | [10组检查](validation/kvm-emergency-snapshot-v1.json)，含5次基线会话切换、活pin退役/崩溃/丢owner拒删等 |
| 同一报告中的两租户混合闭环 | 各120次、244.695秒、402个资源样本，93对跨租户切换区间重叠 |
| 普通guest初始化故障 | [6例](validation/kvm-emergency-initialization-v1.json)，不是guest内部崩溃的替代品 |
| 历史TEST镜像中的部分初始化失败 | [1例](validation/kvm-emergency-machine-id-v1.json) |
| 历史compiler-overlay TEST镜像中标记前崩溃 | [1例](validation/kvm-emergency-before-marker-v1.json)，不是未修改生产ELF崩溃证明 |
| 独立冷路径服务 | [30组回归](validation/kvm-emergency-cold-v1.json)，含legacy升级、guardian/队列/绑定等已有场景 |
| 停止/清理与绑定fsync细项 | [queue9](validation/kvm-emergency-cold-v1-queue.json)、[binding9](validation/kvm-emergency-cold-v1-session.json)，是30组中两个场景的展开，不额外加18 |

快照报告中的5次基线、240次迭代和冷路径5次烟测不是255个独立故障场景。整个外层runner退出0，所有新阶段通过；负对照退出1是严格核对后的预期结果。snapshot/init/storage报告明确cleanup=true；冷路径/细项格式没有统一passed/cleanup布尔值，结论依赖检查列表、对应Go test子进程成功及外层strict finally完成，不能虚构这些JSON字段。另从父视图独立复核7组namespace、自己loop绑定/挂载均无残留。

新混合闭环经验nearest-rank（每租户N=120）：

| 租户 | 首次新命令 P50 / P95 / P99 | 旧host停止 P95 / P99 | 旧代持久销毁 P95 / P99 |
|---|---|---|---|
| alpha | 696.385 / 784.652 / 802.801ms | 790.579 / 834.110ms | 863.572 / 906.571ms |
| beta | 707.271 / 773.435 / 809.845ms | 789.276 / 814.418ms | 856.600 / 878.131ms |

这是同机有限、有显式pacing的闭环，不是开放到达、队列饱和、公平调度或置信尾界。[资源口径](MIXED_LOAD.md) 继续适用：PSS、精确模板映射、mincore共享驻留、cgroup charge相互重叠，不能相加为总RAM；永久metadata/runtime高水位不因短测归零。没有与旧冷/快照样本直接相除宣称通用加速比。

实机guest仍为既有pinned v10 initrd/agent和明确标记的历史TEST镜像/从未分配export；本轮没有部署重建的新guest镜像。process-smoke构建出的agent ELF不代表KVM实际使用它。历史故障fixture角色沿用 [镜像provenance](validation/guest-fault-image-provenance-v4.json)。只有历史legacy升级setup使用0022，当前/恢复daemon与所有新测试均0077；保留这些不同角色，不拿旧程序充当新程序。

## 针对返回ENOSPC慢路径的复现

在专用root Linux/amd64 KVM节点检出源码355，使用已打补丁的Go1.27.3构建新host程序；guest资产保持既有固定摘要。不要用旧c577执行此命令后当成新程序验收。完整参数/私有小卷边界沿用 [STORAGE.md](STORAGE.md)：

```sh
umask 077
GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -o /absolute/private/bin/sandboxd-new ./cmd/sandboxd
python3 scripts/kvm_storage_faults.py \
  --daemon /absolute/private/bin/sandboxd-new \
  --warden /absolute/private/bin/xandbox-warden \
  --firecracker /absolute/private/bin/firecracker \
  --jailer /absolute/private/bin/jailer \
  --kernel /absolute/private/assets/vmlinux \
  --initrd /absolute/private/assets/pinned-v10.cpio.gz \
  --workspace /absolute/private/assets/never-used-128MiB.ext4 \
  --source-revision 35548f67c2ae5a45549e7ecfc312c77c6b6473b0 \
  --max-host-stop-ms 1500 \
  --report /absolute/private/new-stop-error-report.json \
  --log-dir /absolute/private/new-stop-error-log-directory
```

此命令只覆盖5个存储场景，不替代上表的快照/初始化/冷路径完整新运行时回归。guard失败不能过滤样本或当成通过，也不能在未核对同一个runner终态时重复启动。私有receipt和原始日志只用于操作员核对自己资源，不上传public。

## 仍未覆盖的边界

- Save卡住而尚未返回、Stop队列/同代gate或全部worker阻塞、不可中断内核I/O/饥饿、不合约driver、双监督失效：仍没有新生产上界，guardian仍必要。
- 介质EIO/只读/掉电/整机重启、完整snapshot多文件系统矩阵、宿主quota/IO预算、物理擦除与长期元数据归档。
- 其余初始化/partial frame/READY写入窗口、预热池、开放到达公平性、唯一RAM归属、可靠审计/告警/升级回滚、独立操作员验收及生产SLO。

这些仍是 [完整生产Goal门槛](PRODUCTION.md)，不因本次修改或PR合并而完成。
