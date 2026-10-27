# 私有镜像稠密复制与分段回写（候选，未完成运行时验收）

普通 Firecracker `copyAsset` 继续读取、SHA256 校验并**写入全部字节，含零字节**，
单次缓冲区仍为 128 KiB。不使用 sparse、reflink、硬链接或共享可写源，不缩小逻辑
镜像、guest 工作量或物理分配模型。目标仍是 `O_CREATE|O_EXCL` 创建的独立新 inode；
额外拒绝非空、非普通或 offset 非零的目标，错误留给原 ownership/fence/GC 路径处理。

## 撤回无条件零写入消除

历史候选 [`dfc89bc`](https://github.com/123123213weqw/Xandbox/commit/dfc89bc0d2ac7656dc54fc1bfdd0039ed74abc4e)
虽然保持最终字节/SHA/EOF，却会跳过原 `quota_copy_notify` / `node_prepare_cancel`
需要的 **16 MiB WRITE offset、写入前文件前缀及相应配额** 边界。私有 overlay 对其普通
helper 的合成反例中，原稠密循环 oracle ×3 通过、稀疏候选 ×3 失败；后来原生软件
或 CI 通过不能消除该反例。该版本未进入新的 KVM 批次、未合并或部署。

当前撤回的是整个无条件稀疏策略，不是给测试、租户、路径或 profile 加分支，也不
通过只写一个人为稠密前缀来迁就观察器。新回归 `TestAssetCopyPreservesFrozenPartialWriteBoundary`
保留原 WRITE 大小、offset 和之前的文件大小；真实 ext4 quota、18 秒准备取消、cold
及所有旧故障场景仍需实际验证，不由这个软件检查代签。

## 只提前发起已写范围的回写

普通 writer 对**新目标 FD** 执行 Fstatfs：匹配 ext 家族魔数 `0xEF53` 时使用分段
回写 sink，其他魔数保持普通稠密 writer，检查失败则 fail closed。ext2/3/4 共用这个
魔数，**它不是精确的 ext4 身份验证**；quota 模式仍由原 mount ID/UUID/mountinfo
完整验证严格的 ext4 部署，不能用本 hint 选择代替。不是请求/身份/fixture 选择器，没有新 API
或性能 override。sink 不创建 worker、队列或重试，仅保留 written/submitted 两个
游标及首个错误；每写入约 8 MiB 后，对已经写入的连续范围发起
`sync_file_range(..., SYNC_FILE_RANGE_WRITE)`，短读越过段边界时仍拆成每段不超过 8 MiB。
正确 digest 后的 EOF finalization
提交不足一段的尾部；不发送零长度的“整个文件”请求，不覆盖未写范围。

8 MiB 是提交节奏，**不是 dirty pages、物理 IO 队列或完成时间上限**。WRITE 可能
在内核中阻塞，也不代表数据已持久、更不提交元数据或磁盘易失缓存。
原 quota + filesystem `syncfs` 持久化屏障完整保留，不以回写提交替代。
参见 [Linux man-pages](https://man7.org/linux/man-pages/man2/sync_file_range.2.html)。

没有修改 cgroup、IO/BPS/IOPS、project hard limit、fsize、Prepare worker、deadline、
FIFO、身份绑定或 Stop/回收权限。该 hint 仅按上述魔数预选；不同文件系统/挂载模式的
writeback 归属仍须按实际内核及部署验证，不能从函数返回推断 IO 已被正确计费或完成。
魔数定义见 [内核 UAPI](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/magic.h)，
背景见 [内核 writeback 文档](https://docs.kernel.org/admin-guide/cgroup-v2.html#writeback)。

## 失败与验证边界

所有源字节仍参与 SHA；字节写入后才计入回写游标，只有提交成功才前进 submitted。
EIO/ENOSPC/EDQUOT/short-write、提交失败或 Truncate 失败保留原错误并封存 sink，
后续误调用也不重试或追加 IO。`n>0+EIO/EOF`、并发取消的 IO 优先级及 EOF 不能误报
成功；digest 不匹配或读取时取消不能提交最终尾部。Chmod/Close 仍由原 wrapper 返回。
成功后的只读 staged mode、workspace 的原 chown/mode 流程不变。

`TestAssetCopy*` / `TestAssetWriteback*` 分别验证真实普通文件的字节/SHA/EOF/独立副本、
原 16 MiB WRITE 边界、状态机的提交范围/尾部/首错封存、取消/错误优先级及物理接线。
Linux test 执行真实 syscall 和 FD/filesystem 选择检查；root wrapper 测试只在自己的
`/run` 临时目录验证可信路径、O_EXCL、mode、源不变及已确认删除，不是 KVM/quota/cold
证据。非 root 明确 skip 该 wrapper 项，不能把 skip 当作通过。

## 仍未证明提速或生产就绪

e0ea5a3 的第九次原始 KVM 长测仍失败：已完成 open 的准入 + prepare slot 共约
18.526 秒，占约 83%；直接 copy 约 0.866 秒不是主导阶段，失败 switch 的内部阶段
仍未知。提前回写可能改变后续 filesystem-wide barrier 的等待分布，但这只是待验证
的耦合假设，**不宣称修复原 35 秒 actor 超时、提升吞吐或获得时延 SLO**。

改变后的普通 ELF 需自身的探针校准、完整软件/原生 Linux/CI 及 KVM 验收；旧 e0、
dfc 和其他程序的证书不代签。保留完整 [配额](PROJECT_QUOTA.md)、[存储故障](STORAGE.md)、
40 分钟/6360 raw/240 canary/100 tail、checkpoint/原盘 cold、N4/prepare1、历史失败
及完整生产 Goal；不据局部软件正例认定生产就绪。
