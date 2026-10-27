# 私有镜像全零块写入消除（候选，未完成运行时验收）

普通 Firecracker `copyAsset` 改用逐字节等价的稀疏复制：仍读取并 SHA256 校验
**全部**源字节，仅对全零的读取缓冲区移动目标 offset；其他缓冲区完整写入。
读取缓冲区上限仍为 128 KiB。正确 digest 后 Truncate 到精确逻辑 EOF，覆盖空文件、
全零文件、短读和尾部零区。不是依赖源文件 SEEK_HOLE 的复制：稠密源中的零也能消除写入。

目标仍是 `O_CREATE|O_EXCL` 创建的独立新 inode；额外拒绝非空、非普通或 offset 非零
目标。没有 reflink、硬链接、共享可写 extent、源修改、额外准备并发或重试。复制/校验阶段失败保留
0600 的已归属文件交由原 fence/GC 处理，不自行撤销 ownership、配额或容量。
成功后仍使用原只读 staged mode，workspace 仍由原调用者限制 mode/chown。

SHA、逻辑镜像大小、guest 工作量、project ID/继承检查、配额上限、IO/fsize 限制、
持久化 barrier、N4/prepare1、超时、FIFO、公平性、Stop/回收边界均不放宽。
错误仍 fail closed：处理 `Read` 同时返回的字节后，写入/seek 错误优先于读取错误，
原 IO 错误优先于并发取消；EOF 同时取消不能返回成功。digest 不匹配或取消不能被
当成已验证 EOF；Truncate、Chmod、Close 的错误继续返回。

## 不是已证实的超时根因修复

上一冻结源 e0ea5a3 的第九次原始 KVM 长测仍失败。失败 actor 的已完成 open 中，
准入和 prepare slot 两段共约 18.526 秒，占 open 约 83%；直接复制阶段约 0.866 秒，
**不是 open 的主导阶段**。未返回响应的 switch 内部分段仍未知。
因此这项修改仅是通用的写入工作减少候选，不宣称解决 35 秒 actor 超时或已获得
吞吐/时延改善。阶段定义及父子区间限制见 [CREATION_TIMING.md](CREATION_TIMING.md)。

## 稀疏文件的真实含义

逻辑工作盘容量不缩小，但预先分配的物理数据块会减少。后续 guest 向 hole 写入时
仍需在原 project hard limit 和宿主可用空间内实际分配；稀疏不是磁盘容量预留，
更不是绕过 EDQUOT/ENOSPC 的保证。保留完整 [配额](PROJECT_QUOTA.md)、
[存储故障](STORAGE.md)、原盘 cold/崩溃回收以及持续负载验收，不用单元测试代替。
目前也不增加物理磁盘超售、免费容量或性能 SLO 的承诺。

## 验证边界

`TestAssetCopy*` 覆盖精确字节/SHA/EOF、独立 inode 与并发隔离、零缓冲区写入计数、
短读与 `n>0+EOF/EIO`、错误优先级、EIO/ENOSPC/EDQUOT/short-write/seek/Truncate、
取消、坏目标及普通 wrapper 的物理接线。Linux root-only wrapper 测试只在自身
`/run` 临时目录验证原可信路径、O_EXCL、mode、源不变与失败保留，不是 KVM/配额实测。
非 root 环境明确 skip 该项，不能把 skip 算作运行时通过。

新普通 ELF 需要独立的固定探针校准、软件构建/原生 Linux/CI 及真实 KVM 验收；
旧 e0ea5a3 的软件证书和第九次失败记录不为本修改代签。原 40 分钟负载、100 次 tail、
checkpoint/cold、全部历史失败与完整生产 Goal 均保留。当前不宣称生产就绪。
