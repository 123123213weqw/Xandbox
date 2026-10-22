# 双层实验性 I/O 预算（待实机验收）

**开发中，本页还不是通过的验收报告。** 新的operator配置 `io` 同时约束Firecracker workspace请求与每代cgroup的块设备I/O；尚不能将单元测试或读回配置当成实际限流证据。没有完成节点总I/O、controller准备阶段复制、物理空间quota或完整M2。

## 设计

`io` 是与state永久绑定的操作员策略，不是tenant字段；默认缺省保持旧实验行为。配置后缺少io委派、设备/文件系统不匹配、写入或读回失败，都应拒绝创建，不能忽略限制继续运行。不存在在线策略重绑，旧state不能直接加/删/改此字段来绕过恢复。

```json
"io": {
  "version": 1,
  "filesystem_device": "8:3",
  "device": "8:0",
  "bytes_per_second": 8388608,
  "operations_per_second": 4096
}
```

这些设备号仅作示例，不能照抄：启动及每次Prepare需核对runtime的实际st_dev和sysfs backing queue。v1仅接受直接块设备上的ext4/xfs（可含普通partition），拒绝loop/dm/MD/虚拟队列/其他文件系统/未知拓扑，不猜测多层映射。只对自己新建、持久Ref归属的cgroup写 `io.max`；不修改系统级controller或共享设备配置，实例出生仍用CLONE_INTO_CGROUP。

- cgroup层：对应queue的rbps/wbps各为bytes_per_second，riops/wiops各为operations_per_second。全部方向写入后严格读回，缺失io.max不能被创建成普通文件。
- VMM层：workspace的读写请求**合用**bandwidth及ops token bucket，1秒refill、容量等于配置每秒量，没有额外one-time burst。cold在InstanceStart前设置并读回；snapshot在load为PAUSED后覆盖序列化的bucket并读回，成功后才Resume/Initialize。
- bytes_per_second范围1MiB..1GiB，operations_per_second范围128..65536，均必须有界正数。稳定桶自身允许burst，不是任意1秒滑窗的物理硬上界或时延SLO。

为什么需要两层：Linux缓冲写回按inode归属，初始复制镜像的controller可能仍是该inode/page的归属，不能仅凭VM的io.max就宣称所有guest缓冲写都计入该组；缓存命中也不是块设备I/O。VMM请求限流在host page cache之前提供另一道边界，不靠错误的writeback归属假设。依据 [cgroup v2 Writeback与io.max](https://docs.kernel.org/admin-guide/cgroup-v2.html#io) 和固定版本 [Firecracker Drive API](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/src/firecracker/swagger/firecracker.yaml)。

## 待执行的证据

`scripts/kvm_storage_faults.py --io-budget` 及 `scripts/kvm_snapshot_smoke.py --io-budget` 选用固定8MiB/s、4096ops/s，要求实际KVM而非mock：

1. 两层读回、实际设备归属、真实VM fd。
2. 固定32MiB全零O_DIRECT**可信操作员探针**进入自己已拥有的cgroup后才写数据，核对该组io.stat和完成时间；它不是tenant命令、生产执行或VM出生路径，宿主没有租户shell fallback。
3. guest UID65534的64MiB direct写/读、正在写盘时的物理Stop与持久DESTROYED分别计时。不能将读回配置、缓存快、单样本或粗实验guard当生产带宽/尾界认证。
4. 默认未配置IO的旧冷/快照/初始化/存储故障矩阵应以新native程序重新验收；旧D2dc报告不能自动覆盖本次Go变更。

原始controller日志、Ref、argv/输出、receipt、磁盘和内存不公开。即使本轮小实验通过，宿主准备复制/共享快照page fault的完整归属、controller/节点总预算、IOPS实际压力、物理quota/掉电/擦除、持续公平性/恶意load、独立操作员和完整生产Goal仍未完成。
