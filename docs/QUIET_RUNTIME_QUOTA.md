# 当前 quiet 程序的一项 quota runtime 复验

[有限报告](validation/quiet-runtime-quota-syscalls-2026-10-28.json)绑定冻结源
`e2bb82f73f6014464339544a8dd7abc03b9fb535`、普通代码 `6ea28eaf491f2863884db176af94936544620f37`
和普通 daemon `4ddd4bea5ee252fd4b52a7132bfbab9723d76bbaa1941d4c341ce770e0802218`。
不是旧 ELF 报告重签，也不是已通过的完整运行矩阵或生产验收。

## 原范围执行与独立复核

只刷新原 25 runtime +12 boundary 清单内具名 `quota-syscalls` 的 source/工件和输出名称。
原 6 类固定 syscall errno、3 类 clear 各至少 3 次错误、真实内核 continue、错误期间
保留 owner/容量及拒绝新建均核对；不是物理介质错误，也不修改普通 daemon 的 syscall。
随后 running/stopped/destroyed 三个原检查点及原磁盘冷恢复完成，共 4 次真实 KVM 启动，
核对旧 key410、持久销毁、新 guest 及内核 quota 与独立当前 inode 核账，不复用旧分配黄金值。
本 scope 原 2GiB L1 /4vCPU /2GiB盘 /3GiB outer memory 规格不变；它不是节点内存饱和测试。

原生软件43包/24工件和当前CI先完成，才运行该 scope。19份原始文件独立逐一验hash；
1220源文件、24程序、9输入再复核。新4个实际外层代际与此前失败负载批次60个合计64个、
37scope全局不重复，声明资源只读确认不存在，outer OOM/pids-limit0，无补清理。
私有console、receipt、宿主资源身份不公开；公开报告只含闭集数值与来源摘要。

首个编排在 root-only 输入的只读 hash 上因权限失败，尚未进入harness/创建VM，原件保留。
只把该读取移入 sudo，不改文件权限、源码、测试参数或资源；另一个观察器把报告后缀猜错，
依原 manifest 修正读取路径，实际 producer 从未因此重跑。通过结论来自同一原始执行与独立复核。

## 未完成

[第十二批原始持续负载仍失败](validation/kvm-open-arrival-attempt12-failed-2026-10-28.json)，
不原样重跑凑绿，也不以这一较小具名 scope 代替40分钟/100tail/checkpoint/原盘cold。
余36个原具名 runtime/boundary scope、systemd、完整持久窗口/资源压力、预热与共享引用、
审计/备份/升级回滚、百分位长稳和独立操作员等所有未完成生产门槛保持原范围。
不合并、不部署，不宣称生产就绪。
