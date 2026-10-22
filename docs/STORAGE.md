# 有界 ext4 ENOSPC 与真实 KVM 恢复

**开发中，不是完整存储、故障或生产 SLO 认证。** 本轮只验证 guest 工作盘限容，以及元数据所在文件系统的数据块/inode ENOSPC。真实内核 errno 来自独占的小 ext4，而不是 mock Store；没有填满共享宿主盘。

## 来源与安全边界

运行源码 `5276a0432f793f9d5342b9452fb79e8e5108e02b`。生产 Go 代码、go.mod/go.sum 与已验收 `55a2bba` 完全相同，复用原生 Linux Go1.27.3 构建、SHA256为 `c57760c8c6f1ce5e013e51b8053015f367e55e5a29fd9ac064ba6602e32813f1` 的 daemon；本轮没有声称重新执行原生 Go race/vet，相关既有证据见 [混合负载](MIXED_LOAD.md)。本次运行前重新核对 binary SHA，Linux root 的全部19个 Python 测试通过，Darwin不能替代Linux/KVM。

[通过的完整原始报告](validation/kvm-storage-enospc-v5.json) 保留5个场景及探针/辅助代码/工件摘要；source和所有helper的实际SHA均与公开文件一致。Firecracker/jailer1.17.0、kernel6.1.188及原始v10initrd摘要独立核对。schema1冷路径，guest512MiB/2vCPU、128MiB私有工作盘，无业务NIC。没有通过宿主执行租户命令，也没有使用快照跨文件系统硬链接。

1. Runner先re-exec进自己的mount namespace，核对其与实际父进程不同、传播属性private；不修改父namespace的共享挂载。使用方式依据 [unshare手册](https://man7.org/linux/man-pages/man1/unshare.1.html)。
2. 只对自己刚独占创建、预分配的64MiB普通文件执行mkfs.ext4（512个inode、保留块0）；loop挂载到新私有目录，`nosuid,nodev,noexec`。根据sysfs核对该loop的精确backing文件、设备身份和autoclear；填充前再次检查容量不超过64MiB，普通宿主目录不能作为填充目标。
3. 只有state/ledger/backend ownership位于该小卷。runtime、实际VMM执行文件、guest工作盘和私有日志留在健康的宿主ext4。报告/日志路径也在故障卷外，避免故障吞掉结果。无格式化真实块设备、共享盘填充、全局drop_caches或宿主remount。
4. 退出先只停止自己的Popen/cgroup，释放本次filler，再普通umount；核对自己的loop绑定已释放，绝不detach复用给别人的loop编号。若不能证实安全释放则保留本次资源并使测试失败，不用lazy/force卸载掩盖泄漏。

## 5个实际场景

### guest工作盘限容（1个）

guest UID65534尝试写256MiB，实际写入99,553,280 bytes后得到ENOSPC，host工作盘镜像仍为128MiB；guest删除该文件后能继续执行，再正常回收。这个结果受ext4元数据/保留块影响，不应将128MiB镜像宣传成128MiB可用负载；它不证明宿主project quota、inode攻击、IOPS限速或安全擦除。

### 元数据ENOSPC（4个组合）

| 小卷故障 | VM活动 | 独立写探针errno / 阶段 | 删除返回500的观测 | 请求到host cgroup空 |
|---|---|---|---:|---:|
| blocks | busy | 28 / write | 1.355ms | 44.079ms |
| blocks | idle | 28 / write | 1.657ms | 5004.602ms |
| inodes | busy | 28 / open | 1.963ms | 29.343ms |
| inodes | idle | 28 / open | 1.335ms | 4337.057ms |

每组合仅1次，是原始观测，不报P50/P95/P99或最坏界。data-block场景可用块为0而仍有inode；inode场景可用inode为0但仍有约58MiB数据空间，不能只看磁盘剩余字节判断可写。

每个组合都核对：

- busy VM的shell已实际fork两条后台sleep并发布ready标记，guest任务仍RUNNING；idle VM仅先前true已完成，没有待执行工作。所有argv均经guest API。
- DELETE没有返回代表持久接受的202，而返回500；随后新Exec为409。旧持久ledger字节不变、owner/jail还在，未假装DESTROYED。
- 即使元数据不能写，host cgroup最后仍为空；busy任务终态CANCELLED。busy的29–44ms与idle的4.337–5.005s不同：现有Exec取消/模糊传输会调用driver.Stop，idle没有这一路径，依赖停止续约后的guardian到期。相关代码见 `internal/firecracker/driver_linux.go`、`internal/sandbox/manager.go` 和 [GUARDIAN.md](GUARDIAN.md)。不将两条路径混成“磁盘满时都毫秒级停止”。
- 节点与租户上限均为1，节点容量检查先于租户配额：新Create应为503而非429；独立管理指标allocated仍为1，不能在只停VMM、尚未持久回收时归还容量。
- 只SIGKILL自己的controller。在空间仍满时，普通daemon同state重启因真实ENOSPC退出，拒绝恢复准入；既有owner/jail不被假装清掉。
- 仅释放本次filler，普通daemon在同一canonical state/config重启，旧代最终持久DESTROYED，cgroup/jail/owner移除、allocated归0。旧创建key为410，新的key能创建另一真实KVM、执行并完整销毁。

主runner退出0、5个场景通过、finally确认runtime/cgroup/私有挂载/自己的loop绑定全部释放。之后从父namespace独立复核：本次root与cgroup不存在，无本次loop backing，也没有本次私有挂载传播到父视图。原始token、Ref、PID、argv/输出、磁盘镜像、原始日志和宿主私有路径不公开。

## 保留失败，不从中挑样本冒充通过

最初源码42e910a预检已验证私有namespace/loop释放，但Create因脚本错误请求120秒上限（服务策略最多60秒）被400拒绝，尚未进入KVM故障用例，未算成功。源码2c64b49通过guest满盘并进入block ENOSPC后，脚本误以为容量拒绝应为429，但实际节点满额正确返回503，外层退出1并清理确认；[完整失败记录](validation/kvm-storage-enospc-v2-failed.json) 保留，没有改写成通过。修正探针为准确503并增加allocated=1独立检查，而不是放宽服务策略。中间busy-only探针3场景通过，但本页的5场景结论只来自最终全新运行，不拼接旧运行的部分成功。

## 复现

先在专用Linux/KVM节点固定 [KVM资产](../scripts/kvm_assets.json)、构建已打补丁Go版本的daemon/warden和guest镜像。普通CI只执行单测与语法检查，不自动以root填盘；下列命令自己创建private mount namespace并要求root、loop、mkfs.ext4、mount/unshare与KVM权限。

```sh
umask 077
python3 scripts/kvm_storage_faults.py \
  --daemon /absolute/private/bin/sandboxd \
  --warden /absolute/private/bin/xandbox-warden \
  --firecracker /absolute/private/bin/firecracker \
  --jailer /absolute/private/bin/jailer \
  --kernel /absolute/private/assets/vmlinux \
  --initrd /absolute/private/assets/initrd.cpio.gz \
  --workspace /absolute/private/assets/never-used-128MiB.ext4 \
  --source-revision 5276a0432f793f9d5342b9452fb79e8e5108e02b \
  --report /absolute/private/new-storage-report.json \
  --log-dir /absolute/private/new-storage-log-directory
```

普通目录/未挂载卷不能填充、同namespace/共享传播拒绝，均有单元测试。不要复用report/log目录、手动填写隐藏的namespace参数，或在未确认旧runner终态时再启动一份。异常时保留的镜像和资源应由操作员核对专属身份后处理，不据任意PID/loop编号删除资源。

## 仍然没有完成

实际块设备EIO/只读故障、掉电/整机重启、journal损坏、snapshot/cold多文件系统的故障交叉矩阵、宿主磁盘预算/配额、并发IO攻击、长期元数据归档、双监督失效、物理擦除、独立操作员复现和生产SLO均未由本次证明。特别是idle故障路径目前约5秒，而不是极速停止承诺；后续任何提速都必须继续保留“撤权、物理停止、持久回收、容量释放”之间的边界，并重新跑忙碌/空闲故障与旧回归。完整 [M2/M4门槛](PRODUCTION.md) 仍未完成。
