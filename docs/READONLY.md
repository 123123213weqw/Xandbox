# 独立 ledger 只读故障与真实 KVM 恢复

**开发中，不是介质故障、整机故障或生产 SLO 认证。** 在独占64MiB loop ext4上真实触发EROFS，验证已有物理Stop修正不只对ENOSPC生效，同时仍拒绝虚假持久停止、销毁和容量归还。[精确来源与摘要](validation/readonly-ledger-provenance-v3.json) 区分harness源码与原生运行时构建。

## 为什么单独挂 ledger，而不覆盖整个 state

控制器持有可写的 `controller.lock`；有写FD的文件系统不能假定可以普通remount为只读，可能返回EBUSY。另一个陷阱是bind-over一个新只读路径：故障前打开的目录FD可能仍指向原先可写的挂载，不能只凭新路径写失败就宣称全部账本操作只读。相关语义见 [mount(2)](https://man7.org/linux/man-pages/man2/mount.2.html)。

本次在daemon**出生前**，将自己新建的小loop ext4直接挂到 `state/ledger`。锁、API/metrics socket、sessions、backend ownership与runtime留在健康存储；没有bind-over、伪造Store错误、宿主共享盘remount或真实块设备格式化。随后仅对这份精确归属的小卷执行普通 `remount,ro,nosuid,nodev,noexec`，并核对：

1. 自己的private mount namespace与实际父进程不同，传播属性private。
2. loop的设备身份、精确backing文件、autoclear与64MiB容量；每次remount及恢复前重新核对，身份改变则拒绝操作。
3. statvfs实际只读位，以及新路径创建文件得到errno30/EROFS。
4. **故障前已打开且一直保留的directoryFD**，remount后相对它执行openat也得到errno30，而不是绕过只读故障。
5. 空闲数据块和inode仍充足，避免把ENOSPC误标为EROFS。没有持有可写普通文件FD进行强制只读；本实验不是内核因介质错误自动remount或journal故障。

FileStore严格拒绝非record目录。首次预检在daemon启动时因新ext4自带的空 `lost+found` 被正确拒绝，尚未创建VM；[原始失败报告](validation/kvm-ledger-readonly-v1-failed.json) 保留passed=false/0 checks/cleanup=true。修正只在刚格式化且已确认归属的小卷上用rmdir删除该**空目录**，不递归删除未知内容、不放宽生产账本校验；单测验证非空目录保留、非归属卷拒绝操作。中间源码6dd没有单独跑实机，最终结果来自全新源码1d运行，不拼接旧运行。

## 固定运行时与实际范围

- harness源码 `1d4eb7f59a0ec00759c526a2b663ab358e011b26`；JSON的source_revision表示harness/pipeline。
- 所有Go源码、go.mod/go.sum与原native构建源码 `35548f67c2ae5a45549e7ecfc312c77c6b6473b0` 完全一致。复用已核对SHA的Linux Go1.27.3 / CGO0 / trimpath / buildvcs=false daemon：`d2dc5358d0e8adc98847fa6611e6fff6d7e2a48bd28a38b35bed8dca8cbcb7c6`；**本次没有新构建或新native race/vet声明**，既有完整新运行时矩阵见 [EMERGENCY_STOP.md](EMERGENCY_STOP.md)。
- 原pinned v10 initrd/agent与从未分配的cold工作盘；没有部署重建guest或TEST故障镜像。Firecracker/jailer1.17.0、kernel6.1.188，全部输入摘要保留在原始报告。
- 宿主Linux6.8.0-136、Xeon Silver4216/64逻辑CPU、可见内存263,753,640KiB，未控制其他宿主负载、不清空缓存；guest512MiB/2vCPU、128MiB私有盘、无业务NIC、节点与租户实例上限均1，umask077。
- Linux root的28个Python单测全部通过；Darwin同28项中4项Linux/root测试跳过。CI是普通非KVM检查，不能代替实机；[实际阶段转录](validation/readonly-pipeline-transcript-v3.txt) 原样公开，原始controller日志/资源receipt/镜像不公开。

源码1d的 [push CI](https://github.com/123123213weqw/Xandbox/actions/runs/39844188750) 与 [PR CI](https://github.com/123123213weqw/Xandbox/actions/runs/39844198206) 各5个实际job及全部步骤completed/success；后续文档头CI另核对，不拿原生旧矩阵或源码CI冒充新头CI。

## 只读 ledger：busy / idle

[完整原始报告](validation/kvm-ledger-readonly-v3.json) 含下面2个只读故障组合及1个共享的guest工作盘限容检查。

| VM活动 | 路径 / 故障前directoryFD探针 | DELETE到错误500 | 请求到host cgroup空 |
|---|---|---:|---:|
| busy | EROFS / EROFS，均在open阶段 | 1.326ms | 39.017ms |
| idle | EROFS / EROFS，均在open阶段 | 0.646ms | 47.907ms |

各N=1，不是百分位、最坏界或持久回收时延。1500ms只是本次有限实验的观测guard，默认探针不开启；不是线上超时或SLO。busy任务经guest API实际fork两条sleep、发布ready标记并保持RUNNING；idle没有未完成工作。故障后、DELETE计时前重新检查READY、host populated和busy状态。

每组都核对：

- DELETE为500而非持久接受202，新Exec409；API仍STOPPING、没有stop/destroy时间戳，磁盘旧ledger字节不变；owner/jail仍在。
- host执行域最终为空，但allocated仍1、新Create503；不能把物理Stop当持久STOPPED/DESTROYED、已清理或容量可复用。busy还确认旧任务进入终态。
- 只SIGKILL自己的controller。在只读故障仍存在时，普通daemon同state重启因真实 `read-only file system` 拒绝启动；旧归属/私有资源不被假装回收。
- 仅恢复这份专属loop为RW，验证写入/fsync可用。普通daemon同state恢复，旧代最终持久DESTROYED、cgroup/jail/owner移除且allocated归0；旧创建key410，新key能创建另一真实KVM、执行并完整销毁。

## 默认 ENOSPC 路径回归

同一源码、同一个未变的D2dc daemon，另从零跑 [原有5场景](validation/kvm-readonly-enospc-regression-v3.json)。这次ENOSPC仍作用于整个state，不是仅ledger；runtime和诊断仍在健康宿主存储。

| 故障 | VM | DELETE到错误500 | 请求到host cgroup空 |
|---|---|---:|---:|
| blocks | busy | 1.460ms | 38.569ms |
| blocks | idle | 1.405ms | 49.406ms |
| inodes | busy | 1.097ms | 38.065ms |
| inodes | idle | 1.258ms | 43.147ms |

同样逐组验证STOPPING/零时间戳、ledger未改、Exec409/容量保留/新Create503、故障持续重启拒绝、恢复后回收/旧key410/新VM执行。guest工作盘在两个suite中都尝试256MiB，写入99,553,280bytes得到ENOSPC、host镜像仍128MiB；删除文件后可继续执行并正常回收。**这是重复的共同检查，不把3+5宣传为8个独立新故障。** 原有历史样本不覆盖或改写，也不混合计算百分位。

外层runner退出0、两个suite均passed/cleanup=true。另用故障卷外的私有receipt从父视图独立复核3组（含首次失败）：root/cgroup、自己的loop绑定均不存在，私有挂载未传播到父视图。不使用lazy/force卸载或detach复用loop编号掩盖泄漏；不能确认安全释放就保留并报错。

## 复现

在专用root Linux/amd64 KVM节点检出上述harness源码，固定 [资产](../scripts/kvm_assets.json) 并构建已打补丁的Go1.27.3 host程序，或逐摘要核对已验收的同Go源码native工件。完整输入仍沿用 [存储探针](STORAGE.md)：

```sh
umask 077
python3 scripts/kvm_storage_faults.py \
  --daemon /absolute/private/bin/sandboxd \
  --warden /absolute/private/bin/xandbox-warden \
  --firecracker /absolute/private/bin/firecracker \
  --jailer /absolute/private/bin/jailer \
  --kernel /absolute/private/assets/vmlinux \
  --initrd /absolute/private/assets/pinned-v10.cpio.gz \
  --workspace /absolute/private/assets/never-used-128MiB.ext4 \
  --source-revision 1d4eb7f59a0ec00759c526a2b663ab358e011b26 \
  --fault-suite ledger-readonly --max-host-stop-ms 1500 \
  --report /absolute/private/new-readonly-report.json \
  --log-dir /absolute/private/new-readonly-log-directory
```

去掉 `--fault-suite ledger-readonly` 即原有ENOSPC套件，必须另用全新report/log目录。不要复用目录/手动填写隐藏namespace参数，或未确认前一个runner终态就重复启动。

## 未完成

只验证**ledger单独只读的已返回EROFS**；没有证明所有state/backend/catalog/快照交叉只读、介质EIO、内核自动errors=remount-ro、journal损坏、掉电/整机重启、卡死尚未返回的Save、内核饥饿或双监督失效。宿主quota/IO预算、长期归档/擦除、开放到达公平性/唯一RAM、可靠审计/告警/回滚、独立操作员及生产SLO仍未完成，[完整Goal](PRODUCTION.md) 保持开发状态。
