# 双租户快照切换与资源视图（有限实验）

**仍是实验，不是生产持续负载、公平调度或 SLO 认证。** 本次补充两个并行租户的有限闭环、配额隔离和共享/私有资源观测，不勾选完整 M4。

## 可核对的源码与运行范围

运行源码为 `55a2bba857b9232c3aeff1d16bd8e0d921d86ef8`，原生 Linux Go1.27.3 / CGO0 / trimpath / buildvcs=false 的 daemon SHA-256 为 `c57760c8c6f1ce5e013e51b8053015f367e55e5a29fd9ac064ba6602e32813f1`，与此前权限修正后验收的 daemon 逐字节相同。此次没有改动生产 Go 实现；新代码是 Python 实验与采样器。原生 Linux 全量 race、vet，以及全部16个 Python 测试（包括 Linux mincore）先通过，再开始负载。Darwin 测试不替代 Linux/KVM。

[不可变原始报告](validation/kvm-mixed-load-v6.json) 包含工件/探针 SHA-256、测试前只读宿主观测、完整逐次时延、资源时间序列、最终清理结果。原始 controller 日志、令牌、Ref、boot ID、内存/磁盘镜像及私有运行路径不公开。JSON 顶层是原有有限 catalog 正确性探针，新的分布/曲线位于 `mixed_load`；顶层10组检查与240次切换不能相加成250个独立故障场景。

## 协议与边界

- 两个固定 fixture 租户各一个线程、各120次新 VM 切换；每48次轮换 session，保留永久 tombstone，不提高64项历史上限。
- 节点最多8实例、租户各3实例。先占满 alpha 的3个名额，其第4次 Create 返回429；此时 beta 仍能创建真实 KVM 并执行，随后全部回收。这是配额隔离，不是调度公平性证明。
- alpha 每代在 guest `/tmp` 写24MiB、私有 ext4 写8MiB并做4轮 SHA-256；beta 分别4MiB/1MiB/1轮。校验实际字节数；命令只经 guest API 执行。
- 工作负载先完成再切换，写入和脏页在旧代中保留至回收；**不是繁忙旧任务的终止风暴**。每次新代核验 workspace 与 tmpfs 均无旧标记、执行精确当前 revision，并拒绝旧 revision。
- 每个线程独立等旧代持久销毁后才进入下一轮，最多两个租户各一旧代/候选；不是开放到达模型或队列饱和。明确节拍为至少180秒，不隐藏 pacing 空闲时间；切换时延不含该轮切换前的 guest 工作或之后的节拍等待。
- 分别记录从同一客户端请求起点到绑定响应、首次新命令成功、旧 host cgroup 空、旧代持久 DESTROYED 且 jail/cgroup/owner 删除。5ms轮询和采样开销均存在，观测值不是事件精确发生时刻。
- API、快照/宿主页缓存与共享宿主背景负载不控制；不执行 drop_caches、不改共享宿主配置，也不将实验与历史冷路径直接相除得出加速比。

## 实际结果

完整外层 runner 退出0，混合阶段 **246.267秒**，两租户各120次全部完成，各使用3个session；后续原有10组catalog回归也通过，finally确认本次独占runtime/cgroup移除。没有将之前失败运行的部分样本拼接进来。

客户端区间观测中有91对跨租户切换重叠、82对guest工作区间重叠；这是并发的实测证据，不是调度公平性证明。

| 租户 / 请求起点到 | P50 | P95 | P99 | max |
|---|---:|---:|---:|---:|
| alpha / 绑定响应 | 685.323ms | 760.535ms | 794.730ms | 794.924ms |
| alpha / 首次新命令成功 | 698.968ms | 796.962ms | 815.254ms | 829.553ms |
| alpha / 旧host cgroup空 | 724.811ms | 802.917ms | 830.369ms | 831.257ms |
| alpha / 旧代持久销毁 | 795.450ms | 874.061ms | 908.872ms | 912.825ms |
| beta / 绑定响应 | 688.093ms | 762.148ms | 770.521ms | 780.264ms |
| beta / 首次新命令成功 | 704.256ms | 775.614ms | 792.166ms | 796.082ms |
| beta / 旧host cgroup空 | 723.927ms | 791.043ms | 808.048ms | 809.541ms |
| beta / 旧代持久销毁 | 798.374ms | 868.067ms | 898.791ms | 907.039ms |

每个分布N=120，使用经验nearest-rank；P99为排序第119项，不是置信上界、最坏延迟或生产百分位保证。不同工作量和显式pacing使两租户完成时间不同，不能从各完成120次推导公平性。

资源时间序列有404个完整样本。目标等待500ms，实际样本起点间隔204.492–649.338ms、均值611.093ms；单次只读扫描最大149.229ms。该开销不可忽略，曲线可能漏峰值。

| 不相加的资源视图 | 本组采样峰值 | 混合阶段末 |
|---|---:|---:|
| controller PSS | 19.586MiB | 19.031MiB |
| 本次owned进程PSS之和 | 104.184MiB | 0.000MiB |
| 本次VM cgroup charge之和 | 80.871MiB | 0.000MiB |
| 精确模板映射Anonymous之和 | 58.375MiB | 0.000MiB |
| 共享源memory文件mincore驻留 | 512.000MiB | 512.000MiB |
| 私有workspace已分配块 | 498.250MiB | 0.000MiB |

controller PSS从14.727MiB到19.031MiB，FD从8到8、峰值26；不能据此宣称内存不随历史增长。共20次瞬时退出/身份观察miss。队列采样峰值为0、运行worker峰值各1，只说明此闭环未形成可见排队，**没有饱和或背压压力结论**。

混合阶段末owned进程/cgroup/owner、私有盘和allocated/queue/running均为0；共享源memory文件仍驻留512MiB，因为该阶段仍保留active catalog，不能称为总RAM归零或每个已销毁VM的泄漏。后续退役/GC与runner清理已成功，但不是物理擦除证明。

本次测试前宿主：Intel(R) Xeon(R) Silver 4216 CPU @ 2.10GHz、64逻辑CPU、251.535GiB RAM、内核6.8.0-136-generic、ext4；启动前load averages约8.246/6.613/5.823，背景负载不控制。guest规格512MiB/2vCPU、128MiB工作盘、无业务NIC；并未主动触碰每VM全部512MiB。

源码55a2bba的 [push CI](https://github.com/123123213weqw/Xandbox/actions/runs/39830903698) 与 [PR CI](https://github.com/123123213weqw/Xandbox/actions/runs/39830912089) 各5个实际job均completed/success。CI不是KVM隔离证据，后续文档提交CI与该运行源码分开核对。

## 内存与磁盘列该怎样读

| 报告列 | 语义与不可推导的内容 |
|---|---|
| `controller_pss_bytes` | 控制器映射页的比例驻留量，不含所有由复制/发布造成但未映射的文件缓存 |
| `owned_process_pss_sum_bytes` | 仅本次 cgroup 内可验证 PID/starttime 身份的进程 PSS 之和；不是整个宿主的独占 RAM |
| `template_mapping_*` | 精确 dev/inode 匹配所有 hardlink 映射，不按文件名猜测；Anonymous 可观察 COW，但不能直接作为唯一计费页 |
| `catalog_memory_resident_bytes` / `catalog_state_resident_bytes` | root 对只读源文件做 PROT_NONE 映射 + mincore，观察整文件驻留；不主动读取页。发布过程已哈希/复制而暖缓存，不是冷缓存样本 |
| `owned_cgroup_memory_current_bytes` | 本次各 VM cgroup 的当时 charge；含 kernel/cache 等，不是 guest RSS。共享页与发布者的 charge 归属可能在 VM cgroup 之外 |
| `private_workspace_allocated_bytes` / `logical_bytes` | 私有文件已分配块与逻辑长度分列。复制中的短文件也计入，并单列 `preparing_files`；不等于磁盘配额/擦除验收 |

**不能将上面几种内存数相加。** PSS、模板映射、源文件驻留和 cgroup charge 互有重叠，采样也不是同一时刻的原子快照；这里没有完整唯一 RAM 或租户计费结论。只读 PID/cgroup 检查用于采样，绝不据 PID 采取回收动作。瞬时退出/身份变化计为 miss，权限/解析错误中止测试，不能伪装为0。内核语义参见 [Linux6.8 proc 文档](https://www.kernel.org/doc/html/v6.8/filesystems/proc.html) 与 [cgroup v2 文档](https://www.kernel.org/doc/html/v6.8/admin-guide/cgroup-v2.html)。

初次 `94ce306` 两次/租户预检中，观察线程报ValueError且测试失败，finally清理确认，未计作成功。旧采样器还存在要求复制中的workspace已满128MiB的确定错误假设；该异常没有原始trace，不能声称已还原其唯一根因。采样器现已覆盖准备中部分分配的单元测试，`9cf48a8` 的两次/租户预检及原有10组检查通过。完整报告不删除慢样本或只保留成功片段。

随后 `6c59414` 的120次/租户长测在147.934秒失败：[完整失败报告](validation/kvm-mixed-load-v5-failed.json) 保留 alpha72次、beta97次完成及第98次未完成样本，外层退出1、finally清理确认。原始工作线程异常被同伴abort覆盖，不能还原错误类型，也不能据此断言某个生产故障根因。同一节点另用本次独占空cgroup复现了打开 `cgroup.events`、删除目录后读FD得到ENODEV(19)。新探针仅在路径已消失时容忍ENOENT/ENODEV，现存group不被视为停止；权限错误仍失败，并新增原始线程trace/有界错误类型保留及单元测试。这个确定竞态的修正不构成对旧异常根因的证明；重跑使用全新namespace，不把旧169次完成样本拼入新240次验收。

## 复现

先遵照 [CATALOG.md](CATALOG.md) 固定 KVM 资产、构建并保留从未分配的 UNASSIGNED export，再在专用 root Linux/KVM 节点执行：

```sh
umask 077
python3 scripts/kvm_snapshot_smoke.py \
  --daemon /absolute/private/bin/sandboxd \
  --admin /absolute/private/bin/xandbox-template \
  --warden /absolute/private/bin/xandbox-warden \
  --firecracker /absolute/private/bin/firecracker \
  --jailer /absolute/private/bin/jailer \
  --kernel /absolute/private/assets/vmlinux \
  --initrd /absolute/private/assets/initrd.cpio.gz \
  --export-dir /absolute/private/never-assigned-export \
  --source-revision 55a2bba857b9232c3aeff1d16bd8e0d921d86ef8 \
  --report /absolute/private/new-report.json \
  --log-dir /absolute/private/new-log-directory \
  --mixed-cycles 120 --mixed-min-seconds 180
```

该命令在混合负载之后还执行原有 catalog 服务故障/退役回归，不能只取负载片段来声称整个 runner 成功。不得复用 report/log 目录、使用已分配模板或在未核对旧 runner 终态时重复启动。无 `--mixed-cycles` 时保持原有限探针行为。

## 仍需验收

更长且有独立外部到达流的多租户竞争、不同到达率/资源形态/超额队列、拥塞与故障同时发生、调度公平性、完整共享/私有 RAM charge 归属、磁盘配额与故障、长期元数据归档/轮换、置信尾界和生产 SLO，均未由本次闭环证明。可靠审计/告警、升级回滚和独立操作员部署也仍是 [生产门槛](PRODUCTION.md)。
