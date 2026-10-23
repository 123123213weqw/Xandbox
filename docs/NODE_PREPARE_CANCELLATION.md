# 排队取消与 held-copy 下独立停止、回收（TEST ONLY）

**有限实机用例，不是节点满载、公平性或生产 SLO 验收。** 冻结源 `c121f63dd2283fb514cb0ce33655e83d1332bd50`，普通 daemon/admin/warden/builder 四个 ELF 与已验收 2e 字节相同；只有 TEST fixture 变为 `117fdd4e…`。[原始报告](validation/kvm-node-cancel-admission-v1.json)的 `prepare_cancellation` 与[来源清单](validation/node-cancel-provenance-v1.json)记录本次独立证据，不重标旧 DEFAULT/quota240 数据。

## 实际执行顺序

`--node-prepare-cancel` 只是现有独占 `--node-snapshot` 的 TEST modifier；没有改变 8GiB L1/12GiB disk、CPU8、schema3 N4/records1024/sessions32/prepare1、root7GiB/control1GiB、private192MiB/128inodes、catalog4/2GiB 等策略。

1. 真正的 L1 builder 生成并验证 UNASSIGNED 模板后，确认原 daemon allocated/pools/pins 全零，先干净退出，再以 `UseCgroupFD` 在实际 control 内启动固定 TEST wrapper。wrapper 丢弃 CAP_SYS_RESOURCE、设置 NNP/TSYNC 固定通知 filter，然后 exec **同一个 `3ea1e247…` 普通 daemon**；不是另编译带生产钩子的 daemon。
2. 创建真实 KVM keeper，校验 UID/namespace/干净 workspace/boot，各 guest 只触碰8MiB，不声称满512MiB。此后才安装[已校准的9个固定入口探针](NODE_PREPARE_TRACE.md)。
3. 发起原始 H 创建。只在已确认的同一 daemon incarnation/executable inode、实际 FD/workspace inode/project/owner、**实际16MiB前缀**处暂停下一次128KiB WRITE；其 generation cgroup 存在且内核为空、没有 VMM/模板链接/初始化。没有读 tenant buffer，没有注入成功返回或错误。
4. C、Q 两个不同原始请求依次进入实际 gate。通过 key 的 SHA256 在 root0600 atomic version1 ledger 中只读定位其 Creating ref；不用活写期间禁止的 FileStore.Load，也不恢复 owner。两者均无 backend owner/jail/instances group；keeper+H+C+Q 使 frontend allocated4，第5个新请求返回503。不是从503或目录缺失单独推断排队。
5. 取消 **C 原始 HTTP context**，而非取消共享 idempotent replay waiter。client 观察到自己的 ContextCanceled；同一普通 daemon 的 C trace 为 `enter → selected(case1) → cancel(error)`，没有 token、node_ok 或 release。C key410、实际持久 Destroyed、backend资源缺失、allocated3、Stop/GC池 idle；Q仍只有 entry。
6. 在 H 同一 notification ID 仍有效、FD仍指向同一个16MiB前缀、没有执行/初始化、Q仍只在entry时，DELETE keeper。分别观测已知 generation 的内核执行域为空/移除，以及普通回收后的 quota0、owner/jail/group缺失和实际持久 Destroyed。期间 listener 继续处理其他 WRITE 通知，不把整个 listener 卡在 H 上。
7. 对 H **只提交一次 CONTINUE**；这不是 WRITE 已完成的证明。随后两个原始 H/Q 请求都返回 Ready，各自实际 KVM/UID/namespace、新boot、干净 workspace 再核对。15个完整转换证明 H/Q 的实际许可链与 C 的不取 token 取消分支；不把 Ready 当作精确 release 时刻。
8. H/Q 普通 DELETE，4个 project 全零、pins0、allocated/Stop/GC池 idle，持久终态和资源缺失逐项核对。observed daemon 真正退出/reaped、listener关闭后，重新启动普通 daemon；随后原有 calibration、inode/byte pressure、低free原盘 cold、普通回收及相关旧 fixture 回归继续运行。

## 本次 N1 观测，不是承诺

| 分开的单次观测边界 | ms |
|---|---:|
| keeper DELETE 发起 → 已知执行 cgroup 内核为空/已移除 | 36.021190 |
| keeper DELETE 发起 → 本用例的普通私有资源回收及持久终态核验 | 158.599804 |
| H 实际 WRITE notification held → 提交 CONTINUE reply | 223.879566 |
| H 原始请求发起 → 收到 Ready | 2080.233666 |
| Q 原始请求发起 → 收到 Ready | 2690.035135 |

执行域空是采样观测上界，回收观测包括 API/poll/quota/ledger核验开销；不是精确内核事件时间。这里的“回收”限定本 generation 的普通 driver 私有资源及持久终态，**不是物理SSD擦除、所有页缓存清空或所有故障窗口均已证明**。keeper为真实但已完成先前任务的guest，不把它说成CPU满载busy workload。实际有24个其他 CONTINUE replies 在 keeper 清理期间提交；reply计数不等于24个 syscall 都已完成，keeper的完成由独立内核/配额/持久记录证据确认。

## 跟踪、超时和边界

- H 的实际通知 hold 硬上限20s；取消与 keeper 清理的实验观察窗口18s。**原生产 Prepare30s、HTTP40s均未放大**。未把旧工具60s观察预算偷换成生产创建预算，也未等待超时后补发成功。
- 新固定 filter 只观察 count1..128KiB 的 WRITE，以便小型 metadata/HTTP writes 也能被继续处理；其他syscall、0字节/更大WRITE保持原内核行为，architecture/x32 guards保留。最多32768个通知。旧 schema2 partial-copy/errno/cut模式和128KiB-only filter未改；新路径必须先通过完整 schema3 config，再选精确 `instances` cgroup，不能宽松“任选旧/新root”。
- kernel notification 是 TEST 的 syscall-entry hold，**不是实际 filesystem-D、物理EIO或设备挂起**。持有期间不对 H 做观察者 Q_SYNC/syncfs；模板 builder 仍是 NodeRoot 外的可信离线设置，不作为全部节点内存受控的证明。
- 同一 gate、H/Q两个成功链及C一个取消链共15 events；公开 point/本窗口 goroutine_index/selected_case0或1，不公开 g指针、TID/PID、绝对时间或tenant身份。8 CPU loss计数全零，9个kernel probe hit count逐点等于trace，目标 incarnation/inode/control/每事件活Tgid复核，关闭后清空自己注册的固定probe/instance并卸载自己的L1 tracefs。
- 正常释放在 `Prepare.deferwrap1` 中内联，pre-receive和post-receive入口不等于精确channel线性化时刻；下一个 selected 可以早于前一个 post probe。没有完整workspace-copy起止轨迹、scheduler park/fairness、general取消/Stop调度或p99 SLO证明。

## 来源、回归与剩余工作

本轮原生 full race×3/vet、fixture race×10/vet、root Python82、CGO-free实际 kernel/exec filter×3、最终源5个native/cross ELF、最终源Darwin race×3/vet均已实际通过。新case加原space/cold、old cold-node、owner-unlink、inflight-copy、稳定partial-EIO、legacy snapshot、clear和六errno/cold，共8个scope/19个外层代际；[独立只读审计](validation/node-cancel-independent-cleanup-v1.txt)确认精确root/control/cgroup父子及runner均不存在，没有额外cleanup动作。quota证据来自删盘前L1，不从外层删除磁盘推断。私有console/inner trace/receipt/镜像/身份/凭证不公开。先前入口校准的真实失败保留在[原清单](validation/node-prepare-provenance-v3.json)，不当作本轮新增失败或偷偷改为通过。

下一步仍需完整资源最坏压力/ancestor/affinity/uniqueRAM、更多并发与故障窗口、可靠 metadata/catalog 锁协议、归档轮转、部署与独立operator、持久审计/告警/日志导出上界、backup/upgrade/rollback、长期open-loop/fairness/SLO及完整M1–M4。旧space/calibration路径的 `prepare_permit_hardware_trace_claim=false` 不被事后改写；本页另用新 `prepare_cancellation` 对象限定实际通过范围。**Goal与production_ready仍未完成。**
