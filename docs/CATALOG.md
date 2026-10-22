# 实验性快照 catalog 与服务接入（开发中）

**已通过有限同机真实 KVM 服务检查，仍不可按生产服务部署。** 本分支已连接 schema2 → catalog → Driver.Prepare → snapshot/load → 一次性初始化，并新增独立的模板导出、服务与冷路径报告（见下文）。PR #9 的历史报告不覆盖这些新代码；本轮也不是完整初始化故障矩阵、预热池、性能认证或生产认证。默认schema1仍冷启动。

**后续umask077权限修正已完成独立Linux/KVM复验（源码547cd79），见下文最新报告。更早的c7d559e/f9f47ec报告仍只覆盖其固定源码，不能代替修正后证据。**

## 权威与顺序

1. catalog 固定在绑定的 `state-dir/firecracker/catalog/`，不接受租户路径；只允许宿主 root 操作员管理。
2. `index.json` 绑定 backend 配置摘要和 registry 路径摘要。模板 ID 为规范化 manifest 的SHA256，不把可替换的路径当身份。
3. 发布先复制/校验固定大小的memory和有界state，再同步各文件与目录、封存为只读对象，最后原子发布index；不会自动activate。中断的stage/unindexed对象不会被自动采用。
4. 同一个跨进程flock覆盖发布、激活、退役、获取/删除持久归属。**实际引用数来自每代 ownership 文件，不来自内存计数器。** 新owner必须在私有链接/VMM出生前持久化。
5. owner v2保存模板ID、保留UID及`initialization_attempted`。发送任何新身份/熵前先持久化不可逆尝试标记；原guest的CLAIMED ACK是易失的，重启显示WAITING也不能使候选重用。
6. schema2只从被持久化pin住的精确模板建立只读memory/state硬链接，创建独立128MiB写盘，再出生即入cgroup/guardian/network namespace。load/resume后只发送一次初始化，确认精确Ref/bootID/hash与空执行组后才READY；每次执行继续校验该epoch。无普通health或冷启动/宿主执行降级。
7. `RETIRING`清除active，拒绝新pin，但不撤销已获取的pin；已在准备中的候选仍可完成。已有VM不因退役被重置/复用。
8. 私有资源必须先确认宿主cgroup空/监督退出，删除私有链接并同步父目录，再删除ownership并同步。只有之后GC才能删除共享对象。Stop不获取catalog锁；GC可能受catalog锁/磁盘I/O延迟，不能把其接受响应当作完整回收。
9. 重启从ownership重建引用，继续沿用Core“关闭/回收旧代、不复活”的政策。GC先检查全部归属、未知jail/cgroup与实际memory/state inode是否匹配typed pin；丢失/损坏归属或不一致时拒绝删除。

对象目录0555、文件0444且root所有，catalog父目录0700。第一次使用/重启校验摘要，进程内缓存仅保留不可变文件的inode/size/mtime与预期摘要；创建/删除硬链接造成的ctime变化不会触发重复512MiB校验。此优化依赖受支持的操作员工具不修改已发布inode，**不防恶意宿主root或带保留mtime的任意手工改写**。CRC不是真实性证明。

## 显式配置与操作

schema1不允许snapshot字段；schema2必须明确提供snapshot policy。配置/资产仍绑定现有backend registry，不能在已有冷节点上编辑配置后静默转成快照节点。当前需新的独立state/runtime/cgroup命名空间；离线schema迁移和回滚仍未实现。

在原配置中显式使用version2，并增加以下**需替换真实摘要**的策略片段：

```json
{
  "version": 2,
  "snapshot": {
    "version": 1,
    "agent_sha256": "replace-with-pinned-64-lowercase-hex",
    "memory_mib": 512,
    "vcpus": 2,
    "max_entries": 8,
    "max_bytes": 4294967296
  }
}
```

仅支持固定512MiB/2vCPU、Linux amd64的实验恢复。catalog与runtime必须同文件系统，不能hardlink时失败，不偷偷复制memory或回退冷启动。manifest固定Firecracker/jailer/kernel/initrd/agent/workspace摘要、未分配声明、pristine启动参数、格式、生成源码和严格host ABI指纹。指纹包含内核、CPU代际/特征及microcode；它不是跨机/升级兼容性认证，当前测试计划仅同机。

```sh
GOTOOLCHAIN=go1.27.3 go build -trimpath -buildvcs=false -o bin/xandbox-template ./cmd/xandbox-template
# Linux节点读取兼容指纹（不创建或执行guest）。
./bin/xandbox-template host-abi
```

先以新schema2配置启动独立实验controller以建立backend binding。空catalog时Create失败，绝不自动冷启动。使用受审计的**未分配**离线builder生成private manifest/memory/state；publisher只校验声明与文件摘要，**不能证明任意opaque内存中没有租户数据**。禁止导入执行过任务的VM，禁止把租户上传的快照当可信模板。

```sh
sudo -n ./bin/xandbox-template -state-dir /srv/xb-state -config /root/xb-config.json \
  -manifest /srv/private-builder/manifest.json -memory /srv/private-builder/memory \
  -snapshot-state /srv/private-builder/state publish
# 从输出取得TEMPLATE_ID；下面参数是操作员模板ID，不是租户generation。
sudo -n ./bin/xandbox-template -state-dir /srv/xb-state -config /root/xb-config.json activate TEMPLATE_ID
sudo -n ./bin/xandbox-template -state-dir /srv/xb-state -config /root/xb-config.json status
sudo -n ./bin/xandbox-template -state-dir /srv/xb-state -config /root/xb-config.json retire TEMPLATE_ID
sudo -n ./bin/xandbox-template -state-dir /srv/xb-state -config /root/xb-config.json gc
```

manifest为root私有0600文件；源文件/祖先必须root所有、无symlink且不可被其他UID写。失败或未知结果先读取状态，不把超时当作未提交；保留严格TLS/主机验证。命令的context限制锁等待/可取消阶段，不保证物理坏盘上的fsync能按时返回。

`max_entries`范围1..128，含永久RETIRED tombstone；`max_bytes`限制catalog对象字节，失败stage也计入。满额拒绝发布，GC只清理已退役无pin或安全的未发布残留；不是per-VM写盘quota、整机磁盘预留、归档或安全擦除保证。其他工作负载仍可能耗尽同一文件系统，物理存储故障尚未验收。

## 测试现状与下一道门槛

本地测试使用1MiB合成文件，**生产配置校验仍强制512MiB**。覆盖双pin恢复、退役/获取互斥、独立进程flock、真实子进程SIGKILL后的持久pin、owner/namespace缺失拒绝GC、错inode拒绝GC、部分发布/部分删除重建、不可逆初始化尝试、ABI/镜像/权限拒绝等。它们不执行VMM，不证明隔离或性能。

`TestKVMPristineBootstrapSnapshot`新增root fixture的可选`ExportDirectory`，仅在原未分配builder与两克隆验证后导出私有原模板供下一项服务测试；默认不导出，快照本体/fixture绝不提交GitHub。该导出分支已在源码8b1c43f运行并通过；原PR #9报告不覆盖它，本轮报告单独列出。

### 2026-10-22 UTC：独立实机报告

- [模板导出组件](validation/kvm-catalog-builder-v3.json)：源码`8b1c43f5243f540b42d1618be03d1193433446e5`，一个未分配builder、两个实际恢复guest及原9条断言通过，随后仅导出停止的未分配原模板。runner退出0，builder运行目录/cgroup删除；私有离线export为后续故障测试有意保留，不计作服务运行态GC，也不公开快照。
- [schema2服务](validation/kvm-catalog-service-v6.json)：源码`c7d559e9d343ccd6ef308576437a33a8731aa924`，10条有限检查、5次串行闭环切换，runner退出0，`passed/cleanup_confirmed=true`。实际检查所属cgroup内KVM fd、memory/state硬链接、持久尝试标记、两租户/新身份/私有工作区、stale revision和重放；锁下Stop返回并确认宿主停止，DELETE继续到私有jail删除但owner/DESTROYED被catalog锁阻塞，释放后才完成GC。另含活pin退役、实际controller SIGKILL/guardian停止、离线GC重建pin、重启关闭旧代、永久退役、丢失owner时拒删，以及错误ABI/agent/已分配声明拒绝。10条是本脚本的断言分组，不是完整故障矩阵或10种独立灾难场景。
- [独立冷路径](validation/kvm-catalog-cold-v4.json)：源码`e292e4d63d83b3c1130c2df0a196e4394f041e7d`，30项检查及5次冷切换烟测通过；[停止/GC队列](validation/kvm-catalog-cold-v4-queue.json)和[绑定fsync](validation/kvm-catalog-cold-v4-session.json)各9条仅展开其中已有用例，不另加18场景。e292e4d到c7d559e只修改硬件脚本，Go源码相同；Go1.27.3/CGO0/trimpath/buildvcs=false重建daemon/admin/组件与队列测试的SHA256和节点实测完全一致。

5次快照切换从请求开始分别观测：绑定响应654–742ms、新首命令成功666–755ms、旧执行停止682–772ms、旧代持久销毁733–845ms；锁下独立Stop单样本56.281ms。创建READY的3个独立样本为2543.698、615.257、2489.420ms。共享memory/state完整SHA256在写入guest工作区和切换后未变。样本包含复制/校验/调度/观测开销、缓存与背景负载未控制；不能与历史冷切换直接相除得出加速比，更不能当P95/P99/SLO。宿主共享页缓存/私有RAM未完整记账，逻辑unlink不等于物理擦除。

首次服务fixture在创建VMM之前因Unix socket路径109字节被配置校验拒绝；改为107字节并加入显式长度断言后重跑，旧失败不计入通过报告。失败日志/fixture、账号、宿主路径、身份/随机种子均不公开。本轮普通CI仍跳过硬件用例，CI绿不替代上述KVM证据。

### 初始化故障：5个独立实机用例

[初始化故障报告](validation/kvm-catalog-initialization-v2.json) 固定到源码`f9f47ecd026b60ba501d5e9a804907f3a2fb0054`，5个用例、runner退出0、`passed/cleanup_confirmed=true`。这次只新增`_test.go`与Python harness，**未修改生产构造器、Driver.Prepare或guestbridge.Initialize，也未添加生产故障开关**；普通恢复daemon重建的SHA256与之前实测一致。

故障发生时控制器为root测试子进程，通过真实Manager/CreateScoped/Driver创建（不是HTTP创建），其PrepareTimeout为12秒以界定用例；生产daemon的30秒准备上限未改。恢复及旧创建键的HTTP验证使用普通sandboxd；正常HTTP创建/切换仍由上一节服务报告覆盖。

测试子进程包装现有`registry.persist`适配器：先完成真实owner文件/目录fsync，再设置屏障或将实际Firecracker vsock监听inode改名，原路径安装仅用于测试的有界帧转发器。转发器连接真实KVM guest，不伪造guest或在宿主执行任务；只在明确指定的点丢弃ACK或修改实际健康响应的epoch。初始化请求/种子只在私有进程内转发，报告只包含计数与布尔结果。

| 用例 | 实际证据与期望 |
| --- | --- |
| 持久attempt后、initialize发送前SIGKILL | guest实测WAITING、正常执行端口不可用；Core账本仍CREATING、attempt已落盘、所属cgroup有KVM fd。精确父Popen杀死子控制器，guardian停止VM；离线退役GC仍重建1个pin。 |
| guest已封存、宿主READY前SIGKILL | 从真实guest收到精确Ref/boot/hash及0执行组的健康响应，但转发器不把任何成功健康帧交给生产客户端。屏障处账本仍CREATING；随后同样验证guardian、持久pin和普通daemon重启回收。不是guest内部CLAIMED到marker之间的崩溃。 |
| 丢弃CLAIMED ACK | 初始化请求只发送1次；实际guest已认领。原Initialize通过精确正常健康响应确认原epoch后才READY，并通过原Driver执行guest UID65534命令。没有新种子重试。 |
| 丢弃所有正常健康响应 | 真实guest已封存，但客户端不能确认；Create失败、Exec拒绝、候选回收。只发送1个初始化请求，重复的是只读健康探测。 |
| 错误但语法有效的正常健康epoch | 仅修改真实健康响应的hash，其余Ref/bootID/状态/空执行组保持正确；必须拒绝READY并回收，仍只有1次初始化。 |

每个用例独立发布新的可信未分配声明，结束后均由**普通sandboxd**重启验证旧代DESTROYED、旧创建键410（不会再Initialize）、pin为0，才删除RETIRING来源并保留RETIRED tombstone。整个专属运行目录/cgroup清理成功。两个SIGKILL到宿主空cgroup的时长只为本用例观测，包含父进程回收与轮询开销，不是延迟上界或SLO。

普通Linux CI另用合成UDS测试转发器自身；该单测和本轮KVM报告不能相互替代。合成服务器现在会在清零请求前join所有处理协程，避免测试自身的熵清零/读取竞态；修正后的完整5例已再次在KVM运行（本报告），不是仅沿用旧测试二进制。

### 私有umask修正后的完整复验

独立原生Linux Go1.27.3 race×3在`umask077`下发现了真实可用性问题：`OpenFile(...,0444)`实际创建`0400`，catalog严格校验失败；冷路径同样会使降权VMM不能读取kernel/initrd。普通0022的CI没有覆盖这个条件。修正不是接受0400或降低校验，而是：私有0600创建、复制/摘要校验后对**同一FD显式Chmod0444**；catalog在fsync与发布AVAILABLE之前完成封存。冷workspace随后仍单独限制0600并chown保留UID。

额外修正一处负向测试fixture：Mkdir0755也受umask过滤，旧fixture实际是0700，NewFileStore正确接受了它；现在显式Chmod0755后再验证拒绝。没有放宽账本权限策略。umask回归只在独立测试子进程改全局掩码；CI整个race步骤也改为0077，防止再次漏掉这些条件。

源码`547cd79a9c48f49b2410197db065419dcfff6bdf`已在原KVM节点用签名校验的Go1.27.3 Linux工具链重新构建（CGO0、trimpath、buildvcs=false），**全套Linux race×3、vet及以下实机脚本均退出0**：

- [快照服务](validation/kvm-umask-service-v1.json)：10条断言组、5次实际恢复切换，`passed/cleanup_confirmed=true`。
- [初始化故障](validation/kvm-umask-initialization-v1.json)：完整5例再次通过，包含两个精确宿主崩溃屏障、丢CLAIMED/正常健康ACK及错误epoch；全部旧键拒绝、私有回收、退役来源删除。
- [独立冷路径](validation/kvm-umask-cold-v1.json)：30项及5次冷切换烟测通过；[队列](validation/kvm-umask-cold-v1-queue.json)与[绑定fsync](validation/kvm-umask-cold-v1-session.json)各9条仍为已有场景展开，不额外加18。所有**当前/恢复controller均显式0077**；唯一历史旧版本setup用0022（旧不可变二进制尚无此修正），当前恢复仍0077。报告明确记录这个边界，不声称历史程序支持0077。

新原生daemon SHA256为`c57760c8c6f1ce5e013e51b8053015f367e55e5a29fd9ac064ba6602e32813f1`；admin与两类测试程序摘要保存在报告。旧87e6799c不是本轮运行程序。guest-agent、initrd、Firecracker/jailer及从未分配export未变，publisher重新验证其实际摘要/ABI；不沿用旧controller验收。

本轮5次切换的观测范围为：新首命令626–742ms、旧执行停止648–761ms、旧代持久销毁725–812ms；单独Create为2578.527、661.655、2555.702ms。仍只是有限同机样本，不能挑选暖路径、计算跨报告加速比或宣称百分位/SLO。物理擦除、共享RAM完整记账等限制不变。没有通过手改正在被真实VM引用的memory/state权限来掩盖问题；权限修正仅作用于新stage。

### 复现服务用例

先按[组件步骤](PRISTINE.md)创建新的root私有fixture，并增加`ExportDirectory`（Root之外的新绝对目录）与`SHA256.agent`（实际agent摘要）。使用本源码的`TestKVMPristineBootstrapSnapshot`成功终止并确认builder命名空间删除后，才可使用其私有export。不要导入旧租户VM或手工伪造声明。

```sh
# 固定Go1.27.3；这些Linux二进制需与当前源码及固定镜像一致。
GOTOOLCHAIN=go1.27.3 GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/sandboxd ./cmd/sandboxd
GOTOOLCHAIN=go1.27.3 GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/xandbox-template ./cmd/xandbox-template
sudo -n python3 scripts/kvm_snapshot_smoke.py \
  --daemon bin/sandboxd --admin bin/xandbox-template --warden bin/xandbox-warden \
  --firecracker /absolute/pinned/firecracker --jailer /absolute/pinned/jailer \
  --kernel /absolute/pinned/vmlinux --initrd /absolute/pinned/guest.cpio.gz \
  --export-dir /absolute/private-unassigned-export --source-revision "$(git rev-parse HEAD)" \
  --report /absolute/private-proof/service.json --log-dir /absolute/private-proof/logs
```

脚本仅创建新的专属短`/srv`目录和cgroup，显式保留16个未分配UID、固定512MiB/2vCPU/128MiB工作盘；不改宿主时钟/路由、不采用已有目录、不执行宿主任意租户命令。任一错误保留失败终态，不应在相同report/log路径重启runner。需要确认进程终态0、报告`passed/cleanup_confirmed=true`及专属资源确已删除；stdout静默/观察超时不是进程未启动的证据。原始日志和export保持私有，不随报告提交。

初始化故障另用同一源码构建Linux测试二进制，保留前述未分配export；它不能替代常规服务脚本：

```sh
GOTOOLCHAIN=go1.27.3 GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -trimpath -buildvcs=false -o bin/initialization.test ./internal/firecracker
sudo -n python3 scripts/kvm_snapshot_faults.py \
  --test-binary bin/initialization.test --daemon bin/sandboxd --admin bin/xandbox-template \
  --warden bin/xandbox-warden --firecracker /absolute/pinned/firecracker --jailer /absolute/pinned/jailer \
  --kernel /absolute/pinned/vmlinux --initrd /absolute/pinned/guest.cpio.gz \
  --export-dir /absolute/private-unassigned-export --source-revision "$(git rev-parse HEAD)" \
  --report /absolute/private-proof/initialization.json --log-dir /absolute/private-proof/fault-logs
```

### 仍未完成

guest内部CLAIMED到marker之间的进程崩溃、部分特权初始化失败、分片/部分帧丢失和READY账本写入故障等剩余矩阵；物理存储故障/容量压力、跨节点/内核升级兼容性、预热池、持续混合负载/公平性、阶段尾延迟、共享/私有RAM完整记账与长期回收曲线均未验收。M3和整个生产Goal保持未完成。


### 开发中：guest内部故障fixture（尚未实机验收）

新增测试专用的只读观察器（`xandbox_guest_fixture`构建标签，默认构建/生产镜像不包含）、受摘要约束的initrd变体工具，以及独立的未分配故障模板export测试。机器身份目录故障使用未修改的agent，目标是在实际熵注入、guest时钟/只读boot视图之后令machine-id写入失败；认领后标记前崩溃使用固定源码摘要的Go compiler overlay，在该精确位置exit97，**不是生产agent二进制**。观察器仅接受host CID的固定inspect请求，返回布尔状态与进程代数，不接受路径、argv、写入或reset。

这些测试镜像、overlay和诊断端口**不得用于生产模板**；需独立绑定实际agent/initrd摘要与私有state/runtime。普通正向双克隆组件不允许故障模式，故障export也不被计作正向克隆成功。当前仅有编译/合成回归，未通过新真实KVM案例前不宣称这些guest内部窗口已覆盖。
