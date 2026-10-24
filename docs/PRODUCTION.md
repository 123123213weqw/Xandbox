# Xandbox 生产化计划与发布门槛

最后更新：2026-10-24。

## 当前状态

**开发中，不能按生产隔离服务部署。** 已有 Mock 控制面验收及独立 jailed KVM 组件验收，并新增实验性 Firecracker 服务集成；整体门槛尚未完成。Public 仓库不等于生产就绪。

新增 opt-in TEST ONLY `systemd-ingress-v1`，专门运行普通 daemon +
[独立 ingress 启动器](INGRESS_LAUNCHER.md)，而非让自定义PID1 TLS结果冒充systemd组合。
冻结源`d5f3c2e63d7c045a6089d062da31314524d75313`已取得新原件，完整两启动闭集流程通过。
这是限定环境、显式operator编排的组合实测，不是自动安装/升级或完整生产验收；整体仍未生产就绪。

[脱敏证据](validation/systemd-ingress-tls-v1.json)绑定冻结源、归档、12产物、10个harness摘要、
前序失败与独立清理复核。所有原始console/CA/令牌/进程和资源身份保持私有。

自动启动/readiness 的[新独立组合](SERVICE_READINESS.md)已另取9e4da26两启动实证：真实后置闸门/坏pin与冻结后端拒绝、单main启动及原盘enable自动启动通过；新两个外层代际独立只读清理复核，含前序共9scopes/13个全局唯一代际再次复核不存在。不勾选完整生产安装或M4。

后续[持久drain自动启动扩展](READINESS_DRAIN.md)已另取e9c8069双启动实证：完整epoch/revision/最后request提交跨warm/cold保持，健康服务不隐式resume，旧执行/回收继续，新准入拒绝，明确root CAS恢复后真实新guest通过。新增197项Linux Python零skip，13个Go产物未变；首个managed路径测试失败保留。含历史失败的11scopes/16个全局唯一外层代际/49个唯一声明路径再次只读确认不存在，无补充清理，不是完整生产验收。

当前普通 sandboxd 为新 `5bfb2394…`（SIGTERM注册先于Serve），新增[固定清单 Go 启动器](GO_LAUNCHER.md)
`26f35a3d…`。真实systemd→普通认证UDS→四并行KVM、busy Stop/GC、main SIGKILL与原盘cold
有限验证通过，5 scopes/7外层代际独立只读清理复核；后续[25个全新命名运行scope](FIVEB_RUNTIME.md)
已另行通过，[fixture320的live trace两组/10边界/TLS](FIVEB_BOUNDARIES.md)也已另行通过，下文 d163 及更早报告仍为各自历史 ELF，不给新程序代签。完整TLS部署/安装升级/备份和独立
操作员仍未完成，不据此勾选M1–M4。

[新5bfb复验](FIVEB_REQUALIFICATION.md)保留首冷scope及离线探针校准来源；[25组运行](FIVEB_RUNTIME.md)已独立完成，另一个fixture320的[12个live trace/边界scope](FIVEB_BOUNDARIES.md)也完成新证据与独立24代际清理复核；合计37scopes/67嵌套代际/4loop，不提前勾选完整M1–M4。

当前新增生产代码[Version3节点总资源准入](NODE_BUDGET.md)：精确父/控制器cgroup、完整服务计数与恢复库存绑定、保守磁盘/inode余量及有界准备池已实现；新3ea ELF的4真实KVM/漂移拒绝但回收继续/健康同步原盘cold与相关回归通过。仅7 scope/17外层代际的有限基础门槛，不是全部节点压力或完整M2；[新程序DEFAULT/IO全量兼容复验](RUNTIME_REQUALIFICATION.md)已单独通过13个scope，[quota240/双活cold及故障矩阵](QUOTA_REQUALIFICATION.md)也已另通过12个scope/34外层代际；旧522报告不得冒充新ELF认证。

目标：用 Go 实现面向云端短生命周期任务的单节点执行服务，优先验证快速切换、可靠停止和完整回收。第一版不包含 GPU、桌面、跨节点迁移或通用集群调度。

另有[schema3 snapshot/inode/字节压力与低free cold有限门槛](NODE_SNAPSHOT_PRESSURE.md)：生产ELF不变、新fixture实测及8scope/19外层代际独立审计通过；实际permit并发、全RAM/OOM、外部日志/export硬边界及完整节点/生产门槛仍未完成。

部署与恢复的操作员边界、systemd层级限制及尚未实现的备份/回滚门槛见[OPERATIONS.md](OPERATIONS.md)。文档不是已经通过的安装器/操作员验收。[systemd接口冲突与部署契约](DEPLOYMENT_CONSTRAINTS.md)记录 `.control` 边界；后续[真实 systemd L1 地基](SYSTEMD_HOST_FIXTURE.md)已通过两次启动、独立 operator/委派/reload/stop-start，136项原生Python零skip及含失败前序5代际只读复核。选择 nested node 布局，后续Go启动器与普通UDS/KVM有限通过见上方新报告；自动安装仍未完成；自动readiness与TLS→KVM有限组合已另取上方独立证据，不据此勾选M4。

新增[有界发布物仓库](RELEASE_STORE.md)作为安装事务地基：固定清单复制/密封、持久意图及CAS发布引用、精确重试和中断恢复代码已加入；没有unit/服务变更；原0a51原生scope不含privileged CLI组合，后续另见下段；完整owned-L1安装/升级门槛仍不勾选。

后续[普通发布CLI/服务持续性/原盘冷恢复](RELEASE_PUBLISHER_KVM.md)已取得3587双启动有限实证：真实13角色资产、两次4进程CAS、缺源精确重试、库存拒绝、原服务/guest持续及完整readiness/drain回归通过。219项Linux Python零skip，15个既有程序未变；三个失败前序保留，含前序15scopes/21代际/66声明路径独立只读无残留。不是服务安装/激活、升级、备份或完整M4。

## 信任与隔离边界

新增[独立TLS接入与凭证边界](TLS_GATEWAY.md)：新gateway程序实际完成专用UID/caps0/NNP/chroot/cwd/继承FD及root无TCP核对、真实双租户TLS→KVM、外部key/leaf持久轮换、无效reload/旧revision拒绝、健康同盘cold与普通schema3回归。当前0b源含持久lock标记修正，另行通过2scope/4次启动；bootstrap记录丢失仅有原生unit失败对照与修正回归，不宣称物理丢失故障已测。普通4ee五个ELF不变，各前序false/冻结源保留。此有限子门槛不勾选完整M4；PKI/分发、policy提交故障、资源/日志/审计、真实operator部署与长负载尚未完成。

后续[固定policy提交窗口/入口watchdog有限验收](TLS_POLICY_COMMIT.md)已通过：83d为测试修改，同一生产ELF在pre-file FSYNC、post-durable pre-snapshot MEMFD_CREATE两入口实际hold；child在root仍挂起时退出，普通忙任务继续，冷恢复区分真实journal1与2，另有健康TLS/普通schema3回归，共4scope/8代独立审计。未覆盖其余policy介质/提交窗口、孤立临时元数据预算或完整M4，不用通知等待代替真实文件系统D。

历史555b节点的[有界policy库存与真实孤立文件回收](POLICY_METADATA.md)为**新的生产gateway**555b/c402：增加有界11项/8KiB逻辑库存、严格已识别temp的CAS后回收，新程序已另跑pre/post/TLS/普通schema3共4scope/8次启动与独立清理审计。原生19类非法库存和边界负例、实机foreign/symlink/跳号拒绝及真实SIGKILL temp的cold回收有限证据均保留；旧241ca不代签。不是全局物理磁盘、日志/审计预算、完整GC/介质窗口或完整M4。

当前新增[有界异步诊断与闭集原因计数](DIAGNOSTICS.md)：历史29fe的日志窗口证据保持原绑定；新 daemon d163、fixture98ae 已独立通过12scope（nested16次L1启动及4组 DEFAULT/IO×ENOSPC/EROFS）、真实EIO/EDQUOT/部分复制、准备/取消trace及两个日志窗口，并完成无补充清理的独立资源/loop复核。[脱敏摘要](validation/diagnostics-cause-v1.json)含原始归档指纹、native/cross9及72项拒绝检查。旧 raw stderr 负向已迁移到精确闭集启动行、独立 producer 计数或受控真实故障与同输入恢复证据，不恢复原始错误输出；这不是可靠租户审计、持久化根因证书或完整生产验收。新 template573e/nodeea48/gateway41e9/builder5ff7 不能沿用历史报告代签；后续具名矩阵与边界复验见下文，各自保留源绑定。本项不勾选完整M2/M4。

随后另完成[d163 DEFAULT/IO/quota240命名兼容矩阵](D163_RUNTIME.md)：18个新scope与上述同源7个scope组成25组，分别保留原始来源，43个外层执行代际及4个loop绑定均有独立只读复核；冷30、DEFAULT/quota各双租户240次、双活cold及明确列出的故障通过，不重标历史ELF报告。此更新只完成该命名矩阵。后续另有[十个命名边界复验](D163_BOUNDARIES.md)：7组旧fixture与3组新TLS fixture保留原始来源，普通8产物逐字节相同，20个合格代际及1个失败前序代际独立只读复核不存在。饱和压力、可靠审计、独立部署与运营验收仍未完成。下文早期“最新”版本叙述为各自历史节点，以本段及对应源绑定报告区分当前证据，不勾选完整M1–M4。

- 不信任 guest 中的任务代码、文件名、输出或终止行为。
- 信任经过维护的宿主内核、KVM、操作员配置和经过固定版本/校验的模板。
- 一实例一独立 guest、写盘、进程资源组和执行代际；不把已使用实例直接交给另一租户。
- guest 无权修改生命周期账本、控制 socket、身份配置或其他实例的资源。
- guest-agent 的命令执行不能回退到宿主机；真实后端不可用时必须失败。
- 默认不配置 guest 业务网络。后续开放网络必须增加宿主侧策略与已建立连接的撤销测试。
- 微架构侧信道、已被入侵的宿主机和具有宿主权限的恶意操作员，不在第一版隔离承诺内。

## 里程碑

### M0：公开可复现的开发基线

- [x] 单节点生命周期、generation 栅栏、异步回收、TTL、故障重试。
- [x] 本地进程级 SIGKILL/重启验收与重复生命周期验收。
- [x] 固定仓库名 Xandbox、MIT、开发成熟度声明。
- [x] Public 仓库已发布；Linux/macOS CI 实际通过。首轮证据：[CI #39632748731](https://github.com/123123213weqw/Xandbox/actions/runs/39632748731)。

### M1：控制面正确性

- [x] 身份配置仅存 token 摘要；请求不可自行指定或伪造租户。
- [x] 所有实例及执行查询、停止、删除都检查租户归属。
- [x] 节点与租户实例配额包含正在回收的资源。
- [x] 创建幂等 key 在并发与重启后仍生效；冲突参数拒绝。
- [x] 普通 API 错误投影不回传 driver/账本原始错误；进程验收确认不记录令牌、argv 或任务输出。完整结构化审计仍属 M4。
- [x] v1 严格账本格式与显式离线升级，含实际旧 binary/KVM 崩溃恢复证据。
- [x] 节点/租户累计容量与永久 tombstone 政策有并发、满额、降低预算与迁移中断测试。
- [ ] 长期保留/归档/轮换、容量曲线及独立操作员升级恢复验收。

控制面使用方式与未完成限制见 [AUTH.md](AUTH.md)。[账本治理](LEDGER.md) 已有实际旧 binary/真实 KVM 升级与累计容量证据，长期保留/归档、容量曲线及独立操作员复现仍未完成。早期鉴权检查源自 mock，后续真实服务与旧 VM 升级另有报告；M1 长期元数据治理尚未完成，不能据此宣称生产就绪。

### M2：真实 Linux/KVM 执行

- [x] 固定版本、校验摘要的 Firecracker/jailer；保持默认 seccomp（v1.17.0 实验规格）。
- [x] guest-agent 使用 vsock；执行、取消、文件工具位于同一 guest（实验规格）。
- [ ] cgroup v2、vCPU/内存/进程与磁盘预算；宿主资源归属可恢复。
- [ ] guest 中的超时和进程树不会逃逸；STOPPED 必须等到执行单元退出。
- [ ] 控制器崩溃、驱动错误、部分准备失败、宿主重启后的资源清理经过真实验收。
- [x] 未使用 mock 或宿主 shell 绕过实际验收。
- [x] [有界真实ext4 ENOSPC](STORAGE.md)：guest工作盘限容及数据块/inode耗尽×忙碌/空闲KVM共5场景，拒绝虚假持久删除/容量释放，空间恢复后同state回收及旧key拒绝；不是全部磁盘故障/配额验收。
- [x] [存储错误返回后的独立物理Stop](EMERGENCY_STOP.md)：新原生daemon的5场景ENOSPC、快照10组/双租户240次、初始化6+2例及独立冷路径30组回归；不把物理Stop当持久回收，不覆盖卡死尚未返回的I/O或完整M2。
- [x] [独立ledger只读EROFS](READONLY.md)：真实小卷busy/idle两组、故障前目录FD写入拒绝、只读持续时重启拒绝/恢复可写后同state回收及原有5场景ENOSPC回归；不是全state/介质/自动remount故障矩阵。

- [x] [双层I/O预算有限验收](IO.md)：绑定operator策略、正确backing queue/委派、cold与PAUSED快照先设置并读回、真实operator direct IO与guest direct写/读及活跃写盘Stop/GC；新native默认矩阵通过。仅完成该子项，节点总预算/准备复制/IOPS饱和/物理quota与完整M2未完成。
- [x] [独占L1虚拟宿主掉电有限验收](NESTED_HOST.md)：running/stopped/destroyed各一个检查点、四次实际KVM开机、原磁盘与普通daemon恢复/旧键拒绝/新L2执行销毁通过。L0未重启；不是物理介质掉电、所有在途fsync/Prepare窗口或完整宿主故障矩阵。

- [x] [整状态盘EIO/held-fsync有限验收](STATE_IO.md)：原生新程序4例、原程序失败对照、普通daemon真实D-state fsync、独立lease EOF停止/快速intent拒绝、无虚假确认/容量保留及完整新native回归通过。不是VMM自身D-state、所有介质/Prepare窗口或完整M2。

[ext4 project quota 前置验收与协议设计](PROJECT_QUOTA.md)单独区分内核行为与普通驱动功能：root能力绕过、受限root的EDQUOT、共享硬链接/继承及原盘重启持久化已有有限测试；本分支已实现实验性每代projectID/驱动接入并打通cold/snapshot有限恢复、双实例共享pin检查，quota清零已移出catalog pin锁；普通daemon的block/inode EDQUOT、能力/UUID/未知记录/绑定变更/缺enforcement拒绝亦已有有限检查；quota启用的整state I/O、清零后owner/pin待释放的精确掉电窗口已有有限检查；另有6个固定quota syscall errno注入例通过，采用额外TEST ONLY启动层、不是物理介质故障；完整held/重复错误/逐syscall崩溃、节点预算、锁内owner元数据持久化与全部持久窗口验收仍未完成，不能勾选完整磁盘预算。

最新普通daemon已更新为 `522da68e…`：quota同步增加runtime anchor上的显式syncfs提交屏障，真实内核D挂起/pre-fork掉电恢复已有有限证据。旧Q_SYNC-only负对照不构成已确认READY/DESTROYED不安全的证明；旧ab547/B8完整报告也不能代替新runtime全矩阵。新native默认服务兼容矩阵已另复验：cold30/load5、queue/binding展开、snapshot10及两租户各120次、初始化与存储/I/O均通过；后续[真实quota commit故障子门槛](QUOTA_COMMIT_FIXTURE.md)已完成实际syncfs EIO及两个release hold/cold各N=1，production ELF不变；但quota启用的完整切换/并发及其余持久窗口仍未完成，不能勾选完整M2。

最新[重复clear与额外TEST listener失效](QUOTA_LISTENER_FIXTURE.md)有限检查已通过：三个clear各3次及两个最后listener关闭/实际ENOSYS/冷恢复，32个执行代际独立核验清理。生产Go/ELF未改、生产不依赖该TEST listener；不能把它当作完整生产监听器或双监督故障门槛，quota并发/其余持久窗口仍未完成。

新增[quota双租户忙任务切换与双活cold有限验收](QUOTA_SWITCH_FIXTURE.md)：3f9冻结源、明确3GiB/4GiB资源规格，各120次/actual writer/pre-timeout独立Stop与durable回收、测量后双活session同盘冷恢复及旧11个规格回归通过。production522未改，12 passing scope/34外层代际＋4 failed scope/5代际独立核验；不替代节点总预算、其余持久窗口或完整M1–M4。

新增[部分workspace复制失败/keeper有限验收](PARTIAL_COPY_FIXTURE.md)：真实16MiB前缀、一次TEST errno EIO、普通GC/slot复用与retired keeper pin组合通过；另有[未主动同步的固定partial-copy host cut](PARTIAL_COPY_CUT_FIXTURE.md)原盘冷恢复通过，保留失败前序和实际cold文件丢失/独立quota核账；其余元数据持久窗口及完整M2仍未完成。

新增[owner unlink后目录fsync pending原盘cold有限验收](OWNER_COMMIT_FIXTURE.md)：实际owner在冷后重新出现、quota0保留、无虚假DESTROYED/返容量、普通恢复与keeper共享backing/新guest/GC组合通过；其他元数据窗口、catalog锁内慢提交及完整M2仍未完成。

M2 的独立组件见 [GUEST.md](GUEST.md)，服务设计见 [FIRECRACKER.md](FIRECRACKER.md)。[独立组件验收](validation/kvm-guest-2026-10-22.json) 与 [已验收基线的真实KVM冷路径30项回归](validation/kvm-pristine-cold-service-2026-10-22.json) 已通过，覆盖出生即入 cgroup、鉴权/配额、SIGKILL/重启、部分准备恢复、并发停止、控制器暂停、硬 TTL 和 guardian 失效。完整宿主重启窗口/物理介质故障、双监督失效、guest 回收故障注入、存储预算和持续负载仍未完成；不能将本轮小样本通过等同于全部 M2 或生产试运行验收。

停止/GC 独立有界池、所有权 fsync 不持有全局锁及受控慢 I/O 下的恢复已有 [专项证据](LIFECYCLE.md)。[独立 guardian 租约](GUARDIAN.md) 已用真实暂停控制器测试；这只完成该部分基础设施，不替代持续负载、公平性、整机故障和最坏延迟验收。

### M3：快速切换与容量管理

- [ ] 干净模板快照恢复；实例身份在分配后重新初始化。
- [x] 会话绑定以版本条件更新；过期请求不得误操作新实例（冷切换实验规格，实际 KVM 已验证）。
- [x] 新环境准备与旧环境回收解耦；旧环境撤权/停止状态可观察（冷切换与受控绑定 fsync 实验证据）。
- [ ] 预热池只包含未使用的实例；GC 队列有背压与恢复策略。
- [ ] 共享快照/基础盘有引用关系，不能提前删除。

会话冷切换与独立版本准入已有实际 KVM/故障证据，设计、预算和边界见 [SESSIONS.md](SESSIONS.md)。这不是快照或预热；这些机制、共享引用管理、持续负载及切换百分位仍未验收，不能把两个已验证子项当成整个 M3 完成。

[干净模板初始化闸门组件](PRISTINE.md) 已有双克隆证据；新增 [catalog/schema2服务](CATALOG.md) 已独立通过10条有限KVM服务检查、5次恢复切换、活pin退役/控制器崩溃恢复/丢失owner拒删，新源码冷路径另通过30项回归。另有5项真实初始化故障用例，覆盖持久attempt后发送前/封存后READY前宿主崩溃、丢CLAIMED/健康ACK和错误epoch，普通daemon恢复和旧键拒绝均通过。另有一个guest内故障注入崩溃点及一个未修改agent的部分特权失败点通过；其他初始化/存储故障矩阵、预热池、共享资源记账和持续恢复负载仍未完成，不能勾选M3的完整快照门槛。其后发现的umask077封存/冷镜像权限问题已修正，并以新原生Linux程序重跑10组快照/5项初始化故障/30项冷路径，见[当前权限复验范围](CATALOG.md)。

### M4：生产试运行验收

- [x] 固定基数、无生命周期锁/I/O写入的独立私有管理指标；真实KVM不同宿主UID拒绝与连接压力下Stop/GC实验验收。
- [x] 40次新VM切换闭环的独立阶段分布、外部RSS/cgroup/FD采样（67秒有限实验，不代表生产持续负载）。
- [x] [双租户各120次快照切换](MIXED_LOAD.md) 的246.267秒有限混合闭环、租户配额隔离、404个资源视图样本及完整失败前序记录；不是完整共享RAM归属、公平性、开放到达饱和或生产持续负载。

- [ ] CI 的静态分析、race、故障注入、依赖/秘密扫描通过。仓库级[固定秘密扫描门禁](SECRET_SCAN.md)已接入独立 job；当前提交结果须以实际 CI 为准，不替代真实 KVM/部署与完整 M4。
- [ ] 真实 KVM 集成测试有可下载日志和固定环境参数。
- [ ] 结构化审计、指标、告警建议、备份/恢复与升级回滚手册。
- [ ] 持续负载期间回收队列有界，资源占用不会随销毁数量无限增长。
- [ ] 测量并区分创建、撤权、停止、回收、切换的 P50/P95/P99。
- [ ] 操作员按部署说明独立复现；已知限制清楚列出。

本轮有限闭环报告与指标边界见 [OBSERVABILITY.md](OBSERVABILITY.md)。短测中每轮旧GC后的controller FD均为11，RSS仍从约14.60MiB变为16.61MiB；有永久metadata和运行时高水位，不能据此勾选长期稳定性/无限增长门槛。多租户公平性、真正持续混合负载和可靠审计仍未完成。

只有以上门槛通过，才考虑将状态从“开发中”升级到“受限生产试运行”。生产环境、规模和威胁模型变化时需重新验收。

## 性能报告要求

暂不宣称毫秒级完成所有销毁工作。每份报告必须注明：CPU/内存/内核、磁盘与文件系统、guest 规格、实际驻留内存、写入规模、并发数、冷热缓存及是否命中预热池。

分别记录：

1. 接受请求到新任务准入被撤销。
2. 接受请求到执行单元确认停止。
3. 接受请求到私有资源完成回收。
4. 请求切换到新实例第一条命令成功。

Mock 数字只能用于控制面回归，不能作为 microVM 性能宣传。API 202 不是停止或清理完成。
