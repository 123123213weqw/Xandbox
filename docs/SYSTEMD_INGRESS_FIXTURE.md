# 独立 systemd ingress/TLS owned-L1 fixture（有限实机验证通过）

新增 opt-in TEST ONLY `systemd-ingress-v1`，专门运行普通 daemon +
[独立 ingress 启动器](INGRESS_LAUNCHER.md)，而非让自定义PID1 TLS结果冒充systemd组合。
冻结源`d5f3c2e63d7c045a6089d062da31314524d75313`已取得新原件，完整两启动闭集流程通过。
这是限定环境、显式operator编排的组合实测，不是自动安装/升级或完整生产验收；整体仍未生产就绪。

[脱敏证据](validation/systemd-ingress-tls-v1.json)绑定冻结源、归档、12产物、10个harness摘要、
前序失败与独立清理复核。所有原始console/CA/令牌/进程和资源身份保持私有。

## 新规格，不扩张既有profile

- L1 RAM16GiB、12 vCPU、24GiB ext4 root盘；无NIC。
- L0独占外层执行组 memory.max18GiB、swap0、OOM group1、pids512、CPU12/100ms。
- 固定QEMU、内核、模块、Ubuntu/Alpine与服务程序摘要；原15分钟硬lease、父生命周期pipe、
  reserved UID、独立netns、KVM组和磁盘大小/RLIMIT约束仍保留。
- 开始前要求共享L0至少64GiB可用RAM、`/srv`空闲超过48GiB；只创建/回收本次私有路径和组。
  不改共享L0的service、模块、挂载、quota、sysctl、网络或包，不在L0执行/chroot下载的guest。
- 原2GiB/CPU4 primitive和8GiB/CPU8普通UDS profile保持原数值；未知profile仍拒绝。

原 daemon unit 父7.5GiB/512tasks/CPU8/每方向512MiB/s与16384IOPS，独立ingress
512MiB/64tasks/CPU2/每方向64MiB/s与2048IOPS；reserve2GiB/64tasks/CPU2/
每方向128MiB/s与4096IOPS，计入12GiB/1024tasks/CPU12/1GiB/s/32768IOPS核算上限。
它不是共同硬父组、OS/operator硬预留、物理磁盘或主机可用容量证明。独立operator还设有
自己的256MiB/32tasks/CPU1 unit；完整容量规划/全RAM/OOM/公平性仍另验。

## 单一部署来源与两个操作面

`build_systemd_ingress.py`扩展原9资产清单为12项，额外固定gateway、ingress guard及
`cmd/xandbox-deploy-fixture`。后者需要Linux + `xandbox_deploy_fixture` build tag，且
在任何写入前检查专用L1 marker/root/systemd。它只是封闭fixture helper，不是安装器，
不接受任意路径、租户argv或宿主任务。CA/leaf/backend与external令牌仅在私有L1生成/保留。

helper使用生产`ingresslaunch.Manifest.Unit`生成候选unit，不手抄另一套systemd模板；
原gateway.Config与原node manifest/budget/parser仍为唯一来源。
独立operator先等待普通私有UDS真实READY，再显式启动ingress；**不宣称单命令自动安装、
WantedBy自动启用/顺序或完整readiness编排通过**。这是必须另补的部署门槛。

所有测试任务经真正TLS→gateway→普通guest API；短暂关闭TLS时，仅可信operator用已存在
私有UDS观察原guest进度，不向租户提供旁路、更不在host执行任务。

## 本次实际通过的闭集流程

1. 三个各自独立的预检负例：错误config pin、预算与实际kernel不符、额外capability。
   要求真实exit1/指定闭集阶段、manager清除本unit、没有child/TCP listener；只对已经
   证实的故意负例reset-failed，不对未知失败盲目重试。
2. 正常入口MainPID实际exec普通gateway；root/child精确同在独立ingress组，root所有观察
   线程仅SETUID/SETGID/SYS_CHROOT和NNP，child专用UID/空groups/活动caps0/NNP/
   executable-only root、cwd与FD；root无TCP，child持有TLS listener，逐项读回两个父预算。
3. 双租户四个并行真实KVM，guest UID/boot/精确VMM/caps/双seccomp/quota，401/404/
   tenant429/node503，忙任务Stop与durable GC分开，资源/quota真释放后复用干净新guest。
4. 只stop/restart ingress，UDS独立观察原忙guest继续；live key/leaf revision2轮换，更新
   config和manifest pin后发main HUP。核对服务PID不变、guest继续、新leaf/令牌接受以及
   原已建立TLS连接使用旧令牌被拒。
5. 只SIGKILL daemon MainPID，要求BindsTo使ingress两进程/TCP关闭，manager清除两个unit
   cgroup及旧输入目录，不由operator rmdir补救。显式重启/READY/ingress后普通recovery
   回收全部旧guest，旧key410，gateway revision2保留；再保留一个真实忙guest健康checkpoint。
6. 只切断本次外层L1执行组；原盘第二次启动。L1 boot变化/machine-id保留，旧guest确实
   不恢复，生产recovery清账，旧external key401/创建key410，新leaf/令牌和新guest有效，
   最后四个project全0，正常manager stop两个unit/输入目录消失。

每个公开结果只接受完整闭集typed true，未知字段、缺项或整数冒充bool拒绝。
原始console/CA/令牌/进程身份/资源receipt必须保持私有，失败前序单独保留；每次执行后再以
root600单链接/NOFOLLOW receipt和冻结路径构造进行独立只读复核，不做补充清理。
新fixture字节与所有普通服务程序必须分别比较、绑定原生/交叉构建，不能给历史报告重贴标签。

这些流程、代码或纯控制不能替代实际内核/服务证据，也不等于catalog、生产安装、升级回滚、
备份恢复、独立人类operator、饱和长测、审计保留和SLO通过。

## 历史失败前序（均保留原件，不回写成通过）

### 首轮（62d5c27）：TLS启动失败，原因当时尚未收全

新12产物原生/交叉构建一致，十个既有产物字节不变；原生Go race/vet、host fixture与
helper race/vet、quota filter以及161项Python零skip通过。相同新outer fixture下原2GiB
primitive与8GiB普通UDS各两启动通过。新16GiB TLS scope在READY前实际失败，不记成通过。
独立只读复核包含这三个scope/五个外层代际，全部声明路径消失，无补充清理。

原始失败console只保存到Traceback第一行：fixture先写终止标记，L0 reader看到标记立即
进入执行组清场，来不及保存完整原因。失败原件与source62d保留，未回写。
后续只调整新fixture失败报告顺序：有界traceback/journal先完成，再写终止footer；journal
超时也必须写footer。旧顺序已有实际RED控制，新顺序控制通过。不改生产程序、预算、能力
或任何成功断言；**这只是诊断修正，不是已查明/修复的TLS启动根因**。后续须新scope实测。

第二次（78f1fb6）完整诊断确认：第一个故意错误pin负例没有到预期composition阶段，实际
先在placement阶段失败；该scope仍失败，独立只读复核其一个外层代际/全部声明路径消失。
尚不能据此判定是cgroup namespace还是capability不符，不能放宽guard或直接改预算。

下一冻结版本临时采用**诊断专用**同PID Python pre-exec observer：只输出位置分类、namespace
关系可观测性、root UID/GID/NNP布尔值、五个cap bitset与可继承FD计数，再exec固定Go guard。
不输出PID/cgroup实际路径、凭证或任意用户字段。它改变了候选unit的入口，因此这个模式
无条件拒绝资格通过；用于获得出生状态后还必须恢复真正candidate入口并另行实测。

### v3出生观测与后续unit修正（当时新实机待执行）

ac2e5d2诊断scope实测：位置分类expected、绝对unit组可见、UID/GID root、NNP1，
CapBnd=262336(SETUID/GID/CHROOT)，但CapPrm/CapEff=262208，**实际缺SETUID**；
inheritable/ambient0，可继承非stdio FD0。PID1 namespace关系因权限不可观测，不推断相同。
该scope故意不接受资格通过，原件和独立一个代际清理复核保留。

结合[systemd v255 exec-invoke.c](https://github.com/systemd/systemd/blob/v255/src/core/exec-invoke.c)
的keep_seccomp_privileges/enforce_user路径：显式User=与含seccomp的沙箱组合会在没有相应
ambient时drop CAP_SETUID。观测与该路径一致，不能通过放行缺失的active capability解决。
后续候选unit去掉冗余User=root/Group=root，使用
[系统service默认root](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html#User=)；
guard仍逐线程强制root/NNP/精确三项active/permitted/bounding，inheritable/ambient0。
PrivateDevices、只读cgroup/系统、预算和所有失败关闭条件保持；没有添加ambient能力。

新增旧unit实际RED/新unitGREEN控制，以及bounding有SETUID但active缺失仍必须拒绝的
控制。恢复真正Go candidate入口，关闭临时observer模式。此修正改变ingress guard/helper
的重建字节，必须重新原生构建/校验并在新owned L1 scope中验证；旧失败不回写为通过，
当前尚不宣布TLS→KVM/rotation/crash/cold通过。

v4（6a85035）已按原断言完成三个预检负例，故意错误pin到composition、预算漂移到
 envelope、额外能力到placement，说明root精确能力检查已推进；正常入口仍在envelope
拒绝，未接受TLS。完整journal明确提示`CPUQuota=200.000%`非法并被忽略。原有精确kernel
读回阻止了缺失CPU上限的入口启动，没有为通过测试放行无限quota。

[systemd v255 load-fragment](https://github.com/systemd/systemd/blob/v255/src/core/load-fragment.c)
调用[percent-util](https://github.com/systemd/systemd/blob/v255/src/basic/percent-util.c)解析，
百分数至多两位小数。后续render整数200%，可精确表示的小数最多两位；100ms周期对应
10µs精度，不能表示的immutable quota直接拒绝生成，不静默取整。新增旧实现RED/
新实现GREEN控制；预算/所有kernel读回和三项能力断言不变。新guard/helper字节仍须原生
重新构建及新scope实测。v4失败原件与独立一个外层代际清理复核保留。

v5 native已通过完整race/vet、fixture/helper/filter与164项Python、12产物原生/交叉一致；
但首个硬件编排脚本误指向已存在v4资产文件，exclusive-create在任何L1创建之前拒绝，
原文件未覆盖、未启动新VM；记录为编排失败，不是内核/TLS通过或失败。

后续同时加强两个实测oracle：旧令牌401必须来自同一个socket对象、dev/inode与端点，
不能把HTTPConnection自动重连当成旧TLS连接撤权；忙writer须在ingress停机后与轮换后
各自重新采样推进，并且原execution仍RUNNING。保持原401/角色PID/所有关闭与回收断言。
新增重连身份负例控制；这是额外真实验证，不用对象复用或早期counter增量冒充结论。

v6（5a2e9ad）已真正通过入口READY/ingress-probe并进入checkpoint，随后在旧令牌401
之后的socket存活oracle失败。生产gatewayError明确发送Connection:close，Python读取
401后清空HTTPConnection.sock属于预期关闭，不应要求错误响应后的socket仍存活。
后续改为request实际发出后、读取响应前核对同一对象/dev/inode/端点，再严格要求401；
自动重连仍必须失败，401后关闭允许且正向控制覆盖该行为。不放宽身份、401、PID、writer
推进、资源回收或cold门槛。v6仍保留失败，原件及其一个代际/声明路径只读复核不存在；
必须由新scope完成其余流程，不把前序部分步骤补写成完整通过。


## v7有限组合实测与来源边界

`d5f3c2e`硬件runner退出0且原PID已不存在；真实Go guard入口（诊断observer关闭），
两个原盘L1启动、ingress-probe/checkpoint/recover全部闭集字段typed true。实测包括：
三个预检负例、双租户四个同时真实KVM、Stop与durable GC区分、slot干净复用、独立入口
stop/restart时原writer继续、revision2 key/leaf热轮换、原TLS连接旧令牌401、daemon SIGKILL
触发BindsTo关闭入口、manager清场、同策略重启与原盘冷恢复、旧创建key410、四project归零。
401响应按设计关闭旧TLS；同socket/dev/inode/端点在实际发送后、读取响应前核对，仍拒绝
自动重连。轮换前后gateway/daemon incarnation相同，并重新采样同execution RUNNING和进度。

硬件冻结源Go目录与原生构建源`269799f`逐字相同；实际复用已校验12产物，不冒充重新构建。
该原生源通过Go1.27.3 Linux完整race(count3)/vet、host fixture与helper race/vet、quota filter，
164项Python零skip；12原生/交叉产物一致。后续仅Python/doc修订，v7另跑166项Python零skip。
普通daemon `5bfb2394…`、gateway `41e97356…`、launcher `8f612a9d…`保持原字节；
ingress guard为`3da0c06a…`、helper为`5b044e26…`、outer fixture为`bac82851…`。
旧2GiB primitive/8GiB普通UDS回归各两启动，仍绑定原source62d，不给新source重贴报告。

独立只读审计核对root600/单链接/NOFOLLOW原receipt和冻结路径构造：v7两个外层代际、
所有声明路径消失，无补充清理。随后全局再核对本系列8 scopes/11个全局唯一外层代际/
35个唯一声明路径全部不存在；包括前序失败和诊断scope，不把它们记成通过。
v5编排在exclusive-create之前未创建L1，不计为第九scope。另一次私有派生元数据索引误写
已明确记录：v5 payload原字节移回v5索引，v4派生索引从原件重建，v4所有原始测量摘要
重新核对未变；不是原始元数据字节恢复声明，不改测量来源或失败结论。

离线语义门禁额外拒绝缺cold、整数冒充bool、未知flag、缺asset、新旧source重贴、
虚报production及partial-pass共7个负例。有限成功不抹去之前失败，也不解释旧CI退出根因。
当前仍没有自动WantedBy/readiness安装编排、catalog、升级回滚/备份、人类operator、长时
饱和/审计保留或SLO证明；配置与manifest为可信root分两次写入，未宣称原子发布。
