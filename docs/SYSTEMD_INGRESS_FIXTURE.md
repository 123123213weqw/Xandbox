# 独立 systemd ingress/TLS owned-L1 fixture（代码已实现，实机尚未验收）

新增 opt-in TEST ONLY `systemd-ingress-v1`，专门运行普通 daemon +
[独立 ingress 启动器](INGRESS_LAUNCHER.md)，而非让自定义PID1 TLS结果冒充systemd组合。
当前文档只描述新增代码与待执行门槛；没有声明该组合已经通过。整体仍未生产就绪。

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

## 待执行的闭集流程

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
