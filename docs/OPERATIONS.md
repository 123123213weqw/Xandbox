# 单节点部署与恢复契约（尚未独立操作员验收）

**当前没有受支持的生产发布。** 本页描述当前实现所需的操作员边界与验收步骤，不是已经测试过的发行版安装器、systemd unit 或自动恢复程序。Linux/KVM 的有限实验通过不等于本页全部部署门槛通过。不要将带占位符的示意图当作可直接安装的配置。

## 1. 发布物与节点清单

每次部署先冻结一份私有节点清单，至少包含：源码提交、构建工具链/GOOS/GOARCH/CGO/build flags、daemon/admin/warden/Firecracker/jailer/kernel/initrd/空白workspace的SHA-256、快照manifest与HostABI（如启用）、安装路径及其owner/mode、ext4 UUID与实际IO queue、独占UID/projectID区间、cgroup委派根/节点根/CPU affinity、完整NodePolicy和frontend限制、auth配置摘要与备份策略。

- 安装路径及父目录必须可信root所有、不可被group/other写入、不经symlink。state/runtime/config/资产不能从开发者可写目录直接提供给root服务；state和管理socket保持0700/0600。
- schema3要求quota+IO+NodePolicy完整，`-max-instances/-max-records/-max-sessions`与Node声明完全相同。创建、排队准备及未完成回收都计入容量；tombstone/closed sessions也占累计预算。旧schema1/2“降低预算仍可恢复”的兼容语义不能用来更改schema3绑定。
- state/runtime必须在同一直接quota ext4文件系统。磁盘规则是保守准入，不是整个节点的project硬配额；外部资产、builder export、日志及备份必须有独立可执行的空间/保留边界，不能从服务的private配额中推导。
- 保留原始令牌在独立客户端私有文件；服务端只安装digest配置。不得经命令行、环境转储、CI artifact或公开issue分发秘密。
- 当前guest无业务NIC、API只监听私有UDS；这不是可直接公网接入的云网关。公网TLS/身份代理/请求限流/凭证分发与撤销必须另设计、测试，不能用转发root socket替代。

清单只是操作员输入，不授权自动重绑资产、路径或UID区间。当前无在线binding迁移；不要删除`firecracker/config.json`、owners、catalog index、账本或锁文件来让新配置“启动成功”。

## 2. cgroup管理器：不要直接套一个常见unit

内核限制沿祖先生效，较小的祖先边界不能由子树放宽；启用domain资源分配还受内部节点无进程规则约束。[Linux cgroup-v2文档](https://docs.kernel.org/admin-guide/cgroup-v2.html)说明这些内核契约。

systemd与服务各自管理不同层级：系统管理器拥有委派点及其祖先，服务管理其下的私有子树。`Delegate=`不等于子树控制器已全部启用；必须核验实际`cgroup.subtree_control`。[systemd委派说明](https://systemd.io/CGROUP_DELEGATION/)同时要求避免多个写者竞争同一层级。

**schema3 NodeRoot不是任意service cgroup的别名。** 当前代码只允许NodeRoot直属目录`control`和`instances`。systemd的某些Exec*辅助命令会在委派service根创建`.control`；`DelegateSubgroup=`也只接收单个名称而非路径，不能写`node/control`。它从systemd254提供，且不替代辅助命令的`.control`行为。[systemd资源控制手册](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#DelegateSubgroup=)描述了这一差异。

一种待实机验收的层级契约是把**节点根再嵌套一层**，而非放宽驱动的未知子树拒绝：

```text
系统管理器拥有：.../<operator-unit>.service       # 委派点；实际名字由节点清单确认
├── <bootstrap-leaf>                            # 可信启动辅助进程的初始位置
├── .control                                    # 管理器可能创建；不在NodeRoot内
└── node                                        # 配置中的 Node.CgroupRoot
    ├── control                                 # daemon及catalog publisher真实所在位置
    └── instances                               # Config.CgroupRoot
        └── <ID+generation>                     # driver独占管理，VMM/warden出生即进入
```

schema3的catalog管理命令（包括status/gc，不只是publish）也会打开并核验节点包络；从普通SSH/root shell直接运行，不会因是root就免除control位置检查。管理命令需由受信任启动器在同一`node/control`中运行，不能靠更改配置或临时放宽NodeRoot绕过。

操作员的单一、可信启动器需要在准入前完成自己的子树准备与读回，并只将**自身**放入`node/control`后exec daemon。它不能先启动VM再搬PID，不能移动或清理其他服务进程，也不能根据名字猜测遗留资源归属。自动启动器及上述systemd布局**尚未发布/验收**；现有节点实验由独占L1的PID1准备，不证明systemd集成已通过。

检查至少覆盖：

1. `/proc/self/cgroup`确认实际controller/publisher位置；NodeRoot和instances直属无进程，均为cgroup2 domain。
2. NodeRoot及instances启用memory/pids/cpu/io；祖先可用控制器、memory/pids/CPU限制及实际affinity足够。
3. NodeRoot的memory.max/swap0/pids.max/cpu.max/io.max，以及control的memory.max/swap0/pids.max/oom.group与immutable策略精确一致。
4. 目录owner/inode/路径可信、没有未知节点子树；同一节点只有一个controller state-lock持有者。成功创建空目录不证明旧VM已经停止。
5. quota启用时控制器没有CAP_SYS_RESOURCE绕过能力，VMM继承真实quota/project变更过滤器；不能只测普通uid写盘，见[项目quota边界](PROJECT_QUOTA.md)。

不要照抄通用unit的`PrivateDevices`、user namespace、只读cgroup或系统调用allowlist；它们可能移除KVM/clone3/newnet/IO/quota所需能力。反过来，不应因启动失败就无限扩大能力、取消VMM seccomp、放宽UID/路径检查或回退宿主执行。最终unit的准确权限、辅助进程位置、重启/停止行为和升级流程必须在独占节点上逐项验收。

## 3. 首次启动、变更和健康确认

1. 在空的专属节点环境建立并核验清单；不在共享开发宿主试填磁盘、改挂载/route、卸载module或创建不明device-mapper目标。
2. 确认无已有绑定/owners/资源；如果有，先按原配置恢复，而不是当成首次安装覆盖。
3. 用准确frontend计数、auth文件和后端配置启动。服务管理器的“进程已exec”不等于API就绪；`/healthz`也不能代替KVM执行验收。
4. 用所属租户凭证创建新实例，核验真实guest UID/boot、执行/数据边界、跨租户404、配额、超时/TTL；命令只能在guest执行。然后独立检查撤权、host停止、持久DESTROYED与完整资源回收。
5. 同节点执行SIGKILL/暂停/重启与quota/IO/容量拒绝测试；确认未知资源导致拒绝而非adopt/delete。再进行负载和完整部署验收。不能因一次Create成功就启用生产租户。

重启不是无损reload：当前普通daemon会栅栏并回收旧代和会话，不恢复已分配guest。auth配置不热更新；计划的凭证轮换必须包含旧代终止/恢复和客户端切换窗口。预算、路径、资产或schema修改还可能触发不可重绑拒绝，见[NodePolicy](NODE_BUDGET.md)、[账本](LEDGER.md)、[鉴权](AUTH.md)。

## 4. 观测与故障处置

私有metrics socket只供受信任的同宿主UID管理域使用，不授予租户访问；不要chmod开放目录以便collector抓取。指标是非事务快照/进程计数，不是可靠审计或停止证书，见[指标口径](OBSERVABILITY.md)。

| 现象 | 当前应保留的事实与动作 | 不应推断/绕过 |
|---|---|---|
| 第N+1实例503、tenant429 | 查看allocated与仍在回收的代、累计records/sessions及两个池；区分实例与历史预算 | STOPPED不释放容量；不要删tombstone来临时扩容 |
| Prepare因节点预算/策略漂移拒绝 | 停止新准入，检查精确策略、真实祖先/affinity、statfs及外部写入；恢复操作员原声明 | 不能增大limit假装原绑定未变；现有Stop/Cleanup不等待prepare permit |
| ENOSPC/EROFS/EIO、DELETE500或长期RECLAIMING | 分开观察撤权与host execution domain；容量保持占用，恢复存储后让原配置普通daemon幂等回收 | 请求失败不是执行还活着；执行停止也不是持久DESTROYED；q0不是owner/pin已释放 |
| cgroup不空或持久化调用仍未返回 | 保留精确Ref/owner/本节点执行域证明及私有诊断，控制新的准入；按自己的归属处置 | 不按旧PID/UID批量kill，不根据API状态独自确认物理停止，不并开第二controller |
| 未知owner/cgroup/jail/project、绑定不符 | 拒绝并人工对照不可变清单/备份与运行态；保持拒绝的证据 | 不删除绑定、强制adopt或对整个project范围清零 |
| collector失联/指标重置 | 检查独立管理面与进程生命周期；保存外部时间线 | 不能以指标归零宣布VM停止/销毁，不能把重试计数当唯一实例数 |

目前没有已验收的在线drain API、审计日志持久化、自动告警闭环、日志/export轮换或外部存储失效接管。这些是待实现的发布门槛，不要在runbook中填写不存在的命令。受信任入口停止新准入的操作也必须纳入最终部署/鉴权验收，不能假设metrics能撤权。

## 5. 备份、升级、回滚及独立验收门槛

当前没有受支持的backup/restore/rollback工具。仅复制ledger目录不能构成可恢复备份：还涉及session幂等历史、owner/配置绑定、catalog/pins/backing、UID/projectID、内核执行域、资产与HostABI，跨文件也没有通用在线一致性快照承诺。原子单文件替换不等于多文件一致备份。

恢复旧备份可能遗忘备份后创建的代或旧key；不能以“都显示DESTROYED”或“目标目录为空”证明真实执行域和配额不存在。最终协议必须规定停准入、停止/回收证明、一致性切点、摘要与保密、回滚后的幂等/代际栅栏和未知资源拒绝，并在真实节点注入中断验收。不得把备份当成复活已分配guest或绕过immutable binding的办法。

独立操作员验收至少需要产出：

- 精确部署/工具链/资产/配置与权限清单；部署管理器版本、真实cgroup布局与所有辅助进程位置。
- 新装、错误参数/缺能力/限额/磁盘条件拒绝，以及未知资源不adopt/不删除。
- 开始准入、停止准入、正常退出/故障重启、恢复与凭证轮换的可复现演练。
- 持久备份/恢复、升级/回滚、日志/export保留、告警触发与操作员处理闭环的真实失败/成功证据。
- 快速切换、旧执行停止、持久回收分别定义起止点、样本与资源曲线；开放到达/公平性/长期压力和故障尾部，不把同机N1或closed-loop百分位当SLO。

这些证据尚未齐备，因此本页没有勾选完整M1–M4、操作员验收或生产发布。新的DEFAULT/quota240报告只证明其冻结源码与有限工作负载，不会自动完成这些发布门槛。
