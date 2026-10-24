# systemd 部署契约（Go启动器已实现，完整部署未验收）

新增[实验性 Go 启动器](GO_LAUNCHER.md)，真实 systemd/普通认证 UDS→KVM 与原盘恢复的
有限验证已通过；当前仍没有可按生产部署的 systemd unit/安装器。不能把样例 unit、静态 lint 或已有自定义
PID1 的 owned-L1 KVM 试验当成独立 systemd 操作员安装/恢复通过。

## 已确认的接口冲突

`internal/firecracker/node_linux.go` 的 schema3 只接受 node root 下 `control` 与 `instances`；
controller 必须位于 control，root/instances 不带进程，预算及 memory/pids/cpu/io 委派严格读回。
增加未知 `.control` 不是无害变化，会被拒绝；也不能为安装方便放行未归属 helper。

systemd 的 `DelegateSubgroup=control` 从 254 提供，可把主进程放入指定子组；但附加
ExecReload/ExecStartPost/ExecStop/Post 等控制进程采用 `.control`，不是同一个预算组。
来源：[resource-control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)、
[cgroup delegation](https://systemd.io/CGROUP_DELEGATION/)。
所以不能直接套上带 ExecStartPre/ExecReload 清理脚本的常见模板。

## TLS入口的归属仍是部署职责

当前 `gateway.Config` 没有NodeRoot/cgroup字段，`gateway.RunRoot`也不自行检查或迁移到
node/control。已有TLS fixture独立核对的NodeControl出生归属，是**那个冻结部署形态的实测**，
不是gateway库对任意启动方式的保证。Go launcher v1只同PID exec普通daemon，不启动gateway。

因此不能把另一个普通systemd unit直接加入，就宣称仍落在同一NodePolicy预算内；也不能
让长期运行的ExecStartPost/Reload绕过严格node库存。后续须明确选择受监督的同域组合，或
有独立限制且计入总体预留/包络的ingress域，并实际验证生命周期、预算和失败关闭。
选择或文档不是已实现的安装/恢复结果；当前没有通过这项完整组合部署门槛。

## 已选择的层级与实现边界

后续[真实 systemd L1 地基](SYSTEMD_HOST_FIXTURE.md)已完成独立 operator、实际 `.control`
reload、严格 node 库存、stop/start 与原盘第二次启动。选择与 OPERATIONS.md 一致的
**unit root 下再嵌套 node/control、node/instances**，不再把 NodeRoot 直接等同 service root。
这是对前序单一 ExecStart/unit-root 候选的明确取舍，不代表生产安装器已实现。

1. systemd 管理专用 unit root 的父预算；Go launcher 从 `DelegateSubgroup=bootstrap`
   开始，在自身 unit 的委派子树中建立/验证 node/control、node/instances，精确读回预算，
   只移动自身到 node/control 后 exec 普通 daemon。helper 的 `.control` 留在 node 外且受
   unit 父预算；其生产并发/独立预算仍需验收，不因嵌套而免除资源归属。
2. manager 与 launcher 各有单一 writer 范围。使用既有 operator config 验证器，不复制一套
   可漂移的准入规则；state/runtime 保持已验收的同 ext4、quota、backing queue 与短 socket 路径要求。
3. 明确 jailer 所需 capabilities；必须排除可绕过 project quota 的 CAP_SYS_RESOURCE。
   不盲目添加会破坏 KVM/jailer/namespace 的 hardening，也不声称 root 任意 capability 都安全。
4. 父/子 memory、swap、pids、CPU、IO 限制逐项读回。用精确数字避免不同资源单位混淆；
   systemd IO 后缀 K/M/G 为十进制，见上方 resource-control 文档。
5. `KillMode=mixed` 先向 main 发送 TERM、随后向残余进程组发送 KILL，
   见[systemd.kill](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html)。
   结合本项目既有 filesystem D 实验，不能据此推断任意存储卡死都能限时完整回收。
   Type=exec 也不等于真实后端 READY；readiness、drain、恢复必须另验。

验收必须在自己拥有的、真正运行 systemd 的 L1 中完成：干净安装/重启、委派与预算读回、
真实 TLS→KVM、busy drain、主进程崩溃、service kill、原盘 cold/旧键拒绝、新 guest 执行、
密钥权限与独立操作员复现，以及升级/回滚/备份恢复。不得改共享 L0 unit、内核、挂载或 quota
来让测试通过。启动器已落实固定清单、同PID exec 与嵌套预算；其余验收仍未完成，不改变[生产状态](PRODUCTION.md)。
