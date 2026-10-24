# systemd 自动启动/readiness 组合（代码已实现，实机待验）

现有[独立入口有限实测](SYSTEMD_INGRESS_FIXTURE.md)需要可信 operator 先等 UDS 再启动入口。
新增 `cmd/xandbox-ready` / `internal/serviceready`，将这项启动闸门交给 systemd。
当前没有把该新组合记为实机通过，更不等于生产安装器、升级或完整生产就绪。

## 选择与边界

保留既有同 PID Go launcher → 普通 daemon 的执行契约，不引入后台 wrapper 或宿主任务。
新增候选 daemon unit 用 `Type=exec` + 固定 `ExecStartPost=xandbox-ready -manifest ...`；
独立 ingress 保留 `After/BindsTo/PartOf=daemon`，启用其 `WantedBy=daemon` 关系。
根据[systemd255 service 文档](https://www.freedesktop.org/software/systemd/man/255/systemd.service.html#ExecStartPre=)，
ExecStartPost 完成参与 After 排序，失败/超时使启动失败。只看到 exec 成功不再代表后端 READY。
[Install 本身不执行启用](https://www.freedesktop.org/software/systemd/man/255/systemd.unit.html)：
必须实际创建 enable 链接；这里的生成 API 不写入/启用共享宿主，也不是事务安装器。

`serviceready.Manifest.DaemonUnit` 从原 launch.Manifest 生成预算/固定入口/45秒启动与12秒
停止上限，拒绝路径注入和不能精确表示的 CPUQuota；不接受 shell、任意 argv、TCP 探测地址、
bearer token、恢复/准入变更或宿主执行 fallback。Helper CLI 只接受固定 manifest 参数。

## 闸门实际检查的代码路径

- root/systemd PID1、root-private NOFOLLOW manifest、helper 自身摘要及 NodeLaunch pin。
- helper 必须在自己 daemon unit 的 manager `.control`，且该组只有自身一个进程；不迁入 node。
- 在全部 Go 线程丢弃其他能力，保留精确 CAP_SYS_PTRACE permitted/effective/bounding、
  inheritable/ambient0 与 NNP1。它用于读取权限更高的普通 main 的 `/proc` 身份；没有提供
  ptrace/信号/exec/文件写入/控制组修改接口。CGO 外部线程不支持时失败关闭；真实 ELF 要求 CGO0。
- 只读检查原 backend composition 和 daemon 父内核预算；只连接该 manifest 的私有 UDS。
- 先取得 node/control 的单一 main 与 pidfd；连接 peer 必须 UID/GID0 且 PID 相同。
  请求前后核对 pinned daemon ELF、精确普通 argv、实际控制组与 pidfd 仍存活，拒绝旧进程/旁路。
- sealed backend/auth 快照摘要必须与原 pin 一致；健康 JSON 有界且严格解码，要求真正
  firecracker、isolation/authentication true、固定机制，未知/重复字段、mock、重定向拒绝。
  `admission_open=false` 仍可就绪，以免重启擅自解除持久 drain；production_ready=false
  是当前 API 的成熟度声明，不把 health 当成 KVM 或生产认证。
- 网络请求每次250ms、总体30秒，只对明确启动暂态/超时重试，语义错误立即失败。
  这些不是任意内核 D-state/文件系统 I/O 的硬时限；systemd 与外层租约仍需独立清场。

root/内核/固定程序仍是信任根；没有恶意 root 防护、跨 root 变更的原子路径保证或远程证明。
总体预算仍为显式核算，不是共同硬父组或 OS 实际容量/预留证明。

## 新 owned-L1 验证代码（待执行）

独立 `--readiness-assets` 选择器与旧 primitive/UDS/手动 ingress profile 互斥，复用已界定
16GiB/CPU12/24GiB盘、18GiB外层硬组、无NIC/15分钟lease，不扩大共享L0权限。
13个固定资产增加真实 ready ELF；fixture helper 仅在新专用 marker 下生成上述候选 unit。

计划实际检查：

1. 原三个 ingress 预检负例保留；另将 ready NodeLaunch pin 改错，要求启动失败、入口无TCP、
   manager 清除两个组与输入目录，之后才 reset-failed。
2. TEST ONLY 有界 `.control` gate 先暂停后置流程；真实普通 daemon UDS 已可用时入口仍不开放。
   冻结那个真实 MainPID，再释放 gate，让未修改的 ready 程序遇到真正无响应的后端并超时；
   观察其真实 `.control`/固定ELF/逐线程精确一项cap，要求 manager 清场而非 operator rmdir。
   不用 mock backend、伪造健康响应或自动重试未知故障冒充证据。
3. 恢复原生成 unit，只启动一次 daemon，观察被 enable 的 ingress 自动启动；复用真实
   TLS→四并行KVM/轮换/崩溃/回收闭集检查，daemon 重启后不再手动等UDS或启动ingress。
4. 健康同步原盘第二次开机，仅由 enable 链接启动两个服务；operator 不发送 start，验证
   原 unit/policy/链接持久、旧guest回收、新guest干净及正常stop。独立只读审计所有代际/路径。

纯控制、原生构建或新代码存在均不能代替上述实机证据。旧 d5f3c2e 报告保持原绑定；新增
helper 字节、自动启动流程与源码须单独冻结、原生/交叉比较并取得新原件。生产安装/升级回滚、
catalog、备份、人类operator、可靠审计、持续负载及各阶段延迟SLO仍另验。
