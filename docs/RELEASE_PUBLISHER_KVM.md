# 普通发布 CLI 与既有服务的 L1 组合（新增验证代码，实机待验）

[发布物仓库](RELEASE_STORE.md)已有Linux原生unit/测试进程中断证据，但还没有普通root CLI
在真实服务宿主中的执行证据。本项补这道门，不把它称为服务安装、升级/回滚、catalog或备份。

新增显式互斥 `--release-assets`，不是减掉既有检查的轻量profile。复用完整readiness/drain/
TLS→KVM流程，保持16GiB/CPU12/24GiB盘、18GiB外层硬组、无NIC/15分钟租约；固定资产15项、
harness16项。额外两项是普通publisher与template ELF，原13项部署资产不替换。所有Go源不变，
复用实际原生校验的publisher `fa3538fd…`，不重贴原生或旧硬件报告。

## 追加的闭集门槛

- 真实13角色资产：8个普通Go程序及Firecracker/jailer/kernel/initrd/128MiB workspace，而非
  微小伪文件。先逐项核对冻结摘要，复制到私有incoming目录，声明分别绑定9e4/0a51两个
  已实际构建且原有程序字节相同的来源，不编造新版本或把声明当签名认证。
- 普通CLI通过真实UID65534运行被拒且根目录不出现；root下真实symlink、hardlink与可写
  source父目录拒绝，不能生成意图、发布引用或artifact。健康空库存的status作为同输入对照。
- 每次提交实际启动4个独立CLI竞争同一expected revision，只有一个winner；核对实际引用
  绑定winner。只为已存在的operator预算设置Go runtime并发2，不增加cgroup/节点资源。
- 精确重试时将incoming原子移到仓库外，fsync父目录，原source路径确实不存在；旧CAS与
  rebound请求拒绝，完整引用不变。未知根文件、**移到闭集仓库外的缺失bundle**均拒绝，
  程序不adopt/delete/recreate。fixture只恢复自己刚移走且inode相同的对象，不算程序GC。
- 第二份提交后两份完整13角色字节/0500或0400模式/私有元数据逐项核对；第三份拒绝且库存
  不增长。保留原main/gateway身份、完整节点准入提交以及同一个真实guest writer持续推进。
  新专项writer仍是原heartbeat命令，只使用既有协议声明的60秒上限；不放宽任何服务限制。
- 先完成原readiness/drain闭集检查再同步发布checkpoint；原盘第二次启动，在operator发出
  resume前验证两份bundle、完整引用及缺失source保持，普通CLI再次精确重试不推进revision，
  节点仍drained。之后才进入原明确root resume/旧guest回收/新guest与manager stop流程。

guest任务始终经普通TLS API→真实KVM。publisher只复制资产，没有host任务或自动服务切换。
新增结果只含闭集typed true；source路径、请求ID、引用、凭证、guest/进程/资源身份和完整
console保持私有。仍须独立只读核验本次全部外层代际与声明路径已消失，不能用补充清理冒充。

上述目前是代码和验收门槛，不是已经通过的实机结果。它不测试生产CLI的精确syscall中断/
介质故障窗口，也不完成完整安装事务、激活、升级/回滚/备份、可靠审计、饱和负载或SLO。

## 首轮失败与镜像权限修正（修正后实机仍待验）

`ed255f2`的首个L1在非root检查时失败：execve返回EACCES，CLI没有进入程序，不能冒充
程序UID门禁拒绝。原始报告及该外层代际/声明路径的独立只读无残留审计保留。

随后只读核对原pinned Ubuntu目录header均为0755，并在相同Python层复现：data_filter对
directory给出mode=None，private umask077下实际创建/usr为0700。旧builder的同条件纯控制
实际RED（0700!=0755）；这是组装层重构证据，不伪称首轮L1已采到/usr的实时stat。

只修新owned发布profile的非秘密/usr与/usr/libexec为真实root-owned、不可group/other写的
0755，配置目录仍0700，不改旧profile或共享L0。新增非root调用前实际逐层权限核对及私有
诊断；仍必须得到普通CLI的闭集拒绝，不能把exec失败算通过。生产Go、UID门禁、预算和
所有原有KVM断言均未改变；额外修正Python正则的raw字符串警告。

第二轮 `0c72605` 已越过普通非root CLI、source负例及两次实际CAS/完整库存验证，但在最终
旧guest执行检查得到409；整scope仍失败，不算发布组合通过。保留实际报告和独立1代际
无残留审计。当前原件没有该时刻的guest状态/计时，不能认定是60秒任务超时、TTL、OOM或
发布程序改变了guest。后续仅补私有闭集阶段elapsed/guest状态/执行状态采样，仍保留最终
同writer推进断言，不提高协议时限、扩大资源、削减真资产或将旧失败回写成通过。
