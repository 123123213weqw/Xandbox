# 5bfb daemon 全量实机复验（进行中）

**本页不是25组运行矩阵、10组边界或完整生产验收通过声明。** 普通 daemon 从 d163 变为
`5bfb2394…`（信号注册顺序修正）后，不直接继承旧 ELF 的实机结果。
[Go launcher/真实systemd普通UDS子门槛](GO_LAUNCHER.md)已另有原始来源；本批补普通
程序的更广运行/故障矩阵，不能反过来把旧d163报告改名为新程序通过。

## 已实际完成的首个冷路径 scope

冻结 harness 源 **37a862a**，使用原生及交叉比对过的普通 daemon `5bfb2394…` 和同批固定
资产。首个普通DEFAULT冷路径scope已完成30项检查、5次新的guest切换闭环，以及两份Go
子测试报告各9条队列/会话展开断言；展开断言不额外计作18个独立场景。
真实旧binary/KVM账本导入保持drained，经显式CAS resume后才重新开放，不靠测试自动恢复准入。

[冷路径脱敏摘要](validation/fiveb-cold-prefix-v1.json)记录原始报告指纹、源与程序绑定。
独立只读读取root-owned0600、single-link、NOFOLLOW的原始receipt，匹配冻结harness路径
构造后确认该scope声明的root/runtime/noexec/alternate/cgroup均不存在；没有补充清理。
这只是**首个scope**，不是所有仍在运行的测试资源都已清空，也不是全机进程/escape证明。
五次闭环是有限冷路径观察，不冒充性能百分位、开放到达、公平性或生产SLO。

## 旧 ELF 探针重新校准：只读原生门禁已通过，live验证待完成

准备许可/取消的 TEST fixture 原来固定 d163 全ELF SHA与九条 instruction-entry位置。
新增只读 opt-in `TestPrepareProbePinnedOrdinaryELF`，不执行被读ELF、不挂载tracefs、
不注册probe、不绕过owned-L1 guard；未显式提供文件时CI会skip该项，不能将编译当硬件验收。

实际顺序保留如下：

1. 源 **191f024** 保留旧pin，对真实新5bfb ELF运行该原生测试，实际RED；原始日志与源归档保留。
2. 实际对新ELF执行Go1.27.3 linux/amd64 objdump，核对全部九个symbol/完整指令边界、opcode与寄存器。
   这次地址和指令字节恰好与旧表相同；这是实际核对结果，不是假设小改动不移动代码。
3. 源 **7fc305d** 只更新TEST目标pin及当前闭集结果验证器/合成测试，不修改历史测量。
   精确native ELF hash、symbol containment与九条指令验证实际PASS×3；同一新验证器又对真实
   旧d163 ELF实际RED。拒绝坏/旧pin，不把验证放宽到“任意64位摘要”。
4. 完整原生Go race×3、fixture race×3、两项vet、quota filter×3、全部152项Python（零skip）通过。
   十个Linux amd64产物native/cross逐项相同；新fixture `320109a4…`，其余九个产物与前批字节相同。
   普通daemon仍是5bfb，launcher仍是26f35a3d。

[只读校准脱敏证据](validation/fiveb-offline-probes-v1.json)明确 `live_trace_acceptance=false`。
它不是实际entry事件、取消线性化、压力下独立Stop/GC或并发公平性的证明。
当前源码的trace验证器只接受新pin；历史d163报告应使用自身冻结版本的验证器，不将其导入
当前源码后直接宣称再次验证通过。旧数据和原始程序指纹均不重写。

## 在执行但尚未验收的范围

已启动覆盖新5bfb全部25个命名scope的有限流水线：DEFAULT冷/快照、两租户各120次、初始化与
明确标记的历史TEST guest故障、IO、原盘cold、quota两租户各120次忙writer切换与各故障窗口、
ENOSPC/ledger EROFS四组；原来复用的7个cause scope也全部安排新执行，不沿用旧ELF结果。
只有已经拿到原件并校验的首scope写入上方摘要，其余不是既成结果。

后续独立runner以已确认的原runner身份和终态0为依赖，串行执行两个live trace/压力/取消
scope及十个owner/inflight/operator/shutdown/ticket/control/TLS边界。依赖失败或身份变化就
关闭，不通过超时自动复制旧任务；现在不声称这些场景通过。

完成后仍须核对全部原始来源/ELF/闭集数字与状态、独立只读资源和loop绑定消失，再更新结论。
原cv3工作盘/v10 initrd及历史TEST资产不覆盖、不通过共享L0服务/模块/挂载/quota/sysctl/网络
配置修改来让测试通过。所有raw console、receipt、凭证、boot/process/代际身份留在私有证据中。

即使这组兼容/故障矩阵最终通过，真正systemd TLS/catalog组合、安装升级/备份恢复、独立
操作员、长期审计/保留、资源饱和/open-loop及生产SLO仍是[完整Goal门槛](PRODUCTION.md)。
