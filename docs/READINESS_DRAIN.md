# 持久 drain 下的自动启动（有限实机通过）

[9e4da26 的自动 readiness 组合](SERVICE_READINESS.md)只做了 admission_open 两种布尔值的
纯解析控制，没有用真实节点证明持久 drain 在自动重启/原盘开机后仍保留。本项补该缺口，
不修改生产 Go 程序、13个产物、资源规格或既有失败关闭条件，不将旧结果改贴到新源码。

冻结源 `e9c80691ffe2623636d1e41e236f31c68f64a461` 已取得真实两启动实证；
[脱敏摘要](validation/readiness-drain-v1.json)绑定源码归档、14个harness、13个复用产物及原报告摘要。
Go目录与 `9e4da26` 原生源逐字相同，13个现有ELF已逐项核对原摘要、未重编译或改贴来源；
新增代码在Linux原生通过197项Python、零skip。这不是新的生产程序认证或完整生产验收。

当前 `--readiness-assets` 的闭集流程增加**必须执行**的 drain 检查，而非另开一个更容易
通过的简化profile。新 `systemd_drain_probe.py` 及专用owned-L1 marker纳入镜像与source摘要；
仍是固定16GiB/CPU12/24GiB盘、18GiB外层硬组、无NIC/15分钟租约，不改共享L0状态。

## 明确区分服务可用与新建准入

- 只有原固定、摘要匹配的 `xandbox-node` 私有CLI能够执行 status/drain/resume。
  使用刚读取的epoch/revision与固定长度request ID；确认成功后再做exact retry对照。
  不用租户token、TCP管理接口、配置重写或隐式resume改变节点状态。
- 比较完整 committed 状态（epoch/revision/mode/最后request与expected revision），而不只
  比较一个 admission_open 布尔值。重启不应无故换epoch或推进revision。
- drain时 `/healthz` 仍可经真正TLS响应；`/readyz` 与新raw/session/switch准入必须503，
  且错误码为 `NODE_DRAINING`，不能拿node full或其他503冒充。租户管理路径仍在gateway拒绝。
- 拒绝请求不新增ledger record或改变既有session历史；旧guest/session执行继续，物理Stop、
  durable DELETE、真实资源/quota回收不应被drain阻断。session revoke仍不是durable GC ACK。

## 本次实际通过的完整流程

1. 经TLS创建真实session/guest并启动计数writer。root提交drain并exact retry，验证同一writer
   继续RUNNING且新采样推进；已有session exec有效，新raw/session/switch均拒绝且不长元数据。
2. 在drain状态物理Stop与完整GC该guest，正常停止daemon并等待manager移除两个组和inputs；
   只start daemon，由enable/After/readiness自动带起ingress，不再operator等待UDS或start入口。
3. 完整drain committed状态不变、旧CAS resume被拒；只有明确root resume使revision增加一次。
   使用先前被拒的raw key启动新真实、干净guest并回收。
4. 原有四并行真实KVM、入口轮换、原TLS旧key撤权、崩溃/恢复等闭集检查不删除；保存原盘
   健康checkpoint时，额外保存原writer execution ID，再提交持久drain并验证它仍推进/RUNNING。
5. 原盘第二次开机，两个服务由enable关系启动，operator不发start或resume；probe先验证
   原drain committed状态、健康可用但准入仍关闭。旧guest已回收、精确quota为0时仍保持drain。
6. root旧CAS与租户管理请求仍拒绝；明确root resume +exact retry后，使用被拒的raw/session
   key分别获得真实新guest、检查旧cold-marker不存在，再按原流程完成最终回收/manager stop。

所有guest任务仍通过原TLS→gateway→普通guest API→KVM执行，CLI仅操作可信节点管理面；
不存在宿主任务执行回退。新增公开结果只接受闭集typed true，不导出控制request/epoch、
租户凭证、进程/guest身份或资源receipt。每份新原件还须独立只读复核本次代际/声明路径消失，
不以operator补充rmdir冒充manager/driver回收。

实际runner退出0、两次真实启动的probe/checkpoint/recover均为闭集typed true。独立只读核验
本scope两个唯一外层代际与全部声明路径均不存在；原root600/单链接/NOFOLLOW receipt保留，
未做operator补充清理。随后含历史失败的11 scopes、16个全局唯一外层代际、49个唯一声明
路径再次只读确认不存在；清理成功不把历史失败变成通过，VM前编排失败也不算scope。

离线语义门禁实际拒绝13类负例：缺boot2、整数冒充bool、缺ready pin、未知harness、旧手动
启动flag、source重贴、虚报生产、partial failure、缺drain断言、私有控制身份混入、缺新增
source、缺managed拒绝断言，以及误用修正前source。不是只依据runner的passed字段采信。

本项仍不等于生产安装事务、catalog、升级回滚/备份、可靠审计/长期元数据治理、人类operator、
饱和负载或停止/回收/切换SLO通过，也没有新增物理介质/未ACK提交窗口的证明。

## 保留的失败前序与验证路径修正

首个编排脚本在创建任何L1之前，用非root身份重复读取root-private workspace摘要而被拒。
未改资产权限或共享L0设置；保留失败脚本/原件，后续只复制清单，由原有sudo KVM parser在
任何L1创建前逐项验证13个角色/摘要。该编排失败不是一个额外KVM scope。

`a8ccb5a`首个真正L1在warm session检查失败：测试复用了plain sandbox exec来验证managed
session目标，得到正确的409。生产 `sandbox.Admission` 能力要求session目标只能经带版本的
session exec；这不是服务没启动，更不能放开plain exec。该失败原件及其一个外层代际/
全部声明路径的独立只读回收复核保留，不回写为通过。

后续只修测试路径：相同guest UID/boot、精确VMM/caps/seccomp/quota仍全部核对，但session
任务改经原session API，核对响应revision和实际Ref；在真实guest验证前后都要求plain exec
409/NOT_READY。writer、计数和workspace工具同样保留版本路径，不做全局路由替换或host fallback。
旧CAS拒绝还要求CLI实际409/CONFLICT，而非把任意非零退出算成CAS成功负例。

另补TEST ONLY错误帧：完整私有诊断后立即返回固定ok=false，使L0按原失败门禁清理，不再
等串口请求210秒超时；避免重复诊断，不改变任务停止/回收或任何成功断言。离线collector
最初误指资产清单文件名也单独留档，仅按失败脚本的实际文件名修正，无原始测量改写或重跑。

后续 `e9c8069` 的新原件已按以上完整流程通过；首个失败报告、现场诊断与独立清理摘要
保持原值，不用后来的成功回写失败。此前diagnostics CI退出1的精确原因仍未知，
本项不解释或宣称修复该历史故障，见[原记录](SERVICE_READINESS.md#ca500d3-的实际-ci-失败不是-readiness-根因证明)。
