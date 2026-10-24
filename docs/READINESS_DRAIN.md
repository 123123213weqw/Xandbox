# 持久 drain 下的自动启动（新增验证代码，实机待验）

[9e4da26 的自动 readiness 组合](SERVICE_READINESS.md)只做了 admission_open 两种布尔值的
纯解析控制，没有用真实节点证明持久 drain 在自动重启/原盘开机后仍保留。本项补该缺口，
不修改生产 Go 程序、13个产物、资源规格或既有失败关闭条件，不将旧结果改贴到新源码。

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

## 待执行的完整流程

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

上述是新增代码与验收门槛，不是已经通过的实机结果。仍不等于生产安装事务、catalog、
升级回滚/备份、可靠审计/长期元数据治理、人类operator、饱和负载或停止/回收/切换SLO通过。
