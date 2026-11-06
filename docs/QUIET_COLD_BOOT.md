# 安静冷启动控制台候选（不是已证实的延迟修复）

## 2026-10-28 当前证据：负载失败与一项 runtime 正例分开

当前4ddd的[第十二批原始负载](validation/kvm-open-arrival-attempt12-failed-2026-10-28.json)
在第22分钟、canary129/phase2的old_gc阶段耗尽原35秒actor；734行/133周期样本，
不是完整40分钟/100tail/SYNCEDcheckpoint/原盘cold。open与switch均已返回，fresh命令
结束仅余4.225ms；不能据old_gc标签断言GC很慢。该失败行EmptyMS即使错误也计elapsed，
StopReplyMS是switch响应别名，namespace/fullquota零值未观测；不构成物理Stop/回收证明。
基线/OOM各2启动有限通过、原负载批次60代际/36scope声明资源只读无残留不替代负载验收。

另有同一程序的[一项quota runtime复验](QUIET_RUNTIME_QUOTA.md)：6类errno/重复clear、
三个原盘cold检查点/4启动及独立19原件通过；包含此前批次64代际/37scope只读无残留。
这只完成原37具名矩阵之一，不完成剩余36项/systemd或完整生产Goal。软件/CI来源仍按
各自冻结源记录，不借用其他ELF；保留全部原参数、失败与公平性门槛，不合并、不部署。

代码 `6ea28eaf491f2863884db176af94936544620f37` 的普通 daemon 为
`4ddd4bea5ee252fd4b52a7132bfbab9723d76bbaa1941d4c341ce770e0802218`。
普通冷启动的 `/boot-source` 参数只增加一个 `quiet`：保留 `console=ttyS0`、
`reboot=k`、`panic=1`、`pci=off`、`rdinit=/sbin/init`、guest marker 及原 Ref 字段。
没有新增参数选择器、API 调用、worker、队列或调度政策；snapshot 分支不变。
这不是删除控制台，也不修改宿主的内核、服务或配置。

## 为什么测试这个候选，而不是宣称找到了根因

[原始第十一批](validation/kvm-open-arrival-attempt11-failed-2026-10-27.json)仍失败。
完成的 open 响应中 activation 约 2069ms，但该复合阶段包含 fork/jailer/API/
guest 启动与 health/quota 验证，**不是内核启动时间**。新活动观测也不标识某个
失败 actor；不能由此断言控制台、节点复核或纯排队是唯一原因。

原程序明确启用 guest serial console，而 host 已丢弃任务 stdout；丢弃 host
stdout 不等于请求 guest 少输出信息。[固定 Firecracker 1.17.0 FAQ](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/FAQ.md#firecracker-is-not-showing-any-output-on-the-console)
说明默认关闭 serial console 有启动性能方面的考虑，故对这个边界做可证伪的测试。
本候选只请求 quiet，仍保留 serial。上游[启动性能规格](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/SPECIFICATION.md)
使用指定 metal、最小系统、1 CPU/128MiB 且关闭 serial；本项目是 nested KVM、
2 CPU/512MiB，不能借用其 125ms 指标，更不能承诺本候选节省 2 秒。

## 验证范围

源码6ea的[有限软件机制证据](validation/quiet-console-mechanisms-2026-10-27.json)已逐文件绑定：
18项父测试（3 quiet +15 activity）各 race×100/CGO0×100、零skip；完整fixture153
各两构建×3、固定9点ELF检查生效且零skip；root Python312零skip、vet/mod通过。
5个CGO0原生工件等于新交叉构建，35份原始软件文件独立重验hash；旧HTTP/node
实际编译负例、旧活动接线及quiet物理源码负例各两构建×3明确失败。
这不是完整43包/24工件、新CI、真实KVM或延迟证明；不继承旧f286/DA42的验收结论。

三项 source guard 从实际 `driver.Prepare` 的 cold 分支、实际 `/boot-source` 表及
`apiPut` 参数连接读取表达式，拒绝不透明表达式，核对其余参数不变。它们不是
执行 guest 或性能测试；旧物理源码的负例也不是实际编译的旧 guest 启动反事实。
固定九点探针的 Go/Python whole-ELF pin 已离线配对到 4ddd，三个目标函数的
相对指令与旧 DA42 一致；这不是新程序的 live trace 证明。

上述早期有限报告不包含后续完整门槛。冻结e2bb已另完成全部软件/原生Linux/CI后运行原完整KVM三组；第十二批负载仍失败，见顶部新报告。
保持 N4/prepare1、35 秒 actor、40分钟/6360 raw/240 canary/100 tail、
SYNCED inventory/checkpoint、原盘 cold、配额/TTL/history、allowlist/FIFO/公平性
及全部资源边界不变。旧十一批失败均保留，不重跑未修改的失败 DA42 凑绿。
受影响 runtime/systemd/16MiB/18秒取消/quota/errno/cold 矩阵与完整生产 Goal 仍待完成。
不合并、不部署，不宣称生产就绪。
