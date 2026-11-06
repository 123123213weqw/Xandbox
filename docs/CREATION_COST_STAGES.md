# 逐次创建阶段：默认关闭的诊断扩展候选

**不是性能修复或生产就绪。** 新 fixture 与实际 Go/Python 字节已另行完成限定
OFF / observe / maximum 的完整原健康流程、6 次真实 KVM 启动及 3 次原盘 cold；
186 组 fixture Go 用例在 CGO0 / race 下各 3 遍、424 项原生 Python 均无跳过。
[报告](validation/creation-cost-stages-functional-2026-10-30.json)明确限定来源，新提交 CI 单独核对。
先前 `ce47a8b` 的 schema3 三模式实测仅属于原字节，没有给本次扩展代签。
普通 daemon / warden / guest-agent 未修改，生产写回仍为 8 MiB。
不自动重跑已拒绝的 1 MiB 对照、原 40 分钟负载或其他性能比较。

## 为什么增加这一层，而不是再调写回窗口

现有 syscall 诊断观察范围还包括 Stop、GC、quota 与 fresh 操作，只有
CREATE 总时长，没有逐次 CREATE 的 kernel-clock 起止锚点；syscall 耗时
可能重叠且包含调度等待，不能从 HTTP 总时长中相减，称剩余部分为纯排队、
复制、磁盘或 GC 时间。一次合格但负收益的对照不应被重复到通过。

[第十二次原始负载失败](validation/kvm-open-arrival-attempt12-failed-2026-10-28.json)
中，open 与 switch 的“准入＋准备槽”复合时间各约占 HTTP 时长 87%。
它们包含锁、检查和等待，不能称纯排队；历史有限 actor 记录也不是全部
请求的随机样本，不能据此计算总体吞吐或延迟分位数。串行健康基线不证明
这次并发失败的原因。

本扩展复用普通服务已有的 [Server-Timing](CREATION_TIMING.md)，分别保留：

| 层 | 固定阶段 | 解释边界 |
| --- | --- | --- |
| core | admission、owner commit、driver、ready commit | 四个顺序阶段，不含全部 HTTP 工作 |
| driver | slot、owner、quota reserve、copy、quota verify、activation | 嵌套于 core driver；不得再与父阶段相加 |

slot 包含 permit 获取与节点复核；copy 不是纯物理磁盘时间；activation
包括 API 配置、启动、健康及 quota-domain 验证，而非纯 guest boot。
没有新 kernel-clock 锚点，仍不能把某组 syscall 配给某次 CREATE 的关键路径。

## 固定且不改变调用结果的读取

仍只允许显式 `--creation-cost-diagnostics observe|maximum` 的原健康
node-budget 流程，默认 OFF。只在原 `http.Do` 返回处读取固定
`POST /v1/sandboxes` 且原 `create()` 正在计时的原响应；不增加请求、重试、指标读取、身份查询或 IO。
原协议的 N+1 / pressure / replay 拒绝检查也使用该端点，但不是六次测量中的
CREATE，仍执行原调用与状态检查，不进入新向量。组件回归包含测量前后的
503 / 500 / 410；仅按端点匹配而不检查在途状态会错误污染诊断资格。
OFF 首先经过 nil gate，不检查响应头。原 context、状态码、Go 错误、body
读取与 READY 判定不变。解析发生在原 elapsed 范围内，是明确的观察变化，
不是零开销承诺；不能拿新旧工具版本差异宣称提速。

只接受一个至多 2048 字节的头、十项原顺序固定名称、每项调用数 1、有限
非负且至多 35001 ms 的值；不保存原头、自由标签、身份、key 或错误文本。
保存 `observed / not_observed / no_response / missing / invalid`，未知不是零。
重复或非在途捕获会污染诊断资格，不改变原 API 的 success 字段。

normal **schema4** 的每个 `http_create_elapsed` 行新增 `server_timing`。
成功诊断要求全部五次 checkpoint 与一次 cold-fresh 的十项观测完整。
已知嵌套的子阶段和父阶段、顶层阶段与客户端 envelope 做算术一致性检查，
保留独立 0.001 ms 四舍五入的 0.01 ms 容差；这不是共享时钟或物理停止证明。

失败 create 仍保存。失败诊断改为 **schema2**，继续使用原 private failure
前缀及原 4096 字节 payload 上限，五次十项记录无需扩大上限。意外越界显式报错，
不静默丢样本。该失败 payload 不是 normal 成功样本，新旧 inline failure 都拒绝验收。
normal 的既有 1 MiB / 512 帧、最大 2 MiB console、ABI schema1、固定事件、
主机导出期限和资源/持久化/回收门槛均不放宽。

离线分析器继续接受原 schema3，但明确返回阶段不可用；不合成零值或重写原件。
schema4 缺失、未知、重复、错序或不一致的向量拒绝作为成功诊断。
`maximum` 仍只追加 ASCII 空格到原 1 MiB 上限；不是写回窗口优化。

## 验收边界

生成式组件回归覆盖版本区分、完整/未知/坏头、原请求与错误、OFF nil gate、
算术界限、五次失败向量在原上限内无丢失、maximum 原前缀及失败帧拒绝。
这些测试不是实际响应、串口交付、KVM、长负载或生产收益证明。
新源必须分别绑定自己的软件、原生、CI 与受影响硬件资格后，才可更新相应声明；
现有原失败、原资源和收益门槛保留，不合并或部署候选。

先期一次 Linux CGO0 组件回归因新测试错误假设“五次向量必超过 4096 字节”而失败；
本地独立生成的同结构 payload 为 3591 字节，不是原失败时未保存的 payload 原件。
原源码、完整测试输出和失败状态均私有保留，未启动 KVM。
该失败不证明运行时丢数据；已纠正断言并撤回不必要的上限扩张。后续新源独立验收见上述报告，原失败不改判。

私有构建器的一次输出目录碰撞在源码提取前失败；一次本地独立审计变量遮蔽错误也已保留。
修复后只重新执行对应的软件构建或离线审计，没有重跑已启动的 KVM case。完整新 KVM 原件
51 项独立收回，全部帧与十二次被选 CREATE 的十项向量核对，并新鲜复核原盘 cold 与声明资源。
有限串行阶段观测不能推断原并发失败原因；所有 12 次原长测失败及其他生产门槛仍保留。
