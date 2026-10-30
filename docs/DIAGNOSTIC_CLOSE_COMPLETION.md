# 诊断 writer 完成结果优先（开发候选）

代码 `b3f9461b077ee99f1f926858be13a5af1926fbb8` 的普通 daemon 为 `896840d6d41066bb222d617f9a65cec463bc1a93918ae29e41eecd0e0028d768`。
改动只在 `diagnostics.Logger.Close` 已有同步完成边界上增加非阻塞检查：writer 已结束时
保留真实完成结果（包括 ErrWrite），不因调用方 context 同时取消而随机变成 ErrPending。
尚在阻塞的 writer 仍返回 ErrPending、保留描述符和状态所有权；不增加原250ms关闭预算，
不等待额外I/O，不改ring格式/队列/记录、业务准入、worker、TTL或请求路径。

## 原始失败与独立反例不能混为一谈

原[CI25 PR](https://github.com/123123213weqw/Xandbox/actions/runs/40716931860)的 Ubuntu/Go1.27
进程smoke在diagnostics第25次重启exit1；单独push成功不替代失败。取到的原日志显示本周期
service_mock/process_stopped/collector_closed，但可见header不是fsync或writer完成确认。
由冻结代码只能推断最终diagnostic关闭失败，原 ErrPending 还是 ErrWrite 仍未知。

另一个实际编译旧组件的反例证明了双ready select问题：writer早已结束时，已取消context
仍可让旧Close误报pending，甚至遮住已发布ErrWrite。它**不是原CI唯一原因的重建**。
不通过重跑原CI、延长250ms或吞掉非零退出修绿。

## 已取得的有限软件证据

[组件报告](validation/diagnostic-close-completion-mechanisms-2026-10-29.json)：Darwin和真实Linux
各完整21父测试×3、聚焦3父测试×100，均race/CGO0、零skip；包括旧真实ring阻塞/独占控制。
Linux旧组件clean/write-error负例各两构建×3明确失败；25份原始文件、5个工件独立验hash。
Linux新daemon与当前仓库独立交叉构建逐字节一致。组件进程过快，独立探测只在终态看到
runner PID；没有补造live start记录。原wrapper启动代际、独占输出及全部1224输入另有绑定。

额外的Darwin全包×100两构建均撞默认10分钟上限，原件保留、仍未完成，**不是通过**。
原完整包×3和选定机制×100不代替该额外压力结果，也不代替任何正式全程序门槛。

固定9点Go/Python whole-ELF pin已配对到8968；三个目标函数的相对汇编未变，九个精确
指令边界/寄存器角色核对。仍是固定entry probes，不增加任意selector、uretprobe或用户内存读；
node_ok仍在return前，不是函数返回。离线配对不是新程序live trace或硬件验收。

## 尚未验收

当前新程序仍需完整43包/24新原生工件、fixture/全部root Python、新CI与受影响硬件矩阵。
历史4ddd的[9项runtime/27次L1启动](validation/quiet-runtime-core-nine-2026-10-29.json)按冻结e2bb
保留，不为8968代签；包含此前共有91个实际外层代际/46个资源scope声明路径只读无残留，
不是46个通过的具名矩阵scope。该冻结程序只完成原37具名清单中的10项。

第十二批原完整负载仍失败，logger关闭分类修正没有证明改善open/switch服务成本。
不得只因ELF不同就重跑同一失败负载凑绿；需先取得可证伪的相关机制与全部原门槛。
40分钟/6360raw/240canary/100tail/35秒、资源/FIFO/公平性/allowlist及所有生产Goal保持原范围。
未合并、未部署；不能宣称生产就绪。
