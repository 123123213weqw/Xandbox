# 5bfb：live trace/压力/取消与十个命名边界

**12个全新scope有限验收通过，不是完整生产/Goal完成。** 冻结源7fc305d，普通daemon仍为
`5bfb2394…`，新TEST fixture `320109a4…`；九个其他产物与前批逐字节相同。
[原始来源与脱敏结果](validation/fiveb-boundaries-v1.json)保留每份原始报告的源/摘要，
不借用d163旧报告，不把前一批[25运行scope](FIVEB_RUNTIME.md)改名成这些新场景。

## 两个独立的真实 trace/压力 scope

1. schema3 snapshot、inode/字节压力及低free原盘cold。实际固定九个instruction-entry probes，
   新5bfb全ELF、symbol、完整指令字节校验后注册，捕获12条normalized转换，核对两个真实
   创建与迁移goroutine的许可轨迹。所有8个CPU loss counters为0，九个probe hit与事件一致，
   只观察owned L1中精确daemon的start/inode/control身份；不在共享L0追踪。
2. 原始排队取消与另一个workspace WRITE仍暂停时的独立Stop/GC：实际15条转换确认取消者
   不取token；keeper真实执行域停止、持久私有回收/project quota0发生在放行另一个固定16MiB
   copy之前。随后原始holder/survivor请求真正KVM READY，guest启动身份不同、工作区干净，
   最终四个project/pins/池均清零，再执行本scope的压力/健康原盘cold检查。

本次N=1观测：keeper执行域空约37.078ms，
持久回收约173.697ms；暂停WRITE放行观测为
248.571ms。停止/回收在它之前，不是靠放行copy才完成。
这些包含observer开销，不是精确channel线性化、p99/公平性或生产SLO。
notification等待不是filesystem D，单次fallocate压力也不是全RAM/OOM、任意介质故障或安全擦除。
12条entry calibration本身不替代15条取消/独立清理证明，两种断言来源分别保留。

## 十个全新命名边界

| scope | 关键范围 |
|---|---|
| owner | owner unlink可见但目录fsync未返回的原盘恢复，keeper/pins与旧key拒绝 |
| inflight | 未主动同步的16MiB部分workspace复制，cold子集核账与普通回收 |
| operator | 原始busy drain/resume/CAS与原盘状态恢复 |
| shutdown | 真实控制关闭超时、未完成提交跨actual EXIT_GROUP与状态锁 |
| ticket | 已取原始frontend ticket在持久写入前跨drain，非发起新请求替代 |
| control-pre/post | admission控制状态两类实际持久化窗口与cold恢复 |
| TLS-pre/post | policy pre-file/post-commit窗口、入口watchdog与普通guest存活 |
| TLS | 实际TLS1.3双租户→KVM、key/leaf轮换、无效reload关闭、原盘cold |

每scope两次L1启动，总12scopes/24个外层代际；独立只读原始receipt与冻结路径构造复核全部
声明root/control/parent/generation不存在，无补充资源清理。再对本批和25运行scope的新旧
原件做全局复核：**37 scopes / 67个不重复嵌套代际 / 4个owned loop绑定**均消失；两个runner
均终态0并已退出，原始receipt摘要未变。不是全机进程清单或绝对escape证明。

## 剩余部署门槛不合并

本批仍是自定义PID1的owned-L1 fixture，不是实际systemd TLS安装/升级/备份或独立人类
操作员验收。先前真实systemd Go launcher只有单独的普通认证UDS子门槛，来源不换标签。
gateway程序本身不检查NodeControl出生归属，当前实测归属由这个fixture独立核对；后续
生产组合必须落实[独立预算与归属契约](DEPLOYMENT_CONSTRAINTS.md)，不能凭文档或另一
unit的存在就算通过。PKI分发、持久审计/保留、节点饱和/open-loop/长期SLO等仍属
[完整生产门槛](PRODUCTION.md)。原始console、credential、receipt及运行态身份始终私有。
