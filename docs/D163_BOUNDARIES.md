# d163 / 41e9：十个命名边界的有限复验

**十个明确场景通过，不是全部故障、完整生产验收或 Goal 完成。**
[固定脱敏摘要](validation/d163-boundaries-v3.json)保留原始报告名、source、fixture、
报告及归档摘要；不公开 raw receipt、console、运行态身份或凭证。

| 原始来源 | 场景 | 合格 L1 启动 |
|---|---|---:|
| b462946 / fixture98ae | owner unlink、inflight partial-copy、operator、shutdown、session ticket、control pre/post | 14 |
| ecfe5b3 / fixtureb02 | TLS policy pre/post、健康 TLS + metadata | 6 |

普通 daemon d163、gateway41e9 及其余六个普通产物在两冻结源下逐字节相同。
fixture 的 hash 不同，原始报告保持各自源绑定：这是 7+3 组合，不是同一次 runner 执行。
当前 harness 的十项具名 validator 对各自原件重新执行，另核对 source/helper/ELF 摘要、
typed booleans、启动数与原始检查行。发布器实际拒绝 50 个来源/状态/fixture/缺失/多余变体。

独立只读复核覆盖十个成功 scope 的 20 个唯一外层执行代际，以及前序失败 scope 的
另一个代际：声明的 root/control/parent/cgroup 不存在，三个 runner 均不存在，
没有事后补充清理。它不是全机进程清单或绝对逃逸证明；live guest/quota/pin 等性质
仍来自各原始实验内的检查，不能从最终删盘倒推。

## 失败前序保留

- 首批 TLS pre 在目标 hold 前因 fixture 仍固定旧555b gateway 而拒绝；post/healthy
  当时未开始。目标 gateway 的源码树不变，修正精确 ELF pin 后，TLS 三组实际重跑六次启动。
  原始失败归档未覆盖或改成 success。
- b2 push CI 的 fixture 单测错误地要求 UTC 时间严格递增。修正只影响测试：
  先 drain 并经普通 New 打开静止 CLOSED 基线，再验证 Close 的原子 inode 替换；
  不 sleep、不放宽预算、不加生产 hook。原生 race 1000 次基线、fixture10次、
  全量 race3/vet 和 Python116项零skip另通过。失败日志摘要保留在摘要中。

冻结 ecfe 源当时 push/PR CI 各5个 job 通过，运行链接也保留于摘要；它们不是任何后续提交
的 CI 证明。后续新增秘密扫描 job 的当前结果单独核对。

## 边界

这里只完成十个指定场景，及[DEFAULT/IO/quota240矩阵](D163_RUNTIME.md)之外的对应复验。
TEST 通知持有 syscall 不等于真实 filesystem D；注入错误不等于物理介质失效。
独立 systemd 安装/恢复、可靠租户审计与背压、PKI 分发、全局 RAM/CPU/磁盘饱和、
open-loop 公平性/长期 SLO、保留归档、备份升级回滚仍未完成。
