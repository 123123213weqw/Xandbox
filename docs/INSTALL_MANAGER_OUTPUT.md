# 安装器的 manager 子进程输出上限

这是 `xandbox-install` 的一个范围明确的可靠性修正，不改变安装计划、固定
systemd 操作、权限、事务顺序、策略 epoch、资源预算或错误恢复授权。
它不添加命令、路径、unit、远程 host 或测试替换选项。

## 已复现的问题

旧主分支 `9e9915848a1a6937ea5df79daf01d21fd5bea0e0` 的输出 writer
匿名嵌入 `bytes.Buffer`，只重写 `Write`。这仍会提升 `ReadFrom` 方法。
`io.Copy` 可以选择该方法而不调用外层 `Write`；所以满足 `io.Writer` 的
编译期检查不证明所有复制路径都有大小上限。

保留旧生产源码，仅添加回归测试，在 Linux 普通用户环境用实际 Go 测试子进程
复现了 stdout/stderr 的 `os/exec` 复制旁路；固定合成输出最多 64 KiB。
这不是替换宿主 `/usr/bin/systemctl`、调用真实服务变更或制造宿主内存耗尽。
旧 stderr 非空仍会令命令失败；这里证明的是捕获量限制被绕过，
**不是证明任意命令执行、权限绕过或错误的安装成功回执**。

机制参考：[Go io.Copy](https://pkg.go.dev/io#Copy)、
[bytes.Buffer.ReadFrom](https://pkg.go.dev/bytes#Buffer.ReadFrom)、
[os/exec 输出复制](https://pkg.go.dev/os/exec#Cmd.Stdout)。

## 修正后的契约

- writer 只保存私有 byte slice，显式实现 `Write/Len/Bytes`；不暴露提升的
  `ReadFrom`、`WriteString` 或底层可扩容 buffer。
- stdout 最多保存 16,384 bytes，stderr 最多保存 4,096 bytes。
  单次写入超量时拒绝该次写入，不先保存超量部分；使用减法检查剩余量。
- 真实 manager 调用与测试共用同一私有捕获函数。超量、非空 stderr、非零退出
  或取消返回闭集 `ErrPlatform` 且不返回部分输出，不泄露原始命令错误。
- 原有固定 `/usr/bin/systemctl`、可信路径检查、参数、清洁环境和调用者 context
  均不改变。没有新的 shell、生产测试 hook、超时放宽或隐藏重试。

回归同时覆盖负面方法集、没有 WriterTo 的 `io.Copy`、实际子进程的 stdout/stderr
溢出、恰好上限、空输出、stderr 拒绝、带部分输出的非零退出、取消与 reap。
Linux 全包 race 与额外的 CGO-free 实际子进程门禁分别验证。

## 证据边界

软件测试只运行测试自身的子进程，不是 KVM 或真实 PID1 部署验证。
它不会伪造 systemd 结果为已通过，也不证明内核停滞、文件系统 D-state、
子孙进程保留 pipe 或全部 manager 故障窗口的最坏完成时间。
本次不额外增加管道关闭期限，也不把已有 context 当作这些情形的 SLO。

修改了安装器生产代码，旧版本的真实安装、TLS/KVM、热轮换和冷恢复报告
仍只绑定原来的源码/ELF，不能给新安装器代签；后续证据必须另行绑定。
共享 V100 宿主不升级、不改系统服务，不在共享 L0 上运行安装事务。
完整生产验收和 Goal 均未完成。

## 新源码的有限验证

[独立证据](validation/install-manager-output-bound-v1.json)绑定旧源码的负对照、
修正源码 `4587a9d` 的归档/runner/23 个重建产物，以及新 `185e6e3` 测试组合。
Linux 原生全包同进程 race×3、vet、模块校验、四个显式测试组件、CGO-free 子进程
门禁与 270 项 root 纯测试通过；amd64 原生/独立交叉构建相同，arm64 仅编译。

新安装器另在已有边界不变的 owned L1 中完成一条 `draft-kernel-guard` 命名流程：
新安装、普通 root CLI、TLS→四并行 KVM、策略恢复/drain、Stop/回收与原盘冷恢复。
两次启动、两个外层代际的全部声明路径均由独立只读复核确认不存在，无追加清理。
这不是其他策略故障路径、完整生产故障矩阵或停止/回收 SLO 的认证；
CI 结果与本源码绑定报告分开核对。旧报告原样保留，不以新二进制替换其摘要。
