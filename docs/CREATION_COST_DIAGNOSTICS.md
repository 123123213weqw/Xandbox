# 创建成本诊断：默认关闭的测试工具

> **测试工具；当前 Go/脚本字节已完成限定 OFF / observe / maximum 的 Linux/KVM 完整健康基线与原盘冷恢复验证，不是生产就绪声明。**
> 本次新 fixture 与脚本单独绑定并验收；先前私有原型不替新实现签发资格。整仓新提交 CI、长负载与完整生产验收仍需另行核对。
> 现有 12 次原始 40 分钟负载失败、无效性能对照及失败记录均保留，不因诊断工具加入而变为通过。

这些工具只属于 `xandbox_host_fixture` 构建标签和受信任的嵌套 KVM 验收路径，**不是生产 daemon / guest-agent 的新 API**，也不执行租户命令到宿主机。
生产 daemon、warden、agent 代码未改变。

## 默认关闭与显式启用

未指定新选项时，原 [node-budget 完整验收命令](NODE_BUDGET.md) 的 L1 启动脚本保持原字节：
没有额外观察、tracefs 操作、目标身份读取、停止信号、诊断串口输出或主机导出等待。
已禁用的回调不会包装或替换原 API 错误。

仅在原完整 `--node-budget` 命令上附加下列 **一个**选项，其他资产、限制和协议条件全部保留：

```sh
--creation-cost-diagnostics observe
# 或者：
--creation-cost-diagnostics maximum
```

- `observe`：传输真实、未填充的 schema3 JSON；记录五次 checkpoint create 和一次 cold-fresh create。
- `maximum`：保留真实 JSON 的全部原始前缀字节，仅追加明确的 ASCII JSON 空格至**既有 1 MiB 上限**，形成 512 个 2048 字节片段。
  这是合成传输压力，不是 guest 数据、写回窗口优化或性能对照；ABI 包不填充。
- 不支持任意 PID、事件、报文长度、期限选择器。不支持与 load、snapshot、OOM、诊断故障、operator、TLS 等修饰组合；分配资源和启动前拒绝。
- 主机选项通过受信任 initrd 启动参数传给 L1 fixture 的 `-creation-cost-mode`；默认 `off`，仅 `node-budget` 启动可显式选 `observe` / `maximum`。
  租户请求不能开启此模式，`launch` / `qemu-child` 等 L0 模式不能接收开启值。

按 [嵌套 KVM 说明](NESTED_HOST.md) 的原步骤准备资产和 `-tags=xandbox_host_fixture` 程序，不修改共享宿主配置。
诊断额外固定为参考 L1 内核 `6.8.0-136-generic`、8 CPU、明确的 syscall ABI 和受支持的 reference ELF；不匹配就失败，不降级或接受任意程序。
reference 构建使用 `GOTOOLCHAIN=go1.27.3`、Linux amd64 v1、CGO0、`-trimpath -buildvcs=false`。
观察器中列出的第二个实验 ELF 不是已发布的生产功能，也不意味着自动授权执行性能对照。

## 隐私、完整性与时间边界

诊断使用 `/dev/ttyS0` 控制台；fixture 控制回复使用独立 `/dev/ttyS1` / 主机 UNIX socket。
它们不是 L1/L2 guest-agent 的 vsock 数据通道。`write` 成功不代表另一通道的主机已收到全部字节。

启用时，原健康协议验证之后、非优雅断电之前，主机最多以既定 2 秒导出观察期限校验：

- 完整 ABI 和 normal 两组片段，固定 scope、序号、数量、字段和 Base64 范围、完整 SHA-256；拒绝截断、混组、重复、重排及损坏。
- 文件所有者等于启动策略明确指定的**非 root QEMU UID**，不是从文件属主猜测；regular / 0600 / 单链接 / 同 inode / 追加式 / 2 MiB 控制台界限。
- 成功记录包括实际 FD 标量元数据；失败保留限定的文件类型及 UID/GID/mode/link/size/device/inode、errno 和异常类，不能修补原件或掩盖原异常。

这段主机文件读取、解析和校验等待 **不是 API 延迟或执行域停止时间**，会让后台 I/O 有机会继续；因此是明确的观察方法变化。
普通文件读取遇到物理宿主 D-state 不能承诺可抢占硬期限。没有额外 guest fsync、优雅关机、超时放宽或故障窗口替换。
拒绝失败样本，不能补齐缺失帧、静默删去错误、重跑至绿或把 syscall 耗时叫作纯磁盘耗时。

原 console / trace / PID / UID / FD / Ref / key / receipt / wire 都必须保留在私有目录，**不要提交到仓库、公开工单或日志系统**。
“有限报文完整”不等于拥塞丢包率、所有故障窗口、SLO、RAM 擦除或物理介质删除。
API 绑定、停止执行、kernel-empty、namespace 清理和 quota-zero 仍是不同事件，不能互相代称。

## 私有离线完整性摘要

对已经私有收回的 console，调用者必须拥有 regular / 0600 / 单链接且不超过 2 MiB 的输入文件；以非阻塞方式打开后先验证文件类型，拒绝 FIFO 等非 regular 输入；输出目录必须预先存在且为调用者所有的 0700 目录：

```sh
umask 077
python3 -B scripts/creation_cost_trace_analyzer.py \
  --console /absolute/private/l1-console-1.log \
  --scope checkpoint --mode observe \
  --output /absolute/private/new-summary.json
```

cold console 使用 `--scope cold`；合成上限实验必须明确 `--mode maximum`，不能混作 observe。
输出只创建新 0600 文件，不覆盖已有摘要，不把原始数据打印到 stdout。
它只证明所给 console 的完整性/语义约束，**不能单独证明断电前已交付、完整 KVM 协议、来源身份或回收状态**；这些仍需实际 host receipt、源/ELF 绑定和独立资源复核。

## 可移植测试与显式 root 机制测试

所有默认 Python 测试数据均现场生成，不依赖私有 console 或服务器路径：

```sh
python3 -B -m unittest discover -s scripts -p 'test_creation_cost*.py'
go test -tags=xandbox_host_fixture -race -count=3 -run '^TestCreationCost' ./cmd/xandbox-host-fixture
CGO_ENABLED=0 go test -tags=xandbox_host_fixture -count=3 -run '^TestCreationCost' ./cmd/xandbox-host-fixture
```

Go fixture 的编译/执行目标是 Linux；本机不能运行时在已授权 Linux 节点执行。
需要实际非 root UID 文件属主控制的机制测试**不在默认测试里伪装成跳过即通过**，须显式在已授权 Linux/root 环境执行：

```sh
sudo -n python3 -I -B scripts/creation_cost_uid_fixture.py --run-owned-uid-fixture
```

该测试只对自己创建的临时合成文件设置固定测试 UID、校验正确/错误所有者并清理该临时目录，不创建宿主账户、修改运行态 console 或触碰未知进程。
它不是 QEMU、KVM 或完整生产验收。发布门槛仍包括当前源码的 native/CI、默认 OFF 和显式 observe / maximum 的真实完整 KVM 冷恢复验收；旧原型结果不代签。

## 当前有限验收记录（2026-10-30）

[公开限定报告](validation/creation-cost-tools-functional-2026-10-30.json)按 Go/Python 代码指纹和实际 ELF 绑定，不包含私有 console、PID/UID、Ref、key、FD 或原始 receipt。

- 普通 daemon 仍是固定 **8 MiB** 写回版本；新测试 fixture 的默认 OFF、observe、maximum 各完成一轮完整原始 node-budget 健康协议、两次实际 KVM 外层启动及一次原盘冷恢复，合计 **6 次启动 / 3 次 cold**。没有重跑 1 MiB 性能对照或原始 40 分钟负载。
- 默认 OFF 没有诊断帧、模式报告字段或主机交付 gate/receipt；结合禁用回调 no-op 与全部 11 种旧启动配置的完整字节 golden 回归。该有限观察不是“追踪证明所有宿主 syscall 不存在”。
- observe 的 normal 两阶段分别为 **85,018 / 23,884 字节**；maximum 两阶段均为 **1,048,576 字节 / 512 帧**，真实 JSON 前缀全部保留，尾部仅合成 ASCII 空格。四个启用 scope 均有实际文件类型等 8 字段 FD 证明、完整 ABI/帧/SHA/谱系/闭合配对与零 CPU 丢失检查。
- 这四次交付均在首个主机快照已完整，不能外推延迟尾帧、拥塞丢包率或 SLO。最多 2 秒的主机导出等待仍不是 API/Stop 耗时。
- Linux 原生 fixture 178 个父测试各在 CGO0/race 跑 3 次、零跳过，vet 通过；新 Python 完整 415 测试零跳过，显式 root 文件属主机制另测。Mac 本地 415 中有 1 个既有 Linux mincore 跳过，不能写成 415 本地通过。
- 实际私有 console 的离线 CLI 已验证成功、模式误用拒绝与既有摘要不覆盖；默认 OFF 的无帧输入被拒绝。51 份原件及同一归档的新鲜只读复核独立完成；历史清单计数不是通过测试数或 RAM/介质擦除证明。

最初的私有验收校验器在任何 VM 启动前退出 1：正常宿主拒绝错误由 main 加 `host fixture failed:` 前缀，而校验器漏了它。原失败及缺失的旧子进程输出保留，不补造；以新的负向机制证据修正精确格式，并在判断前保存实际子进程输出后，才运行本次完整三模式验收。不是弱化正常退出约束或重跑已启动的 KVM 用例凑绿。

证据收集器另发现三个自有压缩归档按宿主 umask 生成了 0664；原父 home 的 0700 已记录，但这不替代文件私有模式。仅修正这些归档权限至 0600，原字节/哈希/状态/inode 未变，原 0664 事实保留；新的显式 0600 独占导出机制已用合成文件验证。这不是生产 console 属主修改或“没有任何访问”的审计结论。

此前单次完整 1 MiB 写回性能对照**未通过既定收益门槛**，继续保留 8 MiB。以上仅验收诊断工具，不意味着性能提升、全部原始故障窗口或完整生产发布通过。

发布前的格式门槛另拒绝了一处 Python 测试文件尾部多余空行；仅删除该空行，完整 AST（含位置信息）一致。运行时 Go 与非测试 Python 均与实测逐字节相同，报告区分实测与发布代码树指纹；新提交 CI 另核对。
