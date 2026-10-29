# 固定测试夹具的普通 ELF 校准

固定探针/通知夹具必须拒绝未经核对的普通程序，不能自动接受运行时提供的任意哈希。
这也意味着重新构建普通程序后，旧测试 pin 可能在故障注入前拒绝执行；测试常量与
另一个相同常量相等，并不能证明它仍对应当前构建。

## 真实失败，不是 TLS 通过记录

在源码 `bf405dccbead973eacadfa89a0c6866fcc266e36` 的一次原始串行15项批次中，前12项
完成并独立核对：26次外层KVM启动、14次原盘冷启动；包括每租户120次busy-writer切换、
当前daemon的固定9点live校准、排队取消、16MiB复制中断和独立Stop/回收、owner提交窗口、
operator/ticket/shutdown及两种control存储故障。它们是具名有限实验，不是完整负载验收。

第13项TLS pre-file在启动固定gateway子进程前报`fixed gateway artifact required`。
该夹具pin仍为`41e9735696072936388d5481b7dcd595e38e2346437379b0f2999b5cc47b730a`，
而独立原生/交叉构建的当前普通gateway为
`17e2e0d524cd86acb576a26e10b78869ca345370347fd564fe8fcbdc8cbf641f`。
原始批次exit1，失败项没有checkpoint/cold recovery，后两项未运行；不能标成TLS故障测试通过，
也不是当前生产TLS行为失败的证据。原114份文件保留，不修改或重跑原批次凑绿。

原脚本自身finally之后，独立只读核对27个新增外层代际/13个资源scope声明路径均不存在；
与历史基线合计153个代际/71个资源scope。资源scope包含失败实验，不是71个通过项；
未做补充清理，也不是整台宿主机无资源的声明。原37项矩阵只核对完成24项，仍余13项；
额外systemd、完整持续负载、保留/升级/回滚等生产Goal门槛仍未完成。

## 构建前置门槛

`scripts/verify_fixture_calibration.py`只读取明确传入的两个有界静态ELF，不执行它们。
它要求Go中的daemon/gateway各一个固定pin、Python中的daemon字面量与Go相同，
再核对新构建的完整文件SHA256。缺失、改动、重复pin、架构错误、动态ELF、超界、
最终路径为symlink或非普通文件均拒绝。它不是对恶意同UID/source/workflow的认证。

CI的linux-build增加独立前置步骤：Go1.27.3、linux/amd64、GOAMD64=v1、CGO0、
GOENV=off、空GOFLAGS、`-trimpath -buildvcs=false`，新构建普通sandboxd和gateway后核对。
夹具仍只接受单个核定哈希，没有扩大allowlist、通知目标或测试预算；生产代码不变。

这道门槛能在昂贵KVM启动前暴露陈旧校准，不能代替受影响TLS三项的真实Linux/KVM复验，
也不能把旧硬件记录重新签成新夹具或新源码通过。普通daemon仍为
`896840d6d41066bb222d617f9a65cec463bc1a93918ae29e41eecd0e0028d768`；
此次修正没有证明降低open/switch服务成本，不允许因此重放原失败40分钟负载。

## 2026-10-29：即时撤销候选的当前校准（未验收）

生产改动 `9aab936a09ed120f2050083f4664aae0a28bc228` 在准入栅栏之后直接尝试
已有租约 capability 的有界撤销，不再仅等待下一轮 reconcile；Stop/持久化/回收
与容量释放门槛不变。它不是创建服务成本或高负载失败已经解决的证据。

[新候选的实际程序校准](validation/scoped-revoke-program-calibration-v1.json)
记录全1234份源码绑定、同一 V100 的13个实际原生构建及独立交叉编译摘要相等。
规范参数仍为 Go1.27.3 / linux/amd64/v1 / CGO0 / trimpath / buildvcs=false。
本节新 daemon 为 `97f2b7a83c90d877e06aa20a943c71632e142c469c392f52970a9903b25ebd0b`，
gateway 为 `f30f69852a8d7a2db133d0abda7478767b9d1bb6816ef8bc30806fbffda5a84c`。
本次只更新当前固定探针/通知 pin 及其断言，不增加可选摘要、不扩大通知目标或改变预算。

前述 BF、00dc、5b 等旧记录仍保留各自源码、程序及范围，不重新签成新候选。
完整 systemd 组合门槛仍需独立校准：旧来源不能冒称具有新程序字节；完整原生套件、
当前源码 CI 和真实 KVM 矩阵也仍待完成。本报告仅为软件工件的一致性检查，
不证明压力吞吐、停止百分位、共享内存 pristine、生产 SLO 或整个 Goal 完成；
不能仅凭新摘要重放原失败40分钟负载。

### 九点地址校准的真实失败与修复

`9e2b5c9` 的首个原生批次在13份程序构建和新 pair gate 成功后，
`TestPrepareProbePinnedOrdinaryELF` 三次均拒绝了旧绝对指令地址；批次 exit1，
后续 CGO0/vet 未执行，原始62份库存完整保留，不能记为整个夹具通过。
[独立离线比对](validation/scoped-revoke-nine-sites-calibration-v1.json)
逐条核对三函数共207条指令，源码行、函数相对指令边界、寄存器和符号化控制流相同。
九点地址均需加64字节，opcode/register 不变；保持整个 ELF 摘要、符号归属和
精确指令字节门槛，未挂载 tracefs、注册 probe 或改动 L0。
这只是新程序的定位校准，仍需原有完整 Linux 软件和真实 owned-L1 验证。
