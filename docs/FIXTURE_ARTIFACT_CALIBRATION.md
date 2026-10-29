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
