# Gateway 策略提交挂起与入口心跳（有限实机验收）

本页只证明两个固定的真实内核通知窗口及同盘冷恢复，**不是文件系统 D-state、物理介质故障、所有策略提交窗口或生产就绪声明**。冻结测试源 `83d949ec…`；普通五个ELF及gateway `241ca933…` 与既有0b基线逐字节相同，没有生产hook、生产Go/mod/sum/workflow变更。

这是83d/241ca的历史冻结范围。后续[有界策略库存与孤立文件回收](POLICY_METADATA.md)改变了gateway生产代码，新555b已另行完成两窗口和健康TLS/node-budget四scope复验；本页原始JSON与时间数据不改写、不改标为新程序认证。

原始报告：[pre-file](validation/kvm-tls-policy-pre-v1.json)、[post-commit](validation/kvm-tls-policy-post-v1.json)、[未修改的健康TLS回归](validation/kvm-tls-policy-tls-v1.json)、[普通schema3回归](validation/kvm-tls-policy-budget-v1.json)；[完整来源绑定](validation/tls-policy-provenance-v1.json)、[独立清理核验](validation/tls-policy-independent-cleanup-v1.json)。前序TLS失败、bootstrap失败对照与各冻结阶段的报告不改写、不重新贴标签。

## 为什么选择这两个窗口

普通gateway的reload路径为：读取并校验完整操作员输入 → `state.Commit` → `sealedSnapshot` → 发送完整policy → child确认。持久原子替换内部为：临时记录Write → file.Sync → Close → Rename → directory.Sync。只有前者成功返回，才会进入新的policy memfd创建。

| 固定窗口 | 实际停住的位置 | 当时journal | 尚未发生 |
|---|---|---|---|
| pre-file | 完整revision2临时记录的FSYNC入口，尚未执行 | revision1 | Rename、新策略snapshot/发布 |
| post-commit | file/dir Sync已通过检查后，固定policy `MEMFD_CREATE`入口 | revision2 | 新snapshot FD分配、向child发布 |

post-commit不仅检查磁盘命名空间：先观察并CONTINUE临时文件FSYNC，随后目录FSYNC处核对Rename保留的确切inode、临时名已消失，再在固定memfd入口停住。结合冻结的生产控制流，这个后续入口证明先前`Commit`成功返回；**CONTINUE回复本身不证明系统调用完成**。若只停在目录close，可能仍无法区分前一次Sync错误，故不采用它作为成功提交证明。

memfd名称只用于核对固定调用，不作为权限凭证；该系统调用尚未执行，因此不能称新策略已分配/发布。[Linux memfd语义](https://man7.org/linux/man-pages/man2/memfd_create.2.html)

## TEST ONLY 边界

- 仅在owned L1中，额外启动层给确切gateway ELF/TGID/进程起始身份/NodeControl安装FSYNC＋MEMFD_CREATE通知过滤器及所需NNP。不是新增生产开关；默认构建不包含fixture。健康TLS兼容回归使用正常、无此额外通知层的启动。
- root只接受固定gateway/config路径；fixture RPC只接受两个枚举phase，不接受路径、UID、命令、内存地址或任意receipt。实际filter架构/x32与非目标syscall选择有独立负例。
- 只读观察确切root的FD/inode/owner、policy目录与identity/lock摘要；核对固定memfd名称时，仅在通知仍有效期间有界读取该受信进程内存，并在读取前后检查ID。不是面向恶意目标的安全策略或通用内存读取API。[Linux通知、ID_VALID及内存检查限制](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)
- 目标通知**从不获得CONTINUE、errno或伪成功回复**；其他通知仅CONTINUE。20秒固定hold预算不变；继续回复计数为提交次数，不等于完成次数，held期间其他回复为0是合法结果。
- 只配置owned L1的loopback，无业务NIC；未改共享L0的网络、模块、挂载、DM、服务、capability或sysctl。

## 实际执行的顺序

1. 操作员先提供两租户backend auth、外部随机key、私有CA/leaf1/leaf2及config输入；普通controller启动。gateway正常提交revision1，两租户通过验证CA/SNI的TLS1.3创建真实KVM guest，核对UID/boot/workspace与跨租户404。忙写任务也经TLS准入。
2. 完整config2、新外部摘要与leaf2作为**操作员输入**同步落盘，再向确切root发SIGHUP。在所选内核入口暂停；独立核对实际journal1或2、完整目标payload、identity/lock与绑定。
3. 新策略仍未发布：旧key/leaf1可用、新key401。之后root停止发心跳，网络child实际消失且TLS listener关闭；此时root仍活着、目标通知仍VALID。不是通过先杀root/PDEATHSIG制造child退出。
4. 显式私有operator客户端确认同一普通controller仍运行，已接受任务RUNNING且写入进度增加，session身份不变。该UDS只用于测试观察/清理，不是tenant网络失败后的回退。入口关闭不等于撤销所有backend FD副本、取消已接受工作或Stop guest。
5. 使用确切持有的进程句柄SIGKILL root并实际wait/reap，检查目标ID变为ENOENT时observer listener**仍然打开**；不能用EBADF假装进程死亡。没有让被hold的目标系统调用执行。
6. 另发普通Delete，分别观察旧执行域为空与私有路径消失/持久完成状态/project quota0；回收另一session，两代全部DESTROYED、四个project为0、池空闲，正常停止controller后才写私有receipt并做外层cut。

清理、quota或receipt操作可能同步文件系统。因此这不是“完全不主动同步的媒体掉电”；只证明目标调用未得到回复、实际命名空间及下述恢复，不声称未ACK的revision2必然在任何介质上持久。

## 同盘冷恢复不能混淆的两种结果

在启动任何daemon前，第二次L1验证原始config2/auth/CA、实际policy、identity/lock、普通OPEN1 authority、两个DESTROYED记录与quota0；没有fixture修复policy/ledger/control/owner。

- **pre-file：**原journal1合法。当前操作员输入为2，普通gateway自行执行新的`Commit(2)`，随后才发布leaf2/new key。不是把未完成提交伪装成已持久化的2，也不声称此窗口已持久撤销旧key。
- **post-commit：**原journal2实际保留。操作员刻意改回旧config1，普通gateway必须在listen前exit1，journal hash不变；只恢复操作员输入config2后，普通gateway精确重放，journal hash仍不变。没有fixture重写authority。

两者最终均验证leaf2/new key200/old key401、旧raw/session key410与关闭路由410；第三个独立真实guest经TLS运行并全GC，四个project0、所有进程reap、整个NodeRoot移除。冷恢复没有额外通知层。

## 观测数据，不是SLO

| 外部观察（每种N=1） | pre-file ms | post-commit ms |
|---|---:|---:|
| held入口 → child消失 | 2543.520 | 2664.190 |
| 显式Delete → 执行域为空 | 58.822 | 53.873 |
| 同一Delete → 私有回收/持久完成状态/quota0 | 116.921 | 299.086 |

第一行起点不是最后一条root心跳，因此不用于“把3秒watchdog提速为2.5秒”的结论。后两行起点是之后另发的Delete，不是SIGHUP、held或网络撤权时刻。包含独立采样/读回，不能相减当内部耗时，不能当P99、公平性、长负载或生产停止上界。

环境沿用8GiB/12GiB/CPU8、无业务NIC的node-budget规格；L2为512MiB/2vCPU/128MiB workspace。没有增加资源或放宽生产预算来通过检查。

## 验收绑定与复现入口

冻结源实际执行Linux Go1.27.3 full race×3/vet、fixture race×10/vet、CGO0真实kernel quota×3、root Python111项零skip、mock6、7个原生与独立交叉构建SHA一致；同冻结源Darwin race×3/vet通过。两窗口＋健康TLS＋普通node-budget共4个scope/8次外层启动；独立只读核对每个精确root/control/parent/执行group均不存在，runner已退出且没有追加清理。

使用现有[owned L1宿主验收流程](NESTED_HOST.md)准备固定校验资产与static fixture/普通程序；在其原有完整参数后，分别选择：

```text
--node-budget --node-tls-policy pre-file --gateway /absolute/private/xandbox-gateway
--node-budget --node-tls-policy post-commit --gateway /absolute/private/xandbox-gateway
```

每次必须使用全新私有report/log目录，不能与健康TLS或其他modifier混用。单独的`--node-tls-gateway`与普通`--node-budget`仍是本轮实际执行的兼容回归，不用编译结果代替KVM执行。公开4份原始JSON未改写，15个私有raw regular members逐个SHA绑定；不公开key、cert、receipt、进程身份或原始console。

## 尚未完成

本冻结阶段没有policy临时库存回收证据，后续新程序的有限实现与验收见[POLICY_METADATA.md](POLICY_METADATA.md)。其余bootstrap/identity/lock/rename/GC/目录提交窗口、真实文件系统D/介质故障、部分/损坏/超预算元数据恢复、PKI/backend authority生命周期、生产cgroup/日志/archive硬预算、持久审计/告警、operator/systemd独立部署、开放到达/长期公平性及备份升级回滚仍未完成。完整[生产门槛](PRODUCTION.md)仍未通过，PR保持Draft，Goal保持进行中。
