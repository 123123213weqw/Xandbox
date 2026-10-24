# Gateway 策略库存与孤立临时文件（有限实机验收）

冻结源 `c402ecc2…` 引入**新的生产gateway** `555b9974…`，不再用旧`241ca933…`的报告给它代签。普通daemon/admin/warden/node/builder五个ELF、go.mod/sum与workflow不变。本轮原生测试及新程序4scope/8次外层启动通过，**不是全局磁盘配额、全部存储故障、日志/审计预算或生产就绪声明**。

证据：[来源绑定](validation/policy-metadata-provenance-v1.json)、[真实孤立文件/负例/冷恢复](validation/kvm-policy-metadata-pre-v1.json)、[post-commit回归](validation/kvm-policy-metadata-post-v1.json)、[健康TLS](validation/kvm-policy-metadata-tls-v1.json)、[普通node-budget](validation/kvm-policy-metadata-budget-v1.json)、[独立清理审计](validation/policy-metadata-independent-cleanup-v1.json)。

## 缺口及失败对照

旧`state.atomic`只有正常defer会删除临时名；SIGKILL可能留下未引用文件。旧的有效identity/record启动分支没有库存预算或孤立文件回收。先以**未修改83d生产源＋同一份新测试**原生执行，exact-replay和next-revision两例均实际失败“authorized commit retained orphan metadata”，[原始unit对照](validation/policy-metadata-before-native-v1.txt)原样保留。这是在unit私有临时目录中构造的回归输入，不是旧版实机失败或fixture修复authority。

随后新程序的实机测试直接观察到生产程序被中断后留下的文件，并在普通冷启动中回收；没有由fixture制造policy临时记录来假装崩溃产物。

## 固定逻辑预算

| 项目 | 上限 |
|---|---:|
| 已识别孤立临时文件 | 8 |
| admission时目录项总数（含三份命名文件） | 11 |
| 所有这些文件的逻辑字节合计 | 8192 |
| 每个孤立临时文件 | 1024 bytes |
| 命名policy / identity / lock | 4096 / 1024 / 0 bytes |

目录只请求`max+1`个名字（最多12个后判超限），不是先`os.ReadDir`把整个目录装入内存再检查长度；逐项读取还受剩余总字节预算限制。[Go Readdirnames契约](https://pkg.go.dev/os#File.Readdirnames)

这是程序管理的**逻辑库存与有界读取准入**。不计目录块、inode、日志、文件系统journal/快照/分配粒度，不是物理allocated-block quota或存储I/O时间上界。原生unit验证了11/12项、8192/8193字节等边界；本轮KVM证明一个真实孤立文件与选定负例，没有宣称所有预算组合都做过硬件压测。

## 安全回收顺序

1. 保持原始独占`gateway.lock`和CLOEXEC目录FD；核对目录路径/FD及lock inode、权限、owner、single-link、零长度。目录0700、文件为调用者所有的0600普通single-link；生产RunRoot要求root。
2. **先校验snapshot的revision/digest CAS，再考虑回收。**旧revision、跳号和同revision换内容不通过时不能先删临时文件。临时文件永远不授权新revision。
3. 有界验证**整个库存**后才执行第一次unlink。命名policy/identity必须仍匹配实际authority；仅识别`.policy-`或`.identity-`加1–20位ASCII数字的临时名及完整严格schema。policy临时revision须非零、不超当前+1，identity绑定须相同。
4. 未知名字、部分/损坏JSON、额外字段、错误绑定/未来revision、超量/超大、symlink、hardlink、非私有权限和非普通文件均拒绝，不自动删除来“修好”authority。文件以NOFOLLOW/NONBLOCK方式打开并核对inode/大小/内容；避免误跟随链接或阻塞在FIFO。
5. 对可清理项再次检查inode/内容，使用固定目录FD的相对`Unlinkat`，有实际删除则检查目录Sync成功后才继续发布。精确重放可清理已识别垃圾而不改当前revision/journal内容。[Linux unlinkat及仍打开FD语义](https://man7.org/linux/man-pages/man2/unlink.2.html)

初始库存非法时，本轮负例确认没有部分清理；**不承诺后续unlink/目录Sync出错时事务性回滚所有已删项**。这些过程失败会拒绝本次发布，后续启动重新验证实际命名空间；其逐调用故障矩阵仍未完成。没有待删项的重放不为外部操作员未同步的历史文件变更提供持久化保证。

回收不递归、不删除未知对象、不从temp推导authority，不重置revision。已有lock而记录丢失、初始化后丢lock、首次bootstrap中断等既有fail-closed约束保持。整个StateDir被抹除不能靠内部marker证明历史；flock是协作锁，不抵御恶意宿主root/操作员竞争。unlink也不是安全擦除或仍打开FD立即失效的证明。

## 实机证据：真实产物，而非手写authority

沿用[pre-file/post-commit固定通知窗口](TLS_POLICY_COMMIT.md)与原有8GiB/12GiB/CPU8/no-business-NIC规格，重新冻结并运行新gateway：

- pre-file中实际停住生产revision2临时记录FSYNC，SIGKILL/reap root后核对该文件与原held目标**同inode、同完整payload**。冷前、同盘冷后分别有界读回其私有名字/hash/大小；journal仍为合法revision1。post-commit已Rename，孤立文件为0。
- pre冷启动先加入**fixture自己拥有的非authority** foreign普通文件，再换成自己的known-prefix symlink；另将操作员config输入暂设为跳号revision3。三次实际root均exit1 `POLICY_STATE`、无listener。每次拒绝前后，policy目录的名称/inode/权限/内容hash完全一致，真实孤立文件与authority未删改；不把atime读访问说成零物理写入。
- fixture只移除自己引入且inode未变的负例条目，恢复原config2**输入**；没有重写policy.json、identity、lock、ledger、control或owner。真实临时文件留给普通gateway处理。
- 普通新gateway随后自行验证CAS、清理实际孤立文件，进入命名文件仅3项的状态，生产提交2；验证leaf2/new key200/old401。post冷恢复仍实际拒绝old config1，再精确重放2、journal hash不变。
- 旧raw/session key与关闭路由410；第三个独立真实guest经TLS运行并GC，四个project为0、所有进程reap、整个NodeRoot移除。读取不到私有目录的无特权网络child仍通过cwd/FD/caps/NNP/rlimit检查，新加root目录FD没有委托给它。

所选中断后已有两代guest全部GC、controller正常停止、receipt写入再做外层cut；cleanup可能Sync文件系统。它是健康同步后同盘恢复，不是未主动同步的媒体掉电。非法文件/坏revision的负例也不等于真实介质损坏修复能力。

## 独立观测与验收范围

| N=1外部观察 | pre ms | post ms |
|---|---:|---:|
| held入口 → child消失 | 2286.217 | 2631.377 |
| 后续显式Delete → 执行域空 | 64.623 | 63.005 |
| 同一Delete → 私有路径/实际ledger DESTROYED/quota0 | 393.126 | 501.050 |

第一行不从最后一条root心跳计时，后两行不从撤权或SIGHUP计时；包含采样/读回。不是watchdog提速、内部耗时、百分位、公平性或SLO。

实际Linux Go1.27.3 full race×3/vet、fixture race×10/vet、CGO0真实kernel quota×3、root Python111零skip、mock6、7个原生/独立交叉构建SHA一致；冻结Darwin race×3/vet通过。四scope分别为新pre、post、健康TLS、普通schema3，各两次外层启动。独立只读核对所有精确root/control/parent/8个group不存在、runner退出，没有追加清理。公开4份原始JSON和unit失败对照，15个私有raw regular members逐个SHA绑定；不公开实际temp名、key/cert、receipt、console或进程身份。

复现使用[NESTED_HOST.md](NESTED_HOST.md)的完整固定资产参数，以及相同`--node-budget --node-tls-policy pre-file|post-commit --gateway <新static ELF>`；fixture明确固定新gateway SHA，不能混用旧241ca。每次新建私有report/log目录，不能复用旧receipt或修改其authority来通过。

## 仍未完成

全局物理磁盘/cgroup/日志/archive硬边界、部分/损坏/超预算目录的操作员恢复、GC逐unlink/dirSync及其余bootstrap/介质窗口、持久结构化审计/告警、PKI/backend authority生命周期、operator/systemd独立部署、长期开放到达/公平性及备份升级回滚。完整[生产门槛](PRODUCTION.md)尚未满足；Goal继续、PR保持Draft。
