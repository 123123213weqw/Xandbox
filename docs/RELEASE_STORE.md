# 安装事务地基：有界、持久的发布物仓库（新增，未安装验收）

`xandbox-release` / `internal/releasestore` 为后续安装事务提供真实的发布物暂存、完整性校验和
CAS 提交，不是 systemd 安装器。它**不**写 unit、操作服务、改节点绑定/准入、执行发布物、
恢复 guest、处理 catalog pin 或删除旧发布物；不能用它代替升级/回滚/备份与独立操作员验收。
既有真实 KVM 报告仍只绑定各自的源码/ELF，本项没有新的 privileged CLI / owned-L1 验收声明。

冻结源 `0a51f39893fd8d317c4905a603294d6028f92dcf` 已实际通过Linux Go1.27.3完整race(count3)/
vet、新文件系统/8处进程退出控制(count3)、fixture/helper及quota回归；新CLI/test的原生与
交叉字节一致。13个既有程序已重新构建并逐项确认仍等于9e4原生摘要，不给旧程序改贴来源。
[脱敏原生摘要](validation/release-store-native-v1.json)保留这些绑定及实际Python197/skip1结果；
此原生控制不取代原readiness在root条件下197/zero-skip的独立原件。

## 输入和信任根

- 生产入口仅限 Linux、真实/有效 UID0；固定仓库 `/srv/xandbox-releases`，无 root 参数、shell、
  task argv、环境选项、可选执行器或自动安装下载。不修改宿主系统配置。
- 私有 manifest 严格解码，拒绝重复/未知字段、额外 JSON、越界及非规范路径。声明 source
  revision、工具链和目标架构只是受信操作员的构建来源声明，**不是本工具证明了原生构建**。
- 固定13个角色：daemon/firecracker/gateway/ingress/initrd/jailer/kernel/launcher/node/ready/
  template/warden/workspace。角色是闭集，不允许提供目标文件名/目录树；没有凭证或可变节点状态字段。它不按内容识别
  被操作员误标的秘密，也不在本阶段认证ELF/guest格式。每项必须给出 source、实际 SHA256 和精确字节数；重复源、缺项及仓库内自引用拒绝。
- 每个普通角色最多128MiB、workspace最多512MiB、单发布物总计最多1GiB。最多保留当前和
  前一个发布物；第三个拒绝，不做隐式GC。这是逻辑/拷贝上界，不是物理磁盘预留或 quota。
- source/manifest 的完整 ancestry 用 anchored NOFOLLOW FD 打开，root 所有、不可被group/other
  写入；文件为 regular/single-link，私有manifest没有group/other权限。不穿越 `/tmp`、root
  symlink、FIFO/device 或可写父目录。源FD全部校验摘要/大小后才提交事务意图。
- root 是信任根；不是恶意root隔离、签名分发/供应链认证或跨root变更的原子保护。

## 提交与不确定结果

1. 在不更换 inode 的私有 `.lock` 上跨进程排他锁；等待可取消。检查完整固定库存、上一引用
   和所有保留发布物的实际内容。未知文件/目录、权限、硬链接、坏摘要或丢失发布物拒绝，
   不按名称 adopt 或递归删除。
2. 私有意图绑定规范化完整输入、request ID、expected revision 和原引用摘要。先写固定scratch、
   file fsync、rename、directory fsync，然后才允许创建pending目录/复制资产。
3. 只恢复该意图的固定文件。0600 partial 的每个既有字节必须与同一个已校验输入FD的前缀
   相同，才继续追加；不截断/覆盖不匹配内容。完整文件再验实际摘要、file fsync、封为0500
   executable /0400 data并再次sync。固定 manifest 不保存源路径。
4. 全部密封后同步目录，将pending原子rename到内容寻址目录，同步源/目标父目录，再复核
   完整发布物。仅写好了某几个文件不是提交成功。
5. 显式 CAS 发布单一0600引用，持久保存 revision、前一发布物和精确请求摘要；file fsync、
   rename、parent fsync之后才能确认。后置清理仅删除与该提交严格匹配的意图，保留原发布物。

失败/取消返回“未确认”，不是“未提交”。相同request ID、expected revision与完整输入可精确
重试；已经提交时不推进revision，也不再需要原资产源文件，仍须保留输入manifest并复核所有
保留字节、同步引用目录。新的请求不能忘掉未提交意图，也不能以部分库存覆盖现有发布物。
`status` 不自动恢复：有未完成意图时拒绝，不能把pending字节展示为已发布。

Context只在有界读/拷贝及锁等待之间生效；10分钟CLI预算不是任意文件系统 D-state 的硬上限。
fsync成功依赖存储/文件系统的持久性契约，不宣称所有物理介质或掉电故障都已覆盖。

## 命令契约

先通过受信任分发提供真实root私有manifest；不把占位符示例当作可部署配置：

```text
xandbox-release publish -manifest /absolute/private/manifest.json -expected-revision 0 -request-id <32 lowercase hex>
xandbox-release status
```

输出仅闭集版本、revision、保留数量、publication_durable，以及恒false的services_changed /
production_ready；不输出输入路径、request ID、资源身份、令牌或底层错误。stdout写出失败也
可能已提交，必须沿用相同请求恢复，不能另发新request猜测结果。

## 验证范围与下一道门

新增控制覆盖严格schema/预算、路径与身份绑定、真实Linux目录FD/文件权限/摘要、跨handle
锁竞争与取消、每一固定持久化边界的未确认结果及精确恢复、匹配partial与未知库存拒绝、
双保留容量、无源文件的已提交重试，以及测试进程在8个实际文件操作边界突然退出后用新FD
恢复。测试hook仅在包内测试构造器设置，没有生产flag/环境入口。

这批原件的离线核对最初假设sha256sum成功行一定是英文OK，实际系统输出“成功”，
导致离线核对失败；原错误保留。逐项二进制摘要核对已通过，仅补闭集的实际本地化文本核对，
未重跑原生/硬件或改变原始日志。

这些是本地/原生unit与进程级故障控制，不是 privileged生产CLI、系统宿主掉电、真实服务
安装/升级或KVM组合验收。后续须在独占L1运行普通CLI，核对root/权限/原盘恢复、实际服务
和guest持续性；再把发布提交接到停准入/服务切换、固定路径物化、manager启用/恢复、catalog
位置、版本兼容与备份协议。未完成这些之前，完整安装事务和M1–M4仍未通过。
