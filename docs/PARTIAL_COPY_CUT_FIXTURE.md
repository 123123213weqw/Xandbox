# 未主动同步的部分复制宿主掉电：有限验收

> 本页保持原冻结程序的历史证据；准入控制变更后的4ee程序已另行完成[对应有限节点/复制/owner实机复验](NODE4EE_REQUALIFICATION.md)，没有重标本页报告或推断生产就绪。

2026-10-23 固定新case及相关回归已通过，见[精确SHA与全部原始证据](validation/copy-cut-provenance-v2.json)。这是独立于[稳定前缀 TEST EIO](PARTIAL_COPY_FIXTURE.md)的新故障窗口。冻结源 `25423a68dc96a1330ea6c73a47990d86857f0436`，普通生产 daemon / warden / builder / guest 未改，仍为实验状态，不是完整 Prepare、介质或生产验收。

## 故障点与凭据边界

固定 `--quota-partial-copy-cut` 复用 `quota-copy-v1`：3GiB L1 RAM、4GiB raw disk、4GiB outer cgroup、CPU4/pids128/swap0/noNIC/900s，node2/tenant2/projects4、192MiB/128inodes、catalog4 entries/2GiB；旧2GiB和quota-switch-v1资源不变。普通 driver 的 attempted owner 与限额提交在复制前完成。

TEST 观察器只选择原 daemon 的确切 incarnation/TGID:TID/FD/inode、128KiB WRITE、真实16MiB workspace offset。victim 尚无共享链接、初始化或 VMM；keeper 是实际执行过的另一台 KVM guest。选中 WRITE 不收到 EIO 或 CONTINUE，停留在 notification wait，**不是实际 filesystem D-state**，也不是物理介质故障。

keeper 的完整基线在 victim 创建**之前**同步。从选中部分前缀到断电，观察器不做 quota sync、syncfs、fsync、catalog admin scan 或 L1 凭据写入。catalog admin 的 status 会同步 owner 目录，因此此处不能使用它。只读取持久 owner、ledger、index、proc 和 quota；按复制前 index 的精确 SHA 验证原有 AVAILABLE 与 RETIRED tombstone。

私有恢复凭据只经固定控制通道传到外层 L0 的独占0600文件，不写入待故障 L1 文件系统，也不进入公开 JSON/归档。7000字节凭据上限，完整 compact 请求仍须小于原8192 scanner，不扩大控制协议。进行中 Create 使用独立有界90秒 context，避免 checkpoint RPC 返回时取消它。notification hold 上限60秒；控制回复到外层执行域停止须小于15秒。QEMU raw/cache.none/aio.native，不保存/恢复外层 VM。

**未主动同步不等于必然丢失。** 自然后台落盘可能发生；不得要求重启后恰好保留16MiB，也不能宣称测到了实际掉电丢失量。

## 原盘冷恢复验收

第二次 L1 启动后，先不启动普通 daemon：核对不同宿主 boot、原配置/export/HostABI UNASSIGNED、精确 owner/index、两个 pins、旧执行域消失。keeper 的完整 namespace/共享 inode 元数据与配额按旧严格规则核对。victim 只允许空集或 `.`, `root`, `root/workspace.ext4` 的合法子集；文件0..16MiB、root私有权限/UID/links/inherit/project正确；用实际唯一 inode 的 st_blocks/inode 数与实际 kernel quota 独立核账。既不沿用旧已同步前缀计数，也不清空未知 project 或放宽 keeper 元数据比较。

随后只启动普通、无通知观察器的 daemon：两旧代际 DESTROYED/资源消失、旧key410/exec409、四project全零/pins0；再创建两个新实际KVM guest，验证 UID65534、不同 boot、无旧marker。退役后 pins2→1 时 GC 必须0且另一guest继续执行，最后一pin释放才精确 GC1；最后全部quota清零、控制器reap、父cgroup删除。

## 失败前序必须保留

V1 `d06d21e…` 实测在 checkpoint 的 catalog-index 谓词失败，仅一次 L1 开机，未执行 partial-copy host cut 或普通冷恢复。原报告保留 `passed=false`。新测试错误地假设 index 只有一个条目；原有 sharing setup 实际会保留 RETIRED tombstone 再发布新声明。V2 改为保存复制前 index 精确SHA，并严格接受其中已知 active/retired 状态；不是把实际冷配额、owner字节或keeper链接检查放宽。新增纯测试覆盖已知 tombstone、index字节漂移、错误active和额外AVAILABLE条目。

外层失败范围已独立只读审计清理；这不构成失败场景下普通 GC 或 project 清零证明。

## 尚未完成

只有这个固定partial-copy在途窗口；另有[owner unlink后目录fsync pending的独立有限cold证据](OWNER_COMMIT_FIXTURE.md)，不是所有owner unlink/dirfsync/catalog锁窗口；其他keeper/shared-pin持久组合、真实介质错误仍独立待做。节点物理/unique-RAM/IO/catalog/ledger/journal/preparation总准入、开放到达/公平性/长期资源稳定性、独立操作员/SLO以及完整M1–M4未完成。PR19保持Draft，不据此声明生产就绪或完成Goal。先前 quota240 与双活cold证据保留其原3f9c源码标签，不重新贴本轮源码。

## 新固定窗口的实际结果

新case N=1、两次实际L1启动通过。断电前实际16,777,216字节workspace、kernel quota和named allocation各16,785,408字节、三个private inodes。冷启动前检查只剩两个目录，实际quota为8192字节/两个inodes，**workspace文件名未保留**；不是声称“保留了一个空workspace文件”。随后普通daemon回收两旧代际、拒绝旧key、真实新guest/retired pins/最后GC及四project清零/reap/parent删除检查全部通过。

单次外层cgroup停止观察93.694ms；控制回复到外层停止观察99.039ms。只用于该外层测试切点的边界，不是生产销毁、WRITE提交、硬件掉电时延或P95/SLO。


## 回归与证据范围

原生Go1.27.3 full race3/vet、fixture race10/vet、root Python65、实际CGO0 quota内核与exec继承过滤各3次、五种native与独立cross ELF逐字节相同，以及Darwin full race3/vet通过。旧稳定前缀EIO/keeper一例、原snapshot sharing及3个cold、clear后owner仍pin的cold、6个errno（各clear至少3次）及3个cold均回归通过。本轮5个通过scope/13个外层执行代际加旧失败1个scope/1代际，共6个scope/14个代际已独立只读核验退出和路径清理；这些不是tenant VM总数。

[新原始cut报告](validation/kvm-copy-cut-inflight-v2.json)、[失败前序](validation/kvm-copy-cut-inflight-failed-v1.json)与原始回归/编译日志由[清单](validation/copy-cut-provenance-v2.json)逐一绑定SHA。取回归档仅13个白名单普通文件，独立审计stdout单独捕获；私有receipt、inner console、运行标识及镜像不公开。配额检查发生在L1删盘前，不从外层路径已删除倒推出quota清零。
