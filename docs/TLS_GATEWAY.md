# 独立 TLS 接入与凭证边界（开发中）

当前正在实现 Linux `xandbox-gateway`，**尚未完成原生 Linux 权限隔离/KVM 端到端验收，不是可用生产部署声明**。普通 `sandboxd` 仍只监听私有 Unix socket；没有放宽其状态目录、operator/metrics socket 权限，也不增加 root 网络监听器。完整生产门槛仍见 [PRODUCTION.md](PRODUCTION.md)。

## 边界决策

普通 API 为 root0600、state为0700，无特权反向代理不能凭空访问它。本实现选择小型 root **固定连接 broker**，不改普通 daemon 的权限与协议：

- root supervisor不创建 TCP listener、不处理网络HTTP/TLS流量或握手。只校验操作员提供的私有配置/证书、校验静态同源可执行文件，并将子进程降为显式专用UID/GID（1000–65534、相同ID、无附加组）。
- 网络子进程进入root-owned0555且只含同一`/gateway`静态ELF的chroot，显式设置cwd为新根并在子进程再次核对`.`与`/`的inode一致，capabilities为空、NNP开启，nofile192/nproc64/core0/fsize0硬限制。它不读取宿主状态目录或凭证文件；不使用shell，不执行租户程序。
- root创建的私有`SOCK_SEQPACKET` socketpair通过继承FD成为能力；不是可由其他进程连接的broker socket。24字节定长消息只有连接、释放、完整policy更新/确认和liveness心跳，无path/argv/任意syscall选择器。socketpair凭证在创建时确定，不能把其root peer误称为子进程当前UID证明。[Linux Unix socket/SCM_RIGHTS语义](https://man7.org/linux/man-pages/man7/unix.7.html)
- root只连接启动时固定且经过root-owned0700目录、0600 `api.sock` inode与root peer检查的tenant端点，最多16个lease、45秒硬寿命，并对控制消息/新连接限速。子进程拿到的是这个已连接socket的FD，不能请求operator/metrics或其他路径；超时用`shutdown`影响所有dup，不能只close父FD假装撤回。
- 全部policy通过root-owned、只读、全seal的memfd传递，最大512KiB；没有token/cert/key出现在argv、env、日志或公开报告。只读FD和write/grow/shrink/seal锁同时检查，不能把“已传FD”视为不可变。[Linux memfd/sealing语义](https://man7.org/linux/man-pages/man2/memfd_create.2.html)

受信任的是root操作员、内核、controller和gateway程序；不抵御已控制宿主/root、专用gateway UID其他进程或gateway自身被攻破后的所有租户控制面冒用。chroot是文件访问缩小，不是替代KVM的租户隔离；租户命令仍只由普通daemon送进真实guest。

## 凭证与TLS生命周期

外部256位随机Bearer凭证仅保存摘要，并必须有not_before/expires_at（最长90天有效区间）。每个外部摘要映射到一个**不同的私有backend credential**；root对照启动时普通daemon的digest authority校验tenant/quota。外部key不是直接可用于私有controller的token，不能伪造tenant请求头。

外部策略有持久policy_revision及独立root0700 StateDir。独占lock与identity绑定固定socket/进程/后端authority；完整snapshot摘要和revision先原子写入并完成文件/目录Sync，随后才能向子进程发布。首次只接受空目录的revision1，之后仅允许revision+1或重启时同revision同摘要；缺少identity/record、回滚或复用revision均拒绝启动。未ACK的新策略可能已落盘，不能退回旧key。生产state journal不是fixture手写的准入元数据。其物理掉电/所有I/O故障窗口尚未验收。

SIGHUP重新读取完整root私有config/cert/key并传一份新snapshot；证书、私钥和外部key表整体校验后原子发布，进程绑定/tenant socket/backend authority路径不允许暗改。外部key可在不重启daemon/guest的情况下增加/撤销/轮换；空key表明确全部401，不变成无鉴权。普通daemon私有backend credential本身仍是启动配置，更新其authority依然需要单独设计/验收。

新请求读取新snapshot；已准入请求可继续使用其旧snapshot，撤销key不等于取消已接受工作或停止guest。无效reload/传输/ACK超时或root连续3s无消息/心跳会结束ingress子进程并撤回broker连接，不无限保留旧策略。普通daemon独立存活，恢复ingress不自动恢复/删除guest。

仅TLS1.3、精确SNI/Host、HTTP/1.1；禁用会话票据，握手和每次请求都检查当前证书时间。新握手取不可变certificate对象，已经建立的TLS连接不会换证书，但后续请求仍重新鉴权。这里不承诺安全擦除旧heap中的key，也不宣称已有外部PKI自动签发/分发/续期。[Go TLS配置及不可变callback约束](https://pkg.go.dev/crypto/tls#Config)

## HTTP与资源契约

只允许既有health/ready、sandbox和session的固定方法/路径；拒绝CONNECT/upgrade、非规范/编码路径、query、重复鉴权、origin/cookie、转发/租户伪造头、未知头、chunked请求与trailer。重建upstream URL/Host和header，外部Bearer替换为私有backend credential；不转发redirect/cookie/任意response header。非幂等exec禁止Idempotency-Key，不能意外触发transport幂等重试。

固定32个前端连接、握手接入16/s burst32；8个inflight/每tenant2个、全局128/s burst128/tenant32/s burst64。请求64KiB，response8MiB（覆盖现有输出JSON转义上限），header8KiB，header2s/body5s/上游请求40s/write45s/idle10s/连接硬寿命90s。超额拒绝而非无限队列；upstream最多8个active/idle连接且无proxy/DNS fallback。[Go transport连接与header预算](https://pkg.go.dev/net/http#Transport)

这些是实现的固定预算，不是已实测的最坏资源SLO、公平性或完整DoS防护。还需要单独的生产cgroup/日志预算、审计、长负载与真实operator/systemd验收；不允许在共享L0开放公网端口或修改系统服务来代替隔离测试。

## 当前证据状态

- 已有可跨平台运行的package级真实TLS握手、外部key原子轮换/撤销、私有token替换、路由/歧义/响应预算负例和race测试，目前实际执行于Darwin；不证明root子进程权限/chroot/broker路径。
- Linux定长IPC/FD/seal/取消后迟到FD回收测试已编写，当前尚待远程原生执行；不能把交叉编译标记为执行通过。
- 专属L1中的真实UID/cap/NNP/chroot/no-root-listener、KVM经TLS执行/切换/停止/完整回收、证书/key更新及失败关闭验收仍待执行。

没有新的生产就绪或完整Goal完成声明。既有实机报告仍绑定其原冻结源，不用新网关的unit结果给旧runtime或新网络边界背书。


## 未公开候选的修正前序

首个组件源`19092f4…`的原生unit gates通过，但不能证明特权启动边界。首个实机候选`9d9bfb8…`在证书检查失败：新key已接受的连接可能在policy发布前就完成TLS握手，因此仍显示旧leaf。修正测试为先确认新key可用，再主动关闭测试客户端idle连接、验证真正新握手的leaf2；不能把旧连接换证书当成必要条件。原实机false报告保留。

独立代码审查同时发现候选没有显式改变chroot后的cwd。启动器现设置`Dir=/`，子进程校验`.`与`/`同inode，实机另外核对`/proc/child/cwd`与私有root同inode；不能仅检查`/proc/child/root`就声称无外部cwd。[Linux chroot语义](https://man7.org/linux/man-pages/man2/chroot.2.html)。这是真实生产代码修正，不把它藏成测试预期调整；修正后需重新冻结与完整原生/实机验收，旧候选不是可部署版本。
