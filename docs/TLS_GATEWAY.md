# 独立 TLS 接入与凭证边界（有限实机验收）

Linux `xandbox-gateway` 已完成原生权限隔离、实际 TLS→KVM 与同盘冷恢复的有限验收；当前生产冻结源为 `c402ecc2…`、新ELF `555b9974…`，新增[有界策略库存与真实孤立文件回收](POLICY_METADATA.md)，并另行通过4scope/8次外层启动。**不是生产就绪、完整 TLS/PKI 或操作员部署验收声明**。普通 `sandboxd` 仍只监听私有 Unix socket；没有放宽其状态目录、operator/metrics socket 权限，也不增加 root 网络监听器。完整生产门槛仍见 [PRODUCTION.md](PRODUCTION.md)。

## 边界决策

普通 API 为 root0600、state为0700，无特权反向代理不能凭空访问它。本实现选择小型 root **固定连接 broker**，不改普通 daemon 的权限与协议：

- root supervisor不创建 TCP listener、不处理网络HTTP/TLS流量或握手。只校验操作员提供的私有配置/证书、校验静态同源可执行文件，并将子进程降为显式专用UID/GID（1000–65534、相同ID、无附加组）。
- 网络子进程进入root-owned0555且只含同一`/gateway`静态ELF的chroot，显式设置cwd为新根并在子进程再次核对`.`与`/`的inode一致，capabilities为空、NNP开启，nofile192/nproc64/core0/fsize0硬限制。父进程将所有额外继承FD标记CLOEXEC，仅显式传递IPC/policy；子进程stdio改接`/dev/null`，不委托操作员的日志socket/文件/目录能力。它不读取宿主状态目录或凭证文件；不使用shell，不执行租户程序。
- root创建的私有`SOCK_SEQPACKET` socketpair通过继承FD成为能力；不是可由其他进程连接的broker socket。24字节定长消息只有连接、释放、完整policy更新/确认和liveness心跳，无path/argv/任意syscall选择器。socketpair凭证在创建时确定，不能把其root peer误称为子进程当前UID证明。[Linux Unix socket/SCM_RIGHTS语义](https://man7.org/linux/man-pages/man7/unix.7.html)
- root只连接启动时固定且经过root-owned0700目录、0600 `api.sock` inode与root peer检查的tenant端点，最多16个lease、45秒硬寿命，并对控制消息/新连接限速。子进程拿到的是这个已连接socket的FD，不能请求operator/metrics或其他路径；超时用`shutdown`影响所有dup，不能只close父FD假装撤回。
- 全部policy通过root-owned、只读、全seal的memfd传递，最大512KiB；没有token/cert/key出现在argv、env、日志或公开报告。只读FD和write/grow/shrink/seal锁同时检查，不能把“已传FD”视为不可变。[Linux memfd/sealing语义](https://man7.org/linux/man-pages/man2/memfd_create.2.html)

受信任的是root操作员、内核、controller和gateway程序；不抵御已控制宿主/root、专用gateway UID其他进程或gateway自身被攻破后的所有租户控制面冒用。chroot是文件访问缩小，不是替代KVM的租户隔离；租户命令仍只由普通daemon送进真实guest。

## 凭证与TLS生命周期

操作员应生成独立的256位随机外部Bearer；程序保存其SHA-256摘要，并要求not_before/expires_at（最长90天有效区间）。摘要格式检查不能证明原始凭证的熵。每个外部摘要映射到一个**不同的私有backend credential**；root对照启动时普通daemon的digest authority校验tenant/quota。外部key不是直接可用于私有controller的token，不能伪造tenant请求头。

外部策略有持久policy_revision及独立root0700 StateDir。独占lock与identity绑定固定socket/进程/后端authority；完整snapshot摘要和revision先原子写入并完成文件/目录Sync，随后才能向子进程发布。首次只接受空目录的revision1，之后仅允许revision+1或重启时同revision同摘要；缺少identity/record、回滚或复用revision均拒绝启动。lock本身也是使用标记：只可O_EXCL新建，并先完成lock文件及目录Sync，才能首次bootstrap；已有lock但两个authority记录均缺失也拒绝，已初始化目录缺失lock同样拒绝。中断的首次bootstrap不自动重置。未ACK的新策略可能已落盘，不能退回旧key。生产state journal不是fixture手写的准入元数据。其物理掉电/所有I/O故障窗口尚未验收；整个StateDir被抹掉无法仅靠目录内部文件证明历史，不提供宿主root恶意删除后的防回滚承诺。

SIGHUP重新读取完整root私有config/cert/key并传一份新snapshot；证书、私钥和外部key表整体校验后原子发布，进程绑定/tenant socket/backend authority路径不允许暗改。外部key可在不重启daemon/guest的情况下增加/撤销/轮换；空key表明确全部401，不变成无鉴权。普通daemon私有backend credential本身仍是启动配置，更新其authority依然需要单独设计/验收。

新请求读取新snapshot；已准入请求可继续使用其旧snapshot，撤销key不等于取消已接受工作或停止guest。无效reload/传输/ACK超时会关闭ingress并撤回broker连接；child连续3s收不到root消息/心跳也会退出。但root卡在文件系统I/O时，不能保证所有backend socket副本立即被root撤回，仍受普通controller/lease/guardian自身预算约束。另有[固定策略提交通知挂起窗口](TLS_POLICY_COMMIT.md)实际验证child在root仍活着时退出、旧工作继续；它不是文件系统D/物理介质挂起。普通daemon独立存活，恢复ingress不自动恢复/删除guest。

仅TLS1.3、精确SNI/Host、HTTP/1.1；禁用会话票据，握手和每次请求都检查当前证书时间。新握手取不可变certificate对象，已经建立的TLS连接不会换证书，但后续请求仍重新鉴权。这里不承诺安全擦除旧heap中的key，也不宣称已有外部PKI自动签发/分发/续期。[Go TLS配置及不可变callback约束](https://pkg.go.dev/crypto/tls#Config)

## HTTP与资源契约

只允许既有health/ready、sandbox和session的固定方法/路径；拒绝CONNECT/upgrade、非规范/编码路径、query、重复鉴权、origin/cookie、转发/租户伪造头、未知头、chunked请求与trailer。重建upstream URL/Host和header，外部Bearer替换为私有backend credential；不转发redirect/cookie/任意response header。非幂等exec禁止Idempotency-Key，不能意外触发transport幂等重试。

固定32个前端连接、握手接入16/s burst32；8个inflight/每tenant2个、全局128/s burst128/tenant32/s burst64。请求64KiB，response8MiB（覆盖现有输出JSON转义上限），header8KiB，header2s/body5s/上游请求40s/write45s/idle10s/连接硬寿命90s。超额拒绝而非无限队列；upstream最多8个active/idle连接且无proxy/DNS fallback。[Go transport连接与header预算](https://pkg.go.dev/net/http#Transport)

这些是实现的固定预算，不是已实测的最坏资源SLO、公平性或完整DoS防护。还需要单独的生产cgroup/日志预算、审计、长负载与真实operator/systemd验收；不允许在共享L0开放公网端口或修改系统服务来代替隔离测试。

## 此前0b基线证据与测量边界

[最终原始报告](validation/kvm-tls-gateway-live-v4.json)、[普通node-budget回归](validation/kvm-tls-gateway-budget-v4.json)、[当前来源绑定](validation/tls-gateway-bootstrap-provenance-v4.json)、[独立清理核验](validation/tls-gateway-independent-cleanup-v4.json)；[前四个冻结阶段的来源绑定](validation/tls-gateway-provenance-v3.json)及全部原始报告原样保留：

上述为0b生产基线的冻结证据。随后新增[83d测试源的策略提交挂起专项](TLS_POLICY_COMMIT.md)：未修改的同一gateway/普通程序通过pre-file和post-commit两窗口、入口watchdog/guest继续与各自原盘cold，并另做健康TLS及普通node-budget回归，共4scope/8次启动。新报告不改写本节0b数据；只有两个固定通知窗口，不是完整policy故障矩阵。

再后的c402**改变gateway生产代码**，不能由83d/241ca代签：[新555b验收来源](validation/policy-metadata-provenance-v1.json)绑定11项/8KiB逻辑库存、CAS后已识别temp回收、实际SIGKILL产物/原盘cold、foreign/symlink/跳号拒绝及新程序pre/post/TLS/node-budget四scope。仅有逻辑预算与选定窗口，不是物理配额或全部介质恢复。

- 冻结源`0b4eb8cf…`实际执行Linux Go1.27.3全量race×3/vet、tagged fixture race×10/vet、CGO0真实quota filter×3、root Python107项零skip、mock6对象；同冻结源Darwin race×3/vet通过。7个原生ELF与独立交叉构建SHA逐项相等，不把交叉编译当成执行。
- 实际root broker无TCP listener；唯一listener属于UID/GID60001、无附加组/caps0/NNP的child；真实chroot/cwd同inode、rlimits及NodeControl归属核对。特意向root launcher传入外部目录FD10，确认child未继承外部目录能力；自根目录瞬时内部FD不误判成外部目录。
- 两租户经验证CA/SNI的TLS1.3执行真实guest命令；UID、boot、workspace独立，跨租户404，私有backend token不能直接登录外部入口；operator/metrics、歧义鉴权/转发头、TLS1.2及错误SNI均拒绝。
- policy revision2的外部key+leaf轮换不重启普通controller/guest；旧key在**已复用连接**上401，新key经**真正新握手**确认leaf2。无效reload关闭ingress而guest继续；旧revision1重启在listen前拒绝；恢复当前revision2无需重启controller。
- 实际忙任务session切换创建独立新guest，旧revision409。并发观察旧执行域为空、私有回收/持久DESTROYED/四个project quota0，而非用删除外层VM推断guest清理。前三代全部GC、gateway与controller全部reap后才生成私有receipt并进入原盘第二次L1启动。
- 冷恢复在启动daemon前验证原始config/auth/policy journal与3代DESTROYED记录；普通启动无额外TEST通知层、open/pending0；revision2重放journal hash不变，旧raw/session key与关闭路由410；第四个独立真实guest经TLS运行并完成GC。
- 最终TLS与旧正常schema3回归分别2次L1启动，共2 scope/4外层代际。独立只读审计另核对前序93的4代、f698的4代与9d失败的1代，共7 scope/13外层代际；所有精确root/control/parent/group均不存在，五个runner终态且已退出，没有追加清理操作。

同一switch起点的最终N=1外部观测：

| 事件 | ms |
|---|---:|
| 新binding响应 | 3454.827 |
| 新guest首条验证命令 | 3518.551 |
| 旧执行域确认为空 | 3511.796 |
| 旧私有回收、持久销毁及quota0 | 3874.491 |

测试客户端故意每50ms发起请求（20req/s）；数字包含节流与独立采样/读回，**不是内部阶段耗时、优化对比、百分位、公平性或生产SLO**。环境为既有8GiB/12GiB/CPU8的owned L1、无业务NIC，L2为512MiB/2vCPU/128MiB workspace；未在共享L0开放端口或部署服务。

本次新增独立gateway生产程序，但普通daemon/admin/warden/node/builder五个ELF仍与既有`4ee09d0a…`组合完全一致，旧六份验收manifest不改写、不重新贴标签。普通node-budget原报告中静态的更广runtime复验限制原样保留；是否复用历史结果以精确ELF/source绑定为准。


## 保留的失败与修正前序

首个组件源`19092f4…`原生unit gates通过，但无实机启动。首个实机候选`9d9bfb8…`证书检查失败：新key已接受的连接可能在policy发布前就完成TLS握手，因此仍显示旧leaf。修正测试为先确认新key可用，再关闭新客户端idle连接、验证真正新握手的leaf2；保留另一条旧连接验证撤销。[原false报告](validation/kvm-tls-gateway-live-v1.json)与[诊断派生](validation/tls-gateway-failure-diagnostic-v1.json)保留：1次L1、无成功checkpoint/无cold/未开始普通回归；静态limitations描述计划范围，不代表已完成断言。

独立代码审查同时发现候选没有显式改变chroot后的cwd。启动器现设置`Dir=/`，子进程校验`.`与`/`同inode，实机另外核对`/proc/child/cwd`与私有root同inode；不能仅检查`/proc/child/root`就声称无外部cwd。[Linux chroot语义](https://man7.org/linux/man-pages/man2/chroot.2.html)。这是真实生产代码修正，不藏成测试预期调整。修正后f698源另有原生及两scope/4次启动的功能基线；但它尚无后续FD继承修正，不能给最终93源代签。


进一步按实际Go启动实现核对descriptor继承：`ExtraFiles`不负责关闭外部launcher遗留的全部non-CLOEXEC FD。root supervisor在fork前对>=3执行进程本地CLOEXEC标记，显式capability再由exec映射；子进程stdio不继承调用者能力。新增子进程测试与实机故意传入outside目录FD10，核对网络child无外部directory FD；这不涉及修改共享L0内核或关闭其他进程FD。93源另行完成原生及两scope验收，但尚无下述持久lock修正，不作为当前源码的代签。

发布93基线后的复核发现：两个authority文件均丢失、只剩旧`gateway.lock`时，旧逻辑可能再次bootstrap revision1。[原生失败对照](validation/tls-gateway-bootstrap-before-native-v4.txt)用**未修改的93生产源＋新测试**在unit私有临时目录真实复现“首次bootstrap中断”和“两记录丢失”两项失败；不是在KVM fixture里删除/修补authority。当前0b源使用持久lock标记，另拒绝已初始化目录丢失lock；完整原生race及TLS/KVM/cold正常回归另行通过。该正常回归不等于物理丢失或逐提交掉电故障验收，前序93报告不改写、不重新标成0b通过。

## 操作员配置契约（不是已验收安装器）

仅Linux静态ELF；非Linux CLI失败关闭，不回退host执行。在Linux构建：

```sh
GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -o /absolute/private/build/xandbox-gateway ./cmd/xandbox-gateway
```

部署前由操作员提供独立root私有目录、固定NodeControl出生归属与总cgroup/日志预算，见[操作约束](OPERATIONS.md)。本程序**不创建systemd unit、不自动把自身迁入cgroup，也不配置公网、CA签发或防火墙**。root需要chroot/setuid/setgid等权限；内核必须支持seqpacket/SCM_RIGHTS、sealed memfd与close_range(CLOEXEC)，不支持时失败，不能放宽目录或去掉检查。

`-config /absolute/private/gateway/config.json`必须root-owned0600，父目录0700且由可信root控制。示意结构如下；路径、域名需由操作员替换，不可原样当作已配置服务：

```json
{
  "version": 1,
  "policy_revision": 1,
  "state_dir": "/var/lib/xandbox-gateway/policy",
  "uid": 60001,
  "gid": 60001,
  "listen": "127.0.0.1:9443",
  "server_name": "gateway.example.invalid",
  "empty_root": "/var/lib/xandbox-gateway/root",
  "tenant_socket": "/var/lib/xandbox/state/api.sock",
  "backend_auth_file": "/var/lib/xandbox/auth.json",
  "certificate_file": "/var/lib/xandbox-gateway/server-chain.pem",
  "private_key_file": "/var/lib/xandbox-gateway/server-key.pem",
  "keys": []
}
```

- `keys: []`明确拒绝所有外部身份（包括gateway health/ready请求），不是无鉴权。条目字段为`token_sha256`、`tenant_id`、`max_instances`、`backend_token`、RFC3339 `not_before`/`expires_at`。backend token必须不同于对应外部key，且普通daemon启动authority内tenant/quota完全相同。
- **config包含明文私有backend token**，cert key及child内存snapshot也包含私钥；“外部只存摘要”不等于整个config无秘密。禁止commit、日志或把值放argv/env，不能将操作员配置给租户。被攻破的gateway可冒用所委托的租户backend能力，本设计不声称抵御此情形。
- `empty_root`必须root-owned0555且只含普通静态`gateway`文件；文件与root supervisor ELF哈希相同、单link独立文件（不能hardlink），父目录root0700。不挂载proc/dev/state，不留下宿主cwd/stdio/目录FD。可执行文件必须root所有、不可group/other写，安装时确保无并发替换。fixture证明固定启动，不是通用chroot逃逸防护认证。
- `state_dir`独立root0700，首次空目录、revision1；随后仅由生产代码创建lock/identity/journal，不手工复制/删改来“恢复”。config/auth/cert/key均root0600、拒绝symlink；tenant api.sock为root0600，state目录0700。tenant/operator/metrics socket不能混用或放宽。
- 明确预留专用UID/GID，不与guest/其他服务复用。listen为数值IP:port、port>=1024；server_name为精确DNS名，leaf必须有效并匹配，客户端独立验证可信CA。程序不替代issuer、时钟管理及外部信任链分发。
- 操作员原子替换完整私有config/cert/key、将policy_revision严格加1，向**确切持有的root supervisor进程**发SIGHUP。进程绑定不能改；backend authority启动时缓存，不能靠改路径文件偷偷更新。新revision可能已落盘但未成功ACK；只能以该已提交revision的精确snapshot恢复或后续revision，不回滚旧key。
- 本轮只检查健康同步policy后冷启动、无效reload与旧revision启动拒绝；未覆盖两个journal文件之间/每个fsync/介质错误/掉电窗口。不能把删除policy目录、重建identity或重置revision当作修复流程。

## 仍需完成

生产cgroup与日志/archive硬预算、真正operator/systemd部署验收、结构化持久审计/告警、issuer/续期/凭证分发及backend authority升级、其余policy逐提交故障与部分/损坏/超预算元数据的操作员恢复、长时间与开放到达饱和/公平性、升级备份回滚及其余M1–M4。不开生产就绪声明；PR保持Draft，Goal保持进行中。
