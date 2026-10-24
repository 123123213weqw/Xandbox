# 独立 ingress 启动器（已实现，组合部署未验收）

新增 `cmd/xandbox-ingress-launch` / `internal/ingresslaunch`，明确选择**独立受限 ingress
service**，不把 gateway 假装计入普通 NodePolicy，也不改变 Go launcher v1 的单进程 exec
契约。当前只是部署组件，不是可直接使用的安装器；尚无真实 systemd 下该组合的 TLS→KVM、
轮换、崩溃和原盘恢复验收，不能沿用自定义 PID1 TLS fixture 或普通 UDS 部署给它代签。

```text
system.slice
├── xandbox.service             # 整个 daemon 父预算，含 node 与 manager helper 余量
│   ├── bootstrap / .control
│   └── node/{control,instances}
└── xandbox-ingress.service     # 独立 memory/pids/cpu/io 硬限制，不委派、不迁移其他进程
    ├── root connector
    └── 非特权、可执行文件专用 chroot 中的 TLS child
```

## 固定启动契约

CLI 只接受 `-manifest /absolute/root-private/ingress-launch.json`。未知参数、租户命令、
非 Linux、非 root、PID1 非 systemd、任何预检失败均退出，无 shell/mock/host-exec fallback。
失败输出只包含闭集阶段：platform、manifest、placement、composition、envelope、asset、exec。
不打印原始错误、策略、凭证或文件路径。

manifest version1 的字段：

| 字段 | 含义 |
|---|---|
| unit_root | system.slice 直属、受限 ASCII 名称的 service cgroup |
| policy_state_dir | 独立 `/srv/` 下的私有持久 policy 目录，不与 daemon state/runtime 重叠 |
| gateway | 静态本机 ELF 的 path/SHA256，文件名必须是 xandbox-gateway |
| config | 现有 gateway.Config 文件的 path/SHA256，启动时核验整个文件 |
| node_launch | 现有普通 Go launcher manifest 的 path/SHA256；不是另抄一套 daemon 配置 |
| device | 绑定 node backend 的规范 major:minor，拒绝多行/别名/0:0 |
| ingress | 独立 service 的 memory_max/pids_max/cpu_quota/IO bytes/s/ops/s |
| reserve / capacity | 显式操作员/宿主预留与部署核算上限，维度同上 |

manifest/node manifest 各≤16KiB，config≤512KiB，auth≤64KiB，ELF≤64MiB。
拒绝未知/重复键、路径别名、单位或数值越界。root 文件由现有 launch FD-walk/NOFOLLOW
实现读取，要求 root 所有、普通单链接、私有策略权限及固定摘要；不重新实现 TLS/鉴权解析器。
使用现有 gateway.Config 类型、firecracker.ValidateAdmissionConfig 和原 launcher 的 nested
backend 约束。socket 必须是被固定 node state 的 api.sock，authority 必须是该 node manager
RuntimeDirectory 的 auth 副本，字节摘要与 node 原始认证配置相符。

启动器只读核对 daemon 父预算及 ingress 自己的真实 cgroup2 文件。ingress 必须直接位于指定
service root、无子组/委派 helper，直属进程恰好为自身 PID；memory/swap/pids/cpu/io、
memory.oom.group 都必须匹配。不会“修复”漂移、收养/杀死进程、创建或迁移 cgroup。
每个实际观察到的线程要求 UID/GID0、NNP1、inheritable/ambient0，以及 effective/permitted/
bounding **精确**为 SETUID/SETGID/SYS_CHROOT 三项；不授予 SYS_ADMIN、SYS_RESOURCE 或
DAC 绕过。exec 前再次核对位置与能力，拒绝 FD>2 可继承；以核验 ELF FD 同 PID exec 普通
xandbox-gateway，固定环境和 argv。gateway 自身仍负责 child chroot/UID/FD、TLS policy 与
持久 revision 的验证，不因启动器而弱化。

## 总体核算不是伪造一个硬父组

每个维度必须满足：**整个 daemon unit 父上限 + 整个 ingress 上限 + 显式 reserve ≤ capacity**。
用逐项减法拒绝溢出；不是仅计 NodePolicy 或仅计 TLS child。CPU 周期100000µs，IO按每个方向
分别限制。reserve 包含什么、是否够用仍是部署容量验收的内容。

这两项服务当前仍是 system.slice 下的兄弟，`capacity` 是受审策略的**核算上限**，不是共同
父 cgroup、实际剩余 RAM/CPU/磁盘证明或对其他主机工作负载的限制。reserve 尚无独立硬域，
OS、日志和 operator 的预算、硬盘总体容量、长负载/公平性也没有因此通过。不能把本组件
宣传为全节点资源封闭或生产准入完成。

## 候选 unit 与生命周期

`Manifest.Unit` 只生成候选文本，不写 `/etc`、不调用 systemctl 或安装包。所有插入的路径/
名称限定为不含空白、换行、`%`、环境展开或 shell 字符的安全字面量；设备仅接受固定整盘名。
配置 Delegate=no、精确父限制、NNP、上述三项能力、只读 cgroup/系统、仅 policy state 可写、
私有 tmp/devices、KillMode=control-group、Restart=no，无 ExecStartPre/Reload/Stop helper。
`OOMPolicy=kill` 对应 memory.oom.group=1，见
[systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#OOMPolicy=)。

候选 ingress 具有 BindsTo/After/PartOf=daemon，WantedBy=daemon；启用关系需要未来安装器
实际创建，见[systemd.unit](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)。
Type=exec/After **不等于**普通 API READY，guard 只核对已存在的 authority 副本/预算；启动
竞态可能失败关闭，必须用真实组合测试确定 readiness/启动编排，不靠无限重试掩盖。
目前没有证明停止传播、崩溃关闭或自动重启顺序。

## 轮换必须连同启动 pin 发布

config 是普通 gateway 使用的原 reload 路径，不是永远钉死在 RuntimeDirectory 的副本。
特权 operator 轮换时须先发布新的 config **及对应 manifest digest**，再向正确 main PID
发送 SIGHUP；需要确认 gateway 持久 revision 与实际新证书/令牌接受结果。两个文件发布不是
原子事务，中间崩溃会在重启时失败关闭，须完成期望版本发布；不能以旧 manifest 盲目重启。
已有 gateway 的 sameBinding 和持久 policy 提交/拒绝回滚逻辑仍有效，不能删 state 重新
bootstrap。启动器没有增加证书分发/PKI、事务化安装/回滚或恢复证明。

root/manager/发布流程仍是信任根：配置摘要检查后，gateway 会按既有路径重新读取；可信 root
可以替换配置或原地写 ELF。这里没有恶意 root 防护、远程证明或源路径跨 root 变更原子保证。

## 当前验证与后续门槛

新增严格 schema、五维超额/溢出、重叠绑定、全部 kernel readback 漂移/未知子组、各线程
能力字段缺失/重复/越界、CLI错误脱敏和 unit 注入控制。模型证明只读校验顺序，不等于内核
运行；交叉编译不等于 Linux 原生成功；原生单测不等于 privileged systemd 组合通过。
现有普通 daemon/gateway 的发布字节会单独比较；launch 包新增共享读取/校验入口会改变
重新构建的普通 launcher ELF，历史26f3报告不能给新的 launcher 字节代签。

下一步必须在 owned systemd L1：精确 envelope/能力/ELF/进程归属，真实双租户 TLS→KVM，
启动前漂移拒绝且无 TCP child、正常 stop/main crash 与独立 ingress 关闭、key/leaf轮换和
同盘 cold 恢复。然后补 catalog、可复现安装升级/备份及独立操作员。未做共享 L0 部署修改。
整体[生产门槛](PRODUCTION.md)仍未完成。
