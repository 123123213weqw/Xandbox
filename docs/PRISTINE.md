# 实验性干净模板初始化闸门

**仅为快照组件基础设施，不是 sandboxd 快照功能，也不代表生产就绪。** 本页实测报告对应的服务仍冷启动新VM。后续新增 [catalog/schema2接入代码](CATALOG.md)，尚未通过真实KVM服务验收；原报告不覆盖新路径，也没有预热池。M3不因此完成。不得把执行过任务的 VM 制成模板。

## 为什么不能直接恢复现有 VM

冷启动路径把 Ref 写在不可变的内核启动参数中。直接克隆会复制旧身份，也会复制内核/用户态随机状态与启动身份。Firecracker 的 [快照说明](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/snapshotting/snapshot-support.md) 要求恢复期间保持内存 backing 不变，外部管理磁盘，并处理 vsock 断连；[克隆随机状态说明](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/snapshotting/random-for-clones.md) 特别说明 VMGenID 通知存在窗口，用户态缓存另需处理。以下闸门是 Xandbox 的具体工程设计，不是上游对本项目的认证。

## 两条互斥启动路径

- 普通冷启动：`xandbox.guest=1 xandbox.id=... xandbox.generation=...`，保持原端口900协议。
- 未分配模板：`xandbox.guest=1 xandbox.pristine=1`，**不允许出现任何 id/generation 参数**，尚不挂载工作区、不启用执行器，仅在 vsock901接受宿主CID2。
- 重复/缺失/混合启动参数拒绝；普通宿主不满足镜像标记、guest CID与启动参数守卫，不能初始化执行器。

```text
未分配模板 WAITING（仅901）
    → 首个 initialize 原子认领 CLAIMED（不是 READY）
    → /run/xandbox-init/claimed 独占创建，标记存在后进程重启不能重开闸门
    → 注入64字节宿主CSPRNG种子，RNDADDENTROPY + RNDRESEEDCRNG 显式完成
    → 设置 guest CLOCK_REALTIME、只读 proc boot_id 视图和 machine-id
    → root-only receipt：Ref + bootID + 请求哈希，不含种子/nonce
    → exec 固定 agent --initialized，替换 agent 自身的用户态缓存
    → 检查封存记录，才挂载私有工作区并建立执行cgroup
    → 仅900正常健康/执行，901随exec关闭
```

协议与普通执行帧分离，严格JSON且有长度/连接/截止限制；没有任意初始化argv或特权 reset RPC。首个请求包含新的 Ref、256-bit nonce、512-bit seed、UUID与guest时间。摘要覆盖整个请求；重复认领不重复初始化，初始化失败永久关闭。丢失认领ACK时只能用**原请求**确认正常健康响应的 Ref、bootID和摘要全部匹配，不得换种子再试、降级成普通健康检查或转为宿主执行。

`xandbox-guestctl bootstrap-state` / `initialize` 是操作员组件诊断命令，不是租户接口。`initialize` 每次调用生成新请求；调用失败不得作为透明重试再次执行，需停止该候选并以新Ref重建。服务级持久化/恢复策略尚未接入。

## 信任与未完成部分

- 只信任经过校验、从未接收租户输入的模板和宿主操作员；ACK摘要不是远程证明，也不防恶意宿主root或已入侵guest内核。
- 宿主 cgroup 与 BOOTTIME guardian 租约仍独立约束每个恢复实例；guest修改时钟不影响宿主TTL。初始化不能绕过这些资源归属。
- guest `claimed` 是RAM内的进程重启栅栏，不是持久化宿主归属或跨VM全局去重。回到原始快照仍为未分配状态，宿主必须签发全新Ref/种子。
- `CLAIMED` ACK先于文件标记创建，ACK本身只代表进程内认领。若agent恰好在两者之间死亡，尚无特权初始化副作用，但新进程可能再次显示WAITING；这绝不能证明该候选可重新分配。宿主一旦发出初始化，只能确认原请求的精确正常健康响应，否则必须停止候选并以新Ref重建，不能因WAITING而换种子重试。跨该窗口的硬件故障验收仍未实现；新schema2路径已有服务端不可逆尝试记录代码，但尚待真实KVM验证。
- `/proc/.../boot_id` 是guest中的只读文件视图，未重启内核，也不宣称重新生成所有可能的内核/应用标识。文件系统UUID等仍来自模板；生产镜像需要完整的服务、缓存与身份清单。
- 新agent通过exec清除自身继承的运行时缓存；模板中BusyBox init仍存在。生产模板禁止额外的随机状态缓存服务，需独立审计。
- 种子在回调后尽量清零且不写入回执/报告；Go/JSON中间副本、宿主RAM、崩溃转储与存储介质擦除不因此得到安全擦除保证。不得将完整请求写日志或公开内存快照。
- 共享memory backing在全部VM退出前不得修改/删除。CRC不是真实性校验；可信manifest、不可变catalog、版本兼容策略、共享引用与崩溃重建仍未实现。
- 当前组件测试复制私有磁盘并共享只读memory inode，不是reflink/池化性能实现；不从两个克隆样本推导加速、P95或SLO。

## 本轮实测证据

[真实快照组件报告](validation/kvm-pristine-bootstrap-2026-10-22.json) 已通过：从一个未分配模板恢复两个真实KVM guest，9条断言均通过，runner退出0，专属宿主cgroup和运行目录均已删除。9条断言是一个双克隆组件用例，不是9种独立故障场景。新agent另外通过 [冷启动组件15项回归](validation/kvm-pristine-cold-guest-2026-10-22.json)，包含实际KVM fd、进程树取消、UID/no_new_privs、seccomp和私有工作区。

[当前源码冷路径服务回归](validation/kvm-pristine-cold-service-2026-10-22.json) 另通过30项检查，覆盖鉴权、监督/崩溃回收、会话与受控fsync；仅5次新VM闭环为兼容性烟测。停止/GC与绑定fsync各9条断言展开现有用例，不另算18场景。它验证新agent不破坏现有冷路径，不验证服务快照功能。

报告固定到源码 `ec4e56ef417c300d5a302ba245839de5093e7806` 与具体二进制/镜像SHA256；测试材料和快照本体不公开。记录的两个时长包含未优化的私有文件复制、jailer和多条诊断命令，不是切换首命令指标，不能与冷启动样本直接比较或宣称加速/P95/SLO。

当前KVM覆盖正向双克隆和身份拒绝；认领后的guest进程崩溃、部分初始化失败、catalog/共享引用故障和持续恢复压力尚未实测。并发/失败回调/丢失ACK的协议单测不能替代这些硬件故障验收。

## 显式 Linux/KVM 组件验证

普通 `go test` **跳过**硬件用例，跳过不是KVM验收。需要root、Linux amd64、已打补丁的Go1.27.3、独立cgroup v2、KVM、mkfs.ext4，以及 [guest镜像构建步骤](GUEST.md)。不需要Rust编译或修改宿主时钟/路由。

在独立节点从当前源码构建agent、warden和测试二进制，再用固定Alpine输入构建新的initrd：

```sh
GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/xandbox-agent ./cmd/xandbox-agent
GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/xandbox-warden ./cmd/xandbox-warden
GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 go test -c -trimpath -buildvcs=false -o bin/pristine.test ./internal/guestinit
```

创建root所有的0600私有fixture JSON（字段大小写与下列一致）；所有二进制/镜像为绝对路径，填入实际完整SHA256。选择未使用的专用目录、cgroup、宿主UID范围和报告路径；日志/报告目录应root私有，位于Root之外。不能选已有业务目录，测试完成会删除其专属Root。

```json
{
  "Root": "/srv/xandbox-pristine-unique-runtime",
  "Cgroup": "/sys/fs/cgroup/xandbox-pristine-proof-unique",
  "Firecracker": "/absolute/pinned/firecracker",
  "Jailer": "/absolute/pinned/jailer",
  "Warden": "/absolute/bin/xandbox-warden",
  "Kernel": "/absolute/pinned/vmlinux",
  "Initrd": "/absolute/new/guest.cpio.gz",
  "Report": "/absolute/private-proof/report.json",
  "SourceRevision": "replace-with-40-character-source-commit",
  "UIDStart": 390001,
  "SHA256": {"firecracker": "replace", "jailer": "replace", "warden": "replace", "kernel": "replace", "initrd": "replace"}
}
```

```sh
sudo -n env XANDBOX_KVM_PRISTINE=1 \
  XANDBOX_KVM_PRISTINE_FIXTURE=/absolute/private-proof/fixture.json \
  ./bin/pristine.test -test.run '^TestKVMPristineBootstrapSnapshot$' -test.v -test.timeout 180s
```

用例创建未分配模板、暂停并输出完整快照，终止builder，再恢复两个独立jailer/cgroup/写盘的VM。builder输出限制为512MiB，恢复VM仍限制128MiB文件写入；均有独立短租约与硬截止。检查初始化前不可执行、精确认领/初始化身份、guest时钟/身份重绑定、UID、工作区隔离、901关闭、共享inode不变、先停止后删私有文件与交叉Ref拒绝。测试只运行固定的可信宿主mkfs及VMM工具，租户命令始终通过vsock在guest内执行。

仅在测试进程终态0、所属cgroup为空且专属目录已删除时接受报告。失败时检查私有日志并仅回收该fixture的资源，不能通过重新启动同一runner掩盖错误；不得公开原始日志、fixture、Ref、种子或快照。测试若无法确认停止，会保留backing文件供操作员恢复，不冒险删除活VM所需的文件。
