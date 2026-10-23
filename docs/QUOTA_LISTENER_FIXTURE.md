# TEST ONLY：重复clear错误与通知监听器失效

本文件是新增夹具契约，尚不是实测通过报告。生产 `sandboxd` 不依赖通知监听器，不新增故障/BPF/租户接口；额外seccomp/NNP仅是固定owned-L1测试层。

## 重复clear

`--quota-syscalls` 的三个clear子例现在必须在解除注入前收到至少3次成功发送的错误回复。每次都独立检查同一durable owner、已删除namespace和实际quota记录。clear-sync/read在每次错误后重置阶段，只在**下一次cleanup自己的SET之后**再命中；不把同一次clear后的preclear SYNC/GET重试冒充三个post-SET窗口。成功CONTINUE的SET计数也核对：clear-set仍仅reserve的1次；另两例至少reserve+3次clear SET=4次。

解除注入前另读API和一个有界、原子替换的私有ledger envelope，必须RECLAIMING/StoppedAt、无DestroyedAt，owner字节未变、namespace已空、新请求503；不能再次获取运行中FileStore的锁。然后正常CONTINUE恢复清理、旧key410、新真实KVM guest执行销毁/全部project清零。此处errno由TEST ONLY注入，不是物理存储故障。历史报告不追认为重复3次通过。

## 最后一个listener FD消失

两个固定且互斥的profile：`--quota-listener-reserve-loss` 和 `--quota-listener-release-loss`。分别在reserve首个SET或真实Ready guest停止/namespace删除后的clear SET入口关闭**最后一个**listener FD，不发送NOTIF_SEND，不CONTINUE该SET，也不伪造errno或成功。无任意PID/设备/FD/ordinal/程序参数。

根据[Linux6.8 seccomp实现](https://github.com/torvalds/linux/blob/v6.8/kernel/seccomp.c)和[通知接口文档](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)，失去监听器会使匹配调用失败，而不是默认放行。夹具仍要求owned-L1内固定raw sys_exit BPF捕获精确owned TGID/TID的首个`quotactl_fd`真实返回 **-ENOSYS**，不能只引用文档/接口500。BPF只记录首返回码，不代表统计所有后续重试；不在L0安装、不pin、不采集tracee内容。

reserve在SET前保存owner/ref/key/policy receipt并核对quota空；检查点没有旧L2 guest。release先实际KVM/UID/exec/quota/filter检查、保存旧boot及receipt，再DELETE；边界必须保留原owner、已知限额且usage0。选中SET不执行，receipt之前的真实reserve提交保持有效。

listener关闭后不重建，三次间隔检查durable RECLAIMING/StoppedAt、无DestroyedAt、owner bytes、quota未改变、新admission503。健康FS允许这些读回，与aborted-FS EIO夹具不同。503不是另行backend allocator探测。DELETE接收允许，不能把它当完整销毁。

之后仅power-cut自有L1，同盘冷启动先核对精确owner/policy/空namespace；reserve quota必须空，release必须精确已知限额/usage0。再以**无额外通知器**的普通启动回收旧ref/key410，新实际KVM/UID/exec/destroy通过、全部固定project清零；release新旧boot不同，reserve不虚构旧guest比较。不是生产观察器、所有事件系统失效或snapshot/shared-pin组合验收。

尚需固定源native/cross、两个profile冷恢复、重复clear实测、共享notifier/BPF兼容回归、只读资源审计和脱敏原始证据。整体quota并发/节点预算/其余持久窗口和M1–M4仍未完成，PR19保持Draft。
