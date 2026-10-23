# TEST ONLY：部分 workspace 复制失败与存活 keeper

新增夹具尚在验收，**不是通过报告**。生产Go/daemon不增加故障开关，不把已完成的quota双租户240次切换重新当成待验收或该新故障的替代证明。

## 明确的独立规格

固定 `--quota-partial-copy` / `quota-copy-v1`：L1 RAM3GiB、raw disk4GiB、外层cgroup4GiB，CPU4/pids128/swap0/noNIC/hard900秒；独立QMP核对3GiB。启动前L0 available RAM≥8GiB、free disk≥12GiB。普通node容量2、租户2、UID/project slots4、192MiB/128inode。catalog retained entries4 / max bytes2GiB在首次绑定前固定：需要保留旧keeper pin，同时发布新的**从未分配**export声明；不能在线扩大既有binding。旧2GiB profile与quota-switch-v1均不改变，不宣称生产全局node admission。

先在本L1真正build UNASSIGNED模板、两个component clones、普通catalog共享/pin/GC前置检查；不从L0重标HostABI，也不导出已分配clone。然后停掉空的普通daemon，以额外TEST ONLY seccomp/NNP启动层exec同一个未改动的普通daemon，capacity2。只允许固定无参数RPC和固定child mode，L1 PID1/marker/root、child/architecture/配置/FD转移均有guard。

## 实际部分复制，而不是已完成复制后的假故障

生产 `copyAsset` 使用128KiB Read/MultiWriter WRITE，不是copy_file_range。测试只通知完整128KiB的SYS_WRITE；其他syscall直接允许，非目标WRITE使用CONTINUE进入真实内核。定位固定workspace路径的真实FD、原daemon incarnation/TGID:TID/ELF、offset/access及同inode，**不读取tracee buffer或任务payload**。

先保留一个已实际KVM/UID65534/marker/boot及quota/filter核对的keeper。再对新Create在workspace已复制16MiB、下一次128KiB WRITE入口暂停：检查持久attempted owner v4、未initialized、独立project继承、空且已存在的cgroup、无VMM/共享links/执行文件；workspace确实16MiB/root0600/single-link。健康观察器Q_SYNC+syncfs后，独立遍历jail/root/workspace三个inode，要求真实quota space/inodes与st_blocks计数一致；此同步只为稳定测试前缀，**不是生产提交/时延测量**。

同时检查API及原子私有ledger仍CREATING/无Stopped或Destroyed、旧exec409、第三个Create503、两个template pins。退役模板后GC必须0，keeper仍能执行/读取原数据。之后只向该WRITE发送一次TEST errno EIO，不伪造成功；普通Create必须500且私有Prepare日志含EIO，普通GC后owner/jail/cgroup消失、该project全零、原key410。

保持旧keeper pin存活，从原never-assigned export发布新声明并激活；新Create必须在旧quota清零后以新ref/template、同UID/project和干净真实guest复用slot。旧keeper仍保持同boot和数据，共享backing保留至最后pin释放。新实例/keeper分别普通销毁；最后GC恰好删除旧退役模板，四个project全零，普通daemon reaped/owned cgroup root移除。

## 不能扩大解释

- 暂停的是seccomp notification wait，**不是实际filesystem D-state**；错误由TEST errno返回，**不是物理EIO**。CONTINUE计数是成功提交回复数，不是所有WRITE完成或时延统计。
- 该profile只有一次L1开机，没有部分Prepare掉电/任意未同步prefix恢复证明；不能拿健康同步前缀代替in-flight host power cut。
- 未完成的partial-copy冷恢复、owner unlink/dirfsync/catalog锁内持久窗口、其他keeper/shared-pin故障组合和节点总预算仍要继续；完整M1–M4/独立操作员/SLO/生产验收未完成，PR19继续Draft。
