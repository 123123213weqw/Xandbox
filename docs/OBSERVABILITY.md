# 实验性管理指标与有界观测

**不是生产可观测性验收。** 指标不是审计账本，不证明任务成功、宿主停止或物理擦除。结构化审计、告警闭环、独立操作员部署及真正持续/并发负载仍未完成。

## 独立管理面

显式 `sandboxd ... -metrics` 才创建私有 `state-dir/metrics.sock`（0600），不监听TCP，不在tenant API注册 `/metrics`，不提供pprof、环境、堆或对象调试接口。状态目录仍须0700且由controller独占。离线migration不能同时开启指标。退出移除socket，重启重建gauges、清零进程计数。

```sh
# 只由与控制器相同宿主UID的可信操作员采集；路径替换为自己的私有state。
curl --unix-socket /absolute/private/state/metrics.sock http://localhost/metrics
```

这是**宿主UID管理权限**，不是新的租户角色：bearer token不能授予进入私有目录/连接管理socket的权限；能使用同一宿主UID的进程已在可信管理域内，其Authorization头无意义。不要将socket挂载进guest、授权网关租户访问，或未经另行管理鉴权就转发为TCP。root controller部署时collector也需要可信root/受控代理，不能为方便采集把目录/socket改成公开权限。ACL、代理和完整部署审计仍需另验。

只支持无query的GET `/metrics`，Prometheus0.0.4文本；禁止任意label/query。最多16个已接受连接、同时2次渲染；超额连接关闭或scrape503。header1秒、读/写/idle2秒，配置MaxHeaderBytes4096。没有原始错误、令牌、tenant/Ref/generation、key/spec hash、argv、输出或宿主路径label。客户端需自身限时/退避，抓取失败不是VM停止证明。

## 指标语义

`xandbox_operation_seconds` 是固定9种operation × success/error × 固定桶的进程内直方图；含桶/计数/sum及13个gauge，共319个时间序列，不随租户/实例/历史数增加。

- `create_call`：Core创建调用全程，含参数/容量拒绝、幂等重试、ownership/READY写入与新VM准备。**调用次数不是新建VM数**。
- `stop_attempt`：非no-op的停止尝试，含fence写入、driver Stop、已接受执行退出和STOPPED持久化。进入单代operation gate前等待不含在此时长内；重试分别计数，不代表唯一VM数。
- `cleanup_attempt`：已满足停止条件的回收尝试，含RECLAIMING、driver Cleanup与DESTROYED持久化；失败重试分别计数。不是从用户删除请求开始的时延。
- `session_open_call` / `session_switch_call`：Broker调用时长，含拒绝/幂等重试；不含HTTP传输或第一条新命令成功。以上调用/尝试使用Go单调时钟，宿主挂起时间不保证纳入。
- `candidate_ready_offset` / `admission_revoked_offset` / `fence_to_commit` / `route_published_offset`：仅成功发布且阶段时钟有效的**新绑定事务**；包含初次open，不在同key重放时重复记阶段。Linux采用BOOTTIME，与 [SESSIONS.md](SESSIONS.md) 响应语义相同。撤销offset是内存阶段边界，不是Stop确认。

固定秒桶：0.001/0.005/0.01/0.025/0.05/0.1/0.25/0.5/1/2/5/10/30/60/+Inf；sum为微秒精度。粗桶不适合宣称毫秒精确尾延迟；`histogram_quantile`只是聚合估计，客户端首命令/停止/回收分布仍需外部独立观测。

Gauges：累计Core records/预算、仍占实例配额allocated/预算、两个池的queued/running/workers/队列容量、累计session records/预算。包含正在回收及持久化不确定的分配；DESTROYED后才减allocated，永久tombstone不减records。session_records包含CLOSED，不是活路由数。

写入仅固定原子加法，不执行I/O/日志/回调，不等待生命周期锁。采集仅读取原子值、channel长度与不可变配置；不拿Manager/实例/Session锁，不读账本、driver、/proc或runtime堆。因此慢collector不持有Stop/GC权威锁。快照不是事务：跨gauge、hist sum与bins可能来自稍不同时刻；同次+Inf与count从同一组采样bins推导，保持一致。进程崩溃可丢失尚未记入的末尾事件，重启reset正常，**不能把它用作可靠审计或结算**。

## 验收入口与未完成项

- Go race测试覆盖固定桶/输出大小、并发写入与采集的count/+Inf一致、路径/权限、慢scrape503、全部生命周期/会话锁被占时仍能采集、释放配额与保留tombstone。
- `make smoke`增加 `scripts/metrics_smoke.py`：默认关闭、不可覆盖普通文件、真实进程的独立socket、拒绝敏感字段、管理连接压力下Stop/回收、进程重启计数reset。mock不是隔离/性能证据。
- KVM入口 `scripts/kvm_driver_smoke.py --metrics --session-test ... --load-cycles 40`：固定私有fixture中的真实root/不同宿主UID拒绝、管理连接压力下旧guest停止；可选1..50次新VM切换闭环及外部/proc RSS、cgroup memory.current、FD与各阶段分布。只操作runner自己拥有的cgroup/PID，保留原故障回归。
- 闭环每次等旧VM完整回收再开始下一轮，最多两代同时存在；不等于队列饱和、公平性、多租户竞争或生产持续负载。20ms资源采样可漏峰值；RSS不是PSS，cgroup memory.current含page cache/kernel。永久metadata随历史增长至预算，不能据短测宣布常驻内存与历史完全无关。

新路径必须实际运行后才能发布验收结果；此前27项报告不自动覆盖指标代码。完整结构化审计、告警、备份/升级/回滚、长期容量曲线、真正混合持续负载与生产SLO仍保留在 [PRODUCTION.md](PRODUCTION.md) 门槛中。
