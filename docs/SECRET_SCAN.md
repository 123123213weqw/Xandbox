# 固定扫描器的历史秘密门禁

这是仓库级发布门禁，不是“凭证绝不存在”的证明，也不是运行态凭证分发或完整 M4。
CI 独立 `secret-scan` job 全量 checkout（`fetch-depth: 0`），不持久保存 GitHub 凭证，
先运行安装/失败关闭单测及实际扫描器正反例，再扫描所有本地可达 refs 的 Git 历史。
只以最终提交对应的 CI 结果为准，不能把工作树扫描或历史 green 转记为当前结果。

## 固定依赖与复现

[Gitleaks v8.30.1 官方 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)
的 Linux x86_64 / macOS arm64 archive 和解出的 executable 分别固定 SHA-256，
见 `scripts/secret_scanner.json`。归档摘要核对官方 release asset 元数据，二进制摘要
由实际归档的唯一 `gitleaks` regular member 独立计算。不是签名验证或可复现构建证明。
升级必须重新审阅规则、平台摘要和实际正反例；不使用浮动 latest。

```sh
# 在仓库根目录。新建调用者私有目录，不复用未知工具或覆盖已有文件。
umask 077
tools="$(mktemp -d)"
python3 scripts/install_secret_scanner.py --destination "$tools/gitleaks"
make secret-scan SECRET_SCANNER="$tools/gitleaks"
# 完成后由调用者移除这个确切的 tools 目录；不要把工具/报告提交仓库。
```

网络安装只接受 HTTPS 及指定官方 release 下载主机，保留证书校验，瞬态失败有限退避。
已有授权下载可用 `--archive /private/path/archive.tar.gz`，但不跳过任何摘要检查。
只读取唯一 regular member，不按 tar 内路径解包；独立校验二进制后才以 exclusive/no-follow
方式写入调用者拥有的 0700 目录。平台不支持、散列错误、目标已存在均失败关闭。

## 扫描合同

- 显式固定规则文件，沿用该固定版本的默认规则；拒绝目标根目录的 `.gitleaksignore`，
  **不能假设显式空 ignore 文件覆盖仓库 ignore**：该版本仍会额外加载 source 下的文件。
  禁用 inline `gitleaks:allow`，移除环境 `GITLEAKS_*` / `GIT_*` 覆盖，禁用全局/系统 Git 配置与 replace refs。
- 拒绝 shallow、graft、空历史和历史 submodule/gitlink；独立 submodule 对象库必须另行验收。
  固定 `--all --full-history --root -m --no-renames --format=medium --text --no-ext-diff --no-textconv`
  等选项，覆盖初始提交、已删除内容和仅 merge resolution 新增的文本。
  扫描前后核对 HEAD 和可达 commit 集合摘要；扫描期间变化不出具 clean 结论。
- 实际 scanner 的 `--redact=100` 在命令行指定。报告和 console 只留临时私有目录/内存，
  不上传 artifact，不回传 Match/Secret、路径、作者、commit message 或第三方错误文本。
  stdout 仅固定版号/二进制摘要、HEAD/可达集合摘要、commit 数、finding 数和闭集 rule ID。
- **退出 0 不足以通过**。错误级别 console 必须为空，report 必须可读且为有界 JSON list，
  退出码与 findings 必须一致，Secret 字段必须为 REDACTED；否则拒绝 clean 结论。
  有 findings 返回非零；工具不可用、超时、安装失败也非零，不等价于未发现秘密。

该版本扫描入口及 ignore 加载行为可核对
[官方固定版源码](https://github.com/gitleaks/gitleaks/blob/v8.30.1/cmd/root.go)，
Git patch 处理见[官方 Git source](https://github.com/gitleaks/gitleaks/blob/v8.30.1/sources/git.go)。

## 唯一项目例外及实测控制

默认规则对本项目公开的 `0123456789abcdef` 校验字母表产生过 7 个历史误报。
只在 `generic-api-key` 的 **secret 字段**允许这个精确完整常量，不按行/路径放行，
尤其不把所有 64 位 hex 当“安全 hash”：本项目真实 token 也可能是 64 位 hex。
默认上游规则自带的 allowlist 仍存在，不能称所有文件/模式都覆盖。

`test_secret_scan.py` 的 14 个纯控制覆盖安装摘要/regular member/链接/独占目标、
环境隔离、TLS redirect、错误 console 即使退出 0 也拒绝，以及非法/未脱敏/不一致报告。
其中四项固定正例的形状、结构化字符分布、无 RNG 依赖及实际 smoke 接线。
`secret_scan_smoke.py` 实际执行固定二进制，12 项控制包括：

- 固定、均衡字符分布的 provider-format 假 PAT、raw64hex api_key 检出；inline allow 无效；
  精确字母表放行但同一行旁边的假 token 仍检出；普通文本零 finding。
- 真实临时 Git 中：标记 binary 后已删除的假 token，在仓库/环境 allow-all config 及
  inline allow 存在时仍检出；仓库 ignore、graft、shallow 拒绝；merge-only 新秘密检出。
- 修改后的扫描器在执行前拒绝。所有假值不出现在 report 或 console，未使用真实凭证。

开发前序正例曾失败：主动设置 `GIT_GRAFT_FILE=/dev/null` 会在 Git 产生弃用 hint，
该固定扫描器可能记录 Git 错误但仍返回 0 与空报告。修正为移除环境 graft 覆盖并拒绝
实际 graft 文件，同时将任何错误级 console 视为失败；没有将失败前序当 clean 证据。
完整历史最终结果必须另跑，不能从正例通过推断。

### 固定正例，保留失败

源码 `789cdd4` 的原始 PR CI `40448607978` 在实际扫描器自检步骤失败，其他五个
job 通过；同头 push CI `40448602834` 六个 job 通过。失败不能用另一条绿灯替代，
也不直接重跑。原日志只有失败关闭的通用消息，原随机值与具体失败断言不可恢复，
因此**不能确认这次原始失败的唯一原因**。

另一个可重复的软件反例已确认：原正例使用随机字符，不保证符合固定默认规则的
熵下限。[上游固定规则](https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml)
对 generic-api-key 使用 3.5、github-pat 使用 3 的阈值；形状正确的低熵假值可能不检出。
固定一个可能的旧 RNG 输出，旧实际 smoke 三次失败；改为构造确定的均衡假值后，
同一 RNG stub 下完整十二项实际控制三次通过。它证明原控制的随机假设有漏洞，
不是还原原 CI 输入或代签新头 CI。

修正只作用于测试正例：两份 hex 各16字符均出现4次，provider 后缀36字符互异，
并避开默认规则的有序字母表 stopword。所有值仅为测试构造，不是凭证生成器。
没有修改扫描器、阈值、项目例外、扫描范围或失败关闭政策；所有原控制继续执行。
新提交仍需自己的 CI 与完整历史扫描，原失败记录不删除。

## 不覆盖

未提交/未暂存/忽略文件、不可达对象和 reflog、远端未获取的 refs、运行态数据、CI secret、
所有任意编码/格式或嵌套归档都不在承诺内；decode depth=5、archive depth=2，
不按文件大小跳过但有执行和报告上限。固定默认规则有启发式误报/漏报，不验证凭证有效性。
检出后应走撤销/轮换与历史处置，不能仅增加 baseline/路径例外让 CI 变绿。
