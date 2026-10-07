# 更新日志

本文件记录 `wist-release` 的所有重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [0.4.0] - 2026-10-07

### 新增

- **发布计划 id 语义化**：`rollout::plan_id(action, unique)` 生成 `plan-<action>-<yyyyMMdd-HHmmss>-<short>`
  —— 一眼能读「做什么 + 何时发的 + 短唯一后缀」，取代此前纯摘要式（`plan-<sha256>`）的 id。
  同一秒内多发也不撞（短后缀取带纳秒的 `unique` 摘要前 6 位）。

## [0.3.2] - 2026-10-07

### 修复

- **`entry_status_for` 归一化各上报方的措辞**：此前只认 `succeeded` / `failed`，而 gwlinkd 的
  网关升级台账用 `done`（成功）/ `unverified`（执行器报成但未被佐证）/ `rolled_back`（已回滚）。
  这些措辞会被折成 `dispatched`，导致条目永不了结、阶段不算完成 —— 升级**成功后**计划反而卡在
  `rolling`，人工推进又被闸门「阶段未了结」挡住。现归一化：`done → succeeded`，
  `rolled_back` / `unverified → failed`（未佐证的成功**不认成功**）。

## [0.3.1] - 2026-10-06

### 变更

- **底座换成 [`wist-artifact`] 0.1**：制品的**传输与校验**口径（取来源 / 摘要 / 版本比较 / 命名与
  路径安全）下沉到新 crate；本 crate 的 `package` 模块**原样转出**（`pub use`）——
  **公共 API 与调用点零变化**（`wist_release::package::read_verified_source` 等照旧）。
- 本 crate 从此只装**发布域**：包身份解析（`read_package_identity` / `read_binary_package_identity`，
  需要 `flate2` / `tar`）与发布计划（`rollout`）。**被管端（agentd）不再依赖本 crate** —— 它只需要
  底座那一层，不必背发布域概念，也不会凭空多出解包依赖。
- 顺带：本 crate 不再直接依赖 `ring`（摘要口径改用纯 Rust 的 `sha2`，在底座里）与 `reqwest`
  （取来源也在底座里）。

[`wist-artifact`]: https://crates.io/crates/wist-artifact

## [0.3.0] - 2026-10-06

`rollout` 补上「怎么放行」那一半：除了阶段切分（0.1.0 起），把**推进闸门 / 批次节流 / 条目
状态折叠 / 确定性 work_id** 也从网关收进来。这些原本只活在网关（`app/rollout.rs`），
而中心只算阶段、没有闸门语义 —— 收进来之后两边是同一套。

### 新增

- **推进闸门**：`validate_advance_rule`（`manual` / `all_succeeded` / `success_rate:<0..=100>`
  及对应常量）、`phase_settled`（全终态才算了结，**空阶段不算**）、`phase_should_advance`
  （成功率用**整数**比较避浮点误差；`manual` 永不自动放行）。
- **批次节流**：`phase_start_targets`、`next_refill_targets`（`batch_size <= 0` = 不节流）。
- **条目状态折叠**：`entry_status_for` —— 上报的工作状态归到
  `dispatched` / `succeeded` / `failed`（条目只区分「还没做 / 在做 / 做成 / 没成」）。
- **确定性 work id**：`target_work_id(plan_id, target_id)` = `work-<plan_id>-<sha256 前 12 位>`，
  不含时间，配合落库的 upsert 幂等（同一目标重试物化不会并出两件升级）。
- `TargetStatus<'a>`（`(target_id, status)`）：把「目标的状态表」作为入参形状定下来，
  口径函数不依赖任何存储类型。

## [0.2.0] - 2026-10-06

把「制品与发布计划」的口径再收窄一层：**路径安全、摘要、版本比较、取包入口**，让 agentd
也能用同一份（它以前是第四份实现，还自带一套哈希库）。

### 新增

- **路径段安全**：`is_safe_path_segment`（组件名 / 版本号 / 文件名必须真的只有一段）——
  管理面发布与**未鉴权**的制品下载路由据此把 `..` 拒掉；`artifact_filename` 的回落名也保证
  永远是安全段（此前只防来源末段，`component` / `version` 原样拼进去）。
- **内容寻址 id 泛化**：`content_id(prefix, sha256_hex)`；`package_id_for_sha256` 即
  `content_id("pkg", …)`，知识库包的 `kbp-` 也走同一份逻辑。
- **取包入口按机制 / 策略分开**：
  - `read_source_within(source, max_bytes, timeout)` —— 上限与超时由调用方给；
  - `read_source_with_client(client, …)` —— **带入调用方自己的 client**（agentd 的 mTLS 身份靠它）；
  - `read_local_source(path, max_bytes)` —— 只要本机路径那一支（不必为它构造 client）。
- **`PackageError::TooLarge`**：来源超限单独一类，调用方可以回「太大了」而不是笼统的「拿不到」。
- **摘要口径** `parse_digest`：可选 `sha256:` 前缀（大小写不敏感）、大小写不敏感、**校验 64 位 hex**；
  `read_verified_source` 走它，因此「摘要填错」会给一句「这不像摘要」而不是等成一次「不相符」。
- **版本比较** `parse_version` / `version_is_newer`：点分数字段逐段按**数值**比
  （`0.10 > 0.9`、`0.1.0 > 0.1`），带 `-pre` / `+meta` 只看数字段；认不出来返回 `None`
  （升级方向不可判时应当拒绝，不猜）。

### 修复

- **本机路径也受大小上限**：此前只有 http 分支会拦超限，`/abs/path` 会把任意大文件读进内存。
- **`normalize_version` 认大写 `V`**：与解析侧 `looks_like_version` 同口径；此前包内自报 `V1.2.3`
  与运维手输 `v1.2.3` 会被误判成版本不符。
- **`triple_start` 不再被包名里的架构词骗**：`wist-arm-stack-1.2.3` 的 `-arm-` 曾被当作
  target-triple 起头，导致版本整段丢掉；现在要求候选**前一段还能切出版本**。
- **`plan_phases(targets, 0)` 报错**，而不是静默当成 1 阶段。

### 变更（不兼容）

- `PackageError` 多了 `TooLarge` 变体 —— 对它做穷举 `match` 的调用方需要补一支。

## [0.1.0] - 2026-10-06

首个版本。

### 新增

- **`package`**：安装包内核 —— 来源读取（本机绝对路径 / https）、期望摘要校验（可带 `sha256:` 前缀）、
  身份解析（`version` / `arch`）、内容寻址 id（`pkg-<sha256[:16]>`）、制品命名（防路径穿越）。
  - 身份解析提供两套口径：`read_package_identity`（宽松，可回落来源文件名 —— 中心托管任意包）、
    `read_binary_package_identity`（严格，只认包内目录名且必须带已知 target-triple —— 网关的
    agent 安装包）。此前这两套口径分别散落在中心与网关各自的实现里。
- **`rollout`**：发布计划的灰度阶梯 —— 由「目标 + 阶段数」切出**互不重叠**的阶段
  （`1 个（金丝雀）→ 10% → 30% → 70% → 全量`），并给出「台数能支持哪些阶段数」与阶段规模文字。
  运维只选阶段数，不填任何目标 id。
