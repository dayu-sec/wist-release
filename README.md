# wist-release

`wist` 发布域的**纯逻辑**内核：安装包与发布计划两件事的口径，只此一份。

[![crates.io](https://img.shields.io/crates/v/wist-release.svg)](https://crates.io/crates/wist-release)
[![docs.rs](https://img.shields.io/docsrs/wist-release/latest.svg)](https://docs.rs/wist-release)
[![Downloads](https://img.shields.io/crates/d/wist-release.svg)](https://crates.io/crates/wist-release)
[![CI](https://github.com/dayu-sec/wist-release/actions/workflows/ci.yml/badge.svg)](https://github.com/dayu-sec/wist-release/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

「包管理」和「发布计划」在两侧应用里原本各写一遍（中心的托管制品发布、网关的 agent 包与灰度
升级），口径很容易漂移：同一套阶梯切分、同一套包身份解析，改了一边忘了另一边。本 crate 把这两块
**纯逻辑**抽出来共用 —— 不含存储、不含 HTTP 端点、不含鉴权，那三层仍由各应用自己负责。

## 模块

| 模块      | 内容                                                                     |
| --------- | ------------------------------------------------------------------------ |
| `package` | 安装包内核：来源读取（本机路径 / URL）、摘要校验、身份解析（version/arch）、内容寻址 id、制品命名、路径段安全、摘要与版本口径 |
| `rollout` | 发布计划的灰度阶梯：由「目标 + 阶段数」切出互不重叠的阶段（1 → 10% → 30% → 70% → 全量） |

`package` 里除了安装包身份，还有几个**同一套口径只该有一份**的小件：

| 口径 | 入口 |
| --- | --- |
| 取来源（机制 / 策略分开） | `read_source`、`read_source_within`、`read_source_with_client`、`read_local_source` |
| 摘要 | `sha256_hex_bytes`、`parse_digest`、`read_verified_source` |
| 版本 | `normalize_version`、`parse_version`、`version_is_newer` |
| 内容寻址 id | `content_id`、`package_id_for_sha256` |
| 路径段安全 / 命名 | `is_safe_path_segment`、`artifact_filename` |

### `package` 的两套身份口径

安装包的身份解析有两种合理的严格度，本 crate 各给一个入口，调用方按包的类别选：

| 函数                         | 场景                       | 规则                                                                 |
| ---------------------------- | -------------------------- | -------------------------------------------------------------------- |
| `read_package_identity`      | 中心托管任意包             | 先看包内顶层目录名，读不出**回落来源文件名**（部署栈包顶层是 `sys/…`，版本只在文件名里） |
| `read_binary_package_identity` | 网关的 agent 二进制安装包 | **只认**包内目录名，且必须切出**已知 target-triple**；读不出架构就整体留空，绝不把版本错切出来 |

## 消费方

- [`wist-center`](../wist-center) —— 托管制品的发布（包录入、发布计划）。
- [`wist-gateway`](../wist-gateway) —— agent 安装包的获取与灰度升级。

## 相关 crate

- [`wist-control`](../wist-control) —— 中心面 seam 报文与领域模型。
- [`wist-api`](../wist-api) —— agent 面 seam 报文。

## License

[Apache-2.0](LICENSE)
