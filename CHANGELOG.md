# 更新日志

本文件记录 `wist-release` 的所有重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

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
