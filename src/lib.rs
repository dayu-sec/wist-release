//! wist 发布域**纯逻辑**（不含存储 / 端点 / 鉴权）。
//!
//! 两个模块：
//! - [`package`]：安装包内核 —— 来源读取、摘要校验、身份解析（version/arch）、命名。
//!   身份解析有**两套严格度**：宽松口径 [`package::read_package_identity`]（可回落来源文件名，中心托管
//!   任意包）与严格口径 [`package::read_binary_package_identity`]（只认包内目录名且必须带已知
//!   target-triple，网关的 agent 安装包）。
//! - [`rollout`]：发布计划的灰度阶梯 —— 由「目标 + 阶段数」切出互不重叠的阶段。
//!
//! 两侧应用（`wist-center` 托管制品的发布、`wist-gateway` 的 agent 包与灰度升级）共用同一份，
//! 避免同一套口径各写一遍而漂移。

pub mod package;
pub mod rollout;
