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
//!
//! # 例：把机队切成三段灰度
//!
//! ```
//! use wist_release::rollout::plan_phases;
//!
//! let fleet: Vec<String> = (1..=10).map(|i| format!("gw-{i:03}")).collect();
//! let phases = plan_phases(&fleet, 3)?;
//!
//! assert_eq!(phases.len(), 3);
//! assert!(phases[0].is_canary); // 首批 1 台，金丝雀
//! assert!(phases[2].is_final); // 末批铺满剩余
//!
//! // 阶段之间**互不重叠**，且每个目标恰好出现一次。
//! let mut covered: Vec<String> = phases.iter().flat_map(|p| p.target_ids.clone()).collect();
//! covered.sort();
//! covered.dedup();
//! assert_eq!(covered.len(), fleet.len());
//! # Ok::<(), String>(())
//! ```

pub mod package;
pub mod rollout;
