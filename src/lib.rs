//! wist 发布域**纯逻辑**（不含存储 / 端点 / 鉴权）。
//!
//! 两个模块，两层：
//! - [`package`]：安装包的**身份解析** —— 从「来源 + 包字节」读出 `(version, arch)`；
//!   它同时**原样转出**底座 crate [`wist_artifact`] 的制品口径（取来源 / 摘要 / 版本比较 / 命名）。
//! - [`rollout`]：发布计划的**灰度** —— 切阶段（目标 + 阶段数 → 互不重叠的阶段）与放行
//!   （推进闸门 / 批次节流 / 确定性 work id）。
//!
//! **分层**：两边都要用的制品口径在 [`wist_artifact`]（被管端 agentd 也只依赖那一层）；
//! 本 crate 只装**发布域**的概念 —— 包长什么样、灰度怎么走。控制面的两侧应用
//! （`wist-center` 托管制品的发布、`wist-gateway` 的 agent 包与灰度升级）共用本 crate。
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
