//! 发布计划的**编排口径**（与存储 / 物化 / 端点无关）。
//!
//! [`crate::rollout`] 管「怎么切、怎么放行」的**原子规则**；本模块把那些规则**串成一份计划的
//! 推进状态机**：建草稿（切段）、批准、人工推进闸门、推进、结果回填后自动推进、以及**重试**时
//! 重开阶段。
//!
//! 中心（铺网关）与网关（铺 agent）共用这一份 —— 各自只保留把本地存储记录与 [`PhaseDraft`]
//! 互转的**薄适配器**，以及各自的物化 / spec 解析（那两件与各自的域绑死，不该抽到这里）。

use std::collections::HashSet;

/// 一份计划里的一个阶段（中立形状）。
///
/// `target_ids` 是「目标」：中心是 `gateway_id`、网关是 `agent_id` —— 形状一致，语义各表。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseDraft {
    pub index: i64,
    pub target_ids: Vec<String>,
    pub advance_rule: String,
    pub status: String,
}

/// 推进的结果：进了下一段 / 收尾为终态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvanceStep {
    /// 已进入下一阶段；调用方若需物化，去物化 `index` 这一段。
    NextPhase { index: i64 },
    /// 末段收尾，计划到终态。
    Finished { status: &'static str },
}

/// 由「目标 + 阶段数」切出草稿阶段：去重去空白、按阶梯切、首段 `manual` 其后 `all_succeeded`、
/// 状态自 `pending` 起。校验不过返回中性原因（由调用方折成 400）。
///
/// 只做**与目标/阶段数有关**的校验；`action` / `spec` / `deadline` / `timeout` 的校验口径两侧
/// 不同（中心截止可省、网关必填），留在各自应用。
pub fn build_phase_drafts(
    target_ids: &[String],
    phase_count: i64,
) -> Result<Vec<PhaseDraft>, String> {
    let mut unique: Vec<String> = Vec::with_capacity(target_ids.len());
    let mut seen: HashSet<String> = HashSet::new();
    for target in target_ids {
        let target = target.trim();
        if target.is_empty() || !seen.insert(target.to_string()) {
            continue;
        }
        unique.push(target.to_string());
    }
    if unique.is_empty() {
        return Err("target_ids must name at least one target".to_string());
    }
    if phase_count < 1 {
        return Err("phase_count must be at least 1".to_string());
    }
    let planned = crate::rollout::plan_phases(&unique, phase_count as usize)?;
    Ok(planned
        .into_iter()
        .map(|phase| PhaseDraft {
            index: phase.index as i64,
            target_ids: phase.target_ids,
            // 固定闸门策略：金丝雀（首段）人工确认；其后「本段全部成功」自动推进。
            advance_rule: if phase.index == 1 {
                crate::rollout::ADVANCE_RULE_MANUAL
            } else {
                crate::rollout::ADVANCE_RULE_ALL_SUCCEEDED
            }
            .to_string(),
            status: "pending".to_string(),
        })
        .collect())
}

/// 批准：进入第一阶段（**物化由调用方做**）。返回是否进入了（`false` = 没有阶段）。
pub fn approve(phases: &mut [PhaseDraft], current_phase: &mut i64, status: &mut String) -> bool {
    if phases.is_empty() {
        return false;
    }
    *status = "rolling".to_string();
    *current_phase = 1;
    phases[0].status = "rolling".to_string();
    true
}

/// 人工推进的**闸门**：要求当前阶段**已全部了结**（含失败）——「上一阶段确认无问题后再推下一批」。
///
/// 末阶段同理：推进它不派新活、只收尾，也要等本段跑完。返回 `Some(原因)` 表示不可推进。
/// `current_statuses` 是**当前阶段**各目标的条目状态（调用方按自己的存储查好）。
pub fn advance_gate_blocker(
    plan_status: &str,
    phases: &[PhaseDraft],
    current_phase: i64,
    current_statuses: &[&str],
) -> Option<String> {
    if plan_status != "rolling" {
        return Some(format!("plan is {plan_status}, not rolling"));
    }
    let idx = current_phase as usize;
    if idx == 0 || idx > phases.len() {
        return Some("plan has no phase to advance".to_string());
    }
    let phase = &phases[idx - 1];
    if let Err(reason) = crate::rollout::validate_advance_rule(&phase.advance_rule) {
        return Some(format!("phase advance_rule is invalid: {reason}"));
    }
    if !crate::rollout::phase_settled(current_statuses) {
        return Some(format!(
            "phase {} is not settled yet (some targets are still running)",
            phase.index
        ));
    }
    None
}

/// 把一份 `rolling` 计划推进一个阶段：当前阶段划 `completed`；末段收尾（本段有失败就落 `failed`、
/// 否则 `completed`），其余进下一段（状态 `rolling`、`current_phase` +1）。
///
/// 调用方须保证 `current_phase` 在 `1..=phases.len()`；越界返回 `None`（不改动）。
pub fn advance(
    phases: &mut [PhaseDraft],
    current_phase: &mut i64,
    plan_status: &mut String,
    current_statuses: &[&str],
) -> Option<AdvanceStep> {
    let idx = *current_phase as usize;
    if idx == 0 || idx > phases.len() {
        return None;
    }
    phases[idx - 1].status = "completed".to_string();
    if idx == phases.len() {
        // 末段收尾：本段**有失败**就是 `failed` —— 不把失败抹成「完成」。
        let finished: &'static str = if current_statuses.contains(&"failed") {
            "failed"
        } else {
            "completed"
        };
        *plan_status = finished.to_string();
        Some(AdvanceStep::Finished { status: finished })
    } else {
        phases[idx].status = "rolling".to_string();
        *current_phase = (idx + 1) as i64;
        Some(AdvanceStep::NextPhase {
            index: (idx + 1) as i64,
        })
    }
}

/// 终态结果回填后按闸门推进：`Some(step)` = 推进了（调用方据此物化下一段 / 收尾）。
///
/// - 末阶段没有「下一段」：本段全部了结就直接**收尾**（**不看闸门**）；
/// - 其余阶段：`manual` 永不自动放行；`all_succeeded` / `success_rate:` 满足即自动推进。
pub fn progress_after_terminal(
    phases: &mut [PhaseDraft],
    current_phase: &mut i64,
    plan_status: &mut String,
    current_statuses: &[&str],
) -> Option<AdvanceStep> {
    if plan_status != "rolling" {
        return None;
    }
    let idx = *current_phase as usize;
    if idx == 0 || idx > phases.len() {
        return None;
    }
    let is_last = idx == phases.len();
    let rule = phases[idx - 1].advance_rule.clone();
    if is_last {
        if crate::rollout::phase_settled(current_statuses) {
            return advance(phases, current_phase, plan_status, current_statuses);
        }
        return None;
    }
    if rule == crate::rollout::ADVANCE_RULE_MANUAL {
        return None;
    }
    if crate::rollout::phase_should_advance(&rule, current_statuses) {
        return advance(phases, current_phase, plan_status, current_statuses);
    }
    None
}

/// **重试**时**重开**：被重试目标所在阶段改回 `rolling`；计划改回 `rolling`；`current_phase` 指回
/// 最靠后的那一段（推进闸门据此要求该段重新了结）。
///
/// `retried` 里若有**不属于任何阶段**的目标，它们不产生任何影响；并且**只要一个阶段都没被点到，
/// 计划整体不动** —— 否则会把一份 `completed` / `failed` 的计划重开为 `rolling` 却没有阶段可跑，
/// 卡在滚动里等不到了结。
pub fn reopen_for_retry(
    phases: &mut [PhaseDraft],
    current_phase: &mut i64,
    plan_status: &mut String,
    retried: &[String],
) {
    let retried: HashSet<&str> = retried.iter().map(String::as_str).collect();
    let mut reopen = 0i64;
    for phase in phases.iter_mut() {
        if phase
            .target_ids
            .iter()
            .any(|id| retried.contains(id.as_str()))
        {
            phase.status = "rolling".to_string();
            reopen = reopen.max(phase.index);
        }
    }
    if reopen == 0 {
        return;
    }
    *plan_status = "rolling".to_string();
    *current_phase = reopen;
}

/// **重试**用的**新** work id：`<确定性 id>-r<sha6>`（与 [`crate::rollout::target_work_id`] 同族）。
///
/// 必须换个 id：agentd 只对「本机未执行过」的 `work_id` 起升级器 —— 重发同一个 id 是假重试。
/// `nonce` 由调用方给（取当下时间即可）：同一目标连重试两次也得到不同 id。
pub fn retry_work_id(plan_id: &str, target_id: &str, nonce: &str) -> String {
    let digest =
        crate::package::sha256_hex_bytes(format!("retry|{plan_id}|{target_id}|{nonce}").as_bytes());
    format!(
        "{}-r{}",
        crate::rollout::target_work_id(plan_id, target_id),
        &digest[..6]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drafts(targets: &[&str], phase_count: i64) -> Vec<PhaseDraft> {
        let targets: Vec<String> = targets.iter().map(|t| t.to_string()).collect();
        build_phase_drafts(&targets, phase_count).expect("drafts")
    }

    #[test]
    fn build_phase_drafts_splits_dedupes_and_sets_advance_rules() {
        let phases = drafts(&["a", "b", "a", "  ", "c"], 2);
        assert_eq!(phases.len(), 2);
        assert_eq!(phases[0].index, 1);
        assert_eq!(phases[0].advance_rule, crate::rollout::ADVANCE_RULE_MANUAL);
        assert_eq!(
            phases[1].advance_rule,
            crate::rollout::ADVANCE_RULE_ALL_SUCCEEDED
        );
        assert!(phases.iter().all(|p| p.status == "pending"));
        // 去重 + 去空白；覆盖每个目标恰好一次。
        let mut covered: Vec<&str> = phases
            .iter()
            .flat_map(|p| p.target_ids.iter().map(String::as_str))
            .collect();
        covered.sort();
        assert_eq!(covered, vec!["a", "b", "c"]);
    }

    #[test]
    fn build_phase_drafts_rejects_empty_targets_and_bad_phase_count() {
        assert!(build_phase_drafts(&[], 2).is_err());
        assert!(build_phase_drafts(&["  ".to_string()], 2).is_err());
        assert!(build_phase_drafts(&["a".to_string()], 0).is_err());
    }

    #[test]
    fn advance_walks_phases_and_settles_the_last_phase_on_failure() {
        let mut phases = drafts(&["a", "b", "c", "d"], 2);
        let mut current = 1i64;
        let mut status = "rolling".to_string();
        // 第一段三台（金丝雀 1 + 10%）—— 为稳妥，直接看第一段的目标。
        let first = phases[0].target_ids.clone();
        let ok: Vec<&str> = first.iter().map(|_| "succeeded").collect();
        assert_eq!(
            advance(&mut phases, &mut current, &mut status, &ok),
            Some(AdvanceStep::NextPhase { index: 2 })
        );
        assert_eq!(phases[0].status, "completed");
        assert_eq!(phases[1].status, "rolling");
        // 末段：有失败 → 计划 failed。
        let last = phases[1].target_ids.clone();
        let mut mixed: Vec<&str> = last.iter().map(|_| "succeeded").collect();
        mixed[0] = "failed";
        assert_eq!(
            advance(&mut phases, &mut current, &mut status, &mixed),
            Some(AdvanceStep::Finished { status: "failed" })
        );
        assert_eq!(status, "failed");
    }

    #[test]
    fn gate_requires_a_settled_rolling_phase() {
        let phases = drafts(&["a", "b"], 1);
        assert!(
            advance_gate_blocker("draft", &phases, 0, &[]).is_some(),
            "非 rolling 不可推进"
        );
        let mut rolling = "rolling".to_string();
        let mut current = 1i64;
        approve(&mut phases.clone(), &mut current, &mut rolling);
        assert!(
            advance_gate_blocker("rolling", &phases, 1, &["dispatched"]).is_some(),
            "未了结不可推进"
        );
        assert!(
            advance_gate_blocker("rolling", &phases, 1, &["succeeded", "failed"]).is_none(),
            "全部了结即可推进"
        );
    }

    #[test]
    fn progress_auto_advances_only_when_the_rule_allows() {
        // 单段：末段了结即收尾（不看闸门）。
        let mut phases = drafts(&["a"], 1);
        let mut current = 1i64;
        let mut status = "rolling".to_string();
        assert_eq!(
            progress_after_terminal(&mut phases, &mut current, &mut status, &["failed"]),
            Some(AdvanceStep::Finished { status: "failed" })
        );
        // 未了结不动。
        let mut phases = drafts(&["a", "b"], 1);
        let mut current = 1i64;
        let mut status = "rolling".to_string();
        assert_eq!(
            progress_after_terminal(&mut phases, &mut current, &mut status, &["dispatched"]),
            None
        );
        // 首段 manual 不了结不放行（即使全成功）。
        let mut phases = drafts(&["a"], 1);
        let mut current = 1i64;
        let mut status = "rolling".to_string();
        assert_eq!(
            progress_after_terminal(&mut phases, &mut current, &mut status, &["succeeded"]),
            Some(AdvanceStep::Finished {
                status: "completed"
            })
        );
    }

    #[test]
    fn reopen_for_retry_rolls_phases_and_plan_back_to_rolling() {
        let mut phases = drafts(&["a", "b"], 2);
        for phase in &mut phases {
            phase.status = "completed".to_string();
        }
        let mut current = 2i64;
        let mut status = "failed".to_string();
        reopen_for_retry(&mut phases, &mut current, &mut status, &["a".to_string()]);
        assert_eq!(status, "rolling");
        assert_eq!(current, 1, "指回被重试目标所在的最靠后阶段");
        assert_eq!(phases[0].status, "rolling");
        assert_eq!(phases[1].status, "completed", "没被点到的阶段不动");
    }

    #[test]
    fn retry_work_id_differs_from_the_deterministic_id_and_varies_with_nonce() {
        let base = crate::rollout::target_work_id("plan-1", "agent-a");
        let first = retry_work_id("plan-1", "agent-a", "t1");
        assert_ne!(first, base);
        assert!(first.starts_with(&format!("{base}-r")));
        assert_eq!(first, retry_work_id("plan-1", "agent-a", "t1"));
        assert_ne!(first, retry_work_id("plan-1", "agent-a", "t2"));
        assert_ne!(first, retry_work_id("plan-1", "agent-b", "t1"));
    }

    #[test]
    fn reopen_for_retry_is_a_noop_when_no_phase_matches() {
        // 一份已收尾的计划 + 一个不属于它的目标：不能把它重开成没阶段可跑的 rolling。
        let mut phases = drafts(&["a", "b"], 2);
        for phase in &mut phases {
            phase.status = "completed".to_string();
        }
        let mut current = 2i64;
        let mut status = "completed".to_string();
        reopen_for_retry(&mut phases, &mut current, &mut status, &["zzz".to_string()]);
        assert_eq!(status, "completed", "无阶段被点到 → 计划状态不动");
        assert_eq!(current, 2, "current_phase 不动");
        assert!(phases.iter().all(|p| p.status == "completed"));
        // 空 retried 同理。
        let mut status = "failed".to_string();
        reopen_for_retry(&mut phases, &mut current, &mut status, &[]);
        assert_eq!(status, "failed");
    }

    #[test]
    fn reopen_for_retry_points_current_phase_at_the_last_touched_phase() {
        // 重试同时命中两段时，current_phase 取更靠后的那一段（闸门须先满足它）。
        let mut phases = drafts(&["a", "b", "c"], 3);
        for phase in &mut phases {
            phase.status = "completed".to_string();
        }
        let first = phases[0].target_ids[0].clone();
        let last = phases[2].target_ids[0].clone();
        let mut current = 3i64;
        let mut status = "completed".to_string();
        reopen_for_retry(&mut phases, &mut current, &mut status, &[first, last]);
        assert_eq!(status, "rolling");
        assert_eq!(current, 3);
        assert_eq!(phases[0].status, "rolling");
        assert_eq!(phases[2].status, "rolling");
        assert_eq!(phases[1].status, "completed", "没被点到的段不动");
    }

    #[test]
    fn approve_is_a_noop_without_phases() {
        let mut phases: Vec<PhaseDraft> = Vec::new();
        let mut current = 0i64;
        let mut status = "draft".to_string();
        assert!(!approve(&mut phases, &mut current, &mut status));
        assert_eq!(status, "draft", "没有阶段时批准不改动任何状态");
        assert_eq!(current, 0);
    }

    #[test]
    fn advance_and_progress_are_noops_out_of_bounds_or_not_rolling() {
        // current_phase 越界：推进不动。
        let mut phases = drafts(&["a"], 1);
        let mut current = 0i64;
        let mut status = "rolling".to_string();
        assert!(advance(&mut phases, &mut current, &mut status, &[]).is_none());
        assert_eq!(phases[0].status, "pending");
        let mut current = 9i64;
        assert!(advance(&mut phases, &mut current, &mut status, &[]).is_none());
        // 非 rolling：回填推进不动。
        let mut current = 1i64;
        let mut status = "completed".to_string();
        assert!(
            progress_after_terminal(&mut phases, &mut current, &mut status, &["succeeded"])
                .is_none()
        );
        assert_eq!(phases[0].status, "pending");
        assert_eq!(status, "completed");
    }

    #[test]
    fn progress_auto_advances_a_success_rate_phase_but_not_a_manual_one() {
        // 两段：首段 manual，次段 all_succeeded。首段 50% 也不放行，次段末段了结即收尾。
        let mut phases = drafts(&["a", "b", "c", "d"], 2);
        let mut current = 1i64;
        let mut status = "rolling".to_string();
        let first = phases[0].target_ids.clone();
        let mixed: Vec<&str> = first
            .iter()
            .enumerate()
            .map(|(i, _)| if i == 0 { "failed" } else { "succeeded" })
            .collect();
        assert!(progress_after_terminal(&mut phases, &mut current, &mut status, &mixed).is_none());
        assert_eq!(current, 1, "manual 首段等待人工推进");
    }
}
