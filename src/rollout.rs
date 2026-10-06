//! 发布计划的**灰度**：两件事共用一份口径。
//!
//! 1. **怎么切阶段** —— [`plan_phases`]：由「目标 + 阶段数」切出**互不重叠**的阶段
//!    （服务端权威，中心与网关都只让运维选阶段数）。
//! 2. **怎么放行** —— [`phase_should_advance`] / [`next_refill_targets`] 等：阶段推进闸门与批次节流；
//!    以及一个 target 物化成工作时的**确定性 id**（[`target_work_id`]），配合幂等落库。
//!
//! 固定阶梯 **1 个（金丝雀）→ 10% → 30% → 70% → 全量（剩余）**：选 K 个阶段时取阶梯前 K-1 级
//! 作为中间切点，最后一级永远是「剩余全部」，保证一把铺满目标。运维只选**阶段数**，不用填任何
//! 目标 id。
//!
//! 与前端（`wist-center-web` 的发布①、`wist-gateway-web` 的 Agent 升级）同一套口径 —— 前端只做
//! 预览，真值以这里为准。

/// 阶梯一级：固定台数，或占目标总数的百分比。
#[derive(Debug, Clone, Copy)]
enum CoverageCut {
    Count(usize),
    Percent(u64),
}

/// 中间切点阶梯（「全量」由阶段数隐含，不在表里）。
const LADDER: &[CoverageCut] = &[
    CoverageCut::Count(1), // 金丝雀：1 个
    CoverageCut::Percent(10),
    CoverageCut::Percent(30),
    CoverageCut::Percent(70),
];

/// 可选的阶段数：阶梯最多 4 个中间切点 + 一级「剩余」= 5 阶段。
pub const PHASE_COUNTS: &[usize] = &[2, 3, 4, 5];

/// 目标台数**能支持**的阶段数：每段至少 1 个，所以阶段数不能大于台数 —— 目标少时就不该多轮。
/// 只保留 ≤ 台数的预设；一个目标时退化为 `[1]`（不分批，一把到位）。
pub fn available_phase_counts(total: usize) -> Vec<usize> {
    if total == 0 {
        return Vec::new();
    }
    let feasible: Vec<usize> = PHASE_COUNTS
        .iter()
        .copied()
        .filter(|count| *count <= total)
        .collect();
    if feasible.is_empty() {
        vec![1]
    } else {
        feasible
    }
}

/// 一个已分配的阶段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phase {
    /// 从 1 开始。
    pub index: usize,
    /// 本阶段的目标 id（互不重叠，取自排序后的目标）。
    pub target_ids: Vec<String>,
    /// 目标覆盖比例（**阶梯口径**，百分比）；金丝雀段为 `None`。
    pub coverage_percent: Option<u64>,
    /// 金丝雀段（首段且恰好 1 个）。
    pub is_canary: bool,
    /// 收尾段（覆盖到全量）。
    pub is_final: bool,
}

/// 把目标切成 `phase_count` 个互不重叠的阶段。
///
/// 顺序取**排序后的 id**（确定、可复现）。累计覆盖保证切点单调不减，再夹到
/// `[上一切点 + 1, 台数 - 后面阶段数]`，确保每段**非空**；目标为空、阶段数为 0、或目标太少
/// （阶段数 > 台数）直接报错，而不是悄悄给出空阶段。
pub fn plan_phases(targets: &[String], phase_count: usize) -> Result<Vec<Phase>, String> {
    let total = targets.len();
    let mut order: Vec<String> = targets.to_vec();
    order.sort();
    if total == 0 {
        return Err("还没选任何目标，无法分配阶段。".to_string());
    }
    if phase_count == 0 {
        // 0 阶段不是「一把到位」（那是 1 阶段），是调用方传错了 —— 明确报错，不静默吞掉。
        return Err("阶段数至少为 1。".to_string());
    }
    if phase_count > total {
        return Err(format!(
            "只选了 {total} 个目标，分不出 {phase_count} 个非空阶段。"
        ));
    }

    let mut cuts: Vec<usize> = Vec::with_capacity(phase_count);
    let mut previous = 0usize;
    for i in 0..phase_count.saturating_sub(1) {
        let cut = LADDER[i.min(LADDER.len() - 1)];
        // 给后面每个阶段留至少 1 个。
        let upper = total - (phase_count - i - 1);
        let size = (previous + 1).max(cut_size(cut, total).min(upper));
        cuts.push(size);
        previous = size;
    }
    cuts.push(total);

    let mut phases = Vec::with_capacity(cuts.len());
    let mut start = 0usize;
    for (i, end) in cuts.iter().copied().enumerate() {
        let target_ids = order[start..end].to_vec();
        phases.push(Phase {
            index: i + 1,
            coverage_percent: if end == total {
                Some(100)
            } else {
                ladder_coverage_percent(i)
            },
            // 金丝雀 = 首批且恰好 1 个；但若这一批就是全部（只选一个目标），不算金丝雀。
            is_canary: i == 0 && target_ids.len() == 1 && end != total,
            is_final: end == total,
            target_ids,
        });
        start = end;
    }
    Ok(phases)
}

/// 阶段的规模文字：金丝雀读「1 个」，其余读「覆盖 ~X%」。
pub fn phase_scale_label(phase: &Phase) -> String {
    if phase.is_canary {
        return "1 个（金丝雀）".to_string();
    }
    format!("覆盖 ~{}%", phase.coverage_percent.unwrap_or(0))
}

/// 阶梯第 i 级的**目标**覆盖比例（百分比）；这一级是台数（金丝雀）时返回 `None`。
fn ladder_coverage_percent(i: usize) -> Option<u64> {
    match LADDER[i.min(LADDER.len() - 1)] {
        CoverageCut::Percent(value) => Some(value),
        CoverageCut::Count(_) => None,
    }
}

/// 一个切点折算成「覆盖几个」（百分比向上取整）。
fn cut_size(cut: CoverageCut, total: usize) -> usize {
    match cut {
        CoverageCut::Count(value) => value.min(total),
        CoverageCut::Percent(percent) => ((percent as usize) * total).div_ceil(100).min(total),
    }
}

// ─────────────────────────── 推进闸门与批次节流 ───────────────────────────
//
// 切阶段只说「分几段、每段是谁」；下面这些决定「一段什么时候算了结、能不能进下一段、
// 段内一次放几台」。同一份口径，中心（算阶段）与网关（放行/物化）共用。

/// 阶段推进闸门的合法取值。
pub const ADVANCE_RULE_MANUAL: &str = "manual";
pub const ADVANCE_RULE_ALL_SUCCEEDED: &str = "all_succeeded";
/// `success_rate:<NN>` 前缀（成功率阈值，0..=100）。
pub const ADVANCE_RULE_SUCCESS_RATE_PREFIX: &str = "success_rate:";

/// 校验推进闸门是否合法。
///
/// 取值是 `manual` / `all_succeeded` / `success_rate:<0..=100>`。
pub fn validate_advance_rule(rule: &str) -> Result<(), String> {
    let rule = rule.trim();
    if rule == ADVANCE_RULE_MANUAL || rule == ADVANCE_RULE_ALL_SUCCEEDED {
        return Ok(());
    }
    if let Some(rate) = rule.strip_prefix(ADVANCE_RULE_SUCCESS_RATE_PREFIX)
        && let Ok(value) = rate.trim().parse::<u32>()
        && value <= 100
    {
        return Ok(());
    }
    Err(format!(
        "advance_rule {rule:?} must be \"manual\", \"all_succeeded\", or \"success_rate:<0..=100>\""
    ))
}

/// 目标上报的工作状态 → 计划条目的状态。
///
/// `running` 等「在飞」状态都归 `dispatched`（条目只区分「还没做 / 在做 / 做成了 / 没成」）；
/// `rolled_back` 在上报侧已映射成 `failed`，这里不单列。
pub fn entry_status_for(work_status: &str) -> &'static str {
    match work_status {
        "succeeded" => "succeeded",
        "failed" => "failed",
        _ => "dispatched",
    }
}

/// 一个目标的条目状态：`(target_id, status)`。
pub type TargetStatus<'a> = (&'a str, &'a str);

/// 阶段是否已**全部了结**：每个目标都到了 `succeeded` / `failed` 终态。
///
/// 空阶段不算了结 —— `all` 在空集上恒真，那会把「一个目标都没有的阶段」当成可推进。
pub fn phase_settled(statuses: &[&str]) -> bool {
    !statuses.is_empty()
        && statuses
            .iter()
            .all(|status| matches!(*status, "succeeded" | "failed"))
}

/// 阶段推进闸门是否放行（自动推进判定）。
///
/// 前提是阶段**全部了结**才谈推进：还有目标在飞就没出结果，不能拿半截结果判「成没成」。
/// [`ADVANCE_RULE_MANUAL`] 永远不自动放行（要人工确认）。
pub fn phase_should_advance(rule: &str, statuses: &[&str]) -> bool {
    if !phase_settled(statuses) {
        return false;
    }
    let total = statuses.len() as u64;
    let succeeded = statuses
        .iter()
        .filter(|status| **status == "succeeded")
        .count() as u64;
    match rule.trim() {
        ADVANCE_RULE_MANUAL => false,
        ADVANCE_RULE_ALL_SUCCEEDED => succeeded == total,
        _ => {
            if let Some(rate) = rule.trim().strip_prefix(ADVANCE_RULE_SUCCESS_RATE_PREFIX)
                && let Ok(threshold) = rate.trim().parse::<u64>()
            {
                // succeeded / total >= threshold / 100，全程整数，避免浮点误差。
                return succeeded * 100 >= threshold * total;
            }
            false
        }
    }
}

/// 阶段开始时先物化哪些目标：`batch_size <= 0` = 全量；否则最多前 `batch_size` 个。
pub fn phase_start_targets(target_ids: &[String], batch_size: i64) -> Vec<String> {
    if batch_size <= 0 {
        return target_ids.to_vec();
    }
    let take = (batch_size as usize).min(target_ids.len());
    target_ids[..take].to_vec()
}

/// 阶段内补够 `batch_size` 台在飞：从还是 `pending` 的目标里再挑下一批物化。
///
/// 只补「在飞数 < batch_size」的差额；`batch_size <= 0` = 不节流，不需要补。
pub fn next_refill_targets(
    target_ids: &[String],
    states: &[TargetStatus<'_>],
    batch_size: i64,
) -> Vec<String> {
    if batch_size <= 0 {
        return Vec::new();
    }
    let status_of = |target: &str| -> Option<&str> {
        states
            .iter()
            .find(|(id, _)| *id == target)
            .map(|(_, status)| *status)
    };
    let in_flight = target_ids
        .iter()
        .filter(|target| status_of(target) == Some("dispatched"))
        .count();
    let needed = (batch_size as usize).saturating_sub(in_flight);
    if needed == 0 {
        return Vec::new();
    }
    target_ids
        .iter()
        .filter(|target| status_of(target) == Some("pending"))
        .take(needed)
        .cloned()
        .collect()
}

/// 计划里一个目标物化成的那件一次性工作的 `work_id`。
///
/// **确定性**（不含时间）：同一目标重试物化会得到同一个 `work_id`，配合落库的 upsert 幂等 ——
/// 不会因为推进重试而给同一目标并出两件升级。
pub fn target_work_id(plan_id: &str, target_id: &str) -> String {
    let digest = crate::package::sha256_hex_bytes(format!("{plan_id}|{target_id}").as_bytes());
    format!("work-{plan_id}-{}", &digest[..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(n: usize) -> Vec<String> {
        (1..=n).map(|i| format!("gw-{i:03}")).collect()
    }

    fn sizes(phases: &[Phase]) -> Vec<usize> {
        phases.iter().map(|p| p.target_ids.len()).collect()
    }

    #[test]
    fn available_counts_shrink_with_the_target_size() {
        assert_eq!(available_phase_counts(10), vec![2, 3, 4, 5]);
        assert_eq!(available_phase_counts(3), vec![2, 3]);
        assert_eq!(available_phase_counts(1), vec![1]);
        assert!(available_phase_counts(0).is_empty());
    }

    #[test]
    fn cuts_follow_the_ladder_and_cover_everything_once() {
        // 10 个目标：金丝雀 1 → 10% → 30% → 70% → 全量（累计覆盖，切片互不重叠）。
        assert_eq!(sizes(&plan_phases(&targets(10), 2).unwrap()), vec![1, 9]);
        assert_eq!(sizes(&plan_phases(&targets(10), 3).unwrap()), vec![1, 1, 8]);
        assert_eq!(
            sizes(&plan_phases(&targets(10), 4).unwrap()),
            vec![1, 1, 1, 7]
        );
        assert_eq!(
            sizes(&plan_phases(&targets(10), 5).unwrap()),
            vec![1, 1, 1, 4, 3]
        );
    }

    #[test]
    fn phases_are_disjoint_and_ordered() {
        let phases = plan_phases(&targets(10), 5).unwrap();
        let mut all: Vec<String> = phases.iter().flat_map(|p| p.target_ids.clone()).collect();
        assert_eq!(all.len(), 10);
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 10, "阶段之间互不重叠");
        assert_eq!(phases[0].target_ids, vec!["gw-001"]);
        assert!(phases[0].is_canary && !phases[0].is_final);
        assert!(phases.last().unwrap().is_final);
        assert_eq!(phases[2].coverage_percent, Some(30));
    }

    #[test]
    fn small_fleets_stay_non_empty_and_single_target_is_not_a_canary() {
        assert_eq!(
            sizes(&plan_phases(&targets(5), 5).unwrap()),
            vec![1, 1, 1, 1, 1]
        );
        assert_eq!(sizes(&plan_phases(&targets(3), 3).unwrap()), vec![1, 1, 1]);
        // 一个目标：一把到位，不算金丝雀。
        let one = plan_phases(&targets(1), 1).unwrap();
        assert_eq!(sizes(&one), vec![1]);
        assert!(!one[0].is_canary && one[0].is_final);
    }

    #[test]
    fn refuses_empty_and_infeasible_counts() {
        assert!(plan_phases(&[], 2).is_err());
        assert!(plan_phases(&targets(2), 5).is_err());
    }

    #[test]
    fn refuses_a_zero_phase_count() {
        // 0 阶段不是「一把到位」（那是 1 阶段），别静默当成 1 阶段。
        assert!(plan_phases(&targets(5), 0).is_err());
        assert!(plan_phases(&[], 0).is_err());
        // 1 阶段才是合法的「不分批，一把到位」。
        assert_eq!(sizes(&plan_phases(&targets(5), 1).unwrap()), vec![5]);
    }

    #[test]
    fn large_fleets_follow_the_ladder_percentages() {
        // 100 台 × 5 阶段：金丝雀 1 → 到 10%（+9）→ 到 30%（+20）→ 到 70%（+40）→ 余 30。
        assert_eq!(
            sizes(&plan_phases(&targets(100), 5).unwrap()),
            vec![1, 9, 20, 40, 30]
        );
        assert_eq!(sizes(&plan_phases(&targets(100), 2).unwrap()), vec![1, 99]);
        assert_eq!(
            sizes(&plan_phases(&targets(100), 3).unwrap()),
            vec![1, 9, 90]
        );
    }

    #[test]
    fn every_preset_yields_disjoint_phases_that_cover_the_fleet_once() {
        for total in 1..=24usize {
            let fleet = targets(total);
            for count in available_phase_counts(total) {
                let phases = plan_phases(&fleet, count).unwrap();
                assert_eq!(phases.len(), count, "total {total} count {count}");
                // 每段非空、编号从 1 连续、恰好一段收尾。
                assert!(phases.iter().all(|phase| !phase.target_ids.is_empty()));
                assert!(phases.iter().enumerate().all(|(i, p)| p.index == i + 1));
                assert_eq!(phases.iter().filter(|p| p.is_final).count(), 1);
                // 金丝雀只在不分段的单目标机队上缺席。
                assert_eq!(
                    phases.iter().filter(|p| p.is_canary).count(),
                    usize::from(total > 1),
                    "total {total} count {count}"
                );
                // 互不重叠，且一把铺满机队（每个目标恰好出现一次）。
                let mut all: Vec<String> =
                    phases.iter().flat_map(|p| p.target_ids.clone()).collect();
                assert_eq!(all.len(), total, "total {total} count {count}");
                all.sort();
                all.dedup();
                assert_eq!(all.len(), total, "total {total} count {count}");
            }
        }
    }

    #[test]
    fn small_fleets_keep_the_ladder_labels_even_when_clamped() {
        assert_eq!(available_phase_counts(4), vec![2, 3, 4]);
        // 4 台 × 4 阶段：每段 1 台；标签仍是**阶梯口径**（10%），不是 1/4 的真实占比 ——
        // 「实际新增几台」靠 `target_ids.len()` 看，两者刻意分开。
        let phases = plan_phases(&targets(4), 4).unwrap();
        assert_eq!(sizes(&phases), vec![1, 1, 1, 1]);
        assert_eq!(phase_scale_label(&phases[1]), "覆盖 ~10%");
        assert_eq!(phases[3].coverage_percent, Some(100));
    }

    #[test]
    fn scale_labels_read_the_ladder_level() {
        let phases = plan_phases(&targets(10), 4).unwrap();
        assert_eq!(phase_scale_label(&phases[0]), "1 个（金丝雀）");
        assert_eq!(phase_scale_label(&phases[1]), "覆盖 ~10%");
        assert_eq!(phase_scale_label(&phases[3]), "覆盖 ~100%");
    }

    #[test]
    fn advance_rules_accept_the_documented_values_and_reject_garbage() {
        for ok in [
            "manual",
            "all_succeeded",
            "success_rate:0",
            "success_rate:80",
            "success_rate:100",
        ] {
            assert!(validate_advance_rule(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "auto",
            "success_rate:101",
            "success_rate:abc",
            "rate:50",
        ] {
            assert!(validate_advance_rule(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn entry_status_folds_in_flight_and_terminal_onto_the_closed_set() {
        assert_eq!(entry_status_for("succeeded"), "succeeded");
        assert_eq!(entry_status_for("failed"), "failed");
        for flying in ["running", "dispatched", "accepted"] {
            assert_eq!(entry_status_for(flying), "dispatched", "{flying}");
        }
    }

    #[test]
    fn a_phase_advances_only_when_settled_and_the_rule_holds() {
        // 没全部了结就不放行（还有在飞的）。
        let in_flight = ["succeeded", "dispatched"];
        assert!(!phase_should_advance("all_succeeded", &in_flight));
        assert!(!phase_should_advance("success_rate:50", &in_flight));

        let all_ok = ["succeeded", "succeeded"];
        assert!(phase_should_advance("all_succeeded", &all_ok));
        assert!(phase_should_advance("success_rate:100", &all_ok));

        let one_failed = ["succeeded", "failed"];
        assert!(!phase_should_advance("all_succeeded", &one_failed));
        assert!(phase_should_advance("success_rate:50", &one_failed));
        assert!(!phase_should_advance("success_rate:51", &one_failed));

        // manual 永不自动放行；空阶段不算了结。
        assert!(!phase_should_advance("manual", &all_ok));
        assert!(!phase_should_advance("all_succeeded", &[]));
    }

    #[test]
    fn start_and_refill_keep_the_batch_in_flight() {
        let fleet = ["a", "b", "c", "d"].map(str::to_string).to_vec();
        // 0 = 不节流，全量；N = 前 N 个。
        assert_eq!(phase_start_targets(&fleet, 0), vec!["a", "b", "c", "d"]);
        assert_eq!(phase_start_targets(&fleet, 2), vec!["a", "b"]);
        assert_eq!(phase_start_targets(&fleet, 10), vec!["a", "b", "c", "d"]);

        // a 在飞、b/c/d 还 pending，batch=2 → 还差 1 台，补 b。
        let states = [
            ("a", "dispatched"),
            ("b", "pending"),
            ("c", "pending"),
            ("d", "pending"),
        ];
        assert_eq!(next_refill_targets(&fleet, &states, 2), vec!["b"]);
        // a、b 都结束了 → 补 c、d。
        let states = [
            ("a", "succeeded"),
            ("b", "failed"),
            ("c", "pending"),
            ("d", "pending"),
        ];
        assert_eq!(next_refill_targets(&fleet, &states, 2), vec!["c", "d"]);
        // 不节流：补什么都不用。
        assert!(next_refill_targets(&fleet, &states, 0).is_empty());
    }

    #[test]
    fn work_id_is_deterministic_per_target() {
        let id = target_work_id("plan-1", "gw-001");
        assert_eq!(id, target_work_id("plan-1", "gw-001"));
        assert_ne!(id, target_work_id("plan-1", "gw-002"));
        assert_ne!(id, target_work_id("plan-2", "gw-001"));
        assert!(id.starts_with("work-plan-1-"));
        assert_eq!(id.len(), "work-plan-1-".len() + 12);
    }
}
