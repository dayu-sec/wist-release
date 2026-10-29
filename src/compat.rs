//! 安装包 / 组件的**升级兼容性声明与检查**。
//!
//! 发布侧在包里放一份 `compat.json`（可选）：
//!
//! ```json
//! {
//!   "component": "wist-agentd",
//!   "version": "1.5.0",
//!   "requires":  { "wist-gateway": ">=0.9.0 <0.10.0" },
//!   "supports":  { "wist-agentd": ">=0.1.12" },
//!   "coexists_with": { "wist-gateway": ">=0.8.0" },
//!   "compat_mode": true,
//!   "bridge": [],
//!   "reversible": false
//! }
//! ```
//!
//! 检查口径：
//! - `requires` 是**上游 / 管理器**必须满足的范围；不满足 → `error`（默认阻止安装/激活/发布）。
//! - `supports` 是它能服务的**下游**范围；当前节点有该 peer 但在范围外 → `warn`（不阻止）。
//! - `coexists_with` 是混合版本期间可共存的范围；`requires` 不满足但 `coexists_with` 满足且
//!   `compat_mode=true` → `warn`（需要开兼容模式，不阻止）。
//! - 包内没有 `compat.json` → `unknown`（允许，但必须显式显示“未验证兼容性”）。
//!
//! 本模块只做**纯逻辑**（不读网络 / 不依赖应用状态），中心与网关共用。

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::package::{normalize_version, parse_version};

/// 包里兼容声明的文件名（按优先级）。
pub const COMPAT_MANIFEST_FILES: &[&str] = &["compat.json", "wist-compat.json"];

/// 兼容声明文件的最大字节数（防御异常包）。
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

/// 一份组件的兼容性声明。
///
/// **不加 `deny_unknown_fields`**：声明文件是向前兼容的，新增字段不能让老消费者读不懂整个 manifest。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CompatManifest {
    #[serde(default)]
    pub component: String,
    #[serde(default)]
    pub version: String,
    /// 上游 / 管理器必须满足的版本范围。
    #[serde(default)]
    pub requires: BTreeMap<String, String>,
    /// 能服务的下游版本范围（不满足只告警）。
    #[serde(default)]
    pub supports: BTreeMap<String, String>,
    /// 混合版本期间可共存的范围（配合 `compat_mode`）。
    #[serde(default)]
    pub coexists_with: BTreeMap<String, String>,
    /// 是否支持 `compat=mixed` 运行。
    #[serde(default)]
    pub compat_mode: bool,
    /// 需要“旧+新都能谈”的中间版本。
    #[serde(default)]
    pub bridge: Vec<String>,
    /// 是否支持单步回退。
    #[serde(default)]
    pub reversible: bool,
}

/// 兼容性检查的总体结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatStatus {
    /// 所有声明的范围都满足。
    Ok,
    /// 有告警（无声明 / 版本未知 / 兼容模式下可共存 / 下游范围不满足）。
    Warn,
    /// 声明范围被违反，默认阻止。
    Error,
    /// 没有声明，或拿不到对端版本。
    Unknown,
}

impl CompatStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Unknown => "unknown",
        }
    }
}

/// 单条检查的严重级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatSeverity {
    Ok,
    Warn,
    Error,
}

/// 一条具体的兼容性检查。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatCheck {
    pub package: String,
    pub version: String,
    pub peer: String,
    pub required: String,
    pub actual: String,
    pub ok: bool,
    pub severity: CompatSeverity,
    pub message: String,
}

/// 一次兼容性检查的完整报告（可直接进接口 / 页面）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatReport {
    pub status: CompatStatus,
    pub checked_at: String,
    pub current: BTreeMap<String, String>,
    pub checks: Vec<CompatCheck>,
}

impl CompatReport {
    /// 是否应默认阻止安装 / 激活 / 发布。
    pub fn is_blocking(&self) -> bool {
        self.status == CompatStatus::Error
    }

    /// 一行给日志 / 接口用的摘要（错误与告警都收，`ok` 行不重复）。
    pub fn summary(&self) -> String {
        self.checks
            .iter()
            .filter(|check| check.severity != CompatSeverity::Ok)
            .map(|check| check.message.clone())
            .collect::<Vec<_>>()
            .join("；")
    }
}

/// 从包字节（`.tar.gz`）里读 `compat.json`。
///
/// 只看包根或第一层目录下的声明；读不到 / 不是合法 JSON → `None`（调用方按 `unknown` 处理）。
pub fn read_manifest_from_tar(bytes: &[u8]) -> Option<CompatManifest> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let mut best: Option<(usize, CompatManifest)> = None;
    for entry in archive.entries().ok()? {
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = match entry.path() {
            Ok(path) => path.to_string_lossy().to_string(),
            Err(_) => continue,
        };
        let name = path.rsplit('/').next().unwrap_or("");
        if !COMPAT_MANIFEST_FILES.contains(&name) {
            continue;
        }
        let depth = path.matches('/').count();
        if depth > 2 || entry.size() == 0 || entry.size() > MAX_MANIFEST_BYTES {
            continue;
        }
        let mut text = String::new();
        if entry.read_to_string(&mut text).is_err() {
            continue;
        }
        let Ok(manifest) = serde_json::from_str::<CompatManifest>(&text) else {
            continue;
        };
        // 越浅越可信（包根的 compat.json 优先于第一层目录里的）。
        if best
            .as_ref()
            .map(|(best_depth, _)| depth < *best_depth)
            .unwrap_or(true)
        {
            best = Some((depth, manifest));
        }
    }
    best.map(|(_, manifest)| manifest)
}

/// 从已解开的目录里读 `compat.json`（知识库包缓存目录用）。
pub fn read_manifest_from_dir(dir: &Path) -> Option<CompatManifest> {
    if let Some(manifest) = read_manifest_file(dir) {
        return Some(manifest);
    }
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir()
            && let Some(manifest) = read_manifest_file(&path)
        {
            return Some(manifest);
        }
    }
    None
}

fn read_manifest_file(dir: &Path) -> Option<CompatManifest> {
    for name in COMPAT_MANIFEST_FILES {
        let path = dir.join(name);
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Ok(manifest) = serde_json::from_str::<CompatManifest>(&text) {
            return Some(manifest);
        }
    }
    None
}

/// 从路径读：目录 → 找 `compat.json`；文件 → 按 `.tar.gz` 解析。
pub fn read_manifest_from_path(path: &Path) -> Option<CompatManifest> {
    if path.is_dir() {
        return read_manifest_from_dir(path);
    }
    let bytes = std::fs::read(path).ok()?;
    read_manifest_from_tar(&bytes)
}

/// 对一份包做兼容性检查。
///
/// `package` / `version` 是包的身份（用于报告展示）；`current` 是**当前节点**掌握的
/// peer 版本（如 `{"wist-gateway": "0.8.2"}`）。
pub fn check(
    manifest: Option<&CompatManifest>,
    package: &str,
    version: &str,
    current: &BTreeMap<String, String>,
    checked_at: &str,
) -> CompatReport {
    let Some(manifest) = manifest else {
        return CompatReport {
            status: CompatStatus::Unknown,
            checked_at: checked_at.to_string(),
            current: current.clone(),
            checks: vec![CompatCheck {
                package: package.to_string(),
                version: version.to_string(),
                peer: "*".to_string(),
                required: "*".to_string(),
                actual: String::new(),
                ok: false,
                severity: CompatSeverity::Warn,
                message: "包内没有 compat.json：兼容性未声明，安装/激活前请确认上下游版本"
                    .to_string(),
            }],
        };
    };

    let mut checks = Vec::new();
    let mut has_error = false;
    let mut has_warn = false;

    // 自报身份与包身份不一致：多半是复制粘贴了别的包的 manifest。只告警，不阻止
    // （包的组件/版本仍以包名/包内目录名为准）。
    let declared_component = manifest.component.trim();
    if !declared_component.is_empty() && declared_component != package {
        has_warn = true;
        checks.push(check_row(
            package,
            version,
            "manifest.component",
            package,
            declared_component,
            false,
            CompatSeverity::Warn,
            format!(
                "compat.json 自报 component 是 `{declared_component}`，与包的组件 `{package}` 不一致"
            ),
        ));
    }
    let declared_version = manifest.version.trim();
    if !declared_version.is_empty()
        && normalize_version(declared_version) != normalize_version(version)
    {
        has_warn = true;
        checks.push(check_row(
            package,
            version,
            "manifest.version",
            version,
            declared_version,
            false,
            CompatSeverity::Warn,
            format!(
                "compat.json 自报 version 是 `{declared_version}`，与包的版本 `{version}` 不一致"
            ),
        ));
    }

    for (peer, required) in &manifest.requires {
        let actual = current.get(peer).cloned().unwrap_or_default();
        if actual.is_empty() {
            has_warn = true;
            checks.push(check_row(
                package,
                version,
                peer,
                required,
                &actual,
                false,
                CompatSeverity::Warn,
                format!("当前节点没有 `{peer}` 的版本信息，无法判定兼容性"),
            ));
            continue;
        }
        match satisfies(&actual, required) {
            Some(true) => checks.push(check_row(
                package,
                version,
                peer,
                required,
                &actual,
                true,
                CompatSeverity::Ok,
                format!("`{peer}` {actual} 满足 `{required}`"),
            )),
            Some(false) => {
                // `requires` 不满足时，再看声明了 compat 模式可共存的范围。
                let coexists = manifest
                    .compat_mode
                    .then(|| manifest.coexists_with.get(peer))
                    .flatten()
                    .and_then(|range| satisfies(&actual, range).map(|ok| (range, ok)))
                    .filter(|(_, ok)| *ok);
                if let Some((range, _)) = coexists {
                    has_warn = true;
                    checks.push(check_row(
                        package,
                        version,
                        peer,
                        required,
                        &actual,
                        false,
                        CompatSeverity::Warn,
                        format!(
                            "`{peer}` {actual} 不在要求范围 `{required}` 内，但在 `coexists_with` `{range}` 内：需要开兼容模式"
                        ),
                    ));
                } else {
                    has_error = true;
                    checks.push(check_row(
                        package,
                        version,
                        peer,
                        required,
                        &actual,
                        false,
                        CompatSeverity::Error,
                        format!(
                            "`{package}` {version} 要求 `{peer}` `{required}`，当前是 {actual}：请先升级 `{peer}` 当前节点，或改用兼容版本"
                        ),
                    ));
                }
            }
            None => {
                has_warn = true;
                checks.push(check_row(
                    package,
                    version,
                    peer,
                    required,
                    &actual,
                    false,
                    CompatSeverity::Warn,
                    format!("无法解析版本范围 `{required}` 或当前版本 `{actual}`"),
                ));
            }
        }
    }

    // 下游范围只告警：当前节点有该 peer 时提示，但不阻止。
    for (peer, supported) in &manifest.supports {
        let Some(actual) = current.get(peer).filter(|value| !value.is_empty()) else {
            continue;
        };
        match satisfies(actual, supported) {
            Some(true) => checks.push(check_row(
                package,
                version,
                peer,
                supported,
                actual,
                true,
                CompatSeverity::Ok,
                format!("下游 `{peer}` {actual} 在支持范围 `{supported}` 内"),
            )),
            Some(false) => {
                has_warn = true;
                checks.push(check_row(
                    package,
                    version,
                    peer,
                    supported,
                    actual,
                    false,
                    CompatSeverity::Warn,
                    format!("下游 `{peer}` {actual} 不在支持范围 `{supported}` 内"),
                ));
            }
            None => {
                has_warn = true;
                checks.push(check_row(
                    package,
                    version,
                    peer,
                    supported,
                    actual,
                    false,
                    CompatSeverity::Warn,
                    format!("无法解析下游范围 `{supported}` 或当前版本 `{actual}`"),
                ));
            }
        }
    }

    let status = if has_error {
        CompatStatus::Error
    } else if has_warn {
        CompatStatus::Warn
    } else {
        CompatStatus::Ok
    };
    CompatReport {
        status,
        checked_at: checked_at.to_string(),
        current: current.clone(),
        checks,
    }
}

#[allow(clippy::too_many_arguments)]
fn check_row(
    package: &str,
    version: &str,
    peer: &str,
    required: &str,
    actual: &str,
    ok: bool,
    severity: CompatSeverity,
    message: String,
) -> CompatCheck {
    CompatCheck {
        package: package.to_string(),
        version: version.to_string(),
        peer: peer.to_string(),
        required: required.to_string(),
        actual: actual.to_string(),
        ok,
        severity,
        message,
    }
}

/// 版本是否满足范围。认不出来返回 `None`（调用方按“未知”处理，不要猜）。
///
/// 支持：`*`、`1.2.3`、`>=1.2.3`、`>1.2.3`、`<=`、`<`、`=`、`==`、`^`、`~`；
/// 多个条件用空格或逗号分隔（AND），多个候选范围用 `||` 分隔（OR）。
pub fn satisfies(actual: &str, requirement: &str) -> Option<bool> {
    let actual = parse_version(&normalize_version(actual))?;
    let requirement = requirement.trim();
    if requirement.is_empty() || requirement == "*" {
        return Some(true);
    }
    let requirement = normalize_operator_spaces(requirement);
    let mut saw_alternative = false;
    for alternative in requirement.split("||") {
        let alternative = alternative.trim();
        if alternative.is_empty() {
            continue;
        }
        saw_alternative = true;
        let mut all = true;
        for token in alternative
            .split([',', ' '])
            .filter(|token| !token.trim().is_empty())
        {
            let comparator = parse_comparator(token.trim())?;
            if !comparator.matches(&actual) {
                all = false;
                break;
            }
        }
        if all {
            return Some(true);
        }
    }
    if !saw_alternative {
        return None;
    }
    Some(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operator {
    GreaterOrEqual,
    Greater,
    LessOrEqual,
    Less,
    Equal,
    Caret,
    Tilde,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Comparator {
    operator: Operator,
    version: Vec<u64>,
}

impl Comparator {
    fn matches(&self, actual: &[u64]) -> bool {
        match self.operator {
            Operator::GreaterOrEqual => cmp_versions(actual, &self.version) != Ordering::Less,
            Operator::Greater => cmp_versions(actual, &self.version) == Ordering::Greater,
            Operator::LessOrEqual => cmp_versions(actual, &self.version) != Ordering::Greater,
            Operator::Less => cmp_versions(actual, &self.version) == Ordering::Less,
            Operator::Equal => cmp_versions(actual, &self.version) == Ordering::Equal,
            Operator::Caret => {
                cmp_versions(actual, &self.version) != Ordering::Less
                    && cmp_versions(actual, &caret_upper_bound(&self.version)) == Ordering::Less
            }
            Operator::Tilde => {
                cmp_versions(actual, &self.version) != Ordering::Less
                    && cmp_versions(actual, &tilde_upper_bound(&self.version)) == Ordering::Less
            }
        }
    }
}

fn parse_comparator(token: &str) -> Option<Comparator> {
    let (operator, rest) = if let Some(rest) = token.strip_prefix(">=") {
        (Operator::GreaterOrEqual, rest)
    } else if let Some(rest) = token.strip_prefix("<=") {
        (Operator::LessOrEqual, rest)
    } else if let Some(rest) = token.strip_prefix("==") {
        (Operator::Equal, rest)
    } else if let Some(rest) = token.strip_prefix('>') {
        (Operator::Greater, rest)
    } else if let Some(rest) = token.strip_prefix('<') {
        (Operator::Less, rest)
    } else if let Some(rest) = token.strip_prefix('=') {
        (Operator::Equal, rest)
    } else if let Some(rest) = token.strip_prefix('^') {
        (Operator::Caret, rest)
    } else if let Some(rest) = token.strip_prefix('~') {
        (Operator::Tilde, rest)
    } else {
        (Operator::Equal, token)
    };
    let version = parse_version(&normalize_version(rest.trim()))?;
    Some(Comparator { operator, version })
}

fn normalize_operator_spaces(value: &str) -> String {
    let mut out = value.to_string();
    for operator in [">=", "<=", "==", ">", "<", "=", "^", "~"] {
        out = out.replace(&format!("{operator} "), operator);
    }
    out
}

fn cmp_versions(left: &[u64], right: &[u64]) -> Ordering {
    let len = left.len().max(right.len());
    for index in 0..len {
        let left = left.get(index).copied().unwrap_or(0);
        let right = right.get(index).copied().unwrap_or(0);
        match left.cmp(&right) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

fn caret_upper_bound(version: &[u64]) -> Vec<u64> {
    let major = version.first().copied().unwrap_or(0);
    if major > 0 {
        return vec![major + 1, 0, 0];
    }
    match version.len() {
        // `^0` → <1.0.0；`^0.0` → <0.1.0
        0 | 1 => vec![1, 0, 0],
        2 => vec![0, version[1] + 1, 0],
        _ => {
            if version[1] > 0 {
                // `^0.2.3` → <0.3.0
                vec![0, version[1] + 1, 0]
            } else {
                // `^0.0.3` → <0.0.4
                vec![0, 0, version[2] + 1]
            }
        }
    }
}

fn tilde_upper_bound(version: &[u64]) -> Vec<u64> {
    let major = version.first().copied().unwrap_or(0);
    if version.len() <= 1 {
        // `~1` → <2.0.0（不是 <1.1.0）
        vec![major + 1, 0, 0]
    } else {
        // `~1.2` / `~1.2.3` → <1.3.0
        vec![major, version[1] + 1, 0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn manifest(json: &str) -> CompatManifest {
        serde_json::from_str(json).expect("manifest")
    }

    fn current(peer: &str, version: &str) -> BTreeMap<String, String> {
        BTreeMap::from([(peer.to_string(), version.to_string())])
    }

    #[test]
    fn ranges_accept_the_documented_forms() {
        assert_eq!(satisfies("0.9.1", ">=0.9.0 <0.10.0"), Some(true));
        assert_eq!(satisfies("0.8.2", ">=0.9.0 <0.10.0"), Some(false));
        assert_eq!(satisfies("1.5.0", "^1.2.0"), Some(true));
        assert_eq!(satisfies("2.0.0", "^1.2.0"), Some(false));
        assert_eq!(satisfies("0.2.5", "^0.2.3"), Some(true));
        assert_eq!(satisfies("0.3.0", "^0.2.3"), Some(false));
        assert_eq!(satisfies("1.2.9", "~1.2.0"), Some(true));
        assert_eq!(satisfies("1.3.0", "~1.2.0"), Some(false));
        assert_eq!(satisfies("1.2.3", "1.2.3"), Some(true));
        assert_eq!(satisfies("1.2", "1.2.0"), Some(true));
        assert_eq!(satisfies("1.2.3", ">=1.0.0 || >=2.0.0 <3.0.0"), Some(true));
        assert_eq!(satisfies("1.2.3", ">=1.0.0, <1.2.0"), Some(false));
        assert_eq!(satisfies("v1.2.3", ">=1.2.0"), Some(true));
        assert_eq!(satisfies("dev", ">=1.2.0"), None);
        // 缺段的 caret / tilde 按 semver：`~1` 是 1.x，`^0` 是 0.x，`^0.0` 是 0.0.x。
        assert_eq!(satisfies("1.9.0", "~1"), Some(true));
        assert_eq!(satisfies("2.0.0", "~1"), Some(false));
        assert_eq!(satisfies("0.9.0", "^0"), Some(true));
        assert_eq!(satisfies("1.0.0", "^0"), Some(false));
        assert_eq!(satisfies("0.0.9", "^0.0"), Some(true));
        assert_eq!(satisfies("0.1.0", "^0.0"), Some(false));
    }

    #[test]
    fn no_manifest_is_unknown_and_does_not_block() {
        let report = check(
            None,
            "wist-agentd",
            "1.5.0",
            &current("wist-gateway", "0.8.2"),
            "now",
        );
        assert_eq!(report.status, CompatStatus::Unknown);
        assert!(!report.is_blocking());
        assert_eq!(report.checks.len(), 1);
    }

    #[test]
    fn incompatible_requires_is_an_error_and_mentions_upgrading_the_current_node() {
        let manifest = manifest(
            r#"{"requires":{"wist-gateway":">=0.9.0"},"supports":{},"coexists_with":{},"compat_mode":false,"bridge":[],"reversible":false}"#,
        );
        let report = check(
            Some(&manifest),
            "wist-agentd",
            "1.5.0",
            &current("wist-gateway", "0.8.2"),
            "now",
        );
        assert_eq!(report.status, CompatStatus::Error);
        assert!(report.is_blocking());
        assert!(report.summary().contains("请先升级"));
    }

    #[test]
    fn compat_mode_turns_a_requires_miss_into_a_warning() {
        let manifest = manifest(
            r#"{
                "requires":{"wist-gateway":">=0.9.0"},
                "coexists_with":{"wist-gateway":">=0.8.0"},
                "compat_mode":true
            }"#,
        );
        let report = check(
            Some(&manifest),
            "wist-agentd",
            "1.5.0",
            &current("wist-gateway", "0.8.2"),
            "now",
        );
        assert_eq!(report.status, CompatStatus::Warn);
        assert!(!report.is_blocking());
    }

    #[test]
    fn missing_peer_version_is_a_warning_not_an_error() {
        let manifest = manifest(r#"{"requires":{"wist-gateway":">=0.9.0"}}"#);
        let report = check(Some(&manifest), "pkg", "1.0.0", &BTreeMap::new(), "now");
        assert_eq!(report.status, CompatStatus::Warn);
        assert!(!report.is_blocking());
    }

    #[test]
    fn supports_out_of_range_is_a_warning() {
        let manifest = manifest(r#"{"supports":{"wist-agentd":">=0.2.0"}}"#);
        let report = check(
            Some(&manifest),
            "wist-knowledge",
            "1.0.0",
            &current("wist-agentd", "0.1.12"),
            "now",
        );
        assert_eq!(report.status, CompatStatus::Warn);
        assert!(!report.is_blocking());
    }

    #[test]
    fn reads_compat_json_from_a_tar_gz_package() {
        let mut builder = tar::Builder::new(Vec::new());
        let payload = br#"{"component":"wist-agentd","requires":{"wist-gateway":">=0.9.0"}}"#;
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "wist-agentd-1.5.0-aarch64-apple-darwin/compat.json",
                &payload[..],
            )
            .expect("append");
        let tar = builder.into_inner().expect("tar");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar).expect("gzip");
        let bytes = encoder.finish().expect("gzip finish");
        let manifest = read_manifest_from_tar(&bytes).expect("manifest");
        assert_eq!(manifest.component, "wist-agentd");
        assert_eq!(
            manifest.requires.get("wist-gateway").map(String::as_str),
            Some(">=0.9.0")
        );
    }

    #[test]
    fn an_invalid_or_oversized_manifest_is_treated_as_absent() {
        let invalid = br#"{not json"#;
        assert!(read_manifest_from_tar(&tar_gz("pkg/compat.json", invalid)).is_none());
        let oversized = format!(
            r#"{{"component":"x","padding":"{}"}}"#,
            "a".repeat(70 * 1024)
        );
        assert!(read_manifest_from_tar(&tar_gz("pkg/compat.json", oversized.as_bytes())).is_none());
    }

    #[test]
    fn reads_the_manifest_from_a_directory_root_or_first_level() {
        let root = temp_dir("manifest-dir");
        std::fs::write(
            root.join("compat.json"),
            r#"{"requires":{"wist-gateway":">=0.9.0"}}"#,
        )
        .expect("write manifest");
        assert!(read_manifest_from_dir(&root).is_some());

        std::fs::remove_file(root.join("compat.json")).expect("remove");
        let nested = root.join("wist-agentd-1.0.0");
        std::fs::create_dir_all(&nested).expect("nested");
        std::fs::write(
            nested.join("compat.json"),
            r#"{"requires":{"wist-gateway":">=0.9.0"}}"#,
        )
        .expect("write nested");
        assert!(read_manifest_from_dir(&root).is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_non_tar_path_has_no_manifest() {
        let root = temp_dir("manifest-file");
        let file = root.join("package.tar.gz");
        std::fs::write(&file, b"not a tar.gz").expect("write");
        assert!(read_manifest_from_path(&file).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn coexists_with_without_compat_mode_is_still_an_error() {
        let manifest = manifest(
            r#"{
                "requires":{"wist-gateway":">=0.9.0"},
                "coexists_with":{"wist-gateway":">=0.8.0"},
                "compat_mode":false
            }"#,
        );
        let report = check(
            Some(&manifest),
            "wist-agentd",
            "1.5.0",
            &current("wist-gateway", "0.8.2"),
            "now",
        );
        assert_eq!(report.status, CompatStatus::Error);
    }

    #[test]
    fn one_failed_requirement_among_many_is_still_an_error() {
        let manifest =
            manifest(r#"{"requires":{"wist-gateway":">=0.9.0","wist-center":">=0.1.0"}}"#);
        let current = BTreeMap::from([
            ("wist-gateway".to_string(), "0.8.2".to_string()),
            ("wist-center".to_string(), "0.23.0".to_string()),
        ]);
        let report = check(Some(&manifest), "pkg", "1.0.0", &current, "now");
        assert_eq!(report.status, CompatStatus::Error);
        assert_eq!(report.checks.len(), 2);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.peer == "wist-center" && check.ok)
        );
    }

    #[test]
    fn an_unparsable_range_is_a_warning_not_an_error() {
        let manifest = manifest(r#"{"requires":{"wist-gateway":"not-a-range"}}"#);
        let report = check(
            Some(&manifest),
            "pkg",
            "1.0.0",
            &current("wist-gateway", "0.8.2"),
            "now",
        );
        assert_eq!(report.status, CompatStatus::Warn);
        assert!(!report.is_blocking());
    }

    #[test]
    fn a_missing_downstream_peer_is_simply_not_checked() {
        let manifest = manifest(r#"{"supports":{"wist-agentd":">=0.2.0"}}"#);
        let report = check(Some(&manifest), "pkg", "1.0.0", &BTreeMap::new(), "now");
        assert_eq!(report.status, CompatStatus::Ok);
        assert!(report.checks.is_empty());
    }

    #[test]
    fn summary_includes_warnings_as_well_as_errors() {
        let manifest = manifest(r#"{"requires":{"wist-gateway":">=0.9.0"}}"#);
        let report = check(Some(&manifest), "pkg", "1.0.0", &BTreeMap::new(), "now");
        assert!(report.summary().contains("无法判定"));
    }

    #[test]
    fn a_manifest_identity_mismatch_is_a_warning() {
        let manifest = manifest(r#"{"component":"wist-gateway","version":"9.9.9"}"#);
        let report = check(
            Some(&manifest),
            "wist-agentd",
            "1.0.0",
            &BTreeMap::new(),
            "now",
        );
        assert_eq!(report.status, CompatStatus::Warn);
        assert_eq!(report.checks.len(), 2);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.peer == "manifest.component")
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.peer == "manifest.version")
        );
    }

    #[test]
    fn a_matching_manifest_identity_is_clean() {
        let manifest = manifest(r#"{"component":"wist-agentd","version":"v1.0.0"}"#);
        let report = check(
            Some(&manifest),
            "wist-agentd",
            "1.0.0",
            &BTreeMap::new(),
            "now",
        );
        assert_eq!(report.status, CompatStatus::Ok);
        assert!(report.checks.is_empty());
    }

    fn tar_gz(path: &str, payload: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, payload)
            .expect("append");
        let tar = builder.into_inner().expect("tar");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar).expect("gzip");
        encoder.finish().expect("gzip finish")
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wist-compat-{label}-{nanos}"));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }
}
