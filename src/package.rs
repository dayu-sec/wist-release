//! 安装包的**身份解析**：从「来源 + 包字节」读出 `(version, arch)`。
//!
//! 这一层是**发布域**的：它知道「什么是一个安装包」的布局口径 ——
//! `<name>-<version>-<target-triple>.tar.gz` 顶层一层同名目录（或部署栈包的 `sys/…` + 文件名带版本），
//! 以及「已知 target-triple 表」这类知识。因此它需要解包依赖（`flate2` / `tar`），
//! **被管端（agentd）就不该依赖它**。
//!
//! 取来源 / 摘要 / 版本比较 / 命名与路径安全这些**两边都要用**的口径在底座 crate
//! [`wist_artifact`]，本模块**原样转出**（`pub use`）—— 既有调用点
//! （`wist_release::package::read_verified_source` 等）与设计文档的引用继续成立。

// ── 底座（`wist-artifact`）原样转出：两边共用的制品口径 ──
// 名字保持与本模块历史一致（`PackageError` / `MAX_PACKAGE_BYTES`），
// 免得 center / gateway 的调用点跟着改。
pub use wist_artifact::digest::{parse_digest, sha256_hex_bytes};
pub use wist_artifact::naming::{
    artifact_filename, content_id, is_safe_path_segment, package_id_for_sha256,
};
pub use wist_artifact::source::{
    ArtifactError as PackageError, FETCH_TIMEOUT, MAX_ARTIFACT_BYTES as MAX_PACKAGE_BYTES,
    read_local_source, read_source, read_source_with_client, read_source_within,
    read_verified_source,
};
pub use wist_artifact::version::{normalize_version, parse_version, version_is_newer};

/// 从「来源 + 包字节」读出 `(version, arch)`，读不出返回 `("", "")`。**宽松口径**，供中心托管任意包。
///
/// 覆盖当前几类安装包：
/// 1. **二进制包**：`<name>-<version>-<triple>.tar.gz`，顶层一层同名目录 → 目录名带身份；
/// 2. **部署栈包**：`<name>-<version>.tar.gz`，顶层是 `sys/…`（git archive，无包装目录）→ 回落文件名；
/// 3. 读不出（临时文件名、无版本号、非 gzip 字节）→ 空串而**不报错**（仍能被托管与分发）。
///
/// 版本与平台**分别取最可信的一方，可跨来源补齐**：
/// - **版本**：包内顶层目录名切得出就用它（正规二进制包更可信），否则用来源文件名；
/// - **平台**：目录名切得出 target-triple 就用它；切不出时**回落来源文件名** —— 如
///   `galaxy-ops-v2.2.1-alpha-aarch64-apple-darwin.tar.gz` 顶层目录只有 `<name>-<version>`，
///   平台只在文件名里。两边都切不出 → 留空（界面显示「通用」）。
///
/// 注意：回落到文件名时**不要求** target-triple（部署栈包的版本只体现在文件名里）。
/// 若调用方只认「带 target-triple 的二进制包」（如网关的 agent 安装包），用
/// [`read_binary_package_identity`]。
pub fn read_package_identity(source: &str, bytes: &[u8]) -> (String, String) {
    // 包内首条目目录名（正规二进制包在这里带身份）。
    let from_dir = first_tar_entry_component(bytes).map(|dir| parse_package_name(&dir));
    // 来源末段（部署栈包顶层不带身份，但文件名带版本 / target-triple）。
    let from_name = parse_package_name(source_basename(source));

    // 版本：目录名切得出优先，否则回落文件名。
    let dir_version = from_dir
        .as_ref()
        .map(|(version, _)| version.clone())
        .filter(|version| !version.is_empty());
    let version = dir_version.unwrap_or(from_name.0);

    // 平台：目录名切出 target-triple 优先，切不出回落文件名。
    let arch = from_dir
        .map(|(_, arch)| arch)
        .filter(|arch| !arch.is_empty())
        .unwrap_or(from_name.1);

    // 版本都切不出 → 整体留空（调用方据此判断「读不出身份」）。
    if version.is_empty() {
        return (String::new(), String::new());
    }
    (version, arch)
}

/// 二进制安装包的 `(version, arch)`（网关侧口径）。
///
/// 与 [`read_package_identity`] 的差别有两点：
/// - **只认包内目录名**，不回落来源文件名；
/// - 目录名必须切出**已知 target-triple** —— 读不出架构就整体留空，绝不把「版本」从
///   `wist-agentd-1.2.3-some-unknown-triple` 这类名字里错切出来。
///
/// 包是 `wist-agentd-<version>-<target-triple>.tar.gz`，顶层一层同名目录，形如
/// `wist-agentd-0.1.9-aarch64-apple-darwin/wist-agentd`。
///
/// 不是标准包（裸二进制、非 gzip、损坏字节）一律返回空串而**不报错**：这些包仍能被
/// 网关按内容寻址分发，只是历史行里 version/arch 留空；让录入整体失败反而会阻断升级。
pub fn read_binary_package_identity(bytes: &[u8]) -> (String, String) {
    let Some(dir) = first_tar_entry_component(bytes) else {
        return (String::new(), String::new());
    };
    let (version, arch) = parse_package_name(&dir);
    if version.is_empty() || arch.is_empty() {
        return (String::new(), String::new());
    }
    (version, arch)
}

/// 取来源的末段（路径 / URL 的文件名），并剥掉查询串 / fragment。
fn source_basename(source: &str) -> &str {
    let without_query = source.split(['?', '#']).next().unwrap_or(source);
    without_query.rsplit('/').next().unwrap_or(without_query)
}

/// gzip + tar 解出第一个条目路径的首段（如 `wist-agentd-0.1.9-aarch64-apple-darwin`）。
/// 任何一步失败都返回 `None`，绝不 panic。
fn first_tar_entry_component(bytes: &[u8]) -> Option<String> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let mut entries = archive.entries().ok()?;
    let entry = entries.next()?.ok()?;
    let path = entry.path().ok()?;
    // 跳过 `./` / `/` 之类非普通段，取第一个普通目录名。
    path.components().find_map(|component| match component {
        std::path::Component::Normal(name) => name.to_str().map(str::to_string),
        _ => None,
    })
}

/// 目标三元组的已知架构前缀（与两侧同表）。
/// 版本自身可能带 `-`（预发布，如 `0.2.0-beta.1`），不能简单按第一个 `-` 切。
const KNOWN_TRIPLE_ARCHES: &[&str] = &[
    "aarch64",
    "x86_64",
    "i686",
    "i586",
    "armv7",
    "armv6",
    "arm",
    "riscv64",
    "powerpc64",
    "powerpc64le",
    "s390x",
    "x86_64h",
    "loongarch64",
];

/// 从形如 `<name>-<version>[-<target-triple>][<压缩后缀>]` 的串里切出 `(version, triple)`。
///
/// 不写死组件名：
/// - 先剥压缩后缀；
/// - 以「某段起头是已知架构名、**且它前面还能切出版本**」定位 target-triple
///   （版本自身可能带 `-`，如 `v0.2.0-beta.1`）；
/// - 版本取「第一个形如 `v?N.N…` 的段」到三元组之前（保留其后的预发布后缀）。
///
/// 切不出返回 `("", "")`。
fn parse_package_name(name: &str) -> (String, String) {
    let name = strip_archive_suffix(name);
    let (version_part, arch) = match triple_start(name) {
        Some(index) => (&name[..index], name[index + 1..].to_string()),
        None => (name, String::new()),
    };
    match version_start(version_part) {
        Some(index) => (version_part[index..].to_string(), arch),
        None => (String::new(), String::new()),
    }
}

/// target-triple 起始的 `-` 下标（其后即三元组）。
///
/// 取**最靠前**的「其前还能切出版本」的候选。加后半个条件是为了躲开包名里本来就带架构词的
/// 假阳性：`wist-arm-stack-1.2.3` 的 `-arm-` 会被当成三元组起头，从而把版本整段丢掉；
/// 加上该条件后它退回「没有三元组」→ 版本仍能切出 `1.2.3`。
fn triple_start(name: &str) -> Option<usize> {
    for (index, _) in name.match_indices('-') {
        let candidate = &name[index + 1..];
        let arch_head = candidate.split('-').next().unwrap_or("");
        if KNOWN_TRIPLE_ARCHES.contains(&arch_head) && version_start(&name[..index]).is_some() {
            return Some(index);
        }
    }
    None
}

/// 第一个「像版本号」的段在串中的字节下标，用于跳过包名前缀。
fn version_start(name: &str) -> Option<usize> {
    let mut offset = 0;
    for segment in name.split('-') {
        if looks_like_version(segment) {
            return Some(offset);
        }
        offset += segment.len() + 1;
    }
    None
}

/// 段是否像版本号：可选 `v` 前缀 + 至少 `N.N`（`1234`、`2024-10` 这类不算）。
fn looks_like_version(segment: &str) -> bool {
    let rest = segment.strip_prefix(['v', 'V']).unwrap_or(segment);
    let mut parts = rest.split('.');
    let (Some(head), Some(second)) = (parts.next(), parts.next()) else {
        return false;
    };
    !head.is_empty()
        && head.chars().all(|ch| ch.is_ascii_digit())
        && second.chars().next().is_some_and(|ch| ch.is_ascii_digit())
}

/// 剥掉常见压缩 / 归档后缀（只剥一层，够用）。
fn strip_archive_suffix(name: &str) -> &str {
    for suffix in [
        ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tar", ".gz", ".zip", ".bin",
    ] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            return stripped;
        }
    }
    name
}

// ── 安装包结构（版本 + 多平台制品） ──
// 中心与网关共用：**类型 + 纯逻辑**；存储 / 端点 / 状态机留在各应用。

use serde::{Deserialize, Serialize};

/// 平台标识 = 目标三元组（target-triple），如 `aarch64-apple-darwin`。
/// 本模块用 `Option<String>` 承载：无平台概念的包（如部署栈包）为 `None`。
///
/// 平台「家族」：按 OS + CPU 架构归并，**忽略 abi 后缀**（gnu / musl / gnueabihf…）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlatformFamily {
    MacosArm,
    MacosX86,
    LinuxArm,
    LinuxX86,
    WindowsArm,
    WindowsX86,
}

/// 规范化平台串：去空白 + 转小写（比较 / 去重用）。
pub fn normalize_platform(triple: &str) -> String {
    triple.trim().to_ascii_lowercase()
}

/// 把 target-triple 归到平台家族（OS + 架构）；认不出返回 `None`。
pub fn platform_family(triple: &str) -> Option<PlatformFamily> {
    let triple = normalize_platform(triple);
    let arch = triple.split('-').next().unwrap_or("");
    let is_arm = matches!(arch, "aarch64" | "arm64" | "armv8" | "armv7");
    let is_x86 = matches!(arch, "x86_64" | "amd64" | "x64" | "i686" | "i586");
    if triple.contains("apple-darwin") || triple.contains("darwin") {
        if is_arm {
            Some(PlatformFamily::MacosArm)
        } else if is_x86 {
            Some(PlatformFamily::MacosX86)
        } else {
            None
        }
    } else if triple.contains("linux") {
        if is_arm {
            Some(PlatformFamily::LinuxArm)
        } else if is_x86 {
            Some(PlatformFamily::LinuxX86)
        } else {
            None
        }
    } else if triple.contains("windows") {
        if is_arm {
            Some(PlatformFamily::WindowsArm)
        } else if is_x86 {
            Some(PlatformFamily::WindowsX86)
        } else {
            None
        }
    } else {
        None
    }
}

/// 制品：内容身份（sha256）+ 平台 + 取件地址。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseArtifact {
    /// 目标平台（target-triple）；无平台概念为 `None`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// 制品内容的 sha256（裸小写 hex）—— 制品的稳定身份。
    pub sha256: String,
    /// 取件地址 / 来源（URL 或本机路径；由各应用解释）。
    pub source: String,
}

impl ReleaseArtifact {
    pub fn new(
        platform: Option<impl Into<String>>,
        sha256: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            platform: platform.map(Into::into),
            sha256: sha256.into(),
            source: source.into(),
        }
    }
}

/// 安装包 = 版本 + 多个制品（每个平台一个）。
///
/// 键：包 = `version`（在「组件目录」下）；制品 = `sha256`（内容寻址），包内 `platform` 唯一。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasePackage {
    pub version: String,
    pub artifacts: Vec<ReleaseArtifact>,
}

impl ReleasePackage {
    pub fn new(version: impl Into<String>, artifacts: Vec<ReleaseArtifact>) -> Self {
        Self {
            version: version.into(),
            artifacts,
        }
    }

    /// 取某平台的制品（平台按规范化比较）。
    pub fn artifact_for(&self, platform: &str) -> Option<&ReleaseArtifact> {
        let wanted = normalize_platform(platform);
        self.artifacts.iter().find(|artifact| {
            artifact
                .platform
                .as_deref()
                .is_some_and(|value| normalize_platform(value) == wanted)
        })
    }

    /// 包内**有平台**的制品平台列表（规范化、去重、排序）。
    pub fn platforms(&self) -> Vec<String> {
        let mut platforms: Vec<String> = self
            .artifacts
            .iter()
            .filter_map(|artifact| artifact.platform.as_deref())
            .map(normalize_platform)
            .collect();
        platforms.sort();
        platforms.dedup();
        platforms
    }

    /// 是否有多个平台。
    pub fn is_multi_platform(&self) -> bool {
        self.platforms().len() > 1
    }

    /// 平台是否两两不同（无重复平台）。
    pub fn has_distinct_platforms(&self) -> bool {
        let total = self
            .artifacts
            .iter()
            .filter(|artifact| artifact.platform.is_some())
            .count();
        total == self.platforms().len()
    }
}

/// 相对必需平台集，缺哪些（规范化后比较；空 `required` 返回空）。
pub fn missing_platforms(package: &ReleasePackage, required: &[&str]) -> Vec<String> {
    let have = package.platforms();
    let mut missing: Vec<String> = required
        .iter()
        .map(|value| normalize_platform(value))
        .filter(|value| !have.contains(value))
        .collect();
    missing.sort();
    missing.dedup();
    missing
}

/// 校验包的平台：无重复平台、且**覆盖**必需平台集。`required` 为空则只查重复。
pub fn validate_platforms(package: &ReleasePackage, required: &[&str]) -> Result<(), String> {
    if !package.has_distinct_platforms() {
        return Err("package has duplicate platform artifacts".to_string());
    }
    let missing = missing_platforms(package, required);
    if !missing.is_empty() {
        return Err(format!(
            "missing required platforms: {}",
            missing.join(", ")
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tar_gz_with_entry(entry: &str, payload: &[u8]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, entry, payload)
                .expect("append tar entry");
            builder.finish().expect("finish tar");
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &tar_bytes).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }
    #[test]
    fn release_package_reports_platforms_and_missing() {
        use PlatformFamily::*;
        assert_eq!(platform_family("aarch64-apple-darwin"), Some(MacosArm));
        assert_eq!(platform_family("x86_64-apple-darwin"), Some(MacosX86));
        // abi 后缀（gnu / musl）不影响家族。
        assert_eq!(
            platform_family("aarch64-unknown-linux-musl"),
            Some(LinuxArm)
        );
        assert_eq!(platform_family("x86_64-unknown-linux-gnu"), Some(LinuxX86));
        assert_eq!(platform_family("x86_64-pc-windows-msvc"), Some(WindowsX86));
        assert_eq!(platform_family(""), None);
        assert_eq!(
            normalize_platform("  AArch64-Apple-Darwin "),
            "aarch64-apple-darwin"
        );

        let package = ReleasePackage::new(
            "v2.2.2-alpha",
            vec![
                ReleaseArtifact::new(Some("x86_64-unknown-linux-musl"), "aa", "u1"),
                ReleaseArtifact::new(Some("aarch64-apple-darwin"), "bb", "u2"),
                ReleaseArtifact::new(Some("aarch64-unknown-linux-musl"), "cc", "u3"),
            ],
        );
        assert_eq!(
            package.platforms(),
            vec![
                "aarch64-apple-darwin",
                "aarch64-unknown-linux-musl",
                "x86_64-unknown-linux-musl"
            ]
        );
        assert!(package.is_multi_platform());
        assert!(package.has_distinct_platforms());
        assert_eq!(
            package
                .artifact_for("AARCH64-APPLE-DARWIN")
                .map(|artifact| artifact.sha256.as_str()),
            Some("bb")
        );

        let required = [
            "aarch64-apple-darwin",
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-musl",
        ];
        assert!(validate_platforms(&package, &required).is_ok());
        // 缺一个 → 报缺件。
        assert_eq!(
            missing_platforms(
                &package,
                &["aarch64-apple-darwin", "riscv64gc-unknown-linux-gnu"]
            ),
            vec!["riscv64gc-unknown-linux-gnu".to_string()]
        );
    }

    #[test]
    fn validate_platforms_rejects_duplicates() {
        let package = ReleasePackage::new(
            "v1",
            vec![
                ReleaseArtifact::new(Some("aarch64-apple-darwin"), "aa", "u1"),
                ReleaseArtifact::new(Some("aarch64-apple-darwin"), "bb", "u2"),
            ],
        );
        assert!(!package.has_distinct_platforms());
        assert!(validate_platforms(&package, &[]).is_err());
    }

    #[test]
    fn read_package_identity_parses_binary_package_dir() {
        let cases = [
            (
                "wist-agentd-0.1.32-aarch64-apple-darwin/wist-agentd",
                ("0.1.32", "aarch64-apple-darwin"),
            ),
            (
                "wist-agentd-v0.2.0-beta.1-x86_64-unknown-linux-gnu/wist-agentd",
                ("v0.2.0-beta.1", "x86_64-unknown-linux-gnu"),
            ),
            (
                "gops-v0.18.2-aarch64-apple-darwin/gops",
                ("v0.18.2", "aarch64-apple-darwin"),
            ),
            (
                "gx-v0.15.1-x86_64-unknown-linux-gnu/gx",
                ("v0.15.1", "x86_64-unknown-linux-gnu"),
            ),
        ];
        for (entry, expected) in cases {
            let bytes = tar_gz_with_entry(entry, b"bin");
            assert_eq!(
                read_package_identity(entry, &bytes),
                (expected.0.to_string(), expected.1.to_string()),
                "entry {entry}"
            );
        }
    }

    #[test]
    fn read_package_identity_falls_back_to_the_source_name() {
        // 部署栈包：包内首条目是 sys/…，目录名读不出 → 回落文件名。
        let stack = tar_gz_with_entry("sys/sys_model.yml", b"model");
        for source in [
            "/opt/pkgs/wist-gateway-stack-v0.1.17.tar.gz",
            "https://github.com/dayu-sec/wist/releases/download/v0.1.17/wist-gateway-stack-v0.1.17.tar.gz",
        ] {
            assert_eq!(
                read_package_identity(source, &stack),
                ("v0.1.17".to_string(), String::new()),
                "source {source}"
            );
        }
        assert_eq!(
            read_package_identity(
                "https://x/gops-v0.18.2-aarch64-apple-darwin.tar.gz?sig=1",
                &stack
            ),
            ("v0.18.2".to_string(), "aarch64-apple-darwin".to_string())
        );
    }

    #[test]
    fn read_package_identity_returns_empty_for_unreadable_packages() {
        let bytes = tar_gz_with_entry("sys/sys_model.yml", b"x");
        for source in [
            "/opt/pkgs/wist-gateway-stack-notes.tar.gz",
            "/tmp/wic-rel-1728000000000000000.tar.gz",
            "download-1234.bin",
        ] {
            assert_eq!(
                read_package_identity(source, &bytes),
                (String::new(), String::new()),
                "source {source}"
            );
        }
        assert_eq!(
            read_package_identity("/opt/pkgs/thing.tar.gz", b"not a gzip stream"),
            (String::new(), String::new())
        );
    }

    #[test]
    fn binary_package_identity_requires_a_known_triple() {
        // 目录名带已知三元组 → 切出 (version, arch)。
        assert_eq!(
            read_binary_package_identity(&tar_gz_with_entry(
                "wist-agentd-1.2.3-x86_64-unknown-linux-gnu/wist-agentd",
                b"bin",
            )),
            ("1.2.3".to_string(), "x86_64-unknown-linux-gnu".to_string())
        );
        assert_eq!(
            read_binary_package_identity(&tar_gz_with_entry(
                "wist-agentd-0.2.0-beta.1-aarch64-apple-darwin/wist-agentd",
                b"bin",
            )),
            (
                "0.2.0-beta.1".to_string(),
                "aarch64-apple-darwin".to_string()
            )
        );
        // 未知三元组 / 压根没有三元组：整体留空，不把版本错切出来。
        assert_eq!(
            read_binary_package_identity(&tar_gz_with_entry(
                "wist-agentd-1.2.3-some-unknown-triple/wist-agentd",
                b"bin",
            )),
            (String::new(), String::new())
        );
        assert_eq!(
            read_binary_package_identity(&tar_gz_with_entry(
                "wist-agentd-1.2.3/wist-agentd",
                b"bin"
            )),
            (String::new(), String::new())
        );
        // 顶层不带身份（部署栈包）：**不**回落文件名，留空。
        assert_eq!(
            read_binary_package_identity(&tar_gz_with_entry("sys/sys_model.yml", b"model")),
            (String::new(), String::new())
        );
        // 非 gzip / 非 tar：留空，不 panic。
        assert_eq!(
            read_binary_package_identity(b"not a gzip stream"),
            (String::new(), String::new())
        );
    }
    #[test]
    fn read_package_identity_prefers_the_package_dir_over_the_source_name() {
        // 目录名与文件名不一致时，以**包内目录名**为准（文件名只是回落）。
        let bytes = tar_gz_with_entry(
            "wist-agentd-1.2.3-x86_64-unknown-linux-gnu/wist-agentd",
            b"bin",
        );
        assert_eq!(
            read_package_identity(
                "/opt/pkgs/wist-agentd-9.9.9-aarch64-apple-darwin.tar.gz",
                &bytes
            ),
            ("1.2.3".to_string(), "x86_64-unknown-linux-gnu".to_string())
        );
    }

    #[test]
    fn read_package_identity_recovers_arch_from_the_source_name() {
        // 顶层目录只有 `<name>-<version>`（切不出架构）：版本取目录名，**平台回落文件名**。
        let bytes = tar_gz_with_entry("gops-v0.18.2/gops", b"bin");
        assert_eq!(
            read_package_identity("/opt/pkgs/gops-v0.18.2-aarch64-apple-darwin.tar.gz", &bytes),
            ("v0.18.2".to_string(), "aarch64-apple-darwin".to_string())
        );
        // galaxy-ops 同形（带预发布后缀）：版本仍从目录名切，平台从文件名补。
        let galaxy = tar_gz_with_entry("galaxy-ops-v2.2.1-alpha/galaxy-ops", b"bin");
        assert_eq!(
            read_package_identity(
                "/opt/pkgs/galaxy-ops-v2.2.1-alpha-aarch64-apple-darwin.tar.gz",
                &galaxy,
            ),
            (
                "v2.2.1-alpha".to_string(),
                "aarch64-apple-darwin".to_string()
            )
        );
        // 文件名也没有架构（部署栈包）→ 平台仍留空。
        let stack = tar_gz_with_entry("galaxy-ops-v2.2.1-alpha/galaxy-ops", b"bin");
        assert_eq!(
            read_package_identity("/opt/pkgs/galaxy-ops-v2.2.1-alpha.tar.gz", &stack),
            ("v2.2.1-alpha".to_string(), String::new())
        );
    }

    #[test]
    fn read_package_identity_keeps_the_version_when_an_arch_word_is_only_part_of_the_name() {
        // 包名里本来就有架构词（`-arm-`）时，不该把它当三元组起头而把版本整段丢掉。
        let bytes = tar_gz_with_entry("sys/sys_model.yml", b"x");
        for source in [
            "/opt/pkgs/wist-arm-stack-1.2.3.tar.gz",
            "https://x/wist-arm-stack-1.2.3.tar.gz",
        ] {
            assert_eq!(
                read_package_identity(source, &bytes),
                ("1.2.3".to_string(), String::new()),
                "source {source}"
            );
        }
        // 但真三元组仍在时，仍以它切分（`arm` 后面跟着的才是三段式三元组）。
        let bytes = tar_gz_with_entry("wist-arm-tool-1.2.3-aarch64-unknown-linux-gnu/w", b"x");
        assert_eq!(
            read_package_identity("/opt/pkgs/x.tar.gz", &bytes),
            ("1.2.3".to_string(), "aarch64-unknown-linux-gnu".to_string())
        );
    }

    #[test]
    fn read_package_identity_does_not_mistake_a_bare_number_for_a_version() {
        let bytes = tar_gz_with_entry("sys/sys_model.yml", b"x");
        for source in [
            "/opt/pkgs/wist-stack-2024-10.tar.gz",
            "/tmp/wist-stack-build1234.tar.gz",
        ] {
            assert_eq!(
                read_package_identity(source, &bytes),
                (String::new(), String::new()),
                "source {source}"
            );
        }
    }
}
