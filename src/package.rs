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
/// 注意：回落到文件名时**不要求** target-triple（部署栈包的版本只体现在文件名里）。
/// 反过来，一旦**目录名里能切出版本**（哪怕切不出架构），就直接用它、不再回落文件名 —— 二者取一，
/// 不做合并。若调用方只认「带 target-triple 的二进制包」（如网关的 agent 安装包），用
/// [`read_binary_package_identity`]。
pub fn read_package_identity(source: &str, bytes: &[u8]) -> (String, String) {
    // 先看包内首条目目录名（正规二进制包在这里带身份）。
    if let Some(dir) = first_tar_entry_component(bytes) {
        let identity = parse_package_name(&dir);
        if !identity.0.is_empty() {
            return identity;
        }
    }
    // 回落用来源末段（部署栈包顶层不带身份，但文件名带版本）。
    parse_package_name(source_basename(source))
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
    fn read_package_identity_stops_at_a_partial_dir_identity() {
        // 目录名里只要能切出版本，就不再回落文件名 —— 即便文件名上有更全的架构。
        let bytes = tar_gz_with_entry("gops-v0.18.2/gops", b"bin");
        assert_eq!(
            read_package_identity("/opt/pkgs/gops-v0.18.2-aarch64-apple-darwin.tar.gz", &bytes),
            ("v0.18.2".to_string(), String::new())
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
