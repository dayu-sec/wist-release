//! 安装包内核：**来源 → 校验 → 身份 → 命名** 的纯逻辑（不含存储 / 端点 / 鉴权）。
//!
//! 这套口径原先在 `wist-center/src/infra/package.rs` 与 `wist-gateway/src/api/install_package.rs`
//! **各写了一份**（当时刻意重复）；现在收进本模块，两侧共用一份，避免漂移。各自的
//! 存储 / 端点 / 鉴权 / 来源策略仍留在各自仓里。

use std::time::Duration;

/// 拉取来源的超时（制品可能几十 MB，给足时间，但不能无限等）。
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(120);
/// 单包大小上限（防误拉一个大文件把内存吃光）。
pub const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;

/// 取包失败：调用方据此区分「摘要填错了」与「来源拿不到」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageError {
    /// 来源读不到（路径不存在 / URL 拉不到 / 超限）。
    SourceUnavailable(String),
    /// 与期望摘要不符。
    DigestMismatch(String),
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageError::SourceUnavailable(detail) | PackageError::DigestMismatch(detail) => {
                f.write_str(detail)
            }
        }
    }
}

impl std::error::Error for PackageError {}

/// 字节 sha256（裸 hex，不带 `sha256:` 前缀）。
pub fn sha256_hex_bytes(bytes: &[u8]) -> String {
    hex_lower(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

/// 内容寻址 id：`pkg-<sha256 前 16 位>`（裸 hex）。
///
/// 取前 16 位（64 bit）足够区分设备内录入的包，同时保持文件名短、可读。
pub fn package_id_for_sha256(sha256_hex: &str) -> String {
    let prefix: String = sha256_hex.chars().take(16).collect();
    format!("pkg-{prefix}")
}

/// 读来源（**本机绝对路径** 或 https URL）→ 字节。
///
/// 「本机路径」是允许且常见的：包可能就在本机、外网访问不到，或还在开发。
pub async fn read_source(source: &str) -> Result<Vec<u8>, PackageError> {
    if source.starts_with('/') {
        return std::fs::read(source).map_err(|err| {
            PackageError::SourceUnavailable(format!("failed to read package from {source}: {err}"))
        });
    }
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|err| {
            PackageError::SourceUnavailable(format!("failed to build http client: {err}"))
        })?;
    let response = client.get(source).send().await.map_err(|err| {
        PackageError::SourceUnavailable(format!("failed to fetch package from {source}: {err}"))
    })?;
    if !response.status().is_success() {
        return Err(PackageError::SourceUnavailable(format!(
            "package source {source} returned HTTP {}",
            response.status()
        )));
    }
    if let Some(len) = response.content_length()
        && len > MAX_PACKAGE_BYTES
    {
        return Err(PackageError::SourceUnavailable(format!(
            "package at {source} is {len} bytes, over the {MAX_PACKAGE_BYTES} byte limit"
        )));
    }
    let bytes = response.bytes().await.map_err(|err| {
        PackageError::SourceUnavailable(format!("failed to read package body from {source}: {err}"))
    })?;
    if bytes.len() as u64 > MAX_PACKAGE_BYTES {
        return Err(PackageError::SourceUnavailable(format!(
            "package at {source} is {} bytes, over the {MAX_PACKAGE_BYTES} byte limit",
            bytes.len()
        )));
    }
    Ok(bytes.to_vec())
}

/// 读来源 → 校验期望摘要（可带 `sha256:` 前缀），返回（字节, 裸 hex sha256）。
pub async fn read_verified_source(
    source: &str,
    expected_sha256: Option<&str>,
) -> Result<(Vec<u8>, String), PackageError> {
    let bytes = read_source(source).await?;
    let actual = sha256_hex_bytes(&bytes);
    if let Some(expected) = expected_sha256 {
        let expected_hex = expected
            .strip_prefix("sha256:")
            .unwrap_or(expected)
            .to_ascii_lowercase();
        if actual != expected_hex {
            return Err(PackageError::DigestMismatch(format!(
                "package sha256 mismatch: expected {expected_hex} got {actual}"
            )));
        }
    }
    Ok((bytes, actual))
}

/// 版本比对用归一：忽略首尾空白与可选的 `v` 前缀（包内自报常按 git tag 带 `v`）。
pub fn normalize_version(value: &str) -> String {
    value.trim().trim_start_matches('v').to_string()
}

/// 制品文件名：取来源（路径 / URL）的**末段原名**（去掉查询串 / fragment）。
///
/// 用**原文件名**而非内容寻址 id：下发 URL 的末段就是原名，人看着清楚、下载即得可用文件。
/// 取不到 / 不安全（空、`.`、`..`、含分隔符）就回落 `{component}-{version}.bin`（防路径穿越）。
pub fn artifact_filename(url: &str, component: &str, version: &str) -> String {
    let leading = url.split(['?', '#']).next().unwrap_or(url);
    let basename = leading.rsplit('/').next().unwrap_or("");
    if basename.is_empty() || basename == "." || basename == ".." || basename.contains(['/', '\\'])
    {
        return format!("{component}-{version}.bin");
    }
    basename.to_string()
}

/// 从「来源 + 包字节」读出 `(version, arch)`，读不出返回 `("", "")`。**宽松口径**，供中心托管任意包。
///
/// 覆盖当前几类安装包：
/// 1. **二进制包**：`<name>-<version>-<triple>.tar.gz`，顶层一层同名目录 → 目录名带身份；
/// 2. **部署栈包**：`<name>-<version>.tar.gz`，顶层是 `sys/…`（git archive，无包装目录）→ 回落文件名；
/// 3. 读不出（临时文件名、无版本号、非 gzip 字节）→ 空串而**不报错**（仍能被托管与分发）。
///
/// 注意：回落到文件名时**不要求** target-triple（部署栈包的版本只体现在文件名里）。
/// 若调用方只认「带 target-triple 的二进制包」（如网关的 agent 安装包），用 [`read_binary_package_identity`]。
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
/// - 以「某段起头是已知架构名」定位 target-triple（版本自身可能带 `-`，如 `v0.2.0-beta.1`）；
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

/// target-triple 起始的 `-` 下标（其后即三元组）。取**最靠前**的已知架构名。
fn triple_start(name: &str) -> Option<usize> {
    for (index, _) in name.match_indices('-') {
        let candidate = &name[index + 1..];
        let arch_head = candidate.split('-').next().unwrap_or("");
        if KNOWN_TRIPLE_ARCHES.contains(&arch_head) {
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

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
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
    fn sha256_hex_bytes_matches_known_vector() {
        assert_eq!(
            sha256_hex_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn package_id_is_stable_prefixed_and_digest_sized() {
        let id = package_id_for_sha256("0123456789abcdef0123");
        assert_eq!(id, "pkg-0123456789abcdef");
        assert_eq!(id, package_id_for_sha256("0123456789abcdef0123"));
    }

    #[test]
    fn artifact_filename_uses_the_source_basename_and_guards_paths() {
        assert_eq!(
            artifact_filename(
                "https://github.com/galaxio-labs/galaxy-flow/releases/download/v0.16.1-alpha/galaxy-flow-v0.16.1-alpha-x86_64-unknown-linux-musl.tar.gz",
                "galaxy-flow",
                "v0.16.1-alpha",
            ),
            "galaxy-flow-v0.16.1-alpha-x86_64-unknown-linux-musl.tar.gz"
        );
        assert_eq!(
            artifact_filename("https://x/pkg.tar.gz?sig=1#frag", "c", "1.0"),
            "pkg.tar.gz"
        );
        assert_eq!(
            artifact_filename("https://x/dir/", "galaxy-ops", "1.2.3"),
            "galaxy-ops-1.2.3.bin"
        );
        assert_eq!(
            artifact_filename("/opt/pkgs/..", "galaxy-ops", "1.2.3"),
            "galaxy-ops-1.2.3.bin"
        );
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
    fn normalize_version_ignores_whitespace_and_leading_v() {
        assert_eq!(normalize_version(" v0.1.32 "), normalize_version("0.1.32"));
        assert_ne!(normalize_version("0.1.32"), normalize_version("0.1.33"));
    }

    #[tokio::test]
    async fn reads_a_local_path_and_verifies_the_expected_digest() {
        let path = std::env::temp_dir().join("wist-release-src.bin");
        std::fs::write(&path, b"payload").expect("write");
        let source = path.to_string_lossy().to_string();

        let (bytes, sha) = read_verified_source(&source, None).await.expect("read");
        assert_eq!(bytes, b"payload");
        assert_eq!(sha.len(), 64);

        read_verified_source(&source, Some(&sha))
            .await
            .expect("matching digest");
        read_verified_source(&source, Some(&format!("sha256:{sha}")))
            .await
            .expect("prefixed digest");
        let err = read_verified_source(&source, Some("deadbeef"))
            .await
            .expect_err("mismatch");
        assert!(matches!(err, PackageError::DigestMismatch(_)), "{err}");

        let err = read_source("/definitely/not/here.bin")
            .await
            .expect_err("missing");
        assert!(matches!(err, PackageError::SourceUnavailable(_)), "{err}");

        let _ = std::fs::remove_file(path);
    }
}
