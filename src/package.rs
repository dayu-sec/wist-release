//! 安装包内核：**来源 → 校验 → 身份 → 命名** 的纯逻辑（不含存储 / 端点 / 鉴权）。
//!
//! 这套口径原先在 `wist-center/src/infra/package.rs` 与 `wist-gateway/src/api/install_package.rs`
//! **各写了一份**（当时刻意重复）；现在收进本模块，两侧共用一份，避免漂移。各自的
//! 存储 / 端点 / 鉴权 / 来源策略仍留在各自仓里。
//!
//! 另外提供两个与路径安全有关的口径，供调用方在**拼目录 / URL 前**把关：
//! [`is_safe_path_segment`]（组件名 / 版本号 / 文件名必须真的只有一段）与
//! [`artifact_filename`]（返回值保证是安全路径段）。

use std::time::Duration;

/// 拉取来源的超时（制品可能几十 MB，给足时间，但不能无限等）。
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(120);
/// 单包大小上限（防误拉一个大文件把内存吃光）。
pub const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;

/// 取包失败：调用方据此区分「摘要填错了」「来源拿不到」「来源太大」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageError {
    /// 来源读不到（路径不存在 / URL 拉不到 / HTTP 非 2xx）。
    SourceUnavailable(String),
    /// 与期望摘要不符。
    DigestMismatch(String),
    /// 来源**超过大小上限**（读完前就拦下）——单独一类，方便调用方给出「太大了」这种可操作的回应。
    TooLarge(String),
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageError::SourceUnavailable(detail)
            | PackageError::DigestMismatch(detail)
            | PackageError::TooLarge(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for PackageError {}

/// 字节 sha256（裸 hex，不带 `sha256:` 前缀）。
pub fn sha256_hex_bytes(bytes: &[u8]) -> String {
    hex_lower(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

/// 内容寻址 id：`<prefix>-<sha256 前 16 位>`（裸 hex）。
///
/// 取前 16 位（64 bit）足够区分一台机器里录入过的包，同时保持文件名短、可读。
/// 前缀由调用方给（安装包 `pkg`、知识库包 `kbp`）—— 同一套取 id 的口径，不各写一遍。
pub fn content_id(prefix: &str, sha256_hex: &str) -> String {
    let digest_prefix: String = sha256_hex.chars().take(16).collect();
    format!("{prefix}-{digest_prefix}")
}

/// 安装包的内容寻址 id：`pkg-<sha256 前 16 位>`（裸 hex）。= `content_id("pkg", …)`。
pub fn package_id_for_sha256(sha256_hex: &str) -> String {
    content_id("pkg", sha256_hex)
}

/// 一个**路径段**是否安全：非空、不是 `.` / `..`、不含路径分隔符与控制字符。
///
/// 用在「组件名 / 版本号 / 制品文件名」这类要拼进目录或 URL 的字段上 —— 它们必须真的只有一段，
/// 否则 `Path::join`（以及对象存储的 key）会顺着 `..` 或绝对路径逃出目标目录。
/// 这是**校验**侧入口（调用方拿它直接 400/404）；[`artifact_filename`] 的回落名另有兜底。
pub fn is_safe_path_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\'])
        && !value.chars().any(char::is_control)
}

/// 把任意输入压成一个**安全的路径段**：分隔符 / 控制字符换成 `-`，空 / `.` / `..` 换成 `_`。
///
/// 给**不能失败**的地方兜底（[`artifact_filename`] 的回落名），保证本模块永远不会产出一个能逃出
/// 目录的段。要「拒绝非法输入」请用 [`is_safe_path_segment`]。
fn sanitize_segment(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|ch| {
            if ch == '/' || ch == '\\' || ch.is_control() {
                '-'
            } else {
                ch
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return "_".to_string();
    }
    cleaned
}

/// 读来源（**本机绝对路径** 或 URL）→ 字节。
///
/// 甄别方式很简单：**以 `/` 开头**当本机绝对路径，其余一律当 URL 交给 reqwest。于是：
/// - 相对路径（`pkgs/x.tar.gz`）不算「路径」，会被当成 URL 解析并失败 —— 本 crate 只认绝对路径；
/// - **不限制 scheme**（`http://` 也收）：是否强制 https 属于调用方的策略，内容真伪由
///   `expected_sha256` 兜底（见 [`read_verified_source`]）。
///
/// 「本机路径」是允许且常见的：包可能就在本机、外网访问不到，或还在开发。
pub async fn read_source(source: &str) -> Result<Vec<u8>, PackageError> {
    read_source_within(source, MAX_PACKAGE_BYTES, FETCH_TIMEOUT).await
}

/// [`read_source`] 的通用形态：**大小上限与超时由调用方给** —— 机制（甄别路径 / URL、在读完前拦
/// 超限、错误分类）共用一份，**策略**（多大算大、等多久）各域自己定：
///
/// - 安装包：512 MiB / 120s（[`MAX_PACKAGE_BYTES`] / [`FETCH_TIMEOUT`]，即 [`read_source`]）；
/// - 知识库内容包小得多：16 MiB / 60s。
///
/// 上限对**两条来源都生效**，且都在**读完前**先拦一道：
/// - 本机路径：先看 `metadata().len()`，超限就直接拒，不把大文件读进内存；
/// - http：先看 `Content-Length`（响应头可能不给，所以读回后再核一次实际长度）。
///
/// ⚠️ 本机分支是**同步** `std::fs::read`（本 crate 不引 tokio 运行时）：从 async 上下文调用时，
/// 读一个几百 MB 的本地文件会占住当前 worker —— 介意就由调用方套 `spawn_blocking`。
pub async fn read_source_within(
    source: &str,
    max_bytes: u64,
    timeout: Duration,
) -> Result<Vec<u8>, PackageError> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|err| {
            PackageError::SourceUnavailable(format!("failed to build http client: {err}"))
        })?;
    read_source_with_client(&client, source, max_bytes, timeout).await
}

/// 与 [`read_source_within`] 同，但用**调用方给的 client**：例如 agentd 取包要走它自己的
/// **mTLS 客户端证书**（网关的分发端点按 agent 身份认证）；本函数不替它构造 client，就不丢掉那层身份。
///
/// `timeout` 作用在**本次请求**上（调用方给的 client 可能没设超时，或是为别的用途配的）。
pub async fn read_source_with_client(
    client: &reqwest::Client,
    source: &str,
    max_bytes: u64,
    timeout: Duration,
) -> Result<Vec<u8>, PackageError> {
    if source.starts_with('/') {
        return read_local_source(source, max_bytes);
    }
    let response = client
        .get(source)
        .timeout(timeout)
        .send()
        .await
        .map_err(|err| {
            PackageError::SourceUnavailable(format!("failed to fetch package from {source}: {err}"))
        })?;
    if !response.status().is_success() {
        return Err(PackageError::SourceUnavailable(format!(
            "package source {source} returned HTTP {}",
            response.status()
        )));
    }
    if let Some(len) = response.content_length()
        && len > max_bytes
    {
        return Err(over_limit(source, len, max_bytes));
    }
    let bytes = response.bytes().await.map_err(|err| {
        PackageError::SourceUnavailable(format!("failed to read package body from {source}: {err}"))
    })?;
    if bytes.len() as u64 > max_bytes {
        return Err(over_limit(source, bytes.len() as u64, max_bytes));
    }
    Ok(bytes.to_vec())
}

/// 读本机路径：先按元数据拦超限，再读，读完再核一次实际长度。
///
/// 两道检查都是必要的：元数据那道保证**不把超大文件读进内存**；实际长度那道挡住
/// 「看元数据时还没长大」的空档（元数据与读之间文件可能变）。
///
/// 单拎出来是因为它有单独的用途：调用方想先自己决定「这次是本机路径还是远端」（例如本机路径
/// 不该去构造一个需要身份 / 信任锚的 HTTP client）时，可以直接走这一支。
pub fn read_local_source(path: &str, max_bytes: u64) -> Result<Vec<u8>, PackageError> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        PackageError::SourceUnavailable(format!("failed to read package from {path}: {err}"))
    })?;
    if metadata.len() > max_bytes {
        return Err(over_limit(path, metadata.len(), max_bytes));
    }
    let bytes = std::fs::read(path).map_err(|err| {
        PackageError::SourceUnavailable(format!("failed to read package from {path}: {err}"))
    })?;
    if bytes.len() as u64 > max_bytes {
        return Err(over_limit(path, bytes.len() as u64, max_bytes));
    }
    Ok(bytes)
}

fn over_limit(source: &str, actual: u64, max_bytes: u64) -> PackageError {
    PackageError::TooLarge(format!(
        "package at {source} is {actual} bytes, over the {max_bytes} byte limit"
    ))
}

/// 读来源 → 校验期望摘要，返回（字节, 裸 hex sha256）。
///
/// 期望摘要先过 [`parse_digest`]（前缀 / 大小写 / 长度都在那里收口）——
/// **填错的摘要**因此会报「摘要形态不对」而不是等成一次不相符。
pub async fn read_verified_source(
    source: &str,
    expected_sha256: Option<&str>,
) -> Result<(Vec<u8>, String), PackageError> {
    let bytes = read_source(source).await?;
    let actual = sha256_hex_bytes(&bytes);
    if let Some(expected) = expected_sha256 {
        let expected_hex = parse_digest(expected).map_err(|detail| {
            PackageError::DigestMismatch(format!("expected sha256 is malformed: {detail}"))
        })?;
        if actual != expected_hex {
            return Err(PackageError::DigestMismatch(format!(
                "package sha256 mismatch: expected {expected_hex} got {actual}"
            )));
        }
    }
    Ok((bytes, actual))
}

/// 期望摘要的**规范形态**：可选 `sha256:` 前缀（大小写不敏感、容忍两侧空格）、裸 hex 大小写不敏感；
/// 但必须是 **64 位 hex**。返回小写裸 hex。
///
/// 长度也校验，是因为「填错一个摘要」几乎总是笔误：早一步说「这不是摘要」，比让它跑完全程
/// 再报一句 mismatch 可操作得多。
pub fn parse_digest(value: &str) -> Result<String, String> {
    let stripped = strip_digest_prefix(value);
    let looks_like_hex = stripped.len() == 64 && stripped.chars().all(|ch| ch.is_ascii_hexdigit());
    if !looks_like_hex {
        return Err(format!(
            "digest must be 64 hex chars (an optional `sha256:` prefix is allowed), got {value:?}"
        ));
    }
    Ok(stripped.to_ascii_lowercase())
}

/// 版本号拆成可比的分段（`0.1.4` → `[0,1,4]`）。带 `-pre` / `+meta` 后缀时只看前面的数字段。
///
/// 认不出来就返回 `None` —— 比较方向**宁可拒绝，也不要拿字符串去猜大小**。
/// 注意这里**不剥 `v` 前缀**：`v0.1.4` 属于「认不出来的版本」（要不要当合法写法由调用方决定，
/// 例如先用 [`normalize_version`] 归一）。
pub fn parse_version(value: &str) -> Option<Vec<u64>> {
    let core = value.trim().split(['-', '+']).next()?;
    if core.is_empty() {
        return None;
    }
    core.split('.')
        .map(|segment| segment.parse::<u64>().ok())
        .collect()
}

/// 目标版本是否比当前版本**新**（按数字段逐段比，`0.10 > 0.9`、`0.1.0 > 0.1`）。
///
/// 两边任一认不出来就 `None`（见 [`parse_version`]）—— 升级方向不可判时，调用方应当**拒绝**
/// 而不是猜。
pub fn version_is_newer(target: &str, current: &str) -> Option<bool> {
    Some(parse_version(target)? > parse_version(current)?)
}

/// 去掉可选的 `sha256:` 前缀（大小写不敏感，两侧空格容忍）；只认 `sha256` 这一种 scheme，
/// 别的（或没有冒号的裸 hex）原样返回。
fn strip_digest_prefix(value: &str) -> &str {
    let trimmed = value.trim();
    match trimmed.split_once(':') {
        Some((scheme, rest)) if scheme.trim().eq_ignore_ascii_case("sha256") => rest.trim(),
        _ => trimmed,
    }
}

/// 版本比对用归一：忽略首尾空白与可选的 `v` / `V` 前缀（包内自报常按 git tag 带 `v`）。
///
/// 只剥**一个**前缀：`v`/`V` 是 git tag 惯例，`vv1.2` 不是合法版本写法；大小写都认，
/// 与私有实现里的 `looks_like_version` 口径一致（否则包内自报的 `V1.2`
/// 与运维手输的 `v1.2` 归一后不等，会被判成版本不符）。
pub fn normalize_version(value: &str) -> String {
    let trimmed = value.trim();
    trimmed
        .strip_prefix(['v', 'V'])
        .unwrap_or(trimmed)
        .to_string()
}

/// 制品文件名：取来源（路径 / URL）的**末段原名**（去掉查询串 / fragment）。
///
/// 用**原文件名**而非内容寻址 id：下发 URL 的末段就是原名，人看着清楚、下载即得可用文件。
/// 末段不安全（空、`.`、`..`、含分隔符或控制字符）就回落 `{component}-{version}.bin`。
///
/// 两种情况下返回值**都**保证是一个安全路径段：正常分支靠 [`is_safe_path_segment`] 把关，
/// 回落分支把 `component` / `version` 压干净（见 `sanitize_segment`）—— 也就是说即便调用方
/// 忘了校验入参，本函数也不会吐出一个能逃出目录的名字。
pub fn artifact_filename(url: &str, component: &str, version: &str) -> String {
    let leading = url.split(['?', '#']).next().unwrap_or(url);
    let basename = leading.rsplit('/').next().unwrap_or("");
    if is_safe_path_segment(basename) {
        return basename.to_string();
    }
    format!(
        "{}-{}.bin",
        sanitize_segment(component),
        sanitize_segment(version)
    )
}

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
    fn sha256_hex_bytes_is_lowercase_hex_of_the_expected_length() {
        let digest = sha256_hex_bytes(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn package_id_takes_sixteen_chars_and_does_not_normalize_case() {
        // 短输入不补齐；大小写不归一（上游给的就是裸 hex 小写，本函数不替它收拾）。
        assert_eq!(package_id_for_sha256("abc"), "pkg-abc");
        assert_eq!(package_id_for_sha256(""), "pkg-");
        assert_eq!(
            package_id_for_sha256("AB0123456789ABCDEF99"),
            "pkg-AB0123456789ABCD"
        );
        assert_ne!(
            package_id_for_sha256("AB0123456789ABCDEF99"),
            package_id_for_sha256("ab0123456789abcdef99")
        );
    }

    #[test]
    fn normalize_version_strips_one_v_or_capital_v_prefix() {
        assert_eq!(normalize_version("v0.1.32"), "0.1.32");
        assert_eq!(normalize_version("  V0.1.32  "), "0.1.32");
        assert_eq!(normalize_version("0.1.32"), "0.1.32");
        // 只剥一个前缀：`vv1.2` 不是合法版本写法，不该被当成 `1.2`。
        assert_eq!(normalize_version("vv1.2"), "v1.2");
        // 包内自报带 `v`、运维手输不带（或大小写不同）时，归一后必须相等。
        assert_eq!(
            normalize_version("v0.16.1-alpha"),
            normalize_version("0.16.1-alpha")
        );
        assert_eq!(normalize_version("V0.16.1"), normalize_version("v0.16.1"));
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

    #[test]
    fn is_safe_path_segment_accepts_plain_names_and_rejects_escaping_ones() {
        for safe in [
            "pkg",
            "wist-gateway-stack",
            "0.1.0-rc.1",
            ".hidden",
            "a b",
            "….gz",
        ] {
            assert!(is_safe_path_segment(safe), "{safe:?} 应算安全");
        }
        for unsafe_value in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "../x",
            "./x",
            "/etc/passwd",
            "a\nb",
            "a\0b",
            "\u{7f}",
        ] {
            assert!(
                !is_safe_path_segment(unsafe_value),
                "{unsafe_value:?} 应算不安全"
            );
        }
    }

    #[test]
    fn content_id_is_the_prefix_plus_sixteen_hex_chars() {
        let sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(content_id("kbp", sha), "kbp-0123456789abcdef");
        assert_eq!(content_id("pkg", sha), package_id_for_sha256(sha));
        // 前缀原样用（不归一大小写、不额外加分隔符）；短摘要不补齐。
        assert_eq!(content_id("X", sha), "X-0123456789abcdef");
        assert_eq!(content_id("", sha), "-0123456789abcdef");
        assert_eq!(content_id("kbp", "abc"), "kbp-abc");
    }

    #[test]
    fn artifact_filename_never_returns_an_escaping_segment() {
        // 来源末段不安全 → 回落；回落名也**保证**是单段（分隔符 / `..` 被压掉）。
        assert_eq!(
            artifact_filename("https://x/dir/", "../etc", "../passwd"),
            "..-etc-..-passwd.bin"
        );
        // 反斜杠 / 控制字符也算危险末段 → 回落。
        assert_eq!(
            artifact_filename("https://x/..\\evil", "galaxy-ops", "1.2.3"),
            "galaxy-ops-1.2.3.bin"
        );
        assert_eq!(
            artifact_filename("https://x/bad\nname", "galaxy-ops", "1.2.3"),
            "galaxy-ops-1.2.3.bin"
        );
        // 回落名的两段都不可用时用 `_` 占位，仍是单段。
        assert_eq!(artifact_filename("https://x/dir/", "..", "."), "_-_.bin");
        // 正常末段照旧原样用。
        assert_eq!(
            artifact_filename("https://x/dir/pkg.tar.gz", "c", "1.0"),
            "pkg.tar.gz"
        );
    }

    #[test]
    fn parse_digest_normalizes_the_documented_forms_and_rejects_the_rest() {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let upper = digest.to_ascii_uppercase();
        for value in [
            digest.to_string(),
            upper.clone(),
            format!("sha256:{digest}"),
            format!("SHA256:{upper}"),
            format!(" sha256: {upper} "),
        ] {
            assert_eq!(
                parse_digest(&value).expect(&value),
                digest,
                "value {value:?}"
            );
        }
        // 形态不对：空 / 只有前缀 / 太短 / 非 hex / 别的 scheme。
        for value in [
            "",
            "sha256:",
            "deadbeef",
            &digest[..63],
            "zzzz",
            "sha512:abc",
        ] {
            assert!(
                parse_digest(value).is_err(),
                "value {value:?} should be rejected"
            );
        }
    }

    #[test]
    fn version_is_newer_follows_the_documented_rules() {
        // 数值比较（不是字典序）：0.1.10 比 0.1.9 新。
        assert_eq!(version_is_newer("0.1.10", "0.1.9"), Some(true));
        assert_eq!(version_is_newer("0.1.9", "0.1.10"), Some(false));
        // 相等 → Some(false)：同版本重装不算「更新」。
        assert_eq!(version_is_newer("0.1.9", "0.1.9"), Some(false));
        // 预发布 / 构建后缀只看前面的数字段。
        assert_eq!(version_is_newer("0.2.0-beta.1", "0.1.9"), Some(true));
        assert_eq!(version_is_newer("0.1.4+meta", "0.1.3"), Some(true));
        // 段逐段比、不补齐：四段比三段新，`0.1.0` 比 `0.1` 新。
        assert_eq!(version_is_newer("0.1.9.1", "0.1.9"), Some(true));
        assert_eq!(version_is_newer("0.1.0", "0.1"), Some(true));
        // 认不出来就 None（`v` 前缀不算数字段）。
        for (target, current) in [
            ("dev", "0.1.9"),
            ("0.1.9", "dev"),
            ("v0.1.9", "0.1.9"),
            ("abc", "0.1.9"),
            ("0.1.9", ""),
            ("", "0.1.9"),
            ("0.1.9", "0.1.x"),
        ] {
            assert_eq!(
                version_is_newer(target, current),
                None,
                "{target:?} vs {current:?}"
            );
        }
        // 要认 `v` 前缀就由调用方先归一。
        let target = normalize_version("v0.1.9");
        let current = normalize_version("0.1.8");
        assert_eq!(version_is_newer(&target, &current), Some(true));
    }

    #[test]
    fn normalize_version_ignores_whitespace_and_leading_v() {
        assert_eq!(normalize_version(" v0.1.32 "), normalize_version("0.1.32"));
        assert_ne!(normalize_version("0.1.32"), normalize_version("0.1.33"));
    }

    #[tokio::test]
    async fn read_verified_source_accepts_a_prefixed_digest_in_any_case() {
        let path = std::env::temp_dir().join("wist-release-digest-prefix.bin");
        std::fs::write(&path, b"payload").expect("write");
        let source = path.to_string_lossy().to_string();
        let digest = sha256_hex_bytes(b"payload");
        let upper = digest.to_ascii_uppercase();

        for expected in [
            format!("sha256:{digest}"),
            format!("SHA256:{digest}"),
            format!(" sha256: {upper} "),
            upper.clone(),
        ] {
            read_verified_source(&source, Some(&expected))
                .await
                .unwrap_or_else(|err| panic!("expected {expected} to verify: {err}"));
        }
        // 空串 / 只有前缀 / 截断的摘要 → 不符（不静默放行）。
        for bad in ["", "sha256:", &digest[..8]] {
            assert!(
                matches!(
                    read_verified_source(&source, Some(bad)).await,
                    Err(PackageError::DigestMismatch(_))
                ),
                "expected {bad:?} to be rejected"
            );
        }
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn read_source_within_caps_local_files_before_reading_them() {
        let path = std::env::temp_dir().join("wist-release-size-cap.bin");
        std::fs::write(&path, b"0123456789").expect("write"); // 10 字节
        let source = path.to_string_lossy().to_string();

        // 上限 8：超限就拒，且错误里说清是「超了多少字节 / 上限多少」。
        let err = read_source_within(&source, 8, FETCH_TIMEOUT)
            .await
            .expect_err("over limit");
        // 超限是**单独一类**（调用方据此回一句「太大了」，而不是笼统的「拿不到」）。
        assert!(matches!(err, PackageError::TooLarge(_)), "{err}");
        assert!(err.to_string().contains("over the 8 byte limit"), "{err}");
        // 恰好等于上限：放行。
        assert_eq!(
            read_source_within(&source, 10, FETCH_TIMEOUT)
                .await
                .expect("at limit"),
            b"0123456789"
        );
        // 目录：读不了，但不 panic。
        let err = read_source_within(
            &std::env::temp_dir().to_string_lossy(),
            1 << 40,
            FETCH_TIMEOUT,
        )
        .await
        .expect_err("directory");
        assert!(matches!(err, PackageError::SourceUnavailable(_)));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn read_source_with_client_still_reads_local_paths() {
        // 本机路径分支不看 client（agentd 取包也走这条），但入口要能一起用。
        let path = std::env::temp_dir().join("wist-release-with-client.bin");
        std::fs::write(&path, b"payload").expect("write");
        let client = reqwest::Client::new();
        assert_eq!(
            read_source_with_client(&client, &path.to_string_lossy(), 1024, FETCH_TIMEOUT)
                .await
                .expect("read"),
            b"payload"
        );
        assert!(matches!(
            read_source_with_client(&client, "/definitely/not/here.bin", 1024, FETCH_TIMEOUT).await,
            Err(PackageError::SourceUnavailable(_))
        ));
        let _ = std::fs::remove_file(path);
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
