use std::collections::BTreeMap;
use std::fmt;

use serde_json::Value;
use sha2::{Digest, Sha256};
use url::{Host, Url};

use crate::{
    digest_hex,
    manifest::{validate_path, ArchiveFile, MAX_FILE_TABLE_ENTRIES},
    Manifest, ValidationError, MAX_FILE_SIZE_BYTES, MAX_MANIFEST_BYTES,
};

pub const SOURCE_CONTENT_DIGEST_ALGORITHM: &str = "sha256:gorce.provider/source-content/v1";
pub const MAX_SOURCE_FILES: usize = MAX_FILE_TABLE_ENTRIES;
pub const MAX_SOURCE_FILE_SIZE_BYTES: u64 = MAX_FILE_SIZE_BYTES;
pub const MAX_SOURCE_TOTAL_BYTES: u64 = MAX_FILE_SIZE_BYTES.saturating_mul(4);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitHashAlgorithm {
    Sha1,
    Sha256,
}

impl GitHashAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    fn commit_hex_length(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceVerificationError {
    pub field: String,
    pub reason: String,
}

impl SourceVerificationError {
    fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for SourceVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid provider source {}: {}",
            self.field, self.reason
        )
    }
}

impl std::error::Error for SourceVerificationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedGitSource {
    canonical_git_url: String,
    resolved_commit: String,
    commit_hash_algorithm: GitHashAlgorithm,
}

impl PinnedGitSource {
    pub fn new(
        canonical_git_url: impl Into<String>,
        commit_hash_algorithm: GitHashAlgorithm,
        resolved_commit: impl Into<String>,
    ) -> Result<Self, SourceVerificationError> {
        let source = Self {
            canonical_git_url: canonical_git_url.into(),
            resolved_commit: resolved_commit.into(),
            commit_hash_algorithm,
        };
        source.validate()?;
        Ok(source)
    }

    pub fn canonical_git_url(&self) -> &str {
        &self.canonical_git_url
    }

    pub fn resolved_commit(&self) -> &str {
        &self.resolved_commit
    }

    pub fn commit_hash_algorithm(&self) -> GitHashAlgorithm {
        self.commit_hash_algorithm
    }

    fn validate(&self) -> Result<(), SourceVerificationError> {
        validate_git_url(&self.canonical_git_url)?;
        if self.resolved_commit.len() != self.commit_hash_algorithm.commit_hex_length()
            || !self
                .resolved_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(SourceVerificationError::new(
                "resolved_commit",
                "must be a full lower-case commit for its hash algorithm",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum SourceEntryKind {
    RegularFile,
    Symlink,
    Gitlink,
    Directory,
    Special,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolverSourceEntry {
    path: String,
    kind: SourceEntryKind,
    unix_mode: Option<u32>,
    bytes: Vec<u8>,
}

#[allow(dead_code)]
impl ResolverSourceEntry {
    pub(crate) fn new(
        path: impl Into<String>,
        kind: SourceEntryKind,
        unix_mode: Option<u32>,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            path: path.into(),
            kind,
            unix_mode,
            bytes,
        }
    }

    pub(crate) fn regular_file(path: impl Into<String>, unix_mode: u32, bytes: Vec<u8>) -> Self {
        Self::new(path, SourceEntryKind::RegularFile, Some(unix_mode), bytes)
    }

    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn unix_mode(&self) -> Option<u32> {
        self.unix_mode
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Immutable output from a resolver. It is input to source verification, not
/// an authority artifact and cannot be changed after construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverOwnedGitSnapshot {
    source: PinnedGitSource,
    declared_source_content_digest: String,
    manifest_unix_mode: u32,
    manifest_bytes: Vec<u8>,
    files: Vec<ResolverSourceEntry>,
}

#[allow(dead_code)]
impl ResolverOwnedGitSnapshot {
    pub(crate) fn from_resolver(
        source: PinnedGitSource,
        declared_source_content_digest: impl Into<String>,
        manifest_unix_mode: u32,
        manifest_bytes: Vec<u8>,
        files: Vec<ResolverSourceEntry>,
    ) -> Self {
        Self {
            source,
            declared_source_content_digest: declared_source_content_digest.into(),
            manifest_unix_mode,
            manifest_bytes,
            files,
        }
    }

    pub(crate) fn source(&self) -> &PinnedGitSource {
        &self.source
    }

    pub(crate) fn declared_source_content_digest(&self) -> &str {
        &self.declared_source_content_digest
    }

    pub(crate) fn manifest_unix_mode(&self) -> u32 {
        self.manifest_unix_mode
    }

    pub(crate) fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    pub(crate) fn files(&self) -> &[ResolverSourceEntry] {
        &self.files
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSourceFile {
    path: String,
    unix_mode: u32,
    sha256: String,
    bytes: Vec<u8>,
}

impl VerifiedSourceFile {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn unix_mode(&self) -> u32 {
        self.unix_mode
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Opaque authority derived only from one immutable resolver snapshot.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProviderSource {
    source: PinnedGitSource,
    source_content_digest: String,
    manifest_bytes: Vec<u8>,
    manifest_digest: String,
    manifest: Manifest,
    files: Vec<VerifiedSourceFile>,
    executable_path: String,
    executable_bytes: Vec<u8>,
}

impl VerifiedProviderSource {
    pub fn source(&self) -> &PinnedGitSource {
        &self.source
    }

    pub fn canonical_git_url(&self) -> &str {
        self.source.canonical_git_url()
    }

    pub fn resolved_commit(&self) -> &str {
        self.source.resolved_commit()
    }

    pub fn commit_hash_algorithm(&self) -> GitHashAlgorithm {
        self.source.commit_hash_algorithm()
    }

    pub fn source_content_digest_algorithm(&self) -> &'static str {
        SOURCE_CONTENT_DIGEST_ALGORITHM
    }

    pub fn source_content_digest(&self) -> &str {
        &self.source_content_digest
    }

    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn capabilities(&self) -> &crate::Capabilities {
        &self.manifest.capabilities
    }

    pub fn files(&self) -> &[VerifiedSourceFile] {
        &self.files
    }

    pub fn executable_path(&self) -> &str {
        &self.executable_path
    }

    pub fn executable_bytes(&self) -> &[u8] {
        &self.executable_bytes
    }
}

pub fn verify_provider_source(
    snapshot: &ResolverOwnedGitSnapshot,
) -> Result<VerifiedProviderSource, SourceVerificationError> {
    snapshot.source.validate()?;
    if snapshot.manifest_unix_mode & 0o170000 != 0o100000 {
        return Err(SourceVerificationError::new(
            "manifest_mode",
            "manifest.json must have a regular Git file mode",
        ));
    }
    if snapshot.manifest_bytes.is_empty() || snapshot.manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(SourceVerificationError::new(
            "manifest",
            "manifest bytes are empty or oversized",
        ));
    }
    let manifest_value: Value =
        serde_json::from_slice(&snapshot.manifest_bytes).map_err(|error| {
            SourceVerificationError::new("manifest", format!("invalid manifest JSON: {error}"))
        })?;
    if manifest_value
        .as_object()
        .is_some_and(|object| object.contains_key("publisher"))
    {
        return Err(SourceVerificationError::new(
            "manifest.publisher",
            "source manifests must not carry signed-package publisher authority",
        ));
    }
    let source_manifest_modes = extract_source_manifest_modes(&manifest_value)?;
    let mut neutral_manifest_value = manifest_value;
    for file in neutral_manifest_value
        .get_mut("package")
        .and_then(Value::as_object_mut)
        .and_then(|package| package.get_mut("files"))
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        file.as_object_mut().map(|file| file.remove("mode"));
    }
    let manifest: Manifest = serde_json::from_value(neutral_manifest_value).map_err(|error| {
        SourceVerificationError::new("manifest", format!("invalid manifest JSON: {error}"))
    })?;
    manifest
        .validate_source()
        .map_err(|error| SourceVerificationError::new("manifest", error.to_string()))?;
    if snapshot.files.is_empty() || snapshot.files.len() > MAX_SOURCE_FILES {
        return Err(SourceVerificationError::new(
            "files",
            "source file set is empty or oversized",
        ));
    }

    let mut entries = BTreeMap::new();
    let mut casefolded_paths = BTreeMap::new();
    let mut total_bytes = 0_u64;
    for entry in &snapshot.files {
        if entry.kind != SourceEntryKind::RegularFile {
            return Err(SourceVerificationError::new(
                format!("files.{}", entry.path),
                "source entry is not a regular file",
            ));
        }
        let Some(mode) = entry.unix_mode else {
            return Err(SourceVerificationError::new(
                format!("files.{}", entry.path),
                "source entry is missing a Unix file mode",
            ));
        };
        if mode & 0o170000 != 0o100000 {
            return Err(SourceVerificationError::new(
                format!("files.{}", entry.path),
                "source entry does not have a regular-file Unix mode",
            ));
        }
        validate_path(&entry.path, &format!("files.{}.path", entry.path))
            .map_err(source_manifest_error)?;
        if entry.path.eq_ignore_ascii_case("manifest.json")
            || entry.path.eq_ignore_ascii_case("signature.json")
        {
            return Err(SourceVerificationError::new(
                format!("files.{}.path", entry.path),
                "source path is reserved for package envelope metadata",
            ));
        }
        if casefolded_paths
            .insert(entry.path.to_ascii_lowercase(), entry.path.clone())
            .is_some()
        {
            return Err(SourceVerificationError::new(
                "files",
                "source paths collide case-insensitively",
            ));
        }
        let size = entry.bytes.len() as u64;
        if size > MAX_SOURCE_FILE_SIZE_BYTES {
            return Err(SourceVerificationError::new(
                format!("files.{}", entry.path),
                "source file is oversized",
            ));
        }
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or_else(|| SourceVerificationError::new("files", "source size overflow"))?;
        if total_bytes > MAX_SOURCE_TOTAL_BYTES {
            return Err(SourceVerificationError::new(
                "files",
                "source payload is oversized",
            ));
        }
        if entries
            .insert(entry.path.clone(), (mode, entry.bytes.clone()))
            .is_some()
        {
            return Err(SourceVerificationError::new(
                "files",
                "source file path is duplicated",
            ));
        }
    }

    let archive_files = entries
        .iter()
        .map(|(path, (_, bytes))| ArchiveFile {
            path: path.clone(),
            bytes: bytes.clone(),
        })
        .collect::<Vec<_>>();
    manifest
        .package
        .validate_archive_files(&archive_files)
        .map_err(source_manifest_error)?;

    let files = entries
        .into_iter()
        .map(|(path, (unix_mode, bytes))| VerifiedSourceFile {
            sha256: digest_hex(&bytes),
            path,
            unix_mode,
            bytes,
        })
        .collect::<Vec<_>>();
    for file in &files {
        if source_manifest_modes.get(&file.path) != Some(&file.unix_mode) {
            return Err(SourceVerificationError::new(
                format!("manifest.package.files.{}.mode", file.path),
                "source file mode does not match the resolver snapshot",
            ));
        }
    }
    let source_content_digest = compute_source_content_digest(snapshot);
    if snapshot.declared_source_content_digest != source_content_digest {
        return Err(SourceVerificationError::new(
            "source_content_digest",
            "resolver digest does not match the host-computed source digest",
        ));
    }
    let executable_path = manifest.package.executable.path.clone();
    let executable_bytes = files
        .iter()
        .find(|file| file.path == executable_path)
        .map(|file| file.bytes.clone())
        .ok_or_else(|| SourceVerificationError::new("executable", "executable is missing"))?;

    Ok(VerifiedProviderSource {
        source: snapshot.source.clone(),
        source_content_digest,
        manifest_bytes: snapshot.manifest_bytes.clone(),
        manifest_digest: digest_hex(&snapshot.manifest_bytes),
        manifest,
        files,
        executable_path,
        executable_bytes,
    })
}

fn compute_source_content_digest(snapshot: &ResolverOwnedGitSnapshot) -> String {
    let mut files = snapshot
        .files
        .iter()
        .map(|file| VerifiedSourceFile {
            path: file.path.clone(),
            unix_mode: file.unix_mode.unwrap_or(0),
            sha256: digest_hex(&file.bytes),
            bytes: file.bytes.clone(),
        })
        .collect::<Vec<_>>();
    files.sort_by(|left, right| left.path.cmp(&right.path));
    compute_verified_source_content_digest(
        snapshot.manifest_unix_mode,
        &snapshot.manifest_bytes,
        &files,
    )
}

fn compute_verified_source_content_digest(
    manifest_unix_mode: u32,
    manifest_bytes: &[u8],
    files: &[VerifiedSourceFile],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_CONTENT_DIGEST_ALGORITHM.as_bytes());
    hasher.update([0]);
    update_source_digest_record(
        &mut hasher,
        "manifest.json",
        manifest_unix_mode,
        manifest_bytes,
    );
    for file in files {
        update_source_digest_record(&mut hasher, &file.path, file.unix_mode, &file.bytes);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn update_source_digest_record(hasher: &mut Sha256, path: &str, unix_mode: u32, bytes: &[u8]) {
    hasher.update((path.len() as u64).to_be_bytes());
    hasher.update(path.as_bytes());
    hasher.update(unix_mode.to_be_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn extract_source_manifest_modes(
    manifest: &Value,
) -> Result<BTreeMap<String, u32>, SourceVerificationError> {
    let files = manifest
        .get("package")
        .and_then(Value::as_object)
        .and_then(|package| package.get("files"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SourceVerificationError::new("manifest.package.files", "must be an array")
        })?;
    let mut modes = BTreeMap::new();
    for file in files {
        let object = file.as_object().ok_or_else(|| {
            SourceVerificationError::new("manifest.package.files", "file entry must be an object")
        })?;
        let path = object.get("path").and_then(Value::as_str).ok_or_else(|| {
            SourceVerificationError::new("manifest.package.files.path", "must be text")
        })?;
        let mode = object
            .get("mode")
            .and_then(Value::as_u64)
            .and_then(|mode| u32::try_from(mode).ok())
            .ok_or_else(|| {
                SourceVerificationError::new(
                    format!("manifest.package.files.{path}.mode"),
                    "source manifest must declare a regular Git file mode",
                )
            })?;
        if mode & 0o170000 != 0o100000 {
            return Err(SourceVerificationError::new(
                format!("manifest.package.files.{path}.mode"),
                "source manifest file mode must be regular",
            ));
        }
        if modes.insert(path.to_owned(), mode).is_some() {
            return Err(SourceVerificationError::new(
                "manifest.package.files",
                "source manifest file paths must be unique",
            ));
        }
    }
    Ok(modes)
}

fn source_manifest_error(error: ValidationError) -> SourceVerificationError {
    SourceVerificationError::new(error.field, error.reason)
}

fn validate_git_url(value: &str) -> Result<(), SourceVerificationError> {
    if value.is_empty()
        || !value.is_ascii()
        || !value.starts_with("https://")
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || value.contains('%')
        || value.contains('\\')
    {
        return Err(SourceVerificationError::new(
            "canonical_git_url",
            "must be an ASCII canonical HTTPS Git URL",
        ));
    }
    let url = Url::parse(value).map_err(|_| {
        SourceVerificationError::new("canonical_git_url", "is not valid URL syntax")
    })?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() == "/"
        || url.path().is_empty()
        || url.path().ends_with('/')
        || url.as_str() != value
        || url.path().bytes().any(|byte| byte.is_ascii_whitespace())
        || url
            .path()
            .split('/')
            .skip(1)
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(SourceVerificationError::new(
            "canonical_git_url",
            "must have a canonical HTTPS repository authority and path",
        ));
    }
    let authority = value
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or_default();
    let raw_host = if authority.starts_with('[') {
        authority
            .split_once(']')
            .map(|(host, _)| host)
            .unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    let explicit_port = if authority.starts_with('[') {
        authority
            .split_once(']')
            .and_then(|(_, rest)| rest.strip_prefix(':'))
    } else if authority.matches(':').count() == 1 {
        authority.rsplit_once(':').map(|(_, port)| port)
    } else {
        None
    };
    if explicit_port.is_some_and(|port| {
        port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || (port.len() > 1 && port.starts_with('0'))
            || port.parse::<u16>().is_err()
            || port == "0"
            || port == "443"
    }) {
        return Err(SourceVerificationError::new(
            "canonical_git_url",
            "port must be a canonical non-zero decimal number other than 443",
        ));
    }
    if raw_host.is_empty() || raw_host != raw_host.to_ascii_lowercase() {
        return Err(SourceVerificationError::new(
            "canonical_git_url",
            "host must be canonical lowercase",
        ));
    }
    match url.host() {
        Some(Host::Domain(domain)) => {
            if domain.split('.').any(|label| {
                label.is_empty()
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            }) {
                return Err(SourceVerificationError::new(
                    "canonical_git_url",
                    "host is not a canonical DNS name",
                ));
            }
        }
        Some(Host::Ipv4(address)) if raw_host != address.to_string() => {
            return Err(SourceVerificationError::new(
                "canonical_git_url",
                "IPv4 host is not canonical",
            ));
        }
        Some(Host::Ipv6(_)) if raw_host.contains('.') => {
            return Err(SourceVerificationError::new(
                "canonical_git_url",
                "IPv6 host must use hexadecimal notation",
            ));
        }
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => {}
        None => unreachable!("checked above"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn fixture_source() -> PinnedGitSource {
        PinnedGitSource::new(
            "https://example.com/gorce/provider",
            GitHashAlgorithm::Sha1,
            "a".repeat(40),
        )
        .unwrap()
    }

    fn fixture_snapshot(files: Vec<ResolverSourceEntry>) -> ResolverOwnedGitSnapshot {
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v1/source-fixtures.json"
        ))
        .unwrap();
        let mut manifest: Value = serde_json::from_str(
            fixtures["positive"][0]["value"]["manifest"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let manifest_unix_mode = fixtures["positive"][0]["value"]["manifest_mode"]
            .as_u64()
            .unwrap() as u32;
        let mut sorted = files
            .iter()
            .map(|file| {
                (
                    file.path().to_owned(),
                    file.unix_mode(),
                    file.bytes().to_vec(),
                )
            })
            .collect::<Vec<_>>();
        sorted.sort_by(|left, right| left.0.cmp(&right.0));
        manifest["package"]["files"] = Value::Array(
            sorted
                .iter()
                .map(|(path, mode, bytes)| {
                    json!({
                        "path": path,
                        "size": bytes.len(),
                        "sha256": digest_hex(bytes),
                        "mode": mode,
                    })
                })
                .collect(),
        );
        let (executable_path, _executable_mode, executable_bytes) = sorted
            .iter()
            .find(|(path, _mode, _bytes)| path == "bin/provider")
            .unwrap_or_else(|| sorted.first().unwrap());
        manifest["package"]["executable"] = json!({
            "path": executable_path,
            "sha256": digest_hex(executable_bytes),
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let preliminary = ResolverOwnedGitSnapshot::from_resolver(
            fixture_source(),
            "",
            manifest_unix_mode,
            manifest_bytes,
            files,
        );
        let digest = compute_source_content_digest(&preliminary);
        ResolverOwnedGitSnapshot::from_resolver(
            preliminary.source().clone(),
            digest,
            manifest_unix_mode,
            preliminary.manifest_bytes().to_vec(),
            preliminary.files().to_vec(),
        )
    }

    fn valid_files() -> Vec<ResolverSourceEntry> {
        vec![ResolverSourceEntry::regular_file(
            "bin/provider",
            0o100755,
            b"fixture executable".to_vec(),
        )]
    }

    #[test]
    fn shared_source_fixture_matches_the_rust_verifier_boundary() {
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v1/source-fixtures.json"
        ))
        .unwrap();
        let value = &fixtures["positive"][0]["value"];
        let source = PinnedGitSource::new(
            value["source"]["canonical_git_url"].as_str().unwrap(),
            GitHashAlgorithm::Sha1,
            value["source"]["resolved_commit"].as_str().unwrap(),
        )
        .unwrap();
        let file = &value["files"][0];
        let bytes = file["content"]
            .as_array()
            .unwrap()
            .iter()
            .map(|byte| byte.as_u64().unwrap() as u8)
            .collect();
        let snapshot = ResolverOwnedGitSnapshot::from_resolver(
            source,
            value["source_content_digest"].as_str().unwrap(),
            value["manifest_mode"].as_u64().unwrap() as u32,
            value["manifest"].as_str().unwrap().as_bytes().to_vec(),
            vec![ResolverSourceEntry::regular_file(
                file["path"].as_str().unwrap(),
                file["mode"].as_u64().unwrap() as u32,
                bytes,
            )],
        );
        let verified = verify_provider_source(&snapshot).unwrap();
        assert_eq!(
            verified.source_content_digest(),
            value["source_content_digest"].as_str().unwrap()
        );
        assert_eq!(
            verified.manifest_digest(),
            value["manifest_digest"].as_str().unwrap()
        );
    }

    #[test]
    fn shared_source_negative_fixtures_are_rejected_by_the_rust_verifier() {
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v1/source-fixtures.json"
        ))
        .unwrap();
        let base = fixtures["positive"][0]["value"].clone();
        for fixture in fixtures["negative"].as_array().unwrap() {
            let mut value = base.clone();
            match fixture.get("operation").and_then(Value::as_str) {
                Some("append_extra_file") => {
                    let mut extra = value["files"][0].clone();
                    extra["path"] = Value::String("extra".to_owned());
                    extra["content"] = Value::String("extra".to_owned());
                    extra["size"] = Value::from(5_u64);
                    extra["sha256"] = Value::String(digest_hex(b"extra"));
                    value["files"].as_array_mut().unwrap().push(extra);
                }
                Some("add_publisher_to_manifest") => {
                    let mut manifest: Value =
                        serde_json::from_str(value["manifest"].as_str().unwrap()).unwrap();
                    manifest["publisher"] = json!({
                        "name": "forged",
                        "fingerprint": "0".repeat(64),
                    });
                    value["manifest"] = Value::String(serde_json::to_string(&manifest).unwrap());
                }
                Some("change_manifest_executable_path") => {
                    let mut manifest: Value =
                        serde_json::from_str(value["manifest"].as_str().unwrap()).unwrap();
                    manifest["package"]["executable"]["path"] =
                        Value::String("bin/other".to_owned());
                    value["manifest"] = Value::String(serde_json::to_string(&manifest).unwrap());
                }
                Some("oversized_manifest") => {
                    value["manifest"] = Value::String("é".repeat(MAX_MANIFEST_BYTES / 2 + 1));
                }
                Some(operation) => panic!("unsupported source fixture operation: {operation}"),
                None => {}
            }
            for (path, replacement) in fixture
                .get("changes")
                .and_then(Value::as_object)
                .into_iter()
                .flat_map(|changes| changes.iter())
            {
                set_fixture_path(&mut value, path, replacement.clone());
            }
            let result = snapshot_from_fixture_value(&value)
                .and_then(|snapshot| verify_provider_source(&snapshot).map(|_| ()));
            assert!(
                result.is_err(),
                "accepted source fixture: {}",
                fixture["reason"]
            );
        }
    }

    fn set_fixture_path(value: &mut Value, path: &str, replacement: Value) {
        let parts = path.split('.').collect::<Vec<_>>();
        let mut cursor = value;
        for (index, part) in parts.iter().enumerate() {
            if index == parts.len() - 1 {
                if let Ok(index) = part.parse::<usize>() {
                    cursor[index] = replacement;
                } else {
                    cursor[*part] = replacement;
                }
                return;
            }
            cursor = if let Ok(index) = part.parse::<usize>() {
                &mut cursor[index]
            } else {
                &mut cursor[*part]
            };
        }
    }

    fn snapshot_from_fixture_value(
        value: &Value,
    ) -> Result<ResolverOwnedGitSnapshot, SourceVerificationError> {
        let source_value = value
            .get("source")
            .and_then(Value::as_object)
            .ok_or_else(|| SourceVerificationError::new("source", "must be an object"))?;
        if source_value.keys().any(|key| {
            !matches!(
                key.as_str(),
                "canonical_git_url" | "commit_hash_algorithm" | "resolved_commit"
            )
        }) {
            return Err(SourceVerificationError::new(
                "source",
                "contains an unsupported moving-reference field",
            ));
        }
        let source = PinnedGitSource::new(
            source_value
                .get("canonical_git_url")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    SourceVerificationError::new("source.canonical_git_url", "must be text")
                })?,
            match source_value
                .get("commit_hash_algorithm")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    SourceVerificationError::new("source.commit_hash_algorithm", "must be text")
                })? {
                "sha1" => GitHashAlgorithm::Sha1,
                "sha256" => GitHashAlgorithm::Sha256,
                _ => {
                    return Err(SourceVerificationError::new(
                        "source.commit_hash_algorithm",
                        "unsupported hash algorithm",
                    ))
                }
            },
            source_value
                .get("resolved_commit")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    SourceVerificationError::new("source.resolved_commit", "must be text")
                })?,
        )?;
        let files = value
            .get("files")
            .and_then(Value::as_array)
            .ok_or_else(|| SourceVerificationError::new("files", "must be an array"))?
            .iter()
            .map(|file| {
                let kind = match file.get("kind").and_then(Value::as_str) {
                    Some("regular_file") => SourceEntryKind::RegularFile,
                    Some("symlink") => SourceEntryKind::Symlink,
                    Some("gitlink") => SourceEntryKind::Gitlink,
                    Some("directory") => SourceEntryKind::Directory,
                    Some("special") => SourceEntryKind::Special,
                    _ => {
                        return Err(SourceVerificationError::new(
                            "files.kind",
                            "unsupported source entry kind",
                        ))
                    }
                };
                let content = file
                    .get("content")
                    .and_then(Value::as_array)
                    .ok_or_else(|| SourceVerificationError::new("files.content", "must be bytes"))?
                    .iter()
                    .map(|byte| {
                        byte.as_u64()
                            .and_then(|byte| u8::try_from(byte).ok())
                            .ok_or_else(|| {
                                SourceVerificationError::new("files.content", "must contain bytes")
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let mode = match file.get("mode") {
                    Some(Value::Null) | None => None,
                    Some(mode) => Some(
                        mode.as_u64()
                            .and_then(|mode| u32::try_from(mode).ok())
                            .ok_or_else(|| {
                                SourceVerificationError::new("files.mode", "must be a Unix mode")
                            })?,
                    ),
                };
                Ok(ResolverSourceEntry::new(
                    file.get("path").and_then(Value::as_str).ok_or_else(|| {
                        SourceVerificationError::new("files.path", "must be text")
                    })?,
                    kind,
                    mode,
                    content,
                ))
            })
            .collect::<Result<Vec<_>, SourceVerificationError>>()?;
        Ok(ResolverOwnedGitSnapshot::from_resolver(
            source,
            value["source_content_digest"].as_str().ok_or_else(|| {
                SourceVerificationError::new("source_content_digest", "must be text")
            })?,
            value["manifest_mode"]
                .as_u64()
                .and_then(|mode| u32::try_from(mode).ok())
                .ok_or_else(|| {
                    SourceVerificationError::new("manifest_mode", "must be a Unix mode")
                })?,
            value["manifest"]
                .as_str()
                .ok_or_else(|| SourceVerificationError::new("manifest", "must be text"))?
                .as_bytes()
                .to_vec(),
            files,
        ))
    }

    #[test]
    fn source_verification_binds_identity_manifest_files_and_executable() {
        let snapshot = fixture_snapshot(valid_files());
        let verified = verify_provider_source(&snapshot).unwrap();
        assert_eq!(
            verified.canonical_git_url(),
            "https://example.com/gorce/provider"
        );
        assert_eq!(verified.resolved_commit(), "a".repeat(40));
        assert_eq!(verified.commit_hash_algorithm(), GitHashAlgorithm::Sha1);
        assert_eq!(
            verified.source_content_digest(),
            snapshot.declared_source_content_digest()
        );
        assert_eq!(
            verified.manifest_digest(),
            digest_hex(verified.manifest_bytes())
        );
        assert_eq!(verified.files().len(), 1);
        assert_eq!(verified.executable_path(), "bin/provider");
        assert_eq!(verified.executable_bytes(), b"fixture executable");

        let mut copied = verified.executable_bytes().to_vec();
        copied[0] = b'X';
        assert_ne!(copied, verified.executable_bytes());
        assert_eq!(verified.executable_bytes(), b"fixture executable");
    }

    #[test]
    fn source_content_digest_is_stable_across_resolver_file_order() {
        let first =
            ResolverSourceEntry::regular_file("bin/provider", 0o100755, b"provider".to_vec());
        let second = ResolverSourceEntry::regular_file("README", 0o100644, b"readme".to_vec());
        let ordered =
            verify_provider_source(&fixture_snapshot(vec![first.clone(), second.clone()])).unwrap();
        let reversed = verify_provider_source(&fixture_snapshot(vec![second, first])).unwrap();
        assert_eq!(
            ordered.source_content_digest(),
            reversed.source_content_digest()
        );
        assert_eq!(ordered.files()[0].path(), "README");
        assert_eq!(ordered.files()[1].path(), "bin/provider");
    }

    #[test]
    fn source_verification_rejects_identity_digest_and_file_substitution() {
        for url in [
            "https://example.com/gorce/provider?ref=main",
            "https://example.com/gorce%2Fprovider",
            "https://example.com%2frepo/provider",
            "https://example.com:080/gorce/provider",
            "file:///tmp/provider",
        ] {
            assert!(PinnedGitSource::new(url, GitHashAlgorithm::Sha1, "a".repeat(40)).is_err());
        }
        assert!(PinnedGitSource::new(
            "https://example.com/gorce/provider",
            GitHashAlgorithm::Sha1,
            "a".repeat(39),
        )
        .is_err());
        assert!(PinnedGitSource::new(
            "https://example.com/gorce/provider",
            GitHashAlgorithm::Sha256,
            "a".repeat(40),
        )
        .is_err());

        let valid = fixture_snapshot(valid_files());
        let oversized_manifest = ResolverOwnedGitSnapshot::from_resolver(
            valid.source().clone(),
            "0".repeat(64),
            valid.manifest_unix_mode(),
            vec![b'x'; MAX_MANIFEST_BYTES + 1],
            valid.files().to_vec(),
        );
        assert!(verify_provider_source(&oversized_manifest).is_err());
        let wrong_digest = ResolverOwnedGitSnapshot::from_resolver(
            valid.source().clone(),
            "0".repeat(64),
            valid.manifest_unix_mode(),
            valid.manifest_bytes().to_vec(),
            valid.files().to_vec(),
        );
        assert!(verify_provider_source(&wrong_digest).is_err());

        let changed_file = ResolverOwnedGitSnapshot::from_resolver(
            valid.source().clone(),
            valid.declared_source_content_digest().to_owned(),
            valid.manifest_unix_mode(),
            valid.manifest_bytes().to_vec(),
            vec![ResolverSourceEntry::regular_file(
                "bin/provider",
                0o100755,
                b"changed executable".to_vec(),
            )],
        );
        assert!(verify_provider_source(&changed_file).is_err());

        let mut changed_manifest: Value = serde_json::from_slice(valid.manifest_bytes()).unwrap();
        changed_manifest["package"]["executable"]["path"] = Value::String("bin/other".to_owned());
        let changed_executable_path = ResolverOwnedGitSnapshot::from_resolver(
            valid.source().clone(),
            valid.declared_source_content_digest().to_owned(),
            valid.manifest_unix_mode(),
            serde_json::to_vec(&changed_manifest).unwrap(),
            valid.files().to_vec(),
        );
        assert!(verify_provider_source(&changed_executable_path).is_err());
    }

    #[test]
    fn source_mode_only_changes_are_digest_sensitive_and_manifest_bound() {
        let valid = fixture_snapshot(valid_files());
        let manifest_mode_changed = ResolverOwnedGitSnapshot::from_resolver(
            valid.source().clone(),
            "",
            0o100755,
            valid.manifest_bytes().to_vec(),
            valid.files().to_vec(),
        );
        let manifest_mode_changed_with_digest = ResolverOwnedGitSnapshot::from_resolver(
            manifest_mode_changed.source().clone(),
            compute_source_content_digest(&manifest_mode_changed),
            manifest_mode_changed.manifest_unix_mode(),
            manifest_mode_changed.manifest_bytes().to_vec(),
            manifest_mode_changed.files().to_vec(),
        );
        assert!(verify_provider_source(&manifest_mode_changed_with_digest).is_ok());

        let mode_changed = ResolverOwnedGitSnapshot::from_resolver(
            valid.source().clone(),
            "",
            valid.manifest_unix_mode(),
            valid.manifest_bytes().to_vec(),
            vec![ResolverSourceEntry::regular_file(
                "bin/provider",
                0o100644,
                b"fixture executable".to_vec(),
            )],
        );
        assert_ne!(
            compute_source_content_digest(&valid),
            compute_source_content_digest(&mode_changed)
        );
        let mode_changed_with_digest = ResolverOwnedGitSnapshot::from_resolver(
            mode_changed.source().clone(),
            compute_source_content_digest(&mode_changed),
            mode_changed.manifest_unix_mode(),
            mode_changed.manifest_bytes().to_vec(),
            mode_changed.files().to_vec(),
        );
        assert!(verify_provider_source(&mode_changed_with_digest).is_err());
    }

    #[test]
    fn source_verification_rejects_nonregular_missing_extra_and_unsafe_files() {
        for kind in [
            SourceEntryKind::Symlink,
            SourceEntryKind::Gitlink,
            SourceEntryKind::Directory,
            SourceEntryKind::Special,
        ] {
            let snapshot = fixture_snapshot(vec![ResolverSourceEntry::new(
                "bin/provider",
                kind,
                Some(0o100755),
                b"fixture executable".to_vec(),
            )]);
            assert!(verify_provider_source(&snapshot).is_err());
        }
        let missing_mode = fixture_snapshot(vec![ResolverSourceEntry::new(
            "bin/provider",
            SourceEntryKind::RegularFile,
            None,
            b"fixture executable".to_vec(),
        )]);
        assert!(verify_provider_source(&missing_mode).is_err());

        let valid = fixture_snapshot(valid_files());
        let extra = ResolverOwnedGitSnapshot::from_resolver(
            valid.source().clone(),
            valid.declared_source_content_digest().to_owned(),
            valid.manifest_unix_mode(),
            valid.manifest_bytes().to_vec(),
            vec![
                ResolverSourceEntry::regular_file(
                    "bin/provider",
                    valid.files()[0].unix_mode().unwrap(),
                    valid.files()[0].bytes().to_vec(),
                ),
                ResolverSourceEntry::regular_file("extra", 0o100644, b"extra".to_vec()),
            ],
        );
        assert!(verify_provider_source(&extra).is_err());

        let collision = fixture_snapshot(vec![
            ResolverSourceEntry::regular_file(
                "bin/provider",
                0o100755,
                b"fixture executable".to_vec(),
            ),
            ResolverSourceEntry::regular_file(
                "BIN/PROVIDER",
                0o100755,
                b"fixture executable".to_vec(),
            ),
        ]);
        assert!(verify_provider_source(&collision).is_err());

        let unsafe_path = fixture_snapshot(vec![ResolverSourceEntry::regular_file(
            "../provider",
            0o100755,
            b"fixture executable".to_vec(),
        )]);
        assert!(verify_provider_source(&unsafe_path).is_err());
    }
}
