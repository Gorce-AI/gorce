use std::collections::BTreeMap;
use std::fmt;
use std::io::{Cursor, Read};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::{
    manifest::{validate_path, ArchiveFile, MAX_FILE_TABLE_ENTRIES},
    Manifest, ValidationError, ValidationResult, MAX_FILE_SIZE_BYTES, MAX_MANIFEST_BYTES,
};

pub const MAX_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;
pub const RESERVED_ARCHIVE_ENTRIES: usize = 2;
pub const MAX_ARCHIVE_ENTRIES: usize = MAX_FILE_TABLE_ENTRIES + RESERVED_ARCHIVE_ENTRIES;
pub const MAX_ARCHIVE_UNCOMPRESSED_BYTES: u64 =
    crate::MAX_FILE_SIZE_BYTES.saturating_mul(4) + crate::MAX_MANIFEST_BYTES as u64 + 4096;
pub const PROVIDER_ARCHIVE_EXTENSION: &str = ".gorce-provider";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedSignature {
    pub algorithm: SignatureAlgorithm,
    /// Standard base64-encoded Ed25519 public key.
    pub public_key: String,
    /// Standard base64-encoded detached signature over the exact manifest bytes.
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProviderPackage {
    /// Host-computed SHA-256 of immutable archive bytes. It is not in the signed manifest.
    pub archive_digest: String,
    /// UTF-8 JSON text retained byte-for-byte for signature verification.
    pub manifest: String,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    OversizedManifest,
    InvalidArchiveDigest,
    InvalidBase64,
    InvalidKey,
    InvalidSignature,
    Manifest(ValidationError),
    Archive(ValidationError),
    Json(String),
    Zip(String),
}

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OversizedManifest => write!(formatter, "manifest exceeds the ABI size bound"),
            Self::InvalidArchiveDigest => write!(formatter, "archive digest is not host-computed"),
            Self::InvalidBase64 => write!(formatter, "signature contains invalid base64"),
            Self::InvalidKey => write!(formatter, "signature contains an invalid Ed25519 key"),
            Self::InvalidSignature => write!(formatter, "manifest signature does not verify"),
            Self::Manifest(error) | Self::Archive(error) => error.fmt(formatter),
            Self::Json(error) => write!(formatter, "invalid manifest JSON: {error}"),
            Self::Zip(error) => write!(formatter, "invalid .gorce-provider ZIP: {error}"),
        }
    }
}

/// A verifier-produced authority artifact. Its fields are intentionally
/// private: instances must come from `verify_provider_archive`, and callers
/// can only inspect the verified contents through read-only accessors.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProviderArchive {
    package: SignedProviderPackage,
    manifest: Manifest,
    executable_path: String,
    executable_bytes: Vec<u8>,
}

impl VerifiedProviderArchive {
    pub fn package(&self) -> &SignedProviderPackage {
        &self.package
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn archive_digest(&self) -> &str {
        &self.package.archive_digest
    }

    pub fn signed_manifest(&self) -> &str {
        &self.package.manifest
    }

    pub fn signature(&self) -> &DetachedSignature {
        &self.package.signature
    }

    pub fn executable_path(&self) -> &str {
        &self.executable_path
    }

    pub fn executable_bytes(&self) -> &[u8] {
        &self.executable_bytes
    }
}

impl std::error::Error for SignatureError {}

pub fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Host-side archive digest operation. The input is immutable archive bytes;
/// it is intentionally not a field in the signed manifest.
pub fn compute_archive_digest(archive_bytes: &[u8]) -> String {
    digest_hex(archive_bytes)
}

pub fn fingerprint_hex(public_key: &[u8; 32]) -> String {
    digest_hex(public_key)
}

pub fn sign_manifest(
    manifest_bytes: &[u8],
    signing_key: &SigningKey,
) -> Result<DetachedSignature, SignatureError> {
    ensure_manifest_bound(manifest_bytes)?;
    let signature = signing_key.sign(manifest_bytes);
    Ok(DetachedSignature {
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: BASE64.encode(signing_key.verifying_key().to_bytes()),
        signature: BASE64.encode(signature.to_bytes()),
    })
}

fn verify_manifest(
    manifest_bytes: &[u8],
    detached: &DetachedSignature,
) -> Result<Manifest, SignatureError> {
    ensure_manifest_bound(manifest_bytes)?;
    if detached.algorithm != SignatureAlgorithm::Ed25519 {
        return Err(SignatureError::InvalidKey);
    }
    let public_key = BASE64
        .decode(&detached.public_key)
        .map_err(|_| SignatureError::InvalidBase64)?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| SignatureError::InvalidKey)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| SignatureError::InvalidKey)?;
    let signature = BASE64
        .decode(&detached.signature)
        .map_err(|_| SignatureError::InvalidBase64)?;
    let signature =
        Signature::from_slice(&signature).map_err(|_| SignatureError::InvalidSignature)?;
    verifying_key
        .verify(manifest_bytes, &signature)
        .map_err(|_| SignatureError::InvalidSignature)?;
    let manifest: Manifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| SignatureError::Json(error.to_string()))?;
    manifest.validate().map_err(SignatureError::Manifest)?;
    if manifest.publisher.fingerprint != fingerprint_hex(&public_key) {
        return Err(SignatureError::InvalidSignature);
    }
    Ok(manifest)
}

/// Verify the complete bounded `.gorce-provider` ZIP from its immutable bytes.
/// The manifest and detached signature are read from the archive itself; the
/// host archive digest is computed over those exact bytes. Manifest file-table
/// entries intentionally exclude `manifest.json` and `signature.json`, which
/// avoids a self-referential digest while still binding the executable bytes.
pub fn verify_provider_archive(
    archive_bytes: &[u8],
) -> Result<VerifiedProviderArchive, SignatureError> {
    if archive_bytes.is_empty() || archive_bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(SignatureError::Zip(
            "archive exceeds the bounded byte limit".to_owned(),
        ));
    }
    let mut archive = ZipArchive::new(Cursor::new(archive_bytes))
        .map_err(|error| SignatureError::Zip(error.to_string()))?;
    if archive.is_empty() || archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(SignatureError::Zip(
            "archive has an invalid entry count".to_owned(),
        ));
    }
    let mut entries = BTreeMap::new();
    let mut casefolded_paths = BTreeMap::new();
    let mut total_uncompressed = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| SignatureError::Zip(error.to_string()))?;
        if !entry.is_file() {
            return Err(SignatureError::Zip(
                "archive entries must be regular files".to_owned(),
            ));
        }
        let Some(mode) = entry.unix_mode() else {
            return Err(SignatureError::Zip(
                "archive entries must declare a regular Unix file mode".to_owned(),
            ));
        };
        if mode & 0o170000 != 0o100000 {
            return Err(SignatureError::Zip(
                "archive entries must be regular files".to_owned(),
            ));
        }
        let path = entry.name().to_owned();
        if path.eq_ignore_ascii_case("manifest.json") || path.eq_ignore_ascii_case("signature.json")
        {
            if path != "manifest.json" && path != "signature.json" {
                return Err(SignatureError::Zip(
                    "archive metadata paths must use canonical case".to_owned(),
                ));
            }
            // These are checked below and are not part of the signed payload file table.
        } else {
            validate_path(&path, "archive.path").map_err(SignatureError::Archive)?;
        }
        if casefolded_paths
            .insert(path.to_ascii_lowercase(), path.clone())
            .is_some()
        {
            return Err(SignatureError::Zip(
                "case-insensitive archive path collision".to_owned(),
            ));
        }
        if entry.size() > MAX_FILE_SIZE_BYTES {
            return Err(SignatureError::Zip("archive entry is oversized".to_owned()));
        }
        total_uncompressed = total_uncompressed
            .checked_add(entry.size())
            .ok_or_else(|| SignatureError::Zip("archive size overflow".to_owned()))?;
        if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES {
            return Err(SignatureError::Zip(
                "archive payload is oversized".to_owned(),
            ));
        }
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut bytes)
            .map_err(|error| SignatureError::Zip(error.to_string()))?;
        if entries.insert(path, bytes).is_some() {
            return Err(SignatureError::Zip("duplicate archive path".to_owned()));
        }
    }
    let manifest_bytes = entries
        .remove("manifest.json")
        .ok_or_else(|| SignatureError::Zip("manifest.json is missing".to_owned()))?;
    let signature_bytes = entries
        .remove("signature.json")
        .ok_or_else(|| SignatureError::Zip("signature.json is missing".to_owned()))?;
    let signature: DetachedSignature = serde_json::from_slice(&signature_bytes)
        .map_err(|error| SignatureError::Json(error.to_string()))?;
    let manifest = verify_manifest(&manifest_bytes, &signature)?;
    let archive_files = entries
        .iter()
        .map(|(path, bytes)| ArchiveFile {
            path: path.clone(),
            bytes: bytes.clone(),
        })
        .collect::<Vec<_>>();
    manifest
        .package
        .validate_archive_files(&archive_files)
        .map_err(SignatureError::Archive)?;
    let executable_bytes = entries
        .get(&manifest.package.executable.path)
        .ok_or_else(|| SignatureError::Zip("executable is missing from archive".to_owned()))?
        .clone();
    let executable_path = manifest.package.executable.path.clone();
    Ok(VerifiedProviderArchive {
        package: SignedProviderPackage {
            archive_digest: compute_archive_digest(archive_bytes),
            manifest: String::from_utf8(manifest_bytes)
                .map_err(|error| SignatureError::Json(error.to_string()))?,
            signature,
        },
        manifest,
        executable_path,
        executable_bytes,
    })
}

impl SignedProviderPackage {
    pub fn manifest_bytes(&self) -> &[u8] {
        self.manifest.as_bytes()
    }
}

pub fn manifest_bytes(manifest: &Manifest) -> ValidationResult<Vec<u8>> {
    manifest.validate()?;
    let bytes = serde_json::to_vec(manifest).map_err(|error| ValidationError {
        field: "manifest".to_owned(),
        reason: error.to_string(),
    })?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ValidationError {
            field: "manifest".to_owned(),
            reason: "manifest exceeds the ABI size bound".to_owned(),
        });
    }
    Ok(bytes)
}

fn ensure_manifest_bound(bytes: &[u8]) -> Result<(), SignatureError> {
    if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
        return Err(SignatureError::OversizedManifest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ApiKeyDeclaration, AuthMethod, Capabilities, ExecutableEntrypoint, ManifestPackage,
        PackageFile, PackagePublisher, SideEffect, ToolDeclaration, ABI_FORMAT,
    };
    use serde_json::json;
    use std::io::Write;
    use zip::write::FileOptions;
    use zip::{CompressionMethod, ZipWriter};

    fn fixture_manifest() -> (Manifest, SigningKey) {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let executable = b"fixture executable";
        let digest = digest_hex(executable);
        (
            Manifest {
                format: ABI_FORMAT.to_owned(),
                provider_id: "fixture-provider".to_owned(),
                display_name: "Fixture provider".to_owned(),
                version: "1.0.0".to_owned(),
                publisher: PackagePublisher {
                    name: "Fixture publisher".to_owned(),
                    fingerprint: fingerprint_hex(&key.verifying_key().to_bytes()),
                },
                package: ManifestPackage {
                    files: vec![PackageFile {
                        path: "bin/provider".to_owned(),
                        size: executable.len() as u64,
                        sha256: digest.clone(),
                    }],
                    executable: ExecutableEntrypoint {
                        path: "bin/provider".to_owned(),
                        sha256: digest,
                    },
                },
                auth_methods: vec![AuthMethod::ApiKey(ApiKeyDeclaration {
                    id: "fixture_key".to_owned(),
                    credential_class: "fixture-key".to_owned(),
                    label: "Fixture key".to_owned(),
                })],
                capabilities: Capabilities {
                    auth_method_ids: vec!["fixture_key".to_owned()],
                    credential_classes: vec!["fixture-key".to_owned()],
                    network_origins: Vec::new(),
                },
                tools: vec![ToolDeclaration {
                    name: "fixture_tool".to_owned(),
                    description: "Fixture tool".to_owned(),
                    input_schema: json!({"type": "object", "additionalProperties": false}),
                    output_schema: json!({"type": "object", "additionalProperties": false}),
                    side_effects: vec![SideEffect::NetworkRead],
                    auth_method_id: Some("fixture_key".to_owned()),
                    credential_class: Some("fixture-key".to_owned()),
                    network_origins: Vec::new(),
                }],
            },
            key,
        )
    }

    fn fixture_archive(executable_mode: Option<u32>, extra_case_variant: bool) -> Vec<u8> {
        let (manifest, key) = fixture_manifest();
        let manifest_bytes = crate::manifest_bytes(&manifest).unwrap();
        let signature = sign_manifest(&manifest_bytes, &key).unwrap();
        let signature_bytes = serde_json::to_vec(&signature).unwrap();
        let mut output = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut output));
            let regular = FileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(0o644);
            zip.start_file("manifest.json", regular).unwrap();
            zip.write_all(&manifest_bytes).unwrap();
            zip.start_file("signature.json", regular).unwrap();
            zip.write_all(&signature_bytes).unwrap();
            let executable = executable_mode.map_or(regular, |mode| regular.unix_permissions(mode));
            zip.start_file("bin/provider", executable).unwrap();
            zip.write_all(b"fixture executable").unwrap();
            if extra_case_variant {
                zip.start_file("BIN/PROVIDER", regular).unwrap();
                zip.write_all(b"case collision").unwrap();
            }
            zip.finish().unwrap();
        }
        output
    }

    #[test]
    fn archive_verifier_rejects_symlink_modes_and_case_collisions() {
        let mut symlink_archive = fixture_archive(None, false);
        mark_zip_entry_as_unix_mode(&mut symlink_archive, "bin/provider", 0o120777);
        assert!(verify_provider_archive(&symlink_archive).is_err());
        assert!(verify_provider_archive(&fixture_archive(None, true)).is_err());
    }

    #[test]
    fn archive_verifier_rejects_entries_without_an_explicit_unix_mode() {
        for path in ["manifest.json", "signature.json", "bin/provider"] {
            let mut archive = fixture_archive(None, false);
            clear_zip_entry_unix_mode(&mut archive, path);
            assert!(
                verify_provider_archive(&archive).is_err(),
                "entry unexpectedly accepted without a Unix mode: {path}"
            );
        }
    }

    #[test]
    fn archive_verifier_rejects_every_non_regular_unix_entry_type() {
        for mode in [0o010644, 0o020644, 0o040755, 0o060644, 0o120777, 0o140644] {
            let mut archive = fixture_archive(None, false);
            mark_zip_entry_as_unix_mode(&mut archive, "bin/provider", mode);
            assert!(
                verify_provider_archive(&archive).is_err(),
                "non-regular mode unexpectedly accepted: {mode:o}"
            );
        }
    }

    #[test]
    fn verified_archive_contents_are_read_only_views() {
        let archive = fixture_archive(None, false);
        let verified = verify_provider_archive(&archive).unwrap();
        assert_eq!(verified.archive_digest(), compute_archive_digest(&archive));
        assert_eq!(verified.package().archive_digest, verified.archive_digest());
        assert_eq!(verified.manifest().provider_id, "fixture-provider");
        assert_eq!(verified.signed_manifest(), verified.package().manifest);
        assert_eq!(verified.signature(), &verified.package().signature);
        assert_eq!(verified.executable_path(), "bin/provider");

        let mut copied_executable = verified.executable_bytes().to_vec();
        copied_executable[0] = b'X';
        assert_ne!(copied_executable, verified.executable_bytes());
        assert_eq!(verified.executable_bytes(), b"fixture executable");
    }

    fn clear_zip_entry_unix_mode(archive: &mut [u8], name: &str) {
        let signature = b"PK\x01\x02";
        let name_bytes = name.as_bytes();
        let mut offset = 0;
        while let Some(relative) = archive[offset..]
            .windows(signature.len())
            .position(|bytes| bytes == signature)
        {
            let start = offset + relative;
            let name_len = u16::from_le_bytes([archive[start + 28], archive[start + 29]]) as usize;
            let name_start = start + 46;
            if &archive[name_start..name_start + name_len] == name_bytes {
                archive[start + 38..start + 42].copy_from_slice(&0_u32.to_le_bytes());
                return;
            }
            offset = start + signature.len();
        }
        panic!("ZIP entry not found: {name}");
    }

    fn mark_zip_entry_as_unix_mode(archive: &mut [u8], name: &str, mode: u32) {
        let signature = b"PK\x01\x02";
        let name_bytes = name.as_bytes();
        let mut offset = 0;
        while let Some(relative) = archive[offset..]
            .windows(signature.len())
            .position(|bytes| bytes == signature)
        {
            let start = offset + relative;
            let name_len = u16::from_le_bytes([archive[start + 28], archive[start + 29]]) as usize;
            let name_start = start + 46;
            if &archive[name_start..name_start + name_len] == name_bytes {
                archive[start + 4..start + 6].copy_from_slice(&0x0314_u16.to_le_bytes());
                archive[start + 38..start + 42].copy_from_slice(&(mode << 16).to_le_bytes());
                return;
            }
            offset = start + signature.len();
        }
        panic!("ZIP entry not found: {name}");
    }
}
