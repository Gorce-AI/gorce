//! Pure provider approval, lifecycle, and authorized-invocation lease policy.
//!
//! This module deliberately performs no I/O, process management, HTTP/OAuth
//! exchange, persistence, or secret handling. `Approved` means
//! trusted-after-explicit-approval; it does not mean sandboxed. A trusted
//! package executes as the user and can copy a delivered access/API key.

use std::collections::BTreeSet;
use std::fmt;

use gorce_provider_abi::{
    derive_tool_id, digest_hex, AuthMethod, AuthorizedInvocation, DeliveryKind, GitHashAlgorithm,
    Manifest, ScopedSecretDelivery, SideEffect, VerifiedProviderArchive, VerifiedProviderSource,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderPolicyError {
    InvalidManifest(String),
    ApprovalMismatch {
        field: &'static str,
    },
    CapabilityEscalation {
        field: &'static str,
        value: String,
    },
    InvalidLifecycleTransition {
        from: ProviderLifecycle,
        to: ProviderLifecycle,
    },
    LeaseDenied {
        reason: LeaseDenial,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseDenial {
    ProviderRevoked,
    LifecycleNotAuthorized,
    ArchiveNotApproved,
    ToolNotApproved,
    CredentialClassNotApproved,
    InvocationMismatch,
    Expired,
    LifetimeTooLong,
    DeliveryScopeMismatch,
}

impl fmt::Display for ProviderPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifest(reason) => {
                write!(formatter, "invalid provider manifest: {reason}")
            }
            Self::ApprovalMismatch { field } => {
                write!(formatter, "provider approval mismatch: {field}")
            }
            Self::CapabilityEscalation { field, value } => {
                write!(
                    formatter,
                    "provider capability escalation in {field}: {value}"
                )
            }
            Self::InvalidLifecycleTransition { from, to } => {
                write!(
                    formatter,
                    "invalid provider lifecycle transition: {from:?} -> {to:?}"
                )
            }
            Self::LeaseDenied { reason } => write!(formatter, "provider lease denied: {reason:?}"),
        }
    }
}

impl std::error::Error for ProviderPolicyError {}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProviderCapabilitySet {
    pub auth_method_ids: BTreeSet<String>,
    pub auth_policies: BTreeSet<String>,
    pub tool_ids: BTreeSet<String>,
    pub tool_policies: BTreeSet<String>,
    pub credential_classes: BTreeSet<String>,
    pub network_origins: BTreeSet<String>,
    pub side_effects: BTreeSet<SideEffect>,
    pub tool_credentials: BTreeSet<(String, String, String, DeliveryKind)>,
}

impl ProviderCapabilitySet {
    fn from_manifest(
        manifest: &Manifest,
        archive_digest: &str,
    ) -> Result<Self, ProviderPolicyError> {
        let mut capabilities = Self {
            auth_method_ids: manifest
                .capabilities
                .auth_method_ids
                .iter()
                .cloned()
                .collect(),
            auth_policies: manifest.auth_methods.iter().map(auth_policy_key).collect(),
            credential_classes: manifest
                .capabilities
                .credential_classes
                .iter()
                .cloned()
                .collect(),
            network_origins: manifest
                .capabilities
                .network_origins
                .iter()
                .cloned()
                .collect(),
            ..Self::default()
        };
        for tool in &manifest.tools {
            let tool_id = derive_tool_id(archive_digest, &manifest.provider_id, &tool.name);
            capabilities.tool_ids.insert(tool_id.clone());
            capabilities.tool_policies.insert(format!(
                "{}|credential={:?}|origins={:?}|effects={:?}|input={}|output={}",
                tool_id,
                tool.credential_class,
                tool.network_origins,
                tool.side_effects,
                serde_json::to_string(&tool.input_schema).unwrap_or_default(),
                serde_json::to_string(&tool.output_schema).unwrap_or_default(),
            ));
            capabilities
                .side_effects
                .extend(tool.side_effects.iter().copied());
            capabilities
                .network_origins
                .extend(tool.network_origins.iter().cloned());
            if let (Some(auth_method_id), Some(class)) =
                (&tool.auth_method_id, &tool.credential_class)
            {
                if let Some(auth_method) = manifest.auth_method(auth_method_id) {
                    capabilities.tool_credentials.insert((
                        tool_id,
                        auth_method.id().to_owned(),
                        class.clone(),
                        delivery_kind_for_auth(auth_method),
                    ));
                }
            }
        }
        Ok(capabilities)
    }

    pub fn is_subset_of(&self, approved: &Self) -> bool {
        self.auth_method_ids.is_subset(&approved.auth_method_ids)
            && self.auth_policies.is_subset(&approved.auth_policies)
            && self.tool_ids.is_subset(&approved.tool_ids)
            && self.tool_policies.is_subset(&approved.tool_policies)
            && self
                .credential_classes
                .is_subset(&approved.credential_classes)
            && self.network_origins.is_subset(&approved.network_origins)
            && self.side_effects.is_subset(&approved.side_effects)
            && self.tool_credentials.is_subset(&approved.tool_credentials)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderApprovalTuple {
    provider_id: String,
    archive_digest: String,
    manifest_digest: String,
    publisher_fingerprint: Option<String>,
    executable_sha256: String,
    capabilities: ProviderCapabilitySet,
    source_identity: Option<ProviderSourceIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSourceIdentity {
    canonical_git_url: String,
    commit_hash_algorithm: GitHashAlgorithm,
    resolved_commit: String,
    source_content_digest_algorithm: &'static str,
}

impl ProviderSourceIdentity {
    pub fn canonical_git_url(&self) -> &str {
        &self.canonical_git_url
    }

    pub fn commit_hash_algorithm(&self) -> GitHashAlgorithm {
        self.commit_hash_algorithm
    }

    pub fn resolved_commit(&self) -> &str {
        &self.resolved_commit
    }

    pub fn source_content_digest_algorithm(&self) -> &'static str {
        self.source_content_digest_algorithm
    }
}

impl ProviderApprovalTuple {
    /// Derive approval only from the artifact returned by the archive-byte
    /// verifier. The manifest, archive digest, executable bytes, and signed
    /// manifest bytes cannot be supplied independently.
    pub fn from_verified_archive(
        artifact: &VerifiedProviderArchive,
    ) -> Result<Self, ProviderPolicyError> {
        Self::from_verified_parts(
            artifact.manifest(),
            artifact.signed_manifest().as_bytes(),
            artifact.archive_digest(),
            artifact.executable_path(),
            artifact.executable_bytes(),
            artifact
                .manifest()
                .publisher
                .as_ref()
                .map(|publisher| publisher.fingerprint.clone()),
            None,
        )
    }

    /// Derive approval from the resolver-owned, unsigned Git source proof. The
    /// source content digest is the package identity; publisher fingerprints
    /// are deliberately not part of this approval identity.
    pub fn from_verified_source(
        artifact: &VerifiedProviderSource,
    ) -> Result<Self, ProviderPolicyError> {
        if artifact.manifest_digest() != digest_hex(artifact.manifest_bytes()) {
            return Err(ProviderPolicyError::InvalidManifest(
                "verified provider source has an inconsistent manifest digest".to_owned(),
            ));
        }
        Self::from_verified_parts(
            artifact.manifest(),
            artifact.manifest_bytes(),
            artifact.source_content_digest(),
            artifact.executable_path(),
            artifact.executable_bytes(),
            None,
            Some(ProviderSourceIdentity {
                canonical_git_url: artifact.canonical_git_url().to_owned(),
                commit_hash_algorithm: artifact.commit_hash_algorithm(),
                resolved_commit: artifact.resolved_commit().to_owned(),
                source_content_digest_algorithm: artifact.source_content_digest_algorithm(),
            }),
        )
    }

    fn from_verified_parts(
        manifest: &Manifest,
        signed_manifest_bytes: &[u8],
        package_digest: &str,
        executable_path: &str,
        executable_bytes: &[u8],
        publisher_fingerprint: Option<String>,
        source_identity: Option<ProviderSourceIdentity>,
    ) -> Result<Self, ProviderPolicyError> {
        let signed_manifest: Manifest =
            serde_json::from_slice(signed_manifest_bytes).map_err(|_| {
                ProviderPolicyError::InvalidManifest(
                    "verified provider artifact has invalid manifest bytes".to_owned(),
                )
            })?;
        if executable_path != manifest.package.executable.path
            || digest_hex(executable_bytes) != manifest.package.executable.sha256
            || signed_manifest != *manifest
            || package_digest.len() != 64
            || !package_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ProviderPolicyError::InvalidManifest(
                "verified provider artifact is internally inconsistent".to_owned(),
            ));
        }
        if source_identity.is_some() {
            manifest
                .validate_source()
                .map_err(|error| ProviderPolicyError::InvalidManifest(error.to_string()))?;
        } else {
            manifest
                .validate()
                .map_err(|error| ProviderPolicyError::InvalidManifest(error.to_string()))?;
        }
        let manifest_digest = digest_hex(signed_manifest_bytes);
        Ok(Self {
            provider_id: manifest.provider_id.clone(),
            archive_digest: package_digest.to_owned(),
            manifest_digest,
            publisher_fingerprint,
            executable_sha256: manifest.package.executable.sha256.clone(),
            capabilities: ProviderCapabilitySet::from_manifest(manifest, package_digest)?,
            source_identity,
        })
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn archive_digest(&self) -> &str {
        &self.archive_digest
    }

    pub fn package_digest(&self) -> &str {
        &self.archive_digest
    }

    pub fn content_digest(&self) -> &str {
        &self.archive_digest
    }

    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub fn publisher_fingerprint(&self) -> Option<&str> {
        self.publisher_fingerprint.as_deref()
    }

    pub fn capabilities(&self) -> &ProviderCapabilitySet {
        &self.capabilities
    }

    pub fn source_identity(&self) -> Option<&ProviderSourceIdentity> {
        self.source_identity.as_ref()
    }
}

/// Explicit approval is an exact tuple match. Runtime declarations may then
/// be a strict subset, but a different artifact identity, source pin,
/// manifest, publisher, executable, or capability set must not silently
/// inherit approval.
pub fn compare_approval_tuple(
    approved: &ProviderApprovalTuple,
    candidate: &ProviderApprovalTuple,
) -> Result<(), ProviderPolicyError> {
    for (field, expected, actual) in [
        ("provider_id", &approved.provider_id, &candidate.provider_id),
        (
            "archive_digest",
            &approved.archive_digest,
            &candidate.archive_digest,
        ),
        (
            "manifest_digest",
            &approved.manifest_digest,
            &candidate.manifest_digest,
        ),
        (
            "executable_sha256",
            &approved.executable_sha256,
            &candidate.executable_sha256,
        ),
    ] {
        if expected != actual {
            return Err(ProviderPolicyError::ApprovalMismatch { field });
        }
    }
    if approved.publisher_fingerprint != candidate.publisher_fingerprint {
        return Err(ProviderPolicyError::ApprovalMismatch {
            field: "publisher_fingerprint",
        });
    }
    if approved.source_identity != candidate.source_identity {
        return Err(ProviderPolicyError::ApprovalMismatch {
            field: "source_identity",
        });
    }
    if approved.capabilities != candidate.capabilities {
        return Err(ProviderPolicyError::ApprovalMismatch {
            field: "capabilities",
        });
    }
    Ok(())
}

pub fn approval_tuple_matches(
    approved: &ProviderApprovalTuple,
    candidate: &ProviderApprovalTuple,
) -> bool {
    compare_approval_tuple(approved, candidate).is_ok()
}

pub fn validate_capability_subset(
    approved: &ProviderCapabilitySet,
    runtime: &ProviderCapabilitySet,
) -> Result<(), ProviderPolicyError> {
    check_string_subset(
        "auth_method_ids",
        &runtime.auth_method_ids,
        &approved.auth_method_ids,
    )?;
    check_string_subset(
        "auth_policies",
        &runtime.auth_policies,
        &approved.auth_policies,
    )?;
    check_string_subset("tool_ids", &runtime.tool_ids, &approved.tool_ids)?;
    check_string_subset(
        "tool_policies",
        &runtime.tool_policies,
        &approved.tool_policies,
    )?;
    check_string_subset(
        "credential_classes",
        &runtime.credential_classes,
        &approved.credential_classes,
    )?;
    check_string_subset(
        "network_origins",
        &runtime.network_origins,
        &approved.network_origins,
    )?;
    if let Some(value) = runtime
        .side_effects
        .iter()
        .find(|value| !approved.side_effects.contains(*value))
    {
        return Err(ProviderPolicyError::CapabilityEscalation {
            field: "side_effects",
            value: format!("{value:?}"),
        });
    }
    if let Some(value) = runtime
        .tool_credentials
        .iter()
        .find(|value| !approved.tool_credentials.contains(*value))
    {
        return Err(ProviderPolicyError::CapabilityEscalation {
            field: "tool_credentials",
            value: format!("{value:?}"),
        });
    }
    Ok(())
}

fn check_string_subset(
    field: &'static str,
    runtime: &BTreeSet<String>,
    approved: &BTreeSet<String>,
) -> Result<(), ProviderPolicyError> {
    if let Some(value) = runtime.iter().find(|value| !approved.contains(*value)) {
        return Err(ProviderPolicyError::CapabilityEscalation {
            field,
            value: value.clone(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderLifecycle {
    Installed,
    Approved,
    Starting,
    Ready,
    Invoking,
    Stopping,
    Stopped,
    Failed,
    Revoked,
}

pub fn lifecycle_transition(
    from: ProviderLifecycle,
    to: ProviderLifecycle,
) -> Result<(), ProviderPolicyError> {
    let valid = matches!(
        (from, to),
        (ProviderLifecycle::Installed, ProviderLifecycle::Approved)
            | (ProviderLifecycle::Approved, ProviderLifecycle::Starting)
            | (ProviderLifecycle::Approved, ProviderLifecycle::Revoked)
            | (ProviderLifecycle::Starting, ProviderLifecycle::Ready)
            | (ProviderLifecycle::Starting, ProviderLifecycle::Failed)
            | (ProviderLifecycle::Starting, ProviderLifecycle::Revoked)
            | (ProviderLifecycle::Ready, ProviderLifecycle::Invoking)
            | (ProviderLifecycle::Ready, ProviderLifecycle::Stopping)
            | (ProviderLifecycle::Ready, ProviderLifecycle::Failed)
            | (ProviderLifecycle::Ready, ProviderLifecycle::Revoked)
            | (ProviderLifecycle::Invoking, ProviderLifecycle::Ready)
            | (ProviderLifecycle::Invoking, ProviderLifecycle::Stopping)
            | (ProviderLifecycle::Invoking, ProviderLifecycle::Failed)
            | (ProviderLifecycle::Invoking, ProviderLifecycle::Revoked)
            | (ProviderLifecycle::Stopping, ProviderLifecycle::Stopped)
            | (ProviderLifecycle::Stopping, ProviderLifecycle::Failed)
            | (ProviderLifecycle::Stopping, ProviderLifecycle::Revoked)
            | (ProviderLifecycle::Stopped, ProviderLifecycle::Starting)
            | (ProviderLifecycle::Stopped, ProviderLifecycle::Revoked)
            | (ProviderLifecycle::Failed, ProviderLifecycle::Revoked)
    );
    valid
        .then_some(())
        .ok_or(ProviderPolicyError::InvalidLifecycleTransition { from, to })
}

/// Decide lease/access delivery from the host-authorized invocation and the
/// provider's current lifecycle state. There is no caller-provided approval
/// boolean: package digest, tool, credential and deadline all come from the
/// authoritative invocation binding, while revocation is checked at issuance
/// rather than when the approval tuple was derived.
pub fn decide_lease(
    approval: &ProviderApprovalTuple,
    current_lifecycle: ProviderLifecycle,
    invocation: &AuthorizedInvocation,
    delivery: Option<&ScopedSecretDelivery>,
    now_unix_ms: u64,
    max_lifetime_ms: u64,
) -> Result<(), ProviderPolicyError> {
    if current_lifecycle == ProviderLifecycle::Revoked {
        return Err(ProviderPolicyError::LeaseDenied {
            reason: LeaseDenial::ProviderRevoked,
        });
    }
    if !matches!(
        current_lifecycle,
        ProviderLifecycle::Approved
            | ProviderLifecycle::Starting
            | ProviderLifecycle::Ready
            | ProviderLifecycle::Invoking
    ) {
        return Err(ProviderPolicyError::LeaseDenied {
            reason: LeaseDenial::LifecycleNotAuthorized,
        });
    }
    if invocation.validate().is_err() {
        return Err(ProviderPolicyError::LeaseDenied {
            reason: LeaseDenial::InvocationMismatch,
        });
    }
    if invocation.package_digest != approval.archive_digest {
        return Err(ProviderPolicyError::LeaseDenied {
            reason: LeaseDenial::ArchiveNotApproved,
        });
    }
    if invocation.deadline_unix_ms <= now_unix_ms {
        return Err(ProviderPolicyError::LeaseDenied {
            reason: LeaseDenial::Expired,
        });
    }
    if invocation.deadline_unix_ms - now_unix_ms > max_lifetime_ms {
        return Err(ProviderPolicyError::LeaseDenied {
            reason: LeaseDenial::LifetimeTooLong,
        });
    }
    if !approval.capabilities.tool_ids.contains(&invocation.tool_id) {
        return Err(ProviderPolicyError::LeaseDenied {
            reason: LeaseDenial::ToolNotApproved,
        });
    }
    match &invocation.credential_class {
        Some(class) => {
            let Some(auth_method_id) = invocation.auth_method_id.as_ref() else {
                return Err(ProviderPolicyError::LeaseDenied {
                    reason: LeaseDenial::CredentialClassNotApproved,
                });
            };
            let Some(delivery_kind) = invocation.delivery_kind else {
                return Err(ProviderPolicyError::LeaseDenied {
                    reason: LeaseDenial::CredentialClassNotApproved,
                });
            };
            if !approval.capabilities.tool_credentials.contains(&(
                invocation.tool_id.clone(),
                auth_method_id.clone(),
                class.clone(),
                delivery_kind,
            )) {
                return Err(ProviderPolicyError::LeaseDenied {
                    reason: LeaseDenial::CredentialClassNotApproved,
                });
            }
        }
        None if delivery.is_some()
            || invocation.auth_method_id.is_some()
            || invocation.delivery_kind.is_some() =>
        {
            return Err(ProviderPolicyError::LeaseDenied {
                reason: LeaseDenial::CredentialClassNotApproved,
            })
        }
        None => {
            if approval
                .capabilities
                .tool_credentials
                .iter()
                .any(|(tool_id, _, _, _)| tool_id == &invocation.tool_id)
            {
                return Err(ProviderPolicyError::LeaseDenied {
                    reason: LeaseDenial::CredentialClassNotApproved,
                });
            }
            return Ok(());
        }
    }
    if let Some(delivery) = delivery {
        if delivery.expires_at_unix_ms <= now_unix_ms {
            return Err(ProviderPolicyError::LeaseDenied {
                reason: LeaseDenial::Expired,
            });
        }
        delivery
            .validate_for(invocation)
            .map_err(|_| ProviderPolicyError::LeaseDenied {
                reason: LeaseDenial::DeliveryScopeMismatch,
            })?;
    } else {
        return Err(ProviderPolicyError::LeaseDenied {
            reason: LeaseDenial::DeliveryScopeMismatch,
        });
    }
    Ok(())
}

fn auth_policy_key(method: &AuthMethod) -> String {
    match method {
        AuthMethod::ApiKey(value) => format!("api_key|{}|{}", value.id, value.credential_class),
        AuthMethod::OauthAuthorizationCodePkce(value) => format!(
            "oauth_authorization_code_pkce|{}|{}|{}|{}|{}|{}|{:?}|{:?}|{:?}|{}|{}",
            value.id,
            value.credential_class,
            value.client_type,
            value.client_id,
            value.authorization_endpoint,
            value.token_endpoint,
            value.approved_origins,
            value.scopes,
            value.callback,
            value.grant_type,
            value.pkce_method
        ),
    }
}

fn delivery_kind_for_auth(method: &AuthMethod) -> DeliveryKind {
    match method {
        AuthMethod::ApiKey(_) => DeliveryKind::ApiKey,
        AuthMethod::OauthAuthorizationCodePkce(_) => DeliveryKind::AccessToken,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gorce_provider_abi::{digest_hex, verify_provider_archive};

    const FIXTURE_MANIFEST: &str = "{\"format\":\"gorce.provider/v1\",\"provider_id\":\"fixture-provider\",\"display_name\":\"Provider ABI fixture\",\"version\":\"1.0.0\",\"publisher\":{\"name\":\"Fixture publisher\",\"fingerprint\":\"3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f\"},\"package\":{\"files\":[{\"path\":\"bin/provider\",\"size\":1,\"sha256\":\"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d\"}],\"executable\":{\"path\":\"bin/provider\",\"sha256\":\"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d\"}},\"auth_methods\":[{\"kind\":\"api_key\",\"id\":\"fixture_api_key\",\"credential_class\":\"fixture-key\",\"label\":\"Fixture API key\"}],\"capabilities\":{\"auth_method_ids\":[\"fixture_api_key\"],\"credential_classes\":[\"fixture-key\"],\"network_origins\":[]},\"tools\":[{\"name\":\"fixture_tool\",\"description\":\"Fixture tool\",\"input_schema\":{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\",\"minLength\":1}},\"required\":[\"query\"],\"additionalProperties\":false},\"output_schema\":{\"type\":\"object\",\"additionalProperties\":false},\"side_effects\":[\"network_read\"],\"auth_method_id\":\"fixture_api_key\",\"credential_class\":\"fixture-key\",\"network_origins\":[]}]}";
    const FIXTURE_SIGNATURE: &str = "{\"algorithm\":\"ed25519\",\"public_key\":\"IVL40Zt5HSRFMkLhXy6rbLfP+ntqXtMAl5YOBpiB2xI=\",\"signature\":\"VJmCkYiZLUw4QuB6naLXw20SDguWWNOKB3tpVEOKPg5K+n0Ft+WIRzKVHl6/keMmD20IhHiO/6Qt09P2TfBGCg==\"}";

    fn verified_fixture() -> VerifiedProviderArchive {
        verify_provider_archive(&fixture_archive()).unwrap()
    }

    fn fixture_archive() -> Vec<u8> {
        let entries = [
            ("manifest.json", FIXTURE_MANIFEST.as_bytes()),
            ("signature.json", FIXTURE_SIGNATURE.as_bytes()),
            ("bin/provider", &[0_u8][..]),
        ];
        let mut archive = Vec::new();
        let mut central_directory = Vec::new();

        for (path, bytes) in entries {
            let offset = archive.len() as u32;
            let crc = crc32(bytes);
            push_u32(&mut archive, 0x0403_4b50);
            push_u16(&mut archive, 20);
            push_u16(&mut archive, 0);
            push_u16(&mut archive, 0);
            push_u16(&mut archive, 0);
            push_u16(&mut archive, 0);
            push_u32(&mut archive, crc);
            push_u32(&mut archive, bytes.len() as u32);
            push_u32(&mut archive, bytes.len() as u32);
            push_u16(&mut archive, path.len() as u16);
            push_u16(&mut archive, 0);
            archive.extend_from_slice(path.as_bytes());
            archive.extend_from_slice(bytes);

            push_u32(&mut central_directory, 0x0201_4b50);
            push_u16(&mut central_directory, 0x0314);
            push_u16(&mut central_directory, 20);
            push_u16(&mut central_directory, 0);
            push_u16(&mut central_directory, 0);
            push_u16(&mut central_directory, 0);
            push_u16(&mut central_directory, 0);
            push_u32(&mut central_directory, crc);
            push_u32(&mut central_directory, bytes.len() as u32);
            push_u32(&mut central_directory, bytes.len() as u32);
            push_u16(&mut central_directory, path.len() as u16);
            push_u16(&mut central_directory, 0);
            push_u16(&mut central_directory, 0);
            push_u16(&mut central_directory, 0);
            push_u16(&mut central_directory, 0);
            push_u32(&mut central_directory, 0o100644_u32 << 16);
            push_u32(&mut central_directory, offset);
            central_directory.extend_from_slice(path.as_bytes());
        }

        let central_offset = archive.len() as u32;
        let central_size = central_directory.len() as u32;
        archive.extend_from_slice(&central_directory);
        push_u32(&mut archive, 0x0605_4b50);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, entries.len() as u16);
        push_u16(&mut archive, entries.len() as u16);
        push_u32(&mut archive, central_size);
        push_u32(&mut archive, central_offset);
        push_u16(&mut archive, 0);
        archive
    }

    fn push_u16(output: &mut Vec<u8>, value: u16) {
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = u32::MAX;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    #[test]
    fn approval_is_derived_from_one_verified_archive_artifact() {
        let artifact = verified_fixture();
        let approval = ProviderApprovalTuple::from_verified_archive(&artifact).unwrap();
        assert_eq!(approval.archive_digest(), artifact.archive_digest());
        assert_eq!(
            approval.manifest_digest(),
            digest_hex(artifact.signed_manifest().as_bytes())
        );
        assert_eq!(artifact.executable_path(), "bin/provider");
        assert_eq!(artifact.executable_bytes(), &[0_u8]);
    }

    #[test]
    fn source_approval_identity_includes_pinned_source_and_content_authority() {
        let source_digest = "a".repeat(64);
        let provider_id = "source-fixture";
        let source_identity = ProviderSourceIdentity {
            canonical_git_url: "https://example.com/gorce/provider".to_owned(),
            commit_hash_algorithm: GitHashAlgorithm::Sha1,
            resolved_commit: "b".repeat(40),
            source_content_digest_algorithm: gorce_provider_abi::SOURCE_CONTENT_DIGEST_ALGORITHM,
        };
        let tool_id = derive_tool_id(&source_digest, provider_id, "web_search");
        let mut capabilities = ProviderCapabilitySet::default();
        capabilities.tool_ids.insert(tool_id.clone());
        let approval = ProviderApprovalTuple {
            provider_id: provider_id.to_owned(),
            archive_digest: source_digest.clone(),
            manifest_digest: "c".repeat(64),
            publisher_fingerprint: None,
            executable_sha256: "d".repeat(64),
            capabilities,
            source_identity: Some(source_identity.clone()),
        };
        assert_eq!(approval.package_digest(), source_digest);
        assert_eq!(approval.archive_digest(), source_digest);
        assert_eq!(approval.publisher_fingerprint(), None);
        let identity = approval.source_identity().unwrap();
        assert_eq!(
            identity.canonical_git_url(),
            source_identity.canonical_git_url()
        );
        assert_eq!(
            identity.commit_hash_algorithm(),
            source_identity.commit_hash_algorithm()
        );
        assert_eq!(
            identity.resolved_commit(),
            source_identity.resolved_commit()
        );
        assert_eq!(
            identity.source_content_digest_algorithm(),
            gorce_provider_abi::SOURCE_CONTENT_DIGEST_ALGORITHM
        );
        assert!(approval.capabilities().tool_ids.contains(&tool_id));

        let mut substituted = approval.clone();
        substituted.source_identity = Some(ProviderSourceIdentity {
            canonical_git_url: "https://example.com/other/provider".to_owned(),
            commit_hash_algorithm: identity.commit_hash_algorithm(),
            resolved_commit: identity.resolved_commit().to_owned(),
            source_content_digest_algorithm: identity.source_content_digest_algorithm(),
        });
        assert!(matches!(
            compare_approval_tuple(&approval, &substituted),
            Err(ProviderPolicyError::ApprovalMismatch {
                field: "source_identity"
            })
        ));
    }

    #[test]
    fn approved_provider_can_receive_a_lease() {
        let artifact = verified_fixture();
        let approval = ProviderApprovalTuple::from_verified_archive(&artifact).unwrap();
        let package_digest = approval.archive_digest().to_owned();
        let invocation = AuthorizedInvocation {
            package_digest,
            tool_id: derive_tool_id(
                approval.archive_digest(),
                approval.provider_id(),
                "fixture_tool",
            ),
            invocation_id: "approved-invocation".to_owned(),
            auth_method_id: Some("fixture_api_key".to_owned()),
            credential_class: Some("fixture-key".to_owned()),
            delivery_kind: Some(DeliveryKind::ApiKey),
            deadline_unix_ms: 2_000,
        };
        let delivery = ScopedSecretDelivery {
            kind: DeliveryKind::ApiKey,
            credential_class: "fixture-key".to_owned(),
            value: "secret".to_owned(),
            expires_at_unix_ms: 1_900,
        };

        assert_eq!(
            decide_lease(
                &approval,
                ProviderLifecycle::Approved,
                &invocation,
                Some(&delivery),
                1_000,
                2_000,
            ),
            Ok(())
        );
    }

    #[test]
    fn credential_required_tool_rejects_an_all_null_binding() {
        let artifact = verified_fixture();
        let approval = ProviderApprovalTuple::from_verified_archive(&artifact).unwrap();
        let invocation = AuthorizedInvocation {
            package_digest: approval.archive_digest().to_owned(),
            tool_id: derive_tool_id(
                approval.archive_digest(),
                approval.provider_id(),
                "fixture_tool",
            ),
            invocation_id: "null-binding-invocation".to_owned(),
            auth_method_id: None,
            credential_class: None,
            delivery_kind: None,
            deadline_unix_ms: 2_000,
        };

        assert_eq!(
            decide_lease(
                &approval,
                ProviderLifecycle::Approved,
                &invocation,
                None,
                1_000,
                2_000,
            ),
            Err(ProviderPolicyError::LeaseDenied {
                reason: LeaseDenial::CredentialClassNotApproved,
            })
        );
    }

    #[test]
    fn lease_issuance_requires_an_authorized_lifecycle_state() {
        let artifact = verified_fixture();
        let approval = ProviderApprovalTuple::from_verified_archive(&artifact).unwrap();
        let invocation = AuthorizedInvocation {
            package_digest: approval.archive_digest().to_owned(),
            tool_id: derive_tool_id(
                approval.archive_digest(),
                approval.provider_id(),
                "fixture_tool",
            ),
            invocation_id: "lifecycle-invocation".to_owned(),
            auth_method_id: Some("fixture_api_key".to_owned()),
            credential_class: Some("fixture-key".to_owned()),
            delivery_kind: Some(DeliveryKind::ApiKey),
            deadline_unix_ms: 2_000,
        };
        let delivery = ScopedSecretDelivery {
            kind: DeliveryKind::ApiKey,
            credential_class: "fixture-key".to_owned(),
            value: "secret".to_owned(),
            expires_at_unix_ms: 1_900,
        };

        for state in [
            ProviderLifecycle::Approved,
            ProviderLifecycle::Starting,
            ProviderLifecycle::Ready,
            ProviderLifecycle::Invoking,
        ] {
            assert_eq!(
                decide_lease(&approval, state, &invocation, Some(&delivery), 1_000, 2_000,),
                Ok(()),
                "lease unexpectedly denied in {state:?}"
            );
        }

        for state in [
            ProviderLifecycle::Installed,
            ProviderLifecycle::Stopping,
            ProviderLifecycle::Stopped,
            ProviderLifecycle::Failed,
        ] {
            assert_eq!(
                decide_lease(&approval, state, &invocation, Some(&delivery), 1_000, 2_000,),
                Err(ProviderPolicyError::LeaseDenied {
                    reason: LeaseDenial::LifecycleNotAuthorized,
                }),
                "lease unexpectedly allowed in {state:?}"
            );
        }
        assert_eq!(
            decide_lease(
                &approval,
                ProviderLifecycle::Revoked,
                &invocation,
                Some(&delivery),
                1_000,
                2_000,
            ),
            Err(ProviderPolicyError::LeaseDenied {
                reason: LeaseDenial::ProviderRevoked,
            })
        );
    }

    #[test]
    fn revocation_rejects_a_lease_from_a_previously_derived_approval() {
        let artifact = verified_fixture();
        let approval = ProviderApprovalTuple::from_verified_archive(&artifact).unwrap();
        let package_digest = approval.archive_digest().to_owned();
        let invocation = AuthorizedInvocation {
            package_digest,
            tool_id: derive_tool_id(
                approval.archive_digest(),
                approval.provider_id(),
                "fixture_tool",
            ),
            invocation_id: "revoked-invocation".to_owned(),
            auth_method_id: Some("fixture_api_key".to_owned()),
            credential_class: Some("fixture-key".to_owned()),
            delivery_kind: Some(DeliveryKind::ApiKey),
            deadline_unix_ms: 2_000,
        };
        let delivery = ScopedSecretDelivery {
            kind: DeliveryKind::ApiKey,
            credential_class: "fixture-key".to_owned(),
            value: "secret".to_owned(),
            expires_at_unix_ms: 1_900,
        };

        assert!(
            lifecycle_transition(ProviderLifecycle::Approved, ProviderLifecycle::Revoked).is_ok()
        );
        assert_eq!(
            decide_lease(
                &approval,
                ProviderLifecycle::Revoked,
                &invocation,
                Some(&delivery),
                1_000,
                2_000,
            ),
            Err(ProviderPolicyError::LeaseDenied {
                reason: LeaseDenial::ProviderRevoked,
            })
        );
    }

    #[test]
    fn expired_delivery_is_denied_and_terminal_states_can_be_revoked() {
        for state in [
            ProviderLifecycle::Approved,
            ProviderLifecycle::Starting,
            ProviderLifecycle::Invoking,
            ProviderLifecycle::Stopping,
            ProviderLifecycle::Stopped,
            ProviderLifecycle::Failed,
        ] {
            assert!(lifecycle_transition(state, ProviderLifecycle::Revoked).is_ok());
        }

        let artifact = verified_fixture();
        let approval = ProviderApprovalTuple::from_verified_archive(&artifact).unwrap();
        let package_digest = approval.archive_digest().to_owned();
        let tool_id = derive_tool_id(&package_digest, approval.provider_id(), "fixture_tool");
        let invocation = AuthorizedInvocation {
            package_digest,
            tool_id,
            invocation_id: "expired-invocation".to_owned(),
            auth_method_id: Some("fixture_api_key".to_owned()),
            credential_class: Some("fixture-key".to_owned()),
            delivery_kind: Some(DeliveryKind::ApiKey),
            deadline_unix_ms: 2_000,
        };
        let delivery = ScopedSecretDelivery {
            kind: DeliveryKind::ApiKey,
            credential_class: "fixture-key".to_owned(),
            value: "secret".to_owned(),
            expires_at_unix_ms: 999,
        };
        assert_eq!(
            decide_lease(
                &approval,
                ProviderLifecycle::Approved,
                &invocation,
                Some(&delivery),
                1_000,
                2_000,
            ),
            Err(ProviderPolicyError::LeaseDenied {
                reason: LeaseDenial::Expired,
            })
        );

        assert!(
            lifecycle_transition(ProviderLifecycle::Installed, ProviderLifecycle::Revoked).is_err()
        );
        for state in [
            ProviderLifecycle::Installed,
            ProviderLifecycle::Approved,
            ProviderLifecycle::Starting,
            ProviderLifecycle::Ready,
            ProviderLifecycle::Invoking,
            ProviderLifecycle::Stopping,
            ProviderLifecycle::Stopped,
            ProviderLifecycle::Failed,
            ProviderLifecycle::Revoked,
        ] {
            assert!(lifecycle_transition(ProviderLifecycle::Revoked, state).is_err());
        }
    }
}
