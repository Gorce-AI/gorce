use std::collections::{BTreeMap, BTreeSet};

use serde::{de::DeserializeOwned, de::Error as DeError, Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::{Host, Url};

use crate::validation::{validate_local_schema, ValidationError, ValidationResult};

pub const ABI_FORMAT: &str = "gorce.provider/v1";
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_TOOLS: usize = 64;
pub const MAX_AUTH_METHODS: usize = 8;
pub const MAX_FILE_TABLE_ENTRIES: usize = 128;
pub const MAX_FILE_PATH_BYTES: usize = 256;
pub const MAX_FILE_SIZE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STRING_BYTES: usize = 512;
const MAX_LIST_ITEMS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub provider_id: String,
    pub display_name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<PackagePublisher>,
    pub package: ManifestPackage,
    pub auth_methods: Vec<AuthMethod>,
    pub capabilities: Capabilities,
    pub tools: Vec<ToolDeclaration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePublisher {
    pub name: String,
    /// Lower-case SHA-256 of the Ed25519 public key in the detached signature.
    pub fingerprint: String,
}

/// Package metadata is signed, but deliberately contains no archive digest.
/// The archive digest is computed by the host over immutable archive bytes and
/// carried beside the signed manifest. Keeping it out of these bytes prevents
/// a self-referential digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPackage {
    pub files: Vec<PackageFile>,
    pub executable: ExecutableEntrypoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableEntrypoint {
    pub path: String,
    pub sha256: String,
}

/// Host-computed file content supplied to the pure package binding check.
/// This is metadata, not an I/O operation or an archive reader.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ArchiveFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for ArchiveFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArchiveFile")
            .field("path", &self.path)
            .field("size", &self.bytes.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthMethod {
    ApiKey(ApiKeyDeclaration),
    OauthAuthorizationCodePkce(OAuthAuthorizationCodePkceDeclaration),
}

impl AuthMethod {
    pub fn id(&self) -> &str {
        match self {
            Self::ApiKey(value) => &value.id,
            Self::OauthAuthorizationCodePkce(value) => &value.id,
        }
    }

    pub fn credential_class(&self) -> &str {
        match self {
            Self::ApiKey(value) => &value.credential_class,
            Self::OauthAuthorizationCodePkce(value) => &value.credential_class,
        }
    }

    pub fn origins(&self) -> &[String] {
        match self {
            Self::ApiKey(_) => &[],
            Self::OauthAuthorizationCodePkce(value) => &value.approved_origins,
        }
    }

    pub fn scopes(&self) -> &[String] {
        match self {
            Self::ApiKey(_) => &[],
            Self::OauthAuthorizationCodePkce(value) => &value.scopes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyDeclaration {
    pub id: String,
    pub credential_class: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthAuthorizationCodePkceDeclaration {
    pub id: String,
    pub credential_class: String,
    pub label: String,
    /// V1 admits public clients only; private clients and client secrets are not ABI fields.
    pub client_type: String,
    /// A vendor-issued public-client identifier. No client secret is allowed.
    pub client_id: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub approved_origins: Vec<String>,
    pub scopes: Vec<String>,
    /// The only callback policy in v1. The host owns state, verifier and callback handling.
    pub callback: CallbackPolicy,
    pub grant_type: String,
    pub pkce_method: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackPolicy {
    HostManaged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub auth_method_ids: Vec<String>,
    pub credential_classes: Vec<String>,
    pub network_origins: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolDeclaration {
    /// Package-local name. The package never supplies its authority-bearing ID.
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub side_effects: Vec<SideEffect>,
    pub auth_method_id: Option<String>,
    pub credential_class: Option<String>,
    pub network_origins: Vec<String>,
}

struct RequiredNullable<T> {
    present: bool,
    value: Option<T>,
}

impl<T> Default for RequiredNullable<T> {
    fn default() -> Self {
        Self {
            present: false,
            value: None,
        }
    }
}

impl<'de, T> Deserialize<'de> for RequiredNullable<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Value::deserialize(deserializer)?;
        let value = if raw.is_null() {
            None
        } else {
            Some(serde_json::from_value(raw).map_err(D::Error::custom)?)
        };
        Ok(Self {
            present: true,
            value,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolDeclarationWire {
    name: String,
    description: String,
    input_schema: Value,
    output_schema: Value,
    side_effects: Vec<SideEffect>,
    #[serde(default)]
    auth_method_id: RequiredNullable<String>,
    #[serde(default)]
    credential_class: RequiredNullable<String>,
    network_origins: Vec<String>,
}

impl<'de> Deserialize<'de> for ToolDeclaration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ToolDeclarationWire::deserialize(deserializer)?;
        if !wire.auth_method_id.present {
            return Err(D::Error::custom("missing field auth_method_id"));
        }
        if !wire.credential_class.present {
            return Err(D::Error::custom("missing field credential_class"));
        }
        Ok(Self {
            name: wire.name,
            description: wire.description,
            input_schema: wire.input_schema,
            output_schema: wire.output_schema,
            side_effects: wire.side_effects,
            auth_method_id: wire.auth_method_id.value,
            credential_class: wire.credential_class.value,
            network_origins: wire.network_origins,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffect {
    None,
    NetworkRead,
    NetworkWrite,
    LocalWrite,
}

impl Manifest {
    pub fn validate(&self) -> ValidationResult<()> {
        self.validate_common()?;
        let publisher = self.publisher.as_ref().ok_or_else(|| {
            ValidationError::new("publisher", "signed provider manifests require a publisher")
        })?;
        validate_text(&publisher.name, "publisher.name", MAX_STRING_BYTES)?;
        validate_hex(&publisher.fingerprint, 32, "publisher.fingerprint")?;
        Ok(())
    }

    /// Validate the neutral provider contract used by resolver-owned source
    /// manifests. Source authority has no publisher or detached signature.
    pub fn validate_source(&self) -> ValidationResult<()> {
        self.validate_common()
    }

    fn validate_common(&self) -> ValidationResult<()> {
        if self.format != ABI_FORMAT {
            return Err(ValidationError::new("format", "unsupported provider ABI"));
        }
        validate_identifier(&self.provider_id, "provider_id", 64)?;
        validate_text(&self.display_name, "display_name", MAX_STRING_BYTES)?;
        validate_version(&self.version)?;
        self.package.validate()?;

        if self.auth_methods.is_empty() || self.auth_methods.len() > MAX_AUTH_METHODS {
            return Err(ValidationError::new(
                "auth_methods",
                "must contain 1..=8 declarations",
            ));
        }
        let mut auth_ids = BTreeSet::new();
        let mut credential_auth_ids = BTreeMap::new();
        for (index, auth) in self.auth_methods.iter().enumerate() {
            let path = format!("auth_methods[{index}]");
            if !auth_ids.insert(auth.id().to_owned()) {
                return Err(ValidationError::new(
                    path,
                    "duplicate authentication method id",
                ));
            }
            if credential_auth_ids
                .insert(auth.credential_class().to_owned(), auth.id().to_owned())
                .is_some()
            {
                return Err(ValidationError::new(
                    format!("{path}.credential_class"),
                    "each credential class must map to exactly one authentication method",
                ));
            }
            validate_identifier(auth.id(), &format!("{path}.id"), 64)?;
            validate_identifier(
                auth.credential_class(),
                &format!("{path}.credential_class"),
                64,
            )?;
            match auth {
                AuthMethod::ApiKey(value) => {
                    validate_text(&value.label, &format!("{path}.label"), MAX_STRING_BYTES)?;
                }
                AuthMethod::OauthAuthorizationCodePkce(value) => {
                    validate_text(&value.label, &format!("{path}.label"), MAX_STRING_BYTES)?;
                    validate_text(
                        &value.client_id,
                        &format!("{path}.client_id"),
                        MAX_STRING_BYTES,
                    )?;
                    if value.client_type != "public" {
                        return Err(ValidationError::new(
                            format!("{path}.client_type"),
                            "v1 permits public clients only",
                        ));
                    }
                    if value.grant_type != "authorization_code" {
                        return Err(ValidationError::new(
                            format!("{path}.grant_type"),
                            "v1 permits authorization_code only",
                        ));
                    }
                    if value.pkce_method != "S256" {
                        return Err(ValidationError::new(
                            format!("{path}.pkce_method"),
                            "v1 requires PKCE S256",
                        ));
                    }
                    if value.callback != CallbackPolicy::HostManaged {
                        return Err(ValidationError::new(
                            format!("{path}.callback"),
                            "only host-managed callbacks are permitted",
                        ));
                    }
                    validate_urls(
                        &[
                            value.authorization_endpoint.clone(),
                            value.token_endpoint.clone(),
                        ],
                        &format!("{path}.endpoints"),
                    )?;
                    validate_origins(&value.approved_origins, &format!("{path}.approved_origins"))?;
                    for endpoint in [&value.authorization_endpoint, &value.token_endpoint] {
                        let parsed = parse_https_url(endpoint, &format!("{path}.endpoints"))?;
                        let origin = canonical_origin(&parsed, &format!("{path}.endpoints"))?;
                        if !value
                            .approved_origins
                            .iter()
                            .any(|approved| approved == &origin)
                        {
                            return Err(ValidationError::new(
                                format!("{path}.endpoints"),
                                "endpoint origin is not explicitly approved",
                            ));
                        }
                    }
                    validate_scopes(&value.scopes, &format!("{path}.scopes"))?;
                }
            }
            if !self
                .capabilities
                .auth_method_ids
                .contains(&auth.id().to_owned())
            {
                return Err(ValidationError::new(
                    format!("{path}.id"),
                    "authentication method is not capability-approved",
                ));
            }
            if !self
                .capabilities
                .credential_classes
                .contains(&auth.credential_class().to_owned())
            {
                return Err(ValidationError::new(
                    format!("{path}.credential_class"),
                    "credential class is not capability-approved",
                ));
            }
        }
        validate_identifiers(
            &self.capabilities.auth_method_ids,
            "capabilities.auth_method_ids",
            64,
        )?;
        if self.capabilities.auth_method_ids.len() != auth_ids.len()
            || self
                .capabilities
                .auth_method_ids
                .iter()
                .any(|id| !auth_ids.contains(id))
        {
            return Err(ValidationError::new(
                "capabilities.auth_method_ids",
                "must equal the declared authentication methods",
            ));
        }
        validate_identifiers(
            &self.capabilities.credential_classes,
            "capabilities.credential_classes",
            64,
        )?;
        let declared_credential_classes = credential_auth_ids.keys().collect::<BTreeSet<_>>();
        if self.capabilities.credential_classes.len() != declared_credential_classes.len()
            || self
                .capabilities
                .credential_classes
                .iter()
                .any(|class| !declared_credential_classes.contains(class))
        {
            return Err(ValidationError::new(
                "capabilities.credential_classes",
                "must equal the unique declared authentication credential classes",
            ));
        }
        validate_origins(
            &self.capabilities.network_origins,
            "capabilities.network_origins",
        )?;

        if self.tools.is_empty() || self.tools.len() > MAX_TOOLS {
            return Err(ValidationError::new(
                "tools",
                "must contain 1..=64 declarations",
            ));
        }
        let mut tool_names = BTreeSet::new();
        for (index, tool) in self.tools.iter().enumerate() {
            let path = format!("tools[{index}]");
            validate_identifier(&tool.name, &format!("{path}.name"), 64)?;
            if !tool_names.insert(tool.name.clone()) {
                return Err(ValidationError::new(path, "duplicate tool name"));
            }
            validate_text(
                &tool.description,
                &format!("{path}.description"),
                MAX_STRING_BYTES,
            )?;
            validate_local_schema(&tool.input_schema, &format!("{path}.input_schema"))?;
            if tool.input_schema.get("type").and_then(Value::as_str) != Some("object") {
                return Err(ValidationError::new(
                    format!("{path}.input_schema.type"),
                    "tool input schemas must describe JSON objects",
                ));
            }
            validate_local_schema(&tool.output_schema, &format!("{path}.output_schema"))?;
            if tool.side_effects.is_empty() || tool.side_effects.len() > MAX_LIST_ITEMS {
                return Err(ValidationError::new(
                    format!("{path}.side_effects"),
                    "must explicitly declare 1..=64 side effects",
                ));
            }
            let mut side_effects = BTreeSet::new();
            if tool
                .side_effects
                .iter()
                .any(|effect| !side_effects.insert(effect))
            {
                return Err(ValidationError::new(
                    format!("{path}.side_effects"),
                    "contains duplicate side effects",
                ));
            }
            match (&tool.auth_method_id, &tool.credential_class) {
                (Some(auth_method_id), Some(class)) => {
                    validate_identifier(auth_method_id, &format!("{path}.auth_method_id"), 64)?;
                    validate_identifier(class, &format!("{path}.credential_class"), 64)?;
                    let auth_method = self.auth_method(auth_method_id).ok_or_else(|| {
                        ValidationError::new(
                            format!("{path}.auth_method_id"),
                            "authentication method is not declared",
                        )
                    })?;
                    if auth_method.credential_class() != class {
                        return Err(ValidationError::new(
                            format!("{path}.credential_class"),
                            "credential class does not match the bound authentication method",
                        ));
                    }
                    if !self.capabilities.credential_classes.contains(class) {
                        return Err(ValidationError::new(
                            format!("{path}.credential_class"),
                            "credential class is not capability-approved",
                        ));
                    }
                }
                (None, None) => {}
                _ => {
                    return Err(ValidationError::new(
                        format!("{path}.credentials"),
                        "auth method and credential class must be present together",
                    ));
                }
            }
            validate_origins(&tool.network_origins, &format!("{path}.network_origins"))?;
            if tool
                .network_origins
                .iter()
                .any(|origin| !self.capabilities.network_origins.contains(origin))
            {
                return Err(ValidationError::new(
                    format!("{path}.network_origins"),
                    "origin is not capability-approved",
                ));
            }
        }
        Ok(())
    }

    pub fn tool(&self, name: &str) -> Option<&ToolDeclaration> {
        self.tools.iter().find(|tool| tool.name == name)
    }

    pub fn auth_method(&self, id: &str) -> Option<&AuthMethod> {
        self.auth_methods.iter().find(|method| method.id() == id)
    }

    pub fn auth_method_for_credential(&self, class: &str) -> Option<&AuthMethod> {
        self.auth_methods
            .iter()
            .find(|method| method.credential_class() == class)
    }

    pub fn tool_id(&self, archive_digest: &str, name: &str) -> Option<String> {
        self.tool(name)
            .map(|_| derive_tool_id(archive_digest, &self.provider_id, name))
    }
}

impl ManifestPackage {
    pub fn validate(&self) -> ValidationResult<()> {
        if self.files.is_empty() || self.files.len() > MAX_FILE_TABLE_ENTRIES {
            return Err(ValidationError::new(
                "package.files",
                "must contain 1..=128 entries",
            ));
        }
        validate_path(&self.executable.path, "package.executable.path")?;
        validate_hex(&self.executable.sha256, 32, "package.executable.sha256")?;
        let mut paths = BTreeSet::new();
        let mut total = 0_u64;
        let mut executable_found = false;
        for (index, file) in self.files.iter().enumerate() {
            let path = format!("package.files[{index}]");
            validate_path(&file.path, &format!("{path}.path"))?;
            if file.path.eq_ignore_ascii_case("manifest.json")
                || file.path.eq_ignore_ascii_case("signature.json")
            {
                return Err(ValidationError::new(
                    format!("{path}.path"),
                    "archive-reserved metadata path",
                ));
            }
            validate_hex(&file.sha256, 32, &format!("{path}.sha256"))?;
            if file.size > MAX_FILE_SIZE_BYTES {
                return Err(ValidationError::new(
                    format!("{path}.size"),
                    "file is oversized",
                ));
            }
            total = total
                .checked_add(file.size)
                .ok_or_else(|| ValidationError::new("package.files", "file sizes overflow"))?;
            if !paths.insert(file.path.to_ascii_lowercase()) {
                return Err(ValidationError::new(path, "duplicate file path"));
            }
            if file.path == self.executable.path {
                executable_found = true;
                if file.sha256 != self.executable.sha256 {
                    return Err(ValidationError::new(
                        "package.executable.sha256",
                        "executable hash does not match its file-table entry",
                    ));
                }
            }
        }
        if !executable_found || total > MAX_FILE_SIZE_BYTES.saturating_mul(4) {
            return Err(ValidationError::new(
                "package.files",
                "executable is absent or package payload is oversized",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_archive_files(&self, files: &[ArchiveFile]) -> ValidationResult<()> {
        self.validate()?;
        if files.len() != self.files.len() {
            return Err(ValidationError::new(
                "archive.files",
                "archive file table does not match manifest",
            ));
        }
        let mut supplied = BTreeSet::new();
        for file in files {
            let digest = sha256_hex(&file.bytes);
            let declared = self
                .files
                .iter()
                .find(|declared| declared.path == file.path)
                .ok_or_else(|| ValidationError::new("archive.files", "undeclared archive file"))?;
            if !supplied.insert(file.path.clone())
                || file.bytes.len() as u64 != declared.size
                || digest != declared.sha256
            {
                return Err(ValidationError::new(
                    "archive.files",
                    "archive file size or hash mismatch",
                ));
            }
        }
        Ok(())
    }
}

pub fn derive_tool_id(archive_digest: &str, provider_id: &str, tool_name: &str) -> String {
    format!("{ABI_FORMAT}/tool/{archive_digest}/{provider_id}/{tool_name}")
}

pub fn host_tool_id(archive_digest: &str, provider_id: &str, tool_name: &str) -> String {
    derive_tool_id(archive_digest, provider_id, tool_name)
}

fn validate_identifier(value: &str, field: &str, max: usize) -> ValidationResult<()> {
    if value.is_empty()
        || value.len() > max
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        || (!value.as_bytes()[0].is_ascii_lowercase() && !value.as_bytes()[0].is_ascii_digit())
    {
        return Err(ValidationError::new(
            field,
            "must contain bounded lowercase ASCII identifier bytes",
        ));
    }
    Ok(())
}

fn validate_identifiers(values: &[String], field: &str, max: usize) -> ValidationResult<()> {
    if values.is_empty() || values.len() > MAX_LIST_ITEMS {
        return Err(ValidationError::new(field, "must contain 1..=64 values"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_identifier(value, field, max)?;
        if !seen.insert(value) {
            return Err(ValidationError::new(field, "contains duplicate values"));
        }
    }
    Ok(())
}

fn validate_text(value: &str, field: &str, max: usize) -> ValidationResult<()> {
    if value.is_empty() || value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(ValidationError::new(
            field,
            "contains empty, oversized, or control text",
        ));
    }
    Ok(())
}

fn validate_version(value: &str) -> ValidationResult<()> {
    let pieces: Vec<_> = value.split('.').collect();
    if pieces.len() != 3
        || pieces.iter().any(|piece| {
            piece.is_empty()
                || !piece.bytes().all(|byte| byte.is_ascii_digit())
                || piece.parse::<u64>().is_err()
        })
    {
        return Err(ValidationError::new(
            "version",
            "must be a numeric major.minor.patch version",
        ));
    }
    Ok(())
}

fn validate_hex(value: &str, bytes: usize, field: &str) -> ValidationResult<()> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ValidationError::new(
            field,
            "must be lower-case hexadecimal bytes",
        ));
    }
    Ok(())
}

pub(crate) fn validate_path(value: &str, field: &str) -> ValidationResult<()> {
    if value.is_empty()
        || value.len() > MAX_FILE_PATH_BYTES
        || !value.is_ascii()
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains(':')
        || value
            .bytes()
            .any(|byte| !(b'!'..=b'~').contains(&byte) || b"<>\"|?*".contains(&byte))
        || value.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.ends_with('.')
                || windows_reserved_component(part)
        })
    {
        return Err(ValidationError::new(
            field,
            "must be a safe relative package path",
        ));
    }
    Ok(())
}

fn windows_reserved_component(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _)| stem)
        .to_ascii_lowercase();
    matches!(
        stem.as_str(),
        "con" | "conin$" | "conout$" | "prn" | "aux" | "nul" | "clock$"
    ) || (stem.len() == 4
        && (stem.starts_with("com") || stem.starts_with("lpt"))
        && stem.as_bytes()[3].is_ascii_digit()
        && stem.as_bytes()[3] != b'0')
}

fn validate_scopes(values: &[String], field: &str) -> ValidationResult<()> {
    if values.is_empty() || values.len() > MAX_LIST_ITEMS {
        return Err(ValidationError::new(field, "must contain 1..=64 scopes"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_text(value, field, 128)?;
        if !seen.insert(value) {
            return Err(ValidationError::new(field, "contains duplicate scopes"));
        }
    }
    Ok(())
}

fn validate_urls(values: &[String], field: &str) -> ValidationResult<()> {
    if values.len() > MAX_LIST_ITEMS {
        return Err(ValidationError::new(field, "contains too many URLs"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_text(value, field, 2_048)?;
        let url = parse_https_url(value, field)?;
        if !seen.insert(value) {
            return Err(ValidationError::new(
                field,
                "URL contains invalid or duplicate text",
            ));
        }
        let _ = canonical_origin(&url, field)?;
    }
    Ok(())
}

fn validate_origins(values: &[String], field: &str) -> ValidationResult<()> {
    validate_urls(values, field)?;
    for value in values {
        let parsed = parse_https_url(value, field)?;
        if !parsed.path().is_empty() && parsed.path() != "/" {
            return Err(ValidationError::new(
                field,
                "origin declarations may not contain a path",
            ));
        }
        if canonical_origin(&parsed, field)? != *value {
            return Err(ValidationError::new(field, "origin is not canonical"));
        }
    }
    Ok(())
}

fn parse_https_url(value: &str, field: &str) -> ValidationResult<Url> {
    let authority = value
        .strip_prefix("https://")
        .unwrap_or_default()
        .split('/')
        .next()
        .unwrap_or_default();
    let raw_host = if authority.starts_with('[') {
        authority.split_once(']').map(|(host, _)| host)
    } else {
        authority.split(':').next()
    }
    .unwrap_or_default();
    if authority.contains('%') || authority.contains('\\') {
        return Err(ValidationError::new(
            field,
            "URL authority must not contain encoded or backslash-normalized text",
        ));
    }
    if raw_host.is_empty() || raw_host != raw_host.to_ascii_lowercase() {
        return Err(ValidationError::new(
            field,
            "URL host is not canonical lowercase",
        ));
    }
    let explicit_port = if authority.starts_with('[') {
        authority
            .split_once(']')
            .and_then(|(_, rest)| rest.strip_prefix(':'))
    } else {
        authority.rsplit_once(':').map(|(_, port)| port)
    };
    if explicit_port.is_some_and(|port| {
        port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || (port.len() > 1 && port.starts_with('0'))
            || port.parse::<u16>().is_err()
            || port == "0"
    }) {
        return Err(ValidationError::new(
            field,
            "URL port must be a canonical non-zero decimal number",
        ));
    }
    if explicit_port == Some("443") {
        return Err(ValidationError::new(
            field,
            "explicit default HTTPS port is not canonical",
        ));
    }
    let url = Url::parse(value)
        .map_err(|_| ValidationError::new(field, "URL is not valid canonical syntax"))?;
    if !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || !value.starts_with("https://")
        || url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port() == Some(443)
    {
        return Err(ValidationError::new(
            field,
            "only literal HTTPS URLs without credentials/query/fragment are permitted",
        ));
    }
    if let Some(path) = value
        .strip_prefix("https://")
        .and_then(|rest| rest.split_once('/'))
        .map(|(_, path)| path)
    {
        if !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~!$&'()*+,;=:@%/-".contains(&byte))
        {
            return Err(ValidationError::new(
                field,
                "URL path contains non-canonical text",
            ));
        }
    }
    match url.host() {
        Some(Host::Domain(domain)) => {
            if domain.is_empty()
                || (is_whatwg_numeric_host(domain) && !is_canonical_ipv4_host(domain))
                || domain != domain.to_ascii_lowercase()
                || domain.split('.').any(|label| {
                    label.is_empty()
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                        })
                })
            {
                return Err(ValidationError::new(field, "URL host is not canonical"));
            }
        }
        Some(Host::Ipv4(address)) => {
            if raw_host != address.to_string() {
                return Err(ValidationError::new(
                    field,
                    "URL IPv4 host is not canonical",
                ));
            }
        }
        Some(Host::Ipv6(_)) if raw_host.contains('.') => {
            return Err(ValidationError::new(
                field,
                "URL IPv6 host must use hexadecimal notation",
            ));
        }
        Some(Host::Ipv6(_)) => {}
        None => return Err(ValidationError::new(field, "URL has no host")),
    }
    Ok(url)
}

fn is_whatwg_numeric_component(component: &str) -> bool {
    component.strip_prefix("0x").map_or_else(
        || !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit()),
        |hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
    )
}

fn is_whatwg_numeric_host(host: &str) -> bool {
    !host.is_empty() && host.split('.').all(is_whatwg_numeric_component)
}

fn is_canonical_ipv4_host(host: &str) -> bool {
    let components = host.split('.').collect::<Vec<_>>();
    components.len() == 4
        && components.iter().all(|component| {
            !component.is_empty()
                && (component.len() == 1 || !component.starts_with('0'))
                && component.parse::<u8>().is_ok()
        })
}

fn canonical_origin(url: &Url, field: &str) -> ValidationResult<String> {
    let host = url
        .host()
        .ok_or_else(|| ValidationError::new(field, "URL has no host"))?;
    let host_text = url.host_str().unwrap_or_default();
    if host_text != host_text.to_ascii_lowercase() {
        return Err(ValidationError::new(
            field,
            "URL host is not canonical lowercase",
        ));
    }
    let host_text = match host {
        Host::Domain(domain) => domain.to_owned(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    let mut origin = format!("https://{host_text}");
    if let Some(port) = url.port() {
        if port == 443 {
            return Err(ValidationError::new(
                field,
                "explicit default HTTPS port is not canonical",
            ));
        }
        origin.push_str(&format!(":{port}"));
    }
    Ok(origin)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_paths_are_confined_across_posix_and_windows_forms() {
        for path in [
            "../provider",
            "dir/../provider",
            "/tmp/provider",
            "//server/share/provider",
            "\\\\server\\share\\provider",
            "C:provider",
            "C:/provider",
            "provider:stream",
            "provider::$DATA",
            "dir\\provider",
            "provider?name",
            "provider*name",
            "CON",
            "CONIN$",
            "CONOUT$.txt",
            "nul.txt",
            "clock$",
            "COM1.log",
            "LPT9",
            "name.",
            "name ",
        ] {
            assert!(
                validate_path(path, "path").is_err(),
                "accepted unsafe path: {path}"
            );
        }
        assert!(validate_path("bin/provider", "path").is_ok());
        assert!(validate_path("dir/provider.exe", "path").is_ok());

        let hash = "a".repeat(64);
        let package = ManifestPackage {
            files: vec![
                PackageFile {
                    path: "bin/provider".to_owned(),
                    size: 1,
                    sha256: hash.clone(),
                },
                PackageFile {
                    path: "BIN/PROVIDER".to_owned(),
                    size: 1,
                    sha256: hash.clone(),
                },
            ],
            executable: ExecutableEntrypoint {
                path: "bin/provider".to_owned(),
                sha256: hash,
            },
        };
        assert!(package.validate().is_err());
    }

    #[test]
    fn oauth_urls_match_canonical_ascii_https_semantics() {
        for url in [
            "http://example.com/auth",
            "https://EXAMPLE.com/auth",
            "https://user@example.com/auth",
            "https://example.com/auth?code=1",
            "https://example.com:443/auth",
            "https://example.com/auth^bad",
            "https://example.com/auth with-space",
            "https://999.999.999.999/auth",
            "https://01.2.3.4/auth",
        ] {
            assert!(
                parse_https_url(url, "url").is_err(),
                "accepted invalid URL: {url}"
            );
        }
        assert!(parse_https_url("https://example.com:8443/auth", "url").is_ok());
        assert!(parse_https_url("https://[::1]/auth", "url").is_ok());
    }

    #[test]
    fn shared_provider_url_fixtures_match_rust_host_validation() {
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v1/provider-parity-fixtures.json"
        ))
        .unwrap();
        for fixture in fixtures["oauth_urls"].as_array().unwrap() {
            let valid = parse_https_url(fixture["url"].as_str().unwrap(), "url").is_ok()
                && (fixture["allow_path"].as_bool().unwrap()
                    || fixture["url"].as_str().unwrap().split('/').count() == 3);
            assert_eq!(
                valid,
                fixture["valid"].as_bool().unwrap(),
                "{}",
                fixture["url"]
            );
        }
    }

    #[test]
    fn required_nullable_manifest_fields_must_be_explicit() {
        let base: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v1/examples/manifest.json"
        ))
        .unwrap();
        for field in ["auth_method_id", "credential_class"] {
            let mut missing = base.clone();
            missing["tools"][0].as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<Manifest>(missing).is_err(),
                "{field}"
            );

            let mut explicit_null = base.clone();
            explicit_null["tools"][0][field] = Value::Null;
            assert!(
                serde_json::from_value::<Manifest>(explicit_null).is_ok(),
                "{field}"
            );
        }
    }

    #[test]
    fn shared_reserved_archive_paths_are_case_insensitive() {
        let base: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v1/examples/manifest.json"
        ))
        .unwrap();
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v1/provider-parity-fixtures.json"
        ))
        .unwrap();
        for reserved in fixtures["reserved_archive_paths"].as_array().unwrap() {
            let mut value = base.clone();
            let path = reserved.as_str().unwrap();
            value["package"]["files"][0]["path"] = Value::String(path.to_owned());
            value["package"]["executable"]["path"] = Value::String(path.to_owned());
            let manifest: Manifest = serde_json::from_value(value).unwrap();
            assert!(
                manifest.validate().is_err(),
                "accepted reserved path: {path}"
            );
        }
    }

    #[test]
    fn shared_version_u64_bounds_match_rust_validation() {
        let base: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v1/examples/manifest.json"
        ))
        .unwrap();
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v1/provider-parity-fixtures.json"
        ))
        .unwrap();
        for fixture in fixtures["numeric_bounds"].as_array().unwrap() {
            if fixture["kind"] != "version" {
                continue;
            }
            let mut value = base.clone();
            value["version"] = fixture["value"].clone();
            let valid = serde_json::from_value::<Manifest>(value)
                .map(|manifest| manifest.validate().is_ok())
                .unwrap_or(false);
            assert_eq!(
                valid,
                fixture["valid"].as_bool().unwrap(),
                "{}",
                fixture["value"]
            );
        }
    }

    #[test]
    fn bounded_text_uses_schema_character_limits() {
        let text = "é".repeat(MAX_STRING_BYTES);
        assert!(validate_text(&text, "text", MAX_STRING_BYTES).is_ok());
        assert!(validate_text(&format!("{text}é"), "text", MAX_STRING_BYTES).is_err());
    }
}
