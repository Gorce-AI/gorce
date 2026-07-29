//! Representation-only `gorce.provider/v2` ABI types.
//!
//! V2 is deliberately a separate namespace.  In particular, this module does
//! not call the V1 tool-ID, version, manifest, or RPC validators.  It describes
//! the closed authentication binding needed by the later provider-runtime
//! work; it does not grant execution, installation, source, or credential
//! authority.

use std::collections::BTreeSet;
use std::fmt;

use serde::{
    de::DeserializeOwned, de::Error as DeError, ser::SerializeStruct, Deserialize, Deserializer,
    Serialize, Serializer,
};
use serde_json::Value;

use crate::validation::{
    validate_json_value, validate_local_schema, ValidationError, ValidationResult,
};

/// The independent V2 package and RPC version string.
pub const ABI_FORMAT: &str = "gorce.provider/v2";
/// Alias used by callers that refer to the negotiated provider version.
pub const PROVIDER_ABI_VERSION: &str = ABI_FORMAT;
pub const V2_ABI_FORMAT: &str = ABI_FORMAT;

pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_TOOLS: usize = 64;
pub const MAX_AUTH_METHODS: usize = 8;
pub const MAX_FILE_TABLE_ENTRIES: usize = 128;
pub const MAX_FILE_PATH_BYTES: usize = 256;
pub const MAX_FILE_SIZE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_STRING_BYTES: usize = 512;
pub const MAX_LIST_ITEMS: usize = 64;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_JSON_DEPTH: usize = 16;
pub const MAX_JSON_MEMBERS: usize = 256;
pub const MAX_ID_BYTES: usize = 64;
pub const MAX_TOOL_ID_BYTES: usize = 256;
pub const MAX_TIMEOUT_MS: u64 = 120_000;
pub const MAX_SECRET_BYTES: usize = 4096;

pub const METHOD_INITIALIZE: &str = "gorce.initialize";
pub const METHOD_TOOL_INVOKE: &str = "tool.invoke";
pub const METHOD_CONNECTION_DIAGNOSTIC: &str = "connection_diagnostic";

/// The only policies that can occur in an official-CLI V2 binding.
pub const OFFICIAL_CLI_CODEX_POLICY_ID: &str = "gorce.official-cli/codex/v1";
pub const OFFICIAL_CLI_CLAUDE_CODE_POLICY_ID: &str = "gorce.official-cli/claude-code/v1";
pub const CODEX_POLICY_ID: &str = OFFICIAL_CLI_CODEX_POLICY_ID;
pub const CLAUDE_CODE_POLICY_ID: &str = OFFICIAL_CLI_CLAUDE_CODE_POLICY_ID;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcCodecError(pub String);

impl fmt::Display for RpcCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RpcCodecError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(pub String);

impl RequestId {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_bounded_id(&value, "id", MAX_ID_BYTES)?;
        Ok(Self(value))
    }

    pub fn validate(&self) -> ValidationResult<()> {
        validate_bounded_id(&self.0, "id", MAX_ID_BYTES)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryKind {
    ApiKey,
    AccessToken,
}

/// The closed policy identifier used by `official_cli_session`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum OfficialCliPolicyId {
    #[serde(rename = "gorce.official-cli/codex/v1")]
    Codex,
    #[serde(rename = "gorce.official-cli/claude-code/v1")]
    ClaudeCode,
}

impl OfficialCliPolicyId {
    pub const CODEX: Self = Self::Codex;
    pub const CLAUDE_CODE: Self = Self::ClaudeCode;

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => OFFICIAL_CLI_CODEX_POLICY_ID,
            Self::ClaudeCode => OFFICIAL_CLI_CLAUDE_CODE_POLICY_ID,
        }
    }
}

impl fmt::Display for OfficialCliPolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str((*self).as_str())
    }
}

/// A required, strict tagged authentication binding used on every V2 tool
/// declaration, runtime descriptor, and authorized invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthenticationBinding {
    None,
    HostSecret {
        auth_method_id: String,
        credential_class: String,
        delivery_kind: DeliveryKind,
    },
    OfficialCliSession {
        policy_id: OfficialCliPolicyId,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoneAuthenticationWire {
    kind: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostSecretAuthenticationWire {
    kind: String,
    auth_method_id: String,
    credential_class: String,
    delivery_kind: DeliveryKind,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OfficialCliAuthenticationWire {
    kind: String,
    policy_id: OfficialCliPolicyId,
}

impl<'de> Deserialize<'de> for AuthenticationBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Value::deserialize(deserializer)?;
        let kind = raw
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| D::Error::custom("authentication.kind is required"))?;
        match kind {
            "none" => {
                let wire: NoneAuthenticationWire =
                    serde_json::from_value(raw).map_err(D::Error::custom)?;
                if wire.kind != "none" {
                    return Err(D::Error::custom("authentication.kind is invalid"));
                }
                Ok(Self::None)
            }
            "host_secret" => {
                let wire: HostSecretAuthenticationWire =
                    serde_json::from_value(raw).map_err(D::Error::custom)?;
                if wire.kind != "host_secret" {
                    return Err(D::Error::custom("authentication.kind is invalid"));
                }
                Ok(Self::HostSecret {
                    auth_method_id: wire.auth_method_id,
                    credential_class: wire.credential_class,
                    delivery_kind: wire.delivery_kind,
                })
            }
            "official_cli_session" => {
                let wire: OfficialCliAuthenticationWire =
                    serde_json::from_value(raw).map_err(D::Error::custom)?;
                if wire.kind != "official_cli_session" {
                    return Err(D::Error::custom("authentication.kind is invalid"));
                }
                Ok(Self::OfficialCliSession {
                    policy_id: wire.policy_id,
                })
            }
            _ => Err(D::Error::custom("authentication.kind is not supported")),
        }
    }
}

impl AuthenticationBinding {
    pub fn validate(&self, field: &str) -> ValidationResult<()> {
        match self {
            Self::None => Ok(()),
            Self::HostSecret {
                auth_method_id,
                credential_class,
                ..
            } => {
                validate_identifier(auth_method_id, &format!("{field}.auth_method_id"), 64)?;
                validate_identifier(credential_class, &format!("{field}.credential_class"), 64)
            }
            Self::OfficialCliSession { .. } => Ok(()),
        }
    }

    pub fn host_secret(
        auth_method_id: impl Into<String>,
        credential_class: impl Into<String>,
        delivery_kind: DeliveryKind,
    ) -> Self {
        Self::HostSecret {
            auth_method_id: auth_method_id.into(),
            credential_class: credential_class.into(),
            delivery_kind,
        }
    }

    pub fn official_cli_session(policy_id: OfficialCliPolicyId) -> Self {
        Self::OfficialCliSession { policy_id }
    }

    pub fn auth_method_id(&self) -> Option<&str> {
        match self {
            Self::HostSecret { auth_method_id, .. } => Some(auth_method_id),
            Self::None | Self::OfficialCliSession { .. } => None,
        }
    }

    pub fn credential_class(&self) -> Option<&str> {
        match self {
            Self::HostSecret {
                credential_class, ..
            } => Some(credential_class),
            Self::None | Self::OfficialCliSession { .. } => None,
        }
    }

    pub fn delivery_kind(&self) -> Option<DeliveryKind> {
        match self {
            Self::HostSecret { delivery_kind, .. } => Some(*delivery_kind),
            Self::None | Self::OfficialCliSession { .. } => None,
        }
    }

    pub fn policy_id(&self) -> Option<OfficialCliPolicyId> {
        match self {
            Self::OfficialCliSession { policy_id } => Some(*policy_id),
            Self::None | Self::HostSecret { .. } => None,
        }
    }

    pub fn is_host_secret(&self) -> bool {
        matches!(self, Self::HostSecret { .. })
    }
}

/// V2 auth methods are host-secret declarations only.  The `kind` tag belongs
/// to `AuthenticationBinding`, not to this declaration: `delivery_kind` is the
/// method's fixed, capability-bound delivery form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthMethod {
    pub id: String,
    pub credential_class: String,
    pub label: String,
    pub delivery_kind: DeliveryKind,
}

pub type HostSecretAuthMethod = AuthMethod;

impl AuthMethod {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn credential_class(&self) -> &str {
        &self.credential_class
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePublisher {
    pub name: String,
    pub fingerprint: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPackage {
    pub files: Vec<PackageFile>,
    pub executable: ExecutableEntrypoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub auth_method_ids: Vec<String>,
    pub credential_classes: Vec<String>,
    pub network_origins: Vec<String>,
    pub official_cli_policy_ids: Vec<OfficialCliPolicyId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDeclaration {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub side_effects: Vec<SideEffect>,
    pub authentication: AuthenticationBinding,
    pub network_origins: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffect {
    None,
    NetworkRead,
    NetworkWrite,
    LocalWrite,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub provider_id: String,
    pub display_name: String,
    pub version: String,
    pub publisher: PackagePublisher,
    pub package: ManifestPackage,
    pub auth_methods: Vec<AuthMethod>,
    pub capabilities: Capabilities,
    pub tools: Vec<ToolDeclaration>,
}

impl Manifest {
    pub fn validate(&self) -> ValidationResult<()> {
        if self.format != ABI_FORMAT {
            return Err(ValidationError::new("format", "unsupported provider ABI"));
        }
        validate_identifier(&self.provider_id, "provider_id", 64)?;
        validate_text(&self.display_name, "display_name", MAX_STRING_BYTES)?;
        validate_version(&self.version)?;
        validate_text(&self.publisher.name, "publisher.name", MAX_STRING_BYTES)?;
        validate_hex(&self.publisher.fingerprint, 32, "publisher.fingerprint")?;
        self.package.validate()?;

        if self.auth_methods.len() > MAX_AUTH_METHODS {
            return Err(ValidationError::new(
                "auth_methods",
                "must contain 0..=8 declarations",
            ));
        }
        let mut auth_ids = BTreeSet::new();
        let mut classes = BTreeSet::new();
        for (index, method) in self.auth_methods.iter().enumerate() {
            let field = format!("auth_methods[{index}]");
            validate_identifier(&method.id, &format!("{field}.id"), 64)?;
            validate_identifier(
                &method.credential_class,
                &format!("{field}.credential_class"),
                64,
            )?;
            validate_text(&method.label, &format!("{field}.label"), MAX_STRING_BYTES)?;
            if !auth_ids.insert(method.id.clone()) {
                return Err(ValidationError::new(
                    field,
                    "duplicate authentication method id",
                ));
            }
            if !classes.insert(method.credential_class.clone()) {
                return Err(ValidationError::new(
                    format!("{field}.credential_class"),
                    "each credential class must map to exactly one authentication method",
                ));
            }
        }

        validate_set_identifiers(
            &self.capabilities.auth_method_ids,
            "capabilities.auth_method_ids",
            MAX_AUTH_METHODS,
        )?;
        validate_set_identifiers(
            &self.capabilities.credential_classes,
            "capabilities.credential_classes",
            MAX_AUTH_METHODS,
        )?;
        if !same_set(&auth_ids, &self.capabilities.auth_method_ids)
            || !same_set(&classes, &self.capabilities.credential_classes)
        {
            return Err(ValidationError::new(
                "capabilities",
                "auth method and credential capability sets must equal declarations",
            ));
        }
        validate_origins(
            &self.capabilities.network_origins,
            "capabilities.network_origins",
        )?;
        validate_policy_set(
            &self.capabilities.official_cli_policy_ids,
            "capabilities.official_cli_policy_ids",
        )?;

        if self.tools.is_empty() || self.tools.len() > MAX_TOOLS {
            return Err(ValidationError::new(
                "tools",
                "must contain 1..=64 declarations",
            ));
        }
        let mut names = BTreeSet::new();
        let mut used_policies = BTreeSet::new();
        for (index, tool) in self.tools.iter().enumerate() {
            let field = format!("tools[{index}]");
            validate_identifier(&tool.name, &format!("{field}.name"), 64)?;
            if !names.insert(tool.name.clone()) {
                return Err(ValidationError::new(field, "duplicate tool name"));
            }
            validate_text(
                &tool.description,
                &format!("{field}.description"),
                MAX_STRING_BYTES,
            )?;
            validate_local_schema(&tool.input_schema, &format!("{field}.input_schema"))?;
            if tool.input_schema.get("type").and_then(Value::as_str) != Some("object") {
                return Err(ValidationError::new(
                    format!("{field}.input_schema.type"),
                    "tool input schemas must describe JSON objects",
                ));
            }
            validate_local_schema(&tool.output_schema, &format!("{field}.output_schema"))?;
            validate_side_effects(&tool.side_effects, &format!("{field}.side_effects"))?;
            tool.authentication
                .validate(&format!("{field}.authentication"))?;
            match &tool.authentication {
                AuthenticationBinding::None => {}
                AuthenticationBinding::HostSecret {
                    auth_method_id,
                    credential_class,
                    delivery_kind,
                } => {
                    let method = self.auth_method(auth_method_id).ok_or_else(|| {
                        ValidationError::new(
                            format!("{field}.authentication.auth_method_id"),
                            "authentication method is not declared",
                        )
                    })?;
                    if method.credential_class != *credential_class
                        || method.delivery_kind != *delivery_kind
                    {
                        return Err(ValidationError::new(
                            format!("{field}.authentication"),
                            "host-secret binding does not equal its declared method",
                        ));
                    }
                }
                AuthenticationBinding::OfficialCliSession { policy_id } => {
                    used_policies.insert(*policy_id);
                    if !self
                        .capabilities
                        .official_cli_policy_ids
                        .contains(policy_id)
                    {
                        return Err(ValidationError::new(
                            format!("{field}.authentication.policy_id"),
                            "official CLI policy is not capability-approved",
                        ));
                    }
                }
            }
            validate_origins(&tool.network_origins, &format!("{field}.network_origins"))?;
            if tool
                .network_origins
                .iter()
                .any(|origin| !self.capabilities.network_origins.contains(origin))
            {
                return Err(ValidationError::new(
                    format!("{field}.network_origins"),
                    "origin is not capability-approved",
                ));
            }
        }
        if !same_policy_set(&used_policies, &self.capabilities.official_cli_policy_ids) {
            return Err(ValidationError::new(
                "capabilities.official_cli_policy_ids",
                "must equal the unique official CLI policies used by tools",
            ));
        }
        Ok(())
    }

    pub fn tool(&self, name: &str) -> Option<&ToolDeclaration> {
        self.tools.iter().find(|tool| tool.name == name)
    }

    pub fn auth_method(&self, id: &str) -> Option<&AuthMethod> {
        self.auth_methods.iter().find(|method| method.id == id)
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
        validate_package_path(&self.executable.path, "package.executable.path")?;
        validate_hex(&self.executable.sha256, 32, "package.executable.sha256")?;
        let mut paths = BTreeSet::new();
        let mut total = 0_u64;
        let mut executable_found = false;
        for (index, file) in self.files.iter().enumerate() {
            let field = format!("package.files[{index}]");
            validate_package_path(&file.path, &format!("{field}.path"))?;
            if file.path.eq_ignore_ascii_case("manifest.json")
                || file.path.eq_ignore_ascii_case("signature.json")
            {
                return Err(ValidationError::new(
                    format!("{field}.path"),
                    "archive-reserved metadata path",
                ));
            }
            validate_hex(&file.sha256, 32, &format!("{field}.sha256"))?;
            if file.size > MAX_FILE_SIZE_BYTES {
                return Err(ValidationError::new(
                    format!("{field}.size"),
                    "file is oversized",
                ));
            }
            total = total
                .checked_add(file.size)
                .ok_or_else(|| ValidationError::new("package.files", "file sizes overflow"))?;
            if !paths.insert(file.path.to_ascii_lowercase()) {
                return Err(ValidationError::new(field, "duplicate file path"));
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
}

/// V2 tool IDs are not accepted by V1 because the ABI prefix is independently
/// derived and checked.
pub fn derive_tool_id(archive_digest: &str, provider_id: &str, tool_name: &str) -> String {
    format!("{ABI_FORMAT}/tool/{archive_digest}/{provider_id}/{tool_name}")
}

pub fn host_tool_id(archive_digest: &str, provider_id: &str, tool_name: &str) -> String {
    derive_tool_id(archive_digest, provider_id, tool_name)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeResult {
    pub abi_version: String,
    pub provider_id: String,
    pub package_digest: String,
    pub tools: Vec<ToolDescriptor>,
    pub capabilities: RuntimeCapabilities,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCapabilities {
    pub auth_method_ids: Vec<String>,
    pub tool_ids: Vec<String>,
    pub credential_classes: Vec<String>,
    pub network_origins: Vec<String>,
    pub side_effects: Vec<SideEffect>,
    pub official_cli_policy_ids: Vec<OfficialCliPolicyId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDescriptor {
    pub tool_id: String,
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub side_effects: Vec<SideEffect>,
    pub authentication: AuthenticationBinding,
    pub network_origins: Vec<String>,
}

impl ToolDescriptor {
    pub fn from_manifest(
        manifest: &Manifest,
        archive_digest: &str,
        tool: &ToolDeclaration,
    ) -> Self {
        Self {
            tool_id: derive_tool_id(archive_digest, &manifest.provider_id, &tool.name),
            name: tool.name.clone(),
            description: tool.description.clone(),
            input_schema: tool.input_schema.clone(),
            output_schema: tool.output_schema.clone(),
            side_effects: tool.side_effects.clone(),
            authentication: tool.authentication.clone(),
            network_origins: tool.network_origins.clone(),
        }
    }

    pub fn validate_for(&self, manifest: &Manifest, archive_digest: &str) -> ValidationResult<()> {
        let tool = manifest
            .tool(&self.name)
            .ok_or_else(|| ValidationError::new("tool", "tool is not declared"))?;
        let expected = Self::from_manifest(manifest, archive_digest, tool);
        if self != &expected {
            return Err(ValidationError::new(
                "tool",
                "runtime metadata/schema differs from manifest",
            ));
        }
        validate_tool_id(
            &self.tool_id,
            archive_digest,
            &manifest.provider_id,
            &self.name,
        )
    }
}

impl InitializeResult {
    pub fn validate_for(&self, manifest: &Manifest, archive_digest: &str) -> ValidationResult<()> {
        manifest.validate()?;
        validate_hex(archive_digest, 32, "package_digest")?;
        if self.abi_version != ABI_FORMAT
            || self.provider_id != manifest.provider_id
            || self.package_digest != archive_digest
            || self.tools.len() != manifest.tools.len()
        {
            return Err(ValidationError::new(
                "initialize.result",
                "runtime identity differs from approved manifest",
            ));
        }
        let mut names = BTreeSet::new();
        for tool in &self.tools {
            tool.validate_for(manifest, archive_digest)?;
            if !names.insert(tool.name.as_str()) {
                return Err(ValidationError::new(
                    "initialize.tools",
                    "duplicate runtime tool",
                ));
            }
        }
        if manifest
            .tools
            .iter()
            .any(|tool| !names.contains(tool.name.as_str()))
        {
            return Err(ValidationError::new(
                "initialize.tools",
                "runtime tool set is incomplete",
            ));
        }
        if self.capabilities != RuntimeCapabilities::from_manifest(manifest, archive_digest) {
            return Err(ValidationError::new(
                "initialize.capabilities",
                "runtime capability escalation or mismatch",
            ));
        }
        Ok(())
    }
}

impl RuntimeCapabilities {
    pub fn from_manifest(manifest: &Manifest, archive_digest: &str) -> Self {
        let mut tool_ids = Vec::new();
        let mut side_effects = Vec::new();
        for tool in &manifest.tools {
            tool_ids.push(derive_tool_id(
                archive_digest,
                &manifest.provider_id,
                &tool.name,
            ));
            for effect in &tool.side_effects {
                if !side_effects.contains(effect) {
                    side_effects.push(*effect);
                }
            }
        }
        Self {
            auth_method_ids: manifest.capabilities.auth_method_ids.clone(),
            tool_ids,
            credential_classes: manifest.capabilities.credential_classes.clone(),
            network_origins: manifest.capabilities.network_origins.clone(),
            side_effects,
            official_cli_policy_ids: manifest.capabilities.official_cli_policy_ids.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedInvocation {
    pub package_digest: String,
    pub tool_id: String,
    pub invocation_id: String,
    pub authentication: AuthenticationBinding,
    pub deadline_unix_ms: u64,
}

impl AuthorizedInvocation {
    pub fn validate(&self) -> ValidationResult<()> {
        validate_hex(&self.package_digest, 32, "invocation.package_digest")?;
        validate_tool_id_syntax(&self.tool_id)?;
        validate_bounded_id(
            &self.invocation_id,
            "invocation.invocation_id",
            MAX_ID_BYTES,
        )?;
        if self.deadline_unix_ms == 0 {
            return Err(ValidationError::new(
                "invocation.deadline_unix_ms",
                "deadline must be non-zero",
            ));
        }
        self.authentication.validate("invocation.authentication")
    }

    pub fn validate_for(&self, manifest: &Manifest, archive_digest: &str) -> ValidationResult<()> {
        self.validate()?;
        manifest.validate()?;
        if self.package_digest != archive_digest {
            return Err(ValidationError::new(
                "invocation.package_digest",
                "does not match the installed archive",
            ));
        }
        let (_, _, name) = parse_tool_id(&self.tool_id)?;
        let tool = manifest
            .tool(name)
            .ok_or_else(|| ValidationError::new("invocation.tool_id", "tool is undeclared"))?;
        let expected = derive_tool_id(archive_digest, &manifest.provider_id, name);
        if self.tool_id != expected || self.authentication != tool.authentication {
            return Err(ValidationError::new(
                "invocation",
                "authorized invocation does not equal the approved tool binding",
            ));
        }
        Ok(())
    }

    /// Validate the complete manifest → runtime → tool → invocation chain.
    pub fn validate_for_runtime(
        &self,
        manifest: &Manifest,
        runtime: &InitializeResult,
        archive_digest: &str,
    ) -> ValidationResult<()> {
        runtime.validate_for(manifest, archive_digest)?;
        self.validate_for(manifest, archive_digest)?;
        let descriptor = runtime
            .tools
            .iter()
            .find(|tool| tool.tool_id == self.tool_id)
            .ok_or_else(|| ValidationError::new("invocation.tool_id", "runtime tool is absent"))?;
        if descriptor.authentication != self.authentication {
            return Err(ValidationError::new(
                "invocation.authentication",
                "does not equal the runtime descriptor binding",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSecretDelivery {
    pub auth_method_id: String,
    pub invocation_id: String,
    pub kind: DeliveryKind,
    pub credential_class: String,
    pub value: String,
    pub expires_at_unix_ms: u64,
}

impl fmt::Debug for ScopedSecretDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedSecretDelivery")
            .field("auth_method_id", &self.auth_method_id)
            .field("invocation_id", &self.invocation_id)
            .field("kind", &self.kind)
            .field("credential_class", &self.credential_class)
            .field("value", &"<redacted>")
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish()
    }
}

impl ScopedSecretDelivery {
    pub fn validate_for(&self, invocation: &AuthorizedInvocation) -> ValidationResult<()> {
        let (auth_method_id, credential_class, kind) = match &invocation.authentication {
            AuthenticationBinding::HostSecret {
                auth_method_id,
                credential_class,
                delivery_kind,
            } => (auth_method_id, credential_class, delivery_kind),
            AuthenticationBinding::None | AuthenticationBinding::OfficialCliSession { .. } => {
                return Err(ValidationError::new(
                    "secret_delivery",
                    "secret delivery is forbidden for this authentication binding",
                ));
            }
        };
        if &self.auth_method_id != auth_method_id {
            return Err(ValidationError::new(
                "secret_delivery.auth_method_id",
                "method scope mismatch",
            ));
        }
        if self.invocation_id != invocation.invocation_id {
            return Err(ValidationError::new(
                "secret_delivery.invocation_id",
                "invocation scope mismatch",
            ));
        }
        if &self.credential_class != credential_class {
            return Err(ValidationError::new(
                "secret_delivery.credential_class",
                "credential scope mismatch",
            ));
        }
        if &self.kind != kind {
            return Err(ValidationError::new(
                "secret_delivery.kind",
                "delivery kind does not match authorized invocation",
            ));
        }
        validate_bounded_id(
            &self.auth_method_id,
            "secret_delivery.auth_method_id",
            MAX_ID_BYTES,
        )?;
        validate_bounded_id(
            &self.invocation_id,
            "secret_delivery.invocation_id",
            MAX_ID_BYTES,
        )?;
        validate_bounded_id(
            &self.credential_class,
            "secret_delivery.credential_class",
            MAX_ID_BYTES,
        )?;
        if self.value.is_empty()
            || self.value.len() > MAX_SECRET_BYTES
            || self.value.chars().any(char::is_control)
        {
            return Err(ValidationError::new(
                "secret_delivery.value",
                "secret delivery is empty or oversized",
            ));
        }
        if self.expires_at_unix_ms == 0 || self.expires_at_unix_ms > invocation.deadline_unix_ms {
            return Err(ValidationError::new(
                "secret_delivery.expires_at_unix_ms",
                "delivery exceeds invocation deadline",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq)]
pub struct ToolInvokeParams {
    pub invocation: AuthorizedInvocation,
    pub input: Value,
    pub secret_delivery: Option<ScopedSecretDelivery>,
}

impl Serialize for ToolInvokeParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate_wire().map_err(serde::ser::Error::custom)?;
        let field_count = if self.secret_delivery.is_some() { 3 } else { 2 };
        let mut state = serializer.serialize_struct("ToolInvokeParams", field_count)?;
        state.serialize_field("invocation", &self.invocation)?;
        state.serialize_field("input", &self.input)?;
        if let Some(delivery) = &self.secret_delivery {
            state.serialize_field("secret_delivery", delivery)?;
        }
        state.end()
    }
}

impl fmt::Debug for ToolInvokeParams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolInvokeParams")
            .field("invocation", &self.invocation)
            .field("input", &"<redacted>")
            .field("secret_delivery", &self.secret_delivery)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolInvokeParamsWire {
    invocation: AuthorizedInvocation,
    input: Value,
    #[serde(default)]
    secret_delivery: RequiredNullable<ScopedSecretDelivery>,
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
        let value = Value::deserialize(deserializer)?;
        let parsed = if value.is_null() {
            None
        } else {
            Some(serde_json::from_value(value).map_err(D::Error::custom)?)
        };
        Ok(Self {
            present: true,
            value: parsed,
        })
    }
}

impl<'de> Deserialize<'de> for ToolInvokeParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ToolInvokeParamsWire::deserialize(deserializer)?;
        let host_secret = wire.invocation.authentication.is_host_secret();
        if host_secret && wire.secret_delivery.value.is_none() {
            return Err(D::Error::custom(
                "host_secret invocation requires non-null secret_delivery",
            ));
        }
        if !host_secret && wire.secret_delivery.present {
            return Err(D::Error::custom(
                "secret_delivery is forbidden unless authentication.kind is host_secret",
            ));
        }
        let result = Self {
            invocation: wire.invocation,
            input: wire.input,
            secret_delivery: wire.secret_delivery.value,
        };
        result.validate_wire().map_err(D::Error::custom)?;
        Ok(result)
    }
}

impl ToolInvokeParams {
    pub fn validate_wire(&self) -> ValidationResult<()> {
        self.invocation.validate()?;
        match (&self.invocation.authentication, &self.secret_delivery) {
            (AuthenticationBinding::HostSecret { .. }, Some(delivery)) => {
                delivery.validate_for(&self.invocation)
            }
            (AuthenticationBinding::HostSecret { .. }, None) => Err(ValidationError::new(
                "secret_delivery",
                "host_secret invocation requires delivery",
            )),
            (
                AuthenticationBinding::None | AuthenticationBinding::OfficialCliSession { .. },
                None,
            ) => Ok(()),
            (
                AuthenticationBinding::None | AuthenticationBinding::OfficialCliSession { .. },
                Some(_),
            ) => Err(ValidationError::new(
                "secret_delivery",
                "secret delivery is forbidden for this authentication binding",
            )),
        }
    }

    pub fn validate_for(
        &self,
        manifest: &Manifest,
        runtime: &InitializeResult,
        archive_digest: &str,
    ) -> ValidationResult<()> {
        self.validate_wire()?;
        self.invocation
            .validate_for_runtime(manifest, runtime, archive_digest)?;
        let (_, _, name) = parse_tool_id(&self.invocation.tool_id)?;
        validate_json_value(
            &manifest
                .tool(name)
                .ok_or_else(|| ValidationError::new("tool", "tool is undeclared"))?
                .input_schema,
            &self.input,
        )
        .map_err(|error| ValidationError::new("input", error.to_string()))
    }
}

/// A small strict envelope for representation/parity fixtures.  It intentionally
/// has no session or execution state machine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: RequestId,
    pub method: String,
    pub params: Value,
}

impl JsonRpcRequest {
    pub fn validate(&self) -> Result<(), RpcCodecError> {
        if self.jsonrpc != "2.0" {
            return Err(RpcCodecError("jsonrpc must be 2.0".to_owned()));
        }
        self.id
            .validate()
            .map_err(|error| RpcCodecError(error.to_string()))?;
        if !self.params.is_object() {
            return Err(RpcCodecError("params must be an object".to_owned()));
        }
        match self.method.as_str() {
            METHOD_INITIALIZE => serde_json::from_value::<InitializeParams>(self.params.clone())
                .map_err(|error| RpcCodecError(error.to_string()))
                .and_then(|params| params.validate()),
            METHOD_TOOL_INVOKE => serde_json::from_value::<ToolInvokeParams>(self.params.clone())
                .map(|_| ())
                .map_err(|error| RpcCodecError(error.to_string())),
            METHOD_CONNECTION_DIAGNOSTIC => {
                serde_json::from_value::<ConnectionDiagnosticParams>(self.params.clone())
                    .map_err(|error| RpcCodecError(error.to_string()))
                    .and_then(|params| params.validate())
            }
            other => Err(RpcCodecError(format!(
                "method {other} is not in provider v2"
            ))),
        }
    }

    pub fn typed_params<T: for<'de> Deserialize<'de>>(&self) -> Result<T, RpcCodecError> {
        serde_json::from_value(self.params.clone())
            .map_err(|error| RpcCodecError(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    pub minimum: String,
    pub maximum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLimits {
    pub max_frame_bytes: u32,
    pub max_json_depth: u16,
    pub max_members: u16,
    pub max_timeout_ms: u32,
}

impl HostLimits {
    pub fn validate(&self) -> ValidationResult<()> {
        if self.max_frame_bytes == 0 || self.max_frame_bytes as usize > MAX_FRAME_BYTES {
            return Err(ValidationError::new(
                "limits.max_frame_bytes",
                "exceeds ABI bound",
            ));
        }
        if self.max_json_depth == 0 || self.max_json_depth as usize > MAX_JSON_DEPTH {
            return Err(ValidationError::new(
                "limits.max_json_depth",
                "exceeds ABI bound",
            ));
        }
        if self.max_members == 0 || self.max_members as usize > MAX_JSON_MEMBERS {
            return Err(ValidationError::new(
                "limits.max_members",
                "exceeds ABI bound",
            ));
        }
        if self.max_timeout_ms == 0 || self.max_timeout_ms as u64 > MAX_TIMEOUT_MS {
            return Err(ValidationError::new(
                "limits.max_timeout_ms",
                "exceeds ABI bound",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeParams {
    pub version_range: VersionRange,
    pub limits: HostLimits,
}

impl InitializeParams {
    pub fn validate(&self) -> Result<(), RpcCodecError> {
        if self.version_range.minimum != ABI_FORMAT || self.version_range.maximum != ABI_FORMAT {
            return Err(RpcCodecError(
                "v2 requires an exact gorce.provider/v2 version range".to_owned(),
            ));
        }
        self.limits
            .validate()
            .map_err(|error| RpcCodecError(error.to_string()))
    }
}

/// This is a parsing/parity representation only.  No prompt, result mapping,
/// budget, adapter, or execution authority is defined by Phase 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionDiagnosticParams {
    pub provider_id: String,
    pub policy_id: OfficialCliPolicyId,
}

impl ConnectionDiagnosticParams {
    pub fn validate(&self) -> Result<(), RpcCodecError> {
        validate_identifier(&self.provider_id, "provider_id", 64)
            .map_err(|error| RpcCodecError(error.to_string()))
    }
}

pub fn validate_manifest_runtime_invocation(
    manifest: &Manifest,
    runtime: &InitializeResult,
    invocation: &AuthorizedInvocation,
    archive_digest: &str,
) -> ValidationResult<()> {
    invocation.validate_for_runtime(manifest, runtime, archive_digest)
}

fn validate_tool_id(
    value: &str,
    archive_digest: &str,
    provider_id: &str,
    name: &str,
) -> ValidationResult<()> {
    validate_tool_id_syntax(value)?;
    if value != derive_tool_id(archive_digest, provider_id, name) {
        return Err(ValidationError::new(
            "tool_id",
            "tool ID does not match the independent V2 derivation",
        ));
    }
    Ok(())
}

fn validate_tool_id_syntax(value: &str) -> ValidationResult<()> {
    if value.is_empty()
        || value.len() > MAX_TOOL_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-/".contains(&byte))
        || !value.starts_with("gorce.provider/v2/tool/")
    {
        return Err(ValidationError::new(
            "tool_id",
            "contains an invalid V2 tool ID",
        ));
    }
    Ok(())
}

fn parse_tool_id(value: &str) -> ValidationResult<(&str, &str, &str)> {
    let rest = value
        .strip_prefix("gorce.provider/v2/tool/")
        .ok_or_else(|| ValidationError::new("tool_id", "tool ID is not a V2 host ID"))?;
    let (digest, rest) = rest
        .split_once('/')
        .ok_or_else(|| ValidationError::new("tool_id", "tool ID is incomplete"))?;
    let (provider, name) = rest
        .split_once('/')
        .ok_or_else(|| ValidationError::new("tool_id", "tool ID is incomplete"))?;
    if name.contains('/') {
        return Err(ValidationError::new(
            "tool_id",
            "tool ID contains extra path segments",
        ));
    }
    validate_hex(digest, 32, "tool_id.digest")?;
    validate_identifier(provider, "tool_id.provider_id", 64)?;
    validate_identifier(name, "tool_id.name", 64)?;
    Ok((digest, provider, name))
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

fn validate_bounded_id(value: &str, field: &str, max: usize) -> ValidationResult<()> {
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(ValidationError::new(
            field,
            "contains invalid bounded ID bytes",
        ));
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

fn validate_set_identifiers(
    values: &[String],
    field: &str,
    max_items: usize,
) -> ValidationResult<()> {
    if values.len() > max_items {
        return Err(ValidationError::new(field, "contains too many values"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_identifier(value, field, 64)?;
        if !seen.insert(value) {
            return Err(ValidationError::new(field, "contains duplicate values"));
        }
    }
    Ok(())
}

fn same_set(expected: &BTreeSet<String>, actual: &[String]) -> bool {
    expected.len() == actual.len() && actual.iter().all(|item| expected.contains(item))
}

fn validate_policy_set(values: &[OfficialCliPolicyId], field: &str) -> ValidationResult<()> {
    if values.len() > 2 {
        return Err(ValidationError::new(field, "contains too many policies"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(ValidationError::new(field, "contains duplicate policies"));
        }
    }
    Ok(())
}

fn same_policy_set(
    expected: &BTreeSet<OfficialCliPolicyId>,
    actual: &[OfficialCliPolicyId],
) -> bool {
    expected.len() == actual.len() && actual.iter().all(|item| expected.contains(item))
}

fn validate_side_effects(values: &[SideEffect], field: &str) -> ValidationResult<()> {
    if values.is_empty() || values.len() > MAX_LIST_ITEMS {
        return Err(ValidationError::new(
            field,
            "must contain 1..=64 side effects",
        ));
    }
    let mut seen = BTreeSet::new();
    if values.iter().any(|effect| !seen.insert(effect)) {
        return Err(ValidationError::new(
            field,
            "contains duplicate side effects",
        ));
    }
    Ok(())
}

fn validate_origins(values: &[String], field: &str) -> ValidationResult<()> {
    if values.len() > MAX_LIST_ITEMS {
        return Err(ValidationError::new(field, "contains too many origins"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_text(value, field, 2048)?;
        let origin = value.strip_prefix("https://");
        if origin.is_none()
            || origin.is_some_and(|value| value.is_empty() || value.contains('/'))
            || value.contains('?')
            || value.contains('#')
        {
            return Err(ValidationError::new(
                field,
                "origin is not canonical HTTPS syntax",
            ));
        }
        if !seen.insert(value) {
            return Err(ValidationError::new(field, "contains duplicate origins"));
        }
    }
    Ok(())
}

fn validate_package_path(value: &str, field: &str) -> ValidationResult<()> {
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
                || matches!(
                    part.to_ascii_lowercase().as_str(),
                    "con" | "conin$" | "conout$" | "prn" | "aux" | "nul" | "clock$"
                )
        })
    {
        return Err(ValidationError::new(
            field,
            "must be a safe relative package path",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn base_manifest() -> Manifest {
        serde_json::from_str(include_str!(
            "../../../api/provider-abi/v2/examples/manifest.json"
        ))
        .unwrap()
    }

    fn base_runtime(_manifest: &Manifest) -> InitializeResult {
        serde_json::from_str(include_str!(
            "../../../api/provider-abi/v2/examples/initialize-result.json"
        ))
        .unwrap()
    }

    #[test]
    fn v2_examples_validate_the_full_cross_object_chain() {
        let manifest = base_manifest();
        manifest.validate().unwrap();
        let runtime = base_runtime(&manifest);
        runtime.validate_for(&manifest, DIGEST).unwrap();
        let invoke: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v2/examples/tool-invoke-host-secret.json"
        ))
        .unwrap();
        let params: ToolInvokeParams = serde_json::from_value(invoke["params"].clone()).unwrap();
        params.validate_for(&manifest, &runtime, DIGEST).unwrap();
    }

    #[test]
    fn bindings_are_strict_tagged_and_policy_ids_are_closed() {
        for (value, expected) in [
            (json!({"kind":"none"}), AuthenticationBinding::None),
            (
                json!({"kind":"host_secret","auth_method_id":"api","credential_class":"secret","delivery_kind":"api_key"}),
                AuthenticationBinding::host_secret("api", "secret", DeliveryKind::ApiKey),
            ),
            (
                json!({"kind":"official_cli_session","policy_id":OFFICIAL_CLI_CODEX_POLICY_ID}),
                AuthenticationBinding::official_cli_session(OfficialCliPolicyId::Codex),
            ),
        ] {
            assert_eq!(
                serde_json::from_value::<AuthenticationBinding>(value).unwrap(),
                expected
            );
        }
        for value in [
            json!({}),
            json!({"kind":"none","auth_method_id":"legacy"}),
            json!({"kind":"host_secret","auth_method_id":"api","credential_class":"secret"}),
            json!({"kind":"official_cli_session","policy_id":"gorce.official-cli/codex/v2"}),
            json!({"kind":"official_cli_session","policy_id":OFFICIAL_CLI_CODEX_POLICY_ID,"credential_class":"legacy"}),
            json!({"kind":"api_key","id":"api","credential_class":"secret"}),
        ] {
            assert!(serde_json::from_value::<AuthenticationBinding>(value).is_err());
        }
    }

    #[test]
    fn v2_secret_delivery_presence_follows_the_binding_tag() {
        let mut none: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v2/examples/tool-invoke-none.json"
        ))
        .unwrap();
        assert!(serde_json::from_value::<ToolInvokeParams>(none["params"].clone()).is_ok());
        none["params"]["secret_delivery"] = Value::Null;
        assert!(serde_json::from_value::<ToolInvokeParams>(none["params"].clone()).is_err());

        let mut host: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v2/examples/tool-invoke-host-secret.json"
        ))
        .unwrap();
        host["params"]
            .as_object_mut()
            .unwrap()
            .remove("secret_delivery");
        assert!(serde_json::from_value::<ToolInvokeParams>(host["params"].clone()).is_err());
        host["params"]["secret_delivery"] = Value::Null;
        assert!(serde_json::from_value::<ToolInvokeParams>(host["params"].clone()).is_err());

        let mut official: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v2/examples/tool-invoke-official-cli.json"
        ))
        .unwrap();
        official["params"]["secret_delivery"] = json!({});
        assert!(serde_json::from_value::<ToolInvokeParams>(official["params"].clone()).is_err());
    }

    #[test]
    fn v1_ids_and_v1_nullable_fields_do_not_cross_the_v2_boundary() {
        let manifest = base_manifest();
        assert!(serde_json::from_value::<Manifest>(json!({
            "format":"gorce.provider/v1",
            "provider_id":"x"
        }))
        .is_err());
        assert!(parse_tool_id(&format!("gorce.provider/v1/tool/{DIGEST}/demo/tool")).is_err());

        let mut tool = serde_json::to_value(&manifest.tools[0]).unwrap();
        tool["auth_method_id"] = Value::Null;
        assert!(serde_json::from_value::<ToolDeclaration>(tool).is_err());
    }

    #[test]
    fn capabilities_and_swaps_fail_closed() {
        let mut manifest = base_manifest();
        manifest.capabilities.official_cli_policy_ids = vec![OfficialCliPolicyId::Codex];
        assert!(manifest.validate().is_err());

        let mut manifest = base_manifest();
        manifest.tools[1].authentication =
            AuthenticationBinding::host_secret("missing", "secret", DeliveryKind::ApiKey);
        assert!(manifest.validate().is_err());

        let mut manifest = base_manifest();
        manifest.tools[1].authentication =
            AuthenticationBinding::host_secret("api", "wrong-class", DeliveryKind::ApiKey);
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn host_secret_method_collection_allows_zero_and_rejects_more_than_eight() {
        let mut empty = base_manifest();
        empty.auth_methods.clear();
        empty.capabilities.auth_method_ids.clear();
        empty.capabilities.credential_classes.clear();
        empty.tools.retain(|tool| {
            matches!(
                &tool.authentication,
                AuthenticationBinding::None | AuthenticationBinding::OfficialCliSession { .. }
            )
        });
        assert!(empty.validate().is_ok());

        let mut too_many = base_manifest();
        too_many.auth_methods = (0..=MAX_AUTH_METHODS)
            .map(|index| AuthMethod {
                id: format!("method-{index}"),
                credential_class: format!("class-{index}"),
                label: "Fixture".to_owned(),
                delivery_kind: DeliveryKind::ApiKey,
            })
            .collect();
        assert!(too_many.validate().is_err());
    }

    #[test]
    fn semantic_chain_rejects_cross_object_adversarial_fixtures() {
        let manifest = base_manifest();
        let runtime = base_runtime(&manifest);
        runtime.validate_for(&manifest, DIGEST).unwrap();

        for (name, fixture) in [
            (
                "cross-method-swap.json",
                include_str!(
                    "../../../api/provider-abi/v2/examples/adversarial/cross-method-swap.json"
                ),
            ),
            (
                "cross-class-swap.json",
                include_str!(
                    "../../../api/provider-abi/v2/examples/adversarial/cross-class-swap.json"
                ),
            ),
            (
                "cross-tool-swap.json",
                include_str!(
                    "../../../api/provider-abi/v2/examples/adversarial/cross-tool-swap.json"
                ),
            ),
            (
                "cross-policy-swap.json",
                include_str!(
                    "../../../api/provider-abi/v2/examples/adversarial/cross-policy-swap.json"
                ),
            ),
        ] {
            let value: Value = serde_json::from_str(fixture).unwrap();
            let params: ToolInvokeParams = serde_json::from_value(value).unwrap();
            assert!(
                params.validate_for(&manifest, &runtime, DIGEST).is_err(),
                "adversarial fixture unexpectedly passed the semantic chain: {name}"
            );
        }

        let escalated: InitializeResult = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v2/examples/adversarial/runtime-capability-escalation.json"
        ))
        .unwrap();
        assert!(
            escalated.validate_for(&manifest, DIGEST).is_err(),
            "runtime capability escalation unexpectedly passed manifest/runtime equality"
        );
    }

    #[test]
    fn fn_connection_diagnostic_fixtures_are_parsing_only_and_policy_closed() {
        for request in [
            serde_json::from_str::<JsonRpcRequest>(include_str!(
                "../../../api/provider-abi/v2/examples/connection-diagnostic-codex.json"
            )),
            serde_json::from_str::<JsonRpcRequest>(include_str!(
                "../../../api/provider-abi/v2/examples/connection-diagnostic-claude-code.json"
            )),
        ] {
            let request = request.unwrap();
            request.validate().unwrap();
        }
    }
}
