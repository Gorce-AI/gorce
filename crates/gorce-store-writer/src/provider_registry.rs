use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use gorce_core::{ProviderApprovalTuple, ProviderCapabilitySet};
use gorce_platform_security::{
    DurabilityReport, LockGuard, ReplacementError, SecureRuntime, SecurityError,
};
use gorce_provider_abi::{
    DeliveryKind, GitHashAlgorithm, SideEffect, VerifiedProviderSource, MAX_ID_BYTES,
    MAX_TOOL_ID_BYTES, SOURCE_CONTENT_DIGEST_ALGORITHM,
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

pub const PROVIDER_DATA_FORMAT_VERSION: &str = "gorce.provider-data/v1";
pub const PROVIDER_REGISTRY_LOCK_FILE: &str = "LOCK";
pub const PROVIDER_REGISTRY_FILE: &str = "registry.json";
pub const MAX_PROVIDER_REGISTRY_BYTES: usize = 1024 * 1024;
pub const MAX_PROVIDER_REGISTRY_RECORDS: usize = 256;

const FORMAT_FILE: &str = "FORMAT";
const REGISTRY_TEMP_FILE: &str = ".registry.json.tmp";
const REGISTRY_FORMAT: &str = "gorce.provider/registry/v1";
const RECORD_FORMAT: &str = "gorce.provider/source-approval/v1";
const APPROVAL_ID_PREFIX: &str = "sha256-";
const LOCK_RETRIES: usize = 100;
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(5);

#[derive(Debug)]
pub enum RegistryError {
    Security(SecurityError),
    LockContention,
    RecoveryNeeded(String),
    InvalidSource(String),
    RegistryTooLarge,
    Poisoned,
    PublicationAmbiguous(String),
    #[cfg(test)]
    FaultInjected(&'static str),
    LockPoisoned,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Security(error) => write!(formatter, "provider registry security error: {error}"),
            Self::LockContention => write!(formatter, "provider registry lock is contended"),
            Self::RecoveryNeeded(reason) => {
                write!(formatter, "provider registry recovery needed: {reason}")
            }
            Self::InvalidSource(reason) => {
                write!(formatter, "invalid verified provider source: {reason}")
            }
            Self::RegistryTooLarge => {
                write!(formatter, "provider registry exceeds its bounded size")
            }
            Self::Poisoned => write!(formatter, "provider registry is poisoned"),
            Self::PublicationAmbiguous(reason) => {
                write!(
                    formatter,
                    "provider registry publication is ambiguous: {reason}"
                )
            }
            #[cfg(test)]
            Self::FaultInjected(point) => {
                write!(formatter, "injected provider registry fault at {point}")
            }
            Self::LockPoisoned => write!(formatter, "provider registry mutex is poisoned"),
        }
    }
}

impl std::error::Error for RegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Security(error) => Some(error),
            _ => None,
        }
    }
}

impl From<SecurityError> for RegistryError {
    fn from(error: SecurityError) -> Self {
        Self::Security(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryRegistration {
    approval_id: String,
    generation: u64,
    changed: bool,
    durability: Option<DurabilityReport>,
}

impl RegistryRegistration {
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn changed(&self) -> bool {
        self.changed
    }

    pub fn durability(&self) -> Option<DurabilityReport> {
        self.durability
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RegistryDocument {
    format: String,
    generation: u64,
    entries: Vec<RegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RegistryEntry {
    provider_id: String,
    approval_id: String,
    approval: ApprovalRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ApprovalRecord {
    record_format: String,
    provider_id: String,
    package_digest: String,
    manifest_digest: String,
    publisher_fingerprint: Option<String>,
    executable_sha256: String,
    capabilities: StoredCapabilities,
    source_identity: StoredSourceIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StoredSourceIdentity {
    canonical_git_url: String,
    commit_hash_algorithm: String,
    resolved_commit: String,
    source_content_digest_algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StoredCapabilities {
    auth_method_ids: Vec<String>,
    auth_policies: Vec<String>,
    tool_ids: Vec<String>,
    tool_policies: Vec<String>,
    credential_classes: Vec<String>,
    network_origins: Vec<String>,
    side_effects: Vec<SideEffect>,
    tool_credentials: Vec<StoredToolCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
struct StoredToolCredential {
    tool_id: String,
    auth_method_id: String,
    credential_class: String,
    delivery_kind: DeliveryKind,
}

impl RegistryDocument {
    fn empty() -> Self {
        Self {
            format: REGISTRY_FORMAT.to_owned(),
            generation: 0,
            entries: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), RegistryError> {
        if self.format != REGISTRY_FORMAT {
            return recovery("registry format is unsupported");
        }
        if self.entries.len() > MAX_PROVIDER_REGISTRY_RECORDS {
            return recovery("registry contains more than 256 entries");
        }
        for pair in self.entries.windows(2) {
            if pair[0].provider_id >= pair[1].provider_id {
                return recovery("registry entries are not strictly ordered by provider_id");
            }
        }
        let mut approval_ids = BTreeMap::new();
        for entry in &self.entries {
            validate_provider_id(&entry.provider_id)?;
            if approval_ids
                .insert(entry.approval_id.clone(), entry.provider_id.clone())
                .is_some()
            {
                return recovery("registry contains duplicate approval IDs");
            }
            entry.validate()?;
        }
        Ok(())
    }
}

impl RegistryEntry {
    fn validate(&self) -> Result<(), RegistryError> {
        if self.approval.provider_id != self.provider_id {
            return recovery("entry provider_id does not match approval provider_id");
        }
        if self.approval_id != derive_approval_id(&self.approval)? {
            return recovery("approval_id does not match the canonical approval record");
        }
        self.approval.validate()
    }
}

impl ApprovalRecord {
    fn validate(&self) -> Result<(), RegistryError> {
        if self.record_format != RECORD_FORMAT {
            return recovery("approval record format is unsupported");
        }
        validate_provider_id(&self.provider_id)?;
        if self.publisher_fingerprint.is_some()
            || !is_lower_hex_64(&self.package_digest)
            || !is_lower_hex_64(&self.manifest_digest)
            || !is_lower_hex_64(&self.executable_sha256)
        {
            return recovery("approval digest or publisher fields are invalid");
        }
        let algorithm = match self.source_identity.commit_hash_algorithm.as_str() {
            "sha1" => GitHashAlgorithm::Sha1,
            "sha256" => GitHashAlgorithm::Sha256,
            _ => return recovery("source commit hash algorithm is invalid"),
        };
        gorce_provider_abi::PinnedGitSource::new(
            self.source_identity.canonical_git_url.clone(),
            algorithm,
            self.source_identity.resolved_commit.clone(),
        )
        .map_err(|error| RegistryError::RecoveryNeeded(error.to_string()))?;
        if self.source_identity.source_content_digest_algorithm != SOURCE_CONTENT_DIGEST_ALGORITHM {
            return recovery("source content digest algorithm is invalid");
        }
        self.capabilities.validate()
    }
}

impl StoredCapabilities {
    fn from_approval(capabilities: &ProviderCapabilitySet) -> Self {
        Self {
            auth_method_ids: capabilities.auth_method_ids.iter().cloned().collect(),
            auth_policies: capabilities.auth_policies.iter().cloned().collect(),
            tool_ids: capabilities.tool_ids.iter().cloned().collect(),
            tool_policies: capabilities.tool_policies.iter().cloned().collect(),
            credential_classes: capabilities.credential_classes.iter().cloned().collect(),
            network_origins: capabilities.network_origins.iter().cloned().collect(),
            side_effects: capabilities.side_effects.iter().copied().collect(),
            tool_credentials: capabilities
                .tool_credentials
                .iter()
                .map(
                    |(tool_id, auth_method_id, credential_class, delivery_kind)| {
                        StoredToolCredential {
                            tool_id: tool_id.clone(),
                            auth_method_id: auth_method_id.clone(),
                            credential_class: credential_class.clone(),
                            delivery_kind: *delivery_kind,
                        }
                    },
                )
                .collect(),
        }
    }

    fn validate(&self) -> Result<(), RegistryError> {
        validate_sorted_bounded_text(
            &self.auth_method_ids,
            "auth_method_ids",
            8,
            MAX_ID_BYTES,
            true,
        )?;
        validate_sorted(&self.auth_policies, "auth_policies", 8, true)?;
        validate_sorted_bounded_text(&self.tool_ids, "tool_ids", 64, MAX_TOOL_ID_BYTES, true)?;
        validate_sorted(&self.tool_policies, "tool_policies", 64, true)?;
        validate_sorted_bounded_text(
            &self.credential_classes,
            "credential_classes",
            8,
            MAX_ID_BYTES,
            true,
        )?;
        validate_sorted(&self.network_origins, "network_origins", 64, false)?;
        validate_sorted(&self.side_effects, "side_effects", 64, true)?;
        validate_sorted(&self.tool_credentials, "tool_credentials", 64, false)?;
        for credential in &self.tool_credentials {
            validate_bounded_text(&credential.tool_id, MAX_TOOL_ID_BYTES)?;
            validate_bounded_text(&credential.auth_method_id, MAX_ID_BYTES)?;
            validate_bounded_text(&credential.credential_class, MAX_ID_BYTES)?;
        }
        for value in self
            .auth_method_ids
            .iter()
            .chain(&self.auth_policies)
            .chain(&self.tool_ids)
            .chain(&self.tool_policies)
            .chain(&self.credential_classes)
            .chain(&self.network_origins)
        {
            validate_text(value)?;
        }
        Ok(())
    }
}

fn validate_sorted_bounded_text(
    values: &[String],
    field: &str,
    max: usize,
    max_bytes: usize,
    nonempty: bool,
) -> Result<(), RegistryError> {
    validate_sorted(values, field, max, nonempty)?;
    for value in values {
        validate_bounded_text(value, max_bytes)?;
    }
    Ok(())
}

fn validate_sorted<T: Ord>(
    values: &[T],
    field: &str,
    max: usize,
    nonempty: bool,
) -> Result<(), RegistryError> {
    if values.len() > max
        || (nonempty && values.is_empty())
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return recovery(format!(
            "capability field {field} is out of bounds or not sorted"
        ));
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), RegistryError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return recovery("capability text is empty, oversized, or contains control text");
    }
    Ok(())
}

fn validate_bounded_text(value: &str, max_bytes: usize) -> Result<(), RegistryError> {
    if value.len() > max_bytes {
        return recovery("capability text exceeds its ABI field bound");
    }
    validate_text(value)
}

fn validate_provider_id(value: &str) -> Result<(), RegistryError> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        || !value.as_bytes()[0].is_ascii_lowercase() && !value.as_bytes()[0].is_ascii_digit()
    {
        return recovery("provider_id is not a bounded lower-case identifier");
    }
    Ok(())
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn recovery<T>(reason: impl Into<String>) -> Result<T, RegistryError> {
    Err(RegistryError::RecoveryNeeded(reason.into()))
}

fn canonical_json_value(value: Value) -> Value {
    match value {
        Value::Array(values) => {
            Value::Array(values.into_iter().map(canonical_json_value).collect())
        }
        Value::Object(object) => {
            let mut sorted = BTreeMap::new();
            for (key, value) in object {
                sorted.insert(key, canonical_json_value(value));
            }
            let object = sorted.into_iter().collect::<Map<_, _>>();
            Value::Object(object)
        }
        value => value,
    }
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, RegistryError> {
    let value = serde_json::to_value(value).map_err(|error| {
        RegistryError::RecoveryNeeded(format!("cannot canonicalize JSON: {error}"))
    })?;
    serde_json::to_vec(&canonical_json_value(value)).map_err(|error| {
        RegistryError::RecoveryNeeded(format!("cannot serialize canonical JSON: {error}"))
    })
}

fn derive_approval_id(approval: &ApprovalRecord) -> Result<String, RegistryError> {
    let bytes = canonical_json_bytes(approval)?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{APPROVAL_ID_PREFIX}{digest:x}"))
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Null))
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(|number| StrictValue(Value::Number(number)))
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = access.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
            }
            values.insert(key, access.next_value::<StrictValue>()?.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

fn parse_canonical_document(bytes: &[u8]) -> Result<RegistryDocument, RegistryError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer).map_err(|error| {
        RegistryError::RecoveryNeeded(format!("invalid registry JSON: {error}"))
    })?;
    deserializer.end().map_err(|error| {
        RegistryError::RecoveryNeeded(format!("registry has trailing JSON: {error}"))
    })?;
    let document: RegistryDocument = serde_json::from_value(value.0).map_err(|error| {
        RegistryError::RecoveryNeeded(format!("registry DTO is invalid: {error}"))
    })?;
    document.validate()?;
    let canonical = canonical_json_bytes(&document)?;
    if canonical != bytes {
        return recovery("registry JSON is not canonical");
    }
    Ok(document)
}

fn lock_contention(error: &SecurityError) -> bool {
    match error {
        SecurityError::Io(error) => error.kind() == std::io::ErrorKind::WouldBlock,
        SecurityError::Security(message) => message == "runtime instance lock is already held",
        _ => false,
    }
}

fn registry_lock(root: &SecureRuntime) -> Result<LockGuard, RegistryError> {
    for attempt in 0..LOCK_RETRIES {
        match root.lock(PROVIDER_REGISTRY_LOCK_FILE) {
            Ok(lock) => return Ok(lock),
            Err(error) if lock_contention(&error) && attempt + 1 < LOCK_RETRIES => {
                std::thread::sleep(LOCK_RETRY_DELAY);
            }
            Err(error) if lock_contention(&error) => return Err(RegistryError::LockContention),
            Err(error) => return Err(RegistryError::Security(error)),
        }
    }
    Err(RegistryError::LockContention)
}

fn read_private(
    runtime: &SecureRuntime,
    name: &str,
    limit: usize,
) -> Result<Option<Vec<u8>>, RegistryError> {
    runtime
        .read_private_bounded(name, limit)
        .map_err(|error| RegistryError::RecoveryNeeded(error.to_string()))
}

fn canonical_empty_document_bytes() -> Result<Vec<u8>, RegistryError> {
    canonical_json_bytes(&RegistryDocument::empty())
}

enum RegistryPublicationFailure {
    Before(RegistryError),
    Ambiguous(RegistryError),
}

fn publish_registry_document(
    root: &SecureRuntime,
    candidate: &RegistryDocument,
    #[cfg(test)] before_replace_hook: Option<fn(&Path)>,
) -> Result<DurabilityReport, RegistryPublicationFailure> {
    if candidate.entries.len() > MAX_PROVIDER_REGISTRY_RECORDS {
        return Err(RegistryPublicationFailure::Before(
            RegistryError::RegistryTooLarge,
        ));
    }
    candidate
        .validate()
        .map_err(RegistryPublicationFailure::Before)?;
    let bytes = canonical_json_bytes(candidate).map_err(RegistryPublicationFailure::Before)?;
    if bytes.len() > MAX_PROVIDER_REGISTRY_BYTES {
        return Err(RegistryPublicationFailure::Before(
            RegistryError::RegistryTooLarge,
        ));
    }
    let expected = candidate.clone();
    #[cfg(test)]
    let mut before_replace_hook = before_replace_hook;
    match root.replace_private_validated(
        PROVIDER_REGISTRY_FILE,
        REGISTRY_TEMP_FILE,
        &bytes,
        |candidate_bytes| {
            let published =
                parse_canonical_document(candidate_bytes).map_err(|error| error.to_string())?;
            if published != expected {
                return Err("replacement candidate differs from expected document".to_owned());
            }
            #[cfg(test)]
            if let Some(hook) = before_replace_hook.take() {
                hook(root.path());
            }
            Ok(())
        },
    ) {
        Ok(report) => Ok(report),
        Err(ReplacementError::BeforePublication(error)) => Err(RegistryPublicationFailure::Before(
            RegistryError::RecoveryNeeded(format!(
                "replacement candidate failed before publication: {error}"
            )),
        )),
        Err(ReplacementError::PublicationAmbiguous(error)) => {
            Err(RegistryPublicationFailure::Ambiguous(
                RegistryError::PublicationAmbiguous(error.to_string()),
            ))
        }
    }
}

fn load_authoritative(
    root: &SecureRuntime,
    lock: &LockGuard,
) -> Result<RegistryDocument, RegistryError> {
    let lock_len = lock
        .file_len()
        .map_err(|error| RegistryError::RecoveryNeeded(error.to_string()))?;
    if lock_len != 0 {
        return recovery("LOCK must be a zero-length sentinel");
    }
    let format = read_private(root, FORMAT_FILE, 128)?;
    let registry = read_private(root, PROVIDER_REGISTRY_FILE, MAX_PROVIDER_REGISTRY_BYTES)?;
    match (format, registry) {
        (None, None) => {
            root.replace_private(
                FORMAT_FILE,
                format!("{PROVIDER_DATA_FORMAT_VERSION}\n").as_bytes(),
            )
            .map_err(|error| RegistryError::RecoveryNeeded(error.to_string()))?;
            let candidate = RegistryDocument::empty();
            publish_registry_document(
                root,
                &candidate,
                #[cfg(test)]
                None,
            )
            .map_err(|failure| match failure {
                RegistryPublicationFailure::Before(error)
                | RegistryPublicationFailure::Ambiguous(error) => error,
            })?;
            let bytes = canonical_empty_document_bytes()?;
            let format = read_private(root, FORMAT_FILE, 128)?.ok_or_else(|| {
                RegistryError::RecoveryNeeded("FORMAT disappeared during initialization".to_owned())
            })?;
            let registry = read_private(root, PROVIDER_REGISTRY_FILE, MAX_PROVIDER_REGISTRY_BYTES)?
                .ok_or_else(|| {
                    RegistryError::RecoveryNeeded(
                        "registry disappeared during initialization".to_owned(),
                    )
                })?;
            if format != format!("{PROVIDER_DATA_FORMAT_VERSION}\n").as_bytes() || registry != bytes
            {
                return recovery("initial registry publication did not revalidate");
            }
            parse_canonical_document(&registry)
        }
        (Some(format), Some(registry)) => {
            if format != format!("{PROVIDER_DATA_FORMAT_VERSION}\n").as_bytes() {
                return recovery("FORMAT marker is invalid");
            }
            parse_canonical_document(&registry)
        }
        (None, Some(_)) | (Some(_), None) => {
            recovery("provider data root has partial authoritative state")
        }
    }
}

struct RegistryState {
    document: RegistryDocument,
    poisoned: bool,
}

fn lock_state<'a>(
    mutex: &'a Mutex<RegistryState>,
) -> Result<MutexGuard<'a, RegistryState>, RegistryError> {
    mutex.lock().map_err(|_| RegistryError::LockPoisoned)
}

pub struct ProviderRegistry {
    root: Arc<SecureRuntime>,
    state: Mutex<RegistryState>,
    #[cfg(test)]
    fault: Mutex<Option<PublicationFault>>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
enum PublicationFault {
    BeforeReplace,
    #[cfg(unix)]
    ReplaceCallFailure,
    AfterReplace,
}

impl ProviderRegistry {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, RegistryError> {
        let root = Arc::new(SecureRuntime::open(root).map_err(RegistryError::Security)?);
        let lock = registry_lock(&root)?;
        let document = load_authoritative(&root, &lock)?;
        Ok(Self {
            root,
            state: Mutex::new(RegistryState {
                document,
                poisoned: false,
            }),
            #[cfg(test)]
            fault: Mutex::new(None),
        })
    }

    pub fn root(&self) -> &Path {
        self.root.path()
    }

    pub fn registry_path(&self) -> PathBuf {
        self.root.path().join(PROVIDER_REGISTRY_FILE)
    }

    pub fn register_source(
        &self,
        source: &VerifiedProviderSource,
    ) -> Result<RegistryRegistration, RegistryError> {
        let mut state = lock_state(&self.state)?;
        if state.poisoned {
            return Err(RegistryError::Poisoned);
        }
        let lock = registry_lock(&self.root)?;
        let current = match load_authoritative(&self.root, &lock) {
            Ok(document) => document,
            Err(error) => {
                state.poisoned = true;
                return Err(error);
            }
        };
        state.document = current;
        let previous = state.document.clone();
        let record = record_from_source(source)?;
        let position = state
            .document
            .entries
            .binary_search_by(|entry| entry.provider_id.cmp(&record.provider_id));
        let changed = match position {
            Ok(index) if state.document.entries[index].approval_id == record.approval_id => {
                return Ok(RegistryRegistration {
                    approval_id: record.approval_id,
                    generation: state.document.generation,
                    changed: false,
                    durability: None,
                });
            }
            Ok(index) => {
                state.document.entries[index] = record.clone();
                true
            }
            Err(index) => {
                state.document.entries.insert(index, record.clone());
                true
            }
        };
        if state.document.generation == u64::MAX {
            state.poisoned = true;
            return Err(RegistryError::RecoveryNeeded(
                "registry generation exhausted".to_owned(),
            ));
        }
        state.document.generation += 1;
        let candidate = state.document.clone();
        let report = match self.publish_locked(&mut state, candidate, &lock) {
            Ok(report) => report,
            Err(error) => {
                if !state.poisoned {
                    state.document = previous;
                }
                return Err(error);
            }
        };
        Ok(RegistryRegistration {
            approval_id: record.approval_id,
            generation: state.document.generation,
            changed,
            durability: Some(report),
        })
    }

    pub fn matches_source(&self, source: &VerifiedProviderSource) -> Result<bool, RegistryError> {
        let mut state = lock_state(&self.state)?;
        if state.poisoned {
            return Err(RegistryError::Poisoned);
        }
        let lock = registry_lock(&self.root)?;
        let current = match load_authoritative(&self.root, &lock) {
            Ok(document) => document,
            Err(error) => {
                state.poisoned = true;
                return Err(error);
            }
        };
        state.document = current;
        let record = record_from_source(source)?;
        Ok(state
            .document
            .entries
            .binary_search_by(|entry| entry.provider_id.cmp(&record.provider_id))
            .ok()
            .is_some_and(|index| state.document.entries[index] == record))
    }

    fn publish_locked(
        &self,
        state: &mut RegistryState,
        candidate: RegistryDocument,
        lock: &LockGuard,
    ) -> Result<DurabilityReport, RegistryError> {
        #[cfg(test)]
        let fault = self
            .fault
            .lock()
            .map_err(|_| RegistryError::LockPoisoned)?
            .take();
        #[cfg(test)]
        if matches!(fault, Some(PublicationFault::BeforeReplace)) {
            return Err(RegistryError::FaultInjected("before_registry_replace"));
        }
        #[cfg(all(test, unix))]
        let before_replace_hook = if matches!(fault, Some(PublicationFault::ReplaceCallFailure)) {
            Some(force_replace_call_failure as fn(&Path))
        } else {
            None
        };
        #[cfg(all(test, not(unix)))]
        let before_replace_hook = None;
        let report = match publish_registry_document(
            &self.root,
            &candidate,
            #[cfg(test)]
            before_replace_hook,
        ) {
            Ok(report) => report,
            Err(RegistryPublicationFailure::Before(error)) => return Err(error),
            Err(RegistryPublicationFailure::Ambiguous(error)) => {
                state.poisoned = true;
                return Err(error);
            }
        };
        #[cfg(test)]
        if matches!(fault, Some(PublicationFault::AfterReplace)) {
            state.poisoned = true;
            return Err(RegistryError::PublicationAmbiguous(
                "fault injected after replacement".to_owned(),
            ));
        }
        let published = match load_authoritative(&self.root, lock) {
            Ok(document) => document,
            Err(error) => {
                state.poisoned = true;
                return Err(RegistryError::PublicationAmbiguous(error.to_string()));
            }
        };
        if published != candidate {
            state.poisoned = true;
            return Err(RegistryError::PublicationAmbiguous(
                "published registry differs from candidate".to_owned(),
            ));
        }
        state.document = published;
        Ok(report)
    }

    #[cfg(test)]
    fn inject_publication_fault(&self, after_replace: bool) {
        *self.fault.lock().unwrap() = Some(if after_replace {
            PublicationFault::AfterReplace
        } else {
            PublicationFault::BeforeReplace
        });
    }

    #[cfg(all(test, unix))]
    fn inject_replace_call_failure(&self) {
        *self.fault.lock().unwrap() = Some(PublicationFault::ReplaceCallFailure);
    }

    #[cfg(test)]
    fn publish_document_for_test(
        &self,
        document: RegistryDocument,
    ) -> Result<DurabilityReport, RegistryError> {
        let mut state = lock_state(&self.state)?;
        if state.poisoned {
            return Err(RegistryError::Poisoned);
        }
        let lock = registry_lock(&self.root)?;
        self.publish_locked(&mut state, document, &lock)
    }
}

fn record_from_source(source: &VerifiedProviderSource) -> Result<RegistryEntry, RegistryError> {
    let approval = ProviderApprovalTuple::from_verified_source(source)
        .map_err(|error| RegistryError::InvalidSource(error.to_string()))?;
    let identity = approval
        .source_identity()
        .ok_or_else(|| RegistryError::InvalidSource("source identity is absent".to_owned()))?;
    let approval_record = ApprovalRecord {
        record_format: RECORD_FORMAT.to_owned(),
        provider_id: approval.provider_id().to_owned(),
        package_digest: approval.content_digest().to_owned(),
        manifest_digest: approval.manifest_digest().to_owned(),
        publisher_fingerprint: None,
        executable_sha256: source.manifest().package.executable.sha256.clone(),
        capabilities: StoredCapabilities::from_approval(approval.capabilities()),
        source_identity: StoredSourceIdentity {
            canonical_git_url: identity.canonical_git_url().to_owned(),
            commit_hash_algorithm: identity.commit_hash_algorithm().as_str().to_owned(),
            resolved_commit: identity.resolved_commit().to_owned(),
            source_content_digest_algorithm: identity.source_content_digest_algorithm().to_owned(),
        },
    };
    approval_record.validate()?;
    Ok(RegistryEntry {
        provider_id: approval_record.provider_id.clone(),
        approval_id: derive_approval_id(&approval_record)?,
        approval: approval_record,
    })
}

#[cfg(all(test, unix))]
fn force_replace_call_failure(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500)).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_root(label: &str) -> PathBuf {
        std::env::current_dir().unwrap().join(format!(
            ".gorce-provider-registry-{label}-{}",
            uuid::Uuid::new_v4()
        ))
    }

    fn fixture_approval(commit: &str) -> ApprovalRecord {
        ApprovalRecord {
            record_format: RECORD_FORMAT.to_owned(),
            provider_id: "source-fixture".to_owned(),
            package_digest: "a".repeat(64),
            manifest_digest: "b".repeat(64),
            publisher_fingerprint: None,
            executable_sha256: "c".repeat(64),
            capabilities: StoredCapabilities {
                auth_method_ids: vec!["fixture_api_key".to_owned()],
                auth_policies: vec!["fixture-policy".to_owned()],
                tool_ids: vec!["tool".to_owned()],
                tool_policies: vec!["tool-policy".to_owned()],
                credential_classes: vec!["fixture-key".to_owned()],
                network_origins: Vec::new(),
                side_effects: vec![SideEffect::NetworkRead],
                tool_credentials: vec![StoredToolCredential {
                    tool_id: "tool".to_owned(),
                    auth_method_id: "fixture_api_key".to_owned(),
                    credential_class: "fixture-key".to_owned(),
                    delivery_kind: DeliveryKind::ApiKey,
                }],
            },
            source_identity: StoredSourceIdentity {
                canonical_git_url: "https://example.com/gorce/provider".to_owned(),
                commit_hash_algorithm: "sha1".to_owned(),
                resolved_commit: commit.to_owned(),
                source_content_digest_algorithm: SOURCE_CONTENT_DIGEST_ALGORITHM.to_owned(),
            },
        }
    }

    fn fixture_entry(commit: &str) -> RegistryEntry {
        let approval = fixture_approval(commit);
        RegistryEntry {
            provider_id: approval.provider_id.clone(),
            approval_id: derive_approval_id(&approval).unwrap(),
            approval,
        }
    }

    fn fixture_entry_for_provider(provider_id: String) -> RegistryEntry {
        let mut approval = fixture_approval(&"a".repeat(40));
        approval.provider_id = provider_id;
        RegistryEntry {
            provider_id: approval.provider_id.clone(),
            approval_id: derive_approval_id(&approval).unwrap(),
            approval,
        }
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn first_open_publishes_exact_fixed_authority_files_and_empty_document() {
        let root = temporary_root("initial");
        let registry = ProviderRegistry::open(&root).unwrap();
        assert_eq!(
            std::fs::read(root.join(FORMAT_FILE)).unwrap(),
            b"gorce.provider-data/v1\n"
        );
        assert_eq!(
            std::fs::read(root.join(PROVIDER_REGISTRY_LOCK_FILE)).unwrap(),
            b""
        );
        assert_eq!(
            std::fs::read(root.join(PROVIDER_REGISTRY_FILE)).unwrap(),
            br#"{"entries":[],"format":"gorce.provider/registry/v1","generation":0}"#
        );
        drop(registry);
        cleanup(&root);
    }

    #[test]
    fn lock_contention_is_bounded_and_typed() {
        let root = temporary_root("lock-contention");
        let registry = ProviderRegistry::open(&root).unwrap();
        let held = registry.root.lock(PROVIDER_REGISTRY_LOCK_FILE).unwrap();
        assert!(matches!(
            ProviderRegistry::open(&root),
            Err(RegistryError::LockContention)
        ));
        drop(held);
        drop(registry);
        cleanup(&root);
    }

    #[cfg(windows)]
    const HELPER_READY_TIMEOUT: Duration = Duration::from_secs(5);
    #[cfg(windows)]
    const HELPER_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
    #[cfg(windows)]
    const HELPER_HOLD_TIMEOUT: Duration = Duration::from_secs(15);

    #[cfg(windows)]
    struct LockHelperProcess {
        child: Option<std::process::Child>,
        release: PathBuf,
        root: PathBuf,
    }

    #[cfg(windows)]
    impl LockHelperProcess {
        fn new(child: std::process::Child, release: PathBuf, root: PathBuf) -> Self {
            Self {
                child: Some(child),
                release,
                root,
            }
        }

        fn wait_until_ready(&self, ready: &Path) -> bool {
            let deadline = std::time::Instant::now() + HELPER_READY_TIMEOUT;
            while std::time::Instant::now() < deadline {
                if ready.exists() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            ready.exists()
        }

        fn wait_for_exit(&mut self) -> Option<bool> {
            let deadline = std::time::Instant::now() + HELPER_EXIT_TIMEOUT;
            while std::time::Instant::now() < deadline {
                let child = self.child.as_mut()?;
                match child.try_wait() {
                    Ok(Some(status)) => {
                        self.child.take();
                        return Some(status.success());
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                    Err(_) => return None,
                }
            }
            None
        }

        fn kill_and_reap(&mut self) {
            let Some(mut child) = self.child.take() else {
                return;
            };
            let _ = child.kill();
            let deadline = std::time::Instant::now() + HELPER_EXIT_TIMEOUT;
            while std::time::Instant::now() < deadline {
                match child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                    Err(_) => break,
                }
            }
            let _ = child.wait();
        }

        fn release_and_reap(&mut self) -> bool {
            if std::fs::write(&self.release, b"release").is_err() {
                self.kill_and_reap();
                return false;
            }
            match self.wait_for_exit() {
                Some(success) => success,
                None => {
                    self.kill_and_reap();
                    false
                }
            }
        }
    }

    #[cfg(windows)]
    impl Drop for LockHelperProcess {
        fn drop(&mut self) {
            if self.child.is_some() {
                let _ = std::fs::write(&self.release, b"release");
                if self.wait_for_exit().is_none() {
                    self.kill_and_reap();
                }
            }
            cleanup(&self.root);
        }
    }

    #[cfg(windows)]
    #[test]
    fn process_lock_contention_is_bounded_and_typed() {
        if let Some(root) = std::env::var_os("GORCE_PROVIDER_REGISTRY_LOCK_HELPER_ROOT") {
            let root = PathBuf::from(root);
            let ready = PathBuf::from(
                std::env::var_os("GORCE_PROVIDER_REGISTRY_LOCK_HELPER_READY").unwrap(),
            );
            let release = PathBuf::from(
                std::env::var_os("GORCE_PROVIDER_REGISTRY_LOCK_HELPER_RELEASE").unwrap(),
            );
            let runtime = SecureRuntime::open(&root).unwrap();
            let lock = runtime.lock(PROVIDER_REGISTRY_LOCK_FILE).unwrap();
            std::fs::write(ready, b"ready").unwrap();
            let deadline = std::time::Instant::now() + HELPER_HOLD_TIMEOUT;
            while !release.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            drop(lock);
            if !release.exists() {
                std::process::exit(2);
            }
            return;
        }

        let root = temporary_root("process-lock-contention");
        let registry = ProviderRegistry::open(&root).unwrap();
        drop(registry);
        let ready = root.join(".contention-ready");
        let release = root.join(".contention-release");
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("provider_registry::tests::process_lock_contention_is_bounded_and_typed")
            .arg("--nocapture")
            .env("GORCE_PROVIDER_REGISTRY_LOCK_HELPER_ROOT", &root)
            .env("GORCE_PROVIDER_REGISTRY_LOCK_HELPER_READY", &ready)
            .env("GORCE_PROVIDER_REGISTRY_LOCK_HELPER_RELEASE", &release)
            .spawn()
            .unwrap_or_else(|error| {
                cleanup(&root);
                panic!("failed to spawn lock helper: {error}");
            });
        let mut helper = LockHelperProcess::new(child, release, root);

        assert!(
            helper.wait_until_ready(&ready),
            "lock helper did not positively signal readiness"
        );
        let result = ProviderRegistry::open(&helper.root);
        assert!(matches!(result, Err(RegistryError::LockContention)));
        assert!(helper.release_and_reap());
    }

    #[test]
    fn nonempty_lock_sentinel_is_recovery_needed() {
        let root = temporary_root("nonempty-lock");
        let registry = ProviderRegistry::open(&root).unwrap();
        drop(registry);
        std::fs::write(root.join(PROVIDER_REGISTRY_LOCK_FILE), b"not-empty").unwrap();

        assert!(matches!(
            ProviderRegistry::open(&root),
            Err(RegistryError::RecoveryNeeded(reason))
                if reason.contains("zero-length sentinel")
        ));
        cleanup(&root);
    }

    #[test]
    fn missing_or_partial_state_is_recovery_failure() {
        let root = temporary_root("partial");
        let registry = ProviderRegistry::open(&root).unwrap();
        drop(registry);
        std::fs::remove_file(root.join(PROVIDER_REGISTRY_FILE)).unwrap();
        assert!(matches!(
            ProviderRegistry::open(&root),
            Err(RegistryError::RecoveryNeeded(_))
        ));
        cleanup(&root);
    }

    #[test]
    fn stale_replacement_candidate_is_ignored_until_bounded_cleanup() {
        let root = temporary_root("stale-candidate");
        let registry = ProviderRegistry::open(&root).unwrap();
        drop(registry);
        let runtime = SecureRuntime::open(&root).unwrap();
        runtime
            .replace_private(REGISTRY_TEMP_FILE, b"not-authority")
            .unwrap();
        drop(runtime);

        let registry = ProviderRegistry::open(&root).unwrap();
        let base = gorce_provider_abi::test_verified_source_fixture(
            gorce_provider_abi::TestVerifiedSourceFixture::Base,
        )
        .unwrap();
        assert!(registry.register_source(&base).is_ok());
        assert!(!root.join(REGISTRY_TEMP_FILE).exists());
        drop(registry);
        cleanup(&root);
    }

    #[test]
    fn canonical_document_and_record_recovery_is_strict() {
        let root = temporary_root("strict");
        let registry = ProviderRegistry::open(&root).unwrap();
        let entry = fixture_entry(&"a".repeat(40));
        let document = RegistryDocument {
            format: REGISTRY_FORMAT.to_owned(),
            generation: 0,
            entries: vec![entry.clone()],
        };
        let canonical = canonical_json_bytes(&document).unwrap();
        registry
            .root
            .replace_private(PROVIDER_REGISTRY_FILE, &canonical)
            .unwrap();
        assert!(ProviderRegistry::open(&root).is_ok());
        registry
            .root
            .replace_private(
                PROVIDER_REGISTRY_FILE,
                br#"{"format":"gorce.provider/registry/v1","generation":0,"entries":[]}"#,
            )
            .unwrap();
        assert!(matches!(
            ProviderRegistry::open(&root),
            Err(RegistryError::RecoveryNeeded(_))
        ));
        drop(registry);
        cleanup(&root);
    }

    #[test]
    fn duplicate_unsorted_and_mismatched_entries_fail_closed() {
        let root = temporary_root("ordering");
        let registry = ProviderRegistry::open(&root).unwrap();
        let first = fixture_entry(&"a".repeat(40));
        let mut second = fixture_entry(&"b".repeat(40));
        second.provider_id = "other-provider".to_owned();
        second.approval.provider_id = "other-provider".to_owned();
        second.approval_id = derive_approval_id(&second.approval).unwrap();
        let ordered = if first.provider_id < second.provider_id {
            vec![first.clone(), second.clone()]
        } else {
            vec![second.clone(), first.clone()]
        };
        let write = |entries: Vec<RegistryEntry>| {
            let document = RegistryDocument {
                format: REGISTRY_FORMAT.to_owned(),
                generation: 0,
                entries,
            };
            let bytes = canonical_json_bytes(&document).unwrap();
            registry
                .root
                .replace_private(PROVIDER_REGISTRY_FILE, &bytes)
                .unwrap();
            ProviderRegistry::open(&root).is_err()
        };
        assert!(!write(ordered.clone()));
        assert!(write(ordered.into_iter().rev().collect()));
        assert!(write(vec![first.clone(), first.clone()]));
        let mut mismatch = first;
        mismatch.approval_id = format!("{APPROVAL_ID_PREFIX}{}", "0".repeat(64));
        assert!(write(vec![mismatch]));
        drop(registry);
        cleanup(&root);
    }

    #[test]
    fn two_hundred_fifty_seventh_distinct_provider_is_typed_and_nonpoisoning() {
        let root = temporary_root("record-bound");
        let registry = ProviderRegistry::open(&root).unwrap();
        let entries = (0..=MAX_PROVIDER_REGISTRY_RECORDS)
            .map(|index| fixture_entry_for_provider(format!("provider-{index:03}")))
            .collect();
        let candidate = RegistryDocument {
            format: REGISTRY_FORMAT.to_owned(),
            generation: 1,
            entries,
        };
        assert!(matches!(
            registry.publish_document_for_test(candidate),
            Err(RegistryError::RegistryTooLarge)
        ));
        assert!(registry
            .publish_document_for_test(RegistryDocument::empty())
            .is_ok());
        drop(registry);
        cleanup(&root);
    }

    #[test]
    fn ambiguous_publication_poison_is_fail_closed() {
        let root = temporary_root("poison");
        let registry = ProviderRegistry::open(&root).unwrap();
        registry.inject_publication_fault(true);
        let document = RegistryDocument {
            format: REGISTRY_FORMAT.to_owned(),
            generation: 1,
            entries: Vec::new(),
        };
        assert!(matches!(
            registry.publish_document_for_test(document),
            Err(RegistryError::PublicationAmbiguous(_))
        ));
        assert!(matches!(
            registry.publish_document_for_test(RegistryDocument::empty()),
            Err(RegistryError::Poisoned)
        ));
        let reopened = ProviderRegistry::open(&root).unwrap();
        drop(reopened);
        drop(registry);
        cleanup(&root);
    }

    #[test]
    fn prepublication_io_failure_preserves_health_and_prior_authority() {
        let root = temporary_root("prepublication");
        let registry = ProviderRegistry::open(&root).unwrap();
        std::fs::create_dir(root.join(REGISTRY_TEMP_FILE)).unwrap();
        let source = gorce_provider_abi::test_verified_source_fixture(
            gorce_provider_abi::TestVerifiedSourceFixture::Base,
        )
        .unwrap();

        assert!(matches!(
            registry.register_source(&source),
            Err(RegistryError::RecoveryNeeded(_))
        ));
        assert!(!registry.matches_source(&source).unwrap());
        std::fs::remove_dir(root.join(REGISTRY_TEMP_FILE)).unwrap();
        assert!(registry.register_source(&source).unwrap().changed());
        drop(registry);
        cleanup(&root);
    }

    #[test]
    #[cfg(unix)]
    fn post_validation_replace_failure_preserves_health_and_prior_authority() {
        use std::os::unix::fs::PermissionsExt;

        let root = temporary_root("post-validation-replace-failure");
        let registry = ProviderRegistry::open(&root).unwrap();
        let source = gorce_provider_abi::test_verified_source_fixture(
            gorce_provider_abi::TestVerifiedSourceFixture::Base,
        )
        .unwrap();
        registry.inject_replace_call_failure();

        let failure = registry.register_source(&source);
        assert!(matches!(failure, Err(RegistryError::RecoveryNeeded(_))));
        assert_eq!(
            std::fs::read(root.join(PROVIDER_REGISTRY_FILE)).unwrap(),
            br#"{"entries":[],"format":"gorce.provider/registry/v1","generation":0}"#
        );
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!registry.matches_source(&source).unwrap());
        assert!(registry.register_source(&source).unwrap().changed());
        drop(registry);
        cleanup(&root);
    }

    #[test]
    fn entrypoints_are_sealed_source_only() {
        let _register: fn(
            &ProviderRegistry,
            &VerifiedProviderSource,
        ) -> Result<RegistryRegistration, RegistryError> = ProviderRegistry::register_source;
        let _matches: fn(
            &ProviderRegistry,
            &VerifiedProviderSource,
        ) -> Result<bool, RegistryError> = ProviderRegistry::matches_source;
    }

    #[test]
    fn opaque_verified_source_registration_is_idempotent_replaceable_and_reloadable() {
        let root = temporary_root("opaque-source");
        let first_registry = ProviderRegistry::open(&root).unwrap();
        let second_registry = ProviderRegistry::open(&root).unwrap();
        let base = gorce_provider_abi::test_verified_source_fixture(
            gorce_provider_abi::TestVerifiedSourceFixture::Base,
        )
        .unwrap();
        let replacement = gorce_provider_abi::test_verified_source_fixture(
            gorce_provider_abi::TestVerifiedSourceFixture::Replacement,
        )
        .unwrap();

        first_registry.inject_publication_fault(false);
        assert!(matches!(
            first_registry.register_source(&base),
            Err(RegistryError::FaultInjected("before_registry_replace"))
        ));
        let first = first_registry.register_source(&base).unwrap();
        assert!(first.changed());
        assert_eq!(first.generation(), 1);
        assert!(first.approval_id().starts_with(APPROVAL_ID_PREFIX));
        assert!(first_registry.matches_source(&base).unwrap());
        assert!(!first_registry.matches_source(&replacement).unwrap());

        let retry = second_registry.register_source(&base).unwrap();
        assert!(!retry.changed());
        assert_eq!(retry.generation(), first.generation());
        assert_eq!(retry.approval_id(), first.approval_id());
        assert!(retry.durability().is_none());

        let replaced = second_registry.register_source(&replacement).unwrap();
        assert!(replaced.changed());
        assert_eq!(replaced.generation(), 2);
        assert_ne!(replaced.approval_id(), first.approval_id());
        assert!(!first_registry.matches_source(&base).unwrap());
        assert!(first_registry.matches_source(&replacement).unwrap());

        let document: Value =
            serde_json::from_slice(&std::fs::read(root.join(PROVIDER_REGISTRY_FILE)).unwrap())
                .unwrap();
        let approval = &document["entries"][0]["approval"];
        assert_eq!(approval["publisher_fingerprint"], Value::Null);
        assert!(approval.get("manifest").is_none());
        assert!(approval.get("manifest_bytes").is_none());
        assert!(approval.get("source_path").is_none());
        assert_eq!(document["generation"], 2);

        drop(second_registry);
        drop(first_registry);
        cleanup(&root);
    }

    #[test]
    fn large_abi_valid_schema_source_is_stored_within_document_bound() {
        let root = temporary_root("large-schema");
        let registry = ProviderRegistry::open(&root).unwrap();
        let source = gorce_provider_abi::test_verified_source_fixture(
            gorce_provider_abi::TestVerifiedSourceFixture::LargeSchema,
        )
        .unwrap();
        let schema_bytes = serde_json::to_vec(&source.manifest().tools[0].input_schema).unwrap();
        assert!(schema_bytes.len() > 16 * 1024);
        assert!(schema_bytes.len() <= gorce_provider_abi::MAX_SCHEMA_BYTES);
        let registration = registry.register_source(&source).unwrap();
        assert!(registration.changed());
        assert!(
            std::fs::metadata(root.join(PROVIDER_REGISTRY_FILE))
                .unwrap()
                .len()
                <= MAX_PROVIDER_REGISTRY_BYTES as u64
        );
        let document: Value =
            serde_json::from_slice(&std::fs::read(root.join(PROVIDER_REGISTRY_FILE)).unwrap())
                .unwrap();
        assert!(
            document["entries"][0]["approval"]["capabilities"]["tool_policies"][0]
                .as_str()
                .unwrap()
                .len()
                > 16 * 1024
        );
        assert!(registry.matches_source(&source).unwrap());
        drop(registry);
        cleanup(&root);
    }

    #[test]
    fn concurrent_instances_register_opaque_sources_without_lost_updates() {
        let root = temporary_root("concurrent-opaque");
        let first_registry = Arc::new(ProviderRegistry::open(&root).unwrap());
        let second_registry = Arc::new(ProviderRegistry::open(&root).unwrap());
        let base = gorce_provider_abi::test_verified_source_fixture(
            gorce_provider_abi::TestVerifiedSourceFixture::Base,
        )
        .unwrap();
        let replacement = gorce_provider_abi::test_verified_source_fixture(
            gorce_provider_abi::TestVerifiedSourceFixture::Replacement,
        )
        .unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(3));

        let first_barrier = Arc::clone(&barrier);
        let first_thread_registry = Arc::clone(&first_registry);
        let first_thread = std::thread::spawn(move || {
            first_barrier.wait();
            first_thread_registry.register_source(&base)
        });
        let second_barrier = Arc::clone(&barrier);
        let second_thread_registry = Arc::clone(&second_registry);
        let second_thread = std::thread::spawn(move || {
            second_barrier.wait();
            second_thread_registry.register_source(&replacement)
        });
        barrier.wait();

        let first_result = first_thread.join().unwrap().unwrap();
        let second_result = second_thread.join().unwrap().unwrap();
        let mut generations = [first_result.generation(), second_result.generation()];
        generations.sort_unstable();
        assert_eq!(generations, [1, 2]);
        assert!(first_result.changed());
        assert!(second_result.changed());

        let final_base = first_registry
            .matches_source(
                &gorce_provider_abi::test_verified_source_fixture(
                    gorce_provider_abi::TestVerifiedSourceFixture::Base,
                )
                .unwrap(),
            )
            .unwrap();
        let final_replacement = second_registry
            .matches_source(
                &gorce_provider_abi::test_verified_source_fixture(
                    gorce_provider_abi::TestVerifiedSourceFixture::Replacement,
                )
                .unwrap(),
            )
            .unwrap();
        assert_ne!(final_base, final_replacement);
        drop(second_registry);
        drop(first_registry);
        cleanup(&root);
    }

    #[test]
    fn parallel_unique_roots_open_register_match_and_reload() {
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let first_barrier = Arc::clone(&barrier);
        let first = std::thread::spawn(move || {
            let root = temporary_root("parallel-first");
            let source = gorce_provider_abi::test_verified_source_fixture(
                gorce_provider_abi::TestVerifiedSourceFixture::Base,
            )
            .unwrap();
            first_barrier.wait();
            let registry = ProviderRegistry::open(&root).unwrap();
            assert!(registry.register_source(&source).unwrap().changed());
            assert!(registry.matches_source(&source).unwrap());
            drop(registry);
            let reopened = ProviderRegistry::open(&root).unwrap();
            assert!(reopened.matches_source(&source).unwrap());
            drop(reopened);
            root
        });

        let second_barrier = Arc::clone(&barrier);
        let second = std::thread::spawn(move || {
            let root = temporary_root("parallel-second");
            let source = gorce_provider_abi::test_verified_source_fixture(
                gorce_provider_abi::TestVerifiedSourceFixture::Replacement,
            )
            .unwrap();
            second_barrier.wait();
            let registry = ProviderRegistry::open(&root).unwrap();
            assert!(registry.register_source(&source).unwrap().changed());
            assert!(registry.matches_source(&source).unwrap());
            drop(registry);
            let reopened = ProviderRegistry::open(&root).unwrap();
            assert!(reopened.matches_source(&source).unwrap());
            drop(reopened);
            root
        });

        barrier.wait();
        cleanup(&first.join().unwrap());
        cleanup(&second.join().unwrap());
    }
}
