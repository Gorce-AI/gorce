#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "0.1";
pub const API_BASE_PATH: &str = "/v0";
pub const EVENT_BATCH_FORMAT: &str = "gorce.event-batch/v1";
pub const MAX_EVENT_COUNT: usize = 1_024;
pub const MAX_EVENT_TYPE_BYTES: usize = 128;
pub const MAX_EVENT_DATA_BYTES: usize = 1_048_576;
pub const MAX_TOTAL_EVENT_DATA_BYTES: usize = 8 * 1_048_576;
pub const MAX_COMMAND_NAME_BYTES: usize = 128;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
pub const MAX_COMMAND_ARGUMENT_BYTES: usize = 1_048_576;
pub const MAX_REFERENCED_BLOBS: usize = 1_024;
pub const MAX_BLOB_SIZE_BYTES: u64 = 1_073_741_824;
pub const MAX_MEDIA_TYPE_BYTES: usize = 255;
pub const MAX_FILENAME_BYTES: usize = 255;
pub const MAX_TIMESTAMP_BYTES: usize = 64;
pub const MAX_PUBLIC_EVENT_COUNT: usize = 500;
pub const MAX_PUBLIC_EVENT_PAYLOAD_BYTES: usize = 1_048_576;

pub type ProjectId = Uuid;
pub type WorkstreamId = Uuid;
pub type GoalRevisionId = Uuid;
pub type PlanRevisionId = Uuid;
pub type TaskId = Uuid;
pub type TaskRevisionId = Uuid;
pub type TaskEdgeId = Uuid;
pub type TaskAttemptId = Uuid;
pub type LeaseId = Uuid;
pub type OperatorId = Uuid;
pub type SkillManifestId = Uuid;
pub type PermissionRequestId = Uuid;
pub type ContextBundleId = Uuid;
pub type EvidenceBundleId = Uuid;
pub type AttachmentId = Uuid;
pub type MessageId = Uuid;
pub type GoalId = Uuid;
pub type PlanId = Uuid;
pub type PlanItemId = Uuid;
pub type EventBatchId = UuidV7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UuidV7(Uuid);

impl UuidV7 {
    pub fn from_uuid(value: Uuid) -> Option<Self> {
        let bytes = value.as_bytes();
        (bytes[6] >> 4 == 7 && bytes[8] & 0xc0 == 0x80).then_some(Self(value))
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    pub fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl Serialize for UuidV7 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.hyphenated().to_string())
    }
}

impl<'de> Deserialize<'de> for UuidV7 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let uuid = Uuid::parse_str(&value).map_err(<D::Error as serde::de::Error>::custom)?;
        Self::from_uuid(uuid)
            .ok_or_else(|| <D::Error as serde::de::Error>::custom("UUID is not version 7"))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobRef {
    pub digest: String,
    pub size_bytes: u64,
    pub media_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

impl BlobRef {
    pub fn validate(&self) -> Result<(), BlobRefValidationError> {
        if !is_sha256_digest(&self.digest) {
            return Err(BlobRefValidationError(
                "digest must match sha256:<64 lowercase hexadecimal characters>".to_owned(),
            ));
        }
        if self.size_bytes > MAX_BLOB_SIZE_BYTES {
            return Err(BlobRefValidationError(format!(
                "size_bytes exceeds {MAX_BLOB_SIZE_BYTES}"
            )));
        }
        if self.media_type.is_empty() || self.media_type.len() > MAX_MEDIA_TYPE_BYTES {
            return Err(BlobRefValidationError(format!(
                "media_type must contain 1..={MAX_MEDIA_TYPE_BYTES} bytes"
            )));
        }
        if self.media_type.chars().any(char::is_control) {
            return Err(BlobRefValidationError(
                "media_type must not contain control characters".to_owned(),
            ));
        }
        if self
            .filename
            .as_ref()
            .is_some_and(|filename| filename.is_empty() || filename.len() > MAX_FILENAME_BYTES)
        {
            return Err(BlobRefValidationError(format!(
                "filename must contain 1..={MAX_FILENAME_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRefValidationError(String);

impl std::fmt::Display for BlobRefValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BlobRefValidationError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventActorKind {
    Human,
    Agent,
    Service,
    System,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventActor {
    pub kind: EventActorKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_id: Option<OperatorId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventCommand {
    pub name: String,
    pub arguments: Value,
    pub idempotency_key: String,
}

impl EventCommand {
    pub fn validate(&self) -> Result<(), EventCommandValidationError> {
        if self.name.is_empty() || self.name.len() > MAX_COMMAND_NAME_BYTES {
            return Err(EventCommandValidationError(
                "name must contain 1..=128 bytes".to_owned(),
            ));
        }
        if !is_valid_idempotency_key(&self.idempotency_key) {
            return Err(EventCommandValidationError(
                "idempotency_key must contain 1..=256 bytes".to_owned(),
            ));
        }
        let argument_bytes = json_size(&self.arguments).map_err(|error| {
            EventCommandValidationError(format!("arguments cannot be serialized: {error}"))
        })?;
        if argument_bytes > MAX_COMMAND_ARGUMENT_BYTES {
            return Err(EventCommandValidationError(format!(
                "arguments exceed {MAX_COMMAND_ARGUMENT_BYTES} serialized bytes"
            )));
        }
        Ok(())
    }

    /// Returns the bytes to hash for command idempotency comparisons.
    pub fn canonical_payload_digest_input(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut payload = BTreeMap::new();
        payload.insert("arguments", self.arguments.clone());
        payload.insert("name", Value::String(self.name.clone()));
        serde_json::to_vec(&payload)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventCommandValidationError(String);

impl std::fmt::Display for EventCommandValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for EventCommandValidationError {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRecord {
    pub ordinal: u64,
    #[serde(rename = "type")]
    pub event_type: String,
    pub schema_version: u64,
    pub data: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatch {
    #[serde(rename = "format")]
    pub format: String,
    pub project_id: ProjectId,
    pub batch_id: EventBatchId,
    pub batch_sequence: u64,
    pub committed_at: String,
    pub actor: EventActor,
    pub command: EventCommand,
    pub base_revisions: BTreeMap<String, u64>,
    pub events: Vec<EventRecord>,
    /// The authoritative manifest of blob references used by typed event payloads.
    pub referenced_blobs: Vec<BlobRef>,
}

impl EventBatch {
    pub fn validate(&self) -> Result<(), EventBatchValidationError> {
        if self.format != EVENT_BATCH_FORMAT {
            return Err(EventBatchValidationError(format!(
                "format must be {EVENT_BATCH_FORMAT}"
            )));
        }
        if self.batch_sequence == 0 {
            return Err(EventBatchValidationError(
                "batch_sequence must be at least 1".to_owned(),
            ));
        }
        if !is_valid_timestamp(&self.committed_at) {
            return Err(EventBatchValidationError(
                "committed_at must be an RFC 3339 timestamp".to_owned(),
            ));
        }
        self.command
            .validate()
            .map_err(|error| EventBatchValidationError(format!("command: {error}")))?;
        if self.events.is_empty() {
            return Err(EventBatchValidationError(
                "events must contain at least one event".to_owned(),
            ));
        }
        if self.events.len() > MAX_EVENT_COUNT {
            return Err(EventBatchValidationError(format!(
                "events must contain at most {MAX_EVENT_COUNT} events"
            )));
        }

        let mut total_data_bytes = 0usize;
        for (expected_ordinal, event) in self.events.iter().enumerate() {
            let expected_ordinal = u64::try_from(expected_ordinal).map_err(|_| {
                EventBatchValidationError("event ordinal cannot be represented".to_owned())
            })?;
            if event.ordinal != expected_ordinal {
                return Err(EventBatchValidationError(format!(
                    "event ordinal at index {expected_ordinal} must be {expected_ordinal}, got {}",
                    event.ordinal
                )));
            }
            if !is_valid_event_name(&event.event_type, MAX_EVENT_TYPE_BYTES) {
                return Err(EventBatchValidationError(format!(
                    "event {expected_ordinal} type must match ^[a-z][a-z0-9_.-]*$ and be at most {MAX_EVENT_TYPE_BYTES} bytes"
                )));
            }
            if event.schema_version == 0 {
                return Err(EventBatchValidationError(format!(
                    "event {expected_ordinal} schema_version must be at least 1"
                )));
            }
            let data_bytes = json_size(&event.data).map_err(|error| {
                EventBatchValidationError(format!(
                    "event {expected_ordinal} data cannot be serialized: {error}"
                ))
            })?;
            if data_bytes > MAX_EVENT_DATA_BYTES {
                return Err(EventBatchValidationError(format!(
                    "event {expected_ordinal} data exceeds {MAX_EVENT_DATA_BYTES} serialized bytes"
                )));
            }
            total_data_bytes = total_data_bytes.checked_add(data_bytes).ok_or_else(|| {
                EventBatchValidationError("total event data size overflowed".to_owned())
            })?;
        }
        if total_data_bytes > MAX_TOTAL_EVENT_DATA_BYTES {
            return Err(EventBatchValidationError(format!(
                "total event data exceeds {MAX_TOTAL_EVENT_DATA_BYTES} serialized bytes"
            )));
        }

        if self.referenced_blobs.len() > MAX_REFERENCED_BLOBS {
            return Err(EventBatchValidationError(format!(
                "referenced_blobs must contain at most {MAX_REFERENCED_BLOBS} references"
            )));
        }
        let mut digests = std::collections::BTreeSet::new();
        for (index, blob) in self.referenced_blobs.iter().enumerate() {
            blob.validate().map_err(|error| {
                EventBatchValidationError(format!("referenced_blobs[{index}]: {error}"))
            })?;
            if !digests.insert(&blob.digest) {
                return Err(EventBatchValidationError(format!(
                    "referenced_blobs[{index}] duplicates digest {}",
                    blob.digest
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventBatchValidationError(String);

impl std::fmt::Display for EventBatchValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for EventBatchValidationError {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub id: ProjectId,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkstreamStatus {
    Active,
    Archived,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workstream {
    pub id: WorkstreamId,
    pub project_id: ProjectId,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub status: WorkstreamStatus,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionStatus {
    Draft,
    Proposed,
    Approved,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalRevision {
    pub id: GoalRevisionId,
    pub goal_id: GoalId,
    pub project_id: ProjectId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workstream_id: Option<WorkstreamId>,
    pub revision: u64,
    pub title: String,
    pub statement: String,
    pub revision_hash: String,
    pub status: RevisionStatus,
    pub created_by: OperatorId,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRevision {
    pub id: PlanRevisionId,
    pub plan_id: PlanId,
    pub project_id: ProjectId,
    pub goal_revision_id: GoalRevisionId,
    pub revision: u64,
    pub revision_hash: String,
    pub summary: String,
    pub items: Vec<PlanItem>,
    pub promotion_mappings: Vec<PromotionMapping>,
    pub status: RevisionStatus,
    pub created_by: OperatorId,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalLinkRelation {
    Supports,
    DerivedFrom,
    Validates,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalLink {
    pub goal_id: GoalId,
    pub goal_revision_id: GoalRevisionId,
    pub relation: GoalLinkRelation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanItem {
    pub id: PlanItemId,
    pub title: String,
    pub goal_links: Vec<GoalLink>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_revision_id: Option<TaskRevisionId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionDisposition {
    #[serde(rename = "CREATE")]
    Create,
    #[serde(rename = "REUSE")]
    Reuse,
    #[serde(rename = "REVISE")]
    Revise,
    #[serde(rename = "KEEP")]
    Keep,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionMapping {
    pub plan_item_id: PlanItemId,
    pub disposition: PromotionDisposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_revision_id: Option<TaskRevisionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_revision_id: Option<TaskRevisionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskLifecycle {
    Open,
    Waiting,
    Deferred,
    Completed,
    Cancelled,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub id: TaskId,
    pub project_id: ProjectId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workstream_id: Option<WorkstreamId>,
    pub lifecycle: TaskLifecycle,
    pub readiness: TaskReadiness,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_revision_id: Option<TaskRevisionId>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    Ready,
    Blocked,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskReadiness {
    pub status: ReadinessStatus,
    pub blocker_task_ids: Vec<TaskId>,
    pub evaluated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRevision {
    pub id: TaskRevisionId,
    pub task_id: TaskId,
    pub revision: u64,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub acceptance_criteria: Vec<String>,
    pub goal_links: Vec<GoalLink>,
    pub revision_hash: String,
    pub created_by: OperatorId,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskEdgeKind {
    Parent,
    Dependency,
    Supersedes,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskEdge {
    pub id: TaskEdgeId,
    pub project_id: ProjectId,
    pub from_task_id: TaskId,
    pub to_task_id: TaskId,
    pub kind: TaskEdgeKind,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAttemptStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    NeedsReconciliation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttempt {
    pub id: TaskAttemptId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub task_revision_id: TaskRevisionId,
    pub operator_id: OperatorId,
    pub status: TaskAttemptStatus,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_bundle_id: Option<EvidenceBundleId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub id: LeaseId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub holder_operator_id: OperatorId,
    pub acquired_at: String,
    pub expires_at: String,
    pub fencing_token: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorKind {
    Human,
    Agent,
    Service,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorStatus {
    Active,
    Suspended,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorProfile {
    pub id: OperatorId,
    pub display_name: String,
    pub kind: OperatorKind,
    pub status: OperatorStatus,
    pub skills: Vec<String>,
    pub permission_scopes: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillManifest {
    pub id: SkillManifestId,
    pub operator_id: OperatorId,
    pub name: String,
    pub version: String,
    pub skills: Vec<String>,
    pub capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionRequestStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionRequest {
    pub id: PermissionRequestId,
    pub project_id: ProjectId,
    pub operator_id: OperatorId,
    pub action: String,
    pub resource: String,
    pub reason: String,
    pub status: PermissionRequestStatus,
    pub requested_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<OperatorId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextItem {
    pub label: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextBundle {
    pub id: ContextBundleId,
    pub project_id: ProjectId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
    pub items: Vec<ContextItem>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    TestResult,
    Log,
    Screenshot,
    Note,
    Artifact,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceItem {
    pub kind: EvidenceKind,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<BlobRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundle {
    pub id: EvidenceBundleId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub attempt_id: TaskAttemptId,
    pub items: Vec<EvidenceItem>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    pub id: AttachmentId,
    pub project_id: ProjectId,
    pub blob: BlobRef,
    pub filename: String,
    pub media_type: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    User,
    Operator,
    Assistant,
    System,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MessagePart {
    Text { text: String },
    Blob { blob: BlobRef },
    ToolCall { name: String, arguments: Value },
    ToolResult { call_id: String, output: Value },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub id: MessageId,
    pub project_id: ProjectId,
    pub sender_operator_id: OperatorId,
    pub role: MessageRole,
    pub parts: Vec<MessagePart>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicEventCursor(pub String);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEvent {
    pub id: Uuid,
    pub project_id: ProjectId,
    pub sequence: u64,
    pub event_type: String,
    pub occurred_at: String,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEventBatch {
    pub cursor: PublicEventCursor,
    pub events: Vec<PublicEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<PublicEventCursor>,
    pub has_more: bool,
}

pub type PublicEventPage = PublicEventBatch;

impl PublicEvent {
    pub fn validate(&self) -> Result<(), PublicEventValidationError> {
        if self.sequence == 0 {
            return Err(PublicEventValidationError(
                "sequence must be at least 1".to_owned(),
            ));
        }
        if !is_valid_event_name(&self.event_type, MAX_EVENT_TYPE_BYTES) {
            return Err(PublicEventValidationError(
                "event_type must match ^[a-z][a-z0-9_.-]*$ and be at most 128 bytes".to_owned(),
            ));
        }
        if !is_valid_timestamp(&self.occurred_at) {
            return Err(PublicEventValidationError(
                "occurred_at must be an RFC 3339 timestamp".to_owned(),
            ));
        }
        if !self.payload.is_object() {
            return Err(PublicEventValidationError(
                "payload must be an object".to_owned(),
            ));
        }
        let payload_bytes = json_size(&self.payload).map_err(|error| {
            PublicEventValidationError(format!("payload cannot be serialized: {error}"))
        })?;
        if payload_bytes > MAX_PUBLIC_EVENT_PAYLOAD_BYTES {
            return Err(PublicEventValidationError(format!(
                "payload exceeds {MAX_PUBLIC_EVENT_PAYLOAD_BYTES} serialized bytes"
            )));
        }
        Ok(())
    }
}

impl PublicEventBatch {
    pub fn validate(&self) -> Result<(), PublicEventValidationError> {
        if !is_valid_cursor(&self.cursor.0) {
            return Err(PublicEventValidationError(
                "cursor must contain 1..=512 bytes".to_owned(),
            ));
        }
        if self.events.len() > MAX_PUBLIC_EVENT_COUNT {
            return Err(PublicEventValidationError(format!(
                "events must contain at most {MAX_PUBLIC_EVENT_COUNT} events"
            )));
        }
        for event in &self.events {
            event.validate()?;
        }
        if self.has_more && self.next_cursor.is_none() {
            return Err(PublicEventValidationError(
                "next_cursor is required when has_more is true".to_owned(),
            ));
        }
        if let Some(next_cursor) = &self.next_cursor {
            if !is_valid_cursor(&next_cursor.0) {
                return Err(PublicEventValidationError(
                    "next_cursor must contain 1..=512 bytes".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicEventValidationError(String);

impl std::fmt::Display for PublicEventValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PublicEventValidationError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    PreconditionFailed,
    RateLimited,
    ServiceNotReady,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

pub fn protocol_version() -> &'static str {
    PROTOCOL_VERSION
}

fn json_size(value: &Value) -> Result<usize, serde_json::Error> {
    Ok(serde_json::to_vec(value)?.len())
}

fn is_sha256_digest(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 71
        && bytes.starts_with(b"sha256:")
        && bytes[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn is_valid_event_name(value: &str, max_bytes: usize) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= max_bytes
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(byte))
}

fn is_valid_idempotency_key(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDEMPOTENCY_KEY_BYTES
}

fn is_valid_cursor(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte))
}

fn is_valid_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_TIMESTAMP_BYTES || bytes.len() < 20 {
        return false;
    }
    if !(is_digits(&bytes[0..4])
        && bytes[4] == b'-'
        && is_digits(&bytes[5..7])
        && bytes[7] == b'-'
        && is_digits(&bytes[8..10])
        && (bytes[10] == b'T' || bytes[10] == b't')
        && is_digits(&bytes[11..13])
        && bytes[13] == b':'
        && is_digits(&bytes[14..16])
        && bytes[16] == b':'
        && is_digits(&bytes[17..19]))
    {
        return false;
    }
    let hour = two_digits(&bytes[11..13]);
    let minute = two_digits(&bytes[14..16]);
    let second = two_digits(&bytes[17..19]);
    let year = four_digits(&bytes[0..4]);
    let month = two_digits(&bytes[5..7]);
    let day = two_digits(&bytes[8..10]);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) => 29,
        2 => 28,
        _ => 0,
    };
    if month == 0 || day == 0 || day > days_in_month || hour > 23 || minute > 59 || second > 59 {
        return false;
    }

    let mut index = 19;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let fraction_start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if fraction_start == index {
            return false;
        }
    }
    match bytes.get(index) {
        Some(b'Z') | Some(b'z') => index + 1 == bytes.len(),
        Some(b'+') | Some(b'-') => {
            index + 6 == bytes.len()
                && is_digits(&bytes[index + 1..index + 3])
                && bytes[index + 3] == b':'
                && is_digits(&bytes[index + 4..index + 6])
                && two_digits(&bytes[index + 1..index + 3]) <= 23
                && two_digits(&bytes[index + 4..index + 6]) <= 59
        }
        _ => false,
    }
}

fn is_digits(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().all(u8::is_ascii_digit)
}

fn two_digits(value: &[u8]) -> u8 {
    (value[0] - b'0') * 10 + value[1] - b'0'
}

fn four_digits(value: &[u8]) -> u16 {
    u16::from(value[0] - b'0') * 1_000
        + u16::from(value[1] - b'0') * 100
        + u16::from(value[2] - b'0') * 10
        + u16::from(value[3] - b'0')
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        protocol_version, BlobRef, EventActor, EventActorKind, EventBatch, EventCommand,
        EventRecord, PublicEventBatch, PublicEventCursor, UuidV7, EVENT_BATCH_FORMAT,
        PROTOCOL_VERSION,
    };
    use uuid::Uuid;

    fn valid_batch() -> EventBatch {
        let project_id = Uuid::parse_str("018f0f5e-7b12-7abc-8def-0123456789ab").unwrap();
        let batch_id =
            UuidV7::from_uuid(Uuid::parse_str("018f0f5e-7b12-7abd-8def-0123456789ab").unwrap())
                .unwrap();
        EventBatch {
            format: EVENT_BATCH_FORMAT.to_owned(),
            project_id,
            batch_id,
            batch_sequence: 1,
            committed_at: "2026-01-01T00:00:00Z".to_owned(),
            actor: EventActor {
                kind: EventActorKind::System,
                operator_id: None,
            },
            command: EventCommand {
                name: "task.create".to_owned(),
                arguments: serde_json::json!({}),
                idempotency_key: "idem_01hqz7b4m9r7".to_owned(),
            },
            base_revisions: BTreeMap::new(),
            events: vec![EventRecord {
                ordinal: 0,
                event_type: "task.created".to_owned(),
                schema_version: 1,
                data: serde_json::json!({"task_id": project_id}),
            }],
            referenced_blobs: Vec::new(),
        }
    }

    fn valid_blob() -> BlobRef {
        BlobRef {
            digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            size_bytes: 42,
            media_type: "text/plain".to_owned(),
            filename: Some("notes.txt".to_owned()),
        }
    }

    #[test]
    fn exposes_the_protocol_version() {
        assert_eq!(protocol_version(), PROTOCOL_VERSION);
    }

    #[test]
    fn canonical_event_batch_round_trips_through_json() {
        let batch = valid_batch();

        let encoded = serde_json::to_string(&batch).unwrap();
        let decoded: EventBatch = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, batch);
        batch.validate().unwrap();
    }

    #[test]
    fn canonical_payload_digest_input_is_deterministic_and_excludes_key() {
        let mut first = valid_batch().command;
        let mut second = first.clone();
        second.idempotency_key = "another-key".to_owned();
        assert_eq!(
            first.canonical_payload_digest_input().unwrap(),
            second.canonical_payload_digest_input().unwrap()
        );
        assert_eq!(
            first.canonical_payload_digest_input().unwrap(),
            br#"{"arguments":{},"name":"task.create"}"#
        );
        first.arguments = serde_json::json!({"changed": true});
        assert_ne!(
            first.canonical_payload_digest_input().unwrap(),
            second.canonical_payload_digest_input().unwrap()
        );
    }

    #[test]
    fn canonical_validation_rejects_empty_events() {
        let mut batch = valid_batch();
        batch.events.clear();
        assert!(batch.validate().is_err());
    }

    #[test]
    fn canonical_validation_rejects_ordinal_gaps_and_duplicates() {
        let mut gap = valid_batch();
        gap.events.push(EventRecord {
            ordinal: 2,
            event_type: "task.updated".to_owned(),
            schema_version: 1,
            data: serde_json::json!({}),
        });
        assert!(gap.validate().is_err());

        let mut duplicate = valid_batch();
        duplicate.events.push(EventRecord {
            ordinal: 0,
            event_type: "task.updated".to_owned(),
            schema_version: 1,
            data: serde_json::json!({}),
        });
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn canonical_validation_rejects_zero_schema_version_and_invalid_event_type() {
        let mut zero_version = valid_batch();
        zero_version.events[0].schema_version = 0;
        assert!(zero_version.validate().is_err());

        let mut invalid_type = valid_batch();
        invalid_type.events[0].event_type = "Task.Created".to_owned();
        assert!(invalid_type.validate().is_err());

        let mut invalid_timestamp = valid_batch();
        invalid_timestamp.committed_at = "2026-02-30T00:00:00Z".to_owned();
        assert!(invalid_timestamp.validate().is_err());
    }

    #[test]
    fn canonical_deserialization_rejects_missing_idempotency_key() {
        let mut value = serde_json::to_value(valid_batch()).unwrap();
        value["command"]
            .as_object_mut()
            .unwrap()
            .remove("idempotency_key");
        assert!(serde_json::from_value::<EventBatch>(value).is_err());

        let mut empty = valid_batch();
        empty.command.idempotency_key.clear();
        assert!(empty.validate().is_err());
    }

    #[test]
    fn canonical_validation_rejects_duplicate_and_invalid_blob_references() {
        let mut duplicate = valid_batch();
        let blob = valid_blob();
        blob.validate().unwrap();
        duplicate.referenced_blobs = vec![blob.clone(), blob];
        assert!(duplicate.validate().is_err());

        let mut invalid = valid_batch();
        invalid.referenced_blobs = vec![BlobRef {
            digest: "not-a-digest".to_owned(),
            ..valid_blob()
        }];
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn public_event_batch_is_distinct_from_canonical_batch() {
        let page = PublicEventBatch {
            cursor: PublicEventCursor("cursor-1".to_owned()),
            events: Vec::new(),
            next_cursor: None,
            has_more: false,
        };

        let encoded = serde_json::to_string(&page).unwrap();
        assert!(serde_json::from_str::<EventBatch>(&encoded).is_err());
        assert_eq!(
            serde_json::from_str::<PublicEventBatch>(&encoded).unwrap(),
            page
        );
        page.validate().unwrap();
    }

    #[test]
    fn unknown_canonical_event_batch_fields_are_rejected() {
        let value = serde_json::json!({"format": EVENT_BATCH_FORMAT, "unexpected": true});
        assert!(serde_json::from_value::<EventBatch>(value).is_err());
    }

    #[test]
    fn uuidv7_rejects_non_v7_values() {
        let value = serde_json::json!("018f0f5e-7b12-4abc-8def-0123456789ab");
        assert!(serde_json::from_value::<UuidV7>(value).is_err());
    }
}
