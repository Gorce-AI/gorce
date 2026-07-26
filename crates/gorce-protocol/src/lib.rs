#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "0.1";
pub const API_BASE_PATH: &str = "/v0";
pub const EVENT_BATCH_FORMAT: &str = "gorce.event-batch/v1";

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

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
}

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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        protocol_version, EventActor, EventActorKind, EventBatch, EventCommand, EventRecord,
        PublicEventBatch, PublicEventCursor, UuidV7, EVENT_BATCH_FORMAT, PROTOCOL_VERSION,
    };
    use uuid::Uuid;

    #[test]
    fn exposes_the_protocol_version() {
        assert_eq!(protocol_version(), PROTOCOL_VERSION);
    }

    #[test]
    fn canonical_event_batch_round_trips_through_json() {
        let project_id = Uuid::parse_str("018f0f5e-7b12-7abc-8def-0123456789ab").unwrap();
        let batch_id =
            UuidV7::from_uuid(Uuid::parse_str("018f0f5e-7b12-7abd-8def-0123456789ab").unwrap())
                .unwrap();
        let batch = EventBatch {
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
                request_id: None,
            },
            base_revisions: BTreeMap::new(),
            events: vec![EventRecord {
                ordinal: 0,
                event_type: "task.created".to_owned(),
                schema_version: 1,
                data: serde_json::json!({"task_id": project_id}),
            }],
        };

        let encoded = serde_json::to_string(&batch).unwrap();
        let decoded: EventBatch = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, batch);
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
