use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use gorce_protocol::{
    ApiError, AuthorityCommandRequest, CommandCommit, ProjectId, PublicEventBatch,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Ok,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Health {
    pub status: HealthStatus,
    #[serde(default = "unknown_version")]
    pub version: String,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            status: HealthStatus::Degraded,
            version: unknown_version(),
        }
    }
}

fn unknown_version() -> String {
    "unknown".to_owned()
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DaemonDescriptor {
    #[serde(alias = "address")]
    pub endpoint: String,
    pub pid: Option<u32>,
    pub protocol_version: String,
    pub daemon_version: Option<String>,
    pub token_file: Option<PathBuf>,
    pub started_at: Option<String>,
}

impl fmt::Debug for DaemonDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonDescriptor")
            .field("endpoint", &self.endpoint)
            .field("pid", &self.pid)
            .field("protocol_version", &self.protocol_version)
            .field("daemon_version", &self.daemon_version)
            .field("has_token_file", &self.token_file.is_some())
            .field("started_at", &self.started_at)
            .finish()
    }
}

impl DaemonDescriptor {
    pub fn new(endpoint: impl Into<String>, protocol_version: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            protocol_version: protocol_version.into(),
            ..Self::default()
        }
    }
}

pub type CommandRequest = AuthorityCommandRequest;
pub type CommandResponse = CommandCommit;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct OperationResponse {
    pub status: Option<String>,
    pub message: Option<String>,
    pub details: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSnapshot {
    pub project_id: ProjectId,
    pub writer_state: String,
    pub journal_watermark: u64,
    pub index_watermark: u64,
    pub projection_digest: String,
    pub counts: BTreeMap<String, u64>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonMeta {
    pub protocol_version: String,
    pub daemon_version: String,
    pub api_base: String,
    pub address: Option<String>,
    pub project_count: usize,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticCheck {
    pub name: String,
    pub status: DiagnosticStatus,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticReport {
    pub checks: Vec<DiagnosticCheck>,
}

impl DiagnosticReport {
    pub fn is_healthy(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.status != DiagnosticStatus::Fail)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventStreamItem {
    Event(gorce_protocol::PublicEvent),
    Snapshot(PublicEventBatch),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectContext {
    pub project_id: ProjectId,
    pub root: PathBuf,
}

#[derive(Clone, PartialEq)]
pub struct ApiFailure {
    pub status: u16,
    pub error: ApiError,
}

impl fmt::Debug for ApiFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiFailure")
            .field("status", &self.status)
            .finish()
    }
}
