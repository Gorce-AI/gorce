use gorce_protocol::{
    BlobRef, EvidenceBundle, EvidenceItem, EvidenceKind, TaskAttemptId, TaskId, TaskRevisionId,
};
use uuid::Uuid;

use crate::agent::BoxFuture;
use crate::error::{AgentError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualityRequirement {
    EvidenceKind(EvidenceKind),
    SummaryContains(String),
    MinimumEvidence(usize),
    ToolResultSucceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityGate {
    pub requirements: Vec<QualityRequirement>,
    pub minimum_score: u8,
}

impl Default for QualityGate {
    fn default() -> Self {
        Self {
            requirements: Vec::new(),
            minimum_score: 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceContext {
    pub project_id: Uuid,
    pub task_id: TaskId,
    pub attempt_id: TaskAttemptId,
    pub task_revision_id: TaskRevisionId,
    pub revision: u64,
    pub created_at: String,
    pub created_at_ms: u64,
    pub producer: Uuid,
    pub immutable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedEvidenceBundle {
    pub bundle: EvidenceBundle,
    pub context: EvidenceContext,
    pub tool_results: Vec<ToolEvidence>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolEvidence {
    pub call_id: String,
    pub status: ToolEvidenceStatus,
    pub result_hash: String,
    pub blob: Option<BlobRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolEvidenceStatus {
    Succeeded,
    Failed,
    UnknownSideEffect,
}

impl ValidatedEvidenceBundle {
    pub fn validate(
        &self,
        expected: &EvidenceContext,
        now: &str,
        max_age_ms: Option<u64>,
    ) -> Result<()> {
        if self.bundle.id.is_nil()
            || self.bundle.project_id != expected.project_id
            || self.bundle.task_id != expected.task_id
            || self.bundle.attempt_id != expected.attempt_id
            || self.context != expected.clone()
            || !self.context.immutable
            || self.context.producer.is_nil()
            || self.context.created_at.trim().is_empty()
        {
            return Err(AgentError::Conflict(
                "evidence reference does not match the task attempt context".to_owned(),
            ));
        }
        if let Ok(now_ms) = now.parse::<u64>() {
            if now_ms < self.context.created_at_ms {
                return Err(AgentError::Conflict(
                    "evidence timestamp is in the future".to_owned(),
                ));
            }
        }
        if let Some(max_age_ms) = max_age_ms {
            let now_ms = now.parse::<u64>().map_err(|_| {
                AgentError::InvalidInput(
                    "freshness validation requires a daemon millisecond clock".to_owned(),
                )
            })?;
            if now_ms.saturating_sub(self.context.created_at_ms) > max_age_ms {
                return Err(AgentError::Conflict("evidence is stale".to_owned()));
            }
        }
        for item in &self.bundle.items {
            if let Some(blob) = &item.blob {
                blob.validate()
                    .map_err(|error| AgentError::InvalidInput(error.to_string()))?;
            } else if item.uri.is_none() {
                return Err(AgentError::Conflict(
                    "summary-only evidence is not admissible".to_owned(),
                ));
            }
            if item
                .uri
                .as_ref()
                .is_some_and(|uri| uri.trim().is_empty() || uri.chars().any(char::is_control))
            {
                return Err(AgentError::Conflict(
                    "evidence URI is not an immutable reference".to_owned(),
                ));
            }
        }
        for result in &self.tool_results {
            if result.call_id.trim().is_empty() || !result.result_hash.starts_with("sha256:") {
                return Err(AgentError::Conflict(
                    "tool evidence requires a real result hash".to_owned(),
                ));
            }
            if let Some(blob) = &result.blob {
                blob.validate()
                    .map_err(|error| AgentError::InvalidInput(error.to_string()))?;
                if blob.digest.as_str() != result.result_hash.as_str() {
                    return Err(AgentError::Conflict(
                        "tool evidence blob hash mismatch".to_owned(),
                    ));
                }
            }
            if result.status == ToolEvidenceStatus::UnknownSideEffect {
                return Err(AgentError::NeedsReconciliation(
                    "unknown tool side effects cannot satisfy a gate".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

pub trait EvidencePort: Send + Sync {
    fn persist(&self, evidence: ValidatedEvidenceBundle) -> BoxFuture<Result<()>>;
}

pub trait GateEvaluationPort: Send + Sync {
    fn evaluate(
        &self,
        gate: QualityGate,
        evidence: ValidatedEvidenceBundle,
    ) -> BoxFuture<Result<QualityEvaluation>>;
}

pub trait IndependentReviewPort: Send + Sync {
    fn review(&self, evidence: ValidatedEvidenceBundle) -> BoxFuture<Result<IndependentReview>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndependentReview {
    pub evaluator: Uuid,
    pub evaluation: QualityEvaluation,
}

pub trait EvaluationPort: Send + Sync {
    fn persist_evaluation(&self, evaluation: QualityEvaluation) -> BoxFuture<Result<()>>;
}

impl QualityGate {
    pub fn new(minimum_score: u8) -> Self {
        Self {
            minimum_score: minimum_score.min(100),
            ..Self::default()
        }
    }

    pub fn require(mut self, requirement: QualityRequirement) -> Self {
        self.requirements.push(requirement);
        self
    }

    pub fn evaluate(&self, bundle: &EvidenceBundle) -> QualityEvaluation {
        let mut failures = Vec::new();
        if bundle.items.is_empty()
            || bundle
                .items
                .iter()
                .any(|item| item.blob.is_none() && item.uri.is_none())
        {
            failures.push(QualityRequirement::MinimumEvidence(1));
        }
        for requirement in &self.requirements {
            let satisfied = match requirement {
                QualityRequirement::EvidenceKind(kind) => {
                    bundle.items.iter().any(|item| item.kind == kind.clone())
                }
                QualityRequirement::SummaryContains(text) => bundle.items.iter().any(|item| {
                    item.summary.contains(text) && (item.blob.is_some() || item.uri.is_some())
                }),
                QualityRequirement::MinimumEvidence(count) => {
                    bundle
                        .items
                        .iter()
                        .filter(|item| item.blob.is_some() || item.uri.is_some())
                        .count()
                        >= *count
                }
                QualityRequirement::ToolResultSucceeded => false,
            };
            if !satisfied {
                failures.push(requirement.clone());
            }
        }
        let score = if self.requirements.is_empty() && failures.is_empty() {
            100
        } else {
            let total = self
                .requirements
                .len()
                .saturating_add(if failures.is_empty() { 0 } else { 1 })
                .max(1);
            (((total.saturating_sub(failures.len())) * 100) / total) as u8
        };
        QualityEvaluation {
            passed: failures.is_empty() && score >= self.minimum_score,
            score,
            failures,
        }
    }

    pub fn evaluate_bundle(&self, bundle: &EvidenceBundle) -> QualityEvaluation {
        self.evaluate(bundle)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityEvaluation {
    pub passed: bool,
    pub score: u8,
    pub failures: Vec<QualityRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedEvaluation {
    pub id: Uuid,
    pub project_id: Uuid,
    pub task_id: TaskId,
    pub attempt_id: TaskAttemptId,
    pub task_revision_id: TaskRevisionId,
    pub revision: u64,
    pub producer: Uuid,
    pub independent: bool,
    pub evaluation: QualityEvaluation,
}

pub fn evidence_item(kind: EvidenceKind, summary: impl Into<String>) -> EvidenceItem {
    EvidenceItem {
        kind,
        summary: summary.into(),
        blob: None,
        uri: None,
    }
}

pub fn evidence_item_reference(
    kind: EvidenceKind,
    summary: impl Into<String>,
    uri: impl Into<String>,
) -> Result<EvidenceItem> {
    let uri = uri.into();
    if uri.trim().is_empty() {
        return Err(AgentError::InvalidInput(
            "evidence URI must not be empty".to_owned(),
        ));
    }
    Ok(EvidenceItem {
        kind,
        summary: summary.into(),
        blob: None,
        uri: Some(uri),
    })
}

pub fn immutable_producer(producer: Uuid) -> Result<()> {
    if producer.is_nil() {
        return Err(AgentError::InvalidInput(
            "evidence producer must not be nil".to_owned(),
        ));
    }
    Ok(())
}
