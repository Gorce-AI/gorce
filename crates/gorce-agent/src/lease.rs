use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use gorce_protocol::{
    Lease, LeaseId, OperatorId, ProjectId, TaskAttempt, TaskAttemptId, TaskAttemptStatus, TaskId,
    TaskRevisionId,
};
use uuid::Uuid;

use crate::agent::BoxFuture;
use crate::error::{AgentError, Result};
use crate::scheduler::CompletionProof;

#[derive(Debug, Clone, PartialEq)]
pub struct TaskAttemptRecord {
    pub attempt: TaskAttempt,
    pub lease: Option<Lease>,
    pub retry_count: u32,
    pub retry_of: Option<TaskAttemptId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseHeartbeat {
    pub lease_id: LeaseId,
    pub holder_operator_id: OperatorId,
    pub fencing_token: u64,
    pub now_ms: u64,
    pub extend_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconciliation {
    pub attempt_id: TaskAttemptId,
    pub previous_status: TaskAttemptStatus,
    pub status: TaskAttemptStatus,
    pub lease_id: Option<LeaseId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseFence {
    pub lease_id: LeaseId,
    pub holder_operator_id: OperatorId,
    pub fencing_token: u64,
}

#[derive(Debug, Clone)]
pub struct AttemptSpec {
    pub attempt_id: TaskAttemptId,
    pub task_id: TaskId,
    pub task_revision_id: TaskRevisionId,
    pub operator_id: OperatorId,
    pub started_at: String,
    pub retry_of: Option<TaskAttemptId>,
    pub retry_count: u32,
}

impl AttemptSpec {
    pub fn initial(
        attempt_id: TaskAttemptId,
        task_id: TaskId,
        task_revision_id: TaskRevisionId,
        operator_id: OperatorId,
        started_at: impl Into<String>,
    ) -> Self {
        Self {
            attempt_id,
            task_id,
            task_revision_id,
            operator_id,
            started_at: started_at.into(),
            retry_of: None,
            retry_count: 0,
        }
    }
}

pub trait DaemonClock: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub trait LeaseAuthorityPort: Send + Sync {
    fn verify_fence(&self, fence: LeaseFence, now_ms: u64) -> BoxFuture<Result<()>>;
    fn heartbeat(&self, heartbeat: LeaseHeartbeat) -> BoxFuture<Result<Lease>>;
}

#[derive(Debug, Default)]
struct LeaseState {
    attempts: BTreeMap<TaskAttemptId, TaskAttemptRecord>,
    next_fencing_token: u64,
}

#[derive(Debug, Clone)]
pub struct AttemptLeaseManager {
    project_id: ProjectId,
    state: Arc<Mutex<LeaseState>>,
    max_attempts: usize,
}

impl AttemptLeaseManager {
    pub fn new(project_id: ProjectId) -> Result<Self> {
        if project_id.is_nil() {
            return Err(AgentError::InvalidInput(
                "project id must not be nil".to_owned(),
            ));
        }
        Ok(Self {
            project_id,
            state: Arc::new(Mutex::new(LeaseState::default())),
            max_attempts: 10_000,
        })
    }

    pub fn with_max_attempts(mut self, max_attempts: usize) -> Result<Self> {
        if max_attempts == 0 {
            return Err(AgentError::InvalidInput(
                "attempt limit must be positive".to_owned(),
            ));
        }
        self.max_attempts = max_attempts;
        Ok(self)
    }

    pub fn create_attempt(&self, spec: AttemptSpec) -> Result<TaskAttemptRecord> {
        if spec.attempt_id.is_nil()
            || spec.task_id.is_nil()
            || spec.task_revision_id.is_nil()
            || spec.operator_id.is_nil()
        {
            return Err(AgentError::InvalidInput(
                "attempt identity must not be nil".to_owned(),
            ));
        }
        let attempt = TaskAttempt {
            id: spec.attempt_id,
            project_id: self.project_id,
            task_id: spec.task_id,
            task_revision_id: spec.task_revision_id,
            operator_id: spec.operator_id,
            status: TaskAttemptStatus::Pending,
            started_at: spec.started_at.clone(),
            finished_at: None,
            error: None,
            evidence_bundle_id: None,
        };
        let mut state = self.state.lock().expect("lease state lock poisoned");
        if state.attempts.len() >= self.max_attempts {
            return Err(AgentError::BudgetExceeded(
                "attempt state limit exhausted".to_owned(),
            ));
        }
        if state.attempts.contains_key(&spec.attempt_id) {
            return Err(AgentError::Conflict(format!(
                "attempt {} already exists",
                spec.attempt_id
            )));
        }
        let record = TaskAttemptRecord {
            attempt,
            lease: None,
            retry_count: spec.retry_count,
            retry_of: spec.retry_of,
        };
        state.attempts.insert(spec.attempt_id, record.clone());
        Ok(record)
    }

    pub fn claim(
        &self,
        attempt_id: TaskAttemptId,
        holder_operator_id: OperatorId,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<Lease> {
        if holder_operator_id.is_nil() || ttl_ms == 0 {
            return Err(AgentError::InvalidInput(
                "holder must be non-nil and lease ttl must be positive".to_owned(),
            ));
        }
        let mut state = self.state.lock().expect("lease state lock poisoned");
        let existing = state
            .attempts
            .get(&attempt_id)
            .cloned()
            .ok_or_else(|| AgentError::NotFound(format!("attempt {attempt_id}")))?;
        if let Some(lease) = &existing.lease {
            if parse_ms(&lease.expires_at).is_some_and(|expires| expires > now_ms) {
                return Err(AgentError::Conflict(
                    "attempt already has a live lease".to_owned(),
                ));
            }
        }
        if existing.attempt.status != TaskAttemptStatus::Pending {
            return Err(AgentError::NotReady(
                "only pending attempts can be claimed; reconciliation blocks reclaim".to_owned(),
            ));
        }
        state.next_fencing_token = state.next_fencing_token.saturating_add(1);
        let lease = Lease {
            id: Uuid::now_v7(),
            project_id: self.project_id,
            task_id: existing.attempt.task_id,
            holder_operator_id,
            acquired_at: now_ms.to_string(),
            expires_at: now_ms.saturating_add(ttl_ms).to_string(),
            fencing_token: state.next_fencing_token,
        };
        let record = state
            .attempts
            .get_mut(&attempt_id)
            .expect("attempt was checked");
        record.attempt.status = TaskAttemptStatus::Running;
        record.attempt.operator_id = holder_operator_id;
        record.lease = Some(lease.clone());
        Ok(lease)
    }

    pub fn heartbeat(&self, heartbeat: LeaseHeartbeat) -> Result<Lease> {
        let mut state = self.state.lock().expect("lease state lock poisoned");
        let record = state
            .attempts
            .values_mut()
            .find(|record| {
                record
                    .lease
                    .as_ref()
                    .is_some_and(|lease| lease.id == heartbeat.lease_id)
            })
            .ok_or_else(|| AgentError::NotFound(format!("lease {}", heartbeat.lease_id)))?;
        let lease = record.lease.as_mut().expect("lease was found");
        validate_lease(
            lease,
            heartbeat.holder_operator_id,
            heartbeat.fencing_token,
            heartbeat.now_ms,
        )?;
        if heartbeat.extend_ms == 0 {
            return Err(AgentError::InvalidInput(
                "lease extension must be positive".to_owned(),
            ));
        }
        lease.expires_at = heartbeat
            .now_ms
            .saturating_add(heartbeat.extend_ms)
            .to_string();
        Ok(lease.clone())
    }

    pub fn verify_fence_sync(&self, fence: LeaseFence, now_ms: u64) -> Result<()> {
        let state = self.state.lock().expect("lease state lock poisoned");
        let lease = state
            .attempts
            .values()
            .filter_map(|record| record.lease.as_ref())
            .find(|lease| lease.id == fence.lease_id)
            .ok_or(AgentError::Fenced)?;
        validate_lease(lease, fence.holder_operator_id, fence.fencing_token, now_ms)
    }

    pub fn finish(
        &self,
        lease_id: LeaseId,
        holder_operator_id: OperatorId,
        fencing_token: u64,
        status: TaskAttemptStatus,
        at: impl Into<String>,
        error: Option<String>,
    ) -> Result<TaskAttemptRecord> {
        if !matches!(
            &status,
            TaskAttemptStatus::Succeeded | TaskAttemptStatus::Failed | TaskAttemptStatus::Cancelled
        ) {
            return Err(AgentError::InvalidInput(
                "finish status must be terminal".to_owned(),
            ));
        }
        if status == TaskAttemptStatus::Succeeded {
            return Err(AgentError::Conflict(
                "successful attempt completion requires immutable evidence and a passed gate"
                    .to_owned(),
            ));
        }
        let mut state = self.state.lock().expect("lease state lock poisoned");
        let record = state
            .attempts
            .values_mut()
            .find(|record| {
                record
                    .lease
                    .as_ref()
                    .is_some_and(|lease| lease.id == lease_id)
            })
            .ok_or_else(|| AgentError::NotFound(format!("lease {lease_id}")))?;
        let lease = record.lease.as_ref().expect("lease was found");
        if lease.holder_operator_id != holder_operator_id || lease.fencing_token != fencing_token {
            return Err(AgentError::Fenced);
        }
        record.attempt.status = status;
        record.attempt.finished_at = Some(at.into());
        record.attempt.error = error;
        record.lease = None;
        Ok(record.clone())
    }

    pub fn finish_with_proof(
        &self,
        lease_id: LeaseId,
        holder_operator_id: OperatorId,
        fencing_token: u64,
        at: impl Into<String>,
        proof: CompletionProof,
    ) -> Result<TaskAttemptRecord> {
        proof.validate()?;
        let mut state = self.state.lock().expect("lease state lock poisoned");
        let record = state
            .attempts
            .values_mut()
            .find(|record| {
                record
                    .lease
                    .as_ref()
                    .is_some_and(|lease| lease.id == lease_id)
            })
            .ok_or_else(|| AgentError::NotFound(format!("lease {lease_id}")))?;
        let lease = record.lease.as_ref().expect("lease was found");
        if lease.holder_operator_id != holder_operator_id || lease.fencing_token != fencing_token {
            return Err(AgentError::Fenced);
        }
        record.attempt.status = TaskAttemptStatus::Succeeded;
        record.attempt.finished_at = Some(at.into());
        record.attempt.evidence_bundle_id = Some(proof.evidence_id);
        record.lease = None;
        Ok(record.clone())
    }

    pub fn retry(
        &self,
        attempt_id: TaskAttemptId,
        max_attempts: u32,
        at: impl Into<String>,
    ) -> Result<TaskAttemptRecord> {
        let state = self.state.lock().expect("lease state lock poisoned");
        let previous = state
            .attempts
            .get(&attempt_id)
            .cloned()
            .ok_or_else(|| AgentError::NotFound(format!("attempt {attempt_id}")))?;
        drop(state);
        if previous.attempt.status != TaskAttemptStatus::Failed {
            return Err(AgentError::Conflict(
                "only failed attempts can be retried".to_owned(),
            ));
        }
        let retry_count = previous.retry_count.saturating_add(1);
        if retry_count >= max_attempts {
            return Err(AgentError::Conflict("retry budget exhausted".to_owned()));
        }
        self.create_attempt(AttemptSpec {
            attempt_id: Uuid::now_v7(),
            task_id: previous.attempt.task_id,
            task_revision_id: previous.attempt.task_revision_id,
            operator_id: previous.attempt.operator_id,
            started_at: at.into(),
            retry_of: Some(attempt_id),
            retry_count,
        })
    }

    pub fn reconcile(&self, now_ms: u64) -> Vec<Reconciliation> {
        let mut state = self.state.lock().expect("lease state lock poisoned");
        let mut reconciled = Vec::new();
        for record in state.attempts.values_mut() {
            let Some(lease) = record.lease.as_ref() else {
                continue;
            };
            let Some(expires_at) = parse_ms(&lease.expires_at) else {
                continue;
            };
            if expires_at > now_ms || record.attempt.status != TaskAttemptStatus::Running {
                continue;
            }
            let previous_status = record.attempt.status.clone();
            let lease_id = lease.id;
            record.attempt.status = TaskAttemptStatus::NeedsReconciliation;
            record.attempt.finished_at = Some(now_ms.to_string());
            record.lease = None;
            reconciled.push(Reconciliation {
                attempt_id: record.attempt.id,
                previous_status,
                status: TaskAttemptStatus::NeedsReconciliation,
                lease_id: Some(lease_id),
            });
        }
        reconciled
    }

    pub fn resolve_reconciliation(
        &self,
        attempt_id: TaskAttemptId,
        safe_to_retry: bool,
    ) -> Result<()> {
        let mut state = self.state.lock().expect("lease state lock poisoned");
        let record = state
            .attempts
            .get_mut(&attempt_id)
            .ok_or_else(|| AgentError::NotFound(format!("attempt {attempt_id}")))?;
        if record.attempt.status != TaskAttemptStatus::NeedsReconciliation {
            return Err(AgentError::Conflict(
                "attempt is not awaiting reconciliation".to_owned(),
            ));
        }
        if safe_to_retry {
            record.attempt.status = TaskAttemptStatus::Pending;
            record.attempt.finished_at = None;
        }
        Ok(())
    }

    pub fn get(&self, attempt_id: TaskAttemptId) -> Option<TaskAttemptRecord> {
        self.state
            .lock()
            .expect("lease state lock poisoned")
            .attempts
            .get(&attempt_id)
            .cloned()
    }

    pub fn attempts(&self) -> Vec<TaskAttemptRecord> {
        self.state
            .lock()
            .expect("lease state lock poisoned")
            .attempts
            .values()
            .cloned()
            .collect()
    }
}

impl LeaseAuthorityPort for AttemptLeaseManager {
    fn verify_fence(&self, fence: LeaseFence, now_ms: u64) -> BoxFuture<Result<()>> {
        let manager = self.clone();
        Box::pin(async move { manager.verify_fence_sync(fence, now_ms) })
    }

    fn heartbeat(&self, heartbeat: LeaseHeartbeat) -> BoxFuture<Result<Lease>> {
        let manager = self.clone();
        Box::pin(async move { manager.heartbeat(heartbeat) })
    }
}

fn validate_lease(
    lease: &Lease,
    holder_operator_id: OperatorId,
    fencing_token: u64,
    now_ms: u64,
) -> Result<()> {
    if lease.holder_operator_id != holder_operator_id || lease.fencing_token != fencing_token {
        return Err(AgentError::Fenced);
    }
    if match parse_ms(&lease.expires_at) {
        Some(expires) => expires <= now_ms,
        None => true,
    } {
        return Err(AgentError::LeaseExpired);
    }
    Ok(())
}

fn parse_ms(value: &str) -> Option<u64> {
    value.parse().ok()
}
