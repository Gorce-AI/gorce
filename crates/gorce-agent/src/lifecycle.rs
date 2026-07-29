use uuid::Uuid;

use gorce_protocol::OperatorId;

use crate::error::{AgentError, Result};

const MAX_RUN_ATTEMPTS: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    Created,
    Running,
    Paused,
    Cancelling,
    Succeeded,
    Failed,
    Cancelled,
    Recovering,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    NeedsReconciliation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub id: Uuid,
    pub retry_of: Option<Uuid>,
    pub number: u32,
    pub status: AttemptStatus,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub error: Option<String>,
    pub retryable: bool,
    pub side_effect: bool,
}

impl Attempt {
    pub fn new(id: Uuid, number: u32) -> Self {
        Self {
            id,
            retry_of: None,
            number,
            status: AttemptStatus::Pending,
            started_at: None,
            finished_at: None,
            error: None,
            retryable: false,
            side_effect: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub id: Uuid,
    pub root_operator_id: OperatorId,
    pub status: RunStatus,
    pub attempts: Vec<Attempt>,
    pub revision: u64,
    pub created_at: String,
    pub updated_at: String,
    pub cancel_reason: Option<String>,
}

impl Run {
    pub fn new(
        id: Uuid,
        root_operator_id: OperatorId,
        created_at: impl Into<String>,
    ) -> Result<Self> {
        if id.is_nil() || root_operator_id.is_nil() {
            return Err(AgentError::InvalidInput(
                "run and root operator IDs must not be nil".to_owned(),
            ));
        }
        let created_at = created_at.into();
        if created_at.trim().is_empty() {
            return Err(AgentError::InvalidInput(
                "created_at must not be empty".to_owned(),
            ));
        }
        Ok(Self {
            id,
            root_operator_id,
            status: RunStatus::Created,
            attempts: Vec::new(),
            revision: 1,
            updated_at: created_at.clone(),
            created_at,
            cancel_reason: None,
        })
    }

    pub fn start(&mut self, at: impl Into<String>) -> Result<()> {
        if !matches!(self.status, RunStatus::Created | RunStatus::Recovering) {
            return Err(AgentError::Conflict(format!(
                "run cannot start from {:?}",
                self.status
            )));
        }
        self.transition(RunStatus::Running, at)
    }

    pub fn pause(&mut self, at: impl Into<String>) -> Result<()> {
        if self.status != RunStatus::Running {
            return Err(AgentError::Conflict(
                "only a running run can pause".to_owned(),
            ));
        }
        self.transition(RunStatus::Paused, at)
    }

    pub fn resume(&mut self, at: impl Into<String>) -> Result<()> {
        if !matches!(self.status, RunStatus::Paused | RunStatus::Recovering) {
            return Err(AgentError::Conflict(
                "run is not paused or recovering".to_owned(),
            ));
        }
        self.transition(RunStatus::Running, at)
    }

    pub fn cancel(&mut self, reason: impl Into<String>, at: impl Into<String>) -> Result<()> {
        if self.status.is_terminal() {
            return Ok(());
        }
        let at = at.into();
        self.cancel_reason = Some(reason.into());
        self.transition(RunStatus::Cancelling, at.clone())?;
        for attempt in &mut self.attempts {
            if matches!(
                &attempt.status,
                AttemptStatus::Pending | AttemptStatus::Running
            ) {
                attempt.status = AttemptStatus::Cancelled;
            }
        }
        self.transition(RunStatus::Cancelled, at)
    }

    pub fn recover(&mut self, at: impl Into<String>) -> Result<()> {
        if self.status.is_terminal() {
            return Err(AgentError::Conflict(
                "terminal run cannot recover".to_owned(),
            ));
        }
        let at = at.into();
        for attempt in &mut self.attempts {
            if attempt.status == AttemptStatus::Running {
                attempt.status = AttemptStatus::NeedsReconciliation;
                attempt.finished_at = Some(at.clone());
            }
        }
        self.transition(RunStatus::Recovering, at)
    }

    pub fn begin_attempt(&mut self, id: Uuid, at: impl Into<String>) -> Result<&Attempt> {
        self.begin_attempt_linked(id, at, None)
    }

    pub fn begin_attempt_linked(
        &mut self,
        id: Uuid,
        at: impl Into<String>,
        retry_of: Option<Uuid>,
    ) -> Result<&Attempt> {
        if self.status != RunStatus::Running {
            return Err(AgentError::Conflict(
                "attempt requires a running run".to_owned(),
            ));
        }
        if self.attempts.len() >= MAX_RUN_ATTEMPTS {
            return Err(AgentError::BudgetExceeded(
                "run attempt limit exhausted".to_owned(),
            ));
        }
        if self
            .attempts
            .iter()
            .any(|attempt| attempt.status == AttemptStatus::Running)
        {
            return Err(AgentError::Conflict(
                "run already has a running attempt".to_owned(),
            ));
        }
        if id.is_nil() {
            return Err(AgentError::InvalidInput(
                "attempt id must not be nil".to_owned(),
            ));
        }
        if self.attempts.iter().any(|attempt| attempt.id == id) {
            return Err(AgentError::Conflict(format!("attempt {id} already exists")));
        }
        let number = self.attempts.len() as u32 + 1;
        let attempt = Attempt {
            retry_of,
            started_at: Some(at.into()),
            status: AttemptStatus::Running,
            ..Attempt::new(id, number)
        };
        self.attempts.push(attempt);
        self.revision = self.revision.saturating_add(1);
        self.attempts
            .last()
            .ok_or_else(|| AgentError::Conflict("attempt insertion failed".to_owned()))
    }

    pub fn complete_attempt(&mut self, id: Uuid, at: impl Into<String>) -> Result<()> {
        let at = at.into();
        {
            let attempt = self.find_attempt_mut(id)?;
            if attempt.status != AttemptStatus::Running {
                return Err(AgentError::Conflict("attempt is not running".to_owned()));
            }
            attempt.status = AttemptStatus::Succeeded;
            attempt.finished_at = Some(at.clone());
        }
        self.revision = self.revision.saturating_add(1);
        self.transition(RunStatus::Succeeded, at)
    }

    pub fn fail_attempt(
        &mut self,
        id: Uuid,
        error: impl Into<String>,
        retryable: bool,
        at: impl Into<String>,
        policy: &RetryPolicy,
        circuit: &mut CircuitBreaker,
    ) -> Result<RetryDecision> {
        let at = at.into();
        let attempt_number;
        {
            let attempt = self.find_attempt_mut(id)?;
            if !matches!(
                &attempt.status,
                AttemptStatus::Running | AttemptStatus::NeedsReconciliation
            ) {
                return Err(AgentError::Conflict(
                    "attempt cannot fail from its current state".to_owned(),
                ));
            }
            attempt.status = AttemptStatus::Failed;
            attempt.finished_at = Some(at.clone());
            attempt.error = Some(error.into());
            attempt.retryable = retryable;
            attempt_number = attempt.number;
        }
        self.revision = self.revision.saturating_add(1);
        let decision = if !retryable {
            circuit.record_permanent_failure();
            RetryDecision::Exhausted
        } else if !circuit.allow() {
            RetryDecision::CircuitOpen
        } else if attempt_number < policy.max_attempts {
            circuit.record_transient_failure(policy.circuit_failure_threshold);
            if circuit.is_open() {
                RetryDecision::CircuitOpen
            } else {
                RetryDecision::Retry {
                    next_attempt: attempt_number + 1,
                }
            }
        } else {
            circuit.record_transient_failure(policy.circuit_failure_threshold);
            RetryDecision::Exhausted
        };
        if matches!(
            decision,
            RetryDecision::Exhausted | RetryDecision::CircuitOpen
        ) {
            self.transition(RunStatus::Failed, at)?;
        }
        Ok(decision)
    }

    pub fn mark_cancelled_attempt(&mut self, id: Uuid, at: impl Into<String>) -> Result<()> {
        let attempt = self.find_attempt_mut(id)?;
        attempt.status = AttemptStatus::Cancelled;
        attempt.finished_at = Some(at.into());
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    pub fn mark_needs_reconciliation(
        &mut self,
        id: Uuid,
        error: impl Into<String>,
        at: impl Into<String>,
    ) -> Result<()> {
        let attempt = self.find_attempt_mut(id)?;
        attempt.status = AttemptStatus::NeedsReconciliation;
        attempt.side_effect = true;
        attempt.error = Some(error.into());
        attempt.finished_at = Some(at.into());
        self.revision = self.revision.saturating_add(1);
        self.status = RunStatus::Recovering;
        Ok(())
    }

    fn find_attempt_mut(&mut self, id: Uuid) -> Result<&mut Attempt> {
        self.attempts
            .iter_mut()
            .find(|attempt| attempt.id == id)
            .ok_or_else(|| AgentError::NotFound(format!("attempt {id}")))
    }

    fn transition(&mut self, status: RunStatus, at: impl Into<String>) -> Result<()> {
        self.status = status;
        self.updated_at = at.into();
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }
}

impl RunStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub circuit_failure_threshold: u32,
    pub base_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            circuit_failure_threshold: 3,
            base_backoff_ms: 100,
            max_backoff_ms: 10_000,
        }
    }
}

impl RetryPolicy {
    pub fn backoff_ms(&self, attempt_number: u32) -> u64 {
        let exponent = attempt_number.saturating_sub(1).min(20);
        self.base_backoff_ms
            .saturating_mul(1_u64 << exponent)
            .min(self.max_backoff_ms)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    Retry { next_attempt: u32 },
    Exhausted,
    CircuitOpen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitBreaker {
    pub state: CircuitState,
    pub consecutive_failures: u32,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
        }
    }
}

impl CircuitBreaker {
    pub fn allow(&self) -> bool {
        self.state == CircuitState::Closed
    }

    pub fn is_open(&self) -> bool {
        self.state == CircuitState::Open
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.state = CircuitState::Closed;
    }

    pub fn record_permanent_failure(&mut self) {
        self.state = CircuitState::Open;
    }

    pub fn record_transient_failure(&mut self, threshold: u32) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if threshold == 0 || self.consecutive_failures >= threshold {
            self.state = CircuitState::Open;
        }
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}
