use crate::agent::BoxFuture;
use crate::error::{AgentError, Result};
use crate::events::{EventCursor, EventEnvelope};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainEvent {
    pub event_type: String,
    pub schema_version: u64,
    pub payload: String,
}

impl DomainEvent {
    pub fn new(
        event_type: impl Into<String>,
        schema_version: u64,
        payload: impl Into<String>,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            schema_version,
            payload: payload.into(),
        }
    }

    pub fn validate(&self, max_bytes: usize) -> Result<()> {
        if self.event_type.trim().is_empty() || self.schema_version == 0 {
            return Err(AgentError::InvalidInput(
                "domain events require a type and non-zero schema version".to_owned(),
            ));
        }
        if self.event_type.len().saturating_add(self.payload.len()) > max_bytes {
            return Err(AgentError::MessageTooLarge);
        }
        Ok(())
    }
}

pub trait EventAppender: Send + Sync {
    fn append(&self, event: DomainEvent) -> BoxFuture<Result<EventCursor>>;
    fn replay(&self, after: EventCursor) -> BoxFuture<Result<Vec<EventEnvelope<DomainEvent>>>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicEventBatch<S, E> {
    pub state: S,
    pub events: Vec<E>,
    pub expected_revision: u64,
    pub definition_hash: String,
}

pub trait AtomicStateEventPort<S, E>: Send + Sync
where
    S: Send + Sync + 'static,
    E: Send + Sync + 'static,
{
    fn load(&self, aggregate_id: &str) -> BoxFuture<Result<Option<S>>>;
    fn commit(&self, aggregate_id: &str, batch: AtomicEventBatch<S, E>) -> BoxFuture<Result<()>>;
}

pub trait DurableRetryStatePort: Send + Sync {
    fn persist_retry_state(&self, run_id: uuid::Uuid, state: RetryState) -> BoxFuture<Result<()>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryState {
    pub attempt_number: u32,
    pub failures: u32,
    pub next_retry_at_ms: u64,
    pub circuit_open: bool,
}
