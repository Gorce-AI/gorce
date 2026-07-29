use std::fmt;

use gorce_protocol::{TaskEdgeKind, TaskId};

pub type EntityId = TaskId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityKind {
    Workstream,
    Goal,
    Plan,
    Task,
    TaskRevision,
    PlanItem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevisionConflict {
    pub entity: EntityKind,
    pub id: EntityId,
    pub expected: u64,
    pub actual: u64,
}

pub type Conflict = RevisionConflict;
pub type OptimisticConcurrencyError = RevisionConflict;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    Conflict(RevisionConflict),
    InvalidInput {
        field: String,
        reason: String,
    },
    Duplicate {
        entity: EntityKind,
        id: EntityId,
    },
    NotFound {
        entity: EntityKind,
        id: EntityId,
    },
    InvalidTransition {
        task_id: TaskId,
        from: gorce_protocol::TaskLifecycle,
        to: gorce_protocol::TaskLifecycle,
    },
    CycleDetected {
        kind: TaskEdgeKind,
        from: TaskId,
        to: TaskId,
    },
    MissingReplacement {
        task_id: TaskId,
    },
    InvalidMapping {
        plan_item_id: gorce_protocol::PlanItemId,
        reason: String,
    },
    Alignment {
        reason: String,
    },
}

pub type DomainError = CoreError;
pub type Result<T> = std::result::Result<T, CoreError>;

impl CoreError {
    pub(crate) fn invalid(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidInput {
            field: field.into(),
            reason: reason.into(),
        }
    }

    pub(crate) fn conflict(entity: EntityKind, id: EntityId, expected: u64, actual: u64) -> Self {
        Self::Conflict(RevisionConflict {
            entity,
            id,
            expected,
            actual,
        })
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict(conflict) => write!(
                formatter,
                "optimistic concurrency conflict for {:?} {}: expected revision {}, actual {}",
                conflict.entity, conflict.id, conflict.expected, conflict.actual
            ),
            Self::InvalidInput { field, reason } => write!(formatter, "invalid {field}: {reason}"),
            Self::Duplicate { entity, id } => write!(formatter, "duplicate {entity:?} {id}"),
            Self::NotFound { entity, id } => write!(formatter, "unknown {entity:?} {id}"),
            Self::InvalidTransition { task_id, from, to } => {
                write!(
                    formatter,
                    "invalid lifecycle transition for {task_id}: {from:?} -> {to:?}"
                )
            }
            Self::CycleDetected { kind, from, to } => {
                write!(
                    formatter,
                    "{kind:?} edge {from} -> {to} would create a cycle"
                )
            }
            Self::MissingReplacement { task_id } => {
                write!(
                    formatter,
                    "superseding task {task_id} requires a replacement"
                )
            }
            Self::InvalidMapping {
                plan_item_id,
                reason,
            } => {
                write!(
                    formatter,
                    "invalid promotion mapping for {plan_item_id}: {reason}"
                )
            }
            Self::Alignment { reason } => write!(formatter, "goal alignment failure: {reason}"),
        }
    }
}

impl std::error::Error for CoreError {}
