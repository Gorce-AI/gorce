use gorce_protocol::{GoalId, GoalRevision, OperatorId, RevisionStatus};

use crate::error::{CoreError, EntityKind, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalRevisionDraft {
    pub id: gorce_protocol::GoalRevisionId,
    pub title: String,
    pub statement: String,
    pub revision_hash: String,
    pub status: RevisionStatus,
    pub created_by: OperatorId,
    pub created_at: String,
    pub expected_revision: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GoalAggregate {
    revisions: Vec<GoalRevision>,
}

impl GoalAggregate {
    pub fn create(initial: GoalRevision) -> Result<Self> {
        Self::new(initial)
    }

    pub fn new(initial: GoalRevision) -> Result<Self> {
        validate_revision(&initial)?;
        if initial.revision != 1 {
            return Err(CoreError::invalid(
                "revision",
                "the first revision must be 1",
            ));
        }
        Ok(Self {
            revisions: vec![initial],
        })
    }

    pub fn revise(&self, draft: GoalRevisionDraft) -> Result<Self> {
        let current = self.current();
        if draft.expected_revision != current.revision {
            return Err(CoreError::conflict(
                EntityKind::Goal,
                current.goal_id,
                draft.expected_revision,
                current.revision,
            ));
        }
        let revision = GoalRevision {
            id: draft.id,
            goal_id: current.goal_id,
            project_id: current.project_id,
            workstream_id: current.workstream_id,
            revision: current.revision + 1,
            title: draft.title,
            statement: draft.statement,
            revision_hash: draft.revision_hash,
            status: draft.status,
            created_by: draft.created_by,
            created_at: draft.created_at,
        };
        validate_revision(&revision)?;
        if self.revisions.iter().any(|item| item.id == revision.id) {
            return Err(CoreError::Duplicate {
                entity: EntityKind::Goal,
                id: revision.id,
            });
        }
        let mut next = self.clone();
        next.revisions.push(revision);
        Ok(next)
    }

    pub fn goal_id(&self) -> GoalId {
        self.current().goal_id
    }

    pub fn project_id(&self) -> gorce_protocol::ProjectId {
        self.current().project_id
    }

    pub fn current(&self) -> &GoalRevision {
        self.revisions
            .last()
            .expect("aggregate always has a revision")
    }

    pub fn revisions(&self) -> &[GoalRevision] {
        &self.revisions
    }

    pub fn revision(&self) -> u64 {
        self.current().revision
    }

    pub fn find_revision(&self, id: gorce_protocol::GoalRevisionId) -> Option<&GoalRevision> {
        self.revisions.iter().find(|revision| revision.id == id)
    }

    pub fn approved_revision(&self) -> Option<&GoalRevision> {
        self.revisions
            .iter()
            .rev()
            .find(|revision| revision.status == RevisionStatus::Approved)
    }
}

fn validate_revision(revision: &GoalRevision) -> Result<()> {
    if revision.id.is_nil() || revision.goal_id.is_nil() || revision.project_id.is_nil() {
        return Err(CoreError::invalid("identity", "IDs must not be nil"));
    }
    if revision.title.trim().is_empty() {
        return Err(CoreError::invalid("title", "must not be empty"));
    }
    if revision.statement.trim().is_empty() {
        return Err(CoreError::invalid("statement", "must not be empty"));
    }
    if revision.revision_hash.trim().is_empty() {
        return Err(CoreError::invalid("revision_hash", "must not be empty"));
    }
    Ok(())
}
