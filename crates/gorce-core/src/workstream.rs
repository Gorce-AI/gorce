use gorce_protocol::{OperatorId, ProjectId, WorkstreamId, WorkstreamStatus};

use crate::error::{CoreError, EntityKind, Result};

pub type WorkstreamRevisionId = ProjectId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkstreamRevision {
    pub id: WorkstreamRevisionId,
    pub workstream_id: WorkstreamId,
    pub project_id: ProjectId,
    pub revision: u64,
    pub name: String,
    pub description: Option<String>,
    pub status: WorkstreamStatus,
    pub revision_hash: String,
    pub created_by: OperatorId,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkstreamRevisionDraft {
    pub id: WorkstreamRevisionId,
    pub workstream_id: WorkstreamId,
    pub project_id: ProjectId,
    pub name: String,
    pub description: Option<String>,
    pub status: WorkstreamStatus,
    pub revision_hash: String,
    pub created_by: OperatorId,
    pub created_at: String,
    pub expected_revision: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkstreamAggregate {
    pub id: WorkstreamId,
    pub project_id: ProjectId,
    revisions: Vec<WorkstreamRevision>,
}

impl WorkstreamAggregate {
    pub fn create(draft: WorkstreamRevisionDraft) -> Result<Self> {
        Self::new(draft)
    }

    pub fn new(draft: WorkstreamRevisionDraft) -> Result<Self> {
        if draft.expected_revision.is_some() {
            return Err(CoreError::invalid(
                "expected_revision",
                "an initial workstream revision has no base revision",
            ));
        }
        validate_draft(&draft)?;
        let revision = WorkstreamRevision {
            id: draft.id,
            workstream_id: draft.workstream_id,
            project_id: draft.project_id,
            revision: 1,
            name: draft.name,
            description: draft.description,
            status: draft.status,
            revision_hash: draft.revision_hash,
            created_by: draft.created_by,
            created_at: draft.created_at,
        };
        Ok(Self {
            id: revision.workstream_id,
            project_id: revision.project_id,
            revisions: vec![revision],
        })
    }

    pub fn from_revision(revision: WorkstreamRevision) -> Result<Self> {
        if revision.revision != 1 {
            return Err(CoreError::invalid(
                "revision",
                "the first revision must be 1",
            ));
        }
        if revision.id.is_nil() {
            return Err(CoreError::invalid("id", "must not be nil"));
        }
        if revision.workstream_id.is_nil() || revision.project_id.is_nil() {
            return Err(CoreError::invalid("identity", "must not contain nil IDs"));
        }
        if revision.name.trim().is_empty() || revision.revision_hash.trim().is_empty() {
            return Err(CoreError::invalid(
                "revision",
                "name and hash must not be empty",
            ));
        }
        Ok(Self {
            id: revision.workstream_id,
            project_id: revision.project_id,
            revisions: vec![revision],
        })
    }

    pub fn revise(&self, draft: WorkstreamRevisionDraft) -> Result<Self> {
        let expected = draft.expected_revision.ok_or_else(|| {
            CoreError::invalid(
                "expected_revision",
                "a revision must name its base revision",
            )
        })?;
        let actual = self.current().revision;
        if expected != actual {
            return Err(CoreError::conflict(
                EntityKind::Workstream,
                self.id,
                expected,
                actual,
            ));
        }
        validate_draft(&draft)?;
        if draft.workstream_id != self.id || draft.project_id != self.project_id {
            return Err(CoreError::invalid(
                "identity",
                "a revision must retain its workstream and project identity",
            ));
        }
        if self
            .revisions
            .iter()
            .any(|revision| revision.id == draft.id)
        {
            return Err(CoreError::Duplicate {
                entity: EntityKind::Workstream,
                id: draft.id,
            });
        }
        let mut next = self.clone();
        next.revisions.push(WorkstreamRevision {
            id: draft.id,
            workstream_id: draft.workstream_id,
            project_id: draft.project_id,
            revision: actual + 1,
            name: draft.name,
            description: draft.description,
            status: draft.status,
            revision_hash: draft.revision_hash,
            created_by: draft.created_by,
            created_at: draft.created_at,
        });
        Ok(next)
    }

    pub fn current(&self) -> &WorkstreamRevision {
        self.revisions
            .last()
            .expect("aggregate always has a revision")
    }

    pub fn revisions(&self) -> &[WorkstreamRevision] {
        &self.revisions
    }

    pub fn revision(&self) -> u64 {
        self.current().revision
    }
}

fn validate_draft(draft: &WorkstreamRevisionDraft) -> Result<()> {
    if draft.id.is_nil() || draft.workstream_id.is_nil() || draft.project_id.is_nil() {
        return Err(CoreError::invalid("identity", "IDs must not be nil"));
    }
    if draft.name.trim().is_empty() {
        return Err(CoreError::invalid("name", "must not be empty"));
    }
    if draft.revision_hash.trim().is_empty() {
        return Err(CoreError::invalid("revision_hash", "must not be empty"));
    }
    Ok(())
}
