use gorce_protocol::{
    PlanId, PlanItem, PlanRevision, PlanRevisionId, PromotionMapping, RevisionStatus,
};

use crate::error::{CoreError, EntityKind, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct PlanRevisionDraft {
    pub id: PlanRevisionId,
    pub summary: String,
    pub items: Vec<PlanItem>,
    pub promotion_mappings: Vec<PromotionMapping>,
    pub status: RevisionStatus,
    pub created_by: gorce_protocol::OperatorId,
    pub created_at: String,
    pub revision_hash: String,
    pub expected_revision: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlanAggregate {
    revisions: Vec<PlanRevision>,
}

impl PlanAggregate {
    pub fn create(initial: PlanRevision) -> Result<Self> {
        Self::new(initial)
    }

    pub fn new(initial: PlanRevision) -> Result<Self> {
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

    pub fn revise(&self, draft: PlanRevisionDraft) -> Result<Self> {
        let current = self.current();
        if draft.expected_revision != current.revision {
            return Err(CoreError::conflict(
                EntityKind::Plan,
                current.plan_id,
                draft.expected_revision,
                current.revision,
            ));
        }
        let revision = PlanRevision {
            id: draft.id,
            plan_id: current.plan_id,
            project_id: current.project_id,
            goal_revision_id: current.goal_revision_id,
            revision: current.revision + 1,
            revision_hash: draft.revision_hash,
            summary: draft.summary,
            items: draft.items,
            promotion_mappings: draft.promotion_mappings,
            status: draft.status,
            created_by: draft.created_by,
            created_at: draft.created_at,
        };
        validate_revision(&revision)?;
        if self.revisions.iter().any(|item| item.id == revision.id) {
            return Err(CoreError::Duplicate {
                entity: EntityKind::Plan,
                id: revision.id,
            });
        }
        let mut next = self.clone();
        next.revisions.push(revision);
        Ok(next)
    }

    pub fn revise_with_mappings(
        &self,
        mut draft: PlanRevisionDraft,
        lifecycles: &std::collections::BTreeMap<
            gorce_protocol::TaskId,
            gorce_protocol::TaskLifecycle,
        >,
    ) -> Result<Self> {
        let promotion = crate::promotion::merge_plan_promotion(
            self.current(),
            draft.items,
            draft.promotion_mappings,
            lifecycles,
        )?;
        draft.items = promotion.items;
        draft.promotion_mappings = promotion.mappings;
        self.revise(draft)
    }

    pub fn promote(
        &self,
        draft: PlanRevisionDraft,
        lifecycles: &std::collections::BTreeMap<
            gorce_protocol::TaskId,
            gorce_protocol::TaskLifecycle,
        >,
    ) -> Result<Self> {
        self.revise_with_mappings(draft, lifecycles)
    }

    pub fn plan_id(&self) -> PlanId {
        self.current().plan_id
    }

    pub fn current(&self) -> &PlanRevision {
        self.revisions
            .last()
            .expect("aggregate always has a revision")
    }

    pub fn revisions(&self) -> &[PlanRevision] {
        &self.revisions
    }

    pub fn revision(&self) -> u64 {
        self.current().revision
    }
}

fn validate_revision(revision: &PlanRevision) -> Result<()> {
    if revision.id.is_nil()
        || revision.plan_id.is_nil()
        || revision.project_id.is_nil()
        || revision.goal_revision_id.is_nil()
    {
        return Err(CoreError::invalid("identity", "IDs must not be nil"));
    }
    if revision.summary.trim().is_empty() {
        return Err(CoreError::invalid("summary", "must not be empty"));
    }
    if revision.revision_hash.trim().is_empty() {
        return Err(CoreError::invalid("revision_hash", "must not be empty"));
    }
    let mut ids = std::collections::BTreeSet::new();
    for item in &revision.items {
        if item.id.is_nil() || item.title.trim().is_empty() {
            return Err(CoreError::invalid(
                "items",
                "plan item IDs and titles are required",
            ));
        }
        if !ids.insert(item.id) {
            return Err(CoreError::Duplicate {
                entity: EntityKind::PlanItem,
                id: item.id,
            });
        }
    }
    for mapping in &revision.promotion_mappings {
        if !ids.contains(&mapping.plan_item_id) {
            return Err(CoreError::InvalidMapping {
                plan_item_id: mapping.plan_item_id,
                reason: "mapping does not refer to an item in the revision".to_owned(),
            });
        }
    }
    Ok(())
}
