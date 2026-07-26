use std::collections::{BTreeMap, BTreeSet};

use gorce_protocol::{
    PlanItem, PlanRevision, PromotionDisposition, PromotionMapping, TaskId, TaskLifecycle,
};

use crate::error::{CoreError, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct PlanPromotion {
    pub items: Vec<PlanItem>,
    pub mappings: Vec<PromotionMapping>,
}

pub fn merge_plan_promotion(
    previous: &PlanRevision,
    proposed_items: Vec<PlanItem>,
    explicit_mappings: Vec<PromotionMapping>,
    lifecycles: &BTreeMap<TaskId, TaskLifecycle>,
) -> Result<PlanPromotion> {
    let mut items = proposed_items;
    let proposed_ids: BTreeSet<_> = items.iter().map(|item| item.id).collect();
    if proposed_ids.len() != items.len() {
        return Err(CoreError::invalid("items", "plan item IDs must be unique"));
    }
    for item in &previous.items {
        let unfinished = item
            .task_id
            .and_then(|task_id| lifecycles.get(&task_id))
            .map(is_unfinished)
            .unwrap_or(true);
        if unfinished && !proposed_ids.contains(&item.id) {
            items.push(item.clone());
        }
    }
    let mappings =
        normalize_promotion_mappings(&items, &explicit_mappings, Some(previous), lifecycles)?;
    Ok(PlanPromotion { items, mappings })
}

pub fn normalize_promotion_mappings(
    items: &[PlanItem],
    explicit_mappings: &[PromotionMapping],
    previous: Option<&PlanRevision>,
    lifecycles: &BTreeMap<TaskId, TaskLifecycle>,
) -> Result<Vec<PromotionMapping>> {
    let item_by_id: BTreeMap<_, _> = items.iter().map(|item| (item.id, item)).collect();
    if item_by_id.len() != items.len() {
        return Err(CoreError::invalid("items", "plan item IDs must be unique"));
    }

    let mut by_item = BTreeMap::new();
    for mapping in explicit_mappings {
        let Some(item) = item_by_id.get(&mapping.plan_item_id) else {
            return Err(CoreError::InvalidMapping {
                plan_item_id: mapping.plan_item_id,
                reason: "mapping does not refer to a plan item".to_owned(),
            });
        };
        validate_mapping(mapping, item)?;
        if let Some(existing) = by_item.get(&mapping.plan_item_id) {
            if existing != mapping {
                return Err(CoreError::InvalidMapping {
                    plan_item_id: mapping.plan_item_id,
                    reason: "duplicate mappings disagree".to_owned(),
                });
            }
        } else {
            by_item.insert(mapping.plan_item_id, mapping.clone());
        }
    }

    for item in items {
        if by_item.contains_key(&item.id) {
            continue;
        }
        let default_keep = previous
            .and_then(|old| old.items.iter().find(|old_item| old_item.id == item.id))
            .and_then(|old| old.task_id)
            .map(|task_id| {
                let unfinished = lifecycles.get(&task_id).map(is_unfinished).unwrap_or(true);
                unfinished
                    && item.task_id == Some(task_id)
                    && item.task_revision_id
                        == previous
                            .and_then(|old| {
                                old.items.iter().find(|old_item| old_item.id == item.id)
                            })
                            .and_then(|old| old.task_revision_id)
            })
            .unwrap_or(false);
        if default_keep {
            by_item.insert(
                item.id,
                PromotionMapping {
                    plan_item_id: item.id,
                    disposition: PromotionDisposition::Keep,
                    task_id: item.task_id,
                    source_revision_id: None,
                    target_revision_id: None,
                    reason: Some("Unfinished task remains in the next plan unchanged.".to_owned()),
                },
            );
        } else {
            return Err(CoreError::InvalidMapping {
                plan_item_id: item.id,
                reason: "new or changed items require an explicit CREATE, REUSE, or REVISE mapping"
                    .to_owned(),
            });
        }
    }

    Ok(items
        .iter()
        .map(|item| by_item.remove(&item.id).expect("every item was mapped"))
        .collect())
}

fn validate_mapping(mapping: &PromotionMapping, item: &PlanItem) -> Result<()> {
    let error = |reason: &str| CoreError::InvalidMapping {
        plan_item_id: mapping.plan_item_id,
        reason: reason.to_owned(),
    };
    if let Some(reason) = &mapping.reason {
        if reason.trim().is_empty() {
            return Err(error("reason must not be empty"));
        }
    }
    match mapping.disposition {
        PromotionDisposition::Create => {
            if mapping.task_id.is_some()
                || mapping.source_revision_id.is_some()
                || mapping.target_revision_id.is_some()
            {
                return Err(error("CREATE cannot name an existing task or revision"));
            }
            if item.task_id.is_some() || item.task_revision_id.is_some() {
                return Err(error("CREATE must be used by an item without a task"));
            }
        }
        PromotionDisposition::Reuse | PromotionDisposition::Keep => {
            let Some(task_id) = mapping.task_id else {
                return Err(error("REUSE and KEEP require task_id"));
            };
            if item.task_id != Some(task_id) {
                return Err(error("mapping task_id must match the plan item task_id"));
            }
            if mapping.source_revision_id.is_some() || mapping.target_revision_id.is_some() {
                return Err(error("REUSE and KEEP cannot name revision changes"));
            }
        }
        PromotionDisposition::Revise => {
            let Some(task_id) = mapping.task_id else {
                return Err(error("REVISE requires task_id"));
            };
            if mapping.source_revision_id.is_none() {
                return Err(error("REVISE requires source_revision_id"));
            }
            if item.task_id != Some(task_id) {
                return Err(error("mapping task_id must match the plan item task_id"));
            }
        }
    }
    Ok(())
}

fn is_unfinished(lifecycle: &TaskLifecycle) -> bool {
    matches!(
        lifecycle,
        TaskLifecycle::Open | TaskLifecycle::Waiting | TaskLifecycle::Deferred
    )
}
