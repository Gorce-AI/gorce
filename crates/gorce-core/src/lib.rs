#![forbid(unsafe_code)]

pub mod alignment;
pub mod error;
pub mod goal;
pub mod plan;
pub mod promotion;
pub mod task;
pub mod workstream;

pub use alignment::{
    review_goal_alignment, review_task_alignment, GoalAlignmentIssue, GoalAlignmentReview,
};
pub use error::{
    Conflict, CoreError, DomainError, EntityKind, OptimisticConcurrencyError, Result,
    RevisionConflict,
};
pub use goal::{GoalAggregate, GoalRevisionDraft};
pub use plan::{PlanAggregate, PlanRevisionDraft};
pub use promotion::{merge_plan_promotion, normalize_promotion_mappings, PlanPromotion};
pub use task::{
    readiness_projection, AddEdge, CancelTaskCommand, CompleteTaskCommand, DeferTaskCommand,
    DependencyGraph, LifecycleEvent, OpenTaskCommand, ParentChildGraph, ReadinessProjection,
    SupersedeTaskCommand, TaskAggregate, TaskGraph, TaskRevisionCommand, TaskRevisionDraft,
    TaskTransitionCommand, WaitTaskCommand,
};
pub use workstream::{
    WorkstreamAggregate, WorkstreamRevision, WorkstreamRevisionDraft, WorkstreamRevisionId,
};

pub use gorce_protocol::{
    GoalId, GoalLink, GoalLinkRelation, GoalRevision, PlanId, PlanItem, PlanItemId, PlanRevision,
    PromotionDisposition, PromotionMapping, ReadinessStatus, RevisionStatus, Task, TaskEdge,
    TaskEdgeId, TaskEdgeKind, TaskId, TaskLifecycle, TaskReadiness, TaskRevision, TaskRevisionId,
    WorkstreamId, WorkstreamStatus,
};

pub const CORE_VERSION: &str = "0.1";

pub fn core_version() -> &'static str {
    let _ = gorce_protocol::protocol_version();
    CORE_VERSION
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        core_version, review_goal_alignment, CancelTaskCommand, CompleteTaskCommand,
        DeferTaskCommand, DependencyGraph, GoalAggregate, GoalRevision, GoalRevisionDraft,
        PlanRevision, RevisionConflict, TaskAggregate, TaskGraph, TaskRevisionCommand,
        TaskRevisionDraft, TaskTransitionCommand, WorkstreamAggregate, WorkstreamRevisionDraft,
        CORE_VERSION,
    };
    use gorce_protocol::{
        GoalLink, GoalLinkRelation, PlanItem, PromotionDisposition, PromotionMapping,
        RevisionStatus, TaskLifecycle,
    };

    fn id(value: u128) -> gorce_protocol::ProjectId {
        gorce_protocol::ProjectId::from_u128(value)
    }

    fn goal_revision(
        goal_id: gorce_protocol::GoalId,
        revision_id: gorce_protocol::GoalRevisionId,
        revision: u64,
        status: RevisionStatus,
    ) -> GoalRevision {
        GoalRevision {
            id: revision_id,
            goal_id,
            project_id: id(1),
            workstream_id: None,
            revision,
            title: format!("Goal {revision}"),
            statement: "Make the invariant explicit".to_owned(),
            revision_hash: format!("{revision:064x}"),
            status,
            created_by: id(9),
            created_at: format!("2026-01-01T00:00:0{revision}Z"),
        }
    }

    fn task(
        task_id: gorce_protocol::TaskId,
        revision_id: gorce_protocol::TaskRevisionId,
    ) -> TaskAggregate {
        TaskAggregate::new(TaskRevisionDraft {
            id: revision_id,
            task_id,
            project_id: id(1),
            workstream_id: None,
            title: format!("Task {task_id}"),
            description: None,
            acceptance_criteria: vec!["It is true".to_owned()],
            goal_links: Vec::new(),
            revision_hash: "a".repeat(64),
            created_by: id(9),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            evaluated_at: "2026-01-01T00:00:00Z".to_owned(),
            updated_at: "2026-01-01T00:00:00Z".to_owned(),
        })
        .unwrap()
    }

    #[test]
    fn exposes_the_core_version() {
        assert_eq!(core_version(), CORE_VERSION);
    }

    #[test]
    fn revisions_are_append_only_and_conflicts_are_typed() {
        let goal_id = id(10);
        let goal =
            GoalAggregate::new(goal_revision(goal_id, id(11), 1, RevisionStatus::Draft)).unwrap();
        let revised = goal
            .revise(GoalRevisionDraft {
                id: id(12),
                title: "A revised goal".to_owned(),
                statement: "The same goal, made clearer".to_owned(),
                revision_hash: "b".repeat(64),
                status: RevisionStatus::Proposed,
                created_by: id(9),
                created_at: "2026-01-01T00:00:02Z".to_owned(),
                expected_revision: 1,
            })
            .unwrap();

        assert_eq!(goal.revisions().len(), 1);
        assert_eq!(revised.revisions().len(), 2);
        assert_eq!(revised.current().revision, 2);
        assert!(matches!(
            revised.revise(GoalRevisionDraft {
                id: id(13),
                title: "Conflict".to_owned(),
                statement: "Conflict".to_owned(),
                revision_hash: "c".repeat(64),
                status: RevisionStatus::Draft,
                created_by: id(9),
                created_at: "2026-01-01T00:00:03Z".to_owned(),
                expected_revision: 1,
            }),
            Err(super::CoreError::Conflict(RevisionConflict {
                expected: 1,
                actual: 2,
                ..
            }))
        ));
    }

    #[test]
    fn workstream_structure_revisions_are_immutable() {
        let workstream = WorkstreamAggregate::new(WorkstreamRevisionDraft {
            id: id(20),
            workstream_id: id(21),
            project_id: id(1),
            name: "Core".to_owned(),
            description: None,
            status: gorce_protocol::WorkstreamStatus::Active,
            revision_hash: "a".repeat(64),
            created_by: id(9),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            expected_revision: None,
        })
        .unwrap();
        let changed = workstream
            .revise(WorkstreamRevisionDraft {
                id: id(22),
                workstream_id: id(21),
                project_id: id(1),
                name: "Core Domain".to_owned(),
                description: Some("The domain boundary".to_owned()),
                status: gorce_protocol::WorkstreamStatus::Active,
                revision_hash: "b".repeat(64),
                created_by: id(9),
                created_at: "2026-01-01T00:00:01Z".to_owned(),
                expected_revision: Some(1),
            })
            .unwrap();
        assert_eq!(workstream.revisions().len(), 1);
        assert_eq!(changed.revisions().len(), 2);
        assert_eq!(changed.current().name, "Core Domain");
    }

    #[test]
    fn task_identity_survives_revisions_and_lifecycle_requires_cas() {
        let task_id = id(30);
        let original = task(task_id, id(31));
        let revised = original
            .revise(TaskRevisionCommand {
                id: id(32),
                title: "Changed title".to_owned(),
                description: None,
                acceptance_criteria: vec!["Still true".to_owned()],
                goal_links: Vec::new(),
                revision_hash: "b".repeat(64),
                created_by: id(9),
                created_at: "2026-01-01T00:00:01Z".to_owned(),
                expected_revision: 1,
            })
            .unwrap();
        assert_eq!(revised.id(), task_id);
        assert_eq!(revised.revision().unwrap().revision, 2);
        assert!(matches!(
            revised.cancel(CancelTaskCommand {
                expected_revision: 1,
                actor: id(9),
                reason: "No longer needed".to_owned(),
                at: "2026-01-01T00:00:02Z".to_owned(),
            }),
            Err(super::CoreError::Conflict(RevisionConflict {
                expected: 1,
                actual: 2,
                ..
            }))
        ));
        let cancelled = revised
            .cancel(CancelTaskCommand {
                expected_revision: 2,
                actor: id(9),
                reason: "No longer needed".to_owned(),
                at: "2026-01-01T00:00:02Z".to_owned(),
            })
            .unwrap();
        assert_eq!(cancelled.task().lifecycle, TaskLifecycle::Cancelled);
        assert_eq!(cancelled.lifecycle_events().len(), 1);
    }

    #[test]
    fn dependency_projection_keeps_deferred_tasks_blocking() {
        let blocker = task(id(40), id(41));
        let waiting = task(id(42), id(43));
        let graph = TaskGraph::from_tasks([blocker, waiting]).unwrap();
        let graph = graph
            .add_dependency(DependencyGraph::edge(
                id(42),
                id(40),
                id(44),
                "2026-01-01T00:00:00Z",
            ))
            .unwrap();
        let graph = graph
            .defer(
                id(40),
                DeferTaskCommand {
                    expected_revision: 1,
                    actor: id(9),
                    reason: "Waiting for input".to_owned(),
                    at: "2026-01-01T00:00:01Z".to_owned(),
                },
            )
            .unwrap();
        let projection = graph.readiness(id(42)).unwrap();
        assert_eq!(projection.status, gorce_protocol::ReadinessStatus::Blocked);
        assert_eq!(projection.blocker_task_ids, vec![id(40)]);
        let graph = graph
            .complete(
                id(40),
                CompleteTaskCommand {
                    expected_revision: 2,
                    actor: id(9),
                    reason: "Input arrived".to_owned(),
                    at: "2026-01-01T00:00:02Z".to_owned(),
                },
            )
            .unwrap();
        assert_eq!(
            graph.readiness(id(42)).unwrap().status,
            gorce_protocol::ReadinessStatus::Ready
        );
    }

    #[test]
    fn lifecycle_table_covers_dispositions_and_supersede_requires_replacement() {
        let mut task = task(id(80), id(81));
        let transitions = [
            (TaskLifecycle::Waiting, "waiting"),
            (TaskLifecycle::Deferred, "deferred"),
            (TaskLifecycle::Open, "open"),
            (TaskLifecycle::Completed, "completed"),
        ];
        for (target, reason) in transitions {
            task = task
                .transition(TaskTransitionCommand {
                    target,
                    expected_revision: task.version(),
                    actor: id(9),
                    reason: reason.to_owned(),
                    at: "2026-01-01T00:00:00Z".to_owned(),
                    replacement_task_ids: Vec::new(),
                })
                .unwrap();
        }
        assert_eq!(task.task().lifecycle, TaskLifecycle::Completed);
        assert!(task
            .transition(TaskTransitionCommand {
                target: TaskLifecycle::Superseded,
                expected_revision: task.version(),
                actor: id(9),
                reason: "Replace it".to_owned(),
                at: "2026-01-01T00:00:00Z".to_owned(),
                replacement_task_ids: Vec::new(),
            })
            .is_err());
        let readiness =
            super::readiness_projection([id(999)], &BTreeMap::new(), "2026-01-01T00:00:00Z");
        assert_eq!(readiness.status, gorce_protocol::ReadinessStatus::Unknown);
    }

    #[test]
    fn parent_and_dependency_cycles_are_rejected() {
        let graph = TaskGraph::from_tasks([task(id(50), id(51)), task(id(52), id(53))]).unwrap();
        let graph = graph
            .add_parent(DependencyGraph::edge(
                id(50),
                id(52),
                id(54),
                "2026-01-01T00:00:00Z",
            ))
            .unwrap();
        assert!(graph
            .add_parent(DependencyGraph::edge(
                id(52),
                id(50),
                id(55),
                "2026-01-01T00:00:00Z"
            ))
            .is_err());
    }

    #[test]
    fn promotion_merges_unfinished_items_and_is_idempotent() {
        let old_item = PlanItem {
            id: id(60),
            title: "Unfinished".to_owned(),
            goal_links: vec![GoalLink {
                goal_id: id(10),
                goal_revision_id: id(11),
                relation: GoalLinkRelation::Supports,
            }],
            task_id: Some(id(30)),
            task_revision_id: Some(id(31)),
        };
        let previous = PlanRevision {
            id: id(61),
            plan_id: id(62),
            project_id: id(1),
            goal_revision_id: id(11),
            revision: 1,
            revision_hash: "a".repeat(64),
            summary: "Old".to_owned(),
            items: vec![old_item.clone()],
            promotion_mappings: Vec::new(),
            status: RevisionStatus::Approved,
            created_by: id(9),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
        };
        let mappings = vec![PromotionMapping {
            plan_item_id: old_item.id,
            disposition: PromotionDisposition::Keep,
            task_id: Some(id(30)),
            source_revision_id: None,
            target_revision_id: None,
            reason: None,
        }];
        let mut lifecycles = BTreeMap::new();
        lifecycles.insert(id(30), TaskLifecycle::Deferred);
        let first =
            super::merge_plan_promotion(&previous, Vec::new(), mappings.clone(), &lifecycles)
                .unwrap();
        let second = super::merge_plan_promotion(
            &previous,
            first.items.clone(),
            first.mappings.clone(),
            &lifecycles,
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.items, vec![old_item]);
        assert_eq!(first.mappings[0].disposition, PromotionDisposition::Keep);
    }

    #[test]
    fn alignment_review_is_explicit() {
        let goal =
            GoalAggregate::new(goal_revision(id(70), id(71), 1, RevisionStatus::Approved)).unwrap();
        let plan = PlanRevision {
            id: id(72),
            plan_id: id(73),
            project_id: id(1),
            goal_revision_id: id(71),
            revision: 1,
            revision_hash: "a".repeat(64),
            summary: "Plan".to_owned(),
            items: vec![PlanItem {
                id: id(74),
                title: "Item".to_owned(),
                goal_links: Vec::new(),
                task_id: None,
                task_revision_id: None,
            }],
            promotion_mappings: Vec::new(),
            status: RevisionStatus::Draft,
            created_by: id(9),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
        };
        let review = review_goal_alignment(&plan, &goal);
        assert!(!review.aligned);
        assert_eq!(review.issues.len(), 1);
    }
}
