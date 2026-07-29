use gorce_protocol::{GoalLink, PlanRevision, TaskRevision};

use crate::error::Result;
use crate::goal::GoalAggregate;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoalAlignmentIssue {
    PlanUsesNonApprovedGoalRevision {
        expected: Option<gorce_protocol::GoalRevisionId>,
        actual: gorce_protocol::GoalRevisionId,
    },
    ItemHasNoGoalLink {
        plan_item_id: gorce_protocol::PlanItemId,
    },
    ItemDoesNotSupportPlanGoal {
        plan_item_id: gorce_protocol::PlanItemId,
    },
    UnknownGoalRevision {
        goal_revision_id: gorce_protocol::GoalRevisionId,
    },
    LinkHasWrongGoal {
        plan_item_id: gorce_protocol::PlanItemId,
        goal_id: gorce_protocol::GoalId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalAlignmentReview {
    pub goal_id: gorce_protocol::GoalId,
    pub plan_id: gorce_protocol::PlanId,
    pub aligned: bool,
    pub issues: Vec<GoalAlignmentIssue>,
}

pub fn review_goal_alignment(plan: &PlanRevision, goal: &GoalAggregate) -> GoalAlignmentReview {
    let mut issues = Vec::new();
    let approved = goal.approved_revision();
    if approved.map(|revision| revision.id) != Some(plan.goal_revision_id) {
        issues.push(GoalAlignmentIssue::PlanUsesNonApprovedGoalRevision {
            expected: approved.map(|revision| revision.id),
            actual: plan.goal_revision_id,
        });
    }
    if goal.find_revision(plan.goal_revision_id).is_none() {
        issues.push(GoalAlignmentIssue::UnknownGoalRevision {
            goal_revision_id: plan.goal_revision_id,
        });
    }
    for item in &plan.items {
        if item.goal_links.is_empty() {
            issues.push(GoalAlignmentIssue::ItemHasNoGoalLink {
                plan_item_id: item.id,
            });
            continue;
        }
        let mut supports_plan_goal = false;
        for link in &item.goal_links {
            if link.goal_id != goal.goal_id() {
                issues.push(GoalAlignmentIssue::LinkHasWrongGoal {
                    plan_item_id: item.id,
                    goal_id: link.goal_id,
                });
            }
            if link.goal_id == goal.goal_id() && link.goal_revision_id == plan.goal_revision_id {
                supports_plan_goal = true;
            }
        }
        if !supports_plan_goal {
            issues.push(GoalAlignmentIssue::ItemDoesNotSupportPlanGoal {
                plan_item_id: item.id,
            });
        }
    }
    GoalAlignmentReview {
        goal_id: goal.goal_id(),
        plan_id: plan.plan_id,
        aligned: issues.is_empty(),
        issues,
    }
}

pub fn review_task_alignment(
    task: &TaskRevision,
    goal: &GoalAggregate,
) -> Result<GoalAlignmentReview> {
    let links: Vec<GoalLink> = task.goal_links.clone();
    let plan = PlanRevision {
        id: task.id,
        plan_id: task.task_id,
        project_id: goal.project_id(),
        goal_revision_id: goal.current().id,
        revision: 1,
        revision_hash: task.revision_hash.clone(),
        summary: task.title.clone(),
        items: vec![gorce_protocol::PlanItem {
            id: task.id,
            title: task.title.clone(),
            goal_links: links,
            task_id: Some(task.task_id),
            task_revision_id: Some(task.id),
        }],
        promotion_mappings: Vec::new(),
        status: gorce_protocol::RevisionStatus::Draft,
        created_by: task.created_by,
        created_at: task.created_at.clone(),
    };
    Ok(review_goal_alignment(&plan, goal))
}
