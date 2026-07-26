use std::collections::{BTreeMap, BTreeSet, VecDeque};

use gorce_protocol::{
    OperatorId, ProjectId, ReadinessStatus, Task, TaskEdge, TaskEdgeId, TaskEdgeKind, TaskId,
    TaskLifecycle, TaskReadiness, TaskRevision, TaskRevisionId,
};

use crate::error::{CoreError, EntityKind, Result};

pub type AddEdge = TaskEdge;
pub type ReadinessProjection = TaskReadiness;
pub type ParentChildGraph = TaskGraph;

pub fn readiness_projection(
    blocked_by: impl IntoIterator<Item = TaskId>,
    lifecycles: &BTreeMap<TaskId, TaskLifecycle>,
    evaluated_at: impl Into<String>,
) -> TaskReadiness {
    let blocked_by: BTreeSet<_> = blocked_by.into_iter().collect();
    let blocker_task_ids: Vec<_> = blocked_by
        .iter()
        .copied()
        .filter(|task_id| {
            lifecycles
                .get(task_id)
                .map(|lifecycle| *lifecycle != TaskLifecycle::Completed)
                .unwrap_or(true)
        })
        .collect();
    let unknown = blocked_by
        .iter()
        .any(|task_id| !lifecycles.contains_key(task_id));
    TaskReadiness {
        status: if unknown {
            ReadinessStatus::Unknown
        } else if blocker_task_ids.is_empty() {
            ReadinessStatus::Ready
        } else {
            ReadinessStatus::Blocked
        },
        blocker_task_ids,
        evaluated_at: evaluated_at.into(),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskRevisionDraft {
    pub id: TaskRevisionId,
    pub task_id: TaskId,
    pub project_id: ProjectId,
    pub workstream_id: Option<gorce_protocol::WorkstreamId>,
    pub title: String,
    pub description: Option<String>,
    pub acceptance_criteria: Vec<String>,
    pub goal_links: Vec<gorce_protocol::GoalLink>,
    pub revision_hash: String,
    pub created_by: OperatorId,
    pub created_at: String,
    pub evaluated_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskRevisionCommand {
    pub id: TaskRevisionId,
    pub title: String,
    pub description: Option<String>,
    pub acceptance_criteria: Vec<String>,
    pub goal_links: Vec<gorce_protocol::GoalLink>,
    pub revision_hash: String,
    pub created_by: OperatorId,
    pub created_at: String,
    pub expected_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleEvent {
    pub task_id: TaskId,
    pub from: TaskLifecycle,
    pub to: TaskLifecycle,
    pub actor: OperatorId,
    pub reason: String,
    pub expected_revision: u64,
    pub revision: u64,
    pub at: String,
    pub replacement_task_ids: Vec<TaskId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelTaskCommand {
    pub expected_revision: u64,
    pub actor: OperatorId,
    pub reason: String,
    pub at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteTaskCommand {
    pub expected_revision: u64,
    pub actor: OperatorId,
    pub reason: String,
    pub at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferTaskCommand {
    pub expected_revision: u64,
    pub actor: OperatorId,
    pub reason: String,
    pub at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitTaskCommand {
    pub expected_revision: u64,
    pub actor: OperatorId,
    pub reason: String,
    pub at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenTaskCommand {
    pub expected_revision: u64,
    pub actor: OperatorId,
    pub reason: String,
    pub at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupersedeTaskCommand {
    pub expected_revision: u64,
    pub actor: OperatorId,
    pub reason: String,
    pub replacement_task_ids: Vec<TaskId>,
    pub at: String,
}

impl SupersedeTaskCommand {
    pub fn single(
        expected_revision: u64,
        actor: OperatorId,
        reason: impl Into<String>,
        replacement_task_id: TaskId,
        at: impl Into<String>,
    ) -> Self {
        Self {
            expected_revision,
            actor,
            reason: reason.into(),
            replacement_task_ids: vec![replacement_task_id],
            at: at.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskTransitionCommand {
    pub target: TaskLifecycle,
    pub expected_revision: u64,
    pub actor: OperatorId,
    pub reason: String,
    pub at: String,
    pub replacement_task_ids: Vec<TaskId>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskAggregate {
    task: Task,
    revisions: Vec<TaskRevision>,
    lifecycle_events: Vec<LifecycleEvent>,
    version: u64,
}

impl TaskAggregate {
    pub fn create(draft: TaskRevisionDraft) -> Result<Self> {
        Self::new(draft)
    }

    pub fn new(draft: TaskRevisionDraft) -> Result<Self> {
        validate_draft(&draft)?;
        let revision = TaskRevision {
            id: draft.id,
            task_id: draft.task_id,
            revision: 1,
            title: draft.title,
            description: draft.description,
            acceptance_criteria: draft.acceptance_criteria,
            goal_links: draft.goal_links,
            revision_hash: draft.revision_hash,
            created_by: draft.created_by,
            created_at: draft.created_at,
        };
        let task = Task {
            id: draft.task_id,
            project_id: draft.project_id,
            workstream_id: draft.workstream_id,
            lifecycle: TaskLifecycle::Open,
            readiness: TaskReadiness {
                status: ReadinessStatus::Ready,
                blocker_task_ids: Vec::new(),
                evaluated_at: draft.evaluated_at,
            },
            current_revision_id: Some(revision.id),
            created_at: revision.created_at.clone(),
            updated_at: draft.updated_at,
        };
        Ok(Self {
            task,
            revisions: vec![revision],
            lifecycle_events: Vec::new(),
            version: 1,
        })
    }

    pub fn from_parts(task: Task, revision: TaskRevision) -> Result<Self> {
        if task.id.is_nil() || task.project_id.is_nil() || revision.id.is_nil() {
            return Err(CoreError::invalid("identity", "IDs must not be nil"));
        }
        if revision.task_id != task.id || revision.revision != 1 {
            return Err(CoreError::invalid(
                "revision",
                "the first task revision must belong to the task and be revision 1",
            ));
        }
        if task.current_revision_id != Some(revision.id) {
            return Err(CoreError::invalid(
                "current_revision_id",
                "must point to the initial task revision",
            ));
        }
        Ok(Self {
            task,
            revisions: vec![revision],
            lifecycle_events: Vec::new(),
            version: 1,
        })
    }

    pub fn revise(&self, command: TaskRevisionCommand) -> Result<Self> {
        if command.expected_revision != self.version {
            return Err(CoreError::conflict(
                EntityKind::Task,
                self.id(),
                command.expected_revision,
                self.version,
            ));
        }
        if command.id.is_nil() {
            return Err(CoreError::invalid("id", "must not be nil"));
        }
        if command.title.trim().is_empty()
            || command.revision_hash.trim().is_empty()
            || command
                .acceptance_criteria
                .iter()
                .any(|item| item.trim().is_empty())
        {
            return Err(CoreError::invalid(
                "revision",
                "title, hash, and acceptance criteria must not be empty",
            ));
        }
        if self
            .revisions
            .iter()
            .any(|revision| revision.id == command.id)
        {
            return Err(CoreError::Duplicate {
                entity: EntityKind::TaskRevision,
                id: command.id,
            });
        }
        let revision = TaskRevision {
            id: command.id,
            task_id: self.id(),
            revision: self.current_revision().revision + 1,
            title: command.title,
            description: command.description,
            acceptance_criteria: command.acceptance_criteria,
            goal_links: command.goal_links,
            revision_hash: command.revision_hash,
            created_by: command.created_by,
            created_at: command.created_at,
        };
        let mut next = self.clone();
        next.task.current_revision_id = Some(revision.id);
        next.task.updated_at = revision.created_at.clone();
        next.revisions.push(revision);
        next.version += 1;
        Ok(next)
    }

    pub fn transition(&self, command: TaskTransitionCommand) -> Result<Self> {
        if command.expected_revision != self.version {
            return Err(CoreError::conflict(
                EntityKind::Task,
                self.id(),
                command.expected_revision,
                self.version,
            ));
        }
        if command.reason.trim().is_empty() {
            return Err(CoreError::invalid("reason", "must not be empty"));
        }
        if command.actor.is_nil() {
            return Err(CoreError::invalid("actor", "must not be nil"));
        }
        if command.at.trim().is_empty() {
            return Err(CoreError::invalid("at", "must not be empty"));
        }
        if command.target == TaskLifecycle::Superseded && command.replacement_task_ids.is_empty() {
            return Err(CoreError::MissingReplacement { task_id: self.id() });
        }
        if command
            .replacement_task_ids
            .iter()
            .any(|replacement| *replacement == self.id() || replacement.is_nil())
            || command.replacement_task_ids.len()
                != command
                    .replacement_task_ids
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
        {
            return Err(CoreError::invalid(
                "replacement_task_ids",
                "replacements must be non-nil and distinct from the source task",
            ));
        }
        if !valid_transition(self.task.lifecycle.clone(), command.target.clone()) {
            return Err(CoreError::InvalidTransition {
                task_id: self.id(),
                from: self.task.lifecycle.clone(),
                to: command.target,
            });
        }
        let mut next = self.clone();
        let event = LifecycleEvent {
            task_id: self.id(),
            from: self.task.lifecycle.clone(),
            to: command.target.clone(),
            actor: command.actor,
            reason: command.reason,
            expected_revision: command.expected_revision,
            revision: self.version + 1,
            at: command.at.clone(),
            replacement_task_ids: command.replacement_task_ids,
        };
        next.task.lifecycle = command.target;
        next.task.updated_at = command.at;
        next.version += 1;
        next.lifecycle_events.push(event);
        Ok(next)
    }

    pub fn cancel(&self, command: CancelTaskCommand) -> Result<Self> {
        self.transition(TaskTransitionCommand {
            target: TaskLifecycle::Cancelled,
            expected_revision: command.expected_revision,
            actor: command.actor,
            reason: command.reason,
            at: command.at,
            replacement_task_ids: Vec::new(),
        })
    }

    pub fn complete(&self, command: CompleteTaskCommand) -> Result<Self> {
        self.transition(TaskTransitionCommand {
            target: TaskLifecycle::Completed,
            expected_revision: command.expected_revision,
            actor: command.actor,
            reason: command.reason,
            at: command.at,
            replacement_task_ids: Vec::new(),
        })
    }

    pub fn defer(&self, command: DeferTaskCommand) -> Result<Self> {
        self.transition(TaskTransitionCommand {
            target: TaskLifecycle::Deferred,
            expected_revision: command.expected_revision,
            actor: command.actor,
            reason: command.reason,
            at: command.at,
            replacement_task_ids: Vec::new(),
        })
    }

    pub fn wait(&self, command: WaitTaskCommand) -> Result<Self> {
        self.transition(TaskTransitionCommand {
            target: TaskLifecycle::Waiting,
            expected_revision: command.expected_revision,
            actor: command.actor,
            reason: command.reason,
            at: command.at,
            replacement_task_ids: Vec::new(),
        })
    }

    pub fn open(&self, command: OpenTaskCommand) -> Result<Self> {
        self.transition(TaskTransitionCommand {
            target: TaskLifecycle::Open,
            expected_revision: command.expected_revision,
            actor: command.actor,
            reason: command.reason,
            at: command.at,
            replacement_task_ids: Vec::new(),
        })
    }

    pub fn supersede(&self, command: SupersedeTaskCommand) -> Result<Self> {
        self.transition(TaskTransitionCommand {
            target: TaskLifecycle::Superseded,
            expected_revision: command.expected_revision,
            actor: command.actor,
            reason: command.reason,
            at: command.at,
            replacement_task_ids: command.replacement_task_ids,
        })
    }

    pub fn with_readiness(&self, readiness: TaskReadiness) -> Self {
        let mut next = self.clone();
        next.task.readiness = readiness;
        next
    }

    pub fn id(&self) -> TaskId {
        self.task.id
    }

    pub fn task(&self) -> &Task {
        &self.task
    }

    pub fn current_revision(&self) -> &TaskRevision {
        self.revisions
            .last()
            .expect("aggregate always has a revision")
    }

    pub fn revision(&self) -> Option<&TaskRevision> {
        Some(self.current_revision())
    }

    pub fn revisions(&self) -> &[TaskRevision] {
        &self.revisions
    }

    pub fn lifecycle_events(&self) -> &[LifecycleEvent] {
        &self.lifecycle_events
    }

    pub fn version(&self) -> u64 {
        self.version
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DependencyGraph;

impl DependencyGraph {
    pub fn edge(
        from_task_id: TaskId,
        to_task_id: TaskId,
        id: TaskEdgeId,
        created_at: &str,
    ) -> TaskEdge {
        TaskEdge {
            id,
            project_id: ProjectId::nil(),
            from_task_id,
            to_task_id,
            kind: TaskEdgeKind::Dependency,
            created_at: created_at.to_owned(),
        }
    }

    pub fn blocked_by(
        task_id: TaskId,
        blocker_task_id: TaskId,
        id: TaskEdgeId,
        created_at: &str,
    ) -> TaskEdge {
        Self::edge(task_id, blocker_task_id, id, created_at)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskGraph {
    tasks: BTreeMap<TaskId, TaskAggregate>,
    edges: BTreeMap<TaskEdgeId, TaskEdge>,
}

impl TaskGraph {
    pub fn new() -> Self {
        Self {
            tasks: BTreeMap::new(),
            edges: BTreeMap::new(),
        }
    }

    pub fn from_tasks<I>(tasks: I) -> Result<Self>
    where
        I: IntoIterator<Item = TaskAggregate>,
    {
        let mut graph = Self::new();
        for task in tasks {
            graph = graph.insert(task)?;
        }
        Ok(graph)
    }

    pub fn insert(&self, task: TaskAggregate) -> Result<Self> {
        if self.tasks.contains_key(&task.id()) {
            return Err(CoreError::Duplicate {
                entity: EntityKind::Task,
                id: task.id(),
            });
        }
        let mut next = self.clone();
        next.tasks.insert(task.id(), task);
        Ok(next)
    }

    pub fn add_edge(&self, mut edge: TaskEdge) -> Result<Self> {
        let from = self
            .tasks
            .get(&edge.from_task_id)
            .ok_or(CoreError::NotFound {
                entity: EntityKind::Task,
                id: edge.from_task_id,
            })?;
        let to = self
            .tasks
            .get(&edge.to_task_id)
            .ok_or(CoreError::NotFound {
                entity: EntityKind::Task,
                id: edge.to_task_id,
            })?;
        if edge.from_task_id == edge.to_task_id {
            return Err(CoreError::CycleDetected {
                kind: edge.kind,
                from: edge.from_task_id,
                to: edge.to_task_id,
            });
        }
        if from.task().project_id != to.task().project_id {
            return Err(CoreError::invalid(
                "project_id",
                "edge endpoints must share a project",
            ));
        }
        if edge.project_id.is_nil() {
            edge.project_id = from.task().project_id;
        }
        if edge.project_id != from.task().project_id {
            return Err(CoreError::invalid(
                "project_id",
                "edge must belong to its endpoints' project",
            ));
        }
        if let Some(existing) = self.edges.get(&edge.id) {
            if existing == &edge {
                return Ok(self.clone());
            }
            return Err(CoreError::Duplicate {
                entity: EntityKind::TaskRevision,
                id: edge.id,
            });
        }
        if self.has_path(edge.kind.clone(), edge.to_task_id, edge.from_task_id) {
            return Err(CoreError::CycleDetected {
                kind: edge.kind,
                from: edge.from_task_id,
                to: edge.to_task_id,
            });
        }
        let mut next = self.clone();
        next.edges.insert(edge.id, edge);
        Ok(next)
    }

    pub fn add_dependency(&self, mut edge: TaskEdge) -> Result<Self> {
        edge.kind = TaskEdgeKind::Dependency;
        self.add_edge(edge)
    }

    pub fn add_blocked_by(&self, edge: TaskEdge) -> Result<Self> {
        self.add_dependency(edge)
    }

    pub fn add_parent(&self, mut edge: TaskEdge) -> Result<Self> {
        edge.kind = TaskEdgeKind::Parent;
        if let Some(parent) = self.parent(edge.to_task_id)? {
            if parent != edge.from_task_id {
                return Err(CoreError::invalid(
                    "parent",
                    "a task may have only one parent",
                ));
            }
        }
        self.add_edge(edge)
    }

    pub fn add_supersession(&self, mut edge: TaskEdge) -> Result<Self> {
        edge.kind = TaskEdgeKind::Supersedes;
        self.add_edge(edge)
    }

    pub fn task(&self, id: TaskId) -> Option<&TaskAggregate> {
        self.tasks.get(&id)
    }

    pub fn tasks(&self) -> impl Iterator<Item = &TaskAggregate> {
        self.tasks.values()
    }

    pub fn edges(&self) -> impl Iterator<Item = &TaskEdge> {
        self.edges.values()
    }

    pub fn dependencies(&self, task_id: TaskId) -> Result<Vec<TaskId>> {
        self.ensure_task(task_id)?;
        Ok(self
            .edges
            .values()
            .filter(|edge| edge.kind == TaskEdgeKind::Dependency && edge.from_task_id == task_id)
            .map(|edge| edge.to_task_id)
            .collect())
    }

    pub fn children(&self, parent_id: TaskId) -> Result<Vec<TaskId>> {
        self.ensure_task(parent_id)?;
        Ok(self
            .edges
            .values()
            .filter(|edge| edge.kind == TaskEdgeKind::Parent && edge.from_task_id == parent_id)
            .map(|edge| edge.to_task_id)
            .collect())
    }

    pub fn parent(&self, child_id: TaskId) -> Result<Option<TaskId>> {
        self.ensure_task(child_id)?;
        Ok(self
            .edges
            .values()
            .find(|edge| edge.kind == TaskEdgeKind::Parent && edge.to_task_id == child_id)
            .map(|edge| edge.from_task_id))
    }

    pub fn readiness(&self, task_id: TaskId) -> Result<TaskReadiness> {
        self.ensure_task(task_id)?;
        let blocker_task_ids = self
            .dependencies(task_id)?
            .into_iter()
            .filter(|dependency| !self.dependency_resolved(*dependency, &mut BTreeSet::new()))
            .collect::<Vec<_>>();
        Ok(TaskReadiness {
            status: if blocker_task_ids.is_empty() {
                ReadinessStatus::Ready
            } else {
                ReadinessStatus::Blocked
            },
            blocker_task_ids,
            evaluated_at: self
                .task(task_id)
                .expect("task was checked")
                .task()
                .readiness
                .evaluated_at
                .clone(),
        })
    }

    pub fn readiness_at(
        &self,
        task_id: TaskId,
        evaluated_at: impl Into<String>,
    ) -> Result<TaskReadiness> {
        let mut readiness = self.readiness(task_id)?;
        readiness.evaluated_at = evaluated_at.into();
        Ok(readiness)
    }

    pub fn project_readiness(&self, evaluated_at: impl Into<String>) -> Result<Self> {
        let evaluated_at = evaluated_at.into();
        let mut next = self.clone();
        for task_id in self.tasks.keys().copied().collect::<Vec<_>>() {
            let mut readiness = self.readiness(task_id)?;
            readiness.evaluated_at = evaluated_at.clone();
            next.tasks.insert(
                task_id,
                self.tasks
                    .get(&task_id)
                    .expect("task was checked")
                    .with_readiness(readiness),
            );
        }
        Ok(next)
    }

    pub fn apply(&self, task_id: TaskId, command: TaskTransitionCommand) -> Result<Self> {
        let task = self.tasks.get(&task_id).ok_or(CoreError::NotFound {
            entity: EntityKind::Task,
            id: task_id,
        })?;
        let updated = task.transition(command)?;
        let mut next = self.clone();
        next.tasks.insert(task_id, updated);
        Ok(next)
    }

    pub fn cancel(&self, task_id: TaskId, command: CancelTaskCommand) -> Result<Self> {
        let task = self.tasks.get(&task_id).ok_or(CoreError::NotFound {
            entity: EntityKind::Task,
            id: task_id,
        })?;
        let updated = task.cancel(command)?;
        let mut next = self.clone();
        next.tasks.insert(task_id, updated);
        Ok(next)
    }

    pub fn complete(&self, task_id: TaskId, command: CompleteTaskCommand) -> Result<Self> {
        let task = self.tasks.get(&task_id).ok_or(CoreError::NotFound {
            entity: EntityKind::Task,
            id: task_id,
        })?;
        let updated = task.complete(command)?;
        let mut next = self.clone();
        next.tasks.insert(task_id, updated);
        Ok(next)
    }

    pub fn defer(&self, task_id: TaskId, command: DeferTaskCommand) -> Result<Self> {
        let task = self.tasks.get(&task_id).ok_or(CoreError::NotFound {
            entity: EntityKind::Task,
            id: task_id,
        })?;
        let updated = task.defer(command)?;
        let mut next = self.clone();
        next.tasks.insert(task_id, updated);
        Ok(next)
    }

    pub fn supersede(
        &self,
        task_id: TaskId,
        command: SupersedeTaskCommand,
        replacement_edges: Vec<TaskEdge>,
    ) -> Result<Self> {
        let task = self.tasks.get(&task_id).ok_or(CoreError::NotFound {
            entity: EntityKind::Task,
            id: task_id,
        })?;
        if command.replacement_task_ids.len() != replacement_edges.len() {
            return Err(CoreError::invalid(
                "replacement_edges",
                "one supersedes edge is required for each replacement",
            ));
        }
        for (replacement, edge) in command.replacement_task_ids.iter().zip(&replacement_edges) {
            if edge.from_task_id != task_id || edge.to_task_id != *replacement {
                return Err(CoreError::invalid(
                    "replacement_edges",
                    "supersedes edges must point from the source to each replacement",
                ));
            }
        }
        let updated = task.supersede(command)?;
        let mut next = self.clone();
        next.tasks.insert(task_id, updated);
        for edge in replacement_edges {
            next = next.add_supersession(edge)?;
        }
        Ok(next)
    }

    fn ensure_task(&self, id: TaskId) -> Result<()> {
        self.tasks
            .contains_key(&id)
            .then_some(())
            .ok_or(CoreError::NotFound {
                entity: EntityKind::Task,
                id,
            })
    }

    fn has_path(&self, kind: TaskEdgeKind, start: TaskId, target: TaskId) -> bool {
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::from([start]);
        while let Some(current) = queue.pop_front() {
            if current == target {
                return true;
            }
            if !visited.insert(current) {
                continue;
            }
            for edge in self
                .edges
                .values()
                .filter(|edge| edge.kind == kind && edge.from_task_id == current)
            {
                queue.push_back(edge.to_task_id);
            }
        }
        false
    }

    fn dependency_resolved(&self, task_id: TaskId, visited: &mut BTreeSet<TaskId>) -> bool {
        let Some(task) = self.task(task_id) else {
            return false;
        };
        match task.task().lifecycle {
            TaskLifecycle::Completed => true,
            TaskLifecycle::Superseded => {
                if !visited.insert(task_id) {
                    return false;
                }
                self.edges
                    .values()
                    .filter(|edge| {
                        edge.kind == TaskEdgeKind::Supersedes && edge.from_task_id == task_id
                    })
                    .any(|edge| self.dependency_resolved(edge.to_task_id, visited))
            }
            TaskLifecycle::Open
            | TaskLifecycle::Waiting
            | TaskLifecycle::Deferred
            | TaskLifecycle::Cancelled => false,
        }
    }
}

impl Default for TaskGraph {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_draft(draft: &TaskRevisionDraft) -> Result<()> {
    if draft.id.is_nil() || draft.task_id.is_nil() || draft.project_id.is_nil() {
        return Err(CoreError::invalid("identity", "IDs must not be nil"));
    }
    if draft.title.trim().is_empty() || draft.revision_hash.trim().is_empty() {
        return Err(CoreError::invalid(
            "revision",
            "title and hash must not be empty",
        ));
    }
    if draft
        .acceptance_criteria
        .iter()
        .any(|item| item.trim().is_empty())
    {
        return Err(CoreError::invalid(
            "acceptance_criteria",
            "criteria must not be empty",
        ));
    }
    Ok(())
}

fn valid_transition(from: TaskLifecycle, to: TaskLifecycle) -> bool {
    match from {
        TaskLifecycle::Open => matches!(
            to,
            TaskLifecycle::Waiting
                | TaskLifecycle::Deferred
                | TaskLifecycle::Completed
                | TaskLifecycle::Cancelled
                | TaskLifecycle::Superseded
        ),
        TaskLifecycle::Waiting => matches!(
            to,
            TaskLifecycle::Open
                | TaskLifecycle::Deferred
                | TaskLifecycle::Completed
                | TaskLifecycle::Cancelled
                | TaskLifecycle::Superseded
        ),
        TaskLifecycle::Deferred => matches!(
            to,
            TaskLifecycle::Open
                | TaskLifecycle::Waiting
                | TaskLifecycle::Completed
                | TaskLifecycle::Cancelled
                | TaskLifecycle::Superseded
        ),
        TaskLifecycle::Completed | TaskLifecycle::Cancelled | TaskLifecycle::Superseded => false,
    }
}
