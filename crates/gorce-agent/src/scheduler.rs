use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use gorce_core::TaskGraph;
use gorce_protocol::{OperatorId, TaskEdgeKind, TaskId, TaskLifecycle};
use uuid::Uuid;

use crate::agent::BoxFuture;
use crate::error::{AgentError, Result};
use crate::events::CancellationToken;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerTask {
    pub id: TaskId,
    pub dependencies: BTreeSet<TaskId>,
    pub retry_limit: u32,
    pub lifecycle_open: bool,
    pub readiness: bool,
    pub revision_aligned: bool,
    pub capability_aligned: bool,
    pub gates_satisfied: bool,
    pub budget_available: bool,
    pub active_attempt: bool,
}

impl SchedulerTask {
    pub fn new(id: TaskId) -> Self {
        Self {
            id,
            dependencies: BTreeSet::new(),
            retry_limit: 0,
            lifecycle_open: true,
            readiness: true,
            revision_aligned: true,
            capability_aligned: true,
            gates_satisfied: true,
            budget_available: true,
            active_attempt: false,
        }
    }

    pub fn depends_on(mut self, dependency: TaskId) -> Self {
        self.dependencies.insert(dependency);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerNodeState {
    Pending,
    Claimed,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeRecord {
    task: SchedulerTask,
    state: SchedulerNodeState,
    retries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskClaim {
    pub claim_id: Uuid,
    pub task_id: TaskId,
    pub worker_id: OperatorId,
    pub fencing_token: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompletionProof {
    pub evidence_id: Uuid,
    pub gate_passed: bool,
    pub immutable: bool,
}

impl CompletionProof {
    pub fn validate(&self) -> Result<()> {
        if self.evidence_id.is_nil() || !self.gate_passed || !self.immutable {
            return Err(AgentError::Conflict(
                "completion requires immutable evidence and a passed gate".to_owned(),
            ));
        }
        Ok(())
    }
}

pub trait SchedulerAuthorityPort: Send + Sync {
    fn claim(&self, request: SchedulerClaimRequest) -> BoxFuture<Result<Option<TaskClaim>>>;
    fn complete(&self, claim: TaskClaim, proof: CompletionProof) -> BoxFuture<Result<()>>;
    fn cancel(&self, claim: TaskClaim, cancellation: CancellationToken) -> BoxFuture<Result<()>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerClaimRequest {
    pub worker_id: OperatorId,
    pub task_id: Option<TaskId>,
    pub now_ms: u64,
    pub lifecycle_open: bool,
    pub readiness: bool,
    pub revision_aligned: bool,
    pub capability_aligned: bool,
    pub gates_satisfied: bool,
    pub budget_available: bool,
    pub active_attempt: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerLimits {
    pub max_tasks: usize,
    pub max_claims_per_worker: u32,
}

pub type SchedulerClaim = TaskClaim;

#[derive(Debug, Default)]
struct SchedulerState {
    nodes: BTreeMap<TaskId, NodeRecord>,
    claims: BTreeMap<Uuid, TaskClaim>,
    next_fencing_token: u64,
}

#[derive(Debug, Clone)]
pub struct DeterministicScheduler {
    state: Arc<Mutex<SchedulerState>>,
    limits: SchedulerLimits,
}

const MAX_TASK_DEPENDENCIES: usize = 1_024;

impl SchedulerAuthorityPort for DeterministicScheduler {
    fn claim(&self, request: SchedulerClaimRequest) -> BoxFuture<Result<Option<TaskClaim>>> {
        let scheduler = self.clone();
        Box::pin(async move {
            scheduler.claim_inner(
                request.worker_id,
                request.task_id,
                request.lifecycle_open
                    && request.readiness
                    && request.revision_aligned
                    && request.capability_aligned
                    && request.gates_satisfied
                    && request.budget_available
                    && !request.active_attempt,
            )
        })
    }

    fn complete(&self, claim: TaskClaim, proof: CompletionProof) -> BoxFuture<Result<()>> {
        let scheduler = self.clone();
        Box::pin(async move { scheduler.complete(&claim, proof) })
    }

    fn cancel(&self, claim: TaskClaim, cancellation: CancellationToken) -> BoxFuture<Result<()>> {
        let scheduler = self.clone();
        Box::pin(async move {
            cancellation.check()?;
            scheduler.cancel(claim.task_id)
        })
    }
}

impl Default for DeterministicScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl DeterministicScheduler {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(SchedulerState::default())),
            limits: SchedulerLimits {
                max_tasks: 10_000,
                max_claims_per_worker: 16,
            },
        }
    }

    pub fn with_worker_concurrency(mut self, limit: u32) -> Self {
        self.limits.max_claims_per_worker = limit.clamp(1, 1_000_000);
        self
    }

    pub fn with_limits(mut self, limits: SchedulerLimits) -> Result<Self> {
        if limits.max_tasks == 0
            || limits.max_claims_per_worker == 0
            || limits.max_tasks == usize::MAX
            || limits.max_claims_per_worker == u32::MAX
        {
            return Err(AgentError::InvalidInput(
                "scheduler limits must be positive".to_owned(),
            ));
        }
        self.limits = limits;
        Ok(self)
    }

    pub fn from_task_graph(graph: &TaskGraph) -> Result<Self> {
        let scheduler = Self::new();
        for task in graph.tasks() {
            let mut item = SchedulerTask::new(task.id());
            item.retry_limit = 3;
            if task.task().lifecycle == TaskLifecycle::Completed {
                scheduler.add_task(item.clone())?;
            } else {
                scheduler.add_task(item)?;
            }
        }
        for edge in graph
            .edges()
            .filter(|edge| edge.kind == TaskEdgeKind::Dependency)
        {
            scheduler.add_dependency(edge.from_task_id, edge.to_task_id)?;
        }
        for task in graph
            .tasks()
            .filter(|task| task.task().lifecycle == TaskLifecycle::Completed)
        {
            scheduler.complete_task(task.id())?;
        }
        Ok(scheduler)
    }

    pub fn add_task(&self, task: SchedulerTask) -> Result<()> {
        if task.id.is_nil() {
            return Err(AgentError::InvalidInput(
                "scheduled task id must not be nil".to_owned(),
            ));
        }
        if task.dependencies.len() > MAX_TASK_DEPENDENCIES {
            return Err(AgentError::BudgetExceeded(
                "task dependency limit exhausted".to_owned(),
            ));
        }
        let mut state = self.state.lock().expect("scheduler lock poisoned");
        if state.nodes.len() >= self.limits.max_tasks {
            return Err(AgentError::BudgetExceeded(
                "scheduler task limit exhausted".to_owned(),
            ));
        }
        if state.nodes.contains_key(&task.id) {
            return Err(AgentError::Conflict(format!(
                "task {} already scheduled",
                task.id
            )));
        }
        if task.dependencies.contains(&task.id) {
            return Err(AgentError::Conflict(
                "scheduler dependency cycle".to_owned(),
            ));
        }
        if task
            .dependencies
            .iter()
            .any(|id| !state.nodes.contains_key(id))
        {
            return Err(AgentError::NotFound(
                "scheduler dependency must be added first".to_owned(),
            ));
        }
        state.nodes.insert(
            task.id,
            NodeRecord {
                task,
                state: SchedulerNodeState::Pending,
                retries: 0,
            },
        );
        Ok(())
    }

    pub fn add_dependency(&self, task_id: TaskId, dependency: TaskId) -> Result<()> {
        let mut state = self.state.lock().expect("scheduler lock poisoned");
        if task_id == dependency {
            return Err(AgentError::Conflict(
                "scheduler dependency cycle".to_owned(),
            ));
        }
        if !state.nodes.contains_key(&task_id) || !state.nodes.contains_key(&dependency) {
            return Err(AgentError::NotFound("scheduler task not found".to_owned()));
        }
        let mut seen = BTreeSet::new();
        if reaches(&state.nodes, dependency, task_id, &mut seen) {
            return Err(AgentError::Conflict(
                "scheduler dependency cycle".to_owned(),
            ));
        }
        state
            .nodes
            .get_mut(&task_id)
            .expect("task was checked")
            .task
            .dependencies
            .insert(dependency);
        Ok(())
    }

    pub fn ready(&self) -> Vec<TaskId> {
        let state = self.state.lock().expect("scheduler lock poisoned");
        state
            .nodes
            .values()
            .filter(|record| {
                record.state == SchedulerNodeState::Pending
                    && record.task.lifecycle_open
                    && record.task.readiness
                    && record.task.revision_aligned
                    && record.task.capability_aligned
                    && record.task.gates_satisfied
                    && record.task.budget_available
                    && !record.task.active_attempt
                    && record.task.dependencies.iter().all(|dependency| {
                        state
                            .nodes
                            .get(dependency)
                            .is_some_and(|node| node.state == SchedulerNodeState::Completed)
                    })
            })
            .map(|record| record.task.id)
            .collect()
    }

    pub fn claim(&self, worker_id: OperatorId) -> Result<Option<TaskClaim>> {
        self.claim_inner(worker_id, None, true)
    }

    fn claim_inner(
        &self,
        worker_id: OperatorId,
        requested_task: Option<TaskId>,
        checks_passed: bool,
    ) -> Result<Option<TaskClaim>> {
        if worker_id.is_nil() {
            return Err(AgentError::InvalidInput(
                "worker id must not be nil".to_owned(),
            ));
        }
        let mut state = self.state.lock().expect("scheduler lock poisoned");
        let active = state
            .claims
            .values()
            .filter(|claim| claim.worker_id == worker_id)
            .count() as u32;
        if active >= self.limits.max_claims_per_worker {
            return Ok(None);
        }
        if !checks_passed {
            return Ok(None);
        }
        let task_id = state
            .nodes
            .values()
            .filter(|record| {
                record.state == SchedulerNodeState::Pending
                    && match requested_task {
                        Some(task_id) => record.task.id == task_id,
                        None => true,
                    }
                    && record.task.lifecycle_open
                    && record.task.readiness
                    && record.task.revision_aligned
                    && record.task.capability_aligned
                    && record.task.gates_satisfied
                    && record.task.budget_available
                    && !record.task.active_attempt
                    && record.task.dependencies.iter().all(|dependency| {
                        state
                            .nodes
                            .get(dependency)
                            .is_some_and(|node| node.state == SchedulerNodeState::Completed)
                    })
            })
            .map(|record| record.task.id)
            .next();
        let Some(task_id) = task_id else {
            return Ok(None);
        };
        state.next_fencing_token = state.next_fencing_token.saturating_add(1);
        let claim = TaskClaim {
            claim_id: Uuid::now_v7(),
            task_id,
            worker_id,
            fencing_token: state.next_fencing_token,
        };
        state
            .nodes
            .get_mut(&task_id)
            .expect("ready task was checked")
            .state = SchedulerNodeState::Claimed;
        state
            .nodes
            .get_mut(&task_id)
            .expect("ready task was checked")
            .task
            .active_attempt = true;
        state.claims.insert(claim.claim_id, claim.clone());
        Ok(Some(claim))
    }

    pub fn self_claim(&self, worker_id: OperatorId) -> Result<Option<TaskClaim>> {
        self.claim(worker_id)
    }

    pub fn complete(&self, claim: &TaskClaim, proof: CompletionProof) -> Result<()> {
        proof.validate()?;
        let mut state = self.state.lock().expect("scheduler lock poisoned");
        let stored = state
            .claims
            .get(&claim.claim_id)
            .cloned()
            .ok_or_else(|| AgentError::NotFound(format!("claim {}", claim.claim_id)))?;
        if stored != *claim {
            return Err(AgentError::Fenced);
        }
        let task_is_claimed = match state.nodes.get(&claim.task_id) {
            Some(node) => node.state == SchedulerNodeState::Claimed,
            None => false,
        };
        if !task_is_claimed {
            return Err(AgentError::Conflict("task is not claimed".to_owned()));
        }
        state.claims.remove(&claim.claim_id);
        let node = state
            .nodes
            .get_mut(&claim.task_id)
            .ok_or_else(|| AgentError::NotFound(format!("task {}", claim.task_id)))?;
        node.state = SchedulerNodeState::Completed;
        node.task.active_attempt = false;
        Ok(())
    }

    pub fn complete_without_proof_is_rejected(&self, claim: &TaskClaim) -> Result<()> {
        self.complete(
            claim,
            CompletionProof {
                evidence_id: Uuid::nil(),
                gate_passed: false,
                immutable: false,
            },
        )
    }

    pub fn fail(&self, claim: &TaskClaim) -> Result<bool> {
        let mut state = self.state.lock().expect("scheduler lock poisoned");
        let stored = state
            .claims
            .get(&claim.claim_id)
            .cloned()
            .ok_or_else(|| AgentError::NotFound(format!("claim {}", claim.claim_id)))?;
        if stored != *claim {
            return Err(AgentError::Fenced);
        }
        state.claims.remove(&claim.claim_id);
        let node = state
            .nodes
            .get_mut(&claim.task_id)
            .ok_or_else(|| AgentError::NotFound(format!("task {}", claim.task_id)))?;
        if node.retries < node.task.retry_limit {
            node.retries += 1;
            node.state = SchedulerNodeState::Pending;
            node.task.active_attempt = false;
            Ok(true)
        } else {
            node.state = SchedulerNodeState::Failed;
            node.task.active_attempt = false;
            Ok(false)
        }
    }

    pub fn cancel(&self, task_id: TaskId) -> Result<()> {
        let mut state = self.state.lock().expect("scheduler lock poisoned");
        let was_claimed = state
            .nodes
            .get(&task_id)
            .ok_or_else(|| AgentError::NotFound(format!("task {task_id}")))?
            .state
            == SchedulerNodeState::Claimed;
        if was_claimed {
            state.claims.retain(|_, claim| claim.task_id != task_id);
        }
        let node = state.nodes.get_mut(&task_id).expect("task was checked");
        node.state = SchedulerNodeState::Cancelled;
        node.task.active_attempt = false;
        Ok(())
    }

    pub fn complete_task(&self, task_id: TaskId) -> Result<()> {
        let mut state = self.state.lock().expect("scheduler lock poisoned");
        if !state.nodes.contains_key(&task_id) {
            return Err(AgentError::NotFound(format!("task {task_id}")));
        }
        state.claims.retain(|_, claim| claim.task_id != task_id);
        let node = state.nodes.get_mut(&task_id).expect("task was checked");
        node.state = SchedulerNodeState::Completed;
        node.task.active_attempt = false;
        Ok(())
    }

    pub fn state(&self, task_id: TaskId) -> Option<SchedulerNodeState> {
        self.state
            .lock()
            .expect("scheduler lock poisoned")
            .nodes
            .get(&task_id)
            .map(|node| node.state)
    }

    pub fn tasks(&self) -> Vec<SchedulerTask> {
        self.state
            .lock()
            .expect("scheduler lock poisoned")
            .nodes
            .values()
            .map(|node| node.task.clone())
            .collect()
    }
}

fn reaches(
    nodes: &BTreeMap<TaskId, NodeRecord>,
    start: TaskId,
    target: TaskId,
    seen: &mut BTreeSet<TaskId>,
) -> bool {
    if start == target {
        return true;
    }
    if !seen.insert(start) {
        return false;
    }
    nodes
        .get(&start)
        .map(|node| {
            node.task
                .dependencies
                .iter()
                .any(|dependency| reaches(nodes, *dependency, target, seen))
        })
        .unwrap_or(false)
}
