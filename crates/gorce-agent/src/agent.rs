use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use gorce_protocol::{BlobRef, OperatorId, ProjectId};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::capability::{Budget, ResolvedOperatorProfile, SharedReservationState};
use crate::error::{AgentError, Result};
use crate::events::{CancellationToken, EventBus};
use crate::lease::{DaemonClock, LeaseAuthorityPort, LeaseFence};
use crate::lifecycle::{CircuitBreaker, RetryDecision, RetryPolicy, Run};
use crate::permission::{PermissionBroker, PermissionCheck, RiskLevel};
use crate::persistence::RetryState;
use crate::quality::{
    EvidenceContext, GateEvaluationPort, IndependentReviewPort, PersistedEvaluation,
    QualityEvaluation, QualityGate, ToolEvidence, ToolEvidenceStatus, ValidatedEvidenceBundle,
};
use crate::skill::ResolvedOperatorSpec;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentLimits {
    pub max_depth: u32,
    pub max_concurrency: u32,
    pub budget: Budget,
}

impl AgentLimits {
    pub fn from_capabilities(capabilities: &crate::capability::CapabilityGrant) -> Self {
        Self {
            max_depth: capabilities.max_depth,
            max_concurrency: capabilities.max_concurrency,
            budget: capabilities.budget,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentInstance {
    id: OperatorId,
    parent_id: Option<OperatorId>,
    depth: u32,
    project_id: ProjectId,
    run_id: Uuid,
    pub(crate) capabilities: crate::capability::CapabilityGrant,
    pub(crate) limits: AgentLimits,
    runtime: SharedReservationState,
    reservation: Option<Arc<ChildReservation>>,
    pub(crate) profile: ResolvedOperatorProfile,
}

#[derive(Debug)]
struct ChildReservation {
    parent_id: OperatorId,
    child_id: OperatorId,
    runtime: SharedReservationState,
    released: std::sync::atomic::AtomicBool,
}

impl ChildReservation {
    fn release(&self) {
        if self
            .released
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }
        let mut state = self.runtime.lock().expect("agent runtime lock poisoned");
        let remove_parent = if let Some(children) = state.active_children.get_mut(&self.parent_id) {
            children.remove(&self.child_id);
            children.is_empty()
        } else {
            false
        };
        if remove_parent {
            state.active_children.remove(&self.parent_id);
        }
        clear_reservations(&mut state, self.child_id);
    }
}

fn clear_reservations(state: &mut crate::capability::ReservationState, id: OperatorId) {
    if let Some(children) = state.active_children.remove(&id) {
        for child_id in children.keys().copied().collect::<Vec<_>>() {
            clear_reservations(state, child_id);
        }
    }
    state.consumed.remove(&id);
}

impl Drop for ChildReservation {
    fn drop(&mut self) {
        self.release();
    }
}

impl AgentInstance {
    pub(crate) fn admitted(
        project_id: ProjectId,
        run_id: Uuid,
        id: OperatorId,
        profile: ResolvedOperatorProfile,
        capabilities: crate::capability::CapabilityGrant,
    ) -> Result<Self> {
        if project_id.is_nil() || run_id.is_nil() || id.is_nil() {
            return Err(AgentError::InvalidInput(
                "admitted agent identity must not be nil".to_owned(),
            ));
        }
        Ok(Self {
            id,
            parent_id: None,
            depth: 0,
            project_id,
            run_id,
            limits: AgentLimits::from_capabilities(&capabilities),
            capabilities,
            runtime: Arc::new(Mutex::new(Default::default())),
            reservation: None,
            profile,
        })
    }

    pub fn id(&self) -> OperatorId {
        self.id
    }

    pub fn project_id(&self) -> ProjectId {
        self.project_id
    }

    pub fn run_id(&self) -> Uuid {
        self.run_id
    }

    pub fn depth(&self) -> u32 {
        self.depth
    }

    pub fn capabilities(&self) -> &crate::capability::CapabilityGrant {
        &self.capabilities
    }

    pub fn permits(&self, action: &str) -> bool {
        self.capabilities.permits(action)
    }

    pub fn spawn_subagent(
        &self,
        id: OperatorId,
        requested: crate::capability::CapabilityGrant,
    ) -> Result<Self> {
        if id.is_nil() {
            return Err(AgentError::InvalidInput(
                "agent id must not be nil".to_owned(),
            ));
        }
        if !requested.is_subset_of(&self.capabilities) {
            return Err(AgentError::CapabilityDenied(
                "subagent grants must be a strict subset of the parent grant".to_owned(),
            ));
        }
        if self.depth >= self.limits.max_depth {
            return Err(AgentError::DepthExceeded);
        }
        let mut state = self.runtime.lock().expect("agent runtime lock poisoned");
        let active = match state.active_children.get(&self.id) {
            Some(children) => children.len(),
            None => 0,
        };
        if active as u32 >= self.limits.max_concurrency {
            return Err(AgentError::ConcurrencyExceeded);
        }
        if state
            .active_children
            .get(&self.id)
            .is_some_and(|children| children.contains_key(&id))
        {
            return Err(AgentError::Conflict(
                "child id already has a reservation".to_owned(),
            ));
        }
        let allocated = state
            .active_children
            .get(&self.id)
            .map(|children| {
                children
                    .values()
                    .copied()
                    .fold(Budget::ZERO, Budget::saturating_add)
            })
            .unwrap_or(Budget::ZERO);
        let consumed = state
            .consumed
            .get(&self.id)
            .copied()
            .unwrap_or(Budget::ZERO);
        if !consumed
            .saturating_add(allocated)
            .saturating_add(requested.budget)
            .is_subset_of(self.limits.budget)
        {
            return Err(AgentError::BudgetExceeded(
                "combined own consumption and child reservations exceed the parent budget"
                    .to_owned(),
            ));
        }
        state
            .active_children
            .entry(self.id)
            .or_default()
            .insert(id, requested.budget);
        drop(state);
        let reservation = Arc::new(ChildReservation {
            parent_id: self.id,
            child_id: id,
            runtime: self.runtime.clone(),
            released: std::sync::atomic::AtomicBool::new(false),
        });
        let mut profile = self.profile.clone();
        profile.capabilities = requested.clone();
        Ok(Self {
            id,
            parent_id: Some(self.id),
            depth: self.depth.saturating_add(1),
            project_id: self.project_id,
            run_id: self.run_id,
            limits: AgentLimits::from_capabilities(&requested),
            capabilities: requested,
            runtime: self.runtime.clone(),
            reservation: Some(reservation),
            profile,
        })
    }

    pub fn release_subagent(&self, child: &AgentInstance) -> Result<()> {
        if child.parent_id != Some(self.id) {
            return Err(AgentError::InvalidInput(
                "agent is not a child of this instance".to_owned(),
            ));
        }
        if !Arc::ptr_eq(&self.runtime, &child.runtime) {
            return Err(AgentError::Unauthorized);
        }
        let reservation = child
            .reservation
            .as_ref()
            .ok_or_else(|| AgentError::Conflict("child has no reservation".to_owned()))?;
        if reservation
            .released
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(AgentError::Conflict(
                "child reservation already released".to_owned(),
            ));
        }
        reservation.release();
        Ok(())
    }

    pub fn active_children(&self) -> u32 {
        match self
            .runtime
            .lock()
            .expect("agent runtime lock poisoned")
            .active_children
            .get(&self.id)
        {
            Some(children) => children.len() as u32,
            None => 0,
        }
    }

    pub fn reserve_budget(&self, budget: Budget) -> Result<()> {
        if self.reservation.as_ref().is_some_and(|reservation| {
            reservation
                .released
                .load(std::sync::atomic::Ordering::Acquire)
        }) {
            return Err(AgentError::Conflict(
                "agent reservation has been released".to_owned(),
            ));
        }
        let mut state = self.runtime.lock().expect("agent runtime lock poisoned");
        let consumed = state
            .consumed
            .get(&self.id)
            .copied()
            .unwrap_or(Budget::ZERO);
        let allocated = state
            .active_children
            .get(&self.id)
            .map(|children| {
                children
                    .values()
                    .copied()
                    .fold(Budget::ZERO, Budget::saturating_add)
            })
            .unwrap_or(Budget::ZERO);
        let next = consumed.saturating_add(budget);
        if !next
            .saturating_add(allocated)
            .is_subset_of(self.limits.budget)
        {
            return Err(AgentError::BudgetExceeded(
                "agent budget exhausted".to_owned(),
            ));
        }
        state.consumed.insert(self.id, next);
        Ok(())
    }

    pub fn consumed_budget(&self) -> Budget {
        self.runtime
            .lock()
            .expect("agent runtime lock poisoned")
            .consumed
            .get(&self.id)
            .copied()
            .unwrap_or(Budget::ZERO)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
    pub risk: RiskLevel,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelRequest {
    pub project_id: ProjectId,
    pub operator_id: OperatorId,
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub prompt: String,
    pub operator_spec: ResolvedOperatorSpec,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelResponse {
    pub text: String,
    pub tool_calls: Vec<ToolCall>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolRequest {
    pub project_id: ProjectId,
    pub operator_id: OperatorId,
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub action: String,
    pub resource: String,
    pub risk: RiskLevel,
    pub call: ToolCall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolResultStatus {
    Succeeded,
    Failed,
    UnknownSideEffect,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolResponse {
    pub output: Value,
    pub status: ToolResultStatus,
    pub side_effect: bool,
    pub result_hash: String,
    pub blob: Option<BlobRef>,
}

pub trait ModelExecutorPort: Send + Sync {
    fn complete(
        &self,
        request: ModelRequest,
        cancellation: CancellationToken,
    ) -> BoxFuture<Result<ModelResponse>>;
}

pub trait ToolExecutorPort: Send + Sync {
    fn execute(
        &self,
        request: ToolRequest,
        cancellation: CancellationToken,
    ) -> BoxFuture<Result<ToolResponse>>;
}

pub trait RuntimeDurabilityPort: Send + Sync {
    fn persist_run(&self, run: Run, expected_revision: u64) -> BoxFuture<Result<()>>;
    fn record_event(&self, event: AgentEvent) -> BoxFuture<Result<()>>;
    fn build_evidence(
        &self,
        run_id: Uuid,
        attempt_id: Uuid,
        tool_results: Vec<ToolEvidence>,
        output: String,
    ) -> BoxFuture<Result<ValidatedEvidenceBundle>>;
    fn persist_evidence(&self, evidence: ValidatedEvidenceBundle) -> BoxFuture<Result<()>>;
    fn persist_evaluation(&self, evaluation: PersistedEvaluation) -> BoxFuture<Result<()>>;
    fn complete(&self, completion: CompletionRecord) -> BoxFuture<Result<()>>;
    fn persist_retry_state(&self, run_id: Uuid, state: RetryState) -> BoxFuture<Result<()>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionRecord {
    pub project_id: ProjectId,
    pub task_id: gorce_protocol::TaskId,
    pub task_revision_id: gorce_protocol::TaskRevisionId,
    pub revision: u64,
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub evidence_id: Uuid,
    pub gate_score: u8,
    pub review_score: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeLimits {
    pub max_prompt_bytes: usize,
    pub max_model_output_bytes: usize,
    pub max_tool_output_bytes: usize,
    pub max_tool_calls: u32,
    pub max_evidence_items: usize,
    pub max_event_bytes: usize,
}

impl RuntimeLimits {
    pub fn production() -> Self {
        Self {
            max_prompt_bytes: 1_048_576,
            max_model_output_bytes: 4_194_304,
            max_tool_output_bytes: 4_194_304,
            max_tool_calls: 64,
            max_evidence_items: 256,
            max_event_bytes: 1_048_576,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.max_prompt_bytes == 0
            || self.max_model_output_bytes == 0
            || self.max_tool_output_bytes == 0
            || self.max_tool_calls == 0
            || self.max_tool_calls == u32::MAX
            || self.max_evidence_items == 0
            || self.max_event_bytes == 0
            || self.max_prompt_bytes == usize::MAX
            || self.max_model_output_bytes == usize::MAX
            || self.max_tool_output_bytes == usize::MAX
            || self.max_evidence_items == usize::MAX
            || self.max_event_bytes == usize::MAX
        {
            return Err(AgentError::InvalidInput(
                "runtime limits must be positive".to_owned(),
            ));
        }
        Ok(())
    }
}

pub struct RuntimeDependencies {
    pub model: Arc<dyn ModelExecutorPort>,
    pub tool: Arc<dyn ToolExecutorPort>,
    pub permission: Arc<PermissionBroker>,
    pub lease: Arc<dyn LeaseAuthorityPort>,
    pub clock: Arc<dyn DaemonClock>,
    pub durability: Arc<dyn RuntimeDurabilityPort>,
    pub review: Arc<dyn IndependentReviewPort>,
    pub gate: Arc<dyn GateEvaluationPort>,
    pub event_bus: EventBus<AgentEvent>,
    pub limits: RuntimeLimits,
    pub operator_spec: ResolvedOperatorSpec,
    pub gate_definition: QualityGate,
    pub task_id: gorce_protocol::TaskId,
    pub task_revision_id: gorce_protocol::TaskRevisionId,
    pub task_revision: u64,
    pub evidence_created_at: String,
    pub evidence_created_at_ms: u64,
    pub max_evidence_age_ms: Option<u64>,
}

pub struct AgentRuntime {
    instance: AgentInstance,
    dependencies: Arc<RuntimeDependencies>,
}

impl AgentRuntime {
    pub fn new(instance: AgentInstance, dependencies: RuntimeDependencies) -> Result<Self> {
        dependencies.limits.validate()?;
        dependencies.operator_spec.validate()?;
        if dependencies.task_id.is_nil()
            || dependencies.task_revision_id.is_nil()
            || dependencies.evidence_created_at.trim().is_empty()
        {
            return Err(AgentError::InvalidInput(
                "runtime requires task identity, evidence time, and a hashed operator spec"
                    .to_owned(),
            ));
        }
        Ok(Self {
            instance,
            dependencies: Arc::new(dependencies),
        })
    }

    pub fn instance(&self) -> &AgentInstance {
        &self.instance
    }

    pub fn session(&self) -> AgentSession {
        AgentSession {
            runtime: Arc::new(self.clone_runtime()),
            cancellation: CancellationToken::new(),
        }
    }

    fn clone_runtime(&self) -> AgentRuntime {
        AgentRuntime {
            instance: self.instance.clone(),
            dependencies: self.dependencies.clone(),
        }
    }

    async fn emit(&self, event: AgentEvent) -> Result<()> {
        let bytes = match serde_json::to_vec(&format!("{event:?}")) {
            Ok(value) => value.len(),
            Err(_) => 1,
        };
        if bytes > self.dependencies.limits.max_event_bytes {
            return Err(AgentError::MessageTooLarge);
        }
        self.dependencies
            .durability
            .record_event(event.clone())
            .await?;
        self.dependencies.event_bus.try_publish(event, bytes)?;
        Ok(())
    }

    async fn check_fence(&self, fence: Option<LeaseFence>) -> Result<()> {
        if let Some(fence) = fence {
            self.dependencies
                .lease
                .verify_fence(fence, self.dependencies.clock.now_ms())
                .await?;
        }
        Ok(())
    }

    async fn execute_inner(
        &self,
        run_id: Uuid,
        attempt_id: Uuid,
        prompt: String,
        cancellation: CancellationToken,
        fence: Option<LeaseFence>,
    ) -> Result<AgentExecution> {
        if run_id != self.instance.run_id || attempt_id.is_nil() {
            return Err(AgentError::Unauthorized);
        }
        let started_ms = self.dependencies.clock.now_ms();
        if prompt.len() > self.dependencies.limits.max_prompt_bytes {
            return Err(AgentError::MessageTooLarge);
        }
        cancellation.check()?;
        self.check_fence(fence).await?;
        self.emit(AgentEvent::Started { run_id, attempt_id })
            .await?;
        self.instance.reserve_budget(Budget {
            model_tokens: (self.dependencies.limits.max_model_output_bytes as u64).min(8_192),
            tool_calls: 0,
            wall_time_ms: 0,
        })?;
        let model_permission = PermissionCheck::new(
            self.instance.project_id,
            self.instance.id,
            "model",
            &self.dependencies.operator_spec.model_component,
            "agent model execution",
        )?
        .for_run(run_id)?;
        self.dependencies
            .permission
            .authorize(model_permission, &self.instance.capabilities, &cancellation)
            .await?;
        cancellation.check()?;
        self.check_fence(fence).await?;
        let response = self
            .dependencies
            .model
            .complete(
                ModelRequest {
                    project_id: self.instance.project_id,
                    operator_id: self.instance.id,
                    run_id,
                    attempt_id,
                    prompt,
                    operator_spec: self.dependencies.operator_spec.clone(),
                },
                cancellation.clone(),
            )
            .await?;
        cancellation.check()?;
        let output_bytes = response.text.len();
        if output_bytes > self.dependencies.limits.max_model_output_bytes
            || output_bytes > self.dependencies.limits.max_event_bytes
        {
            return Err(AgentError::MessageTooLarge);
        }
        let broker = ToolBroker {
            instance: self.instance.clone(),
            permission: self.dependencies.permission.clone(),
            executor: self.dependencies.tool.clone(),
            lease: self.dependencies.lease.clone(),
            clock: self.dependencies.clock.clone(),
            cancellation: cancellation.clone(),
            fence,
            max_output_bytes: self.dependencies.limits.max_tool_output_bytes,
            max_event_bytes: self.dependencies.limits.max_event_bytes,
        };
        let mut results = Vec::new();
        let mut evidence = Vec::new();
        let tool_call_count = response.tool_calls.len();
        if tool_call_count > self.dependencies.limits.max_tool_calls as usize {
            return Err(AgentError::BudgetExceeded(
                "tool call budget exhausted".to_owned(),
            ));
        }
        for call in response.tool_calls {
            let request = ToolRequest {
                project_id: self.instance.project_id,
                operator_id: self.instance.id,
                run_id,
                attempt_id,
                action: format!("tool:{}", call.name),
                resource: call.name.clone(),
                risk: call.risk,
                call: call.clone(),
            };
            self.emit(AgentEvent::ToolStarted {
                run_id,
                attempt_id,
                call_id: call.id.clone(),
                name: call.name.clone(),
            })
            .await?;
            let result = broker.call(request).await?;
            let event_output = if serde_json::to_vec(&result.output)
                .is_ok_and(|bytes| bytes.len() > self.dependencies.limits.max_event_bytes)
            {
                json!({ "blob_ref": result.blob.as_ref().map(|blob| blob.digest.clone()) })
            } else {
                result.output.clone()
            };
            self.emit(AgentEvent::ToolFinished {
                run_id,
                attempt_id,
                call_id: call.id.clone(),
                output: event_output,
            })
            .await?;
            evidence.push(ToolEvidence {
                call_id: call.id.clone(),
                status: match result.status {
                    ToolResultStatus::Succeeded => ToolEvidenceStatus::Succeeded,
                    ToolResultStatus::Failed => ToolEvidenceStatus::Failed,
                    ToolResultStatus::UnknownSideEffect => ToolEvidenceStatus::UnknownSideEffect,
                },
                result_hash: result.result_hash.clone(),
                blob: result.blob.clone(),
            });
            if result.status == ToolResultStatus::Failed {
                return Err(AgentError::Executor(format!(
                    "tool {} reported failure",
                    call.name
                )));
            }
            results.push(result);
        }
        cancellation.check()?;
        self.check_fence(fence).await?;
        let elapsed_ms = self.dependencies.clock.now_ms().saturating_sub(started_ms);
        if elapsed_ms > self.instance.limits.budget.wall_time_ms {
            return Err(if results.is_empty() {
                AgentError::BudgetExceeded("agent wall-time budget exhausted".to_owned())
            } else {
                AgentError::NeedsReconciliation(
                    "agent wall-time budget exhausted after tool side effects".to_owned(),
                )
            });
        }
        self.instance.reserve_budget(Budget {
            model_tokens: 0,
            tool_calls: 0,
            wall_time_ms: elapsed_ms,
        })?;
        let bundle = self
            .dependencies
            .durability
            .build_evidence(run_id, attempt_id, evidence, response.text.clone())
            .await?;
        if bundle.bundle.items.len() > self.dependencies.limits.max_evidence_items {
            return Err(AgentError::MessageTooLarge);
        }
        let expected = EvidenceContext {
            project_id: self.instance.project_id,
            task_id: self.dependencies.task_id,
            attempt_id,
            task_revision_id: self.dependencies.task_revision_id,
            revision: self.dependencies.task_revision,
            created_at: self.dependencies.evidence_created_at.clone(),
            created_at_ms: self.dependencies.evidence_created_at_ms,
            producer: self.instance.id,
            immutable: true,
        };
        bundle.validate(
            &expected,
            &self.dependencies.clock.now_ms().to_string(),
            self.dependencies.max_evidence_age_ms,
        )?;
        self.dependencies
            .durability
            .persist_evidence(bundle.clone())
            .await?;
        let gate = self
            .dependencies
            .gate
            .evaluate(self.dependencies.gate_definition.clone(), bundle.clone())
            .await?;
        let review = self.dependencies.review.review(bundle.clone()).await?;
        if review.evaluator.is_nil() {
            return Err(AgentError::Conflict(
                "independent review requires an evaluator identity".to_owned(),
            ));
        }
        if review.evaluator == self.instance.id {
            return Err(AgentError::Conflict(
                "completion review must be independent".to_owned(),
            ));
        }
        let evaluation_context =
            |evaluation: QualityEvaluation, producer: Uuid, independent: bool| {
                PersistedEvaluation {
                    id: Uuid::now_v7(),
                    project_id: self.instance.project_id,
                    task_id: self.dependencies.task_id,
                    attempt_id,
                    task_revision_id: self.dependencies.task_revision_id,
                    revision: self.dependencies.task_revision,
                    producer,
                    independent,
                    evaluation,
                }
            };
        self.dependencies
            .durability
            .persist_evaluation(evaluation_context(gate.clone(), self.instance.id, false))
            .await?;
        self.dependencies
            .durability
            .persist_evaluation(evaluation_context(
                review.evaluation.clone(),
                review.evaluator,
                true,
            ))
            .await?;
        if !gate.passed || !review.evaluation.passed {
            return Err(AgentError::Conflict(
                "quality gates did not pass".to_owned(),
            ));
        }
        cancellation.check()?;
        self.check_fence(fence).await?;
        self.dependencies
            .durability
            .complete(CompletionRecord {
                project_id: self.instance.project_id,
                task_id: self.dependencies.task_id,
                task_revision_id: self.dependencies.task_revision_id,
                revision: self.dependencies.task_revision,
                run_id,
                attempt_id,
                evidence_id: bundle.bundle.id,
                gate_score: gate.score,
                review_score: review.evaluation.score,
            })
            .await?;
        self.emit(AgentEvent::Completed {
            run_id,
            attempt_id,
            output: response.text.clone(),
        })
        .await?;
        Ok(AgentExecution {
            output: response.text,
            tool_results: results,
        })
    }

    pub async fn execute(
        &self,
        run_id: Uuid,
        attempt_id: Uuid,
        prompt: String,
        cancellation: CancellationToken,
        fence: Option<LeaseFence>,
    ) -> Result<AgentExecution> {
        let result = self
            .execute_inner(run_id, attempt_id, prompt, cancellation.clone(), fence)
            .await;
        if let Err(error) = &result {
            let _ = self
                .emit(match error {
                    AgentError::Cancelled => AgentEvent::Cancelled { run_id, attempt_id },
                    _ => AgentEvent::Failed {
                        run_id,
                        attempt_id,
                        error: error.to_string(),
                    },
                })
                .await;
        }
        result
    }
}

pub struct ToolBroker {
    instance: AgentInstance,
    permission: Arc<PermissionBroker>,
    executor: Arc<dyn ToolExecutorPort>,
    lease: Arc<dyn LeaseAuthorityPort>,
    clock: Arc<dyn DaemonClock>,
    cancellation: CancellationToken,
    fence: Option<LeaseFence>,
    max_output_bytes: usize,
    max_event_bytes: usize,
}

impl ToolBroker {
    pub async fn call(&self, request: ToolRequest) -> Result<ToolResponse> {
        self.cancellation.check()?;
        if request.project_id != self.instance.project_id || request.operator_id != self.instance.id
        {
            return Err(AgentError::Unauthorized);
        }
        if !self
            .instance
            .capabilities
            .permits_resource(&request.action, &request.resource)
        {
            return Err(AgentError::CapabilityDenied(request.resource));
        }
        self.instance.reserve_budget(Budget {
            model_tokens: 0,
            tool_calls: 1,
            wall_time_ms: 0,
        })?;
        let permission = PermissionCheck::new(
            request.project_id,
            request.operator_id,
            request.action.clone(),
            request.resource.clone(),
            "agent tool execution",
        )?
        .for_run(request.run_id)?
        .with_risk(request.risk);
        self.permission
            .authorize(permission, &self.instance.capabilities, &self.cancellation)
            .await?;
        self.cancellation.check()?;
        if let Some(fence) = self.fence {
            self.lease.verify_fence(fence, self.clock.now_ms()).await?;
        }
        let response = self
            .executor
            .execute(request, self.cancellation.clone())
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                return Err(AgentError::NeedsReconciliation(format!(
                    "tool executor failed without a durable side-effect classification: {error}"
                )))
            }
        };
        if self.cancellation.is_cancelled() || self.fence_is_stale().await? {
            return Err(AgentError::NeedsReconciliation(
                "cancellation or fencing occurred after a tool call".to_owned(),
            ));
        }
        let serialized = serde_json::to_vec(&response.output)
            .map_err(|error| AgentError::Executor(error.to_string()))?;
        if let Some(blob) = &response.blob {
            blob.validate()
                .map_err(|error| AgentError::InvalidInput(error.to_string()))?;
        }
        if serialized.len() > self.max_output_bytes {
            let Some(_) = &response.blob else {
                return Err(AgentError::MessageTooLarge);
            };
        }
        if serialized.len() > self.max_event_bytes && response.blob.is_none() {
            return Err(AgentError::NeedsReconciliation(
                "tool output exceeds the inline event bound without a BlobRef".to_owned(),
            ));
        }
        if response.status == ToolResultStatus::UnknownSideEffect {
            return Err(AgentError::NeedsReconciliation(
                "tool reported unknown side effects".to_owned(),
            ));
        }
        if response.status == ToolResultStatus::Failed && response.side_effect {
            return Err(AgentError::NeedsReconciliation(
                "failed tool reported a side effect".to_owned(),
            ));
        }
        let hash = response
            .blob
            .as_ref()
            .filter(|_| serialized.len() > self.max_output_bytes)
            .map(|blob| blob.digest.clone())
            .unwrap_or_else(|| sha256(&serialized));
        if response
            .blob
            .as_ref()
            .is_some_and(|blob| blob.digest.as_str() != hash.as_str())
        {
            return Err(AgentError::Conflict(
                "tool blob hash does not match the result".to_owned(),
            ));
        }
        if response.result_hash != hash {
            return Err(AgentError::Conflict(
                "tool result hash does not match the result".to_owned(),
            ));
        }
        Ok(response)
    }

    async fn fence_is_stale(&self) -> Result<bool> {
        let Some(fence) = self.fence else {
            return Ok(false);
        };
        match self.lease.verify_fence(fence, self.clock.now_ms()).await {
            Ok(()) => Ok(false),
            Err(AgentError::LeaseExpired | AgentError::Fenced | AgentError::NotFound(_)) => {
                Ok(true)
            }
            Err(error) => Err(error),
        }
    }

    pub fn clock_now_ms(&self) -> u64 {
        self.clock.now_ms()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentEvent {
    Started {
        run_id: Uuid,
        attempt_id: Uuid,
    },
    Progress {
        run_id: Uuid,
        attempt_id: Uuid,
        stage: String,
    },
    ToolStarted {
        run_id: Uuid,
        attempt_id: Uuid,
        call_id: String,
        name: String,
    },
    ToolFinished {
        run_id: Uuid,
        attempt_id: Uuid,
        call_id: String,
        output: Value,
    },
    Completed {
        run_id: Uuid,
        attempt_id: Uuid,
        output: String,
    },
    Failed {
        run_id: Uuid,
        attempt_id: Uuid,
        error: String,
    },
    Cancelled {
        run_id: Uuid,
        attempt_id: Uuid,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentExecution {
    pub output: String,
    pub tool_results: Vec<ToolResponse>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RunExecutor {
    pub retry_policy: RetryPolicy,
}

impl RunExecutor {
    pub async fn execute(
        &self,
        run: Arc<tokio::sync::Mutex<Run>>,
        session: AgentSession,
        prompt: String,
        fence: Option<LeaseFence>,
    ) -> Result<AgentExecution> {
        {
            let mut state = run.lock().await;
            if state.status == crate::lifecycle::RunStatus::Created {
                let expected = state.revision;
                state.start("run.started")?;
                let snapshot = state.clone();
                drop(state);
                session
                    .runtime
                    .dependencies
                    .durability
                    .persist_run(snapshot, expected)
                    .await?;
            }
        }
        let mut circuit = CircuitBreaker::default();
        let mut retry_of = None;
        loop {
            let attempt_id = Uuid::now_v7();
            let run_id = {
                let mut state = run.lock().await;
                let expected = state.revision;
                state.begin_attempt_linked(attempt_id, "attempt.started", retry_of)?;
                let run_id = state.id;
                let snapshot = state.clone();
                drop(state);
                session
                    .runtime
                    .dependencies
                    .durability
                    .persist_run(snapshot, expected)
                    .await?;
                run_id
            };
            let result = session
                .runtime
                .execute(
                    run_id,
                    attempt_id,
                    prompt.clone(),
                    session.cancellation.clone(),
                    fence,
                )
                .await;
            match result {
                Ok(execution) => {
                    let (snapshot, expected) = {
                        let mut state = run.lock().await;
                        let expected = state.revision;
                        state.complete_attempt(attempt_id, "attempt.completed")?;
                        (state.clone(), expected)
                    };
                    session
                        .runtime
                        .dependencies
                        .durability
                        .persist_run(snapshot, expected)
                        .await?;
                    circuit.record_success();
                    return Ok(execution);
                }
                Err(AgentError::Cancelled) => {
                    let (snapshot, expected) = {
                        let mut state = run.lock().await;
                        let expected = state.revision;
                        state.mark_cancelled_attempt(attempt_id, "attempt.cancelled")?;
                        state.cancel("cancelled", "run.cancelled")?;
                        (state.clone(), expected)
                    };
                    session
                        .runtime
                        .dependencies
                        .durability
                        .persist_run(snapshot, expected)
                        .await?;
                    return Err(AgentError::Cancelled);
                }
                Err(AgentError::NeedsReconciliation(message)) => {
                    let (snapshot, expected) = {
                        let mut state = run.lock().await;
                        let expected = state.revision;
                        state.mark_needs_reconciliation(
                            attempt_id,
                            message.clone(),
                            "attempt.reconcile",
                        )?;
                        (state.clone(), expected)
                    };
                    session
                        .runtime
                        .dependencies
                        .durability
                        .persist_run(snapshot, expected)
                        .await?;
                    return Err(AgentError::NeedsReconciliation(message));
                }
                Err(error) => {
                    let retryable = is_safe_transient(&error);
                    let (decision, snapshot, expected) = {
                        let mut state = run.lock().await;
                        let expected = state.revision;
                        let decision = state.fail_attempt(
                            attempt_id,
                            error.to_string(),
                            retryable,
                            "attempt.failed",
                            &self.retry_policy,
                            &mut circuit,
                        )?;
                        (decision, state.clone(), expected)
                    };
                    session
                        .runtime
                        .dependencies
                        .durability
                        .persist_run(snapshot, expected)
                        .await?;
                    session
                        .runtime
                        .dependencies
                        .durability
                        .persist_retry_state(
                            run_id,
                            RetryState {
                                attempt_number: decision.next_attempt().unwrap_or(0),
                                failures: circuit.consecutive_failures,
                                next_retry_at_ms: session
                                    .runtime
                                    .dependencies
                                    .clock
                                    .now_ms()
                                    .saturating_add(
                                        self.retry_policy
                                            .backoff_ms(decision.next_attempt().unwrap_or(1)),
                                    ),
                                circuit_open: circuit.is_open(),
                            },
                        )
                        .await?;
                    if matches!(decision, RetryDecision::Retry { .. }) {
                        retry_of = Some(attempt_id);
                        tokio::select! {
                            _ = tokio::time::sleep(std::time::Duration::from_millis(
                                self.retry_policy.backoff_ms(decision.next_attempt().unwrap_or(1)),
                            )) => {}
                            _ = session.cancellation.cancelled() => {
                                let (snapshot, expected) = {
                                    let mut state = run.lock().await;
                                    let expected = state.revision;
                                    state.cancel("cancelled during retry backoff", "run.cancelled")?;
                                    (state.clone(), expected)
                                };
                                session.runtime.dependencies.durability.persist_run(snapshot, expected).await?;
                                return Err(AgentError::Cancelled);
                            }
                        }
                        continue;
                    }
                    return Err(error);
                }
            }
        }
    }
}

impl RetryDecision {
    fn next_attempt(self) -> Option<u32> {
        match self {
            Self::Retry { next_attempt } => Some(next_attempt),
            Self::Exhausted | Self::CircuitOpen => None,
        }
    }
}

fn is_safe_transient(error: &AgentError) -> bool {
    matches!(error, AgentError::Executor(_))
}

#[derive(Clone)]
pub struct AgentSession {
    runtime: Arc<AgentRuntime>,
    pub cancellation: CancellationToken,
}

impl AgentSession {
    pub fn from_runtime(runtime: AgentRuntime) -> Self {
        Self {
            runtime: Arc::new(runtime),
            cancellation: CancellationToken::new(),
        }
    }

    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
        self
    }

    pub async fn execute(
        &self,
        run_id: Uuid,
        attempt_id: Uuid,
        prompt: String,
        fence: Option<LeaseFence>,
    ) -> Result<AgentExecution> {
        self.runtime
            .execute(run_id, attempt_id, prompt, self.cancellation.clone(), fence)
            .await
    }
}

#[derive(Debug)]
pub struct BackgroundHandle {
    cancellation: CancellationToken,
    join: Option<JoinHandle<Result<AgentExecution>>>,
}

impl BackgroundHandle {
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub async fn join(mut self) -> Result<AgentExecution> {
        let join = self
            .join
            .take()
            .ok_or_else(|| AgentError::Conflict("background handle already joined".to_owned()))?;
        join.await
            .map_err(|error| AgentError::Executor(error.to_string()))?
    }
}

impl Drop for BackgroundHandle {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

pub struct BackgroundSubagent;

impl BackgroundSubagent {
    pub fn start(
        session: AgentSession,
        run_id: Uuid,
        attempt_id: Uuid,
        prompt: String,
        fence: Option<LeaseFence>,
    ) -> Result<BackgroundHandle> {
        let cancellation = session.cancellation.clone();
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|error| AgentError::Executor(format!("Tokio runtime is required: {error}")))?;
        let join =
            runtime.spawn(async move { session.execute(run_id, attempt_id, prompt, fence).await });
        Ok(BackgroundHandle {
            cancellation,
            join: Some(join),
        })
    }
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}
