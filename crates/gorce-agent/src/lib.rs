#![forbid(unsafe_code)]

#[cfg(test)]
mod agent;
#[cfg(test)]
mod capability;
mod error;
#[cfg(test)]
mod events;
#[cfg(test)]
mod lease;
#[cfg(test)]
mod lifecycle;
#[cfg(test)]
mod permission;
#[cfg(test)]
mod persistence;
#[cfg(test)]
mod quality;
#[cfg(test)]
mod scheduler;
#[cfg(test)]
mod skill;
#[cfg(test)]
mod workflow;

pub use error::{AgentError, Result};

pub const AGENT_VERSION: &str = "0.1";

pub fn agent_version() -> &'static str {
    let _ = gorce_core::core_version();
    let _ = gorce_protocol::protocol_version();
    AGENT_VERSION
}

#[cfg(test)]
#[doc(hidden)]
pub mod test_support {
    pub use crate::agent::{
        AgentEvent, AgentExecution, AgentInstance, AgentLimits, AgentRuntime, AgentSession,
        BackgroundHandle, BackgroundSubagent, BoxFuture, CompletionRecord, ModelExecutorPort,
        ModelRequest, ModelResponse, RunExecutor, RuntimeDependencies, RuntimeDurabilityPort,
        RuntimeLimits, ToolBroker, ToolCall, ToolExecutorPort, ToolRequest, ToolResponse,
        ToolResultStatus,
    };
    pub use crate::capability::{
        AdmissionRequest, Budget, CapabilityCeiling, CapabilityGrant, CapabilitySet, HostAuthority,
        OperatorProfile, OperatorProfileResolver, OperatorProfileSpec, ProfileId, ProfileResolver,
        ResolvedOperatorProfile, ResolvedProfile, ResourceScope,
    };
    pub use crate::events::{
        CancellationToken, DurableMailboxPort, EventBus, EventCursor, EventEnvelope, EventLimits,
        EventSubscription, Mailbox, MailboxAuthorization, MailboxBroker, MailboxEnvelope,
        MailboxReceiver, MailboxSender, TypedMailbox,
    };
    pub use crate::lease::{
        AttemptLeaseManager, AttemptSpec, DaemonClock, LeaseAuthorityPort, LeaseFence,
        LeaseHeartbeat, Reconciliation, TaskAttemptRecord,
    };
    pub use crate::lifecycle::{
        Attempt, AttemptStatus, CircuitBreaker, CircuitState, RetryDecision, RetryPolicy, Run,
        RunStatus,
    };
    pub use crate::permission::{
        ApprovalPort, PermissionBroker, PermissionCheck, PermissionDecision,
        PermissionDecisionPort, PermissionEngine, PermissionMode, PermissionOutcome,
        PermissionPolicy, PermissionRule, PermissionVerifier, PolicyEffect, RiskLevel,
        VerifierError, VerifierOutcome,
    };
    pub use crate::persistence::{
        AtomicEventBatch, AtomicStateEventPort, DomainEvent, DurableRetryStatePort, EventAppender,
        RetryState,
    };
    pub use crate::quality::{
        evidence_item, evidence_item_reference, immutable_producer, EvaluationPort,
        EvidenceContext, EvidencePort, GateEvaluationPort, IndependentReview,
        IndependentReviewPort, PersistedEvaluation, QualityEvaluation, QualityGate,
        QualityRequirement, ToolEvidence, ToolEvidenceStatus, ValidatedEvidenceBundle,
    };
    pub use crate::scheduler::{
        CompletionProof, DeterministicScheduler, SchedulerAuthorityPort, SchedulerClaim,
        SchedulerClaimRequest, SchedulerLimits, SchedulerNodeState, SchedulerTask, TaskClaim,
    };
    pub use crate::skill::{
        DisclosureLevel, ResolvedOperatorSpec, Skill, SkillAction, SkillDefinition,
        SkillManifestRef, SkillRegistry, SkillSpec, SkillView,
    };
    pub use crate::workflow::{
        DurableWorkflow, NodeStatus, WorkflowDefinition, WorkflowEvent, WorkflowEventEnvelope,
        WorkflowNode, WorkflowState, WorkflowStateStore, WorkflowStatus,
    };
}

#[cfg(test)]
mod tests {
    use crate::capability::{
        AdmissionRequest, Budget, CapabilityCeiling, CapabilityGrant, HostAuthority,
        OperatorProfile, ProfileResolver, ResourceScope,
    };
    use crate::events::{EventBus, Mailbox};
    use crate::lease::{AttemptLeaseManager, AttemptSpec};
    use crate::lifecycle::{CircuitBreaker, RetryDecision, RetryPolicy, Run};
    use crate::permission::{
        PermissionCheck, PermissionEngine, PermissionMode, PermissionOutcome, PermissionPolicy,
        RiskLevel,
    };
    use crate::quality::{evidence_item, QualityGate};
    use crate::scheduler::{CompletionProof, DeterministicScheduler, SchedulerTask};
    use crate::skill::{ResolvedOperatorSpec, SkillManifestRef};
    use crate::{agent_version, AgentError, AGENT_VERSION};
    use gorce_protocol::{EvidenceBundle, EvidenceKind, TaskAttemptStatus};
    use std::sync::Arc;
    use uuid::Uuid;

    fn id() -> Uuid {
        Uuid::now_v7()
    }

    #[test]
    fn exposes_the_agent_version_without_store_dependency() {
        assert_eq!(agent_version(), AGENT_VERSION);
    }

    #[test]
    fn production_limits_are_bounded() {
        let limits = crate::agent::RuntimeLimits::production();
        assert!(limits.max_tool_calls < u32::MAX);
        assert!(limits.max_event_bytes > 0);
    }

    #[test]
    fn default_public_surface_has_no_authority_or_runtime_exports() {
        let normalized_source = include_str!("lib.rs")
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        let source = normalized_source
            .split("#[cfg(test)]\n#[doc(hidden)]\npub mod test_support")
            .next()
            .expect("test-support module marker");
        for module in [
            "agent",
            "capability",
            "permission",
            "scheduler",
            "workflow",
            "skill",
        ] {
            let forbidden = format!("{}{}{}", "pub use ", module, "::");
            assert!(
                !source.contains(forbidden.as_str()),
                "forbidden public export: {forbidden}"
            );
            let test_only = format!("#[cfg(test)]\nmod {module};");
            assert!(
                source.contains(test_only.as_str()),
                "runtime module is not test-only: {module}"
            );
        }
    }

    #[test]
    fn host_admission_and_child_reservations_are_bounded_and_idempotent() {
        let grant = CapabilityGrant::with_limits(
            ["tool"],
            2,
            1,
            Budget {
                model_tokens: 100,
                tool_calls: 2,
                wall_time_ms: 1_000,
            },
        )
        .with_scopes([ResourceScope::new("tool", "repo/*").unwrap()])
        .unwrap();
        let mut profiles = ProfileResolver::default();
        profiles
            .insert(OperatorProfile::new("worker").with_grants(grant.clone()))
            .unwrap();
        let ceiling = CapabilityCeiling::actions(["tool"])
            .resource_scopes([ResourceScope::new("tool", "repo/*").unwrap()])
            .unwrap()
            .with_budget(grant.budget)
            .with_concurrency(1)
            .with_depth(2);
        let authority = HostAuthority::new(id(), ceiling, Arc::new(profiles)).unwrap();
        let root = authority
            .admit(AdmissionRequest::new(authority.project_id(), id(), id(), "worker").unwrap())
            .unwrap();
        let child = root
            .spawn_subagent(
                id(),
                CapabilityGrant::with_limits(
                    ["tool"],
                    1,
                    0,
                    Budget {
                        model_tokens: 1,
                        tool_calls: 1,
                        wall_time_ms: 1,
                    },
                )
                .with_scopes([ResourceScope::new("tool", "repo/*").unwrap()])
                .unwrap(),
            )
            .unwrap();
        assert_eq!(root.active_children(), 1);
        root.release_subagent(&child).unwrap();
        assert_eq!(root.active_children(), 0);
        assert!(root.release_subagent(&child).is_err());
    }

    #[tokio::test]
    async fn event_cursor_waits_and_mailbox_is_bounded() {
        let bus = EventBus::new(2).unwrap();
        let mut subscription = bus.subscribe();
        bus.publish("event");
        assert_eq!(subscription.next().await.unwrap().unwrap().event, "event");
        let mailbox = Mailbox::new(1).unwrap();
        mailbox.send(1_u32).unwrap();
        assert_eq!(mailbox.send(2).unwrap_err(), AgentError::MailboxFull);
    }

    #[test]
    fn lease_reconciliation_blocks_reclaim_and_scheduler_requires_proof() {
        let manager = AttemptLeaseManager::new(id()).unwrap();
        let record = manager
            .create_attempt(AttemptSpec::initial(id(), id(), id(), id(), "1"))
            .unwrap();
        let lease = manager
            .claim(record.attempt.id, record.attempt.operator_id, 10, 2)
            .unwrap();
        assert_eq!(manager.reconcile(12).len(), 1);
        assert!(manager.claim(record.attempt.id, id(), 13, 2).is_err());
        assert_eq!(
            manager.get(record.attempt.id).unwrap().attempt.status,
            TaskAttemptStatus::NeedsReconciliation
        );

        let scheduler = DeterministicScheduler::new();
        let task = id();
        scheduler.add_task(SchedulerTask::new(task)).unwrap();
        let claim = scheduler.claim(id()).unwrap().unwrap();
        assert!(scheduler
            .complete_without_proof_is_rejected(&claim)
            .is_err());
        scheduler
            .complete(
                &claim,
                CompletionProof {
                    evidence_id: lease.id,
                    gate_passed: true,
                    immutable: true,
                },
            )
            .unwrap();
    }

    #[test]
    fn summary_only_evidence_never_passes_a_gate() {
        let bundle = EvidenceBundle {
            id: id(),
            project_id: id(),
            task_id: id(),
            attempt_id: id(),
            items: vec![evidence_item(EvidenceKind::TestResult, "passed")],
            created_at: "1".to_owned(),
        };
        assert!(!QualityGate::default().evaluate(&bundle).passed);
    }

    #[test]
    fn permission_defaults_ask_and_bypass_is_run_scoped() {
        let request = PermissionCheck::new(id(), id(), "deploy", "production", "test").unwrap();
        let policy = PermissionEngine::new(PermissionMode::Policy, PermissionPolicy::default());
        assert_eq!(
            policy.evaluate_sync(&request).outcome,
            PermissionOutcome::RequiresApproval
        );
        let bypass = PermissionEngine::new(PermissionMode::Bypass, PermissionPolicy::default());
        assert_eq!(
            bypass.evaluate_sync(&request).outcome,
            PermissionOutcome::Denied
        );
        let high = request.clone().with_risk(RiskLevel::High);
        assert_eq!(
            bypass.evaluate_sync(&high).outcome,
            PermissionOutcome::RequiresApproval
        );
    }

    #[test]
    fn retries_create_linked_attempts_and_bound_backoff() {
        let mut run = Run::new(id(), id(), "0").unwrap();
        run.start("1").unwrap();
        let first = id();
        run.begin_attempt(first, "2").unwrap();
        let mut circuit = CircuitBreaker::default();
        let policy = RetryPolicy::default();
        assert!(matches!(
            run.fail_attempt(first, "transient", true, "3", &policy, &mut circuit)
                .unwrap(),
            RetryDecision::Retry { .. }
        ));
        let second = id();
        run.begin_attempt_linked(second, "4", Some(first)).unwrap();
        assert_eq!(run.attempts[1].retry_of, Some(first));
        assert!(policy.backoff_ms(100) <= policy.max_backoff_ms);
    }

    #[test]
    fn operator_spec_is_pinned_and_skills_are_exactly_versioned() {
        let hash = format!("sha256:{}", "a".repeat(64));
        assert!(ResolvedOperatorSpec::new(
            hash,
            "model@sha256:a",
            "tools@sha256:b",
            vec![SkillManifestRef::pinned("review", "1.0.0")],
        )
        .is_ok());
        assert!(ResolvedOperatorSpec::new(
            format!("sha256:{}", "a".repeat(64)),
            "model",
            "tools",
            vec![SkillManifestRef::pinned("review", "latest")],
        )
        .is_err());
    }
}
