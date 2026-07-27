use std::sync::Arc;

use gorce_protocol::{OperatorId, ProjectId};
use uuid::Uuid;

use crate::agent::BoxFuture;
use crate::capability::CapabilityGrant;
use crate::error::{AgentError, Result};
use crate::events::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionMode {
    Supervised,
    Policy,
    AiVerifier,
    Bypass,
}

impl PermissionMode {
    pub fn persisted(self) -> Option<Self> {
        (self != Self::Bypass).then_some(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionRule {
    pub action: String,
    pub resource: String,
    pub effect: PolicyEffect,
}

impl PermissionRule {
    pub fn allow(action: impl Into<String>, resource: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            resource: resource.into(),
            effect: PolicyEffect::Allow,
        }
    }

    pub fn deny(action: impl Into<String>, resource: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            resource: resource.into(),
            effect: PolicyEffect::Deny,
        }
    }

    fn matches(&self, request: &PermissionCheck) -> bool {
        matches_pattern(&self.action, &request.action)
            && matches_pattern(&self.resource, &request.resource)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PermissionPolicy {
    rules: Vec<PermissionRule>,
}

impl PermissionPolicy {
    pub fn new(rules: Vec<PermissionRule>) -> Self {
        Self { rules }
    }

    pub fn add(&mut self, rule: PermissionRule) {
        self.rules.push(rule);
    }

    pub fn rules(&self) -> &[PermissionRule] {
        &self.rules
    }

    fn deterministic_deny(&self, request: &PermissionCheck) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.effect == PolicyEffect::Deny && rule.matches(request))
    }

    fn allows(&self, request: &PermissionCheck) -> bool {
        if self.deterministic_deny(request) {
            return false;
        }
        self.rules
            .iter()
            .rev()
            .find(|rule| rule.matches(request))
            .is_some_and(|rule| rule.effect == PolicyEffect::Allow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionCheck {
    pub request_id: Uuid,
    pub project_id: ProjectId,
    pub operator_id: OperatorId,
    pub run_id: Option<Uuid>,
    pub action: String,
    pub resource: String,
    pub reason: String,
    pub risk: RiskLevel,
    pub core_or_os: bool,
}

impl PermissionCheck {
    pub fn new(
        project_id: ProjectId,
        operator_id: OperatorId,
        action: impl Into<String>,
        resource: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<Self> {
        let request = Self {
            request_id: Uuid::now_v7(),
            project_id,
            operator_id,
            run_id: None,
            action: action.into(),
            resource: resource.into(),
            reason: reason.into(),
            risk: RiskLevel::Low,
            core_or_os: false,
        };
        request.validate()
    }

    pub fn for_run(mut self, run_id: Uuid) -> Result<Self> {
        if run_id.is_nil() {
            return Err(AgentError::InvalidInput(
                "run id must not be nil".to_owned(),
            ));
        }
        self.run_id = Some(run_id);
        Ok(self)
    }

    pub fn with_risk(mut self, risk: RiskLevel) -> Self {
        self.risk = risk;
        self
    }

    pub fn core_or_os(mut self, value: bool) -> Self {
        self.core_or_os = value;
        self
    }

    fn validate(self) -> Result<Self> {
        if self.request_id.is_nil()
            || self.project_id.is_nil()
            || self.operator_id.is_nil()
            || self.action.trim().is_empty()
            || self.resource.trim().is_empty()
        {
            return Err(AgentError::InvalidInput(
                "permission checks require project, operator, action, and resource".to_owned(),
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionOutcome {
    Allowed,
    Denied,
    RequiresApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierOutcome {
    AllowOnce,
    Deny,
    AskUser,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDecision {
    pub outcome: PermissionOutcome,
    pub verifier: Option<VerifierOutcome>,
    pub reason: String,
    pub mode: PermissionMode,
    pub persisted: bool,
    pub audit_id: Uuid,
}

impl PermissionDecision {
    fn denied(mode: PermissionMode, reason: impl Into<String>) -> Self {
        Self {
            outcome: PermissionOutcome::Denied,
            verifier: None,
            reason: reason.into(),
            mode,
            persisted: mode.persisted().is_some(),
            audit_id: Uuid::now_v7(),
        }
    }

    fn ask(mode: PermissionMode, reason: impl Into<String>) -> Self {
        Self {
            outcome: PermissionOutcome::RequiresApproval,
            verifier: None,
            reason: reason.into(),
            mode,
            persisted: mode.persisted().is_some(),
            audit_id: Uuid::now_v7(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifierError {
    Unavailable(String),
    InvalidResponse(String),
}

pub trait PermissionVerifier: Send + Sync {
    fn verify(
        &self,
        request: PermissionCheck,
    ) -> BoxFuture<std::result::Result<VerifierOutcome, VerifierError>>;
}

pub trait PermissionDecisionPort: Send + Sync {
    fn record(
        &self,
        request: PermissionCheck,
        decision: PermissionDecision,
    ) -> BoxFuture<Result<()>>;
}

pub trait ApprovalPort: Send + Sync {
    fn await_approval(
        &self,
        request: PermissionCheck,
        decision: PermissionDecision,
        cancellation: CancellationToken,
    ) -> BoxFuture<Result<PermissionOutcome>>;
}

#[derive(Clone)]
pub struct PermissionEngine {
    mode: PermissionMode,
    policy: PermissionPolicy,
    verifier: Option<Arc<dyn PermissionVerifier>>,
}

impl PermissionEngine {
    pub fn new(mode: PermissionMode, policy: PermissionPolicy) -> Self {
        Self {
            mode,
            policy,
            verifier: None,
        }
    }

    pub fn with_verifier(mut self, verifier: Arc<dyn PermissionVerifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    pub fn mode(&self) -> PermissionMode {
        self.mode
    }

    pub fn policy(&self) -> &PermissionPolicy {
        &self.policy
    }

    pub fn persisted_mode(&self) -> Option<PermissionMode> {
        self.mode.persisted()
    }

    pub fn evaluate_sync(&self, request: &PermissionCheck) -> PermissionDecision {
        if self.policy.deterministic_deny(request) {
            return PermissionDecision::denied(self.mode, "deterministic deny rule matched");
        }
        if request.core_or_os {
            return PermissionDecision::denied(
                self.mode,
                "core and OS authority cannot be bypassed",
            );
        }
        if request.risk == RiskLevel::High {
            return PermissionDecision::ask(self.mode, "high-risk action requires a human");
        }
        match self.mode {
            PermissionMode::Bypass if request.run_id.is_some() => PermissionDecision {
                outcome: PermissionOutcome::Allowed,
                verifier: None,
                reason: "ephemeral per-run bypass".to_owned(),
                mode: self.mode,
                persisted: false,
                audit_id: Uuid::now_v7(),
            },
            PermissionMode::Bypass => {
                PermissionDecision::denied(self.mode, "bypass requires a run-scoped request")
            }
            PermissionMode::Policy => {
                if self.policy.allows(request) {
                    PermissionDecision {
                        outcome: PermissionOutcome::Allowed,
                        verifier: None,
                        reason: "policy allow rule matched".to_owned(),
                        mode: self.mode,
                        persisted: true,
                        audit_id: Uuid::now_v7(),
                    }
                } else {
                    PermissionDecision::ask(self.mode, "no policy allow rule matched")
                }
            }
            PermissionMode::Supervised => {
                PermissionDecision::ask(self.mode, "supervised execution requires approval")
            }
            PermissionMode::AiVerifier => {
                PermissionDecision::ask(self.mode, "AI verification must be awaited")
            }
        }
    }

    pub async fn evaluate(&self, request: PermissionCheck) -> PermissionDecision {
        if self.policy.deterministic_deny(&request) {
            return PermissionDecision::denied(self.mode, "deterministic deny rule matched");
        }
        if request.core_or_os {
            return PermissionDecision::denied(
                self.mode,
                "core and OS authority cannot be bypassed",
            );
        }
        if request.risk == RiskLevel::High {
            return PermissionDecision::ask(self.mode, "high-risk action requires a human");
        }
        if self.mode != PermissionMode::AiVerifier {
            return self.evaluate_sync(&request);
        }
        let Some(verifier) = &self.verifier else {
            return PermissionDecision::ask(
                self.mode,
                "AI verifier unavailable; supervision required",
            );
        };
        match verifier.verify(request).await {
            Ok(VerifierOutcome::AllowOnce) => PermissionDecision {
                outcome: PermissionOutcome::Allowed,
                verifier: Some(VerifierOutcome::AllowOnce),
                reason: "AI verifier allowed this request once".to_owned(),
                mode: self.mode,
                persisted: true,
                audit_id: Uuid::now_v7(),
            },
            Ok(VerifierOutcome::Deny) => PermissionDecision {
                verifier: Some(VerifierOutcome::Deny),
                ..PermissionDecision::denied(self.mode, "AI verifier denied the request")
            },
            Ok(VerifierOutcome::AskUser) => PermissionDecision {
                verifier: Some(VerifierOutcome::AskUser),
                ..PermissionDecision::ask(self.mode, "AI verifier delegated to a human")
            },
            Err(error) => PermissionDecision::ask(
                self.mode,
                format!("AI verifier failed; supervision required: {error:?}"),
            ),
        }
    }
}

pub struct PermissionBroker {
    engine: PermissionEngine,
    decisions: Arc<dyn PermissionDecisionPort>,
    approvals: Arc<dyn ApprovalPort>,
}

impl PermissionBroker {
    pub fn new(
        engine: PermissionEngine,
        decisions: Arc<dyn PermissionDecisionPort>,
        approvals: Arc<dyn ApprovalPort>,
    ) -> Self {
        Self {
            engine,
            decisions,
            approvals,
        }
    }

    pub async fn authorize(
        &self,
        request: PermissionCheck,
        grant: &CapabilityGrant,
        cancellation: &CancellationToken,
    ) -> Result<PermissionDecision> {
        cancellation.check()?;
        if !grant.permits_resource(&request.action, &request.resource) {
            let decision = PermissionDecision::denied(
                self.engine.mode(),
                "resource is outside the admitted capability grant",
            );
            self.decisions.record(request, decision.clone()).await?;
            return Err(AgentError::CapabilityDenied(decision.reason));
        }
        let mut decision = self.engine.evaluate(request.clone()).await;
        self.decisions
            .record(request.clone(), decision.clone())
            .await?;
        if decision.outcome == PermissionOutcome::RequiresApproval {
            let outcome = self
                .approvals
                .await_approval(request.clone(), decision.clone(), cancellation.clone())
                .await?;
            let resolved = PermissionDecision {
                outcome,
                reason: if outcome == PermissionOutcome::Allowed {
                    "human approval granted".to_owned()
                } else {
                    "human approval denied".to_owned()
                },
                ..decision.clone()
            };
            self.decisions
                .record(request.clone(), resolved.clone())
                .await?;
            if outcome != PermissionOutcome::Allowed {
                return Err(AgentError::ApprovalRequired);
            }
            decision = resolved;
        } else if decision.outcome != PermissionOutcome::Allowed {
            return Err(AgentError::CapabilityDenied(decision.reason));
        }
        cancellation.check()?;
        Ok(decision)
    }
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        true
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        pattern == value
    }
}
