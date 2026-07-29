use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use gorce_protocol::{OperatorId, ProjectId};

use crate::error::{AgentError, Result};

pub type ProfileId = String;
pub type CapabilitySet = CapabilityGrant;
pub type OperatorProfileResolver = ProfileResolver;
pub type OperatorProfileSpec = OperatorProfile;
pub type ResolvedProfile = ResolvedOperatorProfile;

const DEFAULT_MODEL_TOKENS: u64 = 32_768;
const DEFAULT_TOOL_CALLS: u32 = 64;
const DEFAULT_WALL_TIME_MS: u64 = 300_000;
const DEFAULT_DEPTH: u32 = 4;
const DEFAULT_CONCURRENCY: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Budget {
    pub model_tokens: u64,
    pub tool_calls: u32,
    pub wall_time_ms: u64,
}

impl Budget {
    pub const ZERO: Self = Self {
        model_tokens: 0,
        tool_calls: 0,
        wall_time_ms: 0,
    };

    pub const SAFE_DEFAULT: Self = Self {
        model_tokens: DEFAULT_MODEL_TOKENS,
        tool_calls: DEFAULT_TOOL_CALLS,
        wall_time_ms: DEFAULT_WALL_TIME_MS,
    };

    pub fn min(self, other: Self) -> Self {
        Self {
            model_tokens: self.model_tokens.min(other.model_tokens),
            tool_calls: self.tool_calls.min(other.tool_calls),
            wall_time_ms: self.wall_time_ms.min(other.wall_time_ms),
        }
    }

    pub fn saturating_add(self, other: Self) -> Self {
        Self {
            model_tokens: self.model_tokens.saturating_add(other.model_tokens),
            tool_calls: self.tool_calls.saturating_add(other.tool_calls),
            wall_time_ms: self.wall_time_ms.saturating_add(other.wall_time_ms),
        }
    }

    pub fn is_subset_of(self, parent: Self) -> bool {
        self.model_tokens <= parent.model_tokens
            && self.tool_calls <= parent.tool_calls
            && self.wall_time_ms <= parent.wall_time_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResourceScope {
    pub action: String,
    pub resource: String,
}

impl ResourceScope {
    pub fn new(action: impl Into<String>, resource: impl Into<String>) -> Result<Self> {
        let scope = Self {
            action: action.into(),
            resource: resource.into(),
        };
        if scope.action.trim().is_empty() || scope.resource.trim().is_empty() {
            return Err(AgentError::InvalidInput(
                "resource scopes require an action and resource".to_owned(),
            ));
        }
        Ok(scope)
    }

    pub fn matches(&self, action: &str, resource: &str) -> bool {
        matches_pattern(&self.action, action) && matches_pattern(&self.resource, resource)
    }

    fn is_subset_of(&self, parent: &ResourceScope) -> bool {
        pattern_is_subset(&self.action, &parent.action)
            && pattern_is_subset(&self.resource, &parent.resource)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapabilityGrant {
    pub actions: BTreeSet<String>,
    pub scopes: BTreeSet<ResourceScope>,
    pub max_depth: u32,
    pub max_concurrency: u32,
    pub budget: Budget,
}

impl CapabilityGrant {
    pub fn empty() -> Self {
        Self {
            actions: BTreeSet::new(),
            scopes: BTreeSet::new(),
            max_depth: 0,
            max_concurrency: 0,
            budget: Budget::ZERO,
        }
    }

    pub fn allow<I, S>(actions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let actions: BTreeSet<String> = actions.into_iter().map(Into::into).collect();
        let scopes = actions
            .iter()
            .map(|action| ResourceScope {
                action: action.clone(),
                resource: "*".to_owned(),
            })
            .collect();
        Self {
            actions,
            scopes,
            max_depth: DEFAULT_DEPTH,
            max_concurrency: DEFAULT_CONCURRENCY,
            budget: Budget::SAFE_DEFAULT,
        }
    }

    pub fn with_limits<I, S>(
        actions: I,
        max_depth: u32,
        max_concurrency: u32,
        budget: Budget,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut grant = Self::allow(actions);
        grant.max_depth = max_depth;
        grant.max_concurrency = max_concurrency;
        grant.budget = budget;
        grant
    }

    pub fn with_scopes<I>(mut self, scopes: I) -> Result<Self>
    where
        I: IntoIterator<Item = ResourceScope>,
    {
        self.scopes = scopes.into_iter().collect();
        if self
            .scopes
            .iter()
            .any(|scope| scope.action.trim().is_empty() || scope.resource.trim().is_empty())
        {
            return Err(AgentError::InvalidInput(
                "resource scopes must not be empty".to_owned(),
            ));
        }
        self.actions
            .extend(self.scopes.iter().map(|scope| scope.action.clone()));
        Ok(self)
    }

    pub fn permits(&self, action: &str) -> bool {
        self.actions.contains(action) || self.actions.contains("*")
    }

    pub fn permits_resource(&self, action: &str, resource: &str) -> bool {
        (self.permits(action)
            || action
                .strip_prefix("tool:")
                .is_some_and(|_| self.permits("tool")))
            && self.scopes.iter().any(|scope| {
                scope.matches(action, resource)
                    || action
                        .strip_prefix("tool:")
                        .is_some_and(|_| scope.matches("tool", resource))
            })
    }

    pub fn is_subset_of(&self, parent: &Self) -> bool {
        let actions_fit = self
            .actions
            .iter()
            .all(|action| parent.actions.contains("*") || parent.actions.contains(action));
        let scopes_fit = self.scopes.iter().all(|scope| {
            parent
                .scopes
                .iter()
                .any(|candidate| scope.is_subset_of(candidate))
        });
        actions_fit
            && scopes_fit
            && self.max_depth <= parent.max_depth
            && self.max_concurrency <= parent.max_concurrency
            && self.budget.is_subset_of(parent.budget)
    }

    pub fn intersect(&self, ceiling: &CapabilityCeiling) -> Self {
        let actions = match &ceiling.actions {
            None => self.actions.clone(),
            Some(allowed) if allowed.contains("*") => self.actions.clone(),
            Some(allowed) if self.actions.contains("*") => allowed.clone(),
            Some(allowed) => self.actions.intersection(allowed).cloned().collect(),
        };
        let scopes = match &ceiling.scopes {
            None => self.scopes.clone(),
            Some(allowed) => self
                .scopes
                .iter()
                .filter(|scope| {
                    allowed
                        .iter()
                        .any(|candidate| scope.is_subset_of(candidate))
                })
                .cloned()
                .collect(),
        };
        Self {
            actions,
            scopes,
            max_depth: match ceiling.max_depth {
                Some(value) => self.max_depth.min(value),
                None => self.max_depth,
            },
            max_concurrency: match ceiling.max_concurrency {
                Some(value) => self.max_concurrency.min(value),
                None => self.max_concurrency,
            },
            budget: match ceiling.budget {
                Some(value) => self.budget.min(value),
                None => self.budget,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapabilityCeiling {
    pub actions: Option<BTreeSet<String>>,
    pub scopes: Option<BTreeSet<ResourceScope>>,
    pub max_depth: Option<u32>,
    pub max_concurrency: Option<u32>,
    pub budget: Option<Budget>,
}

impl CapabilityCeiling {
    pub fn unrestricted() -> Self {
        Self::default()
    }

    pub fn actions<I, S>(actions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            actions: Some(actions.into_iter().map(Into::into).collect()),
            ..Self::default()
        }
    }

    pub fn resource_scopes<I>(mut self, scopes: I) -> Result<Self>
    where
        I: IntoIterator<Item = ResourceScope>,
    {
        self.scopes = Some(scopes.into_iter().collect());
        if self.scopes.as_ref().is_some_and(|scopes| {
            scopes
                .iter()
                .any(|scope| scope.action.is_empty() || scope.resource.is_empty())
        }) {
            return Err(AgentError::InvalidInput(
                "resource scopes must not be empty".to_owned(),
            ));
        }
        Ok(self)
    }

    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = Some(budget);
        self
    }

    pub fn with_concurrency(mut self, max: u32) -> Self {
        self.max_concurrency = Some(max);
        self
    }

    pub fn with_depth(mut self, max: u32) -> Self {
        self.max_depth = Some(max);
        self
    }

    pub fn intersect(&self, other: &Self) -> Self {
        let actions = match (&self.actions, &other.actions) {
            (None, None) => None,
            (Some(value), None) | (None, Some(value)) => Some(value.clone()),
            (Some(left), Some(right)) if left.contains("*") => Some(right.clone()),
            (Some(left), Some(right)) if right.contains("*") => Some(left.clone()),
            (Some(left), Some(right)) => Some(left.intersection(right).cloned().collect()),
        };
        let scopes = match (&self.scopes, &other.scopes) {
            (None, None) => None,
            (Some(value), None) | (None, Some(value)) => Some(value.clone()),
            (Some(left), Some(right)) => Some(
                left.iter()
                    .filter(|scope| right.iter().any(|candidate| scope.is_subset_of(candidate)))
                    .cloned()
                    .collect(),
            ),
        };
        Self {
            actions,
            scopes,
            max_depth: min_option(self.max_depth, other.max_depth),
            max_concurrency: min_option(self.max_concurrency, other.max_concurrency),
            budget: match (self.budget, other.budget) {
                (None, None) => None,
                (Some(value), None) | (None, Some(value)) => Some(value),
                (Some(left), Some(right)) => Some(left.min(right)),
            },
        }
    }
}

fn min_option(left: Option<u32>, right: Option<u32>) -> Option<u32> {
    match (left, right) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value),
        (Some(left), Some(right)) => Some(left.min(right)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorProfile {
    pub id: ProfileId,
    pub extends: Vec<ProfileId>,
    pub grants: CapabilityGrant,
    pub ceiling: CapabilityCeiling,
}

impl OperatorProfile {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            extends: Vec::new(),
            grants: CapabilityGrant::empty(),
            ceiling: CapabilityCeiling::unrestricted(),
        }
    }

    pub fn compose(mut self, parent: impl Into<String>) -> Self {
        self.extends.push(parent.into());
        self
    }

    pub fn with_grants(mut self, grants: CapabilityGrant) -> Self {
        self.grants = grants;
        self
    }

    pub fn with_ceiling(mut self, ceiling: CapabilityCeiling) -> Self {
        self.ceiling = ceiling;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedOperatorProfile {
    pub id: ProfileId,
    pub capabilities: CapabilityGrant,
    pub ceiling: CapabilityCeiling,
    pub ancestry: Vec<ProfileId>,
}

impl ResolvedOperatorProfile {
    pub fn permits(&self, action: &str) -> bool {
        self.capabilities.permits(action)
    }

    pub fn grant_subset(&self, requested: CapabilityGrant) -> Result<CapabilityGrant> {
        if !requested.is_subset_of(&self.capabilities) {
            return Err(AgentError::CapabilityDenied(
                "a child grant exceeds the resolved operator profile".to_owned(),
            ));
        }
        Ok(requested)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProfileResolver {
    profiles: BTreeMap<ProfileId, OperatorProfile>,
}

impl ProfileResolver {
    pub fn insert(&mut self, profile: OperatorProfile) -> Result<()> {
        if profile.id.trim().is_empty() {
            return Err(AgentError::InvalidInput(
                "profile id must not be empty".to_owned(),
            ));
        }
        if self.profiles.contains_key(&profile.id) {
            return Err(AgentError::Conflict("profile id already exists".to_owned()));
        }
        self.profiles.insert(profile.id.clone(), profile);
        Ok(())
    }

    pub fn register(&mut self, profile: OperatorProfile) -> Result<()> {
        self.insert(profile)
    }

    pub fn get(&self, id: &str) -> Option<&OperatorProfile> {
        self.profiles.get(id)
    }

    pub fn resolve(&self, id: &str) -> Result<ResolvedOperatorProfile> {
        self.resolve_inner(id, &mut BTreeSet::new())
    }

    fn resolve_inner(
        &self,
        id: &str,
        visiting: &mut BTreeSet<ProfileId>,
    ) -> Result<ResolvedOperatorProfile> {
        if !visiting.insert(id.to_owned()) {
            return Err(AgentError::Conflict(format!(
                "profile composition cycle at {id}"
            )));
        }
        let profile = self
            .profiles
            .get(id)
            .cloned()
            .ok_or_else(|| AgentError::NotFound(format!("profile {id}")))?;
        let mut capabilities = CapabilityGrant::empty();
        let mut ceiling = CapabilityCeiling::unrestricted();
        let mut ancestry = Vec::new();
        for parent in profile.extends {
            let resolved = self.resolve_inner(&parent, visiting)?;
            capabilities.actions.extend(resolved.capabilities.actions);
            capabilities.scopes.extend(resolved.capabilities.scopes);
            capabilities.max_depth = capabilities.max_depth.max(resolved.capabilities.max_depth);
            capabilities.max_concurrency = capabilities
                .max_concurrency
                .max(resolved.capabilities.max_concurrency);
            capabilities.budget = capabilities
                .budget
                .saturating_add(resolved.capabilities.budget);
            ceiling = ceiling.intersect(&resolved.ceiling);
            ancestry.extend(resolved.ancestry);
        }
        capabilities.actions.extend(profile.grants.actions.clone());
        capabilities.scopes.extend(profile.grants.scopes.clone());
        capabilities.max_depth = capabilities.max_depth.max(profile.grants.max_depth);
        capabilities.max_concurrency = capabilities
            .max_concurrency
            .max(profile.grants.max_concurrency);
        capabilities.budget = capabilities.budget.saturating_add(profile.grants.budget);
        ceiling = ceiling.intersect(&profile.ceiling);
        capabilities = capabilities.intersect(&ceiling);
        ancestry.push(profile.id.clone());
        visiting.remove(id);
        Ok(ResolvedOperatorProfile {
            id: profile.id,
            capabilities,
            ceiling,
            ancestry,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AdmissionRequest {
    pub project_id: ProjectId,
    pub run_id: uuid::Uuid,
    pub operator_id: OperatorId,
    pub profile_id: ProfileId,
    pub requested: Option<CapabilityGrant>,
}

impl AdmissionRequest {
    pub fn new(
        project_id: ProjectId,
        run_id: uuid::Uuid,
        operator_id: OperatorId,
        profile_id: impl Into<String>,
    ) -> Result<Self> {
        if project_id.is_nil() || run_id.is_nil() || operator_id.is_nil() {
            return Err(AgentError::InvalidInput(
                "admission identity must not be nil".to_owned(),
            ));
        }
        Ok(Self {
            project_id,
            run_id,
            operator_id,
            profile_id: profile_id.into(),
            requested: None,
        })
    }

    pub fn with_requested(mut self, requested: CapabilityGrant) -> Self {
        self.requested = Some(requested);
        self
    }
}

#[derive(Debug, Clone)]
pub struct HostAuthority {
    project_id: ProjectId,
    ceiling: CapabilityCeiling,
    profiles: Arc<ProfileResolver>,
}

impl HostAuthority {
    pub fn new(
        project_id: ProjectId,
        ceiling: CapabilityCeiling,
        profiles: Arc<ProfileResolver>,
    ) -> Result<Self> {
        if project_id.is_nil() {
            return Err(AgentError::InvalidInput(
                "project id must not be nil".to_owned(),
            ));
        }
        if ceiling.actions.is_none()
            || ceiling.scopes.is_none()
            || ceiling.budget.is_none()
            || ceiling.max_depth.is_none()
            || ceiling.max_concurrency.is_none()
        {
            return Err(AgentError::InvalidInput(
                "host authority requires action, resource, and budget ceilings".to_owned(),
            ));
        }
        let budget = ceiling.budget.expect("budget ceiling was checked");
        if ceiling.max_depth == Some(u32::MAX)
            || ceiling.max_concurrency == Some(u32::MAX)
            || budget.model_tokens == u64::MAX
            || budget.tool_calls == u32::MAX
            || budget.wall_time_ms == u64::MAX
        {
            return Err(AgentError::InvalidInput(
                "host authority ceilings must be finite".to_owned(),
            ));
        }
        Ok(Self {
            project_id,
            ceiling,
            profiles,
        })
    }

    pub fn project_id(&self) -> ProjectId {
        self.project_id
    }

    pub fn admit(&self, request: AdmissionRequest) -> Result<crate::agent::AgentInstance> {
        if request.project_id != self.project_id {
            return Err(AgentError::CapabilityDenied(
                "admission project is outside the host authority".to_owned(),
            ));
        }
        let profile = self.profiles.resolve(&request.profile_id)?;
        let requested = request
            .requested
            .unwrap_or_else(|| profile.capabilities.clone());
        if !requested.is_subset_of(&profile.capabilities) {
            return Err(AgentError::CapabilityDenied(
                "requested grant exceeds the operator profile".to_owned(),
            ));
        }
        let granted = requested.intersect(&self.ceiling);
        if !requested.is_subset_of(&granted) {
            return Err(AgentError::CapabilityDenied(
                "requested grant exceeds the host authority ceiling".to_owned(),
            ));
        }
        crate::agent::AgentInstance::admitted(
            request.project_id,
            request.run_id,
            request.operator_id,
            profile,
            granted,
        )
    }
}

#[derive(Debug, Default)]
pub(crate) struct ReservationState {
    pub active_children: BTreeMap<OperatorId, BTreeMap<OperatorId, Budget>>,
    pub consumed: BTreeMap<OperatorId, Budget>,
}

pub(crate) type SharedReservationState = Arc<Mutex<ReservationState>>;

fn matches_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        true
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        pattern == value
    }
}

fn pattern_is_subset(child: &str, parent: &str) -> bool {
    parent == "*"
        || child == parent
        || parent.ends_with('*') && child.starts_with(parent.trim_end_matches('*'))
}
