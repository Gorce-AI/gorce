use std::collections::{BTreeMap, BTreeSet};

use gorce_protocol::SkillManifestId;

use crate::capability::{CapabilityGrant, ResourceScope};
use crate::error::{AgentError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedOperatorSpec {
    pub hash: String,
    pub model_component: String,
    pub tool_component: String,
    pub skills: Vec<SkillManifestRef>,
}

impl ResolvedOperatorSpec {
    pub fn new(
        hash: impl Into<String>,
        model_component: impl Into<String>,
        tool_component: impl Into<String>,
        skills: Vec<SkillManifestRef>,
    ) -> Result<Self> {
        let spec = Self {
            hash: hash.into(),
            model_component: model_component.into(),
            tool_component: tool_component.into(),
            skills,
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<()> {
        if !is_sha256_hash(&self.hash)
            || self.model_component.trim().is_empty()
            || self.tool_component.trim().is_empty()
            || self.skills.iter().any(|skill| {
                skill.name.trim().is_empty()
                    || skill.version.trim().is_empty()
                    || skill.version == "latest"
            })
        {
            return Err(AgentError::InvalidInput(
                "resolved operator specs require pinned component and skill references".to_owned(),
            ));
        }
        Ok(())
    }
}

fn is_sha256_hash(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub type Skill = SkillDefinition;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureLevel {
    Summary,
    Instructions,
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillManifestRef {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SkillAction {
    pub action: String,
    pub resource: String,
}

impl SkillAction {
    pub fn new(action: impl Into<String>, resource: impl Into<String>) -> Result<Self> {
        let action = Self {
            action: action.into(),
            resource: resource.into(),
        };
        if action.action.trim().is_empty() || action.resource.trim().is_empty() {
            return Err(AgentError::InvalidInput(
                "skill actions require action and resource".to_owned(),
            ));
        }
        Ok(action)
    }
}

impl SkillManifestRef {
    pub fn pinned(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillDefinition {
    pub id: SkillManifestId,
    pub name: String,
    pub version: String,
    pub summary: String,
    pub instructions: String,
    pub details: String,
    pub required_actions: BTreeSet<SkillAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillSpec {
    pub id: SkillManifestId,
    pub name: String,
    pub version: String,
    pub summary: String,
    pub instructions: String,
    pub details: String,
    pub required_capabilities: CapabilityGrant,
}

impl SkillDefinition {
    pub fn new(spec: SkillSpec) -> Result<Self> {
        let value = Self {
            id: spec.id,
            name: spec.name,
            version: spec.version,
            summary: spec.summary,
            instructions: spec.instructions,
            details: spec.details,
            required_actions: spec
                .required_capabilities
                .scopes
                .iter()
                .map(|scope| SkillAction {
                    action: scope.action.clone(),
                    resource: scope.resource.clone(),
                })
                .collect(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn manifest_ref(&self) -> SkillManifestRef {
        SkillManifestRef::pinned(self.name.clone(), self.version.clone())
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.is_nil() {
            return Err(AgentError::InvalidInput(
                "skill id must not be nil".to_owned(),
            ));
        }
        if self.name.trim().is_empty() || self.version.trim().is_empty() {
            return Err(AgentError::InvalidInput(
                "skill name and version must not be empty".to_owned(),
            ));
        }
        if self.summary.trim().is_empty() || self.instructions.trim().is_empty() {
            return Err(AgentError::InvalidInput(
                "skill summary and instructions must not be empty".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn disclose(&self, level: DisclosureLevel) -> SkillView {
        SkillView {
            manifest: self.manifest_ref(),
            summary: self.summary.clone(),
            instructions: matches!(level, DisclosureLevel::Instructions | DisclosureLevel::Full)
                .then(|| self.instructions.clone()),
            details: matches!(level, DisclosureLevel::Full).then(|| self.details.clone()),
            required_actions: self.required_actions.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillView {
    pub manifest: SkillManifestRef,
    pub summary: String,
    pub instructions: Option<String>,
    pub details: Option<String>,
    pub required_actions: BTreeSet<SkillAction>,
}

#[derive(Debug, Clone, Default)]
pub struct SkillRegistry {
    skills: BTreeMap<(String, String), SkillDefinition>,
}

impl SkillRegistry {
    pub fn register(&mut self, skill: SkillDefinition) -> Result<()> {
        skill.validate()?;
        let key = (skill.name.clone(), skill.version.clone());
        if self.skills.contains_key(&key) {
            return Err(AgentError::Conflict(
                "skill version already registered".to_owned(),
            ));
        }
        self.skills.insert(key, skill);
        Ok(())
    }

    pub fn add(&mut self, skill: SkillDefinition) -> Result<()> {
        self.register(skill)
    }

    pub fn resolve_pinned(&self, reference: &SkillManifestRef) -> Result<&SkillDefinition> {
        if reference.name.trim().is_empty() || reference.version.trim().is_empty() {
            return Err(AgentError::InvalidInput(
                "skill resolution requires an exact name and version".to_owned(),
            ));
        }
        self.skills
            .get(&(reference.name.clone(), reference.version.clone()))
            .ok_or_else(|| {
                AgentError::NotFound(format!("skill {}@{}", reference.name, reference.version))
            })
    }

    pub fn disclose(
        &self,
        reference: &SkillManifestRef,
        level: DisclosureLevel,
        granted: &CapabilityGrant,
    ) -> Result<SkillView> {
        let skill = self.resolve_pinned(reference)?;
        let scopes: BTreeSet<ResourceScope> = skill
            .required_actions
            .iter()
            .map(|action| ResourceScope {
                action: action.action.clone(),
                resource: action.resource.clone(),
            })
            .collect();
        let required = CapabilityGrant::allow(scopes.iter().map(|scope| scope.action.clone()))
            .with_scopes(scopes)?;
        if !required.is_subset_of(granted) {
            return Err(AgentError::CapabilityDenied(format!(
                "skill {}@{} requires capabilities outside its grant",
                reference.name, reference.version
            )));
        }
        Ok(skill.disclose(level))
    }

    pub fn versions(&self, name: &str) -> Vec<String> {
        self.skills
            .keys()
            .filter(|(skill_name, _)| skill_name == name)
            .map(|(_, version)| version.clone())
            .collect()
    }
}
