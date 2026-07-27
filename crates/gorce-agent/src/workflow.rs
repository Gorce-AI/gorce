use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::error::{AgentError, Result};

const MAX_WORKFLOW_NODES: usize = 10_000;
const MAX_WORKFLOW_TEXT_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowNode {
    pub id: String,
    pub dependencies: BTreeSet<String>,
}

impl WorkflowNode {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            dependencies: BTreeSet::new(),
        }
    }

    pub fn depends_on(mut self, dependency: impl Into<String>) -> Self {
        self.dependencies.insert(dependency.into());
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct WorkflowDefinition {
    nodes: BTreeMap<String, WorkflowNode>,
}

impl WorkflowDefinition {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: WorkflowNode) -> Result<()> {
        if self.nodes.len() >= MAX_WORKFLOW_NODES {
            return Err(AgentError::BudgetExceeded(
                "workflow node limit exhausted".to_owned(),
            ));
        }
        if node.id.trim().is_empty() {
            return Err(AgentError::InvalidInput(
                "workflow node id must not be empty".to_owned(),
            ));
        }
        if self.nodes.contains_key(&node.id) {
            return Err(AgentError::Conflict(format!(
                "workflow node {} already exists",
                node.id
            )));
        }
        if node
            .dependencies
            .iter()
            .any(|dependency| dependency == &node.id)
        {
            return Err(AgentError::Conflict("workflow dependency cycle".to_owned()));
        }
        if node
            .dependencies
            .iter()
            .any(|dependency| !self.nodes.contains_key(dependency))
        {
            return Err(AgentError::NotFound(
                "workflow dependencies must be added first".to_owned(),
            ));
        }
        self.nodes.insert(node.id.clone(), node);
        Ok(())
    }

    pub fn add_dependency(&mut self, node: &str, dependency: &str) -> Result<()> {
        if node == dependency {
            return Err(AgentError::Conflict("workflow dependency cycle".to_owned()));
        }
        if !self.nodes.contains_key(node) || !self.nodes.contains_key(dependency) {
            return Err(AgentError::NotFound("workflow node not found".to_owned()));
        }
        let mut seen = BTreeSet::new();
        if reaches(&self.nodes, dependency, node, &mut seen) {
            return Err(AgentError::Conflict("workflow dependency cycle".to_owned()));
        }
        self.nodes
            .get_mut(node)
            .expect("node was checked")
            .dependencies
            .insert(dependency.to_owned());
        Ok(())
    }

    pub fn nodes(&self) -> impl Iterator<Item = &WorkflowNode> {
        self.nodes.values()
    }

    pub fn node(&self, id: &str) -> Option<&WorkflowNode> {
        self.nodes.get(id)
    }

    pub fn definition_hash(&self) -> String {
        let mut hasher = Sha256::new();
        for node in self.nodes.values() {
            hasher.update(node.id.as_bytes());
            hasher.update([0]);
            for dependency in &node.dependencies {
                hasher.update(dependency.as_bytes());
                hasher.update([0]);
            }
        }
        format!("sha256:{:x}", hasher.finalize())
    }

    fn validate(&self) -> Result<()> {
        for node in self.nodes.values() {
            if node
                .dependencies
                .iter()
                .any(|dependency| !self.nodes.contains_key(dependency))
            {
                return Err(AgentError::NotFound(format!(
                    "workflow dependency for {}",
                    node.id
                )));
            }
            let mut seen = BTreeSet::new();
            if node
                .dependencies
                .iter()
                .any(|dependency| reaches(&self.nodes, dependency, &node.id, &mut seen))
            {
                return Err(AgentError::Conflict("workflow dependency cycle".to_owned()));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    NeedsRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowStatus {
    Ready,
    Running,
    Paused,
    Cancelling,
    Cancelled,
    Succeeded,
    Failed,
    Recovering,
}

impl WorkflowStatus {
    fn terminal(self) -> bool {
        matches!(self, Self::Cancelled | Self::Succeeded | Self::Failed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowState {
    pub workflow_id: String,
    pub revision: u64,
    pub definition_hash: String,
    pub status: WorkflowStatus,
    pub nodes: BTreeMap<String, NodeStatus>,
    pub last_error: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowEvent {
    Started {
        workflow_id: String,
    },
    Paused {
        workflow_id: String,
    },
    Resumed {
        workflow_id: String,
    },
    NodeStarted {
        workflow_id: String,
        node_id: String,
    },
    NodeCompleted {
        workflow_id: String,
        node_id: String,
    },
    NodeFailed {
        workflow_id: String,
        node_id: String,
        error: String,
    },
    Cancelled {
        workflow_id: String,
    },
    Recovered {
        workflow_id: String,
    },
    Succeeded {
        workflow_id: String,
    },
}

pub trait WorkflowStateStore: Send + Sync {
    fn load(&self, workflow_id: &str) -> Result<Option<WorkflowState>>;
    fn commit(
        &self,
        workflow_id: &str,
        state: WorkflowState,
        expected_revision: u64,
        definition_hash: &str,
        events: &[WorkflowEvent],
    ) -> Result<()>;
}

pub struct DurableWorkflow {
    definition: WorkflowDefinition,
    state: WorkflowState,
    store: std::sync::Arc<dyn WorkflowStateStore>,
}

impl DurableWorkflow {
    pub fn create(
        workflow_id: impl Into<String>,
        definition: WorkflowDefinition,
        store: std::sync::Arc<dyn WorkflowStateStore>,
        at: impl Into<String>,
    ) -> Result<Self> {
        definition.validate()?;
        let workflow_id = workflow_id.into();
        if workflow_id.trim().is_empty() {
            return Err(AgentError::InvalidInput(
                "workflow id must not be empty".to_owned(),
            ));
        }
        let definition_hash = definition.definition_hash();
        let state = WorkflowState {
            workflow_id: workflow_id.clone(),
            revision: 1,
            definition_hash: definition_hash.clone(),
            status: WorkflowStatus::Ready,
            nodes: definition
                .nodes
                .keys()
                .map(|id| (id.clone(), NodeStatus::Pending))
                .collect(),
            last_error: None,
            updated_at: at.into(),
        };
        store.commit(&workflow_id, state.clone(), 0, &definition_hash, &[])?;
        Ok(Self {
            definition,
            state,
            store,
        })
    }

    pub fn restore(
        workflow_id: &str,
        definition: WorkflowDefinition,
        store: std::sync::Arc<dyn WorkflowStateStore>,
    ) -> Result<Self> {
        definition.validate()?;
        let state = store
            .load(workflow_id)?
            .ok_or_else(|| AgentError::NotFound(format!("workflow {workflow_id}")))?;
        let expected_hash = definition.definition_hash();
        if state.definition_hash != expected_hash {
            return Err(AgentError::Conflict(
                "workflow definition hash mismatch".to_owned(),
            ));
        }
        Ok(Self {
            definition,
            state,
            store,
        })
    }

    pub fn state(&self) -> &WorkflowState {
        &self.state
    }

    pub fn definition(&self) -> &WorkflowDefinition {
        &self.definition
    }

    pub fn start(&mut self, at: impl Into<String>) -> Result<()> {
        if self.state.status != WorkflowStatus::Ready {
            return Err(AgentError::Conflict("workflow is not ready".to_owned()));
        }
        self.transition(
            WorkflowStatus::Running,
            at,
            WorkflowEvent::Started {
                workflow_id: self.state.workflow_id.clone(),
            },
        )
    }

    pub fn pause(&mut self, at: impl Into<String>) -> Result<()> {
        if self.state.status != WorkflowStatus::Running {
            return Err(AgentError::Conflict("workflow is not running".to_owned()));
        }
        self.transition(
            WorkflowStatus::Paused,
            at,
            WorkflowEvent::Paused {
                workflow_id: self.state.workflow_id.clone(),
            },
        )
    }

    pub fn resume(&mut self, at: impl Into<String>) -> Result<()> {
        if !matches!(
            self.state.status,
            WorkflowStatus::Paused | WorkflowStatus::Recovering
        ) {
            return Err(AgentError::Conflict(
                "workflow is not paused or recovering".to_owned(),
            ));
        }
        self.transition(
            WorkflowStatus::Running,
            at,
            WorkflowEvent::Resumed {
                workflow_id: self.state.workflow_id.clone(),
            },
        )
    }

    pub fn cancel(&mut self, at: impl Into<String>) -> Result<()> {
        if self.state.status.terminal() {
            return Ok(());
        }
        let at = at.into();
        let previous = self.state.clone();
        self.state.status = WorkflowStatus::Cancelling;
        self.state.updated_at = at.clone();
        for status in self.state.nodes.values_mut() {
            if matches!(
                *status,
                NodeStatus::Pending | NodeStatus::Running | NodeStatus::NeedsRecovery
            ) {
                *status = NodeStatus::Cancelled;
            }
        }
        self.state.status = WorkflowStatus::Cancelled;
        self.state.revision = self.state.revision.saturating_add(1);
        if let Err(error) = self.commit(
            previous.revision,
            &[WorkflowEvent::Cancelled {
                workflow_id: self.state.workflow_id.clone(),
            }],
        ) {
            self.state = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn recover(&mut self, at: impl Into<String>) -> Result<()> {
        if self.state.status.terminal() {
            return Err(AgentError::Conflict(
                "terminal workflow cannot recover".to_owned(),
            ));
        }
        let at = at.into();
        let previous = self.state.clone();
        for status in self.state.nodes.values_mut() {
            if *status == NodeStatus::Running {
                *status = NodeStatus::NeedsRecovery;
            }
        }
        self.state.status = WorkflowStatus::Recovering;
        self.state.updated_at = at.clone();
        for status in self.state.nodes.values_mut() {
            if *status == NodeStatus::NeedsRecovery {
                *status = NodeStatus::Pending;
            }
        }
        self.state.status = WorkflowStatus::Ready;
        self.state.revision = self.state.revision.saturating_add(1);
        if let Err(error) = self.commit(
            previous.revision,
            &[WorkflowEvent::Recovered {
                workflow_id: self.state.workflow_id.clone(),
            }],
        ) {
            self.state = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn ready_nodes(&self) -> Vec<String> {
        self.definition
            .nodes
            .values()
            .filter(|node| {
                self.state.nodes.get(&node.id) == Some(&NodeStatus::Pending)
                    && node.dependencies.iter().all(|dependency| {
                        self.state.nodes.get(dependency) == Some(&NodeStatus::Completed)
                    })
            })
            .map(|node| node.id.clone())
            .collect()
    }

    pub fn start_node(&mut self, node_id: &str, at: impl Into<String>) -> Result<()> {
        if self.state.status != WorkflowStatus::Running {
            return Err(AgentError::Conflict("workflow is not running".to_owned()));
        }
        if !self.ready_nodes().iter().any(|id| id == node_id) {
            return Err(AgentError::Conflict(format!(
                "workflow node {node_id} is not ready"
            )));
        }
        self.set_node(
            node_id,
            NodeStatus::Running,
            at,
            WorkflowEvent::NodeStarted {
                workflow_id: self.state.workflow_id.clone(),
                node_id: node_id.to_owned(),
            },
        )
    }

    pub fn complete_node(&mut self, node_id: &str, at: impl Into<String>) -> Result<()> {
        if self.state.nodes.get(node_id) != Some(&NodeStatus::Running) {
            return Err(AgentError::Conflict(
                "workflow node is not running".to_owned(),
            ));
        }
        let at = at.into();
        let previous = self.state.clone();
        self.state
            .nodes
            .insert(node_id.to_owned(), NodeStatus::Completed);
        self.state.updated_at = at;
        self.state.status = if self
            .state
            .nodes
            .values()
            .all(|status| *status == NodeStatus::Completed)
        {
            WorkflowStatus::Succeeded
        } else {
            self.state.status
        };
        self.state.revision = self.state.revision.saturating_add(1);
        let mut events = vec![WorkflowEvent::NodeCompleted {
            workflow_id: self.state.workflow_id.clone(),
            node_id: node_id.to_owned(),
        }];
        if self.state.status == WorkflowStatus::Succeeded {
            events.push(WorkflowEvent::Succeeded {
                workflow_id: self.state.workflow_id.clone(),
            });
        }
        if let Err(error) = self.commit(previous.revision, &events) {
            self.state = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn fail_node(
        &mut self,
        node_id: &str,
        error: impl Into<String>,
        at: impl Into<String>,
    ) -> Result<()> {
        let error = error.into();
        if error.len() > MAX_WORKFLOW_TEXT_BYTES {
            return Err(AgentError::MessageTooLarge);
        }
        if self.state.nodes.get(node_id) != Some(&NodeStatus::Running) {
            return Err(AgentError::Conflict(
                "workflow node is not running".to_owned(),
            ));
        }
        self.state.last_error = Some(error.clone());
        let previous = self.state.clone();
        self.state
            .nodes
            .insert(node_id.to_owned(), NodeStatus::Failed);
        self.state.status = WorkflowStatus::Failed;
        self.state.updated_at = at.into();
        self.state.revision = self.state.revision.saturating_add(1);
        if let Err(commit_error) = self.commit(
            previous.revision,
            &[WorkflowEvent::NodeFailed {
                workflow_id: self.state.workflow_id.clone(),
                node_id: node_id.to_owned(),
                error,
            }],
        ) {
            self.state = previous;
            return Err(commit_error);
        }
        Ok(())
    }

    fn set_node(
        &mut self,
        node_id: &str,
        status: NodeStatus,
        at: impl Into<String>,
        event: WorkflowEvent,
    ) -> Result<()> {
        if !self.definition.nodes.contains_key(node_id) {
            return Err(AgentError::NotFound(format!("workflow node {node_id}")));
        }
        let previous = self.state.clone();
        self.state.nodes.insert(node_id.to_owned(), status);
        self.state.updated_at = at.into();
        self.state.revision = self.state.revision.saturating_add(1);
        if let Err(error) = self.commit(previous.revision, &[event]) {
            self.state = previous;
            return Err(error);
        }
        Ok(())
    }

    fn transition(
        &mut self,
        status: WorkflowStatus,
        at: impl Into<String>,
        event: WorkflowEvent,
    ) -> Result<()> {
        let previous = self.state.clone();
        self.state.status = status;
        self.state.updated_at = at.into();
        self.state.revision = self.state.revision.saturating_add(1);
        if let Err(error) = self.commit(previous.revision, &[event]) {
            self.state = previous;
            return Err(error);
        }
        Ok(())
    }

    fn commit(&self, expected_revision: u64, events: &[WorkflowEvent]) -> Result<()> {
        self.store.commit(
            &self.state.workflow_id,
            self.state.clone(),
            expected_revision,
            &self.state.definition_hash,
            events,
        )
    }
}

fn reaches(
    nodes: &BTreeMap<String, WorkflowNode>,
    start: &str,
    target: &str,
    seen: &mut BTreeSet<String>,
) -> bool {
    if start == target {
        return true;
    }
    if !seen.insert(start.to_owned()) {
        return false;
    }
    nodes
        .get(start)
        .map(|node| {
            node.dependencies
                .iter()
                .any(|dependency| reaches(nodes, dependency, target, seen))
        })
        .unwrap_or(false)
}

pub type WorkflowEventEnvelope = crate::events::EventEnvelope<WorkflowEvent>;
