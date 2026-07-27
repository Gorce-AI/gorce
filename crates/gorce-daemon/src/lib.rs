#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{
    rejection::{JsonRejection, QueryRejection},
    DefaultBodyLimit, Path as AxumPath, Query, State,
};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use gorce_platform_security::{LockGuard, SecureRuntime, SecurityError};
use gorce_protocol::{
    Admission, AdmissionCreateArguments, ApiError, AuthorityBootstrap, AuthorityBudget,
    AuthorityCommandKind, AuthorityCommandReceipt, AuthorityCommandRequest,
    AuthorityExecutionDisposition, AuthorityGrant, AuthorityPolicy, AuthorityPolicyEffect,
    AuthorityPolicyRule, AuthorityPrincipal, AuthorityPrincipalKind, AuthorityProfileRevision,
    CommandCommit, CommandError, CommandErrorCode, CommandResult, CommandResultKind,
    EmptyCommandArguments, ErrorCode, EventActor, EventActorKind, EventBatch, EventCommand,
    EventRecord, OperatorBinding, OperatorBindingArguments, PinnedProfileSpec,
    PinnedSkillReference, PrincipalId, ProfileRevisionId, ProjectId, PublicEvent,
    PublicEventCursor, ResourceKind, ResourceReference, UuidV7, MAX_PUBLIC_EVENT_COUNT,
    PROTOCOL_VERSION,
};
use gorce_store::{ProjectStoreReader, StoreError as ReaderStoreError};
use gorce_store_writer::{
    ProjectStoreWriter, StoreError as WriterStoreError, WriterState, STATE_DIRECTORY,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{Mutex as AsyncMutex, Notify, OnceCell};
use tokio::task::JoinError;
use uuid::Uuid;

pub const DAEMON_VERSION: &str = "0.1";
pub const DEFAULT_DESCRIPTOR_NAME: &str = "gorce-daemon.json";
pub const DEFAULT_TOKEN_NAME: &str = "gorce-daemon.token";
pub const DEFAULT_IDENTITY_NAME: &str = "gorce-daemon.identity";
pub const DEFAULT_INSTANCE_LOCK_NAME: &str = "gorce-daemon.instance.lock";
pub const DEFAULT_SUBSCRIBER_QUEUE_CAPACITY: usize = 1024 * 1024;
pub const DEFAULT_EVENT_HISTORY_CAPACITY: usize = 64 * 1024;
pub const MAX_CLIENT_QUEUE_BYTES: usize = 1024 * 1024;
const CURSOR_PREFIX: &str = "g1";
const ORIGIN_CURSOR: CanonicalCursor = CanonicalCursor {
    batch: 0,
    ordinal: 0,
};
const MAX_EVENT_PAGE_BYTES: usize = 1024 * 1024;
const RESYNC_MARKER_BYTES: usize = 1024;
const MAX_IDENTITY_BYTES: usize = 128;
const MAX_TOKEN_BYTES: usize = 4096;
const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024;

tokio::task_local! {
    static CURRENT_REQUEST_ID: String;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageFailureKind {
    InvalidArgument,
    ProjectMismatch,
    NeedsRecovery,
    Other,
}

#[derive(Debug)]
enum CommandFailure {
    InvalidCommand(String),
    InvalidArguments(String),
    MissingIdempotencyKey(String),
    IdempotencyConflict(String),
    Rejected(String),
}

impl CommandFailure {
    fn into_error(self) -> DaemonError {
        let (code, message) = match self {
            Self::InvalidCommand(message) => (CommandErrorCode::InvalidCommand, message),
            Self::InvalidArguments(message) => (CommandErrorCode::InvalidArguments, message),
            Self::MissingIdempotencyKey(message) => {
                (CommandErrorCode::MissingIdempotencyKey, message)
            }
            Self::IdempotencyConflict(message) => (CommandErrorCode::IdempotencyConflict, message),
            Self::Rejected(message) => (CommandErrorCode::CommandRejected, message),
        };
        DaemonError::Command { code, message }
    }
}

pub fn daemon_version() -> &'static str {
    let _ = gorce_agent::agent_version();
    DAEMON_VERSION
}

#[derive(Debug)]
pub enum DaemonError {
    Io(io::Error),
    Json(serde_json::Error),
    Storage {
        kind: StorageFailureKind,
        message: String,
    },
    InvalidConfiguration(String),
    ProjectNotFound(ProjectId),
    ProjectAlreadyConfigured(ProjectId),
    DuplicateProjectRoot(PathBuf),
    Command {
        code: CommandErrorCode,
        message: String,
    },
    TaskJoin(String),
    Discovery(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
            Self::Storage { message, .. } => write!(formatter, "storage error: {message}"),
            Self::InvalidConfiguration(message) => {
                write!(formatter, "invalid daemon configuration: {message}")
            }
            Self::ProjectNotFound(id) => write!(formatter, "project not found: {id}"),
            Self::ProjectAlreadyConfigured(id) => {
                write!(formatter, "project is already configured: {id}")
            }
            Self::DuplicateProjectRoot(path) => {
                write!(
                    formatter,
                    "project root is already configured: {}",
                    path.display()
                )
            }
            Self::Command { message, .. } => {
                write!(formatter, "command dispatch failed: {message}")
            }
            Self::TaskJoin(message) => write!(formatter, "background task failed: {message}"),
            Self::Discovery(message) => write!(formatter, "discovery error: {message}"),
        }
    }
}

impl std::error::Error for DaemonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for DaemonError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for DaemonError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

fn writer_error(error: WriterStoreError) -> DaemonError {
    let kind = match &error {
        WriterStoreError::InvalidArgument(_) => StorageFailureKind::InvalidArgument,
        WriterStoreError::ProjectMismatch { .. } => StorageFailureKind::ProjectMismatch,
        WriterStoreError::NeedsRecovery { .. } => StorageFailureKind::NeedsRecovery,
        _ => StorageFailureKind::Other,
    };
    DaemonError::Storage {
        kind,
        message: error.to_string(),
    }
}

impl From<ReaderStoreError> for DaemonError {
    fn from(error: ReaderStoreError) -> Self {
        Self::Storage {
            kind: StorageFailureKind::Other,
            message: error.to_string(),
        }
    }
}

impl From<SecurityError> for DaemonError {
    fn from(error: SecurityError) -> Self {
        Self::Discovery(error.to_string())
    }
}

impl DaemonError {
    fn command(message: impl Into<String>) -> Self {
        CommandFailure::Rejected(message.into()).into_error()
    }

    fn idempotency_conflict(message: impl Into<String>) -> Self {
        CommandFailure::IdempotencyConflict(message.into()).into_error()
    }
}

impl From<JoinError> for DaemonError {
    fn from(error: JoinError) -> Self {
        Self::TaskJoin(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, DaemonError>;

#[derive(Debug, Clone)]
pub struct ProjectConfig {
    pub id: ProjectId,
    pub root: PathBuf,
}

impl ProjectConfig {
    pub fn new(id: ProjectId, root: impl Into<PathBuf>) -> Self {
        Self {
            id,
            root: root.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub bind_addr: SocketAddr,
    pub runtime_dir: Option<PathBuf>,
    pub descriptor_name: String,
    pub token_name: String,
    pub projects: Vec<ProjectConfig>,
    pub subscriber_queue_capacity: usize,
    pub event_history_capacity: usize,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            runtime_dir: None,
            descriptor_name: DEFAULT_DESCRIPTOR_NAME.to_owned(),
            token_name: DEFAULT_TOKEN_NAME.to_owned(),
            projects: Vec::new(),
            subscriber_queue_capacity: DEFAULT_SUBSCRIBER_QUEUE_CAPACITY,
            event_history_capacity: DEFAULT_EVENT_HISTORY_CAPACITY,
        }
    }
}

impl DaemonConfig {
    pub fn new(projects: Vec<ProjectConfig>) -> Self {
        Self {
            projects,
            ..Self::default()
        }
    }

    pub fn with_bind_addr(mut self, bind_addr: SocketAddr) -> Self {
        self.bind_addr = bind_addr;
        self
    }

    pub fn with_runtime_dir(mut self, runtime_dir: impl Into<PathBuf>) -> Self {
        self.runtime_dir = Some(runtime_dir.into());
        self
    }

    pub fn with_queue_limits(
        mut self,
        subscriber_queue_bytes: usize,
        event_history_bytes: usize,
    ) -> Self {
        self.subscriber_queue_capacity = subscriber_queue_bytes;
        self.event_history_capacity = event_history_bytes;
        self
    }

    pub fn validate(&self) -> Result<()> {
        if !self.bind_addr.ip().is_loopback() {
            return Err(DaemonError::InvalidConfiguration(
                "the daemon must bind to a loopback address".to_owned(),
            ));
        }
        if self.descriptor_name.is_empty()
            || self.token_name.is_empty()
            || self.descriptor_name == self.token_name
            || self.descriptor_name == DEFAULT_INSTANCE_LOCK_NAME
            || self.token_name == DEFAULT_INSTANCE_LOCK_NAME
        {
            return Err(DaemonError::InvalidConfiguration(
                "discovery files must have distinct non-empty names".to_owned(),
            ));
        }
        if Path::new(&self.descriptor_name).components().count() != 1
            || Path::new(&self.token_name).components().count() != 1
        {
            return Err(DaemonError::InvalidConfiguration(
                "discovery file names must be single file names".to_owned(),
            ));
        }
        if self.subscriber_queue_capacity == 0
            || self.subscriber_queue_capacity > MAX_CLIENT_QUEUE_BYTES
            || self.event_history_capacity == 0
        {
            return Err(DaemonError::InvalidConfiguration(
                "event queue byte limits are invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryDescriptor {
    pub address: SocketAddr,
    pub pid: u32,
    pub protocol_version: String,
    pub daemon_version: String,
    pub token_file: PathBuf,
    pub started_at: String,
}

#[derive(Clone)]
pub struct DaemonDiscovery {
    pub descriptor: DiscoveryDescriptor,
    pub token: String,
}

impl DaemonDiscovery {
    pub fn load(runtime_dir: impl AsRef<Path>) -> Result<Self> {
        Self::load_named(runtime_dir.as_ref(), DEFAULT_DESCRIPTOR_NAME)
    }

    pub fn load_named(runtime_dir: &Path, descriptor_name: &str) -> Result<Self> {
        if Path::new(descriptor_name).components().count() != 1 {
            return Err(DaemonError::Discovery(
                "descriptor name is not a file name".to_owned(),
            ));
        }
        let runtime = SecureRuntime::open(runtime_dir).map_err(DaemonError::from)?;
        let descriptor_bytes = runtime
            .read_private_bounded(descriptor_name, MAX_DESCRIPTOR_BYTES)
            .map_err(DaemonError::from)?
            .ok_or_else(|| DaemonError::Discovery("descriptor file is missing".to_owned()))?;
        let descriptor: DiscoveryDescriptor = serde_json::from_slice(&descriptor_bytes)?;
        if descriptor.protocol_version != PROTOCOL_VERSION
            || descriptor.daemon_version != DAEMON_VERSION
            || !descriptor.address.ip().is_loopback()
        {
            return Err(DaemonError::Discovery(
                "unsupported daemon descriptor".to_owned(),
            ));
        }
        let token_path = descriptor.token_file.clone();
        if token_path.parent() != Some(runtime.path()) {
            return Err(DaemonError::Discovery(
                "token file is outside the runtime directory".to_owned(),
            ));
        }
        let token_name = token_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| DaemonError::Discovery("token file has no valid name".to_owned()))?;
        let token = String::from_utf8(
            runtime
                .read_private_bounded(token_name, MAX_TOKEN_BYTES)
                .map_err(DaemonError::from)?
                .ok_or_else(|| DaemonError::Discovery("token file is missing".to_owned()))?,
        )
        .map_err(|_| DaemonError::Discovery("token file is not UTF-8".to_owned()))?
        .trim_end()
        .to_owned();
        if token.is_empty() {
            return Err(DaemonError::Discovery("token file is empty".to_owned()));
        }
        Ok(Self { descriptor, token })
    }
}

pub fn platform_runtime_dir() -> Result<PathBuf> {
    #[cfg(unix)]
    if let Some(path) = std::env::var_os("XDG_RUNTIME_DIR") {
        let path = PathBuf::from(path);
        if path.is_dir() {
            return Ok(path);
        }
    }
    #[cfg(windows)]
    if let Some(path) = std::env::var_os("LOCALAPPDATA") {
        let path = PathBuf::from(path);
        if path.is_dir() {
            return Ok(path);
        }
    }
    Ok(std::env::temp_dir())
}

#[derive(Debug, Clone, Serialize)]
pub struct MetaResponse {
    pub protocol_version: &'static str,
    pub daemon_version: &'static str,
    pub api_base: &'static str,
    pub address: Option<SocketAddr>,
    pub project_count: usize,
    pub capabilities: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectHealth {
    pub project_id: ProjectId,
    pub status: &'static str,
    pub journal_watermark: u64,
    pub index_watermark: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub projects: Vec<ProjectHealth>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectSnapshot {
    pub project_id: ProjectId,
    pub writer_state: &'static str,
    pub journal_watermark: u64,
    pub index_watermark: u64,
    pub projection_digest: String,
    pub counts: BTreeMap<String, u64>,
    pub metadata: BTreeMap<String, String>,
}

/// Read-only project access exposed outside the daemon's private writer path.
pub struct ProjectReadFacade {
    store: ProjectStoreReader,
}

impl ProjectReadFacade {
    pub fn open_existing(
        project_root: impl AsRef<Path>,
        project_id: ProjectId,
    ) -> std::result::Result<Self, ReaderStoreError> {
        Ok(Self {
            store: ProjectStoreReader::open_existing(project_root, project_id)?,
        })
    }

    pub fn project_id(&self) -> ProjectId {
        self.store.project_id()
    }

    pub fn history_page(
        &self,
        after_sequence: u64,
        limit: usize,
    ) -> std::result::Result<gorce_store::HistoryPage, ReaderStoreError> {
        self.store.history_page(after_sequence, limit)
    }

    pub fn semantic_snapshot(
        &self,
    ) -> std::result::Result<gorce_store::SemanticSnapshot, ReaderStoreError> {
        self.store.index().semantic_snapshot()
    }

    pub fn metadata(&self) -> std::result::Result<BTreeMap<String, String>, ReaderStoreError> {
        self.store.index().metadata()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EventPage {
    pub project_id: ProjectId,
    pub cursor: PublicEventCursor,
    pub events: Vec<PublicEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<PublicEventCursor>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResyncRequired {
    pub project_id: ProjectId,
    pub requested_cursor: PublicEventCursor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_cursor: Option<PublicEventCursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_cursor: Option<PublicEventCursor>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicStreamEvent {
    pub cursor: PublicEventCursor,
    pub event: PublicEvent,
}

#[derive(Debug, Clone)]
pub enum SubscriptionMessage {
    Event(PublicStreamEvent),
    Gap(ResyncRequired),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalCursor {
    batch: u64,
    ordinal: u64,
}

fn encode_cursor(cursor: CanonicalCursor) -> PublicEventCursor {
    PublicEventCursor(format!(
        "{CURSOR_PREFIX}-{}-{}",
        cursor.batch, cursor.ordinal
    ))
}

fn parse_canonical_cursor(value: &str) -> std::result::Result<CanonicalCursor, &'static str> {
    if value == encode_cursor(ORIGIN_CURSOR).0 {
        return Ok(ORIGIN_CURSOR);
    }
    let mut parts = value.split('-');
    if parts.next() != Some(CURSOR_PREFIX) {
        return Err("cursor has an unsupported format");
    }
    let batch = parts
        .next()
        .ok_or("cursor is missing its batch location")?
        .parse::<u64>()
        .map_err(|_| "cursor has an invalid batch location")?;
    let ordinal = parts
        .next()
        .ok_or("cursor is missing its event location")?
        .parse::<u64>()
        .map_err(|_| "cursor has an invalid event location")?;
    if parts.next().is_some() || batch == 0 {
        return Err("cursor has an invalid canonical location");
    }
    Ok(CanonicalCursor { batch, ordinal })
}

#[derive(Clone)]
struct PublicEventEnvelope {
    cursor: CanonicalCursor,
    public_cursor: PublicEventCursor,
    event: Arc<PublicEvent>,
    encoded: Arc<str>,
    bytes: usize,
}

enum QueueItem {
    Event(Arc<PublicEventEnvelope>),
    Gap(ResyncRequired),
}

struct QueueState {
    items: VecDeque<QueueItem>,
    bytes: usize,
    gap_pending: bool,
    closed: bool,
}

struct SubscriberQueue {
    project_id: ProjectId,
    capacity_bytes: usize,
    state: Mutex<QueueState>,
    notify: Arc<Notify>,
}

impl SubscriberQueue {
    fn new(project_id: ProjectId, capacity_bytes: usize) -> Self {
        Self {
            project_id,
            capacity_bytes: capacity_bytes.clamp(1, MAX_CLIENT_QUEUE_BYTES),
            state: Mutex::new(QueueState {
                items: VecDeque::new(),
                bytes: 0,
                gap_pending: false,
                closed: false,
            }),
            notify: Arc::new(Notify::new()),
        }
    }

    fn push(&self, item: QueueItem) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.closed || state.gap_pending {
            return;
        }
        let item_bytes = match &item {
            QueueItem::Event(event) => event.bytes,
            QueueItem::Gap(_) => RESYNC_MARKER_BYTES,
        };
        if item_bytes > self.capacity_bytes
            || state.bytes.saturating_add(item_bytes) > self.capacity_bytes
        {
            let requested_cursor = state.items.back().map_or_else(
                || encode_cursor(ORIGIN_CURSOR),
                |queued| match queued {
                    QueueItem::Event(event) => event.public_cursor.clone(),
                    QueueItem::Gap(gap) => gap.requested_cursor.clone(),
                },
            );
            let latest_cursor = match &item {
                QueueItem::Event(event) => Some(event.public_cursor.clone()),
                QueueItem::Gap(gap) => gap.latest_cursor.clone(),
            };
            state.items.clear();
            state.bytes = RESYNC_MARKER_BYTES;
            state.gap_pending = true;
            state.items.push_back(QueueItem::Gap(ResyncRequired {
                project_id: self.project_id,
                requested_cursor,
                oldest_cursor: latest_cursor.clone(),
                latest_cursor,
            }));
        } else {
            state.bytes = state.bytes.saturating_add(item_bytes);
            state.items.push_back(item);
        }
        drop(state);
        self.notify.notify_one();
    }

    async fn receive_envelope(&self) -> Option<QueueItem> {
        loop {
            let notified = self.notify.clone().notified_owned();
            let item = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(item) = state.items.pop_front() {
                    let bytes = state.items.iter().fold(0usize, |bytes, queued| {
                        bytes.saturating_add(match queued {
                            QueueItem::Event(event) => event.bytes,
                            QueueItem::Gap(_) => RESYNC_MARKER_BYTES,
                        })
                    });
                    state.bytes = bytes;
                    if matches!(&item, QueueItem::Gap(_)) {
                        state.gap_pending = false;
                    }
                    Some(item)
                } else if state.closed {
                    return None;
                } else {
                    None
                }
            };
            if let Some(item) = item {
                return Some(item);
            }
            notified.await;
        }
    }

    fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.closed = true;
        drop(state);
        self.notify.notify_waiters();
    }
}

struct HubState {
    next_subscriber: u64,
    retained: VecDeque<Arc<PublicEventEnvelope>>,
    retained_bytes: usize,
    subscribers: HashMap<u64, Arc<SubscriberQueue>>,
    history_bytes: usize,
}

struct EventBroadcasterInner {
    state: Mutex<HubState>,
    queue_bytes: usize,
}

#[derive(Clone)]
pub struct EventBroadcaster {
    inner: Arc<EventBroadcasterInner>,
}

impl EventBroadcaster {
    pub fn new(queue_bytes: usize, history_bytes: usize) -> Self {
        Self {
            inner: Arc::new(EventBroadcasterInner {
                state: Mutex::new(HubState {
                    next_subscriber: 1,
                    retained: VecDeque::new(),
                    retained_bytes: 0,
                    subscribers: HashMap::new(),
                    history_bytes: history_bytes.clamp(1, MAX_CLIENT_QUEUE_BYTES),
                }),
                queue_bytes: queue_bytes.clamp(1, MAX_CLIENT_QUEUE_BYTES),
            }),
        }
    }

    fn publish(&self, event: Arc<PublicEventEnvelope>) {
        let subscribers = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.retained_bytes = state.retained_bytes.saturating_add(event.bytes);
            state.retained.push_back(event.clone());
            while state.retained_bytes > state.history_bytes {
                if let Some(old) = state.retained.pop_front() {
                    state.retained_bytes = state.retained_bytes.saturating_sub(old.bytes);
                } else {
                    break;
                }
            }
            state.subscribers.values().cloned().collect::<Vec<_>>()
        };
        for subscriber in subscribers {
            if subscriber.project_id == event.event.project_id {
                subscriber.push(QueueItem::Event(event.clone()));
            }
        }
    }

    fn subscribe(&self, project_id: ProjectId, _after: CanonicalCursor) -> EventSubscription {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let queue = Arc::new(SubscriberQueue::new(project_id, self.inner.queue_bytes));
        let id = state.next_subscriber;
        state.next_subscriber = state.next_subscriber.saturating_add(1);
        state.subscribers.insert(id, queue.clone());
        EventSubscription {
            id,
            queue,
            inner: Arc::downgrade(&self.inner),
        }
    }

    pub fn subscribe_cursor(
        &self,
        project_id: ProjectId,
        cursor: PublicEventCursor,
    ) -> Result<EventSubscription> {
        let cursor = parse_canonical_cursor(&cursor.0)
            .map_err(|message| DaemonError::InvalidConfiguration(message.to_owned()))?;
        Ok(self.subscribe(project_id, cursor))
    }

    pub fn subscriber_count(&self) -> usize {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .subscribers
            .len()
    }

    pub fn close(&self) {
        let subscribers = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .subscribers
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for subscriber in subscribers {
            subscriber.close();
        }
    }
}

pub struct EventSubscription {
    id: u64,
    queue: Arc<SubscriberQueue>,
    inner: Weak<EventBroadcasterInner>,
}

impl EventSubscription {
    async fn receive_envelope(&self) -> Option<QueueItem> {
        self.queue.receive_envelope().await
    }

    pub async fn recv(&self) -> Option<SubscriptionMessage> {
        match self.receive_envelope().await? {
            QueueItem::Event(event) => Some(SubscriptionMessage::Event(PublicStreamEvent {
                cursor: event.public_cursor.clone(),
                event: (*event.event).clone(),
            })),
            QueueItem::Gap(gap) => Some(SubscriptionMessage::Gap(gap)),
        }
    }
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            let mut state = inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.subscribers.remove(&self.id);
        }
    }
}

struct ProjectHandle {
    id: ProjectId,
    store: Arc<ProjectStoreWriter>,
    writer_lock: AsyncMutex<()>,
}

impl ProjectHandle {
    async fn snapshot(&self) -> Result<ProjectSnapshot> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let (journal_watermark, index_watermark) =
                store.index().watermarks().map_err(writer_error)?;
            let semantic = store.index().semantic_snapshot().map_err(writer_error)?;
            let metadata = store.index().metadata().map_err(writer_error)?;
            let writer_state = store.writer_state().map_err(writer_error)?;
            Ok(ProjectSnapshot {
                project_id: store.project_id(),
                writer_state: writer_state_name(writer_state),
                journal_watermark,
                index_watermark,
                projection_digest: semantic.digest,
                counts: semantic.counts,
                metadata,
            })
        })
        .await
        .map_err(DaemonError::from)?
    }

    async fn health(&self) -> Result<ProjectHealth> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let (journal_watermark, index_watermark) =
                store.index().watermarks().map_err(writer_error)?;
            Ok(ProjectHealth {
                project_id: store.project_id(),
                status: writer_state_name(store.writer_state().map_err(writer_error)?),
                journal_watermark,
                index_watermark,
            })
        })
        .await
        .map_err(DaemonError::from)?
    }

    async fn history(
        &self,
        after_sequence: u64,
        limit: usize,
    ) -> Result<gorce_store_writer::HistoryPage> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || store.history_page(after_sequence, limit))
            .await
            .map_err(DaemonError::from)?
            .map_err(writer_error)
    }

    async fn cursor_known(&self, cursor: CanonicalCursor) -> Result<bool> {
        if cursor == ORIGIN_CURSOR {
            return Ok(true);
        }
        let mut after_batch = cursor.batch.saturating_sub(1);
        loop {
            let page = self.history(after_batch, 500).await?;
            for entry in &page.entries {
                if entry.batch.batch_sequence == cursor.batch
                    && entry
                        .batch
                        .events
                        .iter()
                        .any(|event| event.ordinal == cursor.ordinal)
                {
                    return Ok(true);
                }
            }
            let Some(last) = page.entries.last() else {
                return Ok(false);
            };
            if last.batch.batch_sequence >= cursor.batch || !page.has_more {
                return Ok(false);
            }
            after_batch = last.batch.batch_sequence;
        }
    }
}

struct ProjectRegistry {
    projects: std::sync::RwLock<HashMap<ProjectId, Arc<ProjectHandle>>>,
}

impl ProjectRegistry {
    fn open(configs: &[ProjectConfig]) -> Result<Self> {
        let mut projects = HashMap::new();
        let mut roots = HashSet::new();
        for config in configs {
            if projects.contains_key(&config.id) {
                return Err(DaemonError::ProjectAlreadyConfigured(config.id));
            }
            let store = ProjectStoreWriter::open(&config.root, config.id).map_err(writer_error)?;
            let root = store.project_root().to_owned();
            if !roots.insert(root.clone()) {
                return Err(DaemonError::DuplicateProjectRoot(root));
            }
            projects.insert(
                config.id,
                Arc::new(ProjectHandle {
                    id: config.id,
                    store: Arc::new(store),
                    writer_lock: AsyncMutex::new(()),
                }),
            );
        }
        Ok(Self {
            projects: std::sync::RwLock::new(projects),
        })
    }

    fn project(&self, project_id: ProjectId) -> Option<Arc<ProjectHandle>> {
        self.projects.read().ok()?.get(&project_id).cloned()
    }

    fn project_ids(&self) -> Vec<ProjectId> {
        self.projects
            .read()
            .map(|projects| projects.keys().copied().collect())
            .unwrap_or_default()
    }

    fn len(&self) -> usize {
        self.projects
            .read()
            .map(|projects| projects.len())
            .unwrap_or(0)
    }
}

struct DaemonState {
    registry: Arc<ProjectRegistry>,
    broadcaster: EventBroadcaster,
    token: String,
    local_principal_id: PrincipalId,
    bound_address: OnceCell<SocketAddr>,
}

#[derive(Clone)]
struct ProjectCommandService {
    state: Arc<DaemonState>,
}

struct CommittedCommand {
    result: CommandCommit,
    public_events: Vec<Arc<PublicEventEnvelope>>,
}

impl ProjectCommandService {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    async fn submit(
        &self,
        project_id: ProjectId,
        request: AuthorityCommandRequest,
        idempotency_key: String,
    ) -> Result<CommandCommit> {
        request
            .validate()
            .map_err(|error| CommandFailure::InvalidCommand(error.to_string()).into_error())?;
        if idempotency_key.is_empty() {
            return Err(CommandFailure::MissingIdempotencyKey(
                "Idempotency-Key must contain at least one byte".to_owned(),
            )
            .into_error());
        }
        if idempotency_key.len() > gorce_protocol::MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(CommandFailure::InvalidArguments(
                "Idempotency-Key must not exceed 256 bytes".to_owned(),
            )
            .into_error());
        }
        let project = self
            .state
            .registry
            .project(project_id)
            .ok_or(DaemonError::ProjectNotFound(project_id))?;
        let _guard = project.writer_lock.lock().await;
        let store = project.store.clone();
        let principal_id = self.state.local_principal_id;
        let committed = tokio::task::spawn_blocking(move || {
            execute_authority_command(&store, project_id, principal_id, request, idempotency_key)
        })
        .await
        .map_err(DaemonError::from)??;

        // Publication is deliberately best effort. The command result has already been
        // durably appended and projected, so a missing subscriber must not change it.
        for event in committed.public_events {
            self.state.broadcaster.publish(event);
        }
        Ok(committed.result)
    }
}

fn authority_event(ordinal: usize, event_type: &str, value: Value) -> EventRecord {
    EventRecord {
        ordinal: ordinal as u64,
        event_type: event_type.to_owned(),
        schema_version: gorce_protocol::AUTHORITY_EVENT_SCHEMA_VERSION,
        data: value,
    }
}

fn default_policy(
    project_id: ProjectId,
    policy_id: gorce_protocol::PolicyId,
    created_at: &str,
) -> Result<AuthorityPolicy> {
    let mut policy = AuthorityPolicy {
        id: policy_id,
        project_id,
        revision: 1,
        rules: vec![AuthorityPolicyRule {
            action: "authority.*".to_owned(),
            resource: project_id.to_string(),
            effect: AuthorityPolicyEffect::Allow,
        }],
        digest: String::new(),
        created_at: created_at.to_owned(),
    };
    policy.digest = policy
        .content_digest()
        .map_err(|error| DaemonError::command(error.to_string()))?;
    Ok(policy)
}

fn default_profile(
    project_id: ProjectId,
    profile_id: ProfileRevisionId,
    policy_id: gorce_protocol::PolicyId,
    created_at: &str,
) -> Result<AuthorityProfileRevision> {
    let mut profile = AuthorityProfileRevision {
        id: profile_id,
        project_id,
        revision: 1,
        name: "phase1-disabled".to_owned(),
        policy_id,
        spec: PinnedProfileSpec {
            execution_disposition: AuthorityExecutionDisposition::Disabled,
            model_component: "phase1-disabled-model".to_owned(),
            tool_component: "phase1-disabled-tool".to_owned(),
            skills: vec![PinnedSkillReference {
                name: "phase1-disabled".to_owned(),
                version: "1.0.0".to_owned(),
            }],
        },
        grant: AuthorityGrant {
            actions: Vec::new(),
            scopes: Vec::new(),
            max_depth: 0,
            max_concurrency: 0,
            budget: AuthorityBudget {
                model_tokens: 0,
                tool_calls: 0,
                wall_time_ms: 0,
            },
        },
        digest: String::new(),
        created_at: created_at.to_owned(),
    };
    profile.digest = profile
        .content_digest()
        .map_err(|error| DaemonError::command(error.to_string()))?;
    Ok(profile)
}

fn bootstrap_authority(
    store: &ProjectStoreWriter,
    project_id: ProjectId,
    principal_id: PrincipalId,
) -> Result<()> {
    let timestamp = timestamp_now();
    let policy = default_policy(project_id, Uuid::now_v7(), &timestamp)?;
    let profile = default_profile(project_id, Uuid::now_v7(), policy.id, &timestamp)?;
    let batch_id = UuidV7::from_uuid(Uuid::now_v7()).ok_or_else(|| {
        DaemonError::command("could not create a version-seven bootstrap batch id".to_owned())
    })?;
    let principal = AuthorityPrincipal {
        id: principal_id,
        project_id,
        kind: AuthorityPrincipalKind::LocalControl,
        subject: "local-control".to_owned(),
        created_at: timestamp.clone(),
    };
    let events = vec![
        authority_event(
            0,
            gorce_protocol::AUTHORITY_BOOTSTRAP_EVENT,
            serde_json::to_value(AuthorityBootstrap {
                principal_id,
                policy_id: policy.id,
                profile_revision_id: profile.id,
            })?,
        ),
        authority_event(
            1,
            gorce_protocol::AUTHORITY_PRINCIPAL_CREATED_EVENT,
            serde_json::to_value(principal)?,
        ),
        authority_event(
            2,
            gorce_protocol::AUTHORITY_POLICY_CREATED_EVENT,
            serde_json::to_value(policy)?,
        ),
        authority_event(
            3,
            gorce_protocol::AUTHORITY_PROFILE_REGISTERED_EVENT,
            serde_json::to_value(profile)?,
        ),
    ];
    let batch = EventBatch {
        format: gorce_protocol::EVENT_BATCH_FORMAT.to_owned(),
        project_id,
        batch_id,
        batch_sequence: store.next_batch_sequence().map_err(writer_error)?,
        committed_at: timestamp,
        actor: EventActor {
            kind: EventActorKind::System,
            operator_id: None,
        },
        command: EventCommand {
            name: "authority.bootstrap".to_owned(),
            arguments: json!({"principal_id": principal_id}),
            idempotency_key: format!("authority:bootstrap:{principal_id}"),
        },
        base_revisions: BTreeMap::new(),
        events,
        referenced_blobs: Vec::new(),
    };
    let append = store.append_next(batch).map_err(writer_error)?;
    if append.location.batch_sequence() == 0 {
        return Err(DaemonError::Discovery(
            "authority bootstrap did not receive a durable sequence".to_owned(),
        ));
    }
    Ok(())
}

fn execute_authority_command(
    store: &ProjectStoreWriter,
    project_id: ProjectId,
    principal_id: PrincipalId,
    request: AuthorityCommandRequest,
    idempotency_key: String,
) -> Result<CommittedCommand> {
    let command_arguments = serde_json::to_value(&request.command)?;
    let event_command = EventCommand {
        name: "authority.command".to_owned(),
        arguments: command_arguments,
        idempotency_key: idempotency_key.clone(),
    };
    let digest = event_command
        .command_digest()
        .map_err(|error| DaemonError::command(error.to_string()))?;
    if let Some(existing) = store
        .index()
        .authority_command(principal_id, &idempotency_key)
        .map_err(writer_error)?
    {
        if existing.command_digest == digest {
            return Ok(CommittedCommand {
                result: existing.result,
                public_events: Vec::new(),
            });
        }
        return Err(DaemonError::idempotency_conflict(
            "idempotency key conflicts with the original command body".to_owned(),
        ));
    }

    let timestamp = timestamp_now();
    let principal = store
        .index()
        .authority_principal()
        .map_err(writer_error)?
        .ok_or_else(|| {
            DaemonError::Discovery("project authority principal is missing".to_owned())
        })?;
    if principal.id != principal_id
        || principal.project_id != project_id
        || principal.kind != AuthorityPrincipalKind::LocalControl
        || principal.subject != "local-control"
    {
        return Err(DaemonError::Discovery(
            "project authority identity mismatch".to_owned(),
        ));
    }
    principal
        .validate()
        .map_err(|error| DaemonError::command(error.to_string()))?;

    let _policy = store
        .index()
        .authority_latest_policy()
        .map_err(writer_error)?
        .ok_or_else(|| DaemonError::Discovery("project authority policy is missing".to_owned()))?;
    let profile = store
        .index()
        .authority_latest_profile_revision()
        .map_err(writer_error)?
        .ok_or_else(|| DaemonError::Discovery("project authority profile is missing".to_owned()))?;
    let mut events = Vec::new();
    profile
        .validate()
        .map_err(|error| DaemonError::command(error.to_string()))?;

    let (result_kind, resource) = match &request.command {
        AuthorityCommandKind::ProfileRegister {
            arguments: EmptyCommandArguments {},
        } => (
            CommandResultKind::Accepted,
            (ResourceKind::ProfileRevision, profile.id),
        ),
        AuthorityCommandKind::OperatorBind {
            arguments: OperatorBindingArguments { operator_id },
        } => {
            if let Some(existing) = store
                .index()
                .authority_binding_for_operator(*operator_id)
                .map_err(writer_error)?
            {
                if existing.principal_id != principal_id {
                    return Err(DaemonError::command(
                        "operator is bound to a different authority principal".to_owned(),
                    ));
                }
                return Err(DaemonError::command("operator is already bound".to_owned()));
            }
            let binding = OperatorBinding {
                id: Uuid::now_v7(),
                project_id,
                principal_id,
                operator_id: *operator_id,
                profile_revision_id: profile.id,
                policy_id: profile.policy_id,
                created_at: timestamp.clone(),
            };
            binding
                .validate()
                .map_err(|error| DaemonError::command(error.to_string()))?;
            events.push((
                gorce_protocol::AUTHORITY_OPERATOR_BOUND_EVENT,
                serde_json::to_value(&binding)?,
            ));
            (
                CommandResultKind::Created,
                (ResourceKind::OperatorBinding, binding.id),
            )
        }
        AuthorityCommandKind::AdmissionCreate {
            arguments:
                AdmissionCreateArguments {
                    operator_id,
                    run_id,
                },
        } => {
            let binding = store
                .index()
                .authority_binding_for_operator(*operator_id)
                .map_err(writer_error)?
                .ok_or_else(|| {
                    DaemonError::command("operator has no authority binding".to_owned())
                })?;
            if binding.principal_id != principal_id {
                return Err(DaemonError::command(
                    "operator binding belongs to a different authority principal".to_owned(),
                ));
            }
            let bound_profile = store
                .index()
                .authority_profile_revision(binding.profile_revision_id)
                .map_err(writer_error)?
                .ok_or_else(|| {
                    DaemonError::command("bound profile revision is missing".to_owned())
                })?;
            let policy = store
                .index()
                .authority_policy(binding.policy_id)
                .map_err(writer_error)?
                .ok_or_else(|| DaemonError::command("bound policy is missing".to_owned()))?;
            bound_profile
                .validate()
                .map_err(|error| DaemonError::command(error.to_string()))?;
            policy
                .validate()
                .map_err(|error| DaemonError::command(error.to_string()))?;
            if bound_profile.policy_id != binding.policy_id
                || bound_profile.project_id != project_id
                || policy.project_id != project_id
            {
                return Err(DaemonError::Discovery(
                    "authority binding profile or policy identity mismatch".to_owned(),
                ));
            }
            if let Some(existing) = store
                .index()
                .authority_admission_for_run(*run_id)
                .map_err(writer_error)?
            {
                return Err(DaemonError::command(format!(
                    "run is already admitted as {}",
                    existing.id
                )));
            }
            let admission = Admission {
                id: Uuid::now_v7(),
                project_id,
                principal_id,
                operator_id: *operator_id,
                run_id: *run_id,
                binding_id: binding.id,
                profile_revision_id: bound_profile.id,
                policy_id: policy.id,
                grant: bound_profile.grant.clone(),
                spec_digest: bound_profile
                    .spec
                    .digest()
                    .map_err(|error| DaemonError::command(error.to_string()))?,
                execution_disposition: AuthorityExecutionDisposition::Disabled,
                actor: EventActor {
                    kind: EventActorKind::Service,
                    operator_id: Some(*operator_id),
                },
                created_at: timestamp.clone(),
            };
            admission
                .validate()
                .map_err(|error| DaemonError::command(error.to_string()))?;
            events.push((
                gorce_protocol::AUTHORITY_ADMISSION_CREATED_EVENT,
                serde_json::to_value(&admission)?,
            ));
            (
                CommandResultKind::Created,
                (ResourceKind::Admission, admission.id),
            )
        }
    };

    let batch_id = UuidV7::from_uuid(Uuid::now_v7()).ok_or_else(|| {
        DaemonError::command("could not create a version-seven batch id".to_owned())
    })?;
    let batch_sequence = store.next_batch_sequence().map_err(writer_error)?;
    let result = CommandCommit {
        project_id,
        batch_id,
        batch_sequence,
        public_cursors: Vec::new(),
        result: CommandResult {
            kind: result_kind,
            resource_refs: vec![ResourceReference {
                kind: resource.0,
                id: resource.1,
            }],
        },
        evidence_refs: Vec::new(),
    };
    let receipt = AuthorityCommandReceipt {
        principal_id,
        idempotency_key: idempotency_key.clone(),
        command_digest: digest,
        result: result.clone(),
    };
    let mut records = vec![(
        gorce_protocol::AUTHORITY_COMMAND_RECORDED_EVENT,
        serde_json::to_value(receipt)?,
    )];
    records.extend(events);
    let events = records
        .into_iter()
        .enumerate()
        .map(|(ordinal, (kind, value))| authority_event(ordinal, kind, value))
        .collect();
    let batch = EventBatch {
        format: gorce_protocol::EVENT_BATCH_FORMAT.to_owned(),
        project_id,
        batch_id,
        batch_sequence,
        committed_at: timestamp,
        actor: EventActor {
            kind: EventActorKind::Service,
            operator_id: None,
        },
        command: event_command,
        base_revisions: BTreeMap::new(),
        events,
        referenced_blobs: Vec::new(),
    };
    let public_events = public_envelopes(&batch)?
        .into_iter()
        .map(Arc::new)
        .collect::<Vec<_>>();
    let append = store.append_next(batch).map_err(writer_error)?;
    if append.location.batch_sequence() != batch_sequence {
        return Err(DaemonError::command(
            "authority sequence changed while committing".to_owned(),
        ));
    }
    Ok(CommittedCommand {
        result,
        public_events: if append.duplicate {
            Vec::new()
        } else {
            public_events
        },
    })
}

pub struct Daemon {
    config: DaemonConfig,
    runtime: SecureRuntime,
    instance_lock: Option<LockGuard>,
    state: Arc<DaemonState>,
}

impl Daemon {
    pub fn new(config: DaemonConfig) -> Result<Self> {
        config.validate()?;
        let runtime_dir = match &config.runtime_dir {
            Some(path) => path.clone(),
            None => platform_runtime_dir()?.join("gorce"),
        };
        let runtime = SecureRuntime::open(&runtime_dir).map_err(DaemonError::from)?;
        let instance_lock = runtime
            .lock(DEFAULT_INSTANCE_LOCK_NAME)
            .map_err(DaemonError::from)?;
        let local_principal_id = load_or_create_daemon_identity(&runtime, &config.projects)?;
        let registry = Arc::new(ProjectRegistry::open(&config.projects)?);
        for project_id in registry.project_ids() {
            let project = registry
                .project(project_id)
                .ok_or(DaemonError::ProjectNotFound(project_id))?;
            match project
                .store
                .index()
                .authority_state(local_principal_id)
                .map_err(writer_error)?
            {
                gorce_store_writer::AuthorityState::Empty => {
                    bootstrap_authority(&project.store, project_id, local_principal_id)?;
                }
                gorce_store_writer::AuthorityState::Ready => {}
                gorce_store_writer::AuthorityState::Invalid => {
                    return Err(DaemonError::Discovery(
                        "project authority state is partial or inconsistent".to_owned(),
                    ));
                }
            }
        }
        Ok(Self {
            config: config.clone(),
            runtime,
            instance_lock: Some(instance_lock),
            state: Arc::new(DaemonState {
                registry,
                broadcaster: EventBroadcaster::new(
                    config.subscriber_queue_capacity,
                    config.event_history_capacity,
                ),
                token: Uuid::new_v4().hyphenated().to_string(),
                local_principal_id,
                bound_address: OnceCell::new(),
            }),
        })
    }

    pub fn read_facade(&self, project_id: ProjectId) -> Result<Option<ProjectReadFacade>> {
        let Some(project) = self.state.registry.project(project_id) else {
            return Ok(None);
        };
        let root = project.store.project_root().to_owned();
        ProjectReadFacade::open_existing(root, project_id)
            .map(Some)
            .map_err(DaemonError::from)
    }

    pub fn broadcaster(&self) -> EventBroadcaster {
        self.state.broadcaster.clone()
    }

    pub fn router(&self) -> Router {
        app(self.state.clone())
    }

    pub async fn start(self) -> Result<RunningDaemon> {
        let instance_lock = self.instance_lock;
        let runtime = self.runtime;
        let runtime_dir = runtime.path().to_owned();
        let descriptor_name = self.config.descriptor_name.clone();
        let token_name = self.config.token_name.clone();
        let token = self.state.token.clone();
        let descriptor_path = runtime_dir.join(&descriptor_name);
        let token_path = runtime_dir.join(&token_name);
        reconcile_discovery(&runtime, &descriptor_name, &token_name)?;
        let listener = tokio::net::TcpListener::bind(self.config.bind_addr).await?;
        let address = listener.local_addr()?;
        let _ = self.state.bound_address.set(address);
        write_discovery(&runtime, &descriptor_name, &token_name, &token, address)?;
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let cleanup_descriptor_name = descriptor_name.clone();
        let cleanup_token_name = token_name.clone();
        let cleanup_token_value = self.state.token.clone();
        let broadcaster = self.state.broadcaster.clone();
        let router = app(self.state.clone());
        let join = tokio::spawn(async move {
            let runtime = runtime;
            let _instance_lock = instance_lock;
            let serve_result = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_receiver.await;
                    broadcaster.close();
                })
                .await
                .map_err(DaemonError::from);
            let cleanup = cleanup_discovery(
                &runtime,
                &cleanup_descriptor_name,
                &cleanup_token_name,
                &cleanup_token_value,
            );
            serve_result.and(cleanup)
        });
        Ok(RunningDaemon {
            address,
            descriptor_path,
            token_path,
            shutdown_sender: Some(shutdown_sender),
            join: Some(join),
        })
    }
}

pub struct RunningDaemon {
    address: SocketAddr,
    descriptor_path: PathBuf,
    token_path: PathBuf,
    shutdown_sender: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl RunningDaemon {
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn descriptor_path(&self) -> &Path {
        &self.descriptor_path
    }

    pub fn token_path(&self) -> &Path {
        &self.token_path
    }

    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(());
        }
        if let Some(join) = self.join.take() {
            join.await.map_err(DaemonError::from)??;
        }
        Ok(())
    }

    pub async fn wait(mut self) -> Result<()> {
        if let Some(join) = self.join.take() {
            join.await.map_err(DaemonError::from)??;
        }
        Ok(())
    }
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(());
        }
    }
}

fn writer_state_name(state: WriterState) -> &'static str {
    match state {
        WriterState::Healthy => "healthy",
        WriterState::NeedsRecovery => "needs_recovery",
    }
}

const PUBLIC_EVENT_TYPES: &[&str] = &[
    "project.created",
    "project.updated",
    "workstream.created",
    "workstream.updated",
    "workstream.archived",
    "goal.created",
    "goal.revised",
    "plan.created",
    "plan.revised",
    "task.created",
    "task.updated",
    "task.lifecycle_changed",
    "task.edge_created",
    "task.edge_updated",
];

fn is_public_event_type(event_type: &str) -> bool {
    PUBLIC_EVENT_TYPES.contains(&event_type)
}

fn sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "secret",
        "token",
        "password",
        "authorization",
        "credential",
        "private_key",
        "api_key",
        "access_key",
        "tool",
        "output",
        "permission",
        "evidence",
    ]
    .iter()
    .any(|word| key.contains(word))
}

fn redact_public_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut redacted = BTreeMap::new();
            for (key, value) in object {
                if !sensitive_key(key) {
                    redacted.insert(key.clone(), redact_public_value(value));
                }
            }
            Value::Object(redacted.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.iter().map(redact_public_value).collect()),
        value => value.clone(),
    }
}

fn make_public_envelope(
    batch: &EventBatch,
    event: &EventRecord,
) -> Result<Option<PublicEventEnvelope>> {
    if !is_public_event_type(&event.event_type) {
        return Ok(None);
    }
    let payload = if event.data.is_object() {
        redact_public_value(&event.data)
    } else {
        json!({ "data": redact_public_value(&event.data) })
    };
    let public_event = PublicEvent {
        id: Uuid::from_u128(
            batch
                .batch_id
                .into_uuid()
                .as_u128()
                .wrapping_add(event.ordinal as u128),
        ),
        project_id: batch.project_id,
        sequence: batch.batch_sequence,
        event_type: event.event_type.clone(),
        occurred_at: batch.committed_at.clone(),
        payload,
    };
    public_event.validate().map_err(|error| {
        DaemonError::command(format!("public projection rejected an event: {error}"))
    })?;
    let public_cursor = encode_cursor(CanonicalCursor {
        batch: batch.batch_sequence,
        ordinal: event.ordinal,
    });
    let encoded = Arc::<str>::from(serde_json::to_string(&public_event)?);
    Ok(Some(PublicEventEnvelope {
        cursor: CanonicalCursor {
            batch: batch.batch_sequence,
            ordinal: event.ordinal,
        },
        public_cursor,
        event: Arc::new(public_event),
        bytes: encoded.len().saturating_add(64),
        encoded,
    }))
}

fn public_envelopes(batch: &EventBatch) -> Result<Vec<PublicEventEnvelope>> {
    batch
        .events
        .iter()
        .map(|event| make_public_envelope(batch, event))
        .filter_map(|result| match result {
            Ok(Some(envelope)) => Some(Ok(envelope)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

struct PublicReplay {
    events: Vec<Arc<PublicEventEnvelope>>,
    too_large: bool,
}

async fn durable_public_replay(
    project: &ProjectHandle,
    cursor: CanonicalCursor,
    max_events: usize,
    max_bytes: usize,
) -> Result<PublicReplay> {
    let mut after_batch = cursor.batch.saturating_sub(1);
    let mut events = Vec::new();
    let mut bytes = 0usize;
    loop {
        let page = project.history(after_batch, 500).await?;
        let Some(last) = page.entries.last() else {
            break;
        };
        for entry in &page.entries {
            for envelope in public_envelopes(&entry.batch)? {
                if envelope.cursor <= cursor {
                    continue;
                }
                if events.len() >= max_events || bytes.saturating_add(envelope.bytes) > max_bytes {
                    return Ok(PublicReplay {
                        events,
                        too_large: true,
                    });
                }
                bytes = bytes.saturating_add(envelope.bytes);
                events.push(Arc::new(envelope));
            }
        }
        if !page.has_more {
            break;
        }
        after_batch = last.batch.batch_sequence;
    }
    Ok(PublicReplay {
        events,
        too_large: false,
    })
}

async fn durable_public_page(
    project: &ProjectHandle,
    cursor: CanonicalCursor,
    limit: usize,
) -> Result<EventPage> {
    let replay = durable_public_replay(project, cursor, limit, MAX_EVENT_PAGE_BYTES).await?;
    let events = replay
        .events
        .iter()
        .map(|event| (*event.event).clone())
        .collect::<Vec<_>>();
    let next_cursor = replay
        .events
        .last()
        .map(|event| event.public_cursor.clone());
    Ok(EventPage {
        project_id: project.id,
        cursor: encode_cursor(cursor),
        events,
        next_cursor,
        has_more: replay.too_large,
    })
}

fn parse_request_cursor(
    query_cursor: Option<String>,
    last_event_id: Option<&HeaderValue>,
) -> std::result::Result<CanonicalCursor, ApiHttpError> {
    let value = match query_cursor {
        Some(value) => Some(value),
        None => last_event_id
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()
            .map_err(|_| ApiHttpError::bad_request("Last-Event-ID is not valid UTF-8"))?,
    };
    let Some(value) = value else {
        return Ok(ORIGIN_CURSOR);
    };
    parse_canonical_cursor(&value).map_err(ApiHttpError::bad_request)
}

fn parse_project_id(value: &str) -> std::result::Result<ProjectId, ApiHttpError> {
    Uuid::parse_str(value).map_err(|_| ApiHttpError::bad_request("project_id must be a UUID"))
}

fn load_or_create_daemon_identity(
    runtime: &SecureRuntime,
    projects: &[ProjectConfig],
) -> Result<PrincipalId> {
    match runtime
        .read_private_bounded(DEFAULT_IDENTITY_NAME, MAX_IDENTITY_BYTES)
        .map_err(DaemonError::from)?
    {
        Some(_) => read_daemon_identity(runtime),
        None => {
            let existing_project = projects.iter().any(|project| {
                fs::metadata(project.root.join(STATE_DIRECTORY))
                    .map(|metadata| metadata.is_dir())
                    .unwrap_or(false)
            });
            if existing_project {
                return Err(DaemonError::Discovery(
                    "stable daemon identity is missing for an existing project".to_owned(),
                ));
            }
            let principal_id = Uuid::now_v7();
            runtime
                .replace_private(
                    DEFAULT_IDENTITY_NAME,
                    format!("{principal_id}\n").as_bytes(),
                )
                .map_err(DaemonError::from)?;
            read_daemon_identity(runtime)
        }
    }
}

fn read_daemon_identity(runtime: &SecureRuntime) -> Result<PrincipalId> {
    let contents = runtime
        .read_private_bounded(DEFAULT_IDENTITY_NAME, MAX_IDENTITY_BYTES)
        .map_err(DaemonError::from)?
        .ok_or_else(|| DaemonError::Discovery("daemon identity file is missing".to_owned()))?;
    if contents.len() > 128 {
        return Err(DaemonError::Discovery(
            "daemon identity file is too large".to_owned(),
        ));
    }
    let contents = String::from_utf8(contents)
        .map_err(|_| DaemonError::Discovery("daemon identity file is not UTF-8".to_owned()))?;
    Uuid::parse_str(contents.trim())
        .map_err(|_| DaemonError::Discovery("daemon identity file is malformed".to_owned()))
}

fn probe_descriptor_health(descriptor: &DiscoveryDescriptor, token: &str) -> Result<bool> {
    if !descriptor.address.ip().is_loopback() {
        return Err(DaemonError::Discovery(
            "existing descriptor is not loopback-only".to_owned(),
        ));
    }
    let mut stream =
        match TcpStream::connect_timeout(&descriptor.address, Duration::from_millis(250)) {
            Ok(stream) => stream,
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => return Ok(false),
            Err(_) => {
                return Err(DaemonError::Discovery(
                    "existing daemon health probe was inconclusive".to_owned(),
                ))
            }
        };
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    stream.set_write_timeout(Some(Duration::from_millis(250)))?;
    let request = format!(
        "GET /v0/health HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        descriptor.address, token
    );
    stream.write_all(request.as_bytes())?;
    let mut response = [0_u8; 16];
    let read = stream.read(&mut response)?;
    Ok(read > 0)
}

fn reconcile_discovery(
    runtime: &SecureRuntime,
    descriptor_name: &str,
    token_name: &str,
) -> Result<()> {
    let descriptor = runtime
        .read_private_bounded(descriptor_name, MAX_DESCRIPTOR_BYTES)
        .map_err(DaemonError::from)?;
    let token = runtime
        .read_private_bounded(token_name, MAX_TOKEN_BYTES)
        .map_err(DaemonError::from)?;
    let Some(descriptor_bytes) = descriptor else {
        if token.is_some() {
            return Err(DaemonError::Discovery(
                "runtime discovery files are incomplete".to_owned(),
            ));
        }
        return Ok(());
    };
    let Some(token_bytes) = token else {
        return Err(DaemonError::Discovery(
            "runtime discovery files are incomplete".to_owned(),
        ));
    };
    let descriptor: DiscoveryDescriptor = serde_json::from_slice(&descriptor_bytes)?;
    let token = String::from_utf8(token_bytes)
        .map_err(|_| DaemonError::Discovery("runtime token is not UTF-8".to_owned()))?
        .trim_end()
        .to_owned();
    let token_path = runtime.path().join(token_name);
    if descriptor.token_file != token_path {
        return Err(DaemonError::Discovery(
            "runtime descriptor ownership does not match".to_owned(),
        ));
    }
    if descriptor.protocol_version != PROTOCOL_VERSION
        || descriptor.daemon_version != DAEMON_VERSION
    {
        return Err(DaemonError::Discovery(
            "existing daemon descriptor is incompatible".to_owned(),
        ));
    }
    if probe_descriptor_health(&descriptor, &token)? {
        return Err(DaemonError::Discovery(
            "an authenticated daemon is already running".to_owned(),
        ));
    }
    runtime
        .remove_private(descriptor_name)
        .map_err(DaemonError::from)?;
    runtime
        .remove_private(token_name)
        .map_err(DaemonError::from)?;
    Ok(())
}

fn write_discovery(
    runtime: &SecureRuntime,
    descriptor_name: &str,
    token_name: &str,
    token: &str,
    address: SocketAddr,
) -> Result<()> {
    if runtime
        .read_private_bounded(descriptor_name, MAX_DESCRIPTOR_BYTES)
        .map_err(DaemonError::from)?
        .is_some()
        || runtime
            .read_private_bounded(token_name, MAX_TOKEN_BYTES)
            .map_err(DaemonError::from)?
            .is_some()
    {
        return Err(DaemonError::Discovery(
            "runtime discovery files already exist".to_owned(),
        ));
    }
    runtime
        .replace_private(token_name, format!("{token}\n").as_bytes())
        .map_err(DaemonError::from)?;
    let descriptor = DiscoveryDescriptor {
        address,
        pid: std::process::id(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        daemon_version: DAEMON_VERSION.to_owned(),
        token_file: runtime.path().join(token_name),
        started_at: timestamp_now(),
    };
    if let Err(error) = runtime
        .replace_private(descriptor_name, &serde_json::to_vec(&descriptor)?)
        .map_err(DaemonError::from)
    {
        let _ = runtime.remove_private(token_name);
        return Err(error);
    }
    Ok(())
}

fn cleanup_discovery(
    runtime: &SecureRuntime,
    descriptor_name: &str,
    token_name: &str,
    token: &str,
) -> Result<()> {
    let Some(descriptor_bytes) = runtime
        .read_private_bounded(descriptor_name, MAX_DESCRIPTOR_BYTES)
        .map_err(DaemonError::from)?
    else {
        if let Some(token_bytes) = runtime
            .read_private_bounded(token_name, MAX_TOKEN_BYTES)
            .map_err(DaemonError::from)?
        {
            let current = String::from_utf8(token_bytes)
                .map_err(|_| DaemonError::Discovery("runtime token is not UTF-8".to_owned()))?;
            if current.trim_end() == token {
                runtime
                    .remove_private(token_name)
                    .map_err(DaemonError::from)?;
            }
        }
        return Ok(());
    };
    let descriptor: DiscoveryDescriptor = serde_json::from_slice(&descriptor_bytes)?;
    if descriptor.pid != std::process::id()
        || descriptor.token_file != runtime.path().join(token_name)
    {
        return Err(DaemonError::Discovery(
            "runtime discovery ownership changed".to_owned(),
        ));
    }
    if let Some(token_bytes) = runtime
        .read_private_bounded(token_name, MAX_TOKEN_BYTES)
        .map_err(DaemonError::from)?
    {
        let current = String::from_utf8(token_bytes)
            .map_err(|_| DaemonError::Discovery("runtime token is not UTF-8".to_owned()))?;
        if current.trim_end() != token {
            return Err(DaemonError::Discovery(
                "runtime token ownership changed".to_owned(),
            ));
        }
    }
    runtime
        .remove_private(descriptor_name)
        .map_err(DaemonError::from)?;
    runtime
        .remove_private(token_name)
        .map_err(DaemonError::from)?;
    Ok(())
}

fn timestamp_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = seconds / 86_400;
    let day_seconds = seconds % 86_400;
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    let mut year = 1970_u64;
    let mut remaining_days = days;
    loop {
        let leap = year % 400 == 0 || (year % 4 == 0 && year % 100 != 0);
        let year_days = if leap { 366 } else { 365 };
        if remaining_days < year_days {
            break;
        }
        remaining_days -= year_days;
        year += 1;
    }
    let month_days = [31_u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1_u64;
    for (index, normal_days) in month_days.iter().enumerate() {
        let leap_day =
            usize::from(index == 1 && (year % 400 == 0 || (year % 4 == 0 && year % 100 != 0)));
        let length = normal_days + leap_day as u64;
        if remaining_days < length {
            break;
        }
        remaining_days -= length;
        month += 1;
    }
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z",
        day = remaining_days + 1
    )
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    let mut difference = left.len() ^ right.len();
    for (a, b) in left.bytes().zip(right.bytes()) {
        difference |= usize::from(a ^ b);
    }
    difference == 0
}

#[derive(Clone)]
struct RequestId(String);

fn new_request_id() -> String {
    Uuid::new_v4().hyphenated().to_string()
}

fn authorized(headers: &HeaderMap, token: &str) -> bool {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    bearer.is_some_and(|candidate| constant_time_equal(candidate, token))
}

fn api_error_response(
    status: StatusCode,
    code: ErrorCode,
    message: impl Into<String>,
    request_id: Option<String>,
) -> Response {
    (
        status,
        Json(ApiError {
            code,
            message: message.into(),
            request_id,
            details: None,
        }),
    )
        .into_response()
}

#[derive(Debug)]
struct ApiHttpError {
    status: StatusCode,
    error: ApiError,
}

#[derive(Debug)]
struct CommandHttpError {
    status: StatusCode,
    error: CommandError,
}

impl CommandHttpError {
    fn new(status: StatusCode, code: CommandErrorCode, message: impl Into<String>) -> Self {
        Self {
            status,
            error: CommandError {
                code,
                message: message.into(),
                request_id: CURRENT_REQUEST_ID.try_with(|value| value.clone()).ok(),
                details: None,
            },
        }
    }

    fn from_daemon(error: DaemonError) -> Self {
        match error {
            DaemonError::Command { code, message } => {
                Self::new(command_error_status(&code), code, message)
            }
            DaemonError::Storage {
                kind: StorageFailureKind::NeedsRecovery,
                message,
            } => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                CommandErrorCode::CommitUnavailable,
                message,
            ),
            DaemonError::Discovery(message) => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                CommandErrorCode::CommitUnavailable,
                message,
            ),
            _ => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                CommandErrorCode::CommitUnavailable,
                "command commit is unavailable",
            ),
        }
    }
}

fn command_error_status(code: &CommandErrorCode) -> StatusCode {
    match code {
        CommandErrorCode::IdempotencyConflict => StatusCode::CONFLICT,
        CommandErrorCode::CommitUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        CommandErrorCode::InvalidCommand
        | CommandErrorCode::InvalidArguments
        | CommandErrorCode::MissingIdempotencyKey
        | CommandErrorCode::CommandNotSupported
        | CommandErrorCode::CommandRejected => StatusCode::BAD_REQUEST,
    }
}

impl IntoResponse for CommandHttpError {
    fn into_response(self) -> Response {
        (self.status, Json(self.error)).into_response()
    }
}

impl ApiHttpError {
    fn new(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            status,
            error: ApiError {
                code,
                message: message.into(),
                request_id: CURRENT_REQUEST_ID.try_with(|value| value.clone()).ok(),
                details: None,
            },
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, message)
    }

    fn resync(project_id: ProjectId, cursor: PublicEventCursor) -> Self {
        let mut error = Self::new(
            StatusCode::CONFLICT,
            ErrorCode::PreconditionFailed,
            "cursor is unknown or expired; resynchronization is required",
        );
        error.error.details = Some(json!(ResyncRequired {
            project_id,
            requested_cursor: cursor,
            oldest_cursor: None,
            latest_cursor: None,
        }));
        error
    }

    fn service_unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::ServiceNotReady,
            "daemon service is unavailable",
        )
    }

    fn from_daemon(error: DaemonError) -> Self {
        match error {
            DaemonError::ProjectNotFound(_) => Self::new(
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                "project was not found",
            ),
            DaemonError::Storage {
                kind: StorageFailureKind::NeedsRecovery,
                ..
            } => Self::service_unavailable(),
            DaemonError::Storage {
                kind: StorageFailureKind::InvalidArgument,
                ..
            } => Self::bad_request("request is invalid"),
            DaemonError::Storage {
                kind: StorageFailureKind::ProjectMismatch,
                ..
            } => Self::new(
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "request conflicts with the project",
            ),
            DaemonError::Command { message, .. } => Self::bad_request(message),
            DaemonError::Discovery(message) => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::ServiceNotReady,
                message,
            ),
            _ => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::Internal,
                "internal daemon error",
            ),
        }
    }
}

impl IntoResponse for ApiHttpError {
    fn into_response(self) -> Response {
        (self.status, Json(self.error)).into_response()
    }
}

async fn request_context(mut request: Request<Body>, next: Next) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map_or_else(new_request_id, |value| value.to_owned());
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));
    let mut response = CURRENT_REQUEST_ID
        .scope(request_id.clone(), next.run(request))
        .await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

async fn auth_middleware(
    State(state): State<Arc<DaemonState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|id| id.0.clone());
    if !authorized(request.headers(), &state.token) {
        return api_error_response(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Unauthorized,
            "a valid bearer token is required",
            request_id,
        );
    }
    if let Some(version) = request
        .headers()
        .get("x-gorce-protocol-version")
        .and_then(|value| value.to_str().ok())
    {
        if version != PROTOCOL_VERSION {
            return api_error_response(
                StatusCode::BAD_REQUEST,
                ErrorCode::PreconditionFailed,
                "client protocol version is incompatible",
                request_id,
            );
        }
    }
    next.run(request).await
}

async fn not_found() -> ApiHttpError {
    ApiHttpError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::NotFound,
        "route was not found",
    )
}

async fn method_not_allowed() -> ApiHttpError {
    ApiHttpError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        ErrorCode::InvalidRequest,
        "HTTP method is not allowed",
    )
}

fn app(state: Arc<DaemonState>) -> Router {
    Router::new()
        .route("/v0/meta", get(meta).fallback(method_not_allowed))
        .route("/v0/health", get(health).fallback(method_not_allowed))
        .route("/v0/healthz", get(health).fallback(method_not_allowed))
        .route("/healthz", get(health).fallback(method_not_allowed))
        .route("/v0/events", get(event_stream).fallback(method_not_allowed))
        .route(
            "/v0/events/stream",
            get(event_stream).fallback(method_not_allowed),
        )
        .route(
            "/v0/projects/:project_id/snapshot",
            get(snapshot).fallback(method_not_allowed),
        )
        .route(
            "/v0/projects/:project_id/commands",
            post(submit_project_command).fallback(method_not_allowed),
        )
        .route(
            "/v0/projects/:project_id/events",
            get(event_page).fallback(method_not_allowed),
        )
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn(request_context))
        .fallback(not_found)
        .with_state(state)
}

async fn meta(State(state): State<Arc<DaemonState>>) -> Json<MetaResponse> {
    Json(MetaResponse {
        protocol_version: PROTOCOL_VERSION,
        daemon_version: DAEMON_VERSION,
        api_base: "/v0",
        address: state.bound_address.get().copied(),
        project_count: state.registry.len(),
        capabilities: vec![
            "snapshot",
            "event_retrieval",
            "event_stream",
            "authority_commands",
        ],
    })
}

async fn health(
    State(state): State<Arc<DaemonState>>,
) -> std::result::Result<(StatusCode, Json<HealthResponse>), ApiHttpError> {
    let mut projects = Vec::new();
    for project_id in state.registry.project_ids() {
        let project = project_for(&state, project_id)?;
        projects.push(
            project
                .health()
                .await
                .map_err(|_| ApiHttpError::service_unavailable())?,
        );
    }
    let healthy = projects.iter().all(|project| project.status == "healthy");
    let response = HealthResponse {
        status: if healthy { "ok" } else { "degraded" },
        projects,
    };
    Ok((
        if healthy {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(response),
    ))
}

async fn snapshot(
    State(state): State<Arc<DaemonState>>,
    AxumPath(project_id): AxumPath<String>,
) -> std::result::Result<Json<ProjectSnapshot>, ApiHttpError> {
    let project_id = parse_project_id(&project_id)?;
    let project = project_for(&state, project_id)?;
    Ok(Json(
        project
            .snapshot()
            .await
            .map_err(ApiHttpError::from_daemon)?,
    ))
}

async fn submit_project_command(
    State(state): State<Arc<DaemonState>>,
    AxumPath(project_id): AxumPath<String>,
    headers: HeaderMap,
    body: std::result::Result<Json<AuthorityCommandRequest>, JsonRejection>,
) -> std::result::Result<(StatusCode, Json<CommandCommit>), CommandHttpError> {
    let project_id = Uuid::parse_str(&project_id).map_err(|_| {
        CommandHttpError::new(
            StatusCode::BAD_REQUEST,
            CommandErrorCode::InvalidArguments,
            "project_id must be a UUID",
        )
    })?;
    let idempotency_key = headers
        .get(gorce_protocol::IDEMPOTENCY_KEY_HEADER)
        .ok_or_else(|| {
            CommandHttpError::new(
                StatusCode::BAD_REQUEST,
                CommandErrorCode::MissingIdempotencyKey,
                "Idempotency-Key is required",
            )
        })?
        .to_str()
        .map_err(|_| {
            CommandHttpError::new(
                StatusCode::BAD_REQUEST,
                CommandErrorCode::InvalidArguments,
                "Idempotency-Key is not valid UTF-8",
            )
        })?
        .to_owned();
    let Json(request) = body.map_err(|_| {
        CommandHttpError::new(
            StatusCode::BAD_REQUEST,
            CommandErrorCode::InvalidCommand,
            "command body is invalid",
        )
    })?;
    let commit = ProjectCommandService::new(state)
        .submit(project_id, request, idempotency_key)
        .await
        .map_err(CommandHttpError::from_daemon)?;
    Ok((StatusCode::CREATED, Json(commit)))
}

#[derive(Debug, Deserialize)]
struct EventQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn event_page(
    State(state): State<Arc<DaemonState>>,
    AxumPath(project_id): AxumPath<String>,
    query: std::result::Result<Query<EventQuery>, QueryRejection>,
) -> std::result::Result<Json<EventPage>, ApiHttpError> {
    let project_id = parse_project_id(&project_id)?;
    let Query(query) =
        query.map_err(|_| ApiHttpError::bad_request("query parameters are invalid"))?;
    let input_cursor = query
        .cursor
        .as_deref()
        .map(parse_canonical_cursor)
        .transpose()
        .map_err(ApiHttpError::bad_request)?
        .unwrap_or(ORIGIN_CURSOR);
    let public_cursor = encode_cursor(input_cursor);
    let project = project_for(&state, project_id)?;
    if !project
        .cursor_known(input_cursor)
        .await
        .map_err(ApiHttpError::from_daemon)?
    {
        return Err(ApiHttpError::resync(project_id, public_cursor));
    }
    let limit = query
        .limit
        .unwrap_or(MAX_PUBLIC_EVENT_COUNT)
        .clamp(1, MAX_PUBLIC_EVENT_COUNT);
    Ok(Json(
        durable_public_page(&project, input_cursor, limit)
            .await
            .map_err(ApiHttpError::from_daemon)?,
    ))
}

#[derive(Debug, Deserialize)]
struct StreamQuery {
    project_id: Option<String>,
    cursor: Option<String>,
}

async fn event_stream(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    query: std::result::Result<Query<StreamQuery>, QueryRejection>,
) -> std::result::Result<
    Sse<
        impl futures_core::Stream<
            Item = std::result::Result<axum::response::sse::Event, std::convert::Infallible>,
        >,
    >,
    ApiHttpError,
> {
    let Query(query) =
        query.map_err(|_| ApiHttpError::bad_request("query parameters are invalid"))?;
    let project_id = query
        .project_id
        .as_deref()
        .ok_or_else(|| ApiHttpError::bad_request("project_id is required for an event stream"))
        .and_then(parse_project_id)?;
    let cursor = parse_request_cursor(query.cursor, headers.get("last-event-id"))?;
    let project = project_for(&state, project_id)?;
    let subscription = state.broadcaster.subscribe(project_id, cursor);
    let known = project
        .cursor_known(cursor)
        .await
        .map_err(ApiHttpError::from_daemon)?;
    let replay = if known {
        durable_public_replay(
            &project,
            cursor,
            MAX_PUBLIC_EVENT_COUNT,
            MAX_CLIENT_QUEUE_BYTES,
        )
        .await
        .map_err(ApiHttpError::from_daemon)?
    } else {
        PublicReplay {
            events: Vec::new(),
            too_large: false,
        }
    };
    let initial_gap = !known || replay.too_large;
    let stream = async_stream::stream! {
        if initial_gap {
            let gap = ResyncRequired {
                project_id,
                requested_cursor: encode_cursor(cursor),
                oldest_cursor: None,
                latest_cursor: None,
            };
            let data = serde_json::to_string(&gap).unwrap_or_else(|_| "{}".to_owned());
            yield Ok(axum::response::sse::Event::default().event("resync_required").data(data));
        } else {
            let mut last_cursor = cursor;
            for event in replay.events {
                last_cursor = event.cursor;
                yield Ok(axum::response::sse::Event::default()
                    .event("public")
                    .id(event.public_cursor.0.clone())
                    .data(&event.encoded));
            }
            while let Some(item) = subscription.receive_envelope().await {
                match item {
                    QueueItem::Event(event) => {
                        if event.cursor <= last_cursor {
                            continue;
                        }
                        last_cursor = event.cursor;
                        yield Ok(axum::response::sse::Event::default()
                            .event("public")
                            .id(event.public_cursor.0.clone())
                            .data(&event.encoded));
                    }
                    QueueItem::Gap(gap) => {
                        let data = serde_json::to_string(&gap).unwrap_or_else(|_| "{}".to_owned());
                        yield Ok(axum::response::sse::Event::default().event("resync_required").data(data));
                        break;
                    }
                }
            }
        }
    };
    Ok(Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

fn project_for(
    state: &DaemonState,
    project_id: ProjectId,
) -> std::result::Result<Arc<ProjectHandle>, ApiHttpError> {
    state.registry.project(project_id).ok_or_else(|| {
        ApiHttpError::new(
            StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "project was not found",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request};
    use std::process::Command;
    use tower::util::ServiceExt;

    fn test_state() -> Arc<DaemonState> {
        Arc::new(DaemonState {
            registry: Arc::new(ProjectRegistry::open(&[]).unwrap()),
            broadcaster: EventBroadcaster::new(1024, 4096),
            token: "test-token".to_owned(),
            local_principal_id: Uuid::now_v7(),
            bound_address: OnceCell::new(),
        })
    }

    fn public_event_batch(event_type: &str, data: Value) -> EventBatch {
        let project_id = Uuid::new_v4();
        EventBatch {
            format: gorce_protocol::EVENT_BATCH_FORMAT.to_owned(),
            project_id,
            batch_id: UuidV7::from_uuid(Uuid::now_v7()).unwrap(),
            batch_sequence: 1,
            committed_at: "2026-01-01T00:00:00Z".to_owned(),
            actor: EventActor {
                kind: EventActorKind::Service,
                operator_id: None,
            },
            command: EventCommand {
                name: "test".to_owned(),
                arguments: json!({}),
                idempotency_key: "test-key".to_owned(),
            },
            base_revisions: BTreeMap::new(),
            events: vec![EventRecord {
                ordinal: 0,
                event_type: event_type.to_owned(),
                schema_version: 1,
                data,
            }],
            referenced_blobs: Vec::new(),
        }
    }

    #[test]
    fn exposes_the_daemon_version() {
        assert_eq!(daemon_version(), DAEMON_VERSION);
    }

    #[test]
    fn rejects_non_loopback_binding_and_count_limits() {
        let config = DaemonConfig::default().with_bind_addr(SocketAddr::from(([192, 0, 2, 1], 0)));
        assert!(matches!(
            config.validate(),
            Err(DaemonError::InvalidConfiguration(_))
        ));
        let config = DaemonConfig::default().with_queue_limits(MAX_CLIENT_QUEUE_BYTES + 1, 1);
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_invalid_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong"),
        );
        assert!(!authorized(&headers, "right"));
        headers.insert("x-gorce-token", HeaderValue::from_static("right"));
        assert!(!authorized(&headers, "right"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer right"),
        );
        assert!(authorized(&headers, "right"));
    }

    #[test]
    fn cursor_is_opaque_and_does_not_use_reserved_event_count() {
        let cursor = CanonicalCursor {
            batch: 19,
            ordinal: 7,
        };
        assert_eq!(
            parse_canonical_cursor(&encode_cursor(cursor).0).unwrap(),
            cursor
        );
        assert!(parse_canonical_cursor("19").is_err());
    }

    #[test]
    fn projector_allowlists_and_redacts() {
        let batch = public_event_batch(
            "task.updated",
            json!({"name":"safe", "access_token":"secret", "tool_output":"hidden", "nested":{"password":"hidden"}}),
        );
        let event = public_envelopes(&batch).unwrap().pop().unwrap();
        assert_eq!(event.event.payload, json!({"name":"safe", "nested":{}}));
        let private_batch = public_event_batch("permission.requested", json!({"token":"secret"}));
        assert!(public_envelopes(&private_batch).unwrap().is_empty());
    }

    #[test]
    fn instance_lock_rejects_a_second_owner() {
        let root = std::env::temp_dir().join(format!("gorce-daemon-lock-{}", Uuid::new_v4()));
        let runtime = SecureRuntime::open(&root).unwrap();
        let first = runtime.lock(DEFAULT_INSTANCE_LOCK_NAME).unwrap();
        assert!(runtime.lock(DEFAULT_INSTANCE_LOCK_NAME).is_err());
        drop(first);
        assert!(runtime.lock(DEFAULT_INSTANCE_LOCK_NAME).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_fresh_process_first_start_has_one_owner() {
        if std::env::var_os("GORCE_FIRST_START_HELPER").is_some() {
            let runtime = PathBuf::from(std::env::var_os("GORCE_FIRST_START_RUNTIME").unwrap());
            let result = Daemon::new(DaemonConfig::default().with_runtime_dir(runtime));
            if result.is_ok() {
                std::thread::sleep(Duration::from_millis(300));
                std::process::exit(0);
            }
            std::process::exit(1);
        }
        let runtime = std::env::temp_dir().join(format!("gorce-daemon-first-{}", Uuid::new_v4()));
        let executable = std::env::current_exe().unwrap();
        let mut children = Vec::new();
        for _ in 0..2 {
            children.push(
                Command::new(&executable)
                    .arg("--exact")
                    .arg("tests::concurrent_fresh_process_first_start_has_one_owner")
                    .arg("--nocapture")
                    .env("GORCE_FIRST_START_HELPER", "1")
                    .env("GORCE_FIRST_START_RUNTIME", &runtime)
                    .spawn()
                    .unwrap(),
            );
        }
        let statuses = children
            .into_iter()
            .map(|mut child| child.wait().unwrap().success())
            .collect::<Vec<_>>();
        assert_eq!(statuses.iter().filter(|success| **success).count(), 1);
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn discovery_round_trips_without_debug_token_surface() {
        let root = std::env::temp_dir().join(format!("gorce-daemon-discovery-{}", Uuid::new_v4()));
        let runtime = SecureRuntime::open(&root).unwrap();
        write_discovery(
            &runtime,
            DEFAULT_DESCRIPTOR_NAME,
            DEFAULT_TOKEN_NAME,
            "test-token",
            SocketAddr::from(([127, 0, 0, 1], 42_000)),
        )
        .unwrap();
        let discovery = DaemonDiscovery::load(&root).unwrap();
        assert_eq!(discovery.token, "test-token");
        runtime.remove_private(DEFAULT_DESCRIPTOR_NAME).unwrap();
        runtime.remove_private(DEFAULT_TOKEN_NAME).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn opened_identity_validation_rejects_symlink_and_non_private_mode() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root =
            std::env::temp_dir().join(format!("gorce-daemon-identity-check-{}", Uuid::new_v4()));
        let runtime = SecureRuntime::open(&root).unwrap();
        let identity = runtime.path().join(DEFAULT_IDENTITY_NAME);
        let target = runtime.path().join("identity-target");
        fs::write(&target, format!("{}\n", Uuid::now_v7())).unwrap();
        symlink(&target, &identity).unwrap();
        assert!(load_or_create_daemon_identity(&runtime, &[]).is_err());
        fs::remove_file(&identity).unwrap();
        fs::rename(&target, &identity).unwrap();
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_daemon_identity(&runtime).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_runtime_creation_validates_every_opened_private_handle() {
        let root =
            std::env::temp_dir().join(format!("gorce-daemon-windows-handles-{}", Uuid::new_v4()));
        let runtime = SecureRuntime::open(&root).unwrap();
        runtime
            .replace_private(
                DEFAULT_IDENTITY_NAME,
                format!("{}\n", Uuid::now_v7()).as_bytes(),
            )
            .unwrap();
        runtime
            .replace_private(DEFAULT_TOKEN_NAME, b"token\n")
            .unwrap();
        runtime
            .replace_private(DEFAULT_DESCRIPTOR_NAME, b"descriptor")
            .unwrap();
        assert!(runtime
            .open_private(DEFAULT_IDENTITY_NAME, false)
            .unwrap()
            .is_some());
        assert!(runtime
            .open_private(DEFAULT_TOKEN_NAME, false)
            .unwrap()
            .is_some());
        assert!(runtime
            .open_private(DEFAULT_DESCRIPTOR_NAME, false)
            .unwrap()
            .is_some());
        let lock = runtime.lock(DEFAULT_INSTANCE_LOCK_NAME).unwrap();
        runtime.replace_private("durability", b"durable").unwrap();
        drop(lock);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn bounded_subscriber_reports_one_resync_marker() {
        let broadcaster = EventBroadcaster::new(300, 4096);
        let batch = public_event_batch("task.updated", json!({"value":"x"}));
        let project_id = batch.project_id;
        let subscription = broadcaster.subscribe(project_id, ORIGIN_CURSOR);
        let envelope = Arc::new(public_envelopes(&batch).unwrap().pop().unwrap());
        broadcaster.publish(envelope.clone());
        broadcaster.publish(envelope);
        assert!(matches!(
            subscription.recv().await,
            Some(SubscriptionMessage::Gap(_))
        ));
        broadcaster.close();
        assert!(subscription.recv().await.is_none());
    }

    #[tokio::test]
    async fn durable_public_commit_notifies_live_subscriber() {
        let root = std::env::temp_dir().join(format!("gorce-daemon-live-{}", Uuid::new_v4()));
        let runtime =
            std::env::temp_dir().join(format!("gorce-daemon-live-runtime-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let project_id = Uuid::new_v4();
        let daemon = Daemon::new(
            DaemonConfig::new(vec![ProjectConfig::new(project_id, &root)])
                .with_runtime_dir(&runtime),
        )
        .unwrap();
        let project = daemon.state.registry.project(project_id).unwrap();
        let subscription = daemon.broadcaster().subscribe(project_id, ORIGIN_CURSOR);
        let task_id = Uuid::new_v4();
        let mut batch = public_event_batch(
            "task.updated",
            json!({
                "id": task_id,
                "project_id": project_id,
                "lifecycle": "open",
                "readiness": {
                    "status": "ready",
                    "blocker_task_ids": [],
                    "evaluated_at": "2026-01-01T00:00:00Z"
                },
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            }),
        );
        batch.project_id = project_id;
        batch.batch_sequence = project.store.next_batch_sequence().unwrap();
        batch.command.idempotency_key = format!("live-{}", Uuid::new_v4());
        let public_events = public_envelopes(&batch)
            .unwrap()
            .into_iter()
            .map(Arc::new)
            .collect::<Vec<_>>();

        let append = project.store.append_next(&batch).unwrap();
        assert!(!append.duplicate);
        for event in public_events {
            daemon.broadcaster().publish(event);
        }

        match subscription.recv().await {
            Some(SubscriptionMessage::Event(event)) => {
                assert_eq!(event.event.project_id, project_id);
                assert_eq!(event.event.event_type, "task.updated");
                assert_eq!(event.event.payload["id"], json!(task_id));
            }
            other => panic!("expected a live public event, got {other:?}"),
        }
        drop(subscription);
        drop(project);
        drop(daemon);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(runtime).unwrap();
    }

    #[tokio::test]
    async fn subscriber_cleanup_is_exact_under_churn() {
        let broadcaster = EventBroadcaster::new(1024, 4096);
        let project_id = Uuid::new_v4();
        for _ in 0..100 {
            let subscription = broadcaster.subscribe(project_id, ORIGIN_CURSOR);
            assert_eq!(broadcaster.subscriber_count(), 1);
            drop(subscription);
            assert_eq!(broadcaster.subscriber_count(), 0);
        }
    }

    #[tokio::test]
    async fn router_returns_typed_auth_404_and_405_errors() {
        let state = test_state();
        let router = app(state);
        let unauthorized = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v0/meta")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert!(unauthorized.headers().contains_key("x-request-id"));

        let post = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v0/projects/00000000-0000-0000-0000-000000000000/events")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);

        let missing = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/not-a-route")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let stream_without_project = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v0/events")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stream_without_project.status(), StatusCode::BAD_REQUEST);

        let x_token_only = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v0/projects/00000000-0000-0000-0000-000000000000/commands")
                    .header("x-gorce-token", "test-token")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(x_token_only.status(), StatusCode::UNAUTHORIZED);

        let missing_key = router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v0/projects/00000000-0000-0000-0000-000000000000/commands")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_key.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(missing_key.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let error: CommandError = serde_json::from_slice(&body).unwrap();
        assert_eq!(error.code, CommandErrorCode::MissingIdempotencyKey);
    }

    #[tokio::test]
    async fn command_route_rejects_incompatible_protocol_before_dispatch() {
        let router = app(test_state());
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v0/projects/00000000-0000-0000-0000-000000000000/commands")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .header("x-gorce-protocol-version", "incompatible")
                    .header(gorce_protocol::IDEMPOTENCY_KEY_HEADER, "protocol-test")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().contains_key("x-request-id"));
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let error: ApiError = serde_json::from_slice(&body).unwrap();
        assert_eq!(error.code, ErrorCode::PreconditionFailed);
        assert_eq!(error.message, "client protocol version is incompatible");
    }

    #[test]
    fn every_command_error_code_has_an_explicit_http_mapping() {
        let cases = [
            (CommandErrorCode::InvalidCommand, StatusCode::BAD_REQUEST),
            (CommandErrorCode::InvalidArguments, StatusCode::BAD_REQUEST),
            (
                CommandErrorCode::MissingIdempotencyKey,
                StatusCode::BAD_REQUEST,
            ),
            (CommandErrorCode::IdempotencyConflict, StatusCode::CONFLICT),
            (
                CommandErrorCode::CommandNotSupported,
                StatusCode::BAD_REQUEST,
            ),
            (CommandErrorCode::CommandRejected, StatusCode::BAD_REQUEST),
            (
                CommandErrorCode::CommitUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ];
        for (code, status) in cases {
            let response = CommandHttpError::from_daemon(DaemonError::Command {
                code: code.clone(),
                message: "test".to_owned(),
            });
            assert_eq!(response.status, status);
            assert_eq!(response.error.code, code);
        }
    }

    #[tokio::test]
    async fn authority_commands_project_and_replay_durably() {
        let root = std::env::temp_dir().join(format!("gorce-authority-{}", Uuid::new_v4()));
        let runtime =
            std::env::temp_dir().join(format!("gorce-authority-runtime-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let project_id = Uuid::new_v4();
        let daemon = Daemon::new(
            DaemonConfig::new(vec![ProjectConfig::new(project_id, &root)])
                .with_runtime_dir(&runtime),
        )
        .unwrap();
        let service = ProjectCommandService::new(daemon.state.clone());
        let profile = AuthorityCommandRequest {
            version: gorce_protocol::COMMAND_ENVELOPE_FORMAT.to_owned(),
            command: AuthorityCommandKind::ProfileRegister {
                arguments: EmptyCommandArguments {},
            },
        };
        let first = service
            .submit(project_id, profile.clone(), "profile-1".to_owned())
            .await
            .unwrap();
        let replay = service
            .submit(project_id, profile, "profile-1".to_owned())
            .await
            .unwrap();
        assert_eq!(first, replay);

        let operator_id = Uuid::new_v4();
        let binding = AuthorityCommandRequest {
            version: gorce_protocol::COMMAND_ENVELOPE_FORMAT.to_owned(),
            command: AuthorityCommandKind::OperatorBind {
                arguments: OperatorBindingArguments { operator_id },
            },
        };
        service
            .submit(project_id, binding, "binding-1".to_owned())
            .await
            .unwrap();
        let run_id = Uuid::new_v4();
        let admission = AuthorityCommandRequest {
            version: gorce_protocol::COMMAND_ENVELOPE_FORMAT.to_owned(),
            command: AuthorityCommandKind::AdmissionCreate {
                arguments: AdmissionCreateArguments {
                    operator_id,
                    run_id,
                },
            },
        };
        service
            .submit(project_id, admission.clone(), "admission-1".to_owned())
            .await
            .unwrap();
        let project = daemon.state.registry.project(project_id).unwrap();
        project.store.rebuild_index().unwrap();
        assert!(project
            .store
            .index()
            .authority_admission_for_run(run_id)
            .unwrap()
            .is_some());
        let concurrent_run = Uuid::new_v4();
        let concurrent_admission = AuthorityCommandRequest {
            version: gorce_protocol::COMMAND_ENVELOPE_FORMAT.to_owned(),
            command: AuthorityCommandKind::AdmissionCreate {
                arguments: AdmissionCreateArguments {
                    operator_id,
                    run_id: concurrent_run,
                },
            },
        };
        let concurrent = tokio::join!(
            service.submit(
                project_id,
                concurrent_admission.clone(),
                "admission-replay".to_owned()
            ),
            service.submit(
                project_id,
                concurrent_admission,
                "admission-replay".to_owned()
            ),
        );
        assert_eq!(concurrent.0.unwrap(), concurrent.1.unwrap());
        drop(service);
        drop(project);
        drop(daemon);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn opens_project_through_the_registry() {
        let root = std::env::temp_dir().join(format!("gorce-daemon-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let project_id = Uuid::new_v4();
        let registry = ProjectRegistry::open(&[ProjectConfig::new(project_id, &root)]).unwrap();
        assert_eq!(registry.project(project_id).unwrap().id, project_id);
        drop(registry);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn daemon_identity_is_stable_and_bootstraps_only_empty_authority_state() {
        let root = std::env::temp_dir().join(format!("gorce-daemon-identity-{}", Uuid::new_v4()));
        let runtime = std::env::temp_dir().join(format!("gorce-daemon-runtime-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let project_id = Uuid::new_v4();
        let config = DaemonConfig::new(vec![ProjectConfig::new(project_id, &root)])
            .with_runtime_dir(&runtime);
        let first = Daemon::new(config.clone()).unwrap();
        let principal_id = first.state.local_principal_id;
        let project = first.state.registry.project(project_id).unwrap();
        assert_eq!(
            project
                .store
                .index()
                .authority_principal()
                .unwrap()
                .unwrap()
                .id,
            principal_id
        );
        drop(first);
        drop(project);
        let second = Daemon::new(config.clone()).unwrap();
        assert_eq!(second.state.local_principal_id, principal_id);
        assert_eq!(
            second
                .state
                .registry
                .project(project_id)
                .unwrap()
                .store
                .index()
                .authority_latest_profile_revision()
                .unwrap()
                .unwrap()
                .grant
                .max_depth,
            0
        );
        drop(second);
        fs::remove_file(runtime.join(DEFAULT_IDENTITY_NAME)).unwrap();
        assert!(Daemon::new(config.clone()).is_err());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(runtime).unwrap();
    }
}
