#![forbid(unsafe_code)]

use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode},
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::{backend::CrosstermBackend, Frame, Terminal};
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::io::{self, Write};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::time::Duration;

pub const TUI_VERSION: &str = env!("CARGO_PKG_VERSION");
pub fn tui_version() -> &'static str {
    TUI_VERSION
}
const MAX_TRANSCRIPT: usize = 2_000;
const MAX_ACTIVITY: usize = 200;
const MAX_FILES: usize = 500;
const MAX_EVENT_IDS: usize = MAX_TRANSCRIPT;
const LARGE_PASTE: usize = 32 * 1024;
pub const INBOUND_EVENT_BUDGET: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionMode {
    Supervised,
    PolicyVerified,
    AiVerified,
    Bypass,
}
impl PermissionMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Supervised => "SUPERVISED",
            Self::PolicyVerified => "POLICY",
            Self::AiVerified => "AI-VERIFIED",
            Self::Bypass => "BYPASS",
        }
    }
    pub fn banner(self) -> &'static str {
        match self {
            Self::Supervised => "Actions require confirmation",
            Self::PolicyVerified => "Approved by policy",
            Self::AiVerified => "Approved by verifier",
            Self::Bypass => "NO ACTION CONFIRMATION",
        }
    }
    fn style(self) -> Style {
        match self {
            Self::Supervised => Style::default().fg(Color::Yellow),
            Self::PolicyVerified | Self::AiVerified => Style::default().fg(Color::Cyan),
            Self::Bypass => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Attention {
    Silent,
    Ambient,
    Attention,
    Critical,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskStatus {
    Queued,
    Running,
    Blocked,
    Done,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobStatus {
    Running,
    Waiting,
    Completed,
    Failed,
    Cancelled,
    Stale,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileStatus {
    Added,
    Modified,
    Deleted,
    Conflicted,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Task {
    pub id: String,
    pub title: String,
    pub depth: u16,
    pub status: TaskStatus,
    pub done: u16,
    pub total: u16,
    pub expanded: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Activity {
    pub label: String,
    pub agent: String,
    pub detail: String,
    pub attention: Attention,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Job {
    pub name: String,
    pub agent: String,
    pub status: JobStatus,
    pub elapsed: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Approval {
    pub id: String,
    pub request: String,
    pub detail: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangedFile {
    pub path: String,
    pub status: FileStatus,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiffKind {
    Context,
    Added,
    Removed,
    Header,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffLine {
    pub left: Option<u32>,
    pub right: Option<u32>,
    pub kind: DiffKind,
    pub text: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffEntry {
    pub path: String,
    pub lines: Vec<DiffLine>,
    pub side_by_side: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Attachment {
    Text(String),
    Png(Vec<u8>),
    Jpeg(Vec<u8>),
    Path(String),
    File {
        name: String,
        bytes: usize,
        lines: usize,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentKind {
    File,
    Image,
    Paste,
    Path,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentStatus {
    Ready,
    Pending,
    Error,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentChip {
    pub id: String,
    pub kind: AttachmentKind,
    pub source: String,
    pub bytes: Option<usize>,
    pub lines: Option<usize>,
    pub status: AttachmentStatus,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentAction {
    Inspect,
    Remove,
    Retry,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptEntry {
    pub source: String,
    pub body: String,
    pub attention: Attention,
    pub attachment: Option<Attachment>,
}

/// An event identity supplied by the daemon composition layer.
///
/// The value is intentionally opaque: the TUI can compare and hash it, but
/// cannot inspect it, order it, or use it as a cursor.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct ConfirmedEventId(Vec<u8>);

impl ConfirmedEventId {
    /// Construct an identity from bytes without interpreting their contents.
    pub fn from_opaque_bytes(value: impl AsRef<[u8]>) -> Self {
        Self(value.as_ref().to_vec())
    }

    /// Convenience constructor for composition adapters that already hold an
    /// opaque string representation. The string is never parsed or ordered.
    pub fn new(value: impl AsRef<[u8]>) -> Self {
        Self::from_opaque_bytes(value)
    }
}

impl fmt::Debug for ConfirmedEventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfirmedEventId(..)")
    }
}

/// A timestamp confirmed by the daemon. It is displayable metadata, not an
/// ordering key for replay or deduplication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedTimestamp(String);

impl ConfirmedTimestamp {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub type ConfirmedAt = ConfirmedTimestamp;

/// Text that has crossed the typed, safe presentation boundary. The TUI does
/// not accept protocol payloads or raw JSON as presentation content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafeText(String);

impl SafeText {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub type PresentationText = SafeText;

impl From<String> for SafeText {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SafeText {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmedPresentationKind {
    User,
    Agent,
    Tool,
    Activity,
    Background,
    Diff,
    Status,
}

impl ConfirmedPresentationKind {
    fn label(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Agent => "agent",
            Self::Tool => "tool",
            Self::Activity => "activity",
            Self::Background => "background",
            Self::Diff => "diff",
            Self::Status => "status",
        }
    }
}

pub type PresentationKind = ConfirmedPresentationKind;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedPresentation {
    pub kind: ConfirmedPresentationKind,
    pub text: SafeText,
    pub attention: Attention,
}

impl ConfirmedPresentation {
    pub fn new(kind: ConfirmedPresentationKind, text: impl Into<SafeText>) -> Self {
        Self {
            kind,
            text: text.into(),
            attention: Attention::Silent,
        }
    }

    pub fn with_attention(mut self, attention: Attention) -> Self {
        self.attention = attention;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedEvent {
    pub identity: ConfirmedEventId,
    pub confirmed_at: ConfirmedTimestamp,
    pub presentation: ConfirmedPresentation,
}

impl ConfirmedEvent {
    pub fn new(
        identity: ConfirmedEventId,
        confirmed_at: ConfirmedTimestamp,
        presentation: ConfirmedPresentation,
    ) -> Self {
        Self {
            identity,
            confirmed_at,
            presentation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedRow {
    pub identity: ConfirmedEventId,
    pub confirmed_at: ConfirmedTimestamp,
    pub kind: ConfirmedPresentationKind,
    pub text: SafeText,
    pub attention: Attention,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalNoticeKind {
    Connecting,
    Reconnecting,
    Reconciliation,
    Offline,
    Info,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalNotice {
    pub kind: LocalNoticeKind,
    pub text: SafeText,
}

impl LocalNotice {
    pub fn new(kind: LocalNoticeKind, text: impl Into<SafeText>) -> Self {
        Self {
            kind,
            text: text.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingRequestKind {
    Submission,
    ApprovalDecision,
    Attachment,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingRequest {
    pub id: String,
    pub kind: PendingRequestKind,
    pub text: SafeText,
}

impl PendingRequest {
    pub fn new(id: impl Into<String>, kind: PendingRequestKind, text: impl Into<SafeText>) -> Self {
        Self {
            id: id.into(),
            kind,
            text: text.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineReason(String);

impl OfflineReason {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Reconnecting {
        attempt: u32,
        last_confirmed_at: Option<ConfirmedTimestamp>,
    },
    RetryPaused {
        attempt: u32,
    },
    Reconciling,
    Offline {
        reason: OfflineReason,
        retryability: Retryability,
    },
}

impl ConnectionState {
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }
}

pub type ConnectionStatus = ConnectionState;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Retryability {
    Retryable,
    Permanent,
}

pub type OfflineRetryability = Retryability;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionEvent {
    Connecting,
    Connected,
    Reconnecting {
        attempt: u32,
        last_confirmed_at: Option<ConfirmedTimestamp>,
    },
    RetryPaused {
        attempt: u32,
    },
    BeginReconciliation,
    Reconciling {
        mode: ReconciliationMode,
    },
    ReconciliationComplete,
    Offline {
        reason: OfflineReason,
        retryability: Retryability,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationMode {
    Delta,
    Replace,
}

pub type ReconciliationOrigin = ReconciliationMode;

/// Capabilities explicitly granted by the composition layer. The first
/// read-only event-stream slice starts with both request routes unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiCapabilities {
    pub send: bool,
    pub approval_decision: bool,
}

impl UiCapabilities {
    pub const READ_ONLY: Self = Self {
        send: false,
        approval_decision: false,
    };

    pub const fn new(send: bool, approval_decision: bool) -> Self {
        Self {
            send,
            approval_decision,
        }
    }
}

impl Default for UiCapabilities {
    fn default() -> Self {
        Self::READ_ONLY
    }
}

pub type CapabilityState = UiCapabilities;

/// Typed messages accepted by the TUI boundary. Confirmed daemon events,
/// local notices, and pending requests deliberately have different variants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UiEvent {
    Confirmed(ConfirmedEvent),
    LocalNotice(LocalNotice),
    PendingRequest(PendingRequest),
    Connection(ConnectionEvent),
    Capabilities(UiCapabilities),
}

pub type InboundUiEvent = UiEvent;
pub type UiInboundEvent = UiEvent;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UiIntent {
    Submit(String),
    Paste(PastePayload),
    Copy(String),
    RetryConnection,
    Resolve {
        id: String,
        allow: bool,
    },
    Attachment {
        id: String,
        action: AttachmentAction,
    },
    OpenPalette,
    ToggleOperations,
    Quit,
}

pub type UiEventSender = SyncSender<UiEvent>;
pub type UiEventReceiver = Receiver<UiEvent>;
pub type UiIntentSender = SyncSender<UiIntent>;
pub type UiIntentReceiver = Receiver<UiIntent>;

/// Create the bounded channels used by the later `gorce` composition lane.
pub fn channels(
    capacity: usize,
) -> (
    UiEventSender,
    UiEventReceiver,
    UiIntentSender,
    UiIntentReceiver,
) {
    let (events_tx, events_rx) = mpsc::sync_channel(capacity.max(1));
    let (intents_tx, intents_rx) = mpsc::sync_channel(capacity.max(1));
    (events_tx, events_rx, intents_tx, intents_rx)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientEvent {
    Transcript(TranscriptEntry),
    Diff(DiffEntry),
    Task(Task),
    Activity(Activity),
    Job(Job),
    Approval(Approval),
    ApprovalResolved(String),
    File(ChangedFile),
    Budget {
        spent: String,
        limit: String,
        percent: u16,
    },
    Permission(PermissionMode),
    SessionTitle(String),
}
pub trait ClientAdapter {
    type Error;
    fn send_text(&mut self, text: String) -> Result<(), Self::Error>;
    fn send_attachment(&mut self, attachment: Attachment) -> Result<(), Self::Error>;
    fn resolve_approval(&mut self, id: String, allow: bool) -> Result<(), Self::Error>;
}
pub trait Clipboard {
    fn copy(&mut self, text: &str) -> io::Result<()>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PastePayload {
    Inline(String),
    Blob { bytes: usize, preview: String },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UiAction {
    None,
    Submit(String),
    Paste(PastePayload),
    Copy(String),
    RetryConnection,
    OpenPalette,
    ToggleOperations,
    Quit,
    Resolve {
        id: String,
        allow: bool,
    },
    Attachment {
        id: String,
        action: AttachmentAction,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputEvent {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Paste(String),
    Resize(u16, u16),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Density {
    Wide,
    Medium,
    Narrow,
}
pub fn density(width: u16) -> Density {
    if width >= 120 {
        Density::Wide
    } else if width >= 90 {
        Density::Medium
    } else {
        Density::Narrow
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Focus {
    Stream,
    Operations,
    Input,
    Palette,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TranscriptProvenance {
    Confirmed {
        identity: ConfirmedEventId,
        confirmed_at: ConfirmedTimestamp,
        kind: ConfirmedPresentationKind,
    },
    Legacy,
}

pub struct App {
    pub title: String,
    pub permission: PermissionMode,
    pub transcript: VecDeque<TranscriptEntry>,
    pub confirmed_rows: VecDeque<ConfirmedRow>,
    pub transcript_offset: usize,
    pub selection: Option<(usize, usize)>,
    pub focus: Focus,
    pub viewport: (u16, u16),
    pub tasks: Vec<Task>,
    pub activities: VecDeque<Activity>,
    pub jobs: Vec<Job>,
    pub approvals: Vec<Approval>,
    pub files: Vec<ChangedFile>,
    pub diffs: VecDeque<DiffEntry>,
    pub attachments: Vec<AttachmentChip>,
    pub focused_attachment: Option<usize>,
    pub budget_spent: Option<String>,
    pub budget_limit: Option<String>,
    pub budget_percent: Option<u16>,
    pub context_used: Option<String>,
    pub context_limit: Option<String>,
    pub model: Option<String>,
    pub foreground_agent: Option<String>,
    pub operations_open: bool,
    pub filter: String,
    pub palette_open: bool,
    pub input: String,
    pub pending_attention: usize,
    pub status: String,
    pub connection: ConnectionState,
    pub capabilities: UiCapabilities,
    pub reconciliation_mode: Option<ReconciliationMode>,
    pub last_confirmed_at: Option<ConfirmedTimestamp>,
    pub local_notices: VecDeque<LocalNotice>,
    pub pending_requests: VecDeque<PendingRequest>,
    transcript_provenance: VecDeque<TranscriptProvenance>,
    confirmed_ids: HashSet<ConfirmedEventId>,
    confirmed_id_history: VecDeque<ConfirmedEventId>,
    reconciliation_shadow: VecDeque<ConfirmedRow>,
    reconciliation_shadow_ids: HashSet<ConfirmedEventId>,
}
impl Default for App {
    fn default() -> Self {
        Self {
            title: "Gorce session".into(),
            permission: PermissionMode::Supervised,
            transcript: VecDeque::new(),
            confirmed_rows: VecDeque::new(),
            transcript_offset: 0,
            selection: None,
            focus: Focus::Input,
            viewport: (80, 24),
            tasks: Vec::new(),
            activities: VecDeque::new(),
            jobs: Vec::new(),
            approvals: Vec::new(),
            files: Vec::new(),
            diffs: VecDeque::new(),
            attachments: Vec::new(),
            focused_attachment: None,
            budget_spent: None,
            budget_limit: None,
            budget_percent: None,
            context_used: None,
            context_limit: None,
            model: None,
            foreground_agent: None,
            operations_open: true,
            filter: String::new(),
            palette_open: false,
            input: String::new(),
            pending_attention: 0,
            status: String::new(),
            connection: ConnectionState::Connecting,
            capabilities: UiCapabilities::READ_ONLY,
            reconciliation_mode: None,
            last_confirmed_at: None,
            local_notices: VecDeque::new(),
            pending_requests: VecDeque::new(),
            transcript_provenance: VecDeque::new(),
            confirmed_ids: HashSet::new(),
            confirmed_id_history: VecDeque::new(),
            reconciliation_shadow: VecDeque::new(),
            reconciliation_shadow_ids: HashSet::new(),
        }
    }
}
impl App {
    /// Reduce a typed inbound event. This is the only path that can add a
    /// confirmed row to the new event-backed projection.
    pub fn reduce_inbound(&mut self, event: UiEvent) {
        match event {
            UiEvent::Confirmed(event) => self.reduce_confirmed(event),
            UiEvent::LocalNotice(notice) => {
                self.local_notices.push_back(notice);
                while self.local_notices.len() > MAX_ACTIVITY {
                    self.local_notices.pop_front();
                }
            }
            UiEvent::PendingRequest(request) => {
                self.pending_requests.retain(|item| item.id != request.id);
                self.pending_requests.push_back(request);
                while self.pending_requests.len() > MAX_ACTIVITY {
                    self.pending_requests.pop_front();
                }
            }
            UiEvent::Connection(event) => self.reduce_connection(event),
            UiEvent::Capabilities(capabilities) => self.capabilities = capabilities,
        }
    }

    pub fn reduce_ui_event(&mut self, event: InboundUiEvent) {
        self.reduce_inbound(event);
    }

    fn reduce_connection(&mut self, event: ConnectionEvent) {
        match event {
            ConnectionEvent::Connecting => self.connection = ConnectionState::Connecting,
            ConnectionEvent::Connected => self.connection = ConnectionState::Connected,
            ConnectionEvent::Reconnecting {
                attempt,
                last_confirmed_at,
            } => {
                self.connection = ConnectionState::Reconnecting {
                    attempt,
                    last_confirmed_at,
                };
            }
            ConnectionEvent::RetryPaused { attempt } => {
                self.connection = ConnectionState::RetryPaused { attempt };
            }
            ConnectionEvent::BeginReconciliation => {
                self.begin_reconciliation(ReconciliationMode::Delta);
            }
            ConnectionEvent::Reconciling { mode } => {
                self.begin_reconciliation(mode);
            }
            ConnectionEvent::ReconciliationComplete => {
                let mode = self
                    .reconciliation_mode
                    .take()
                    .unwrap_or(ReconciliationMode::Delta);
                let staged = std::mem::take(&mut self.reconciliation_shadow);
                self.reconciliation_shadow_ids.clear();
                match mode {
                    ReconciliationMode::Delta => self.commit_delta(staged),
                    ReconciliationMode::Replace => self.commit_replace(staged),
                }
                self.connection = ConnectionState::Connected;
            }
            ConnectionEvent::Offline {
                reason,
                retryability,
            } => {
                self.connection = ConnectionState::Offline {
                    reason,
                    retryability,
                };
            }
        }
    }

    fn begin_reconciliation(&mut self, mode: ReconciliationMode) {
        self.reconciliation_shadow.clear();
        self.reconciliation_shadow_ids.clear();
        self.reconciliation_mode = Some(mode);
        self.connection = ConnectionState::Reconciling;
    }

    fn commit_delta(&mut self, staged: VecDeque<ConfirmedRow>) {
        // Replay order is the order supplied by the event pump; no cursor,
        // sequence, UUID, or timestamp ordering is involved.
        let mut commit = Vec::with_capacity(staged.len());
        let mut seen = HashSet::new();
        for row in staged {
            if !self.confirmed_ids.contains(&row.identity) && seen.insert(row.identity.clone()) {
                commit.push(row);
            }
        }
        for row in commit {
            self.commit_confirmed_row(row);
        }
    }

    fn commit_replace(&mut self, staged: VecDeque<ConfirmedRow>) {
        let mut confirmed_rows = staged;
        while confirmed_rows.len() > MAX_TRANSCRIPT {
            confirmed_rows.pop_front();
        }

        let mut confirmed_ids = HashSet::new();
        let mut confirmed_id_history = VecDeque::new();
        for row in &confirmed_rows {
            if confirmed_ids.insert(row.identity.clone()) {
                confirmed_id_history.push_back(row.identity.clone());
            }
        }

        let mut transcript = VecDeque::new();
        let mut provenance = VecDeque::new();
        for index in 0..self.transcript.len() {
            let item = &self.transcript[index];
            if !matches!(
                self.transcript_provenance.get(index),
                Some(TranscriptProvenance::Confirmed { .. })
            ) {
                transcript.push_back(item.clone());
                provenance.push_back(TranscriptProvenance::Legacy);
            }
        }
        for row in &confirmed_rows {
            transcript.push_back(row_transcript_entry(row));
            provenance.push_back(TranscriptProvenance::Confirmed {
                identity: row.identity.clone(),
                confirmed_at: row.confirmed_at.clone(),
                kind: row.kind,
            });
        }
        while transcript.len() > MAX_TRANSCRIPT {
            transcript.pop_front();
            provenance.pop_front();
        }

        let last_confirmed_at = confirmed_rows.back().map(|row| row.confirmed_at.clone());
        self.confirmed_rows = confirmed_rows;
        self.confirmed_ids = confirmed_ids;
        self.confirmed_id_history = confirmed_id_history;
        self.transcript = transcript;
        self.transcript_provenance = provenance;
        self.last_confirmed_at = last_confirmed_at;
    }

    fn reduce_confirmed(&mut self, event: ConfirmedEvent) {
        let duplicate_visible = self.reconciliation_mode != Some(ReconciliationMode::Replace)
            && self.confirmed_ids.contains(&event.identity);
        if duplicate_visible || self.reconciliation_shadow_ids.contains(&event.identity) {
            return;
        }
        let row = ConfirmedRow {
            identity: event.identity,
            confirmed_at: event.confirmed_at,
            kind: event.presentation.kind,
            text: event.presentation.text,
            attention: event.presentation.attention,
        };
        if self.connection.is_connected() {
            self.commit_confirmed_row(row);
        } else {
            self.reconciliation_shadow_ids.insert(row.identity.clone());
            self.reconciliation_shadow.push_back(row);
            while self.reconciliation_shadow.len() > MAX_TRANSCRIPT {
                if let Some(old) = self.reconciliation_shadow.pop_front() {
                    self.reconciliation_shadow_ids.remove(&old.identity);
                }
            }
        }
    }

    fn commit_confirmed_row(&mut self, row: ConfirmedRow) {
        if self.confirmed_ids.contains(&row.identity) {
            return;
        }
        if row.attention >= Attention::Attention {
            self.pending_attention += 1;
        }
        self.last_confirmed_at = Some(row.confirmed_at.clone());
        self.remember_confirmed_id(row.identity.clone());
        self.confirmed_rows.push_back(row.clone());
        while self.confirmed_rows.len() > MAX_TRANSCRIPT {
            self.confirmed_rows.pop_front();
        }
        self.append_transcript(
            row_transcript_entry(&row),
            TranscriptProvenance::Confirmed {
                identity: row.identity,
                confirmed_at: row.confirmed_at,
                kind: row.kind,
            },
        );
    }

    fn remember_confirmed_id(&mut self, identity: ConfirmedEventId) {
        if !self.confirmed_ids.insert(identity.clone()) {
            return;
        }
        self.confirmed_id_history.push_back(identity);
        while self.confirmed_id_history.len() > MAX_EVENT_IDS {
            if let Some(old) = self.confirmed_id_history.pop_front() {
                self.confirmed_ids.remove(&old);
            }
        }
    }

    fn append_transcript(&mut self, item: TranscriptEntry, provenance: TranscriptProvenance) {
        self.transcript.push_back(item);
        self.transcript_provenance.push_back(provenance);
        while self.transcript.len() > MAX_TRANSCRIPT {
            self.transcript.pop_front();
            self.transcript_provenance.pop_front();
        }
    }

    pub fn reduce(&mut self, event: ClientEvent) {
        match event {
            ClientEvent::Transcript(item) => {
                if item.attention >= Attention::Attention {
                    self.pending_attention += 1;
                }
                self.append_transcript(item, TranscriptProvenance::Legacy);
            }
            ClientEvent::Diff(item) => {
                self.diffs.push_back(item);
                while self.diffs.len() > MAX_FILES {
                    self.diffs.pop_front();
                }
            }
            ClientEvent::Task(item) => upsert(&mut self.tasks, item, |x| &x.id),
            ClientEvent::Activity(item) => {
                if item.attention >= Attention::Attention {
                    self.pending_attention += 1;
                }
                self.activities.push_back(item);
                while self.activities.len() > MAX_ACTIVITY {
                    self.activities.pop_front();
                }
            }
            ClientEvent::Job(item) => upsert(&mut self.jobs, item, |x| &x.name),
            ClientEvent::Approval(item) => {
                if !self.approvals.iter().any(|approval| approval.id == item.id) {
                    self.pending_attention += 1;
                }
                self.approvals.retain(|x| x.id != item.id);
                self.approvals.push(item);
            }
            ClientEvent::ApprovalResolved(id) => {
                if self.approvals.iter().any(|approval| approval.id == id) {
                    self.approvals.retain(|x| x.id != id);
                    self.pending_attention = self.pending_attention.saturating_sub(1);
                }
            }
            ClientEvent::File(item) => {
                self.files.retain(|x| x.path != item.path);
                self.files.push(item);
                if self.files.len() > MAX_FILES {
                    self.files.remove(0);
                }
            }
            ClientEvent::Budget {
                spent,
                limit,
                percent,
            } => {
                self.budget_spent = Some(spent);
                self.budget_limit = Some(limit);
                self.budget_percent = Some(percent);
            }
            ClientEvent::Permission(mode) => self.permission = mode,
            ClientEvent::SessionTitle(title) => self.title = title,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connection.is_connected()
    }

    pub fn set_capabilities(&mut self, capabilities: UiCapabilities) {
        self.capabilities = capabilities;
    }

    pub fn can_send(&self) -> bool {
        self.is_connected() && self.capabilities.send
    }

    pub fn can_decide(&self) -> bool {
        self.is_connected() && self.capabilities.approval_decision
    }

    pub fn retry_available(&self) -> bool {
        matches!(
            &self.connection,
            ConnectionState::Reconnecting { .. }
                | ConnectionState::RetryPaused { .. }
                | ConnectionState::Offline {
                    retryability: Retryability::Retryable,
                    ..
                }
        )
    }

    pub fn connection_state(&self) -> &ConnectionState {
        &self.connection
    }

    pub fn controls_enabled(&self) -> bool {
        self.can_send()
    }

    pub fn confirmed_id_history_len(&self) -> usize {
        self.confirmed_id_history.len()
    }

    pub fn reconciliation_shadow_len(&self) -> usize {
        self.reconciliation_shadow.len()
    }

    /// Resolve an approval only when the live daemon stream is available.
    /// The approval remains pending otherwise.
    pub fn resolve_approval(&mut self, id: impl Into<String>, allow: bool) -> UiAction {
        if !self.can_decide() {
            return UiAction::None;
        }
        UiAction::Resolve {
            id: id.into(),
            allow,
        }
    }
    pub fn handle(&mut self, input: InputEvent) -> UiAction {
        match input {
            InputEvent::Paste(value) => {
                let payload = paste_payload(value);
                if let PastePayload::Inline(ref text) = payload {
                    self.input.push_str(text);
                }
                UiAction::Paste(payload)
            }
            InputEvent::Resize(width, height) => {
                self.viewport = (width, height);
                UiAction::None
            }
            InputEvent::Mouse(mouse) => self.mouse(mouse),
            InputEvent::Key(key) => self.key(key),
        }
    }
    fn key(&mut self, key: KeyEvent) -> UiAction {
        if key.code == KeyCode::Char('r') {
            if self.retry_available() {
                return UiAction::RetryConnection;
            }
            if matches!(
                self.connection,
                ConnectionState::Offline {
                    retryability: Retryability::Permanent,
                    ..
                }
            ) {
                return UiAction::None;
            }
        }
        if self.palette_open {
            if key.code == KeyCode::Esc || key.code == KeyCode::Enter {
                self.palette_open = false;
            }
            return UiAction::None;
        }
        match (key.code, key.modifiers) {
            (KeyCode::Char('q'), KeyModifiers::CONTROL) => UiAction::Quit,
            (KeyCode::Char('k'), KeyModifiers::CONTROL) | (KeyCode::Char(':'), _) => {
                self.palette_open = true;
                UiAction::OpenPalette
            }
            (KeyCode::Char('o'), KeyModifiers::CONTROL) => {
                self.operations_open = !self.operations_open;
                UiAction::ToggleOperations
            }
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => UiAction::Copy(self.input.clone()),
            (KeyCode::Enter, _) if self.can_send() && !self.input.is_empty() => {
                UiAction::Submit(std::mem::take(&mut self.input))
            }
            (KeyCode::Backspace, _) => {
                self.input.pop();
                UiAction::None
            }
            (KeyCode::Delete, _) => self.remove_focused_attachment(),
            (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
                self.transcript_offset += 1;
                UiAction::None
            }
            (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                self.transcript_offset = self.transcript_offset.saturating_sub(1);
                UiAction::None
            }
            (KeyCode::Char(ch), _) => {
                self.input.push(ch);
                UiAction::None
            }
            (KeyCode::Esc, _) => {
                self.filter.clear();
                UiAction::None
            }
            _ => UiAction::None,
        }
    }
    fn mouse(&mut self, mouse: MouseEvent) -> UiAction {
        if mouse.modifiers.contains(KeyModifiers::SHIFT) {
            return UiAction::None;
        }
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                self.focus = Focus::Stream;
                self.transcript_offset += 3;
                UiAction::None
            }
            MouseEventKind::ScrollDown => {
                self.focus = Focus::Stream;
                self.transcript_offset = self.transcript_offset.saturating_sub(3);
                UiAction::None
            }
            MouseEventKind::Down(MouseButton::Left)
                if mouse.row >= self.viewport.1.saturating_sub(3) =>
            {
                if self.focus_attachment(0) {
                    self.focus = Focus::Input;
                    self.attachment_action(AttachmentAction::Inspect)
                } else {
                    UiAction::None
                }
            }
            MouseEventKind::Down(MouseButton::Left) => {
                self.selection = Some((mouse.row as usize, mouse.row as usize));
                self.focus = if self.viewport.0 >= 90 && mouse.column >= self.viewport.0 * 72 / 100
                {
                    Focus::Operations
                } else {
                    Focus::Stream
                };
                self.operations_open = true;
                UiAction::None
            }
            MouseEventKind::Drag(MouseButton::Left) => {
                if let Some((start, _)) = self.selection {
                    self.selection = Some((start, mouse.row as usize));
                }
                UiAction::None
            }
            MouseEventKind::Up(MouseButton::Left) => {
                if let Some((start, end)) = self.selection {
                    UiAction::Copy(self.copy_selection(start, end).copy_text())
                } else {
                    UiAction::None
                }
            }
            MouseEventKind::Down(MouseButton::Right)
                if mouse.row >= self.viewport.1.saturating_sub(3) =>
            {
                self.attachment_action(AttachmentAction::Remove)
            }
            MouseEventKind::Down(MouseButton::Right) => {
                self.focus = Focus::Input;
                UiAction::Copy(self.input.clone())
            }
            MouseEventKind::Down(MouseButton::Middle)
                if mouse.row >= self.viewport.1.saturating_sub(3) =>
            {
                self.attachment_action(AttachmentAction::Retry)
            }
            _ => UiAction::None,
        }
    }
    pub fn copy_selection(&self, start: usize, end: usize) -> UiAction {
        UiAction::Copy(
            self.transcript
                .iter()
                .skip(start.min(end))
                .take(start.abs_diff(end) + 1)
                .map(|x| x.body.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }
    pub fn focus_attachment(&mut self, index: usize) -> bool {
        if index < self.attachments.len() {
            self.focused_attachment = Some(index);
            true
        } else {
            false
        }
    }
    pub fn attachment_action(&self, action: AttachmentAction) -> UiAction {
        self.focused_attachment
            .and_then(|i| self.attachments.get(i))
            .map_or(UiAction::None, |chip| UiAction::Attachment {
                id: chip.id.clone(),
                action,
            })
    }
    pub fn remove_focused_attachment(&mut self) -> UiAction {
        if let Some(index) = self.focused_attachment {
            if index < self.attachments.len() {
                let id = self.attachments.remove(index).id;
                self.focused_attachment = if self.attachments.is_empty() {
                    None
                } else {
                    Some(index.min(self.attachments.len() - 1))
                };
                return UiAction::Attachment {
                    id,
                    action: AttachmentAction::Remove,
                };
            }
        }
        UiAction::None
    }
}

fn row_transcript_entry(row: &ConfirmedRow) -> TranscriptEntry {
    TranscriptEntry {
        source: row.kind.label().into(),
        body: row.text.as_str().into(),
        attention: row.attention,
        attachment: None,
    }
}

impl UiAction {
    fn copy_text(&self) -> String {
        match self {
            Self::Copy(text) => text.clone(),
            _ => String::new(),
        }
    }

    pub fn into_intent(self) -> Option<UiIntent> {
        match self {
            Self::None => None,
            Self::Submit(text) => Some(UiIntent::Submit(text)),
            Self::Paste(payload) => Some(UiIntent::Paste(payload)),
            Self::Copy(text) => Some(UiIntent::Copy(text)),
            Self::RetryConnection => Some(UiIntent::RetryConnection),
            Self::OpenPalette => Some(UiIntent::OpenPalette),
            Self::ToggleOperations => Some(UiIntent::ToggleOperations),
            Self::Quit => Some(UiIntent::Quit),
            Self::Resolve { id, allow } => Some(UiIntent::Resolve { id, allow }),
            Self::Attachment { id, action } => Some(UiIntent::Attachment { id, action }),
        }
    }
}
fn paste_payload(value: String) -> PastePayload {
    if value.len() > LARGE_PASTE {
        PastePayload::Blob {
            bytes: value.len(),
            preview: value.chars().take(512).collect(),
        }
    } else {
        PastePayload::Inline(value)
    }
}
pub fn attachment_chip(
    id: impl Into<String>,
    attachment: &Attachment,
    status: AttachmentStatus,
) -> AttachmentChip {
    let (kind, source, bytes, lines) = match attachment {
        Attachment::Text(text) => (
            AttachmentKind::Paste,
            "clipboard".into(),
            Some(text.len()),
            Some(text.lines().count()),
        ),
        Attachment::Png(data) | Attachment::Jpeg(data) => (
            AttachmentKind::Image,
            "image".into(),
            Some(data.len()),
            None,
        ),
        Attachment::Path(path) => (
            AttachmentKind::Path,
            path.rsplit('/').next().unwrap_or(path).into(),
            None,
            None,
        ),
        Attachment::File { name, bytes, lines } => (
            AttachmentKind::File,
            name.clone(),
            Some(*bytes),
            Some(*lines),
        ),
    };
    AttachmentChip {
        id: id.into(),
        kind,
        source,
        bytes,
        lines,
        status,
    }
}
pub fn attachment_metadata(chip: &AttachmentChip) -> String {
    match (chip.bytes, chip.lines) {
        (Some(bytes), Some(lines)) => format!("{} · {} lines", byte_label(bytes), lines),
        (Some(bytes), None) => byte_label(bytes),
        _ => String::new(),
    }
}
fn byte_label(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
fn attachment_kind_label(kind: AttachmentKind) -> &'static str {
    match kind {
        AttachmentKind::File => "File",
        AttachmentKind::Image => "Image",
        AttachmentKind::Paste => "Paste",
        AttachmentKind::Path => "Path",
    }
}
fn attachment_style(kind: AttachmentKind) -> Style {
    Style::default().fg(match kind {
        AttachmentKind::File => Color::Rgb(130, 150, 180),
        AttachmentKind::Image => Color::Rgb(145, 125, 175),
        AttachmentKind::Paste => Color::Rgb(175, 145, 90),
        AttachmentKind::Path => Color::Rgb(110, 145, 135),
    })
}
fn attachment_status_style(status: AttachmentStatus) -> Style {
    Style::default().fg(match status {
        AttachmentStatus::Ready => Color::DarkGray,
        AttachmentStatus::Pending => Color::Yellow,
        AttachmentStatus::Error => Color::Red,
    })
}
fn attachment_status_label(status: AttachmentStatus) -> &'static str {
    match status {
        AttachmentStatus::Ready => "",
        AttachmentStatus::Pending => " · pending",
        AttachmentStatus::Error => " · error",
    }
}
pub fn attachment_rows(chips: &[AttachmentChip], width: u16) -> Vec<Vec<usize>> {
    let mut rows = vec![Vec::new()];
    let mut used = 0u16;
    for (index, chip) in chips.iter().enumerate() {
        let size = attachment_width(chip);
        if used > 0 && used + size > width.max(1) {
            rows.push(Vec::new());
            used = 0;
        }
        rows.last_mut().unwrap().push(index);
        used = used.saturating_add(size);
    }
    rows
}
fn attachment_width(chip: &AttachmentChip) -> u16 {
    (attachment_kind_label(chip.kind).len()
        + chip.source.len()
        + attachment_metadata(chip).len()
        + 7)
    .min(u16::MAX as usize) as u16
}
fn upsert<T, F>(items: &mut Vec<T>, item: T, key: F)
where
    F: Fn(&T) -> &String,
{
    let id = key(&item).clone();
    if let Some(old) = items.iter_mut().find(|x| key(x) == &id) {
        *old = item;
    } else {
        items.push(item);
    }
}

pub fn osc52_copy(text: &str) -> io::Result<()> {
    let mut out = io::stdout();
    write!(out, "\x1b]52;c;{}\x07", base64(text.as_bytes()))?;
    out.flush()
}
pub fn enter_terminal() -> io::Result<()> {
    enable_raw_mode()?;
    if let Err(error) = execute!(io::stdout(), EnableMouseCapture, EnableBracketedPaste) {
        let _ = disable_raw_mode();
        return Err(error);
    }
    Ok(())
}
pub fn leave_terminal() -> io::Result<()> {
    let terminal_result = execute!(io::stdout(), DisableMouseCapture, DisableBracketedPaste);
    let raw_result = disable_raw_mode();
    terminal_result.and(raw_result)
}

/// Owns terminal mode for the duration of a runner. Dropping it always tries
/// to restore the terminal, including when rendering or input returns an
/// error.
pub struct TerminalGuard;

impl TerminalGuard {
    pub fn enter() -> io::Result<Self> {
        enter_terminal()?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = leave_terminal();
    }
}

pub trait UiSurface {
    fn draw(&mut self, app: &App) -> io::Result<()>;
}

pub struct CrosstermSurface {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl CrosstermSurface {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            terminal: Terminal::new(CrosstermBackend::new(io::stdout()))?,
        })
    }
}

impl UiSurface for CrosstermSurface {
    fn draw(&mut self, app: &App) -> io::Result<()> {
        self.terminal.draw(|frame| {
            let area = frame.size();
            render(frame, app, area);
        })?;
        Ok(())
    }
}

pub trait InputSource {
    fn poll(&mut self, timeout: Duration) -> io::Result<bool>;
    fn read(&mut self) -> io::Result<Option<InputEvent>>;
}

pub struct CrosstermInput;

impl InputSource for CrosstermInput {
    fn poll(&mut self, timeout: Duration) -> io::Result<bool> {
        event::poll(timeout)
    }

    fn read(&mut self) -> io::Result<Option<InputEvent>> {
        Ok(match event::read()? {
            Event::Key(key) => Some(InputEvent::Key(key)),
            Event::Mouse(mouse) => Some(InputEvent::Mouse(mouse)),
            Event::Paste(value) => Some(InputEvent::Paste(value)),
            Event::Resize(width, height) => Some(InputEvent::Resize(width, height)),
            Event::FocusGained | Event::FocusLost => None,
        })
    }
}

/// The terminal-side event loop. It only reduces typed UI events and emits
/// typed intents; network and SDK work belong to the composition layer.
pub struct TerminalRunner<S, I> {
    surface: S,
    input: I,
    inbound: UiEventReceiver,
    outbound: UiIntentSender,
    pending_retry: Option<UiIntent>,
    poll_timeout: Duration,
}

impl<S, I> TerminalRunner<S, I>
where
    S: UiSurface,
    I: InputSource,
{
    pub fn new(surface: S, input: I, inbound: UiEventReceiver, outbound: UiIntentSender) -> Self {
        Self {
            surface,
            input,
            inbound,
            outbound,
            pending_retry: None,
            poll_timeout: Duration::from_millis(50),
        }
    }

    pub fn with_poll_timeout(mut self, timeout: Duration) -> Self {
        self.poll_timeout = timeout;
        self
    }

    pub fn drain_inbound(&mut self, app: &mut App) -> usize {
        let mut count = 0;
        while count < INBOUND_EVENT_BUDGET {
            let Ok(event) = self.inbound.try_recv() else {
                break;
            };
            app.reduce_inbound(event);
            count += 1;
        }
        count
    }

    pub fn retry_pending(&self) -> bool {
        self.pending_retry.is_some()
    }

    fn flush_pending_retry(&mut self) {
        let Some(intent) = self.pending_retry.take() else {
            return;
        };
        match self.outbound.try_send(intent) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(intent)) => self.pending_retry = Some(intent),
        }
    }

    fn emit(&mut self, intent: UiIntent) {
        // A retained retry is always attempted before later ticks and takes
        // precedence over later external intents while the channel is full.
        if self.pending_retry.is_some() {
            return;
        }
        match self.outbound.try_send(intent) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(intent)) => {
                if matches!(&intent, UiIntent::RetryConnection) {
                    self.pending_retry = Some(intent);
                }
            }
        }
    }

    fn run_loop(&mut self, app: &mut App) -> io::Result<()> {
        loop {
            self.flush_pending_retry();
            self.drain_inbound(app);
            self.surface.draw(app)?;
            if !self.input.poll(self.poll_timeout)? {
                continue;
            }
            self.flush_pending_retry();
            let Some(input) = self.input.read()? else {
                continue;
            };
            let action = app.handle(input);
            let quit = matches!(action, UiAction::Quit);
            if let Some(intent) = action.into_intent() {
                self.emit(intent);
            }
            if quit {
                break;
            }
        }
        Ok(())
    }

    pub fn run(&mut self, app: &mut App) -> io::Result<()> {
        let _terminal_guard = TerminalGuard::enter()?;
        self.run_loop(app)
    }

    /// Run the same reducer/channel loop without changing terminal modes.
    /// This is intended for deterministic harnesses and embedded front ends.
    pub fn run_without_terminal(&mut self, app: &mut App) -> io::Result<()> {
        self.run_loop(app)
    }
}

fn base64(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in bytes.chunks(3) {
        let a = c[0] as u32;
        let b = *c.get(1).unwrap_or(&0) as u32;
        let d = *c.get(2).unwrap_or(&0) as u32;
        s.push(T[(a >> 2) as usize] as char);
        s.push(T[((a << 4 | b >> 4) & 63) as usize] as char);
        s.push(if c.len() > 1 {
            T[((b << 2 | d >> 6) & 63) as usize] as char
        } else {
            '='
        });
        s.push(if c.len() > 2 {
            T[(d & 63) as usize] as char
        } else {
            '='
        });
    }
    s
}

pub fn render(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let shell = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(area);
    frame.render_widget(
        Paragraph::new(header_line(app)).style(Style::default().bg(Color::Rgb(10, 11, 13))),
        shell[0],
    );
    if area.width < 60 || area.height < 16 {
        frame.render_widget(
            Paragraph::new(" terminal too small; resize to continue")
                .style(Style::default().fg(Color::Yellow)),
            shell[1],
        );
    } else {
        let body = if density(area.width) == Density::Narrow {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(8), Constraint::Min(5)])
                .split(shell[1])
        } else {
            Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(78), Constraint::Percentage(22)])
                .split(shell[1])
        };
        render_main(frame, app, body[0]);
        if app.operations_open {
            render_sidebar(frame, app, body[1]);
        }
    }
    render_composer(frame, app, shell[2]);
    if app.palette_open {
        let popup = Rect {
            x: area.x + area.width / 5,
            y: area.y + area.height / 4,
            width: area.width * 3 / 5,
            height: area.height / 2,
        };
        frame.render_widget(
            Paragraph::new(Text::from(vec![
                Line::styled("Command palette", Style::default().fg(Color::Gray)),
                Line::from("> focus approvals"),
                Line::from("  open Operations"),
                Line::from("  collapse sections"),
            ]))
            .block(Block::default().title(" Commands ").borders(Borders::ALL)),
            popup,
        );
    }
}

fn header_line(app: &App) -> Line<'static> {
    let mut spans = vec![
        Span::styled(" session ", Style::default().fg(Color::DarkGray)),
        Span::styled(app.title.clone(), Style::default().fg(Color::Gray)),
    ];
    if let Some(agent) = &app.foreground_agent {
        spans.push(Span::raw("  /  "));
        spans.push(Span::styled(
            agent.clone(),
            Style::default().fg(Color::Gray),
        ));
    }
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        connection_label(&app.connection),
        connection_style(&app.connection),
    ));
    spans.push(Span::raw("  "));
    spans.push(Span::styled(app.permission.label(), app.permission.style()));
    if app.permission == PermissionMode::Bypass {
        spans.push(Span::styled(
            "  NO ACTION CONFIRMATION",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }
    if app.pending_attention > 0 {
        spans.push(Span::styled(
            format!("  !{}", app.pending_attention),
            Style::default().fg(Color::Yellow),
        ));
    }
    Line::from(spans)
}

fn connection_label(state: &ConnectionState) -> String {
    match state {
        ConnectionState::Connecting => "connecting".into(),
        ConnectionState::Connected => "connected".into(),
        ConnectionState::Reconnecting {
            attempt,
            last_confirmed_at,
        } => match last_confirmed_at {
            Some(timestamp) => format!(
                "reconnecting {} · last confirmed {}",
                attempt,
                timestamp.as_str()
            ),
            None => format!("reconnecting {}", attempt),
        },
        ConnectionState::RetryPaused { attempt } => format!("retry paused {}", attempt),
        ConnectionState::Reconciling => "reconciling".into(),
        ConnectionState::Offline { reason, .. } => format!("offline · {}", reason.as_str()),
    }
}

fn connection_style(state: &ConnectionState) -> Style {
    match state {
        ConnectionState::Connected => Style::default().fg(Color::DarkGray),
        ConnectionState::Offline { .. } => Style::default().fg(Color::Red),
        _ => Style::default().fg(Color::Yellow),
    }
}

fn render_main(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let has_strip = !matches!(app.connection, ConnectionState::Connected);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if has_strip {
            vec![
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(1),
            ]
        } else {
            vec![Constraint::Length(1), Constraint::Min(1)]
        })
        .split(area);
    frame.render_widget(
        Paragraph::new(" stream / diff").style(Style::default().fg(Color::DarkGray)),
        rows[0],
    );
    let stream_row = if has_strip {
        frame.render_widget(
            Paragraph::new(reconnect_strip(app)).style(Style::default().fg(Color::Yellow)),
            rows[1],
        );
        2
    } else {
        1
    };
    let mut lines = Vec::new();
    for notice in app.local_notices.iter().rev().take(2).rev() {
        lines.push(Line::from(vec![
            Span::styled(" local ", Style::default().fg(Color::Yellow)),
            Span::raw(notice.text.as_str()),
        ]));
    }
    for request in app.pending_requests.iter().rev().take(2).rev() {
        lines.push(Line::from(vec![
            Span::styled(" pending ", Style::default().fg(Color::Yellow)),
            Span::raw(request.text.as_str()),
        ]));
    }
    let available = rows[stream_row].height.saturating_sub(2) as usize;
    let end = app.transcript.len().saturating_sub(app.transcript_offset);
    let start = end.saturating_sub(available.saturating_sub(lines.len()));
    for index in start..end {
        let item = &app.transcript[index];
        let provenance = app.transcript_provenance.get(index);
        match provenance {
            Some(TranscriptProvenance::Confirmed {
                confirmed_at,
                kind,
                identity: _,
            }) => lines.push(Line::from(vec![
                Span::styled(" confirmed ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    format!("{} {:<10} ", confirmed_at.as_str(), kind.label()),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(&item.body),
            ])),
            _ => lines.push(Line::from(vec![
                Span::styled(
                    format!(" {:<12} ", item.source),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(&item.body),
            ])),
        }
    }
    for diff in app.diffs.iter().rev().take(1) {
        lines.push(Line::styled(
            format!("  diff  {}", diff.path),
            Style::default()
                .fg(Color::Gray)
                .add_modifier(Modifier::BOLD),
        ));
        for line in diff.lines.iter().take(
            rows[stream_row]
                .height
                .saturating_sub(lines.len() as u16 + 2) as usize,
        ) {
            lines.push(diff_line(line, diff.side_by_side));
        }
    }
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::TOP | Borders::BOTTOM)
                .border_style(Style::default().fg(Color::Rgb(45, 47, 51))),
        ),
        rows[stream_row],
    );
}

fn reconnect_strip(app: &App) -> String {
    match &app.connection {
        ConnectionState::Connecting => " CONNECTING · events held".into(),
        ConnectionState::Connected => String::new(),
        ConnectionState::Reconnecting {
            attempt,
            last_confirmed_at,
        } => format!(
            " RECONNECTING · events held · attempt {}{} · r retry",
            attempt,
            last_confirmed_suffix(last_confirmed_at.as_ref()),
        ),
        ConnectionState::RetryPaused { attempt } => {
            format!(
                " RETRY PAUSED · events held · attempt {} · r retry",
                attempt
            )
        }
        ConnectionState::Reconciling => format!(
            " RECONCILING · replay staged · events held{}",
            last_confirmed_suffix(app.last_confirmed_at.as_ref())
        ),
        ConnectionState::Offline {
            reason,
            retryability: Retryability::Retryable,
        } => format!(
            " OFFLINE · {}{} · r retry",
            reason.as_str(),
            last_confirmed_suffix(app.last_confirmed_at.as_ref()),
        ),
        ConnectionState::Offline {
            reason,
            retryability: Retryability::Permanent,
        } => format!(
            " OFFLINE · {}{}",
            reason.as_str(),
            last_confirmed_suffix(app.last_confirmed_at.as_ref()),
        ),
    }
}

fn last_confirmed_suffix(timestamp: Option<&ConfirmedTimestamp>) -> String {
    timestamp
        .map(|value| format!(" · last confirmed {}", value.as_str()))
        .unwrap_or_default()
}
fn diff_line(line: &DiffLine, side_by_side: bool) -> Line<'static> {
    let tone = match line.kind {
        DiffKind::Added => Color::Rgb(115, 145, 105),
        DiffKind::Removed => Color::Rgb(160, 95, 90),
        DiffKind::Header => Color::Cyan,
        DiffKind::Context => Color::DarkGray,
    };
    let marker = match line.kind {
        DiffKind::Added => "+",
        DiffKind::Removed => "-",
        DiffKind::Header => "@",
        DiffKind::Context => " ",
    };
    let nums = if side_by_side {
        format!(
            "{:>4} {:>4} ",
            line.left.map_or(String::new(), |n| n.to_string()),
            line.right.map_or(String::new(), |n| n.to_string())
        )
    } else {
        format!(
            "{:>4} ",
            line.right
                .or(line.left)
                .map_or(String::new(), |n| n.to_string())
        )
    };
    Line::from(vec![
        Span::styled(nums, Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{} {}", marker, line.text),
            Style::default().fg(tone),
        ),
    ])
}
fn render_sidebar(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let mut lines = vec![Line::styled(
        " operations",
        Style::default()
            .fg(Color::Gray)
            .add_modifier(Modifier::BOLD),
    )];
    if let (Some(used), Some(limit)) = (&app.context_used, &app.context_limit) {
        lines.push(Line::styled(
            format!(" context  {} / {}", used, limit),
            Style::default().fg(Color::DarkGray),
        ));
    }
    if let Some(model) = &app.model {
        lines.push(Line::styled(
            format!(" model  {}", model),
            Style::default().fg(Color::DarkGray),
        ));
    }
    if app.context_used.is_some() || app.model.is_some() {
        lines.push(Line::from(""));
    }
    if !app.tasks.is_empty() {
        lines.push(Line::styled(
            format!(
                " todo                              {}/{}",
                app.tasks
                    .iter()
                    .filter(|x| x.status == TaskStatus::Done)
                    .count(),
                app.tasks.len()
            ),
            Style::default()
                .fg(Color::Gray)
                .add_modifier(Modifier::BOLD),
        ));
        for task in app.tasks.iter().take(14) {
            lines.push(Line::styled(
                format!(
                    "{}{} {}",
                    "  ".repeat(task.depth as usize),
                    task_icon(task.status, task.expanded),
                    task.title
                ),
                task_style(task.status),
            ));
        }
    }
    if !app.activities.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            " activity",
            Style::default().fg(Color::DarkGray),
        ));
        for item in app.activities.iter().rev().take(2) {
            lines.push(Line::styled(
                format!("  {}  {}", item.label, item.agent),
                Style::default().fg(Color::DarkGray),
            ));
        }
    }
    if !app.approvals.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            format!(" approvals                         {}", app.approvals.len()),
            Style::default().fg(Color::Yellow),
        ));
        for approval in app.approvals.iter().take(2) {
            lines.push(Line::styled(
                format!("  ! {}", approval.request),
                Style::default().fg(Color::Yellow),
            ));
        }
    }
    if let (Some(spent), Some(limit)) = (&app.budget_spent, &app.budget_limit) {
        lines.push(Line::from(""));
        let percent = app
            .budget_percent
            .map_or(String::new(), |value| format!("  {}%", value));
        lines.push(Line::styled(
            format!(" budget  {} / {}{}", spent, limit, percent),
            Style::default().fg(Color::DarkGray),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(
            Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::default().fg(Color::Rgb(45, 47, 51))),
        ),
        area,
    );
}
fn render_composer(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let send_status = if app.can_send() {
        ""
    } else if app.is_connected() {
        "    send unavailable"
    } else {
        "    send disabled"
    };
    let decision_status = if !app.approvals.is_empty() && !app.can_decide() {
        "    decisions unavailable"
    } else {
        ""
    };
    let mut lines = vec![Line::from(vec![
        Span::styled(" > ", Style::default().fg(Color::Cyan)),
        Span::raw(&app.input),
    ])];
    for row in attachment_rows(&app.attachments, area.width.saturating_sub(2)) {
        let mut spans = Vec::new();
        for index in row {
            let chip = &app.attachments[index];
            let focused = app.focused_attachment == Some(index);
            let base = if focused {
                Style::default()
                    .bg(Color::Rgb(38, 40, 44))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            spans.push(Span::styled(
                format!(" {} ", attachment_kind_label(chip.kind)),
                attachment_style(chip.kind).patch(base),
            ));
            spans.push(Span::styled(
                format!(
                    "{} {}{} ",
                    chip.source,
                    attachment_metadata(chip),
                    attachment_status_label(chip.status)
                ),
                attachment_status_style(chip.status).patch(base),
            ));
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled("attachments", Style::default().fg(Color::DarkGray)),
        Span::raw("    "),
        Span::styled(app.permission.label(), app.permission.style()),
        Span::styled("    Ctrl+K commands", Style::default().fg(Color::DarkGray)),
        Span::styled(send_status, Style::default().fg(Color::Yellow)),
        Span::styled(decision_status, Style::default().fg(Color::Yellow)),
    ]));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Color::Rgb(45, 47, 51))),
        ),
        area,
    );
}
fn task_icon(status: TaskStatus, expanded: bool) -> &'static str {
    match status {
        TaskStatus::Done => "[x]",
        TaskStatus::Running => "[~]",
        TaskStatus::Blocked => "[!]",
        TaskStatus::Failed => "[!]",
        TaskStatus::Queued => {
            if expanded {
                "[-]"
            } else {
                "[+]"
            }
        }
    }
}
fn task_style(status: TaskStatus) -> Style {
    match status {
        TaskStatus::Running => Style::default().fg(Color::Yellow),
        TaskStatus::Blocked | TaskStatus::Failed => Style::default().fg(Color::Red),
        TaskStatus::Done => Style::default().fg(Color::DarkGray),
        _ => Style::default().fg(Color::Gray),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn key(c: char) -> InputEvent {
        InputEvent::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
    }
    #[test]
    fn layout_breakpoints() {
        assert_eq!(density(89), Density::Narrow);
        assert_eq!(density(90), Density::Medium);
        assert_eq!(density(119), Density::Medium);
        assert_eq!(density(120), Density::Wide);
    }
    #[test]
    fn reducer_bounds_and_attention() {
        let mut a = App::default();
        for i in 0..MAX_TRANSCRIPT + 5 {
            a.reduce(ClientEvent::Transcript(TranscriptEntry {
                source: "x".into(),
                body: i.to_string(),
                attention: Attention::Silent,
                attachment: None,
            }));
        }
        assert_eq!(a.transcript.len(), MAX_TRANSCRIPT);
        a.reduce(ClientEvent::Approval(Approval {
            id: "1".into(),
            request: "run".into(),
            detail: String::new(),
        }));
        assert_eq!(a.pending_attention, 1);
    }
    #[test]
    fn large_paste_blob() {
        assert!(matches!(
            paste_payload("x".repeat(LARGE_PASTE + 1)),
            PastePayload::Blob { .. }
        ));
        assert!(matches!(
            paste_payload("x".repeat(LARGE_PASTE)),
            PastePayload::Inline(_)
        ));
    }
    #[test]
    fn permission_banner_is_explicit() {
        assert_eq!(PermissionMode::Bypass.banner(), "NO ACTION CONFIRMATION");
    }
    #[test]
    fn input_and_copy() {
        let mut a = App::default();
        a.handle(key('h'));
        a.handle(key('i'));
        assert_eq!(a.input, "hi");
        assert_eq!(a.copy_selection(0, 0), UiAction::Copy(String::new()));
    }
    #[test]
    fn mouse_scroll() {
        let mut a = App::default();
        a.handle(InputEvent::Mouse(MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 2,
            row: 2,
            modifiers: KeyModifiers::NONE,
        }));
        assert_eq!(a.transcript_offset, 3);
    }
    #[test]
    fn attachment_metadata_is_compact_and_bounded() {
        let chip = attachment_chip(
            "p",
            &Attachment::File {
                name: "src/main.rs".into(),
                bytes: 43_315,
                lines: 418,
            },
            AttachmentStatus::Ready,
        );
        assert_eq!(chip.kind, AttachmentKind::File);
        assert_eq!(attachment_metadata(&chip), "42.3 KiB · 418 lines");
        let paste = attachment_chip(
            "x",
            &Attachment::Text("a\nb".into()),
            AttachmentStatus::Ready,
        );
        assert_eq!(paste.source, "clipboard");
    }
    #[test]
    fn attachment_kind_and_status_are_distinct() {
        assert_ne!(
            attachment_style(AttachmentKind::Image),
            attachment_style(AttachmentKind::Paste)
        );
        assert_ne!(
            attachment_status_style(AttachmentStatus::Error),
            attachment_status_style(AttachmentStatus::Ready)
        );
    }
    #[test]
    fn attachment_rows_wrap_without_reordering() {
        let chips = vec![
            attachment_chip(
                "a",
                &Attachment::Path("one.txt".into()),
                AttachmentStatus::Ready,
            ),
            attachment_chip(
                "b",
                &Attachment::Path("two.txt".into()),
                AttachmentStatus::Ready,
            ),
        ];
        let rows = attachment_rows(&chips, 18);
        assert_eq!(rows, vec![vec![0], vec![1]]);
    }
    #[test]
    fn attachment_focus_and_actions_are_deterministic() {
        let mut app = App::default();
        app.attachments.push(attachment_chip(
            "a",
            &Attachment::Path("one.txt".into()),
            AttachmentStatus::Error,
        ));
        assert!(app.focus_attachment(0));
        assert_eq!(
            app.attachment_action(AttachmentAction::Inspect),
            UiAction::Attachment {
                id: "a".into(),
                action: AttachmentAction::Inspect
            }
        );
        assert_eq!(
            app.remove_focused_attachment(),
            UiAction::Attachment {
                id: "a".into(),
                action: AttachmentAction::Remove
            }
        );
        assert!(app.attachments.is_empty());
    }

    fn confirmed(id: &str, text: &str) -> UiEvent {
        UiEvent::Confirmed(ConfirmedEvent::new(
            ConfirmedEventId::new(id),
            ConfirmedTimestamp::new("10:42:18"),
            ConfirmedPresentation::new(ConfirmedPresentationKind::Agent, text),
        ))
    }

    #[test]
    fn reconnect_preserves_working_state_and_disables_controls() {
        let mut app = App::default();
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::Connected));
        app.reduce(ClientEvent::Task(Task {
            id: "task".into(),
            title: "preserve me".into(),
            depth: 0,
            status: TaskStatus::Running,
            done: 0,
            total: 1,
            expanded: true,
        }));
        app.reduce(ClientEvent::Approval(Approval {
            id: "approval".into(),
            request: "confirm".into(),
            detail: String::new(),
        }));
        app.input = "draft survives".into();
        app.focus = Focus::Operations;
        app.transcript_offset = 7;
        app.operations_open = false;
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::Reconnecting {
            attempt: 2,
            last_confirmed_at: Some(ConfirmedTimestamp::new("10:42:18")),
        }));
        assert!(!app.controls_enabled());
        assert_eq!(
            app.handle(InputEvent::Key(KeyEvent::new(
                KeyCode::Enter,
                KeyModifiers::NONE
            ))),
            UiAction::None
        );
        assert_eq!(app.input, "draft survives");
        assert_eq!(app.focus, Focus::Operations);
        assert_eq!(app.transcript_offset, 7);
        assert!(!app.operations_open);
        assert_eq!(app.tasks.len(), 1);
        assert_eq!(app.approvals.len(), 1);
        assert_eq!(app.resolve_approval("approval", true), UiAction::None);
    }

    #[test]
    fn connected_read_only_slice_preserves_draft_and_suppresses_decisions() {
        let mut app = App::default();
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::Connected));
        assert_eq!(app.capabilities, UiCapabilities::READ_ONLY);
        assert!(app.is_connected());
        assert!(!app.can_send());
        assert!(!app.can_decide());

        app.input = "read-only draft".into();
        assert_eq!(
            app.handle(InputEvent::Key(KeyEvent::new(
                KeyCode::Enter,
                KeyModifiers::NONE,
            ))),
            UiAction::None
        );
        assert_eq!(app.input, "read-only draft");

        app.reduce(ClientEvent::Approval(Approval {
            id: "approval".into(),
            request: "confirm".into(),
            detail: String::new(),
        }));
        assert_eq!(app.resolve_approval("approval", true), UiAction::None);
        assert_eq!(app.approvals.len(), 1);
        assert!(app.confirmed_rows.is_empty());
    }

    #[test]
    fn capability_enabled_connected_controls_take_or_emit_requests() {
        let mut app = App::default();
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::Connected));
        app.reduce_inbound(UiEvent::Capabilities(UiCapabilities::new(true, true)));
        assert!(app.can_send());
        assert!(app.can_decide());

        app.input = "send this".into();
        assert_eq!(
            app.handle(InputEvent::Key(KeyEvent::new(
                KeyCode::Enter,
                KeyModifiers::NONE,
            ))),
            UiAction::Submit("send this".into())
        );
        assert!(app.input.is_empty());
        assert_eq!(
            app.resolve_approval("approval", false),
            UiAction::Resolve {
                id: "approval".into(),
                allow: false,
            }
        );
    }

    #[test]
    fn permanent_offline_has_no_retry_affordance_or_intent() {
        let mut app = App {
            input: "preserved draft".into(),
            ..Default::default()
        };
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::Offline {
            reason: OfflineReason::new("terminal failure"),
            retryability: Retryability::Permanent,
        }));

        assert!(!app.retry_available());
        assert!(!reconnect_strip(&app).contains("r retry"));
        assert_eq!(
            app.handle(InputEvent::Key(KeyEvent::new(
                KeyCode::Char('r'),
                KeyModifiers::NONE,
            ))),
            UiAction::None
        );
        assert_eq!(app.input, "preserved draft");
    }

    #[test]
    fn retryable_offline_preserves_draft_and_emits_retry_intent() {
        let mut app = App {
            input: "preserved draft".into(),
            ..Default::default()
        };
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::Offline {
            reason: OfflineReason::new("temporary failure"),
            retryability: Retryability::Retryable,
        }));

        assert!(app.retry_available());
        assert!(reconnect_strip(&app).contains("r retry"));
        assert_eq!(
            app.handle(InputEvent::Key(KeyEvent::new(
                KeyCode::Char('r'),
                KeyModifiers::NONE,
            ))),
            UiAction::RetryConnection
        );
        assert_eq!(app.input, "preserved draft");
        assert_eq!(
            UiAction::RetryConnection.into_intent(),
            Some(UiIntent::RetryConnection)
        );
    }

    #[test]
    fn replace_reconciliation_keeps_newest_bounded_window_even_with_overlap() {
        let mut app = App::default();
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::Connected));
        app.reduce_inbound(confirmed("existing", "stale visible row"));
        let last_confirmed_at = app.last_confirmed_at.clone();
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::Reconnecting {
            attempt: 1,
            last_confirmed_at,
        }));
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::Reconciling {
            mode: ReconciliationMode::Replace,
        }));
        for index in 0..(MAX_TRANSCRIPT + 5) {
            let (id, text) = if index == MAX_TRANSCRIPT + 4 {
                (
                    "existing".to_owned(),
                    "replacement newest overlap".to_owned(),
                )
            } else {
                (format!("replace-{index}"), format!("replacement-{index}"))
            };
            app.reduce_inbound(UiEvent::Confirmed(ConfirmedEvent::new(
                ConfirmedEventId::new(id),
                ConfirmedTimestamp::new(index.to_string()),
                ConfirmedPresentation::new(ConfirmedPresentationKind::Agent, text),
            )));
        }

        assert_eq!(app.confirmed_rows.len(), 1);
        assert_eq!(
            app.confirmed_rows.front().unwrap().text.as_str(),
            "stale visible row"
        );
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::ReconciliationComplete));
        assert_eq!(app.confirmed_rows.len(), MAX_TRANSCRIPT);
        assert_eq!(app.transcript.len(), MAX_TRANSCRIPT);
        assert_eq!(
            app.confirmed_rows.front().unwrap().text.as_str(),
            "replacement-5"
        );
        assert_eq!(
            app.confirmed_rows.back().unwrap().text.as_str(),
            "replacement newest overlap"
        );
        assert_eq!(app.transcript.front().unwrap().body, "replacement-5");
        assert_eq!(
            app.transcript.back().unwrap().body,
            "replacement newest overlap"
        );
    }

    struct TestSurface {
        draws: usize,
    }

    impl UiSurface for TestSurface {
        fn draw(&mut self, _app: &App) -> io::Result<()> {
            self.draws += 1;
            Ok(())
        }
    }

    struct TestInput {
        events: VecDeque<InputEvent>,
        polls: usize,
    }

    impl InputSource for TestInput {
        fn poll(&mut self, _timeout: Duration) -> io::Result<bool> {
            self.polls += 1;
            Ok(true)
        }

        fn read(&mut self) -> io::Result<Option<InputEvent>> {
            Ok(self.events.pop_front())
        }
    }

    fn quit_input() -> InputEvent {
        InputEvent::Key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL))
    }

    #[test]
    fn runner_retains_retry_with_draft_when_outbound_is_full() {
        let (event_tx, event_rx, intent_tx, intent_rx) = channels(1);
        intent_tx.send(UiIntent::Copy("occupied".into())).unwrap();
        let mut runner = TerminalRunner::new(
            TestSurface { draws: 0 },
            TestInput {
                events: VecDeque::from([key('r'), quit_input()]),
                polls: 0,
            },
            event_rx,
            intent_tx,
        );
        let mut app = App {
            input: "draft retained".into(),
            ..Default::default()
        };
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::Reconnecting {
            attempt: 2,
            last_confirmed_at: None,
        }));

        runner.run_without_terminal(&mut app).unwrap();
        assert!(runner.retry_pending());
        assert_eq!(app.input, "draft retained");
        drop(event_tx);
        assert_eq!(intent_rx.try_recv(), Ok(UiIntent::Copy("occupied".into())));
        runner.flush_pending_retry();
        assert!(!runner.retry_pending());
        assert_eq!(intent_rx.try_recv(), Ok(UiIntent::RetryConnection));
    }

    #[test]
    fn runner_bounds_inbound_work_before_draw_and_input() {
        let (event_tx, event_rx, intent_tx, _intent_rx) = channels(INBOUND_EVENT_BUDGET + 1);
        for index in 0..(INBOUND_EVENT_BUDGET + 1) {
            event_tx
                .send(UiEvent::LocalNotice(LocalNotice::new(
                    LocalNoticeKind::Info,
                    index.to_string(),
                )))
                .unwrap();
        }
        let mut runner = TerminalRunner::new(
            TestSurface { draws: 0 },
            TestInput {
                events: VecDeque::from([quit_input()]),
                polls: 0,
            },
            event_rx,
            intent_tx,
        );
        let mut app = App::default();
        assert_eq!(runner.drain_inbound(&mut app), INBOUND_EVENT_BUDGET);
        assert_eq!(runner.drain_inbound(&mut app), 1);

        runner.run_without_terminal(&mut app).unwrap();
        assert_eq!(runner.surface.draws, 1);
        assert_eq!(runner.input.polls, 1);
    }

    #[test]
    fn replay_is_shadowed_until_atomic_reconciliation_commit() {
        let mut app = App::default();
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::Connected));
        app.reduce_inbound(confirmed("before", "already confirmed"));
        let last_confirmed_at = app.last_confirmed_at.clone();
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::Reconnecting {
            attempt: 1,
            last_confirmed_at,
        }));
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::BeginReconciliation));
        app.reduce_inbound(confirmed("replayed", "replayed once"));
        app.reduce_inbound(confirmed("replayed", "replayed duplicate"));
        assert_eq!(app.confirmed_rows.len(), 1);
        assert_eq!(app.reconciliation_shadow_len(), 1);
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::ReconciliationComplete));
        assert_eq!(app.confirmed_rows.len(), 2);
        assert_eq!(app.transcript.len(), 2);
        assert_eq!(app.reconciliation_shadow_len(), 0);
        app.reduce_inbound(confirmed("replayed", "replayed again"));
        assert_eq!(app.confirmed_rows.len(), 2);
    }

    #[test]
    fn confirmed_identity_dedupe_does_not_use_timestamp_or_text() {
        let mut app = App::default();
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::Connected));
        app.reduce_inbound(confirmed("same", "first"));
        app.reduce_inbound(UiEvent::Confirmed(ConfirmedEvent::new(
            ConfirmedEventId::new("same"),
            ConfirmedTimestamp::new("later"),
            ConfirmedPresentation::new(ConfirmedPresentationKind::Tool, "different"),
        )));
        assert_eq!(app.confirmed_rows.len(), 1);
        assert_eq!(app.confirmed_id_history_len(), 1);
    }

    #[test]
    fn provenance_keeps_local_and_pending_messages_out_of_confirmed_rows() {
        let mut app = App::default();
        app.reduce_inbound(UiEvent::Connection(ConnectionEvent::Connected));
        app.reduce_inbound(UiEvent::LocalNotice(LocalNotice::new(
            LocalNoticeKind::Reconnecting,
            "disconnected; last confirmed event 10:42:18",
        )));
        app.reduce_inbound(UiEvent::PendingRequest(PendingRequest::new(
            "request",
            PendingRequestKind::Submission,
            "requesting",
        )));
        assert!(app.transcript.is_empty());
        app.reduce_inbound(confirmed("confirmed", "daemon result"));
        assert_eq!(app.transcript.len(), 1);
        assert_eq!(app.confirmed_rows.len(), 1);
        assert_eq!(app.local_notices.len(), 1);
        assert_eq!(app.pending_requests.len(), 1);
    }

    #[test]
    fn render_state_omits_absent_metadata() {
        let app = App::default();
        assert!(app.budget_spent.is_none());
        assert!(app.budget_limit.is_none());
        assert!(app.context_used.is_none());
        assert!(app.context_limit.is_none());
        assert!(app.model.is_none());
        assert!(!reconnect_strip(&app).contains("connected"));
        assert!(!format!("{:?}", header_line(&app)).contains("MCP"));
        assert!(!format!("{:?}", header_line(&app)).contains("LSP"));
    }
}
