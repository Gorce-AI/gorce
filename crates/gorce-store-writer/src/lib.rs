#![forbid(unsafe_code)]

mod provider_registry;

pub use provider_registry::{
    ProviderRegistry, RegistryError, RegistryRegistration, MAX_PROVIDER_REGISTRY_BYTES,
    MAX_PROVIDER_REGISTRY_RECORDS, PROVIDER_DATA_FORMAT_VERSION, PROVIDER_REGISTRY_FILE,
    PROVIDER_REGISTRY_LOCK_FILE,
};

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use fs2::FileExt;
#[cfg(windows)]
use gorce_platform_security::SecureRuntime;
use gorce_protocol::{
    Admission, AuthorityCommandKind, AuthorityCommandReceipt, AuthorityPolicy, AuthorityPrincipal,
    AuthorityProfileRevision, BlobRef, CommandCommit, CommandResultKind, EventBatch, EventBatchId,
    EventRecord, GoalRevision, Message, OperatorBinding, PlanRevision, PolicyId, PrincipalId,
    ProfileRevisionId, ProjectId, ResourceKind, Task, TaskAttempt, TaskAttemptStatus, TaskEdge,
    TaskLifecycle, TaskReadiness, UuidV7, Workstream,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const STORAGE_FORMAT_VERSION: &str = "0.1";
pub const STATE_DIRECTORY: &str = ".gorce/state";
pub const JOURNAL_DIRECTORY: &str = "journal";
pub const BLOB_DIRECTORY: &str = "blobs";
pub const INDEX_FILE: &str = "index.sqlite3";
pub const WRITER_LOCK_FILE: &str = "writer.lock";
pub const JOURNAL_SEGMENT_LIMIT: u64 = 64 * 1024 * 1024;
pub const JOURNAL_SEGMENT_BYTES: u64 = JOURNAL_SEGMENT_LIMIT;
pub const MAX_JSONL_LINE_BYTES: usize = 1024 * 1024;
pub const MAX_PAGE_SIZE: usize = 500;
pub const MAX_BLOB_SIZE_BYTES: u64 = 25 * 1024 * 1024;
pub const DEFAULT_BLOB_MEDIA_TYPE: &str = "application/octet-stream";

const JOURNAL_SEGMENT_PREFIX: &str = "segment-";
const JOURNAL_SEGMENT_SUFFIX: &str = ".jsonl";
const INDEX_SCHEMA_VERSION: i64 = 5;
const MAX_METADATA_VALUE_BYTES: usize = 16 * 1024;
const COPY_BUFFER_SIZE: usize = 64 * 1024;
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

type AuthorityReceiptRow = (String, String, String, String, String, String, u64);

pub fn storage_format_version() -> &'static str {
    let _ = gorce_core::core_version();
    STORAGE_FORMAT_VERSION
}

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Json(serde_json::Error),
    Sqlite(rusqlite::Error),
    InvalidArgument(String),
    InvalidFormat(String),
    BatchValidation(String),
    SemanticProjection {
        batch_sequence: u64,
        event_ordinal: u64,
        event_type: String,
        schema_version: u64,
        reason: String,
    },
    JournalCorrupt {
        segment: String,
        offset: u64,
        reason: String,
    },
    SequenceGap {
        expected: u64,
        actual: u64,
        segment: String,
        offset: u64,
    },
    ProjectMismatch {
        expected: ProjectId,
        actual: ProjectId,
    },
    DuplicateBatchId {
        batch_id: EventBatchId,
    },
    SequenceConflict {
        sequence: u64,
        batch_id: EventBatchId,
    },
    IdempotencyConflict {
        key: String,
    },
    AuthorityIdempotencyConflict {
        principal_id: PrincipalId,
        key: String,
    },
    StoreAlreadyLocked {
        path: PathBuf,
    },
    SymlinkRejected {
        path: PathBuf,
    },
    PathEscape {
        path: PathBuf,
    },
    IndexIncompatible(String),
    BlobDigestMismatch {
        expected: String,
        actual: String,
    },
    BlobSizeMismatch {
        expected: u64,
        actual: u64,
    },
    BlobTooLarge {
        limit: u64,
    },
    MissingBlob {
        digest: String,
    },
    NeedsRecovery {
        reason: String,
    },
    LockPoisoned,
    FaultInjected(&'static str),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
            Self::Sqlite(error) => write!(formatter, "SQLite error: {error}"),
            Self::InvalidArgument(message) => write!(formatter, "invalid argument: {message}"),
            Self::InvalidFormat(message) => write!(formatter, "invalid storage format: {message}"),
            Self::BatchValidation(message) => write!(formatter, "invalid event batch: {message}"),
            Self::SemanticProjection {
                batch_sequence,
                event_ordinal,
                event_type,
                schema_version,
                reason,
            } => write!(
                formatter,
                "unsupported event at batch {batch_sequence}, ordinal {event_ordinal} ({event_type}/v{schema_version}): {reason}"
            ),
            Self::JournalCorrupt {
                segment,
                offset,
                reason,
            } => write!(
                formatter,
                "journal corruption in {segment} at byte {offset}: {reason}"
            ),
            Self::SequenceGap {
                expected,
                actual,
                segment,
                offset,
            } => write!(
                formatter,
                "journal sequence gap in {segment} at byte {offset}: expected {expected}, got {actual}"
            ),
            Self::ProjectMismatch { expected, actual } => {
                write!(formatter, "project mismatch: expected {expected}, got {actual}")
            }
            Self::DuplicateBatchId { batch_id } => write!(formatter, "duplicate batch id {batch_id:?}"),
            Self::SequenceConflict { sequence, batch_id } => {
                write!(formatter, "sequence {sequence} already belongs to batch {batch_id:?}")
            }
            Self::IdempotencyConflict { key } => {
                write!(formatter, "idempotency key is already bound to a different command: {key}")
            }
            Self::AuthorityIdempotencyConflict { principal_id, key } => write!(
                formatter,
                "authority idempotency key is already bound to a different command for principal {principal_id}: {key}"
            ),
            Self::StoreAlreadyLocked { path } => write!(formatter, "store is already locked: {}", path.display()),
            Self::SymlinkRejected { path } => write!(formatter, "symlink is not allowed: {}", path.display()),
            Self::PathEscape { path } => write!(formatter, "path escapes the state root: {}", path.display()),
            Self::IndexIncompatible(message) => write!(formatter, "incompatible index: {message}"),
            Self::BlobDigestMismatch { expected, actual } => {
                write!(formatter, "blob digest mismatch: expected {expected}, got {actual}")
            }
            Self::BlobSizeMismatch { expected, actual } => {
                write!(formatter, "blob size mismatch: expected {expected}, got {actual}")
            }
            Self::BlobTooLarge { limit } => write!(formatter, "blob exceeds {limit} bytes"),
            Self::MissingBlob { digest } => write!(formatter, "referenced blob is missing: {digest}"),
            Self::NeedsRecovery { reason } => write!(formatter, "store needs recovery: {reason}"),
            Self::LockPoisoned => write!(formatter, "storage lock is poisoned"),
            Self::FaultInjected(point) => write!(formatter, "injected storage failure at {point}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;
pub type StorageError = StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterState {
    Healthy,
    NeedsRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityState {
    Empty,
    Ready,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchLocation {
    segment: String,
    byte_offset: u64,
    byte_length: u64,
    batch_sequence: u64,
    batch_id: EventBatchId,
}

impl BatchLocation {
    pub fn segment(&self) -> &str {
        &self.segment
    }

    pub fn byte_offset(&self) -> u64 {
        self.byte_offset
    }

    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub fn batch_sequence(&self) -> u64 {
        self.batch_sequence
    }

    pub fn batch_id(&self) -> EventBatchId {
        self.batch_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventLocation {
    batch_sequence: u64,
    batch_id: EventBatchId,
    event_ordinal: u64,
    event_type: String,
    schema_version: u64,
    segment: String,
    byte_offset: u64,
    byte_length: u64,
    data_digest: String,
}

impl EventLocation {
    pub fn batch_sequence(&self) -> u64 {
        self.batch_sequence
    }

    pub fn batch_id(&self) -> EventBatchId {
        self.batch_id
    }

    pub fn event_ordinal(&self) -> u64 {
        self.event_ordinal
    }

    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    pub fn schema_version(&self) -> u64 {
        self.schema_version
    }

    pub fn segment(&self) -> &str {
        &self.segment
    }

    pub fn byte_offset(&self) -> u64 {
        self.byte_offset
    }

    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub fn data_digest(&self) -> &str {
        &self.data_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendResult {
    pub location: BatchLocation,
    pub index_watermark: u64,
    pub duplicate: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HistoryEntry {
    pub batch: EventBatch,
    pub location: BatchLocation,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HistoryPage {
    pub entries: Vec<HistoryEntry>,
    pub next_sequence: Option<u64>,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataEntry {
    pub key: String,
    pub value: String,
    pub batch_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticSnapshot {
    pub digest: String,
    pub counts: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthorityCommandRecord {
    pub principal_id: PrincipalId,
    pub idempotency_key: String,
    pub command_digest: String,
    pub result: CommandCommit,
}

fn lock<'a, T>(mutex: &'a Mutex<T>) -> Result<MutexGuard<'a, T>> {
    mutex.lock().map_err(|_| StoreError::LockPoisoned)
}

fn canonical_project_root(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(StoreError::SymlinkRejected {
            path: path.to_owned(),
        });
    }
    if !metadata.is_dir() {
        return Err(StoreError::InvalidArgument(format!(
            "project root is not a directory: {}",
            path.display()
        )));
    }
    Ok(fs::canonicalize(path)?)
}

fn ensure_directory(path: &Path, bound: &Path) -> Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(StoreError::SymlinkRejected {
                    path: path.to_owned(),
                });
            }
            if !metadata.is_dir() {
                return Err(StoreError::InvalidFormat(format!(
                    "expected directory: {}",
                    path.display()
                )));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    let canonical = fs::canonicalize(path)?;
    if !canonical.starts_with(bound) {
        return Err(StoreError::PathEscape { path: canonical });
    }
    set_directory_mode(&canonical)?;
    Ok(canonical)
}

fn ensure_regular_file(path: &Path, bound: &Path, allow_missing: bool) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(StoreError::SymlinkRejected {
                    path: path.to_owned(),
                });
            }
            if !metadata.is_file() {
                return Err(StoreError::InvalidFormat(format!(
                    "expected regular file: {}",
                    path.display()
                )));
            }
            let canonical = fs::canonicalize(path)?;
            if !canonical.starts_with(bound) {
                return Err(StoreError::PathEscape { path: canonical });
            }
            set_file_mode(path)?;
            Ok(true)
        }
        Err(error) if allow_missing && error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn set_directory_mode(path: &Path) -> Result<()> {
    #[cfg(not(unix))]
    let _ = path;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_file_mode(path: &Path) -> Result<()> {
    #[cfg(not(unix))]
    let _ = path;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        // Windows has no Unix-equivalent directory fsync. File contents are
        // flushed by the existing file sync/write-through paths; directory
        // entry durability is explicitly best effort on this platform.
        let _ = path;
        Ok(())
    }
    #[cfg(not(windows))]
    File::open(path)?.sync_all()?;
    #[cfg(not(windows))]
    Ok(())
}

#[cfg(windows)]
fn open_protected_state(path: &Path) -> Result<SecureRuntime> {
    SecureRuntime::open(path).map_err(|error| {
        StoreError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            error.to_string(),
        ))
    })
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::InvalidArgument("path has no parent".to_owned()))?;
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .ok_or_else(|| StoreError::InvalidArgument("path has no file name".to_owned()))?;
    let temporary = parent.join(format!(".{}.{}.tmp", name.to_string_lossy(), counter));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        set_file_mode(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn is_lock_contention(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    {
        matches!(error.raw_os_error(), Some(32 | 33))
    }
    #[cfg(not(windows))]
    {
        false
    }
}

struct StateLayout {
    state: PathBuf,
    journal: PathBuf,
    blobs: PathBuf,
    cas: PathBuf,
    tmp: PathBuf,
    index: PathBuf,
    lock: PathBuf,
    #[cfg(windows)]
    _state_security: SecureRuntime,
    #[cfg(windows)]
    _journal_security: SecureRuntime,
    #[cfg(windows)]
    _blobs_security: SecureRuntime,
    #[cfg(windows)]
    _cas_security: SecureRuntime,
    #[cfg(windows)]
    _tmp_security: SecureRuntime,
}

impl StateLayout {
    fn create(project_root: &Path) -> Result<Self> {
        let gorce = ensure_directory(&project_root.join(".gorce"), project_root)?;
        let state_path = gorce.join("state");
        #[cfg(windows)]
        let state_security = open_protected_state(&state_path)?;
        #[cfg(windows)]
        let state = state_path;
        #[cfg(not(windows))]
        let state = ensure_directory(&state_path, project_root)?;

        let journal_path = state.join(JOURNAL_DIRECTORY);
        let blobs_path = state.join(BLOB_DIRECTORY);
        #[cfg(windows)]
        let journal_security = open_protected_state(&journal_path)?;
        #[cfg(windows)]
        let journal = journal_path;
        #[cfg(not(windows))]
        let journal = ensure_directory(&journal_path, &state)?;

        #[cfg(windows)]
        let blobs_security = open_protected_state(&blobs_path)?;
        #[cfg(windows)]
        let blobs = blobs_path;
        #[cfg(not(windows))]
        let blobs = ensure_directory(&blobs_path, &state)?;

        let cas_path = blobs.join("sha256");
        let tmp_path = blobs.join("tmp");
        #[cfg(windows)]
        let cas_security = open_protected_state(&cas_path)?;
        #[cfg(windows)]
        let cas = cas_path;
        #[cfg(not(windows))]
        let cas = ensure_directory(&cas_path, &state)?;
        #[cfg(windows)]
        let tmp_security = open_protected_state(&tmp_path)?;
        #[cfg(windows)]
        let tmp = tmp_path;
        #[cfg(not(windows))]
        let tmp = ensure_directory(&tmp_path, &state)?;
        let index = state.join(INDEX_FILE);
        let lock = state.join(WRITER_LOCK_FILE);
        ensure_regular_file(&index, &state, true)?;
        ensure_regular_file(&lock, &state, true)?;
        let format = state.join("format-version");
        if ensure_regular_file(&format, &state, true)? {
            let contents = fs::read_to_string(&format)?;
            if contents.trim_end_matches(&['\r', '\n'][..]) != STORAGE_FORMAT_VERSION {
                return Err(StoreError::InvalidFormat(format!(
                    "unsupported storage version in {}",
                    format.display()
                )));
            }
        } else {
            atomic_write(&format, format!("{STORAGE_FORMAT_VERSION}\n").as_bytes())?;
            set_file_mode(&format)?;
        }
        Ok(Self {
            state,
            journal,
            blobs,
            cas,
            tmp,
            index,
            lock,
            #[cfg(windows)]
            _state_security: state_security,
            #[cfg(windows)]
            _journal_security: journal_security,
            #[cfg(windows)]
            _blobs_security: blobs_security,
            #[cfg(windows)]
            _cas_security: cas_security,
            #[cfg(windows)]
            _tmp_security: tmp_security,
        })
    }
}

/// The operating system releases this advisory lock when the process exits.
struct WriterLock {
    file: File,
    path: PathBuf,
}

impl WriterLock {
    fn acquire(path: &Path, state: &Path) -> Result<Self> {
        ensure_regular_file(path, state, true)?;
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if is_lock_contention(&error) => {
                return Err(StoreError::StoreAlreadyLocked {
                    path: path.to_owned(),
                })
            }
            Err(error) => return Err(error.into()),
        };
        set_file_mode(path)?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Self {
                file,
                path: path.to_owned(),
            }),
            Err(error) if is_lock_contention(&error) => Err(StoreError::StoreAlreadyLocked {
                path: path.to_owned(),
            }),
            Err(error) => Err(error.into()),
        }
    }
}

impl Drop for WriterLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
        let _ = &self.path;
    }
}

#[derive(Debug, Clone)]
struct SegmentMeta {
    number: u64,
    path: PathBuf,
    length: u64,
}

#[derive(Debug, Clone)]
struct JournalHead {
    next_sequence: u64,
    current_segment: u64,
    current_length: u64,
    last_batch_id: Option<EventBatchId>,
    last_command_digest: Option<String>,
}

struct Journal {
    directory: PathBuf,
    max_segment_bytes: u64,
    segments: Vec<SegmentMeta>,
    head: JournalHead,
}

impl Journal {
    fn open(directory: &Path, max_segment_bytes: u64) -> Result<Self> {
        if max_segment_bytes == 0 {
            return Err(StoreError::InvalidArgument(
                "journal segment limit must be positive".to_owned(),
            ));
        }
        let mut files = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(StoreError::SymlinkRejected { path });
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(number) = parse_segment_number(&name) {
                if !metadata.is_file() || segment_file_name(number) != name {
                    return Err(StoreError::InvalidFormat(format!(
                        "invalid journal segment: {name}"
                    )));
                }
                let canonical = fs::canonicalize(&path)?;
                let root = fs::canonicalize(directory)?;
                if !canonical.starts_with(&root) {
                    return Err(StoreError::PathEscape { path: canonical });
                }
                set_file_mode(&path)?;
                files.push((number, path));
            } else if name.ends_with(JOURNAL_SEGMENT_SUFFIX) {
                return Err(StoreError::InvalidFormat(format!(
                    "invalid journal segment name: {name}"
                )));
            } else if metadata.is_file() {
                return Err(StoreError::InvalidFormat(format!(
                    "unexpected journal file: {name}"
                )));
            }
        }
        files.sort_by_key(|(number, _)| *number);
        for pair in files.windows(2) {
            if pair[1].0 != pair[0].0 + 1 {
                return Err(StoreError::InvalidFormat(
                    "journal segment number gap".to_owned(),
                ));
            }
        }
        if let Some((first, _)) = files.first() {
            if *first != 1 {
                return Err(StoreError::InvalidFormat(
                    "journal must start at segment 1".to_owned(),
                ));
            }
        }
        let mut expected = 1;
        let mut last_batch_id = None;
        let mut last_command_digest = None;
        let mut segments = Vec::new();
        for (index, (number, path)) in files.iter().enumerate() {
            let last = index + 1 == files.len();
            let length = scan_segment(path, last, *number, expected, &mut |batch, _location| {
                expected = batch.batch_sequence.saturating_add(1);
                last_batch_id = Some(batch.batch_id);
                last_command_digest = Some(command_digest(batch)?);
                Ok(())
            })?;
            segments.push(SegmentMeta {
                number: *number,
                path: path.to_owned(),
                length,
            });
        }
        let current_segment = segments.last().map_or(1, |segment| segment.number);
        let current_length = segments.last().map_or(0, |segment| segment.length);
        Ok(Self {
            directory: directory.to_owned(),
            max_segment_bytes,
            segments,
            head: JournalHead {
                next_sequence: expected,
                current_segment,
                current_length,
                last_batch_id,
                last_command_digest,
            },
        })
    }

    fn last_sequence(&self) -> u64 {
        self.head.next_sequence.saturating_sub(1)
    }

    fn next_sequence(&self) -> u64 {
        self.head.next_sequence
    }

    fn head_fingerprint(&self) -> Option<(EventBatchId, String)> {
        self.head
            .last_batch_id
            .zip(self.head.last_command_digest.clone())
    }

    fn append(&mut self, batch: &EventBatch) -> Result<BatchLocation> {
        batch
            .validate()
            .map_err(|error| StoreError::BatchValidation(error.to_string()))?;
        if batch.batch_sequence != self.head.next_sequence {
            return Err(StoreError::SequenceGap {
                expected: self.head.next_sequence,
                actual: batch.batch_sequence,
                segment: segment_file_name(self.head.current_segment),
                offset: self.head.current_length,
            });
        }
        let mut encoded = BoundedBuffer::new(MAX_JSONL_LINE_BYTES);
        serde_json::to_writer(&mut encoded, batch).map_err(|error| {
            if error.is_io() {
                StoreError::InvalidArgument(format!(
                    "journal line exceeds {MAX_JSONL_LINE_BYTES} bytes"
                ))
            } else {
                StoreError::Json(error)
            }
        })?;
        encoded.write_all(b"\n")?;
        let encoded_length = encoded.len() as u64;
        if self.head.current_length > 0
            && self.head.current_length.saturating_add(encoded_length) > self.max_segment_bytes
        {
            self.head.current_segment = self.head.current_segment.saturating_add(1);
            self.head.current_length = 0;
            let path = self.segment_path(self.head.current_segment);
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            set_file_mode(&path)?;
            file.sync_all()?;
            sync_directory(&self.directory)?;
            self.segments.push(SegmentMeta {
                number: self.head.current_segment,
                path,
                length: 0,
            });
        }
        let path = self.segment_path(self.head.current_segment);
        ensure_regular_file(&path, &self.directory, true)?;
        if self.segments.is_empty() {
            self.segments.push(SegmentMeta {
                number: self.head.current_segment,
                path: path.clone(),
                length: 0,
            });
        }
        let offset = self.head.current_length;
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        file.write_all(encoded.as_slice())?;
        file.sync_all()?;
        sync_directory(&self.directory)?;
        let location = BatchLocation {
            segment: segment_file_name(self.head.current_segment),
            byte_offset: offset,
            byte_length: encoded_length,
            batch_sequence: batch.batch_sequence,
            batch_id: batch.batch_id,
        };
        self.head.current_length = self.head.current_length.saturating_add(encoded_length);
        self.head.next_sequence = self.head.next_sequence.saturating_add(1);
        self.head.last_batch_id = Some(batch.batch_id);
        self.head.last_command_digest = Some(command_digest(batch)?);
        if let Some(segment) = self.segments.last_mut() {
            segment.length = self.head.current_length;
        }
        Ok(location)
    }

    fn for_each_batch<F>(&self, mut callback: F) -> Result<()>
    where
        F: FnMut(&EventBatch, &BatchLocation) -> Result<()>,
    {
        let mut expected = 1;
        for (index, segment) in self.segments.iter().enumerate() {
            scan_segment(
                &segment.path,
                index + 1 == self.segments.len(),
                segment.number,
                expected,
                &mut |batch, location| {
                    expected = batch.batch_sequence.saturating_add(1);
                    callback(batch, location)
                },
            )?;
        }
        Ok(())
    }

    fn page(&self, after_sequence: u64, limit: usize) -> Result<HistoryPage> {
        let limit = limit.min(MAX_PAGE_SIZE);
        let mut entries = Vec::with_capacity(limit);
        let mut expected = 1;
        let mut has_more = false;
        for (index, segment) in self.segments.iter().enumerate() {
            scan_segment(
                &segment.path,
                index + 1 == self.segments.len(),
                segment.number,
                expected,
                &mut |batch, location| {
                    expected = batch.batch_sequence.saturating_add(1);
                    if batch.batch_sequence > after_sequence {
                        if entries.len() < limit {
                            entries.push(HistoryEntry {
                                batch: batch.clone(),
                                location: location.clone(),
                            });
                        } else {
                            has_more = true;
                        }
                    }
                    Ok(())
                },
            )?;
            if has_more {
                break;
            }
        }
        let next_sequence = entries.last().map(|entry| entry.batch.batch_sequence);
        Ok(HistoryPage {
            entries,
            next_sequence,
            has_more,
        })
    }

    fn segment_path(&self, number: u64) -> PathBuf {
        self.directory.join(segment_file_name(number))
    }
}

fn segment_file_name(number: u64) -> String {
    format!("{JOURNAL_SEGMENT_PREFIX}{number:020}{JOURNAL_SEGMENT_SUFFIX}")
}

fn parse_segment_number(name: &str) -> Option<u64> {
    name.strip_prefix(JOURNAL_SEGMENT_PREFIX)
        .and_then(|value| value.strip_suffix(JOURNAL_SEGMENT_SUFFIX))
        .and_then(|value| value.parse().ok())
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(8192)),
            limit,
        }
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bounded buffer limit exceeded",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn read_bounded_line(reader: &mut BufReader<File>) -> Result<Option<(Vec<u8>, u64, bool)>> {
    let mut line = Vec::new();
    let mut total = 0usize;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some((line, total as u64, false)))
            };
        }
        if let Some(index) = buffer.iter().position(|byte| *byte == b'\n') {
            let count = index + 1;
            if total.saturating_add(count) > MAX_JSONL_LINE_BYTES {
                return Err(StoreError::InvalidArgument(format!(
                    "journal line exceeds {MAX_JSONL_LINE_BYTES} bytes"
                )));
            }
            line.extend_from_slice(&buffer[..count]);
            reader.consume(count);
            total += count;
            return Ok(Some((line, total as u64, true)));
        }
        if total.saturating_add(buffer.len()) > MAX_JSONL_LINE_BYTES {
            return Err(StoreError::InvalidArgument(format!(
                "journal line exceeds {MAX_JSONL_LINE_BYTES} bytes"
            )));
        }
        line.extend_from_slice(buffer);
        total += buffer.len();
        let count = buffer.len();
        reader.consume(count);
    }
}

fn scan_segment<F>(
    path: &Path,
    is_last: bool,
    number: u64,
    mut expected: u64,
    callback: &mut F,
) -> Result<u64>
where
    F: FnMut(&EventBatch, &BatchLocation) -> Result<()>,
{
    let segment = segment_file_name(number);
    let mut reader = BufReader::new(File::open(path)?);
    let mut offset = 0_u64;
    loop {
        let Some((mut line, line_length, complete)) = read_bounded_line(&mut reader)? else {
            break;
        };
        if !complete {
            if !is_last {
                return Err(StoreError::JournalCorrupt {
                    segment,
                    offset,
                    reason: "incomplete line before the final segment".to_owned(),
                });
            }
            drop(reader);
            let file = OpenOptions::new().write(true).open(path)?;
            file.set_len(offset)?;
            file.sync_all()?;
            sync_directory(path.parent().ok_or_else(|| {
                StoreError::InvalidArgument("journal segment has no parent".to_owned())
            })?)?;
            return Ok(offset);
        }
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let batch: EventBatch =
            serde_json::from_slice(&line).map_err(|error| StoreError::JournalCorrupt {
                segment: segment.clone(),
                offset,
                reason: error.to_string(),
            })?;
        batch
            .validate()
            .map_err(|error| StoreError::JournalCorrupt {
                segment: segment.clone(),
                offset,
                reason: error.to_string(),
            })?;
        if batch.batch_sequence != expected {
            return Err(StoreError::SequenceGap {
                expected,
                actual: batch.batch_sequence,
                segment: segment.clone(),
                offset,
            });
        }
        let location = BatchLocation {
            segment: segment.clone(),
            byte_offset: offset,
            byte_length: line_length,
            batch_sequence: batch.batch_sequence,
            batch_id: batch.batch_id,
        };
        callback(&batch, &location)?;
        expected = expected.saturating_add(1);
        offset = offset.saturating_add(line_length);
    }
    Ok(offset)
}

pub struct BlobStore {
    directory: PathBuf,
    cas: PathBuf,
    tmp: PathBuf,
}

impl BlobStore {
    fn from_layout(layout: &StateLayout) -> Result<Self> {
        Ok(Self {
            directory: layout.blobs.clone(),
            cas: layout.cas.clone(),
            tmp: layout.tmp.clone(),
        })
    }

    pub fn new(directory: impl AsRef<Path>) -> Result<Self> {
        let directory = directory.as_ref().to_path_buf();
        let root = canonical_project_root(&directory)?;
        let cas = ensure_directory(&root.join("sha256"), &root)?;
        let tmp = ensure_directory(&root.join("tmp"), &root)?;
        Ok(Self {
            directory: root,
            cas,
            tmp,
        })
    }

    pub fn for_state_directory(state_dir: impl AsRef<Path>) -> Result<Self> {
        let state = canonical_project_root(state_dir.as_ref())?;
        let blobs = ensure_directory(&state.join(BLOB_DIRECTORY), &state)?;
        let cas = ensure_directory(&blobs.join("sha256"), &state)?;
        let tmp = ensure_directory(&blobs.join("tmp"), &state)?;
        Ok(Self {
            directory: blobs,
            cas,
            tmp,
        })
    }

    pub fn from_state_directory(state_dir: impl AsRef<Path>) -> Result<Self> {
        Self::for_state_directory(state_dir)
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn put<R: Read>(&self, reader: R) -> Result<BlobRef> {
        self.put_with_metadata(reader, DEFAULT_BLOB_MEDIA_TYPE, None)
    }

    pub fn put_reader<R: Read>(&self, reader: R, media_type: impl Into<String>) -> Result<BlobRef> {
        self.put_with_metadata(reader, media_type, None)
    }

    pub fn put_stream<R: Read>(
        &self,
        reader: R,
        media_type: impl Into<String>,
        filename: Option<String>,
    ) -> Result<BlobRef> {
        self.put_with_metadata(reader, media_type, filename)
    }

    pub fn put_with_metadata<R: Read>(
        &self,
        mut reader: R,
        media_type: impl Into<String>,
        filename: Option<String>,
    ) -> Result<BlobRef> {
        let temporary = self.tmp.join(format!(
            "blob-{}-{}.tmp",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            set_file_mode(&temporary)?;
            let mut hasher = Sha256::new();
            let mut buffer = [0_u8; COPY_BUFFER_SIZE];
            let mut size = 0_u64;
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                size = size.saturating_add(read as u64);
                if size > MAX_BLOB_SIZE_BYTES {
                    return Err(StoreError::BlobTooLarge {
                        limit: MAX_BLOB_SIZE_BYTES,
                    });
                }
                output.write_all(&buffer[..read])?;
                hasher.update(&buffer[..read]);
            }
            output.sync_all()?;
            let digest = format!("sha256:{:x}", hasher.finalize());
            let blob = BlobRef {
                digest: digest.clone(),
                size_bytes: size,
                media_type: media_type.into(),
                filename,
            };
            blob.validate()
                .map_err(|error| StoreError::BatchValidation(error.to_string()))?;
            let destination = self.path_for_digest(&digest)?;
            if ensure_regular_file(&destination, &self.directory, true)? {
                verify_blob_file(&destination, &digest, size)?;
                fs::remove_file(&temporary)?;
            } else {
                fs::rename(&temporary, &destination)?;
                set_file_mode(&destination)?;
                sync_directory(&self.cas)?;
                sync_directory(&self.directory)?;
            }
            Ok(blob)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub fn put_bytes(&self, bytes: &[u8]) -> Result<BlobRef> {
        self.put(bytes)
    }

    pub fn path_for_digest(&self, digest: &str) -> Result<PathBuf> {
        let hex = digest_hex(digest)?;
        Ok(self.cas.join(hex))
    }

    pub fn contains(&self, digest: &str) -> Result<bool> {
        let path = self.path_for_digest(digest)?;
        Ok(ensure_regular_file(&path, &self.directory, true)?
            .then_some(())
            .is_some())
    }

    pub fn open_digest(&self, digest: &str) -> Result<File> {
        let path = self.path_for_digest(digest)?;
        ensure_regular_file(&path, &self.directory, false)?;
        Ok(File::open(path)?)
    }

    pub fn get(&self, digest: &str) -> Result<File> {
        self.open_digest(digest)
    }

    pub fn open(&self, blob: &BlobRef) -> Result<File> {
        blob.validate()
            .map_err(|error| StoreError::BatchValidation(error.to_string()))?;
        let file = self.open_digest(&blob.digest)?;
        let size = file.metadata()?.len();
        if size != blob.size_bytes {
            return Err(StoreError::BlobSizeMismatch {
                expected: blob.size_bytes,
                actual: size,
            });
        }
        Ok(file)
    }

    pub fn copy_to<W: Write>(&self, blob: &BlobRef, mut writer: W) -> Result<u64> {
        let mut file = self.open(blob)?;
        Ok(io::copy(&mut file, &mut writer)?)
    }

    fn verify_reference(&self, blob: &BlobRef) -> Result<()> {
        blob.validate()
            .map_err(|error| StoreError::BatchValidation(error.to_string()))?;
        if blob.size_bytes > MAX_BLOB_SIZE_BYTES {
            return Err(StoreError::BlobTooLarge {
                limit: MAX_BLOB_SIZE_BYTES,
            });
        }
        let path = self.path_for_digest(&blob.digest)?;
        if !ensure_regular_file(&path, &self.directory, true)? {
            return Err(StoreError::MissingBlob {
                digest: blob.digest.clone(),
            });
        }
        verify_blob_file(&path, &blob.digest, blob.size_bytes)
    }
}

fn digest_hex(digest: &str) -> Result<String> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| StoreError::InvalidArgument("blob digest must use sha256:".to_owned()))?;
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StoreError::InvalidArgument(
            "blob digest must contain 64 hexadecimal characters".to_owned(),
        ));
    }
    Ok(hex.to_ascii_lowercase())
}

fn verify_blob_file(path: &Path, expected_digest: &str, expected_size: u64) -> Result<()> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    let mut size = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size = size.saturating_add(read as u64);
        if size > MAX_BLOB_SIZE_BYTES {
            return Err(StoreError::BlobTooLarge {
                limit: MAX_BLOB_SIZE_BYTES,
            });
        }
        hasher.update(&buffer[..read]);
    }
    let actual_digest = format!("sha256:{:x}", hasher.finalize());
    if actual_digest != expected_digest {
        return Err(StoreError::BlobDigestMismatch {
            expected: expected_digest.to_owned(),
            actual: actual_digest,
        });
    }
    if size != expected_size {
        return Err(StoreError::BlobSizeMismatch {
            expected: expected_size,
            actual: size,
        });
    }
    Ok(())
}

#[derive(Clone)]
struct StoredBatch {
    location: BatchLocation,
    batch_id: EventBatchId,
    command_digest: String,
}

pub struct Index {
    path: PathBuf,
    connection: Mutex<Connection>,
}

impl Index {
    fn open(path: &Path, project_id: ProjectId) -> Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| StoreError::InvalidArgument("index has no parent".to_owned()))?;
        let state = fs::canonicalize(parent)?;
        ensure_regular_file(path, &state, true)?;
        let wal = path.with_extension("sqlite3-wal");
        let shm = path.with_extension("sqlite3-shm");
        ensure_regular_file(&wal, &state, true)?;
        ensure_regular_file(&shm, &state, true)?;
        let connection = Connection::open(path)?;
        configure_sqlite(&connection)?;
        migrate(&connection, project_id)?;
        set_file_mode(path)?;
        if wal.exists() {
            set_file_mode(&wal)?;
        }
        if shm.exists() {
            set_file_mode(&shm)?;
        }
        Ok(Self {
            path: path.to_owned(),
            connection: Mutex::new(connection),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn journal_watermark(&self) -> Result<u64> {
        let connection = lock(&self.connection)?;
        metadata_u64(&connection, "journal_watermark")
    }

    pub fn index_watermark(&self) -> Result<u64> {
        let connection = lock(&self.connection)?;
        metadata_u64(&connection, "index_watermark")
    }

    pub fn watermarks(&self) -> Result<(u64, u64)> {
        Ok((self.journal_watermark()?, self.index_watermark()?))
    }

    pub fn projection_digest(&self) -> Result<String> {
        let connection = lock(&self.connection)?;
        Ok(connection.query_row(
            "SELECT value FROM store_metadata WHERE key = 'projection_digest'",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn semantic_snapshot_digest(&self) -> Result<String> {
        self.projection_digest()
    }

    pub fn semantic_snapshot(&self) -> Result<SemanticSnapshot> {
        let connection = lock(&self.connection)?;
        let mut counts = BTreeMap::new();
        for table in ENTITY_TABLES {
            let query = format!("SELECT COUNT(*) FROM {table}");
            let count: i64 = connection.query_row(&query, [], |row| row.get(0))?;
            counts.insert((*table).to_owned(), u64::try_from(count).unwrap_or(0));
        }
        let digest: String = connection.query_row(
            "SELECT value FROM store_metadata WHERE key = 'projection_digest'",
            [],
            |row| row.get(0),
        )?;
        Ok(SemanticSnapshot { digest, counts })
    }

    pub fn entity_json(&self, kind: &str, id: &str) -> Result<Option<Value>> {
        if !ENTITY_TABLES.contains(&kind) {
            return Err(StoreError::InvalidArgument(format!(
                "unknown entity table: {kind}"
            )));
        }
        let connection = lock(&self.connection)?;
        let query = format!("SELECT value_json FROM {kind} WHERE id = ?1");
        let value: Option<String> = connection
            .query_row(&query, params![id], |row| row.get(0))
            .optional()?;
        value
            .map(|value| serde_json::from_str(&value).map_err(StoreError::from))
            .transpose()
    }

    pub fn authority_principal(&self) -> Result<Option<AuthorityPrincipal>> {
        self.authority_value("principals", None)
    }

    pub fn authority_policy(&self, id: PolicyId) -> Result<Option<AuthorityPolicy>> {
        self.authority_value("policies", Some(&id.to_string()))
    }

    pub fn authority_profile_revision(
        &self,
        id: ProfileRevisionId,
    ) -> Result<Option<AuthorityProfileRevision>> {
        self.authority_value("profile_revisions", Some(&id.to_string()))
    }

    pub fn authority_latest_policy(&self) -> Result<Option<AuthorityPolicy>> {
        self.authority_value("policies", None)
    }

    pub fn authority_latest_profile_revision(&self) -> Result<Option<AuthorityProfileRevision>> {
        self.authority_value("profile_revisions", None)
    }

    pub fn authority_binding_for_operator(
        &self,
        operator_id: gorce_protocol::OperatorId,
    ) -> Result<Option<OperatorBinding>> {
        let project_id = self.project_id_from_metadata()?;
        let connection = lock(&self.connection)?;
        let value: Option<String> = connection
            .query_row(
                "SELECT value_json FROM operator_bindings
                 WHERE project_id = ?1 AND json_extract(value_json, '$.operator_id') = ?2
                 ORDER BY updated_sequence DESC LIMIT 1",
                params![project_id, operator_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        value
            .map(|value| serde_json::from_str(&value).map_err(StoreError::from))
            .transpose()
    }

    pub fn authority_admission_for_run(
        &self,
        run_id: gorce_protocol::RunId,
    ) -> Result<Option<Admission>> {
        let project_id = self.project_id_from_metadata()?;
        let connection = lock(&self.connection)?;
        let value: Option<String> = connection
            .query_row(
                "SELECT value_json FROM admissions
                 WHERE project_id = ?1 AND json_extract(value_json, '$.run_id') = ?2
                 ORDER BY updated_sequence DESC LIMIT 1",
                params![project_id, run_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        value
            .map(|value| serde_json::from_str(&value).map_err(StoreError::from))
            .transpose()
    }

    pub fn authority_command(
        &self,
        principal_id: PrincipalId,
        idempotency_key: &str,
    ) -> Result<Option<AuthorityCommandRecord>> {
        let connection = lock(&self.connection)?;
        let row: Option<(String, String, String)> = connection
            .query_row(
                "SELECT command_digest, idempotency_key, result_json
                 FROM authority_commands WHERE principal_id = ?1 AND idempotency_key = ?2",
                params![principal_id.to_string(), idempotency_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        row.map(|(command_digest, key, result_json)| {
            Ok(AuthorityCommandRecord {
                principal_id,
                idempotency_key: key,
                command_digest,
                result: serde_json::from_str(&result_json)?,
            })
        })
        .transpose()
    }

    fn authority_command_location(
        &self,
        principal_id: PrincipalId,
        idempotency_key: &str,
    ) -> Result<Option<StoredBatch>> {
        let connection = lock(&self.connection)?;
        let sequence: Option<i64> = connection
            .query_row(
                "SELECT batch_sequence FROM authority_commands
                 WHERE principal_id = ?1 AND idempotency_key = ?2",
                params![principal_id.to_string(), idempotency_key],
                |row| row.get(0),
            )
            .optional()?;
        drop(connection);
        let Some(sequence) = sequence else {
            return Ok(None);
        };
        let sequence = u64::try_from(sequence).map_err(|error| {
            StoreError::InvalidFormat(format!("invalid authority sequence: {error}"))
        })?;
        self.batch_by_sequence(sequence)
    }

    fn authority_value<T: for<'de> serde::Deserialize<'de>>(
        &self,
        table: &str,
        id: Option<&str>,
    ) -> Result<Option<T>> {
        let connection = lock(&self.connection)?;
        let query = if id.is_some() {
            format!("SELECT value_json FROM {table} WHERE id = ?1")
        } else {
            format!("SELECT value_json FROM {table} ORDER BY updated_sequence DESC LIMIT 1")
        };
        let value: Option<String> = if let Some(id) = id {
            connection
                .query_row(&query, params![id], |row| row.get(0))
                .optional()?
        } else {
            connection
                .query_row(&query, [], |row| row.get(0))
                .optional()?
        };
        value
            .map(|value| serde_json::from_str(&value).map_err(StoreError::from))
            .transpose()
    }

    fn project_id_from_metadata(&self) -> Result<String> {
        Ok(lock(&self.connection)?.query_row(
            "SELECT value FROM store_metadata WHERE key = 'project_id'",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn event_locations_page(
        &self,
        after_sequence: u64,
        limit: usize,
    ) -> Result<(Vec<EventLocation>, bool)> {
        let limit = limit.min(MAX_PAGE_SIZE);
        let connection = lock(&self.connection)?;
        let mut statement = connection.prepare(
            "SELECT batch_sequence, batch_id, event_ordinal, event_type, schema_version,
                    segment, byte_offset, byte_length, data_digest
             FROM event_locations WHERE batch_sequence > ?1
             ORDER BY batch_sequence, event_ordinal LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![
                sql_integer(after_sequence)?,
                sql_integer((limit + 1) as u64)?
            ],
            event_location_from_row,
        )?;
        let mut values = rows.collect::<std::result::Result<Vec<_>, _>>()?;
        let has_more = values.len() > limit;
        if has_more {
            values.pop();
        }
        Ok((values, has_more))
    }

    pub fn current_metadata(&self) -> Result<Vec<MetadataEntry>> {
        let connection = lock(&self.connection)?;
        let mut statement = connection
            .prepare("SELECT key, value, batch_sequence FROM current_metadata ORDER BY key")?;
        let rows = statement.query_map([], |row| {
            Ok(MetadataEntry {
                key: row.get(0)?,
                value: row.get(1)?,
                batch_sequence: from_sql_integer(row.get(2)?)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn metadata(&self) -> Result<BTreeMap<String, String>> {
        Ok(self
            .current_metadata()?
            .into_iter()
            .map(|entry| (entry.key, entry.value))
            .collect())
    }

    pub fn authority_state(&self, expected_principal: PrincipalId) -> Result<AuthorityState> {
        let connection = lock(&self.connection)?;
        // A projection is not ready merely because its rows deserialize.  The
        // tables and their constraints are part of the authority state too.
        // Keep this check on the read path so an index/FK change made after
        // startup cannot turn an otherwise malformed projection into Ready.
        if !schema_supports_scoped_authority(&connection)? {
            return Ok(AuthorityState::Invalid);
        }
        let mut counts = Vec::new();
        for table in [
            "principals",
            "policies",
            "profile_revisions",
            "operator_bindings",
            "admissions",
            "authority_commands",
        ] {
            let count: i64 =
                connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })?;
            counts.push(count);
        }
        if counts.iter().all(|count| *count == 0) {
            return Ok(AuthorityState::Empty);
        }
        let Some(stored_project) = connection.query_row(
            "SELECT value FROM store_metadata WHERE key = 'project_id'",
            [],
            |row| row.get::<_, Option<String>>(0),
        )?
        else {
            return Ok(AuthorityState::Invalid);
        };
        let Ok(project_id) = stored_project.parse::<ProjectId>() else {
            return Ok(AuthorityState::Invalid);
        };
        let valid =
            Self::validate_authority_projection(&connection, expected_principal, project_id)?;
        Ok(if valid {
            AuthorityState::Ready
        } else {
            AuthorityState::Invalid
        })
    }

    fn authority_projection_rows<T: for<'de> serde::Deserialize<'de>>(
        connection: &Connection,
        table: &str,
    ) -> Result<Option<Vec<(String, String, T)>>> {
        let mut statement = connection.prepare(&format!(
            "SELECT CAST(id AS TEXT), CAST(project_id AS TEXT), CAST(value_json AS TEXT)
             FROM {table} ORDER BY updated_sequence, id"
        ))?;
        let raw = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut rows = Vec::with_capacity(raw.len());
        for (id, project_id, value) in raw {
            let (Some(id), Some(project_id), Some(value)) = (id, project_id, value) else {
                return Ok(None);
            };
            let Ok(value) = serde_json::from_str(&value) else {
                return Ok(None);
            };
            rows.push((id, project_id, value));
        }
        Ok(Some(rows))
    }

    fn normalized_columns_match<T: serde::Serialize>(
        connection: &Connection,
        table: &str,
        id: &str,
        value: &T,
        columns: &[(&str, &str)],
    ) -> Result<bool> {
        let value = serde_json::to_value(value)?;
        for (column, key) in columns {
            let actual: Option<String> = connection.query_row(
                &format!("SELECT CAST({column} AS TEXT) FROM {table} WHERE id = ?1"),
                params![id],
                |row| row.get(0),
            )?;
            let Some(actual) = actual else {
                return Ok(false);
            };
            let expected = key
                .split('.')
                .try_fold(&value, |current, part| current.get(part));
            let Some(expected) = expected else {
                return Ok(false);
            };
            let expected = expected
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| expected.to_string());
            if actual != expected {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn authority_receipt_rows(connection: &Connection) -> Result<Option<Vec<AuthorityReceiptRow>>> {
        let mut statement = connection.prepare(
            "SELECT CAST(project_id AS TEXT), CAST(principal_id AS TEXT),
                    CAST(idempotency_key AS TEXT), CAST(command_digest AS TEXT),
                    CAST(result_json AS TEXT), CAST(batch_id AS TEXT), batch_sequence
             FROM authority_commands ORDER BY batch_sequence, idempotency_key",
        )?;
        let raw = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut rows = Vec::with_capacity(raw.len());
        for (project, principal, key, digest, result, batch_id, sequence) in raw {
            let (
                Some(project),
                Some(principal),
                Some(key),
                Some(digest),
                Some(result),
                Some(batch_id),
            ) = (project, principal, key, digest, result, batch_id)
            else {
                return Ok(None);
            };
            let Ok(sequence) = u64::try_from(sequence) else {
                return Ok(None);
            };
            rows.push((project, principal, key, digest, result, batch_id, sequence));
        }
        Ok(Some(rows))
    }

    fn validate_authority_projection(
        connection: &Connection,
        expected_principal: PrincipalId,
        project_id: ProjectId,
    ) -> Result<bool> {
        let Some(principals) =
            Self::authority_projection_rows::<AuthorityPrincipal>(connection, "principals")?
        else {
            return Ok(false);
        };
        if principals.len() != 1 {
            return Ok(false);
        }
        let principal = &principals[0].2;
        if !Self::normalized_columns_match(
            connection,
            "principals",
            &principals[0].0,
            principal,
            &[
                ("project_id", "project_id"),
                ("kind", "kind"),
                ("subject", "subject"),
                ("created_at", "created_at"),
            ],
        )? {
            return Ok(false);
        }
        if principals[0].0 != principal.id.to_string()
            || principals[0].1 != project_id.to_string()
            || principal.id != expected_principal
            || principal.project_id != project_id
            || principal.kind != gorce_protocol::AuthorityPrincipalKind::LocalControl
            || principal.subject != "local-control"
            || principal.validate().is_err()
        {
            return Ok(false);
        }

        let Some(policies) =
            Self::authority_projection_rows::<AuthorityPolicy>(connection, "policies")?
        else {
            return Ok(false);
        };
        if policies.is_empty() {
            return Ok(false);
        }
        for (id, row_project, policy) in &policies {
            if !Self::normalized_columns_match(
                connection,
                "policies",
                id,
                policy,
                &[
                    ("project_id", "project_id"),
                    ("revision", "revision"),
                    ("digest", "digest"),
                    ("created_at", "created_at"),
                ],
            )? {
                return Ok(false);
            }
            if id != &policy.id.to_string()
                || row_project != &project_id.to_string()
                || policy.project_id != project_id
                || policy.validate().is_err()
                || policies
                    .iter()
                    .filter(|(_, _, other)| other.revision == policy.revision)
                    .count()
                    != 1
            {
                return Ok(false);
            }
        }

        let Some(profiles) = Self::authority_projection_rows::<AuthorityProfileRevision>(
            connection,
            "profile_revisions",
        )?
        else {
            return Ok(false);
        };
        if profiles.is_empty() {
            return Ok(false);
        }
        for (id, row_project, profile) in &profiles {
            if !Self::normalized_columns_match(
                connection,
                "profile_revisions",
                id,
                profile,
                &[
                    ("project_id", "project_id"),
                    ("revision", "revision"),
                    ("name", "name"),
                    ("policy_id", "policy_id"),
                    ("execution_disposition", "spec.execution_disposition"),
                    ("digest", "digest"),
                    ("created_at", "created_at"),
                ],
            )? {
                return Ok(false);
            }
            if id != &profile.id.to_string()
                || row_project != &project_id.to_string()
                || profile.project_id != project_id
                || profile.validate().is_err()
                || !policies
                    .iter()
                    .any(|(_, _, policy)| policy.id == profile.policy_id)
                || profiles
                    .iter()
                    .filter(|(_, _, other)| other.revision == profile.revision)
                    .count()
                    != 1
            {
                return Ok(false);
            }
        }

        let Some(bindings) =
            Self::authority_projection_rows::<OperatorBinding>(connection, "operator_bindings")?
        else {
            return Ok(false);
        };
        for (id, row_project, binding) in &bindings {
            let Some(profile) = profiles
                .iter()
                .find(|(_, _, profile)| profile.id == binding.profile_revision_id)
            else {
                return Ok(false);
            };
            if !Self::normalized_columns_match(
                connection,
                "operator_bindings",
                id,
                binding,
                &[
                    ("project_id", "project_id"),
                    ("principal_id", "principal_id"),
                    ("operator_id", "operator_id"),
                    ("profile_revision_id", "profile_revision_id"),
                    ("policy_id", "policy_id"),
                    ("created_at", "created_at"),
                ],
            )? {
                return Ok(false);
            }
            if id != &binding.id.to_string()
                || row_project != &project_id.to_string()
                || binding.project_id != project_id
                || binding.principal_id != expected_principal
                || binding.policy_id != profile.2.policy_id
                || binding.validate().is_err()
            {
                return Ok(false);
            }
        }

        let Some(admissions) =
            Self::authority_projection_rows::<Admission>(connection, "admissions")?
        else {
            return Ok(false);
        };
        for (id, row_project, admission) in &admissions {
            let Some(binding) = bindings
                .iter()
                .find(|(_, _, binding)| binding.id == admission.binding_id)
            else {
                return Ok(false);
            };
            let Some(profile) = profiles
                .iter()
                .find(|(_, _, profile)| profile.id == admission.profile_revision_id)
            else {
                return Ok(false);
            };
            if !Self::normalized_columns_match(
                connection,
                "admissions",
                id,
                admission,
                &[
                    ("project_id", "project_id"),
                    ("principal_id", "principal_id"),
                    ("operator_id", "operator_id"),
                    ("run_id", "run_id"),
                    ("binding_id", "binding_id"),
                    ("profile_revision_id", "profile_revision_id"),
                    ("policy_id", "policy_id"),
                    ("execution_disposition", "execution_disposition"),
                    ("spec_digest", "spec_digest"),
                    ("created_at", "created_at"),
                ],
            )? {
                return Ok(false);
            }
            if id != &admission.id.to_string()
                || row_project != &project_id.to_string()
                || admission.project_id != project_id
                || admission.principal_id != expected_principal
                || admission.operator_id != binding.2.operator_id
                || admission.profile_revision_id != binding.2.profile_revision_id
                || admission.policy_id != binding.2.policy_id
                || admission.spec_digest != profile.2.spec.digest().unwrap_or_default()
                || admission.validate().is_err()
            {
                return Ok(false);
            }
        }

        let Some(receipts) = Self::authority_receipt_rows(connection)? else {
            return Ok(false);
        };
        for (row_project, principal, key, digest, result_json, batch_id, sequence) in receipts {
            let Ok(principal_id) = principal.parse::<PrincipalId>() else {
                return Ok(false);
            };
            let Ok(result) = serde_json::from_str::<CommandCommit>(&result_json) else {
                return Ok(false);
            };
            let Ok(batch_uuid) = uuid::Uuid::parse_str(&batch_id) else {
                return Ok(false);
            };
            let Some(batch_id) = UuidV7::from_uuid(batch_uuid) else {
                return Ok(false);
            };
            let Some((header_project, header_key, header_digest, header_sequence)) = connection
                .query_row(
                    "SELECT project_id, idempotency_key, command_digest, batch_sequence FROM batch_headers WHERE batch_id = ?1",
                    params![batch_id.into_uuid().to_string()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?)),
                )
                .optional()?
            else {
                return Ok(false);
            };
            if row_project != project_id.to_string()
                || principal_id != expected_principal
                || key.is_empty()
                || key.len() > gorce_protocol::MAX_IDEMPOTENCY_KEY_BYTES
                || header_project != project_id.to_string()
                || header_key != key
                || header_digest != digest
                || u64::try_from(header_sequence).unwrap_or(0) != sequence
                || result.project_id != project_id
                || result.batch_id != batch_id
                || result.batch_sequence != sequence
                || result.validate().is_err()
                || !result
                    .result
                    .resource_refs
                    .iter()
                    .all(|reference| match &reference.kind {
                        gorce_protocol::ResourceKind::ProfileRevision => {
                            profiles.iter().any(|(_, _, row)| row.id == reference.id)
                        }
                        gorce_protocol::ResourceKind::OperatorBinding => {
                            bindings.iter().any(|(_, _, row)| row.id == reference.id)
                        }
                        gorce_protocol::ResourceKind::Admission => {
                            admissions.iter().any(|(_, _, row)| row.id == reference.id)
                        }
                        _ => false,
                    })
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn idempotency(&self, key: &str) -> Result<Option<StoredBatch>> {
        let connection = lock(&self.connection)?;
        let row = connection
            .query_row(
                "SELECT batch_sequence, batch_id, command_digest, segment, byte_offset, byte_length
                 FROM commands WHERE idempotency_key = ?1",
                params![key],
                stored_batch_from_row,
            )
            .optional()?;
        row.map(validate_stored_batch).transpose()
    }

    fn batch_by_id(&self, id: EventBatchId) -> Result<Option<StoredBatch>> {
        let connection = lock(&self.connection)?;
        let row = connection
            .query_row(
                "SELECT batch_sequence, batch_id, command_digest, segment, byte_offset, byte_length
                 FROM batch_headers WHERE batch_id = ?1",
                params![id.into_uuid().to_string()],
                stored_batch_from_row,
            )
            .optional()?;
        row.map(validate_stored_batch).transpose()
    }

    fn batch_by_sequence(&self, sequence: u64) -> Result<Option<StoredBatch>> {
        let connection = lock(&self.connection)?;
        let row = connection
            .query_row(
                "SELECT batch_sequence, batch_id, command_digest, segment, byte_offset, byte_length
                 FROM batch_headers WHERE batch_sequence = ?1",
                params![sql_integer(sequence)?],
                stored_batch_from_row,
            )
            .optional()?;
        row.map(validate_stored_batch).transpose()
    }

    fn preflight_batch(&self, batch: &EventBatch) -> Result<()> {
        let connection = lock(&self.connection)?;
        let mut transaction = connection.unchecked_transaction()?;
        project_batch(&mut transaction, batch)?;
        transaction.rollback()?;
        Ok(())
    }

    fn apply_batch(&self, batch: &EventBatch, location: &BatchLocation) -> Result<()> {
        let digest = command_digest(batch)?;
        let connection = lock(&self.connection)?;
        let mut transaction = connection.unchecked_transaction()?;
        if let Some(existing) = transaction
            .query_row(
                "SELECT batch_id, command_digest FROM batch_headers WHERE batch_sequence = ?1",
                params![sql_integer(batch.batch_sequence)?],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            let existing_id = parse_batch_id(&existing.0)?;
            if existing_id == batch.batch_id && existing.1 == digest {
                transaction.commit()?;
                return Ok(());
            }
            return Err(StoreError::SequenceConflict {
                sequence: batch.batch_sequence,
                batch_id: existing_id,
            });
        }
        if transaction
            .query_row(
                "SELECT 1 FROM batch_headers WHERE batch_id = ?1",
                params![batch.batch_id.into_uuid().to_string()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some()
        {
            return Err(StoreError::DuplicateBatchId {
                batch_id: batch.batch_id,
            });
        }
        insert_batch_headers(&mut transaction, batch, location, &digest)?;
        project_batch(&mut transaction, batch)?;
        update_current_metadata(&mut transaction, batch)?;
        let previous = metadata_text_tx(&transaction, "projection_digest")?;
        let projection_digest = projection_step(&previous, batch, location)?;
        set_metadata_tx(
            &mut transaction,
            "journal_watermark",
            &batch.batch_sequence.to_string(),
        )?;
        set_metadata_tx(
            &mut transaction,
            "index_watermark",
            &batch.batch_sequence.to_string(),
        )?;
        set_metadata_tx(&mut transaction, "projection_digest", &projection_digest)?;
        transaction.commit()?;
        Ok(())
    }

    fn rebuild(&self, journal: &Journal, project_id: ProjectId) -> Result<()> {
        let connection = lock(&self.connection)?;
        let mut transaction = connection.unchecked_transaction()?;
        for table in ALL_TABLES {
            transaction.execute(&format!("DELETE FROM {table}"), [])?;
        }
        set_metadata_tx(&mut transaction, "journal_watermark", "0")?;
        set_metadata_tx(&mut transaction, "index_watermark", "0")?;
        set_metadata_tx(
            &mut transaction,
            "projection_digest",
            &empty_projection_digest(),
        )?;
        let mut count = 0_u64;
        let mut previous = empty_projection_digest();
        journal.for_each_batch(|batch, location| {
            if batch.project_id != project_id {
                return Err(StoreError::ProjectMismatch {
                    expected: project_id,
                    actual: batch.project_id,
                });
            }
            let digest = command_digest(batch)?;
            insert_batch_headers(&mut transaction, batch, location, &digest)?;
            project_batch(&mut transaction, batch)?;
            update_current_metadata(&mut transaction, batch)?;
            previous = projection_step(&previous, batch, location)?;
            count = batch.batch_sequence;
            Ok(())
        })?;
        set_metadata_tx(&mut transaction, "journal_watermark", &count.to_string())?;
        set_metadata_tx(&mut transaction, "index_watermark", &count.to_string())?;
        set_metadata_tx(&mut transaction, "projection_digest", &previous)?;
        transaction.commit()?;
        Ok(())
    }
}

const ENTITY_TABLES: &[&str] = &[
    "admissions",
    "operator_bindings",
    "profile_revisions",
    "policies",
    "principals",
    "workstreams",
    "goal_revisions",
    "plan_revisions",
    "tasks",
    "task_edges",
    "task_attempts",
    "messages",
];
const ALL_TABLES: &[&str] = &[
    "commands",
    "authority_commands",
    "batch_headers",
    "event_locations",
    "current_metadata",
    "admissions",
    "operator_bindings",
    "profile_revisions",
    "policies",
    "principals",
    "workstreams",
    "goal_revisions",
    "plan_revisions",
    "tasks",
    "task_edges",
    "task_attempts",
    "messages",
];
const REQUIRED_TABLES: &[&str] = &[
    "store_metadata",
    "commands",
    "authority_commands",
    "batch_headers",
    "event_locations",
    "current_metadata",
    "principals",
    "policies",
    "profile_revisions",
    "operator_bindings",
    "admissions",
    "workstreams",
    "goal_revisions",
    "plan_revisions",
    "tasks",
    "task_edges",
    "task_attempts",
    "messages",
];

fn configure_sqlite(connection: &Connection) -> Result<()> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;",
    )?;
    Ok(())
}

fn migrate(connection: &Connection, project_id: ProjectId) -> Result<()> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != 0 && version != 3 && version != 4 && version != INDEX_SCHEMA_VERSION {
        return Err(StoreError::IndexIncompatible(format!(
            "schema version {version}"
        )));
    }
    if version == 0 {
        connection
            .execute_batch(
                "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS schema_migrations (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS store_metadata (
                 key TEXT PRIMARY KEY NOT NULL,
                 value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS batch_headers (
                 batch_sequence INTEGER PRIMARY KEY,
                 batch_id TEXT NOT NULL UNIQUE,
                 project_id TEXT NOT NULL,
                 idempotency_key TEXT NOT NULL,
                 command_digest TEXT NOT NULL,
                 segment TEXT NOT NULL,
                 byte_offset INTEGER NOT NULL,
                 byte_length INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS commands (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 idempotency_key TEXT NOT NULL,
                 batch_id TEXT NOT NULL UNIQUE,
                 batch_sequence INTEGER NOT NULL UNIQUE,
                 command_digest TEXT NOT NULL,
                 segment TEXT NOT NULL,
                 byte_offset INTEGER NOT NULL,
                 byte_length INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS event_locations (
                 batch_sequence INTEGER NOT NULL,
                 batch_id TEXT NOT NULL,
                 event_ordinal INTEGER NOT NULL,
                 event_type TEXT NOT NULL,
                 schema_version INTEGER NOT NULL,
                 segment TEXT NOT NULL,
                 byte_offset INTEGER NOT NULL,
                 byte_length INTEGER NOT NULL,
                 data_digest TEXT NOT NULL,
                 PRIMARY KEY (batch_sequence, event_ordinal)
             );
             CREATE TABLE IF NOT EXISTS current_metadata (
                 key TEXT PRIMARY KEY NOT NULL,
                 value TEXT NOT NULL,
                 batch_sequence INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS event_locations_type
                 ON event_locations(event_type, batch_sequence, event_ordinal);
             CREATE TABLE IF NOT EXISTS workstreams (
                 id TEXT PRIMARY KEY, project_id TEXT NOT NULL, value_json TEXT NOT NULL,
                 updated_sequence INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS goal_revisions (
                 id TEXT PRIMARY KEY, project_id TEXT NOT NULL, value_json TEXT NOT NULL,
                 updated_sequence INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS plan_revisions (
                 id TEXT PRIMARY KEY, project_id TEXT NOT NULL, value_json TEXT NOT NULL,
                 updated_sequence INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS tasks (
                 id TEXT PRIMARY KEY, project_id TEXT NOT NULL, value_json TEXT NOT NULL,
                 updated_sequence INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS task_edges (
                 id TEXT PRIMARY KEY, project_id TEXT NOT NULL, value_json TEXT NOT NULL,
                 updated_sequence INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS task_attempts (
                 id TEXT PRIMARY KEY, project_id TEXT NOT NULL, value_json TEXT NOT NULL,
                 updated_sequence INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS messages (
                 id TEXT PRIMARY KEY, project_id TEXT NOT NULL, value_json TEXT NOT NULL,
                 updated_sequence INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS principals (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL, created_at TEXT NOT NULL, value_json TEXT NOT NULL, updated_sequence INTEGER NOT NULL, UNIQUE(project_id, id), UNIQUE(project_id, subject));
             CREATE TABLE IF NOT EXISTS policies (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, revision INTEGER NOT NULL, digest TEXT NOT NULL, created_at TEXT NOT NULL, value_json TEXT NOT NULL, updated_sequence INTEGER NOT NULL, UNIQUE(project_id, id), UNIQUE(project_id, revision));
             CREATE TABLE IF NOT EXISTS profile_revisions (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, revision INTEGER NOT NULL, name TEXT NOT NULL, policy_id TEXT NOT NULL, execution_disposition TEXT NOT NULL, digest TEXT NOT NULL, created_at TEXT NOT NULL, value_json TEXT NOT NULL, updated_sequence INTEGER NOT NULL, UNIQUE(project_id, id), UNIQUE(project_id, revision), FOREIGN KEY(project_id, policy_id) REFERENCES policies(project_id, id));
             CREATE TABLE IF NOT EXISTS operator_bindings (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, principal_id TEXT NOT NULL, operator_id TEXT NOT NULL, profile_revision_id TEXT NOT NULL, policy_id TEXT NOT NULL, created_at TEXT NOT NULL, value_json TEXT NOT NULL, updated_sequence INTEGER NOT NULL, UNIQUE(project_id, id), UNIQUE(project_id, operator_id), FOREIGN KEY(project_id, principal_id) REFERENCES principals(project_id, id), FOREIGN KEY(project_id, profile_revision_id) REFERENCES profile_revisions(project_id, id), FOREIGN KEY(project_id, policy_id) REFERENCES policies(project_id, id));
             CREATE TABLE IF NOT EXISTS admissions (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, principal_id TEXT NOT NULL, operator_id TEXT NOT NULL, run_id TEXT NOT NULL, binding_id TEXT NOT NULL, profile_revision_id TEXT NOT NULL, policy_id TEXT NOT NULL, execution_disposition TEXT NOT NULL, spec_digest TEXT NOT NULL, created_at TEXT NOT NULL, value_json TEXT NOT NULL, updated_sequence INTEGER NOT NULL, UNIQUE(project_id, id), UNIQUE(project_id, run_id), FOREIGN KEY(project_id, principal_id) REFERENCES principals(project_id, id), FOREIGN KEY(project_id, binding_id) REFERENCES operator_bindings(project_id, id), FOREIGN KEY(project_id, profile_revision_id) REFERENCES profile_revisions(project_id, id), FOREIGN KEY(project_id, policy_id) REFERENCES policies(project_id, id));
             CREATE TABLE IF NOT EXISTS authority_commands (project_id TEXT NOT NULL, principal_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, command_digest TEXT NOT NULL, result_json TEXT NOT NULL, batch_id TEXT NOT NULL, batch_sequence INTEGER NOT NULL, PRIMARY KEY (project_id, principal_id, idempotency_key), FOREIGN KEY(project_id, principal_id) REFERENCES principals(project_id, id));
             INSERT INTO store_metadata(key, value) VALUES
                 ('project_id', ''), ('journal_watermark', '0'),
                 ('index_watermark', '0'), ('projection_digest', '');
             INSERT INTO schema_migrations(version, applied_at) VALUES (5, 'initial');
             PRAGMA user_version = 5;
             COMMIT;",
            )
            .map_err(StoreError::Sqlite)?;
        let project = project_id.to_string();
        let digest = empty_projection_digest();
        connection.execute(
            "UPDATE store_metadata SET value = ?1 WHERE key = 'project_id'",
            params![project],
        )?;
        connection.execute(
            "UPDATE store_metadata SET value = ?1 WHERE key = 'projection_digest'",
            params![digest],
        )?;
    } else if version == 3 {
        let transaction = connection.unchecked_transaction()?;
        transaction.execute_batch(
            "
             CREATE TABLE IF NOT EXISTS principals (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL, created_at TEXT NOT NULL, value_json TEXT NOT NULL, updated_sequence INTEGER NOT NULL, UNIQUE(project_id, id), UNIQUE(project_id, subject));
             CREATE TABLE IF NOT EXISTS policies (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, revision INTEGER NOT NULL, digest TEXT NOT NULL, created_at TEXT NOT NULL, value_json TEXT NOT NULL, updated_sequence INTEGER NOT NULL, UNIQUE(project_id, id), UNIQUE(project_id, revision));
             CREATE TABLE IF NOT EXISTS profile_revisions (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, revision INTEGER NOT NULL, name TEXT NOT NULL, policy_id TEXT NOT NULL, execution_disposition TEXT NOT NULL, digest TEXT NOT NULL, created_at TEXT NOT NULL, value_json TEXT NOT NULL, updated_sequence INTEGER NOT NULL, UNIQUE(project_id, id), UNIQUE(project_id, revision), FOREIGN KEY(project_id, policy_id) REFERENCES policies(project_id, id));
             CREATE TABLE IF NOT EXISTS operator_bindings (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, principal_id TEXT NOT NULL, operator_id TEXT NOT NULL, profile_revision_id TEXT NOT NULL, policy_id TEXT NOT NULL, created_at TEXT NOT NULL, value_json TEXT NOT NULL, updated_sequence INTEGER NOT NULL, UNIQUE(project_id, id), UNIQUE(project_id, operator_id), FOREIGN KEY(project_id, principal_id) REFERENCES principals(project_id, id), FOREIGN KEY(project_id, profile_revision_id) REFERENCES profile_revisions(project_id, id), FOREIGN KEY(project_id, policy_id) REFERENCES policies(project_id, id));
             CREATE TABLE IF NOT EXISTS admissions (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, principal_id TEXT NOT NULL, operator_id TEXT NOT NULL, run_id TEXT NOT NULL, binding_id TEXT NOT NULL, profile_revision_id TEXT NOT NULL, policy_id TEXT NOT NULL, execution_disposition TEXT NOT NULL, spec_digest TEXT NOT NULL, created_at TEXT NOT NULL, value_json TEXT NOT NULL, updated_sequence INTEGER NOT NULL, UNIQUE(project_id, id), UNIQUE(project_id, run_id), FOREIGN KEY(project_id, principal_id) REFERENCES principals(project_id, id), FOREIGN KEY(project_id, binding_id) REFERENCES operator_bindings(project_id, id), FOREIGN KEY(project_id, profile_revision_id) REFERENCES profile_revisions(project_id, id), FOREIGN KEY(project_id, policy_id) REFERENCES policies(project_id, id));
             CREATE TABLE IF NOT EXISTS authority_commands (project_id TEXT NOT NULL, principal_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, command_digest TEXT NOT NULL, result_json TEXT NOT NULL, batch_id TEXT NOT NULL, batch_sequence INTEGER NOT NULL, PRIMARY KEY (project_id, principal_id, idempotency_key), FOREIGN KEY(project_id, principal_id) REFERENCES principals(project_id, id));",
        )?;
        rebuild_authority_commands_table(&transaction)?;
        rebuild_legacy_commands_index(&transaction)?;
        rebuild_authority_commands_table(&transaction)?;
        authority_indexes(&transaction)?;
        if !schema_supports_scoped_authority(&transaction)? {
            return Err(StoreError::IndexIncompatible(
                "schema version 3 authority layout requires index replacement".to_owned(),
            ));
        }
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (5, 'authority')",
            [],
        )?;
        transaction.pragma_update(None, "user_version", INDEX_SCHEMA_VERSION)?;
        transaction.commit()?;
    } else if version == 4 {
        let transaction = connection.unchecked_transaction()?;
        authority_indexes(&transaction)?;
        if !schema_supports_scoped_authority(&transaction)? {
            return Err(StoreError::IndexIncompatible(
                "schema version 4 lacks the scoped authority layout".to_owned(),
            ));
        }
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (5, 'authority-integrity')",
            [],
        )?;
        transaction.pragma_update(None, "user_version", INDEX_SCHEMA_VERSION)?;
        transaction.commit()?;
    }
    // A v5 database is already the normalized layout.  Do not repair it here
    // and then call the result compatible: a malformed v5 schema must be
    // observable as incompatible and go through the explicit recovery path.
    // Legacy v3/v4 layouts are migrated above, in their transaction.
    if version != INDEX_SCHEMA_VERSION {
        authority_indexes(connection)?;
    }
    if !schema_supports_scoped_authority(connection)? {
        return Err(StoreError::IndexIncompatible(
            "schema lacks the normalized scoped authority layout".to_owned(),
        ));
    }
    for table in REQUIRED_TABLES {
        let present: Option<String> = connection
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |row| row.get(0),
            )
            .optional()?;
        if present.is_none() {
            return Err(StoreError::IndexIncompatible(format!(
                "required table is missing: {table}"
            )));
        }
    }
    let stored_project: String = connection.query_row(
        "SELECT value FROM store_metadata WHERE key = 'project_id'",
        [],
        |row| row.get(0),
    )?;
    if stored_project != project_id.to_string() {
        return Err(StoreError::IndexIncompatible(
            "index belongs to another project".to_owned(),
        ));
    }
    Ok(())
}

fn rebuild_legacy_commands_index(transaction: &Transaction<'_>) -> Result<()> {
    if !table_has_global_unique_idempotency_constraint(transaction, "commands")? {
        return Ok(());
    }
    transaction.execute_batch(
        "
         ALTER TABLE commands RENAME TO commands_legacy;
         CREATE TABLE commands (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             idempotency_key TEXT NOT NULL,
             batch_id TEXT NOT NULL UNIQUE,
             batch_sequence INTEGER NOT NULL UNIQUE,
             command_digest TEXT NOT NULL,
             segment TEXT NOT NULL,
             byte_offset INTEGER NOT NULL,
             byte_length INTEGER NOT NULL
         );
         INSERT INTO commands(idempotency_key,batch_id,batch_sequence,command_digest,segment,byte_offset,byte_length)
             SELECT idempotency_key,batch_id,batch_sequence,command_digest,segment,byte_offset,byte_length
             FROM commands_legacy ORDER BY batch_sequence;
         DROP TABLE commands_legacy;
         ",
    )?;
    Ok(())
}

fn authority_commands_has_scoped_pk(connection: &Connection) -> Result<bool> {
    let mut statement = connection.prepare(
        "SELECT name, pk FROM pragma_table_info('authority_commands') WHERE pk > 0 ORDER BY pk",
    )?;
    let columns = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(columns
        == [
            ("project_id".to_owned(), 1),
            ("principal_id".to_owned(), 2),
            ("idempotency_key".to_owned(), 3),
        ])
}

fn rebuild_authority_commands_table(transaction: &Transaction<'_>) -> Result<()> {
    if authority_commands_has_scoped_pk(transaction)?
        && !table_has_global_unique_idempotency_constraint(transaction, "authority_commands")?
    {
        return Ok(());
    }
    transaction.execute_batch(
        "ALTER TABLE authority_commands RENAME TO authority_commands_legacy;
         CREATE TABLE authority_commands (
             project_id TEXT NOT NULL,
             principal_id TEXT NOT NULL,
             idempotency_key TEXT NOT NULL,
             command_digest TEXT NOT NULL,
             result_json TEXT NOT NULL,
             batch_id TEXT NOT NULL,
             batch_sequence INTEGER NOT NULL,
             PRIMARY KEY (project_id, principal_id, idempotency_key),
             FOREIGN KEY(project_id, principal_id) REFERENCES principals(project_id, id)
         );
         INSERT INTO authority_commands(project_id,principal_id,idempotency_key,command_digest,result_json,batch_id,batch_sequence)
             SELECT project_id,principal_id,idempotency_key,command_digest,result_json,batch_id,batch_sequence
             FROM authority_commands_legacy;
         DROP TABLE authority_commands_legacy;",
    )?;
    Ok(())
}

fn schema_supports_scoped_authority(connection: &Connection) -> Result<bool> {
    let required_columns = [
        (
            "principals",
            &[
                "id",
                "project_id",
                "kind",
                "subject",
                "created_at",
                "value_json",
                "updated_sequence",
            ] as &[&str],
        ),
        (
            "policies",
            &[
                "id",
                "project_id",
                "revision",
                "digest",
                "created_at",
                "value_json",
                "updated_sequence",
            ],
        ),
        (
            "profile_revisions",
            &[
                "id",
                "project_id",
                "revision",
                "name",
                "policy_id",
                "execution_disposition",
                "digest",
                "created_at",
                "value_json",
                "updated_sequence",
            ],
        ),
        (
            "operator_bindings",
            &[
                "id",
                "project_id",
                "principal_id",
                "operator_id",
                "profile_revision_id",
                "policy_id",
                "created_at",
                "value_json",
                "updated_sequence",
            ],
        ),
        (
            "admissions",
            &[
                "id",
                "project_id",
                "principal_id",
                "operator_id",
                "run_id",
                "binding_id",
                "profile_revision_id",
                "policy_id",
                "execution_disposition",
                "spec_digest",
                "created_at",
                "value_json",
                "updated_sequence",
            ],
        ),
        (
            "authority_commands",
            &[
                "project_id",
                "principal_id",
                "idempotency_key",
                "command_digest",
                "result_json",
                "batch_id",
                "batch_sequence",
            ],
        ),
    ];
    for (table, required) in required_columns {
        let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if columns.len() != required.len()
            || columns
                .iter()
                .zip(required.iter())
                .any(|(actual, expected)| actual != expected)
        {
            return Ok(false);
        }
    }
    let mut statement = connection.prepare("PRAGMA table_info(commands)")?;
    let command_columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let expected_command_columns = [
        "id",
        "idempotency_key",
        "batch_id",
        "batch_sequence",
        "command_digest",
        "segment",
        "byte_offset",
        "byte_length",
    ];
    if command_columns.len() != expected_command_columns.len()
        || command_columns
            .iter()
            .zip(expected_command_columns.iter())
            .any(|(actual, expected)| actual != expected)
    {
        return Ok(false);
    }

    if !authority_commands_has_scoped_pk(connection)?
        || !foreign_keys_match(
            connection,
            "profile_revisions",
            &[(
                "policies",
                &[("project_id", "project_id"), ("policy_id", "id")],
            )],
        )?
        || !foreign_keys_match(
            connection,
            "operator_bindings",
            &[
                (
                    "principals",
                    &[("project_id", "project_id"), ("principal_id", "id")],
                ),
                (
                    "profile_revisions",
                    &[("project_id", "project_id"), ("profile_revision_id", "id")],
                ),
                (
                    "policies",
                    &[("project_id", "project_id"), ("policy_id", "id")],
                ),
            ],
        )?
        || !foreign_keys_match(
            connection,
            "admissions",
            &[
                (
                    "principals",
                    &[("project_id", "project_id"), ("principal_id", "id")],
                ),
                (
                    "operator_bindings",
                    &[("project_id", "project_id"), ("binding_id", "id")],
                ),
                (
                    "profile_revisions",
                    &[("project_id", "project_id"), ("profile_revision_id", "id")],
                ),
                (
                    "policies",
                    &[("project_id", "project_id"), ("policy_id", "id")],
                ),
            ],
        )?
        || !foreign_keys_match(
            connection,
            "authority_commands",
            &[(
                "principals",
                &[("project_id", "project_id"), ("principal_id", "id")],
            )],
        )?
    {
        return Ok(false);
    }
    for (table, columns) in [
        ("principals", &["project_id", "id"] as &[&str]),
        ("policies", &["project_id", "id"]),
        ("profile_revisions", &["project_id", "id"]),
        ("operator_bindings", &["project_id", "id"]),
    ] {
        if !has_unique_constraint_columns(connection, table, columns)? {
            return Ok(false);
        }
    }
    let foreign_key_violations: i64 =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if foreign_key_violations != 0 || has_global_unique_idempotency_constraint(connection)? {
        return Ok(false);
    }

    let scoped_indexes = [
        (
            "principals_project_subject",
            "onprincipals(project_id,json_extract(value_json,'$.subject'))",
        ),
        (
            "policies_project_revision",
            "onpolicies(project_id,json_extract(value_json,'$.revision'))",
        ),
        (
            "profiles_project_revision",
            "onprofile_revisions(project_id,json_extract(value_json,'$.revision'))",
        ),
        (
            "bindings_project_operator",
            "onoperator_bindings(project_id,json_extract(value_json,'$.operator_id'))",
        ),
        (
            "admissions_project_run",
            "onadmissions(project_id,json_extract(value_json,'$.run_id'))",
        ),
    ];
    for (name, expected_definition) in scoped_indexes {
        let definition: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?;
        let Some(definition) = definition else {
            return Ok(false);
        };
        let normalized = definition
            .to_ascii_lowercase()
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect::<String>();
        if !normalized.starts_with("createuniqueindex") || !normalized.contains(expected_definition)
        {
            return Ok(false);
        }
    }

    Ok(true)
}

#[derive(Debug, PartialEq, Eq)]
struct ForeignKeyGroup {
    parent_table: String,
    columns: Vec<(String, String)>,
}

fn foreign_keys_match(
    connection: &Connection,
    table: &str,
    expected: &[(&str, &[(&str, &str)])],
) -> Result<bool> {
    let mut statement = connection.prepare(&format!(
        "SELECT id, seq, \"table\", \"from\", \"to\"
         FROM pragma_foreign_key_list('{table}') ORDER BY id, seq"
    ))?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut groups = BTreeMap::<i64, ForeignKeyGroup>::new();
    for (id, seq, parent_table, from, to) in actual {
        let (Some(from), Some(to)) = (from, to) else {
            return Ok(false);
        };
        if seq < 0 {
            return Ok(false);
        }
        let group = groups.entry(id).or_insert_with(|| ForeignKeyGroup {
            parent_table: parent_table.clone(),
            columns: Vec::new(),
        });
        if group.parent_table != parent_table {
            return Ok(false);
        }
        if group.columns.len() != seq as usize {
            // Preserve each composite FK's seq pairing.  Treating these rows
            // as a sortable flat list permits a cross-column/cross-FK swap.
            return Ok(false);
        }
        group.columns.push((from, to));
    }
    let mut actual = groups.into_values().collect::<Vec<_>>();
    if actual.len() != expected.len() {
        return Ok(false);
    }
    for (parent_table, columns) in expected {
        let wanted = ForeignKeyGroup {
            parent_table: (*parent_table).to_owned(),
            columns: columns
                .iter()
                .map(|(from, to)| ((*from).to_owned(), (*to).to_owned()))
                .collect(),
        };
        let Some(index) = actual.iter().position(|group| *group == wanted) else {
            return Ok(false);
        };
        actual.remove(index);
    }
    Ok(actual.is_empty())
}

fn has_global_unique_idempotency_constraint(connection: &Connection) -> Result<bool> {
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_master
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )?;
    let tables = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for table in tables {
        if table_has_global_unique_idempotency_constraint(connection, &table)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn table_has_global_unique_idempotency_constraint(
    connection: &Connection,
    table: &str,
) -> Result<bool> {
    let mut column_statement = connection.prepare(&format!(
        "PRAGMA table_info('{}')",
        table.replace('\'', "''")
    ))?;
    let columns = column_statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|column| column == "idempotency_key") {
        return Ok(false);
    }

    // Inspect SQLite autoindexes as well as explicit indexes: PRIMARY KEY and
    // UNIQUE constraints are represented there too.
    let mut statement = connection.prepare(&format!(
        "SELECT name FROM pragma_index_list('{}') WHERE \"unique\" = 1",
        table.replace('\'', "''")
    ))?;
    let indexes = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for index in indexes {
        let mut columns_statement = connection.prepare(&format!(
            "PRAGMA index_xinfo('{}')",
            index.replace('\'', "''")
        ))?;
        let columns = columns_statement
            .query_map([], |row| {
                Ok((row.get::<_, i64>(5)?, row.get::<_, Option<String>>(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let key_columns = columns
            .iter()
            .filter(|(key, _)| *key != 0)
            .map(|(_, column)| column.as_deref())
            .collect::<Vec<_>>();
        if key_columns.contains(&Some("idempotency_key"))
            && !key_columns.contains(&Some("principal_id"))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn has_unique_constraint_columns(
    connection: &Connection,
    table: &str,
    expected: &[&str],
) -> Result<bool> {
    let mut statement = connection.prepare(&format!(
        "SELECT name FROM pragma_index_list('{table}') WHERE \"unique\" = 1"
    ))?;
    let indexes = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for index in indexes {
        let mut columns_statement = connection.prepare(&format!(
            "PRAGMA index_info('{}')",
            index.replace('\'', "''")
        ))?;
        let columns = columns_statement
            .query_map([], |row| row.get::<_, Option<String>>(2))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if columns.len() == expected.len()
            && columns
                .iter()
                .zip(expected.iter())
                .all(|(actual, expected)| actual.as_deref() == Some(*expected))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn authority_indexes(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS principals_project_subject
             ON principals(project_id, json_extract(value_json, '$.subject'));
         CREATE UNIQUE INDEX IF NOT EXISTS policies_project_revision
             ON policies(project_id, json_extract(value_json, '$.revision'));
         CREATE UNIQUE INDEX IF NOT EXISTS profiles_project_revision
             ON profile_revisions(project_id, json_extract(value_json, '$.revision'));
         CREATE UNIQUE INDEX IF NOT EXISTS bindings_project_operator
             ON operator_bindings(project_id, json_extract(value_json, '$.operator_id'));
         CREATE UNIQUE INDEX IF NOT EXISTS admissions_project_run
             ON admissions(project_id, json_extract(value_json, '$.run_id'));",
    )?;
    Ok(())
}

fn metadata_text_tx(transaction: &Transaction<'_>, key: &str) -> Result<String> {
    Ok(transaction.query_row(
        "SELECT value FROM store_metadata WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )?)
}

fn set_metadata_tx(transaction: &mut Transaction<'_>, key: &str, value: &str) -> Result<()> {
    if value.len() > MAX_METADATA_VALUE_BYTES && key != "projection_digest" {
        return Err(StoreError::InvalidArgument(format!(
            "metadata value for {key} is too large"
        )));
    }
    transaction.execute(
        "UPDATE store_metadata SET value = ?1 WHERE key = ?2",
        params![value, key],
    )?;
    Ok(())
}

fn metadata_u64(connection: &Connection, key: &str) -> Result<u64> {
    let value: String = connection.query_row(
        "SELECT value FROM store_metadata WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )?;
    value
        .parse()
        .map_err(|_| StoreError::InvalidFormat(format!("invalid metadata value for {key}")))
}

fn sql_integer(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| StoreError::InvalidArgument("value exceeds SQLite integer range".to_owned()))
}

fn from_sql_integer(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn parse_batch_id(value: &str) -> Result<EventBatchId> {
    let uuid = uuid::Uuid::parse_str(value)
        .map_err(|error| StoreError::InvalidFormat(format!("invalid batch id: {error}")))?;
    EventBatchId::from_uuid(uuid)
        .ok_or_else(|| StoreError::InvalidFormat("batch id is not UUIDv7".to_owned()))
}

fn stored_batch_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredBatch> {
    let sequence = from_sql_integer(row.get(0)?)?;
    let batch_id = parse_batch_id_sql(row.get::<_, String>(1)?)?;
    Ok(StoredBatch {
        location: BatchLocation {
            segment: row.get(3)?,
            byte_offset: from_sql_integer(row.get(4)?)?,
            byte_length: from_sql_integer(row.get(5)?)?,
            batch_sequence: sequence,
            batch_id,
        },
        batch_id,
        command_digest: row.get(2)?,
    })
}

fn validate_stored_batch(batch: StoredBatch) -> Result<StoredBatch> {
    let valid_segment = parse_segment_number(&batch.location.segment)
        .map(|number| segment_file_name(number) == batch.location.segment)
        .unwrap_or(false);
    if !valid_segment
        || batch.location.byte_length == 0
        || batch.location.byte_length > MAX_JSONL_LINE_BYTES as u64
        || batch
            .location
            .byte_offset
            .checked_add(batch.location.byte_length)
            .is_none()
    {
        return Err(StoreError::InvalidFormat(
            "invalid location stored in index".to_owned(),
        ));
    }
    Ok(batch)
}

fn parse_batch_id_sql(value: String) -> rusqlite::Result<EventBatchId> {
    let uuid = uuid::Uuid::parse_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error))
    })?;
    EventBatchId::from_uuid(uuid).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Text,
            Box::new(io::Error::new(io::ErrorKind::InvalidData, "not UUIDv7")),
        )
    })
}

fn insert_batch_headers(
    transaction: &mut Transaction<'_>,
    batch: &EventBatch,
    location: &BatchLocation,
    digest: &str,
) -> Result<()> {
    let id = batch.batch_id.into_uuid().to_string();
    let sequence = sql_integer(batch.batch_sequence)?;
    transaction.execute(
        "INSERT INTO batch_headers(batch_sequence,batch_id,project_id,idempotency_key,command_digest,segment,byte_offset,byte_length)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            sequence,
            id,
            batch.project_id.to_string(),
            batch.command.idempotency_key,
            digest,
            &location.segment,
            sql_integer(location.byte_offset)?,
            sql_integer(location.byte_length)?,
        ],
    )?;
    transaction.execute(
        "INSERT INTO commands(idempotency_key,batch_id,batch_sequence,command_digest,segment,byte_offset,byte_length)
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![
            batch.command.idempotency_key,
            id,
            sequence,
            digest,
            &location.segment,
            sql_integer(location.byte_offset)?,
            sql_integer(location.byte_length)?,
        ],
    )?;
    for event in &batch.events {
        transaction.execute(
            "INSERT INTO event_locations(batch_sequence,batch_id,event_ordinal,event_type,schema_version,segment,byte_offset,byte_length,data_digest)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                sequence,
                id,
                sql_integer(event.ordinal)?,
                &event.event_type,
                sql_integer(event.schema_version)?,
                &location.segment,
                sql_integer(location.byte_offset)?,
                sql_integer(location.byte_length)?,
                json_digest(&event.data)?,
            ],
        )?;
    }
    Ok(())
}

fn update_current_metadata(transaction: &mut Transaction<'_>, batch: &EventBatch) -> Result<()> {
    let values = [
        ("project_id", batch.project_id.to_string()),
        ("last_batch_id", batch.batch_id.into_uuid().to_string()),
        ("last_command", batch.command.name.clone()),
        (
            "last_idempotency_key",
            batch.command.idempotency_key.clone(),
        ),
        ("last_committed_at", batch.committed_at.clone()),
        ("last_event_count", batch.events.len().to_string()),
    ];
    for (key, value) in values {
        transaction.execute(
            "INSERT INTO current_metadata(key,value,batch_sequence) VALUES (?1,?2,?3)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value,batch_sequence=excluded.batch_sequence",
            params![key, value, sql_integer(batch.batch_sequence)?],
        )?;
    }
    Ok(())
}

fn event_location_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EventLocation> {
    let segment: String = row.get(5)?;
    let valid_segment = parse_segment_number(&segment)
        .map(|number| segment_file_name(number) == segment)
        .unwrap_or(false);
    let byte_offset: i64 = row.get(6)?;
    let byte_length: i64 = row.get(7)?;
    if !valid_segment
        || byte_offset < 0
        || byte_length <= 0
        || byte_length > MAX_JSONL_LINE_BYTES as i64
        || byte_offset.checked_add(byte_length).is_none()
    {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Text,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid journal location",
            )),
        ));
    }
    Ok(EventLocation {
        batch_sequence: from_sql_integer(row.get(0)?)?,
        batch_id: parse_batch_id_sql(row.get(1)?)?,
        event_ordinal: from_sql_integer(row.get(2)?)?,
        event_type: row.get(3)?,
        schema_version: from_sql_integer(row.get(4)?)?,
        segment,
        byte_offset: from_sql_integer(byte_offset)?,
        byte_length: from_sql_integer(byte_length)?,
        data_digest: row.get(8)?,
    })
}

fn command_digest(batch: &EventBatch) -> Result<String> {
    Ok(batch.command.command_digest()?)
}

#[derive(Debug, Clone)]
struct AuthorityEnvelope {
    receipt: AuthorityCommandReceipt,
    canonical_digest: String,
}

fn validate_authority_envelope(
    transaction: Option<&Transaction<'_>>,
    batch: &EventBatch,
) -> Result<Option<AuthorityEnvelope>> {
    let receipt_events = batch
        .events
        .iter()
        .filter(|event| event.event_type == gorce_protocol::AUTHORITY_COMMAND_RECORDED_EVENT)
        .collect::<Vec<_>>();
    let authority_events = batch.events.iter().any(|event| {
        matches!(
            event.event_type.as_str(),
            gorce_protocol::AUTHORITY_BOOTSTRAP_EVENT
                | gorce_protocol::AUTHORITY_COMMAND_RECORDED_EVENT
                | gorce_protocol::AUTHORITY_PRINCIPAL_CREATED_EVENT
                | gorce_protocol::AUTHORITY_POLICY_CREATED_EVENT
                | gorce_protocol::AUTHORITY_PROFILE_REGISTERED_EVENT
                | gorce_protocol::AUTHORITY_OPERATOR_BOUND_EVENT
                | gorce_protocol::AUTHORITY_ADMISSION_CREATED_EVENT
        )
    });

    if batch.command.name == "authority.bootstrap" {
        if !receipt_events.is_empty() {
            return Err(StoreError::BatchValidation(
                "authority bootstrap cannot contain a command receipt".to_owned(),
            ));
        }
        let bootstrap_events = batch
            .events
            .iter()
            .filter(|event| event.event_type == gorce_protocol::AUTHORITY_BOOTSTRAP_EVENT)
            .collect::<Vec<_>>();
        if bootstrap_events.len() != 1 {
            return Err(StoreError::BatchValidation(
                "authority bootstrap must contain exactly one bootstrap envelope".to_owned(),
            ));
        }
        let bootstrap: gorce_protocol::AuthorityBootstrap =
            serde_json::from_value(bootstrap_events[0].data.clone())
                .map_err(|error| StoreError::BatchValidation(error.to_string()))?;
        if batch.command.arguments
            != serde_json::json!({
                "principal_id": bootstrap.principal_id
            })
        {
            return Err(StoreError::BatchValidation(
                "authority bootstrap arguments do not match its envelope".to_owned(),
            ));
        }
        let principal = batch
            .events
            .iter()
            .filter(|event| event.event_type == gorce_protocol::AUTHORITY_PRINCIPAL_CREATED_EVENT)
            .map(|event| serde_json::from_value::<AuthorityPrincipal>(event.data.clone()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| StoreError::BatchValidation(error.to_string()))?;
        let policy = batch
            .events
            .iter()
            .filter(|event| event.event_type == gorce_protocol::AUTHORITY_POLICY_CREATED_EVENT)
            .map(|event| serde_json::from_value::<AuthorityPolicy>(event.data.clone()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| StoreError::BatchValidation(error.to_string()))?;
        let profile = batch
            .events
            .iter()
            .filter(|event| event.event_type == gorce_protocol::AUTHORITY_PROFILE_REGISTERED_EVENT)
            .map(|event| serde_json::from_value::<AuthorityProfileRevision>(event.data.clone()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| StoreError::BatchValidation(error.to_string()))?;
        if batch.events.len() != 4
            || principal.len() != 1
            || policy.len() != 1
            || profile.len() != 1
            || principal[0].id != bootstrap.principal_id
            || policy[0].id != bootstrap.policy_id
            || profile[0].id != bootstrap.profile_revision_id
        {
            return Err(StoreError::BatchValidation(
                "authority bootstrap envelope does not match its entities".to_owned(),
            ));
        }
        return Ok(None);
    }
    if !authority_events {
        if batch.command.name == "authority.command" || !receipt_events.is_empty() {
            return Err(StoreError::BatchValidation(
                "reserved authority command requires an authority receipt envelope".to_owned(),
            ));
        }
        return Ok(None);
    }
    if batch.command.name != "authority.command" || receipt_events.len() != 1 {
        return Err(StoreError::BatchValidation(
            "authority command must contain exactly one receipt envelope".to_owned(),
        ));
    }
    let receipt: AuthorityCommandReceipt =
        serde_json::from_value(receipt_events[0].data.clone())
            .map_err(|error| StoreError::BatchValidation(error.to_string()))?;
    if receipt.principal_id.is_nil()
        || receipt.idempotency_key != batch.command.idempotency_key
        || receipt.idempotency_key.is_empty()
        || receipt.idempotency_key.len() > gorce_protocol::MAX_IDEMPOTENCY_KEY_BYTES
    {
        return Err(StoreError::BatchValidation(
            "authority receipt principal or idempotency key does not match the command".to_owned(),
        ));
    }
    let canonical_digest = command_digest(batch)?;
    if receipt.command_digest != canonical_digest {
        return Err(StoreError::BatchValidation(
            "authority receipt digest does not match the persisted command".to_owned(),
        ));
    }
    if receipt.result.project_id != batch.project_id
        || receipt.result.batch_id != batch.batch_id
        || receipt.result.batch_sequence != batch.batch_sequence
    {
        return Err(StoreError::BatchValidation(
            "authority receipt result does not match the persisted batch".to_owned(),
        ));
    }
    receipt
        .result
        .validate()
        .map_err(|error| StoreError::BatchValidation(error.to_string()))?;
    let command: AuthorityCommandKind = serde_json::from_value(batch.command.arguments.clone())
        .map_err(|error| StoreError::BatchValidation(error.to_string()))?;
    validate_authority_result(
        transaction,
        batch,
        receipt.principal_id,
        &command,
        &receipt.result,
    )?;
    Ok(Some(AuthorityEnvelope {
        receipt,
        canonical_digest,
    }))
}

fn validate_authority_result(
    transaction: Option<&Transaction<'_>>,
    batch: &EventBatch,
    principal_id: PrincipalId,
    command: &AuthorityCommandKind,
    result: &CommandCommit,
) -> Result<()> {
    if result.result.resource_refs.len() != 1 || result.result.resource_refs[0].id.is_nil() {
        return Err(StoreError::BatchValidation(
            "authority command result must contain exactly one resource".to_owned(),
        ));
    }
    let reference = &result.result.resource_refs[0];
    match command {
        AuthorityCommandKind::ProfileRegister { .. } => {
            if result.result.kind != CommandResultKind::Accepted
                || reference.kind != ResourceKind::ProfileRevision
                || batch.events.iter().any(|event| {
                    event.event_type != gorce_protocol::AUTHORITY_COMMAND_RECORDED_EVENT
                })
            {
                return Err(StoreError::BatchValidation(
                    "profile registration result is inconsistent with the command".to_owned(),
                ));
            }
            if let Some(transaction) = transaction {
                let present: Option<String> = transaction
                    .query_row(
                        "SELECT id FROM profile_revisions WHERE project_id = ?1 AND id = ?2",
                        params![batch.project_id.to_string(), reference.id.to_string()],
                        |row| row.get(0),
                    )
                    .optional()?;
                if present.is_none() {
                    return Err(StoreError::BatchValidation(
                        "profile registration result references an unknown profile".to_owned(),
                    ));
                }
            }
        }
        AuthorityCommandKind::OperatorBind {
            arguments: gorce_protocol::OperatorBindingArguments { operator_id },
        } => {
            let events = batch
                .events
                .iter()
                .filter(|event| event.event_type == gorce_protocol::AUTHORITY_OPERATOR_BOUND_EVENT)
                .collect::<Vec<_>>();
            if events.len() != 1
                || batch
                    .events
                    .iter()
                    .filter(|event| {
                        event.event_type != gorce_protocol::AUTHORITY_COMMAND_RECORDED_EVENT
                    })
                    .count()
                    != 1
            {
                return Err(StoreError::BatchValidation(
                    "operator binding command must contain exactly one binding".to_owned(),
                ));
            }
            let binding: OperatorBinding = serde_json::from_value(events[0].data.clone())
                .map_err(|error| StoreError::BatchValidation(error.to_string()))?;
            if result.result.kind != CommandResultKind::Created
                || reference.kind != ResourceKind::OperatorBinding
                || reference.id != binding.id
                || binding.operator_id != *operator_id
                || binding.principal_id != principal_id
            {
                return Err(StoreError::BatchValidation(
                    "operator binding result is inconsistent with the command".to_owned(),
                ));
            }
        }
        AuthorityCommandKind::AdmissionCreate {
            arguments:
                gorce_protocol::AdmissionCreateArguments {
                    operator_id,
                    run_id,
                },
        } => {
            let events = batch
                .events
                .iter()
                .filter(|event| {
                    event.event_type == gorce_protocol::AUTHORITY_ADMISSION_CREATED_EVENT
                })
                .collect::<Vec<_>>();
            if events.len() != 1
                || batch
                    .events
                    .iter()
                    .filter(|event| {
                        event.event_type != gorce_protocol::AUTHORITY_COMMAND_RECORDED_EVENT
                    })
                    .count()
                    != 1
            {
                return Err(StoreError::BatchValidation(
                    "admission command must contain exactly one admission".to_owned(),
                ));
            }
            let admission: Admission = serde_json::from_value(events[0].data.clone())
                .map_err(|error| StoreError::BatchValidation(error.to_string()))?;
            if result.result.kind != CommandResultKind::Created
                || reference.kind != ResourceKind::Admission
                || reference.id != admission.id
                || admission.operator_id != *operator_id
                || admission.run_id != *run_id
                || admission.principal_id != principal_id
            {
                return Err(StoreError::BatchValidation(
                    "admission result is inconsistent with the command".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn authority_command_scope(batch: &EventBatch) -> Result<Option<(PrincipalId, String, String)>> {
    Ok(validate_authority_envelope(None, batch)?.map(|envelope| {
        (
            envelope.receipt.principal_id,
            envelope.receipt.idempotency_key,
            envelope.canonical_digest,
        )
    }))
}

fn json_digest(value: &Value) -> Result<String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(value)?)
    ))
}

fn empty_projection_digest() -> String {
    format!("sha256:{:x}", Sha256::digest([]))
}

fn projection_step(previous: &str, batch: &EventBatch, location: &BatchLocation) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(previous.as_bytes());
    serde_json::to_writer(DigestWriter(&mut hasher), &batch.events)?;
    hasher.update(batch.command.idempotency_key.as_bytes());
    hasher.update(command_digest(batch)?.as_bytes());
    hasher.update(location.segment.as_bytes());
    hasher.update(location.byte_offset.to_le_bytes());
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

struct DigestWriter<'a>(&'a mut Sha256);

impl Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
enum ProjectionMutation {
    AuthorityBootstrap {
        principal_id: PrincipalId,
        policy_id: PolicyId,
        profile_revision_id: ProfileRevisionId,
    },
    Entity {
        table: &'static str,
        id: String,
        project_id: ProjectId,
        value: Value,
    },
    TaskPatch {
        id: String,
        field: &'static str,
        value: Value,
    },
    AttemptPatch {
        id: String,
        field: &'static str,
        value: Value,
    },
    AuthorityEntity {
        table: &'static str,
        id: String,
        project_id: ProjectId,
        value: Value,
    },
    AuthorityCommand {
        principal_id: PrincipalId,
        idempotency_key: String,
        command_digest: String,
        result: CommandCommit,
    },
}

fn semantic_error(
    batch: &EventBatch,
    event: &EventRecord,
    reason: impl Into<String>,
) -> StoreError {
    StoreError::SemanticProjection {
        batch_sequence: batch.batch_sequence,
        event_ordinal: event.ordinal,
        event_type: event.event_type.clone(),
        schema_version: event.schema_version,
        reason: reason.into(),
    }
}

fn projection_mutation(batch: &EventBatch, event: &EventRecord) -> Result<ProjectionMutation> {
    if event.schema_version != 1 {
        return Err(semantic_error(
            batch,
            event,
            "schema version is not supported",
        ));
    }
    let value = &event.data;
    match event.event_type.as_str() {
        gorce_protocol::AUTHORITY_BOOTSTRAP_EVENT => {
            let bootstrap: gorce_protocol::AuthorityBootstrap =
                serde_json::from_value(value.clone())
                    .map_err(|error| semantic_error(batch, event, error.to_string()))?;
            if bootstrap.principal_id.is_nil()
                || bootstrap.policy_id.is_nil()
                || bootstrap.profile_revision_id.is_nil()
            {
                return Err(semantic_error(
                    batch,
                    event,
                    "authority bootstrap is invalid",
                ));
            }
            Ok(ProjectionMutation::AuthorityBootstrap {
                principal_id: bootstrap.principal_id,
                policy_id: bootstrap.policy_id,
                profile_revision_id: bootstrap.profile_revision_id,
            })
        }
        gorce_protocol::AUTHORITY_COMMAND_RECORDED_EVENT => {
            let receipt: AuthorityCommandReceipt = serde_json::from_value(value.clone())
                .map_err(|error| semantic_error(batch, event, error.to_string()))?;
            if receipt.principal_id.is_nil()
                || receipt.idempotency_key.is_empty()
                || receipt.command_digest.is_empty()
            {
                return Err(semantic_error(
                    batch,
                    event,
                    "authority command receipt is invalid",
                ));
            }
            receipt
                .result
                .validate()
                .map_err(|error| semantic_error(batch, event, error.to_string()))?;
            Ok(ProjectionMutation::AuthorityCommand {
                principal_id: receipt.principal_id,
                idempotency_key: receipt.idempotency_key,
                command_digest: receipt.command_digest,
                result: receipt.result,
            })
        }
        gorce_protocol::AUTHORITY_PRINCIPAL_CREATED_EVENT => {
            let entity: AuthorityPrincipal = serde_json::from_value(value.clone())
                .map_err(|error| semantic_error(batch, event, error.to_string()))?;
            entity
                .validate()
                .map_err(|error| semantic_error(batch, event, error.to_string()))?;
            Ok(ProjectionMutation::AuthorityEntity {
                table: "principals",
                id: entity.id.to_string(),
                project_id: entity.project_id,
                value: serde_json::to_value(entity)?,
            })
        }
        gorce_protocol::AUTHORITY_POLICY_CREATED_EVENT => {
            let entity: AuthorityPolicy = serde_json::from_value(value.clone())
                .map_err(|error| semantic_error(batch, event, error.to_string()))?;
            entity
                .validate()
                .map_err(|error| semantic_error(batch, event, error.to_string()))?;
            Ok(ProjectionMutation::AuthorityEntity {
                table: "policies",
                id: entity.id.to_string(),
                project_id: entity.project_id,
                value: serde_json::to_value(entity)?,
            })
        }
        gorce_protocol::AUTHORITY_PROFILE_REGISTERED_EVENT => {
            let entity: AuthorityProfileRevision = serde_json::from_value(value.clone())
                .map_err(|error| semantic_error(batch, event, error.to_string()))?;
            entity
                .validate()
                .map_err(|error| semantic_error(batch, event, error.to_string()))?;
            Ok(ProjectionMutation::AuthorityEntity {
                table: "profile_revisions",
                id: entity.id.to_string(),
                project_id: entity.project_id,
                value: serde_json::to_value(entity)?,
            })
        }
        gorce_protocol::AUTHORITY_OPERATOR_BOUND_EVENT => {
            let entity: OperatorBinding = serde_json::from_value(value.clone())
                .map_err(|error| semantic_error(batch, event, error.to_string()))?;
            entity
                .validate()
                .map_err(|error| semantic_error(batch, event, error.to_string()))?;
            Ok(ProjectionMutation::AuthorityEntity {
                table: "operator_bindings",
                id: entity.id.to_string(),
                project_id: entity.project_id,
                value: serde_json::to_value(entity)?,
            })
        }
        gorce_protocol::AUTHORITY_ADMISSION_CREATED_EVENT => {
            let entity: Admission = serde_json::from_value(value.clone())
                .map_err(|error| semantic_error(batch, event, error.to_string()))?;
            entity
                .validate()
                .map_err(|error| semantic_error(batch, event, error.to_string()))?;
            Ok(ProjectionMutation::AuthorityEntity {
                table: "admissions",
                id: entity.id.to_string(),
                project_id: entity.project_id,
                value: serde_json::to_value(entity)?,
            })
        }
        "workstream.created" | "workstream.updated" | "workstream.archived" => {
            let entity: Workstream = parse_entity(value, "workstream")
                .map_err(|error| semantic_error(batch, event, error))?;
            Ok(ProjectionMutation::Entity {
                table: "workstreams",
                id: entity.id.to_string(),
                project_id: entity.project_id,
                value: serde_json::to_value(entity)?,
            })
        }
        "goal_revision.created"
        | "goal_revision.updated"
        | "goal.revision.created"
        | "goal.revision.updated" => {
            let entity: GoalRevision = parse_entity(value, "goal_revision")
                .map_err(|error| semantic_error(batch, event, error))?;
            Ok(ProjectionMutation::Entity {
                table: "goal_revisions",
                id: entity.id.to_string(),
                project_id: entity.project_id,
                value: serde_json::to_value(entity)?,
            })
        }
        "plan_revision.created"
        | "plan_revision.updated"
        | "plan.revision.created"
        | "plan.revision.updated"
        | "plan.revision.promoted"
        | "plan.promoted" => {
            let entity: PlanRevision = parse_entity(value, "plan_revision")
                .map_err(|error| semantic_error(batch, event, error))?;
            Ok(ProjectionMutation::Entity {
                table: "plan_revisions",
                id: entity.id.to_string(),
                project_id: entity.project_id,
                value: serde_json::to_value(entity)?,
            })
        }
        "task.created" | "task.updated" => {
            let entity: Task =
                parse_entity(value, "task").map_err(|error| semantic_error(batch, event, error))?;
            Ok(ProjectionMutation::Entity {
                table: "tasks",
                id: entity.id.to_string(),
                project_id: entity.project_id,
                value: serde_json::to_value(entity)?,
            })
        }
        "task.lifecycle_changed"
        | "task.lifecycle.changed"
        | "task.readiness_changed"
        | "task.readiness.changed" => {
            if let Ok(entity) = parse_entity::<Task>(value, "task") {
                Ok(ProjectionMutation::Entity {
                    table: "tasks",
                    id: entity.id.to_string(),
                    project_id: entity.project_id,
                    value: serde_json::to_value(entity)?,
                })
            } else if event.event_type == "task.lifecycle_changed"
                || event.event_type == "task.lifecycle.changed"
            {
                patch_mutation(batch, event, "task_id", "lifecycle", "tasks")
            } else {
                patch_mutation(batch, event, "task_id", "readiness", "tasks")
            }
        }
        "task_edge.created" | "task_edge.updated" | "task.edge.created" => {
            let entity: TaskEdge = parse_entity(value, "task_edge")
                .map_err(|error| semantic_error(batch, event, error))?;
            Ok(ProjectionMutation::Entity {
                table: "task_edges",
                id: entity.id.to_string(),
                project_id: entity.project_id,
                value: serde_json::to_value(entity)?,
            })
        }
        "task_attempt.created" | "task_attempt.updated" | "task.attempt.created" => {
            let entity: TaskAttempt = parse_entity(value, "task_attempt")
                .map_err(|error| semantic_error(batch, event, error))?;
            Ok(ProjectionMutation::Entity {
                table: "task_attempts",
                id: entity.id.to_string(),
                project_id: entity.project_id,
                value: serde_json::to_value(entity)?,
            })
        }
        "task_attempt.status_changed" | "task.attempt.status.changed" => {
            if let Ok(entity) = parse_entity::<TaskAttempt>(value, "task_attempt") {
                Ok(ProjectionMutation::Entity {
                    table: "task_attempts",
                    id: entity.id.to_string(),
                    project_id: entity.project_id,
                    value: serde_json::to_value(entity)?,
                })
            } else {
                patch_mutation(batch, event, "attempt_id", "status", "task_attempts")
            }
        }
        "message.created" | "message.updated" => {
            let entity: Message = parse_entity(value, "message")
                .map_err(|error| semantic_error(batch, event, error))?;
            Ok(ProjectionMutation::Entity {
                table: "messages",
                id: entity.id.to_string(),
                project_id: entity.project_id,
                value: serde_json::to_value(entity)?,
            })
        }
        _ => Err(semantic_error(
            batch,
            event,
            "event type is not supported by the projection",
        )),
    }
}

fn parse_entity<T: for<'de> serde::Deserialize<'de>>(
    value: &Value,
    envelope: &str,
) -> std::result::Result<T, String> {
    let value = if value.get(envelope).is_some() {
        let object = value
            .as_object()
            .ok_or_else(|| "event data must be an object".to_owned())?;
        if object.len() != 1 {
            return Err("event envelope contains unknown fields".to_owned());
        }
        object
            .get(envelope)
            .ok_or_else(|| "event envelope is missing its entity".to_owned())?
    } else {
        value
    };
    serde_json::from_value(value.clone()).map_err(|error| error.to_string())
}

fn patch_mutation(
    batch: &EventBatch,
    event: &EventRecord,
    id_key: &str,
    field: &'static str,
    table: &'static str,
) -> Result<ProjectionMutation> {
    let object = event
        .data
        .as_object()
        .ok_or_else(|| semantic_error(batch, event, "patch data must be an object"))?;
    let id = object
        .get(id_key)
        .and_then(Value::as_str)
        .ok_or_else(|| semantic_error(batch, event, format!("missing {id_key}")))?;
    let value = object
        .get(field)
        .cloned()
        .ok_or_else(|| semantic_error(batch, event, format!("missing {field}")))?;
    if field == "lifecycle" {
        serde_json::from_value::<TaskLifecycle>(value.clone())
            .map_err(|error| semantic_error(batch, event, error.to_string()))?;
    } else if field == "readiness" {
        serde_json::from_value::<TaskReadiness>(value.clone())
            .map_err(|error| semantic_error(batch, event, error.to_string()))?;
    } else if field == "status" {
        serde_json::from_value::<TaskAttemptStatus>(value.clone())
            .map_err(|error| semantic_error(batch, event, error.to_string()))?;
    }
    let task_allowed = [id_key, field, "updated_at"];
    let attempt_allowed = [id_key, field, "finished_at", "error", "evidence_bundle_id"];
    let allowed = if table == "tasks" {
        &task_allowed[..]
    } else {
        &attempt_allowed[..]
    };
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(semantic_error(
            batch,
            event,
            "patch contains unknown fields",
        ));
    }
    if table == "tasks" && object.get("updated_at").and_then(Value::as_str).is_none() {
        return Err(semantic_error(batch, event, "missing updated_at"));
    }
    Ok(if table == "tasks" {
        ProjectionMutation::TaskPatch {
            id: id.to_owned(),
            field,
            value,
        }
    } else {
        ProjectionMutation::AttemptPatch {
            id: id.to_owned(),
            field,
            value,
        }
    })
}

fn project_batch(transaction: &mut Transaction<'_>, batch: &EventBatch) -> Result<()> {
    validate_authority_envelope(Some(transaction), batch)?;
    let mutations = batch
        .events
        .iter()
        .map(|event| projection_mutation(batch, event))
        .collect::<Result<Vec<_>>>()?;
    let mut deferred = Vec::new();
    for mutation in mutations {
        if matches!(
            mutation,
            ProjectionMutation::AuthorityCommand { .. }
                | ProjectionMutation::AuthorityBootstrap { .. }
        ) {
            deferred.push(mutation);
        } else {
            apply_projection_mutation(transaction, batch, mutation)?;
        }
    }
    for mutation in deferred {
        apply_projection_mutation(transaction, batch, mutation)?;
    }
    Ok(())
}

fn apply_projection_mutation(
    transaction: &mut Transaction<'_>,
    batch: &EventBatch,
    mutation: ProjectionMutation,
) -> Result<()> {
    match mutation {
        ProjectionMutation::AuthorityBootstrap {
            principal_id,
            policy_id,
            profile_revision_id,
        } => {
            if !authority_row_exists(transaction, "principals", batch.project_id, principal_id)?
                || !authority_row_exists(transaction, "policies", batch.project_id, policy_id)?
                || !authority_row_exists(
                    transaction,
                    "profile_revisions",
                    batch.project_id,
                    profile_revision_id,
                )?
            {
                return Err(StoreError::InvalidFormat(
                    "authority bootstrap references missing projected state".to_owned(),
                ));
            }
            Ok(())
        }
        ProjectionMutation::AuthorityEntity {
            table,
            id,
            project_id,
            value,
        } => {
            if project_id != batch.project_id {
                return Err(semantic_error(
                    batch,
                    &batch.events[0],
                    "authority projection belongs to another project",
                ));
            }
            validate_authority_references(transaction, batch.project_id, table, &value)?;
            insert_authority_entity(
                transaction,
                table,
                &id,
                project_id,
                &value,
                batch.batch_sequence,
            )
        }
        ProjectionMutation::AuthorityCommand {
            principal_id,
            idempotency_key,
            command_digest,
            result,
        } => {
            if result.project_id != batch.project_id
                || result.batch_id != batch.batch_id
                || result.batch_sequence != batch.batch_sequence
            {
                return Err(StoreError::InvalidFormat(
                    "authority command result does not match its batch".to_owned(),
                ));
            }
            if idempotency_key.is_empty()
                || idempotency_key.len() > gorce_protocol::MAX_IDEMPOTENCY_KEY_BYTES
                || !authority_row_exists(transaction, "principals", batch.project_id, principal_id)?
            {
                return Err(StoreError::InvalidFormat(
                    "authority command receipt is not project-scoped".to_owned(),
                ));
            }
            transaction.execute(
                "INSERT INTO authority_commands(project_id,principal_id,idempotency_key,command_digest,result_json,batch_id,batch_sequence)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    batch.project_id.to_string(),
                    principal_id.to_string(),
                    idempotency_key,
                    command_digest,
                    serde_json::to_string(&result)?,
                    batch.batch_id.into_uuid().to_string(),
                    sql_integer(batch.batch_sequence)?,
                ],
            )?;
            Ok(())
        }
        ProjectionMutation::Entity {
            table,
            id,
            project_id,
            value,
        } => upsert_entity(
            transaction,
            table,
            &id,
            project_id,
            &value,
            batch.batch_sequence,
        ),
        ProjectionMutation::TaskPatch { id, field, value } => patch_entity(
            transaction,
            "tasks",
            &id,
            field,
            value,
            batch.batch_sequence,
        ),
        ProjectionMutation::AttemptPatch { id, field, value } => patch_entity(
            transaction,
            "task_attempts",
            &id,
            field,
            value,
            batch.batch_sequence,
        ),
    }
}

fn authority_row_exists<T: ToString>(
    transaction: &Transaction<'_>,
    table: &str,
    project_id: ProjectId,
    id: T,
) -> Result<bool> {
    Ok(transaction
        .query_row(
            &format!("SELECT 1 FROM {table} WHERE project_id = ?1 AND id = ?2"),
            params![project_id.to_string(), id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
}

fn authority_json<T: for<'de> serde::Deserialize<'de>>(
    transaction: &Transaction<'_>,
    table: &str,
    project_id: ProjectId,
    id: &str,
) -> Result<Option<T>> {
    let value: Option<String> = transaction
        .query_row(
            &format!("SELECT value_json FROM {table} WHERE project_id = ?1 AND id = ?2"),
            params![project_id.to_string(), id],
            |row| row.get(0),
        )
        .optional()?;
    value
        .map(|value| serde_json::from_str(&value).map_err(StoreError::from))
        .transpose()
}

fn validate_authority_references(
    transaction: &Transaction<'_>,
    project_id: ProjectId,
    table: &str,
    value: &Value,
) -> Result<()> {
    match table {
        "profile_revisions" => {
            let profile: AuthorityProfileRevision = serde_json::from_value(value.clone())?;
            let policy = authority_json::<AuthorityPolicy>(
                transaction,
                "policies",
                project_id,
                &profile.policy_id.to_string(),
            )?
            .ok_or_else(|| {
                StoreError::InvalidFormat("profile references missing policy".to_owned())
            })?;
            if policy.project_id != project_id {
                return Err(StoreError::InvalidFormat(
                    "profile policy belongs to another project".to_owned(),
                ));
            }
        }
        "operator_bindings" => {
            let binding: OperatorBinding = serde_json::from_value(value.clone())?;
            let principal = authority_json::<AuthorityPrincipal>(
                transaction,
                "principals",
                project_id,
                &binding.principal_id.to_string(),
            )?;
            let profile = authority_json::<AuthorityProfileRevision>(
                transaction,
                "profile_revisions",
                project_id,
                &binding.profile_revision_id.to_string(),
            )?;
            let policy = authority_json::<AuthorityPolicy>(
                transaction,
                "policies",
                project_id,
                &binding.policy_id.to_string(),
            )?;
            if principal.is_none()
                || profile
                    .as_ref()
                    .is_none_or(|profile| profile.policy_id != binding.policy_id)
                || policy.is_none()
            {
                return Err(StoreError::InvalidFormat(
                    "operator binding has missing or mismatched authority references".to_owned(),
                ));
            }
        }
        "admissions" => {
            let admission: Admission = serde_json::from_value(value.clone())?;
            let binding = authority_json::<OperatorBinding>(
                transaction,
                "operator_bindings",
                project_id,
                &admission.binding_id.to_string(),
            )?
            .ok_or_else(|| {
                StoreError::InvalidFormat("admission references missing binding".to_owned())
            })?;
            let profile = authority_json::<AuthorityProfileRevision>(
                transaction,
                "profile_revisions",
                project_id,
                &admission.profile_revision_id.to_string(),
            )?
            .ok_or_else(|| {
                StoreError::InvalidFormat("admission references missing profile".to_owned())
            })?;
            let policy = authority_json::<AuthorityPolicy>(
                transaction,
                "policies",
                project_id,
                &admission.policy_id.to_string(),
            )?
            .ok_or_else(|| {
                StoreError::InvalidFormat("admission references missing policy".to_owned())
            })?;
            if binding.operator_id != admission.operator_id
                || binding.principal_id != admission.principal_id
                || binding.profile_revision_id != admission.profile_revision_id
                || binding.policy_id != admission.policy_id
                || profile.policy_id != admission.policy_id
                || policy.project_id != project_id
                || profile.grant != admission.grant
            {
                return Err(StoreError::InvalidFormat(
                    "admission authority references do not agree".to_owned(),
                ));
            }
            if admission.spec_digest
                != profile
                    .spec
                    .digest()
                    .map_err(|error| StoreError::InvalidFormat(error.to_string()))?
            {
                return Err(StoreError::InvalidFormat(
                    "admission spec digest does not match profile".to_owned(),
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn insert_authority_entity(
    transaction: &mut Transaction<'_>,
    table: &str,
    id: &str,
    project_id: ProjectId,
    value: &Value,
    sequence: u64,
) -> Result<()> {
    let value_json = serde_json::to_string(value)?;
    match table {
        "principals" => {
            let entity: AuthorityPrincipal = serde_json::from_value(value.clone())?;
            transaction.execute(
                "INSERT INTO principals(id,project_id,kind,subject,created_at,value_json,updated_sequence)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![id, project_id.to_string(), "local_control", entity.subject, entity.created_at, value_json, sql_integer(sequence)?],
            )?;
        }
        "policies" => {
            let entity: AuthorityPolicy = serde_json::from_value(value.clone())?;
            transaction.execute(
                "INSERT INTO policies(id,project_id,revision,digest,created_at,value_json,updated_sequence)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![id, project_id.to_string(), sql_integer(entity.revision)?, entity.digest, entity.created_at, value_json, sql_integer(sequence)?],
            )?;
        }
        "profile_revisions" => {
            let entity: AuthorityProfileRevision = serde_json::from_value(value.clone())?;
            transaction.execute(
                "INSERT INTO profile_revisions(id,project_id,revision,name,policy_id,execution_disposition,digest,created_at,value_json,updated_sequence)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![id, project_id.to_string(), sql_integer(entity.revision)?, entity.name, entity.policy_id.to_string(), "disabled", entity.digest, entity.created_at, value_json, sql_integer(sequence)?],
            )?;
        }
        "operator_bindings" => {
            let entity: OperatorBinding = serde_json::from_value(value.clone())?;
            transaction.execute(
                "INSERT INTO operator_bindings(id,project_id,principal_id,operator_id,profile_revision_id,policy_id,created_at,value_json,updated_sequence)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![id, project_id.to_string(), entity.principal_id.to_string(), entity.operator_id.to_string(), entity.profile_revision_id.to_string(), entity.policy_id.to_string(), entity.created_at, value_json, sql_integer(sequence)?],
            )?;
        }
        "admissions" => {
            let entity: Admission = serde_json::from_value(value.clone())?;
            transaction.execute(
                "INSERT INTO admissions(id,project_id,principal_id,operator_id,run_id,binding_id,profile_revision_id,policy_id,execution_disposition,spec_digest,created_at,value_json,updated_sequence)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![id, project_id.to_string(), entity.principal_id.to_string(), entity.operator_id.to_string(), entity.run_id.to_string(), entity.binding_id.to_string(), entity.profile_revision_id.to_string(), entity.policy_id.to_string(), "disabled", entity.spec_digest, entity.created_at, value_json, sql_integer(sequence)?],
            )?;
        }
        _ => {
            return Err(StoreError::InvalidFormat(format!(
                "unknown authority table: {table}"
            )));
        }
    }
    Ok(())
}

fn upsert_entity(
    transaction: &mut Transaction<'_>,
    table: &str,
    id: &str,
    project_id: ProjectId,
    value: &Value,
    sequence: u64,
) -> Result<()> {
    let value_json = serde_json::to_string(value)?;
    transaction.execute(
        &format!(
            "INSERT INTO {table}(id,project_id,value_json,updated_sequence) VALUES (?1,?2,?3,?4)
             ON CONFLICT(id) DO UPDATE SET project_id=excluded.project_id,value_json=excluded.value_json,updated_sequence=excluded.updated_sequence"
        ),
        params![id, project_id.to_string(), value_json, sql_integer(sequence)?],
    )?;
    Ok(())
}

fn patch_entity(
    transaction: &mut Transaction<'_>,
    table: &str,
    id: &str,
    field: &str,
    value: Value,
    sequence: u64,
) -> Result<()> {
    let existing: Option<(String, String)> = transaction
        .query_row(
            &format!("SELECT project_id,value_json FROM {table} WHERE id = ?1"),
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((project_id, current)) = existing else {
        return Err(StoreError::InvalidFormat(format!(
            "cannot patch missing {table} entity {id}"
        )));
    };
    let mut current: Value = serde_json::from_str(&current)?;
    let object = current
        .as_object_mut()
        .ok_or_else(|| StoreError::InvalidFormat("projected entity is not an object".to_owned()))?;
    object.insert(field.to_owned(), value);
    upsert_entity(
        transaction,
        table,
        id,
        project_id.parse().map_err(|error| {
            StoreError::InvalidFormat(format!("invalid projected project id: {error}"))
        })?,
        &current,
        sequence,
    )
}

pub struct ProjectStoreWriter {
    project_root: PathBuf,
    project_id: ProjectId,
    layout: StateLayout,
    _writer_lock: WriterLock,
    journal: Mutex<Journal>,
    blobs: BlobStore,
    index: Index,
    state: Mutex<WriterState>,
    #[cfg(test)]
    faults: Mutex<FaultInjection>,
}

pub type Store = ProjectStoreWriter;
pub type Storage = ProjectStoreWriter;

impl ProjectStoreWriter {
    pub fn open(project_root: impl AsRef<Path>, project_id: ProjectId) -> Result<Self> {
        let project_root = canonical_project_root(project_root.as_ref())?;
        let layout = StateLayout::create(&project_root)?;
        let writer_lock = WriterLock::acquire(&layout.lock, &layout.state)?;
        let blobs = BlobStore::from_layout(&layout)?;
        let journal = Journal::open(&layout.journal, JOURNAL_SEGMENT_LIMIT)?;
        journal.for_each_batch(|batch, _| {
            if batch.project_id != project_id {
                return Err(StoreError::ProjectMismatch {
                    expected: project_id,
                    actual: batch.project_id,
                });
            }
            for blob in &batch.referenced_blobs {
                blobs.verify_reference(blob)?;
            }
            Ok(())
        })?;
        let index = match Index::open(&layout.index, project_id) {
            Ok(index) => index,
            Err(StoreError::IndexIncompatible(_)) => replace_index(&layout, project_id)?,
            Err(error) => return Err(error),
        };
        if index.journal_watermark()? != journal.last_sequence()
            || index_head_fingerprint(&index)? != journal.head_fingerprint()
        {
            index.rebuild(&journal, project_id)?;
        }
        Ok(Self {
            project_root,
            project_id,
            blobs,
            layout,
            _writer_lock: writer_lock,
            journal: Mutex::new(journal),
            index,
            state: Mutex::new(WriterState::Healthy),
            #[cfg(test)]
            faults: Mutex::new(FaultInjection::default()),
        })
    }

    pub fn new(project_root: impl AsRef<Path>, project_id: ProjectId) -> Result<Self> {
        Self::open(project_root, project_id)
    }

    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    pub fn project_id(&self) -> ProjectId {
        self.project_id
    }

    pub fn state_dir(&self) -> PathBuf {
        self.layout.state.clone()
    }

    pub fn state_path(&self) -> PathBuf {
        self.state_dir()
    }

    pub fn journal_dir(&self) -> PathBuf {
        self.layout.journal.clone()
    }

    pub fn blobs_dir(&self) -> PathBuf {
        self.layout.blobs.clone()
    }

    pub fn index_path(&self) -> PathBuf {
        self.layout.index.clone()
    }

    pub fn writer_state(&self) -> Result<WriterState> {
        Ok(*lock(&self.state)?)
    }

    pub fn health(&self) -> Result<WriterState> {
        self.writer_state()
    }

    pub fn blobs(&self) -> &BlobStore {
        &self.blobs
    }

    pub fn index(&self) -> &Index {
        &self.index
    }

    pub fn history_page(&self, after_sequence: u64, limit: usize) -> Result<HistoryPage> {
        lock(&self.journal)?.page(after_sequence, limit)
    }

    pub fn next_batch_sequence(&self) -> Result<u64> {
        Ok(lock(&self.journal)?.next_sequence())
    }

    #[cfg(test)]
    pub fn append_batch<B: Borrow<EventBatch>>(&self, batch: B) -> Result<AppendResult> {
        let batch = batch.borrow();
        self.append_validated(batch)
    }

    #[cfg(test)]
    pub fn append<B: Borrow<EventBatch>>(&self, batch: B) -> Result<AppendResult> {
        self.append_batch(batch)
    }

    #[cfg(test)]
    pub fn append_event_batch<B: Borrow<EventBatch>>(&self, batch: B) -> Result<AppendResult> {
        self.append_batch(batch)
    }

    pub fn append_next<B: Borrow<EventBatch>>(&self, batch: B) -> Result<AppendResult> {
        let mut batch = batch.borrow().clone();
        let next = lock(&self.journal)?.next_sequence();
        batch.batch_sequence = next;
        self.append_validated(&batch)
    }

    fn append_validated(&self, batch: &EventBatch) -> Result<AppendResult> {
        if self.writer_state()? == WriterState::NeedsRecovery {
            return Err(StoreError::NeedsRecovery {
                reason: "recover() must complete before another write".to_owned(),
            });
        }
        batch
            .validate()
            .map_err(|error| StoreError::BatchValidation(error.to_string()))?;
        if batch.project_id != self.project_id {
            return Err(StoreError::ProjectMismatch {
                expected: self.project_id,
                actual: batch.project_id,
            });
        }
        let authority_scope = authority_command_scope(batch)?;
        for event in &batch.events {
            projection_mutation(batch, event)?;
        }
        for blob in &batch.referenced_blobs {
            self.blobs.verify_reference(blob)?;
        }
        let digest = command_digest(batch)?;
        let mut journal = lock(&self.journal)?;
        if let Some((principal_id, idempotency_key, canonical_digest)) = authority_scope {
            if let Some(existing) = self
                .index
                .authority_command(principal_id, &idempotency_key)?
            {
                if existing.command_digest == canonical_digest {
                    let location = self
                        .index
                        .authority_command_location(principal_id, &idempotency_key)?
                        .ok_or_else(|| {
                            StoreError::InvalidFormat(
                                "authority receipt is missing its batch header".to_owned(),
                            )
                        })?
                        .location;
                    return Ok(AppendResult {
                        location,
                        index_watermark: self.index.index_watermark()?,
                        duplicate: true,
                    });
                }
                return Err(StoreError::AuthorityIdempotencyConflict {
                    principal_id,
                    key: idempotency_key,
                });
            }
        } else if let Some(existing) = self.index.idempotency(&batch.command.idempotency_key)? {
            if existing.command_digest == digest {
                return Ok(AppendResult {
                    location: existing.location,
                    index_watermark: self.index.index_watermark()?,
                    duplicate: true,
                });
            }
            return Err(StoreError::IdempotencyConflict {
                key: batch.command.idempotency_key.clone(),
            });
        }
        if let Some(existing) = self.index.batch_by_id(batch.batch_id)? {
            return Err(StoreError::DuplicateBatchId {
                batch_id: existing.batch_id,
            });
        }
        if let Some(existing) = self.index.batch_by_sequence(batch.batch_sequence)? {
            return Err(StoreError::SequenceConflict {
                sequence: batch.batch_sequence,
                batch_id: existing.batch_id,
            });
        }
        if batch.batch_sequence != journal.next_sequence() {
            return Err(StoreError::SequenceGap {
                expected: journal.next_sequence(),
                actual: batch.batch_sequence,
                segment: segment_file_name(1),
                offset: 0,
            });
        }
        self.index.preflight_batch(batch)?;
        let location = match journal.append(batch) {
            Ok(location) => location,
            Err(error) => {
                self.mark_needs_recovery(error.to_string())?;
                return Err(error);
            }
        };
        #[cfg(test)]
        if take_fault(&self.faults, |faults| faults.after_journal_append) {
            self.mark_needs_recovery("failure after durable journal append".to_owned())?;
            return Err(StoreError::FaultInjected("after_journal_append"));
        }
        #[cfg(test)]
        if take_fault(&self.faults, |faults| faults.projection) {
            self.mark_needs_recovery("projection failure".to_owned())?;
            return Err(StoreError::FaultInjected("projection"));
        }
        if let Err(error) = self.index.apply_batch(batch, &location) {
            self.mark_needs_recovery(error.to_string())?;
            return Err(error);
        }
        Ok(AppendResult {
            location,
            index_watermark: self.index.index_watermark()?,
            duplicate: false,
        })
    }

    pub fn recover(&self) -> Result<()> {
        let mut journal_guard = lock(&self.journal)?;
        let candidate = Journal::open(&self.layout.journal, JOURNAL_SEGMENT_LIMIT)?;
        candidate.for_each_batch(|batch, _| {
            if batch.project_id != self.project_id {
                return Err(StoreError::ProjectMismatch {
                    expected: self.project_id,
                    actual: batch.project_id,
                });
            }
            for blob in &batch.referenced_blobs {
                self.blobs.verify_reference(blob)?;
            }
            Ok(())
        })?;
        if let Err(error) = self.index.rebuild(&candidate, self.project_id) {
            self.mark_needs_recovery(error.to_string())?;
            return Err(error);
        }
        *journal_guard = candidate;
        *lock(&self.state)? = WriterState::Healthy;
        Ok(())
    }

    pub fn rebuild_index(&self) -> Result<()> {
        let journal = lock(&self.journal)?;
        self.index.rebuild(&journal, self.project_id)
    }

    pub fn put_blob<R: Read>(
        &self,
        reader: R,
        media_type: impl Into<String>,
        filename: Option<String>,
    ) -> Result<BlobRef> {
        self.blobs.put_with_metadata(reader, media_type, filename)
    }

    fn mark_needs_recovery(&self, _reason: String) -> Result<()> {
        *lock(&self.state)? = WriterState::NeedsRecovery;
        Ok(())
    }

    #[cfg(test)]
    fn inject_after_journal_append(&self) {
        if let Ok(mut faults) = self.faults.lock() {
            faults.after_journal_append = true;
        }
    }

    #[cfg(test)]
    fn inject_projection_failure(&self) {
        if let Ok(mut faults) = self.faults.lock() {
            faults.projection = true;
        }
    }
}

fn index_head_fingerprint(index: &Index) -> Result<Option<(EventBatchId, String)>> {
    let connection = lock(&index.connection)?;
    let row: Option<(String, String)> = connection
        .query_row(
            "SELECT batch_id, command_digest FROM batch_headers ORDER BY batch_sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(id, digest)| Ok((parse_batch_id(&id)?, digest)))
        .transpose()
}

fn replace_index(layout: &StateLayout, project_id: ProjectId) -> Result<Index> {
    if ensure_regular_file(&layout.index, &layout.state, true)? {
        let token = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("index.sqlite3.incompatible.{token}");
        let replacement = layout.state.join(name);
        fs::rename(&layout.index, &replacement)?;
        set_file_mode(&replacement)?;
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{}", layout.index.display(), suffix));
            if ensure_regular_file(&sidecar, &layout.state, true)? {
                let sidecar_replacement =
                    PathBuf::from(format!("{}{}", replacement.display(), suffix));
                fs::rename(sidecar, sidecar_replacement)?;
            }
        }
        sync_directory(&layout.state)?;
    }
    Index::open(&layout.index, project_id)
}

#[cfg(test)]
#[derive(Default)]
struct FaultInjection {
    after_journal_append: bool,
    projection: bool,
}

#[cfg(test)]
fn take_fault(
    faults: &Mutex<FaultInjection>,
    predicate: impl FnOnce(&FaultInjection) -> bool,
) -> bool {
    let Ok(mut faults) = faults.lock() else {
        return false;
    };
    if predicate(&faults) {
        faults.after_journal_append = false;
        faults.projection = false;
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gorce_protocol::{
        BlobRef, EventActor, EventActorKind, EventCommand, EventRecord, UuidV7, EVENT_BATCH_FORMAT,
    };

    fn temporary_directory(name: &str) -> PathBuf {
        let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("gorce-store-final-{name}-{counter}"));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn batch(
        project_id: ProjectId,
        sequence: u64,
        key: &str,
        event_type: &str,
        data: Value,
    ) -> EventBatch {
        EventBatch {
            format: EVENT_BATCH_FORMAT.to_owned(),
            project_id,
            batch_id: UuidV7::from_uuid(uuid::Uuid::now_v7()).unwrap(),
            batch_sequence: sequence,
            committed_at: "2026-07-26T00:00:00Z".to_owned(),
            actor: EventActor {
                kind: EventActorKind::System,
                operator_id: None,
            },
            command: EventCommand {
                name: "test.command".to_owned(),
                arguments: serde_json::json!({}),
                idempotency_key: key.to_owned(),
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

    fn task_data(project_id: ProjectId, task_id: uuid::Uuid) -> Value {
        serde_json::json!({
            "id": task_id,
            "project_id": project_id,
            "lifecycle": "open",
            "readiness": {"status":"unknown", "blocker_task_ids":[], "evaluated_at":"2026-07-26T00:00:00Z"},
            "current_revision_id": null,
            "created_at": "2026-07-26T00:00:00Z",
            "updated_at": "2026-07-26T00:00:00Z"
        })
    }

    fn valid_authority_base(
        store: &ProjectStoreWriter,
        project_id: ProjectId,
        principal_id: PrincipalId,
    ) -> (
        gorce_protocol::AuthorityPrincipal,
        AuthorityPolicy,
        AuthorityProfileRevision,
    ) {
        use gorce_protocol::{
            AuthorityBudget, AuthorityExecutionDisposition, AuthorityGrant, AuthorityPolicyEffect,
            AuthorityPolicyRule, AuthorityPrincipalKind, PinnedProfileSpec, PinnedSkillReference,
        };

        let timestamp = "2026-07-26T00:00:00Z".to_owned();
        let principal = gorce_protocol::AuthorityPrincipal {
            id: principal_id,
            project_id,
            kind: AuthorityPrincipalKind::LocalControl,
            subject: "local-control".to_owned(),
            created_at: timestamp.clone(),
        };
        let mut policy = AuthorityPolicy {
            id: uuid::Uuid::now_v7(),
            project_id,
            revision: 1,
            rules: vec![AuthorityPolicyRule {
                action: "authority.*".to_owned(),
                resource: project_id.to_string(),
                effect: AuthorityPolicyEffect::Allow,
            }],
            digest: String::new(),
            created_at: timestamp.clone(),
        };
        policy.digest = policy.content_digest().unwrap();
        let mut profile = AuthorityProfileRevision {
            id: uuid::Uuid::now_v7(),
            project_id,
            revision: 1,
            name: "phase1-disabled".to_owned(),
            policy_id: policy.id,
            spec: PinnedProfileSpec {
                execution_disposition: AuthorityExecutionDisposition::Disabled,
                model_component: "disabled-model".to_owned(),
                tool_component: "disabled-tool".to_owned(),
                skills: vec![PinnedSkillReference {
                    name: "disabled".to_owned(),
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
            created_at: timestamp.clone(),
        };
        profile.digest = profile.content_digest().unwrap();

        let connection = lock(&store.index.connection).unwrap();
        connection
            .execute(
                "INSERT INTO principals(id,project_id,kind,subject,created_at,value_json,updated_sequence)
                 VALUES (?1,?2,'local_control',?3,?4,?5,0)",
                params![
                    principal.id.to_string(),
                    project_id.to_string(),
                    &principal.subject,
                    &principal.created_at,
                    serde_json::to_string(&principal).unwrap(),
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO policies(id,project_id,revision,digest,created_at,value_json,updated_sequence)
                 VALUES (?1,?2,?3,?4,?5,?6,0)",
                params![
                    policy.id.to_string(),
                    project_id.to_string(),
                    sql_integer(policy.revision).unwrap(),
                    &policy.digest,
                    &policy.created_at,
                    serde_json::to_string(&policy).unwrap(),
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO profile_revisions(id,project_id,revision,name,policy_id,execution_disposition,digest,created_at,value_json,updated_sequence)
                 VALUES (?1,?2,?3,?4,?5,'disabled',?6,?7,?8,0)",
                params![
                    profile.id.to_string(),
                    project_id.to_string(),
                    sql_integer(profile.revision).unwrap(),
                    &profile.name,
                    profile.policy_id.to_string(),
                    &profile.digest,
                    &profile.created_at,
                    serde_json::to_string(&profile).unwrap(),
                ],
            )
            .unwrap();
        (principal, policy, profile)
    }

    #[test]
    fn exposes_the_storage_format_version() {
        assert_eq!(storage_format_version(), STORAGE_FORMAT_VERSION);
    }

    #[test]
    fn second_open_attempt_is_typed_locked_error() {
        let directory = temporary_directory("lock");
        let project_id = uuid::Uuid::now_v7();
        let first = ProjectStoreWriter::open(&directory, project_id).unwrap();
        let expected_lock_path =
            fs::canonicalize(directory.join(STATE_DIRECTORY).join(WRITER_LOCK_FILE)).unwrap();
        let error = match ProjectStoreWriter::open(&directory, project_id) {
            Ok(_) => panic!("second opener unexpectedly succeeded"),
            Err(error) => error,
        };
        match error {
            StoreError::StoreAlreadyLocked { path } => assert_eq!(path, expected_lock_path),
            other => panic!("second opener returned unexpected error: {other:?}"),
        }
        drop(first);
        assert!(ProjectStoreWriter::open(&directory, project_id).is_ok());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn lock_contention_predicate_maps_portable_and_non_contention_errors() {
        assert!(is_lock_contention(&io::Error::from(
            io::ErrorKind::WouldBlock
        )));
        assert!(!is_lock_contention(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "access denied",
        )));
        assert!(!is_lock_contention(&io::Error::from_raw_os_error(5)));
    }

    #[cfg(windows)]
    #[test]
    fn lock_contention_predicate_maps_windows_lock_errors() {
        assert!(is_lock_contention(&io::Error::from_raw_os_error(32)));
        assert!(is_lock_contention(&io::Error::from_raw_os_error(33)));
    }

    #[cfg(unix)]
    #[test]
    fn controlled_symlink_is_rejected() {
        use std::os::unix::fs::symlink;
        let directory = temporary_directory("symlink");
        symlink("/tmp", directory.join(".gorce")).unwrap();
        let error = match ProjectStoreWriter::open(&directory, uuid::Uuid::now_v7()) {
            Ok(_) => panic!("symlinked store unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(matches!(error, StoreError::SymlinkRejected { .. }));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn idempotent_retry_returns_original_location_and_conflict() {
        let directory = temporary_directory("idempotency");
        let project_id = uuid::Uuid::now_v7();
        let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
        let first_batch = batch(
            project_id,
            1,
            "retry-key",
            "task.created",
            task_data(project_id, uuid::Uuid::now_v7()),
        );
        let first = store.append(&first_batch).unwrap();
        let retry = store.append(&first_batch).unwrap();
        assert!(retry.duplicate);
        assert_eq!(retry.location, first.location);
        let mut conflict = first_batch.clone();
        conflict.batch_id = UuidV7::from_uuid(uuid::Uuid::now_v7()).unwrap();
        conflict.command.arguments = serde_json::json!({"changed":true});
        let error = store.append(&conflict).unwrap_err();
        assert!(matches!(error, StoreError::IdempotencyConflict { .. }));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn validation_and_blob_reference_happen_before_journal_growth() {
        let directory = temporary_directory("references");
        let project_id = uuid::Uuid::now_v7();
        let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
        let mut invalid = batch(
            project_id,
            1,
            "invalid",
            "task.created",
            task_data(project_id, uuid::Uuid::now_v7()),
        );
        invalid.command.idempotency_key.clear();
        assert!(matches!(
            store.append(&invalid),
            Err(StoreError::BatchValidation(_))
        ));
        let before = fs::read_dir(store.journal_dir()).unwrap().count();
        assert_eq!(before, 0);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn authority_references_fail_before_append_and_during_rebuild() {
        use gorce_protocol::{
            AuthorityBudget, AuthorityExecutionDisposition, AuthorityGrant,
            AuthorityProfileRevision, PinnedProfileSpec, PinnedSkillReference,
            AUTHORITY_PROFILE_REGISTERED_EVENT,
        };
        let directory = temporary_directory("authority-preflight");
        let project_id = uuid::Uuid::now_v7();
        let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
        let mut profile = AuthorityProfileRevision {
            id: uuid::Uuid::now_v7(),
            project_id,
            revision: 1,
            name: "disabled".to_owned(),
            policy_id: uuid::Uuid::now_v7(),
            spec: PinnedProfileSpec {
                execution_disposition: AuthorityExecutionDisposition::Disabled,
                model_component: "disabled-model".to_owned(),
                tool_component: "disabled-tool".to_owned(),
                skills: vec![PinnedSkillReference {
                    name: "disabled".to_owned(),
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
            created_at: "2026-07-26T00:00:00Z".to_owned(),
        };
        profile.digest = profile.content_digest().unwrap();
        let invalid = batch(
            project_id,
            1,
            "authority-invalid",
            AUTHORITY_PROFILE_REGISTERED_EVENT,
            serde_json::to_value(profile).unwrap(),
        );
        assert!(matches!(
            store.append(&invalid),
            Err(StoreError::InvalidFormat(_)) | Err(StoreError::BatchValidation(_))
        ));
        assert!(store.history_page(0, 10).unwrap().entries.is_empty());
        {
            let mut journal = store.journal.lock().unwrap();
            journal.append(&invalid).unwrap();
        }
        assert!(store.rebuild_index().is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn missing_and_symlink_blob_references_are_rejected_before_append() {
        let directory = temporary_directory("blob-reference");
        let project_id = uuid::Uuid::now_v7();
        let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
        let mut missing = batch(
            project_id,
            1,
            "missing-blob",
            "task.created",
            task_data(project_id, uuid::Uuid::now_v7()),
        );
        missing.referenced_blobs = vec![BlobRef {
            digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            size_bytes: 1,
            media_type: "text/plain".to_owned(),
            filename: None,
        }];
        assert!(matches!(
            store.append(&missing),
            Err(StoreError::MissingBlob { .. })
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let path = store
                .blobs_dir()
                .join("sha256")
                .join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
            symlink("/tmp", &path).unwrap();
            let mut linked = missing;
            linked.batch_sequence = 1;
            linked.command.idempotency_key = "linked-blob".to_owned();
            linked.referenced_blobs[0].digest =
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_owned();
            assert!(matches!(
                store.append(&linked),
                Err(StoreError::SymlinkRejected { .. })
            ));
        }
        assert_eq!(fs::read_dir(store.journal_dir()).unwrap().count(), 0);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn unknown_semantic_event_stops_at_exact_cursor() {
        let directory = temporary_directory("unknown-event");
        let project_id = uuid::Uuid::now_v7();
        let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
        let unknown = batch(
            project_id,
            1,
            "unknown-event",
            "future.event",
            task_data(project_id, uuid::Uuid::now_v7()),
        );
        assert!(matches!(
            store.append(&unknown),
            Err(StoreError::SemanticProjection {
                batch_sequence: 1,
                event_ordinal: 0,
                ..
            })
        ));
        assert_eq!(fs::read_dir(store.journal_dir()).unwrap().count(), 0);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn history_page_is_bounded() {
        let directory = temporary_directory("history-page");
        let project_id = uuid::Uuid::now_v7();
        let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
        let task_id = uuid::Uuid::now_v7();
        for sequence in 1..=3 {
            let event_batch = batch(
                project_id,
                sequence,
                &format!("history-{sequence}"),
                "task.created",
                task_data(project_id, task_id),
            );
            store.append(event_batch).unwrap();
        }
        let page = store.history_page(0, 1).unwrap();
        assert_eq!(page.entries.len(), 1);
        assert!(page.has_more);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn health_blocks_after_durable_journal_failure_until_recovery() {
        let directory = temporary_directory("health");
        let project_id = uuid::Uuid::now_v7();
        let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
        let event_batch = batch(
            project_id,
            1,
            "health-key",
            "task.created",
            task_data(project_id, uuid::Uuid::now_v7()),
        );
        store.inject_after_journal_append();
        assert!(store.append(&event_batch).is_err());
        assert_eq!(store.writer_state().unwrap(), WriterState::NeedsRecovery);
        assert!(matches!(
            store.append(&event_batch),
            Err(StoreError::NeedsRecovery { .. })
        ));
        store.recover().unwrap();
        assert_eq!(store.writer_state().unwrap(), WriterState::Healthy);
        assert!(store.append(&event_batch).unwrap().duplicate);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn projection_failure_requires_recovery() {
        let directory = temporary_directory("projection-failure");
        let project_id = uuid::Uuid::now_v7();
        let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
        let event_batch = batch(
            project_id,
            1,
            "projection-key",
            "task.created",
            task_data(project_id, uuid::Uuid::now_v7()),
        );
        store.inject_projection_failure();
        assert!(store.append(&event_batch).is_err());
        assert_eq!(store.writer_state().unwrap(), WriterState::NeedsRecovery);
        store.recover().unwrap();
        assert_eq!(store.index().index_watermark().unwrap(), 1);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn oversized_jsonl_line_is_rejected_before_append() {
        let directory = temporary_directory("line-limit");
        let project_id = uuid::Uuid::now_v7();
        let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
        let mut event_batch = batch(
            project_id,
            1,
            "large-key",
            "task.created",
            task_data(project_id, uuid::Uuid::now_v7()),
        );
        event_batch.command.arguments =
            serde_json::json!({"large": "x".repeat(MAX_JSONL_LINE_BYTES)});
        assert!(matches!(
            store.append(&event_batch),
            Err(StoreError::BatchValidation(_)) | Err(StoreError::InvalidArgument(_))
        ));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn semantic_projection_rebuild_has_parity() {
        let directory = temporary_directory("semantic");
        let project_id = uuid::Uuid::now_v7();
        let task_id = uuid::Uuid::now_v7();
        let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
        let event_batch = batch(
            project_id,
            1,
            "semantic-key",
            "task.created",
            task_data(project_id, task_id),
        );
        store.append(event_batch).unwrap();
        let before = store.index().semantic_snapshot().unwrap();
        store.rebuild_index().unwrap();
        let after = store.index().semantic_snapshot().unwrap();
        assert_eq!(before, after);
        assert!(store
            .index()
            .entity_json("tasks", &task_id.to_string())
            .unwrap()
            .is_some());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn authority_envelope_rejects_mismatched_receipt_before_append() {
        use gorce_protocol::{
            AuthorityBudget, AuthorityCommandReceipt, AuthorityExecutionDisposition,
            AuthorityGrant, AuthorityPolicy, AuthorityPolicyEffect, AuthorityPolicyRule,
            AuthorityPrincipal, AuthorityPrincipalKind, AuthorityProfileRevision, CommandCommit,
            CommandResult, CommandResultKind, EmptyCommandArguments, OperatorBinding,
            PinnedProfileSpec, PinnedSkillReference, ResourceKind, ResourceReference,
            AUTHORITY_COMMAND_RECORDED_EVENT, AUTHORITY_OPERATOR_BOUND_EVENT,
            AUTHORITY_POLICY_CREATED_EVENT, AUTHORITY_PRINCIPAL_CREATED_EVENT,
            AUTHORITY_PROFILE_REGISTERED_EVENT,
        };
        let directory = temporary_directory("authority-projection");
        let project_id = uuid::Uuid::now_v7();
        let principal_id = uuid::Uuid::now_v7();
        let policy_id = uuid::Uuid::now_v7();
        let profile_id = uuid::Uuid::now_v7();
        let binding_id = uuid::Uuid::now_v7();
        let operator_id = uuid::Uuid::now_v7();
        let batch_id = UuidV7::from_uuid(uuid::Uuid::now_v7()).unwrap();
        let timestamp = "2026-07-26T00:00:00Z";
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
            created_at: timestamp.to_owned(),
        };
        policy.digest = policy.content_digest().unwrap();
        let mut profile = AuthorityProfileRevision {
            id: profile_id,
            project_id,
            revision: 1,
            name: "phase1-disabled".to_owned(),
            policy_id,
            spec: PinnedProfileSpec {
                execution_disposition: AuthorityExecutionDisposition::Disabled,
                model_component: "disabled-model".to_owned(),
                tool_component: "disabled-tool".to_owned(),
                skills: vec![PinnedSkillReference {
                    name: "disabled".to_owned(),
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
            created_at: timestamp.to_owned(),
        };
        profile.digest = profile.content_digest().unwrap();
        let principal = AuthorityPrincipal {
            id: principal_id,
            project_id,
            kind: AuthorityPrincipalKind::LocalControl,
            subject: "local-control".to_owned(),
            created_at: timestamp.to_owned(),
        };
        let binding = OperatorBinding {
            id: binding_id,
            project_id,
            principal_id,
            operator_id,
            profile_revision_id: profile_id,
            policy_id,
            created_at: timestamp.to_owned(),
        };
        let result = CommandCommit {
            project_id,
            batch_id,
            batch_sequence: 1,
            public_cursors: Vec::new(),
            result: CommandResult {
                kind: CommandResultKind::Created,
                resource_refs: vec![ResourceReference {
                    kind: ResourceKind::ProfileRevision,
                    id: profile_id,
                }],
            },
            evidence_refs: Vec::new(),
        };
        let receipt = AuthorityCommandReceipt {
            principal_id,
            idempotency_key: "authority-key".to_owned(),
            command_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            result,
        };
        let events = vec![
            (
                AUTHORITY_COMMAND_RECORDED_EVENT,
                serde_json::to_value(receipt).unwrap(),
            ),
            (
                AUTHORITY_PRINCIPAL_CREATED_EVENT,
                serde_json::to_value(principal).unwrap(),
            ),
            (
                AUTHORITY_POLICY_CREATED_EVENT,
                serde_json::to_value(policy).unwrap(),
            ),
            (
                AUTHORITY_PROFILE_REGISTERED_EVENT,
                serde_json::to_value(profile).unwrap(),
            ),
            (
                AUTHORITY_OPERATOR_BOUND_EVENT,
                serde_json::to_value(binding).unwrap(),
            ),
        ];
        let event_batch = EventBatch {
            format: EVENT_BATCH_FORMAT.to_owned(),
            project_id,
            batch_id,
            batch_sequence: 1,
            committed_at: timestamp.to_owned(),
            actor: EventActor {
                kind: EventActorKind::Service,
                operator_id: None,
            },
            command: EventCommand {
                name: "authority.command".to_owned(),
                arguments: serde_json::to_value(EmptyCommandArguments {}).unwrap(),
                idempotency_key: "authority:principal:authority-key".to_owned(),
            },
            base_revisions: BTreeMap::new(),
            events: events
                .into_iter()
                .enumerate()
                .map(|(ordinal, (event_type, data))| EventRecord {
                    ordinal: ordinal as u64,
                    event_type: event_type.to_owned(),
                    schema_version: 1,
                    data,
                })
                .collect(),
            referenced_blobs: Vec::new(),
        };
        let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
        assert!(matches!(
            store.append(&event_batch),
            Err(StoreError::BatchValidation(_))
        ));
        assert!(store.history_page(0, 10).unwrap().entries.is_empty());
        store.journal.lock().unwrap().append(&event_batch).unwrap();
        assert!(matches!(
            store.rebuild_index(),
            Err(StoreError::BatchValidation(_))
                | Err(StoreError::InvalidFormat(_))
                | Err(StoreError::SemanticProjection { .. })
        ));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn v3_legacy_commands_index_is_rebuilt_for_scoped_key_reuse() {
        let directory = temporary_directory("legacy-idempotency");
        let project_id = uuid::Uuid::now_v7();
        {
            let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
            drop(store);
        }
        let index_path = directory.join(STATE_DIRECTORY).join(INDEX_FILE);
        {
            let connection = Connection::open(&index_path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE migration_sentinel(marker TEXT NOT NULL);
                     INSERT INTO migration_sentinel(marker) VALUES ('in-place');",
                )
                .unwrap();
            connection
                .execute_batch(
                    "ALTER TABLE commands RENAME TO commands_current;
                     CREATE TABLE commands (
                         idempotency_key TEXT PRIMARY KEY,
                         batch_id TEXT NOT NULL UNIQUE,
                         batch_sequence INTEGER NOT NULL UNIQUE,
                         command_digest TEXT NOT NULL,
                         segment TEXT NOT NULL,
                         byte_offset INTEGER NOT NULL,
                         byte_length INTEGER NOT NULL
                     );
                     INSERT INTO commands(idempotency_key,batch_id,batch_sequence,command_digest,segment,byte_offset,byte_length)
                         SELECT idempotency_key,batch_id,batch_sequence,command_digest,segment,byte_offset,byte_length FROM commands_current;
                     DROP TABLE commands_current;
                     DELETE FROM schema_migrations WHERE version = 5;
                     PRAGMA user_version = 3;",
                )
                .unwrap();
        }
        let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
        drop(store);
        let connection = Connection::open(index_path).unwrap();
        let sentinel: String = connection
            .query_row("SELECT marker FROM migration_sentinel", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(sentinel, "in-place");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, INDEX_SCHEMA_VERSION);
        let primary_key: i64 = connection
            .query_row(
                "SELECT pk FROM pragma_table_info('commands') WHERE name = 'idempotency_key'",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap()
            .unwrap_or(0);
        assert_eq!(primary_key, 0);
        let key = "x".repeat(gorce_protocol::MAX_IDEMPOTENCY_KEY_BYTES);
        connection
            .execute(
                "INSERT INTO commands(idempotency_key,batch_id,batch_sequence,command_digest,segment,byte_offset,byte_length) VALUES (?1, '00000000-0000-7000-8000-000000000001', 1, 'd', 'segment-00000000000000000001.jsonl', 0, 1)",
                params![&key],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO commands(idempotency_key,batch_id,batch_sequence,command_digest,segment,byte_offset,byte_length) VALUES (?1, '00000000-0000-7000-8000-000000000002', 2, 'd', 'segment-00000000000000000001.jsonl', 1, 1)",
                params![&key],
            )
            .unwrap();
        let first_principal = uuid::Uuid::now_v7();
        let second_principal = uuid::Uuid::now_v7();
        for (principal, subject) in [(first_principal, "first"), (second_principal, "second")] {
            connection
                .execute(
                    "INSERT INTO principals(id,project_id,kind,subject,created_at,value_json,updated_sequence) VALUES (?1,?2,'local_control',?3,'2026-01-01T00:00:00Z','{}',0)",
                    params![principal.to_string(), project_id.to_string(), subject],
                )
                .unwrap();
        }
        for (principal, batch_id, sequence) in [
            (
                first_principal,
                "00000000-0000-7000-8000-000000000011",
                11_i64,
            ),
            (
                second_principal,
                "00000000-0000-7000-8000-000000000012",
                12_i64,
            ),
        ] {
            connection
                .execute(
                    "INSERT INTO authority_commands(project_id,principal_id,idempotency_key,command_digest,result_json,batch_id,batch_sequence) VALUES (?1,?2,?3,'d','{}',?4,?5)",
                    params![project_id.to_string(), principal.to_string(), &key, batch_id, sequence],
                )
                .unwrap();
        }
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn authority_ready_validation_rejects_partial_mismatched_extra_and_corrupt_rows() {
        let cases = ["partial", "mismatched", "extra", "normalized"];
        for case in cases {
            let directory = temporary_directory(&format!("authority-state-{case}"));
            let project_id = uuid::Uuid::now_v7();
            let principal_id = uuid::Uuid::now_v7();
            let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
            let (principal, _policy, _profile) =
                valid_authority_base(&store, project_id, principal_id);
            let connection = lock(&store.index.connection).unwrap();
            match case {
                "partial" => {
                    connection
                        .execute(
                            "DELETE FROM principals WHERE id = ?1",
                            params![principal.id.to_string()],
                        )
                        .unwrap();
                }
                "mismatched" => {
                    connection
                        .execute(
                            "UPDATE principals SET project_id = ?1 WHERE id = ?2",
                            params![uuid::Uuid::now_v7().to_string(), principal.id.to_string()],
                        )
                        .unwrap();
                }
                "extra" => {
                    let extra = gorce_protocol::AuthorityPrincipal {
                        id: uuid::Uuid::now_v7(),
                        project_id,
                        kind: gorce_protocol::AuthorityPrincipalKind::LocalControl,
                        subject: "extra-principal".to_owned(),
                        created_at: "2026-07-26T00:00:00Z".to_owned(),
                    };
                    connection
                        .execute(
                            "INSERT INTO principals(id,project_id,kind,subject,created_at,value_json,updated_sequence)
                             VALUES (?1,?2,'local_control',?3,?4,?5,0)",
                            params![
                                extra.id.to_string(),
                                project_id.to_string(),
                                &extra.subject,
                                &extra.created_at,
                                serde_json::to_string(&extra).unwrap(),
                            ],
                        )
                        .unwrap();
                }
                "normalized" => {
                    connection
                        .execute(
                            "UPDATE principals SET kind = 'service' WHERE id = ?1",
                            params![principal.id.to_string()],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            drop(connection);
            assert_eq!(
                store.index().authority_state(principal_id).unwrap(),
                AuthorityState::Invalid,
                "case {case} unexpectedly passed Ready validation"
            );
            drop(store);
            let _ = fs::remove_dir_all(directory);
        }
    }

    #[test]
    fn valid_authority_projection_is_ready() {
        let directory = temporary_directory("authority-ready");
        let project_id = uuid::Uuid::now_v7();
        let principal_id = uuid::Uuid::now_v7();
        let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
        let (principal, _policy, _profile) = valid_authority_base(&store, project_id, principal_id);
        assert_eq!(
            store.index().authority_state(principal.id).unwrap(),
            AuthorityState::Ready
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn authority_schema_rejects_global_idempotency_and_preserves_fk_grouping() {
        let directory = temporary_directory("authority-schema-index");
        let project_id = uuid::Uuid::now_v7();
        let principal_id = uuid::Uuid::now_v7();
        let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
        let connection = Connection::open(store.index_path()).unwrap();
        connection
            .execute(
                "CREATE UNIQUE INDEX bad_authority_idempotency ON authority_commands(idempotency_key)",
                [],
            )
            .unwrap();
        assert_eq!(
            store.index().authority_state(principal_id).unwrap(),
            AuthorityState::Invalid
        );
        drop(connection);
        drop(store);
        let _ = fs::remove_dir_all(directory);

        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE principals(project_id TEXT NOT NULL, id TEXT NOT NULL, PRIMARY KEY(project_id,id));
                 CREATE TABLE policies(project_id TEXT NOT NULL, id TEXT NOT NULL, PRIMARY KEY(project_id,id));
                 CREATE TABLE bindings(
                     project_id TEXT NOT NULL,
                     principal_id TEXT NOT NULL,
                     policy_id TEXT NOT NULL,
                     FOREIGN KEY(project_id,principal_id) REFERENCES principals(project_id,id),
                     FOREIGN KEY(project_id,policy_id) REFERENCES policies(project_id,id)
                 );",
            )
            .unwrap();
        assert!(foreign_keys_match(
            &connection,
            "bindings",
            &[
                (
                    "principals",
                    &[("project_id", "project_id"), ("principal_id", "id")],
                ),
                (
                    "policies",
                    &[("project_id", "project_id"), ("policy_id", "id")],
                ),
            ],
        )
        .unwrap());
        assert!(!foreign_keys_match(
            &connection,
            "bindings",
            &[
                (
                    "principals",
                    &[("project_id", "id"), ("principal_id", "project_id")],
                ),
                (
                    "policies",
                    &[("project_id", "project_id"), ("policy_id", "id")],
                ),
            ],
        )
        .unwrap());
    }

    #[test]
    fn reopen_keeps_journal_and_index_heads_bound() {
        let directory = temporary_directory("reopen");
        let project_id = uuid::Uuid::now_v7();
        let event_batch = batch(
            project_id,
            1,
            "reopen-key",
            "task.created",
            task_data(project_id, uuid::Uuid::now_v7()),
        );
        {
            let store = ProjectStoreWriter::open(&directory, project_id).unwrap();
            store.append(event_batch).unwrap();
        }
        let reopened = ProjectStoreWriter::open(&directory, project_id).unwrap();
        assert_eq!(reopened.index().index_watermark().unwrap(), 1);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn blob_stream_is_content_addressed_and_bounded() {
        let directory = temporary_directory("blob");
        let state = ProjectStoreWriter::open(&directory, uuid::Uuid::now_v7()).unwrap();
        let blob = state
            .blobs()
            .put_reader(&b"hello"[..], "text/plain")
            .unwrap();
        assert_eq!(blob.size_bytes, 5);
        assert!(state.blobs().contains(&blob.digest).unwrap());
        let _ = fs::remove_dir_all(directory);
    }
}
