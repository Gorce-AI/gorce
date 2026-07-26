#![forbid(unsafe_code)]

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
use gorce_protocol::{
    BlobRef, EventBatch, EventBatchId, EventRecord, GoalRevision, Message, PlanRevision, ProjectId,
    Task, TaskAttempt, TaskAttemptStatus, TaskEdge, TaskLifecycle, TaskReadiness, Workstream,
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
const INDEX_SCHEMA_VERSION: i64 = 3;
const MAX_METADATA_VALUE_BYTES: usize = 16 * 1024;
const COPY_BUFFER_SIZE: usize = 64 * 1024;
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_file_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
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

struct StateLayout {
    state: PathBuf,
    journal: PathBuf,
    blobs: PathBuf,
    cas: PathBuf,
    tmp: PathBuf,
    index: PathBuf,
    lock: PathBuf,
}

impl StateLayout {
    fn create(project_root: &Path) -> Result<Self> {
        let gorce = ensure_directory(&project_root.join(".gorce"), project_root)?;
        let state = ensure_directory(&gorce.join("state"), project_root)?;
        let journal = ensure_directory(&state.join(JOURNAL_DIRECTORY), &state)?;
        let blobs = ensure_directory(&state.join(BLOB_DIRECTORY), &state)?;
        let cas = ensure_directory(&blobs.join("sha256"), &state)?;
        let tmp = ensure_directory(&blobs.join("tmp"), &state)?;
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
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        set_file_mode(path)?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Self {
                file,
                path: path.to_owned(),
            }),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                Err(StoreError::StoreAlreadyLocked {
                    path: path.to_owned(),
                })
            }
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
    "batch_headers",
    "event_locations",
    "current_metadata",
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
    "batch_headers",
    "event_locations",
    "current_metadata",
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
    if version != 0 && version != INDEX_SCHEMA_VERSION {
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
                 idempotency_key TEXT NOT NULL UNIQUE,
                 command_digest TEXT NOT NULL,
                 segment TEXT NOT NULL,
                 byte_offset INTEGER NOT NULL,
                 byte_length INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS commands (
                 idempotency_key TEXT PRIMARY KEY,
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
             INSERT INTO store_metadata(key, value) VALUES
                 ('project_id', ''), ('journal_watermark', '0'),
                 ('index_watermark', '0'), ('projection_digest', '');
             INSERT INTO schema_migrations(version, applied_at) VALUES (3, 'initial');
             PRAGMA user_version = 3;
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
    let input = batch.command.canonical_payload_digest_input()?;
    Ok(format!("sha256:{:x}", Sha256::digest(input)))
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
    for event in &batch.events {
        match projection_mutation(batch, event)? {
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
            )?,
            ProjectionMutation::TaskPatch { id, field, value } => patch_entity(
                transaction,
                "tasks",
                &id,
                field,
                value,
                batch.batch_sequence,
            )?,
            ProjectionMutation::AttemptPatch { id, field, value } => patch_entity(
                transaction,
                "task_attempts",
                &id,
                field,
                value,
                batch.batch_sequence,
            )?,
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

pub struct ProjectStore {
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

pub type Store = ProjectStore;
pub type Storage = ProjectStore;

impl ProjectStore {
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

    pub fn append_batch<B: Borrow<EventBatch>>(&self, batch: B) -> Result<AppendResult> {
        let batch = batch.borrow();
        self.append_validated(batch)
    }

    pub fn append<B: Borrow<EventBatch>>(&self, batch: B) -> Result<AppendResult> {
        self.append_batch(batch)
    }

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
        for event in &batch.events {
            projection_mutation(batch, event)?;
        }
        for blob in &batch.referenced_blobs {
            self.blobs.verify_reference(blob)?;
        }
        let digest = command_digest(batch)?;
        let mut journal = lock(&self.journal)?;
        if let Some(existing) = self.index.idempotency(&batch.command.idempotency_key)? {
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

    #[test]
    fn exposes_the_storage_format_version() {
        assert_eq!(storage_format_version(), STORAGE_FORMAT_VERSION);
    }

    #[test]
    fn second_open_attempt_is_typed_locked_error() {
        let directory = temporary_directory("lock");
        let project_id = uuid::Uuid::now_v7();
        let first = ProjectStore::open(&directory, project_id).unwrap();
        let error = match ProjectStore::open(&directory, project_id) {
            Ok(_) => panic!("second opener unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(matches!(error, StoreError::StoreAlreadyLocked { .. }));
        drop(first);
        assert!(ProjectStore::open(&directory, project_id).is_ok());
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn controlled_symlink_is_rejected() {
        use std::os::unix::fs::symlink;
        let directory = temporary_directory("symlink");
        symlink("/tmp", directory.join(".gorce")).unwrap();
        let error = match ProjectStore::open(&directory, uuid::Uuid::now_v7()) {
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
        let store = ProjectStore::open(&directory, project_id).unwrap();
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
        let store = ProjectStore::open(&directory, project_id).unwrap();
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
    fn missing_and_symlink_blob_references_are_rejected_before_append() {
        let directory = temporary_directory("blob-reference");
        let project_id = uuid::Uuid::now_v7();
        let store = ProjectStore::open(&directory, project_id).unwrap();
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
        let store = ProjectStore::open(&directory, project_id).unwrap();
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
        let store = ProjectStore::open(&directory, project_id).unwrap();
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
        let store = ProjectStore::open(&directory, project_id).unwrap();
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
        let store = ProjectStore::open(&directory, project_id).unwrap();
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
        let store = ProjectStore::open(&directory, project_id).unwrap();
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
        let store = ProjectStore::open(&directory, project_id).unwrap();
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
            let store = ProjectStore::open(&directory, project_id).unwrap();
            store.append(event_batch).unwrap();
        }
        let reopened = ProjectStore::open(&directory, project_id).unwrap();
        assert_eq!(reopened.index().index_watermark().unwrap(), 1);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn blob_stream_is_content_addressed_and_bounded() {
        let directory = temporary_directory("blob");
        let state = ProjectStore::open(&directory, uuid::Uuid::now_v7()).unwrap();
        let blob = state
            .blobs()
            .put_reader(&b"hello"[..], "text/plain")
            .unwrap();
        assert_eq!(blob.size_bytes, 5);
        assert!(state.blobs().contains(&blob.digest).unwrap());
        let _ = fs::remove_dir_all(directory);
    }
}
