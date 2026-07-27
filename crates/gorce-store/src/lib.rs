#![forbid(unsafe_code)]

//! Read-only access to an existing Gorce project store.
//!
//! Mutable layout creation, journal append, projection, and recovery live in
//! the unpublished `gorce-store-writer` package. Keeping this crate reader
//! only makes the normal library dependency graph unable to name those APIs.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use gorce_protocol::{
    Admission, AuthorityPolicy, AuthorityPrincipal, AuthorityProfileRevision, BlobRef, EventBatch,
    EventBatchId, OperatorBinding, PolicyId, PrincipalId, ProfileRevisionId, ProjectId,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const STORAGE_FORMAT_VERSION: &str = "0.1";
pub const STATE_DIRECTORY: &str = ".gorce/state";
pub const JOURNAL_DIRECTORY: &str = "journal";
pub const BLOB_DIRECTORY: &str = "blobs";
pub const INDEX_FILE: &str = "index.sqlite3";
pub const MAX_JSONL_LINE_BYTES: usize = 1024 * 1024;
pub const MAX_PAGE_SIZE: usize = 500;
pub const MAX_BLOB_SIZE_BYTES: u64 = 25 * 1024 * 1024;

const JOURNAL_SEGMENT_PREFIX: &str = "segment-";
const JOURNAL_SEGMENT_SUFFIX: &str = ".jsonl";

pub fn storage_format_version() -> &'static str {
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
    JournalCorrupt {
        segment: String,
        offset: u64,
        reason: String,
    },
    ProjectMismatch {
        expected: ProjectId,
        actual: ProjectId,
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
            Self::JournalCorrupt {
                segment,
                offset,
                reason,
            } => write!(
                formatter,
                "journal corruption in {segment} at byte {offset}: {reason}"
            ),
            Self::ProjectMismatch { expected, actual } => {
                write!(
                    formatter,
                    "project mismatch: expected {expected}, got {actual}"
                )
            }
            Self::IndexIncompatible(message) => write!(formatter, "incompatible index: {message}"),
            Self::BlobDigestMismatch { expected, actual } => {
                write!(
                    formatter,
                    "blob digest mismatch: expected {expected}, got {actual}"
                )
            }
            Self::BlobSizeMismatch { expected, actual } => {
                write!(
                    formatter,
                    "blob size mismatch: expected {expected}, got {actual}"
                )
            }
            Self::BlobTooLarge { limit } => write!(formatter, "blob exceeds {limit} bytes"),
            Self::MissingBlob { digest } => {
                write!(formatter, "referenced blob is missing: {digest}")
            }
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
    pub result: gorce_protocol::CommandCommit,
}

fn lock<'a, T>(mutex: &'a Mutex<T>) -> Result<MutexGuard<'a, T>> {
    mutex
        .lock()
        .map_err(|_| StoreError::InvalidFormat("reader lock is poisoned".to_owned()))
}

fn reject_symlink(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(StoreError::InvalidFormat(format!(
            "symlink is not allowed: {}",
            path.display()
        )));
    }
    Ok(metadata)
}

fn existing_directory(path: &Path) -> Result<PathBuf> {
    let metadata = reject_symlink(path)?;
    if !metadata.is_dir() {
        return Err(StoreError::InvalidFormat(format!(
            "expected directory: {}",
            path.display()
        )));
    }
    Ok(fs::canonicalize(path)?)
}

fn existing_file(path: &Path) -> Result<PathBuf> {
    let metadata = reject_symlink(path)?;
    if !metadata.is_file() {
        return Err(StoreError::InvalidFormat(format!(
            "expected regular file: {}",
            path.display()
        )));
    }
    Ok(fs::canonicalize(path)?)
}

fn parse_segment_number(name: &str) -> Option<u64> {
    name.strip_prefix(JOURNAL_SEGMENT_PREFIX)?
        .strip_suffix(JOURNAL_SEGMENT_SUFFIX)?
        .parse()
        .ok()
}

fn segment_file_name(number: u64) -> String {
    format!("{JOURNAL_SEGMENT_PREFIX}{number:020}{JOURNAL_SEGMENT_SUFFIX}")
}

struct JournalReader {
    directory: PathBuf,
    segments: Vec<u64>,
    last_sequence: u64,
}

impl JournalReader {
    fn open(directory: &Path, project_id: ProjectId) -> Result<Self> {
        existing_directory(directory)?;
        let mut segments = fs::read_dir(directory)?
            .map(|entry| {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let Some(number) = parse_segment_number(&name) else {
                    return Ok(None);
                };
                let path = entry.path();
                let metadata = reject_symlink(&path)?;
                if !metadata.is_file() {
                    return Err(StoreError::InvalidFormat(format!(
                        "journal segment is not a file: {}",
                        path.display()
                    )));
                }
                Ok(Some(number))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        segments.sort_unstable();
        if segments.is_empty() {
            return Err(StoreError::InvalidFormat(
                "journal has no segments".to_owned(),
            ));
        }
        let reader = Self {
            directory: directory.to_owned(),
            segments,
            last_sequence: 0,
        };
        let mut last: u64 = 0;
        reader.for_each_batch(|batch, _| {
            if batch.project_id != project_id {
                return Err(StoreError::ProjectMismatch {
                    expected: project_id,
                    actual: batch.project_id,
                });
            }
            if batch.batch_sequence != last.saturating_add(1) {
                return Err(StoreError::InvalidFormat(
                    "journal sequence is not contiguous".to_owned(),
                ));
            }
            last = batch.batch_sequence;
            Ok(())
        })?;
        Ok(Self {
            last_sequence: last,
            ..reader
        })
    }

    fn segment_path(&self, number: u64) -> PathBuf {
        self.directory.join(segment_file_name(number))
    }

    fn for_each_batch<F>(&self, mut callback: F) -> Result<()>
    where
        F: FnMut(&EventBatch, &BatchLocation) -> Result<()>,
    {
        for number in &self.segments {
            let segment = segment_file_name(*number);
            let path = self.segment_path(*number);
            let file = OpenOptions::new().read(true).open(&path)?;
            let mut reader = BufReader::new(file);
            let mut offset = 0_u64;
            loop {
                let mut line = Vec::new();
                let read = reader.read_until(b'\n', &mut line)?;
                if read == 0 {
                    break;
                }
                if read > MAX_JSONL_LINE_BYTES {
                    return Err(StoreError::JournalCorrupt {
                        segment: segment.clone(),
                        offset,
                        reason: "line exceeds configured limit".to_owned(),
                    });
                }
                while line
                    .last()
                    .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
                {
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
                    .map_err(|error| StoreError::BatchValidation(error.to_string()))?;
                let location = BatchLocation {
                    segment: segment.clone(),
                    byte_offset: offset,
                    byte_length: read as u64,
                    batch_sequence: batch.batch_sequence,
                    batch_id: batch.batch_id,
                };
                callback(&batch, &location)?;
                offset = offset.saturating_add(read as u64);
            }
        }
        Ok(())
    }

    fn page(&self, after_sequence: u64, limit: usize) -> Result<HistoryPage> {
        let limit = limit.clamp(1, MAX_PAGE_SIZE);
        let mut entries = Vec::with_capacity(limit);
        let mut has_more = false;
        self.for_each_batch(|batch, location| {
            if batch.batch_sequence <= after_sequence {
                return Ok(());
            }
            if entries.len() < limit {
                entries.push(HistoryEntry {
                    batch: batch.clone(),
                    location: location.clone(),
                });
            } else {
                has_more = true;
            }
            Ok(())
        })?;
        let next_sequence = entries.last().map(|entry| entry.batch.batch_sequence);
        Ok(HistoryPage {
            entries,
            next_sequence,
            has_more,
        })
    }
}

pub struct Index {
    path: PathBuf,
    connection: Mutex<Connection>,
}

impl Index {
    fn open_existing(path: &Path, project_id: ProjectId) -> Result<Self> {
        let path = existing_file(path)?;
        let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
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
        Ok(Self {
            path,
            connection: Mutex::new(connection),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn journal_watermark(&self) -> Result<u64> {
        self.metadata_u64("journal_watermark")
    }
    pub fn index_watermark(&self) -> Result<u64> {
        self.metadata_u64("index_watermark")
    }
    pub fn watermarks(&self) -> Result<(u64, u64)> {
        Ok((self.journal_watermark()?, self.index_watermark()?))
    }

    pub fn projection_digest(&self) -> Result<String> {
        self.metadata_text("projection_digest")
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
        let value: Option<String> = connection
            .query_row(
                &format!("SELECT value_json FROM {kind} WHERE id = ?1"),
                params![id],
                |row| row.get(0),
            )
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
        let value: Option<String> = connection.query_row(
            "SELECT value_json FROM operator_bindings WHERE project_id = ?1 AND json_extract(value_json, '$.operator_id') = ?2 ORDER BY updated_sequence DESC LIMIT 1",
            params![project_id, operator_id.to_string()], |row| row.get(0)
        ).optional()?;
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
        let value: Option<String> = connection.query_row(
            "SELECT value_json FROM admissions WHERE project_id = ?1 AND json_extract(value_json, '$.run_id') = ?2 ORDER BY updated_sequence DESC LIMIT 1",
            params![project_id, run_id.to_string()], |row| row.get(0)
        ).optional()?;
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
        let row: Option<(String, String, String)> = connection.query_row(
            "SELECT command_digest, idempotency_key, result_json FROM authority_commands WHERE principal_id = ?1 AND idempotency_key = ?2",
            params![principal_id.to_string(), idempotency_key], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        ).optional()?;
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

    pub fn current_metadata(&self) -> Result<Vec<MetadataEntry>> {
        let connection = lock(&self.connection)?;
        let mut statement = connection
            .prepare("SELECT key, value, batch_sequence FROM current_metadata ORDER BY key")?;
        let rows = statement.query_map([], |row| {
            Ok(MetadataEntry {
                key: row.get(0)?,
                value: row.get(1)?,
                batch_sequence: sql_u64(row.get(2)?)?,
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

    fn metadata_text(&self, key: &str) -> Result<String> {
        Ok(lock(&self.connection)?.query_row(
            "SELECT value FROM store_metadata WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )?)
    }

    fn metadata_u64(&self, key: &str) -> Result<u64> {
        self.metadata_text(key)?
            .parse()
            .map_err(|_| StoreError::InvalidFormat(format!("invalid metadata value for {key}")))
    }

    fn project_id_from_metadata(&self) -> Result<String> {
        self.metadata_text("project_id")
    }

    fn authority_value<T: for<'de> serde::Deserialize<'de>>(
        &self,
        table: &str,
        id: Option<&str>,
    ) -> Result<Option<T>> {
        let connection = lock(&self.connection)?;
        let value: Option<String> = if let Some(id) = id {
            connection
                .query_row(
                    &format!("SELECT value_json FROM {table} WHERE id = ?1"),
                    params![id],
                    |row| row.get(0),
                )
                .optional()?
        } else {
            connection
                .query_row(
                    &format!(
                        "SELECT value_json FROM {table} ORDER BY updated_sequence DESC LIMIT 1"
                    ),
                    [],
                    |row| row.get(0),
                )
                .optional()?
        };
        value
            .map(|value| serde_json::from_str(&value).map_err(StoreError::from))
            .transpose()
    }
}

fn sql_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
}

const ENTITY_TABLES: &[&str] = &[
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

pub struct ProjectStore {
    project_root: PathBuf,
    project_id: ProjectId,
    journal: JournalReader,
    index: Index,
    blobs: BlobStore,
}

pub type ProjectStoreReader = ProjectStore;

impl ProjectStore {
    /// Opens an already initialized project without creating, migrating, or locking it.
    pub fn open_existing(project_root: impl AsRef<Path>, project_id: ProjectId) -> Result<Self> {
        let project_root = existing_directory(project_root.as_ref())?;
        let state = existing_directory(&project_root.join(STATE_DIRECTORY))?;
        let format = existing_file(&state.join("format-version"))?;
        let contents = fs::read_to_string(format)?;
        if contents.trim_end() != STORAGE_FORMAT_VERSION {
            return Err(StoreError::InvalidFormat(
                "unsupported storage version".to_owned(),
            ));
        }
        let journal_path = existing_directory(&state.join(JOURNAL_DIRECTORY))?;
        let blobs_path = existing_directory(&state.join(BLOB_DIRECTORY))?;
        let index = Index::open_existing(&state.join(INDEX_FILE), project_id)?;
        let journal = JournalReader::open(&journal_path, project_id)?;
        Ok(Self {
            project_root,
            project_id,
            journal,
            index,
            blobs: BlobStore {
                directory: blobs_path,
            },
        })
    }

    pub fn project_root(&self) -> &Path {
        &self.project_root
    }
    pub fn project_id(&self) -> ProjectId {
        self.project_id
    }
    pub fn index(&self) -> &Index {
        &self.index
    }
    pub fn history_page(&self, after_sequence: u64, limit: usize) -> Result<HistoryPage> {
        self.journal.page(after_sequence, limit)
    }
    pub fn last_sequence(&self) -> u64 {
        self.journal.last_sequence
    }
    pub fn blobs(&self) -> &BlobStore {
        &self.blobs
    }
}

pub struct BlobStore {
    directory: PathBuf,
}

impl BlobStore {
    pub fn for_state_directory(state_dir: impl AsRef<Path>) -> Result<Self> {
        let state = existing_directory(state_dir.as_ref())?;
        Ok(Self {
            directory: existing_directory(&state.join(BLOB_DIRECTORY))?,
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn path_for_digest(&self, digest: &str) -> Result<PathBuf> {
        let hex = digest.strip_prefix("sha256:").ok_or_else(|| {
            StoreError::InvalidArgument("digest must use sha256: prefix".to_owned())
        })?;
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(StoreError::InvalidArgument("digest is invalid".to_owned()));
        }
        Ok(self.directory.join("sha256").join(&hex[..2]).join(hex))
    }

    pub fn contains(&self, digest: &str) -> Result<bool> {
        let path = self.path_for_digest(digest)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                Err(StoreError::InvalidFormat("blob is a symlink".to_owned()))
            }
            Ok(metadata) => Ok(metadata.is_file()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn open_digest(&self, digest: &str) -> Result<File> {
        let path = self.path_for_digest(digest)?;
        if !self.contains(digest)? {
            return Err(StoreError::MissingBlob {
                digest: digest.to_owned(),
            });
        }
        Ok(OpenOptions::new().read(true).open(path)?)
    }

    pub fn get(&self, digest: &str) -> Result<File> {
        self.open_digest(digest)
    }

    pub fn open(&self, blob: &BlobRef) -> Result<File> {
        blob.validate()
            .map_err(|error| StoreError::InvalidArgument(error.to_string()))?;
        let file = self.open_digest(&blob.digest)?;
        verify_blob_file(
            &self.path_for_digest(&blob.digest)?,
            &blob.digest,
            blob.size_bytes,
        )?;
        Ok(file)
    }

    pub fn copy_to<W: Write>(&self, blob: &BlobRef, mut writer: W) -> Result<u64> {
        let mut file = self.open(blob)?;
        Ok(io::copy(&mut file, &mut writer)?)
    }
}

fn verify_blob_file(path: &Path, expected_digest: &str, expected_size: u64) -> Result<()> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
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
    let actual = format!("sha256:{:x}", hasher.finalize());
    if actual != expected_digest {
        return Err(StoreError::BlobDigestMismatch {
            expected: expected_digest.to_owned(),
            actual,
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
