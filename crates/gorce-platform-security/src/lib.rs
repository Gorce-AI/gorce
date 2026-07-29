#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Safe, capability-oriented runtime storage.
//!
//! `SecureRuntime` retains the validated runtime directory capability. Unix
//! child operations are descriptor-relative; Windows operations are delegated
//! to the separate audited `gorce-platform-security-win` enclave. No handle,
//! pointer, ACL builder, or unsafe operation is exposed by this facade.

use std::fmt;
#[cfg(unix)]
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const MAX_PRIVATE_READ_BYTES: usize = 1024 * 1024;

#[cfg(windows)]
use gorce_platform_security_win as windows_backend;

#[derive(Debug)]
pub enum SecurityError {
    Io(io::Error),
    Invalid(String),
    Security(String),
    Platform(String),
}

impl fmt::Display for SecurityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "platform security I/O error: {error}"),
            Self::Invalid(message) => {
                write!(formatter, "invalid protected runtime object: {message}")
            }
            Self::Security(message) => {
                write!(formatter, "platform security validation failed: {message}")
            }
            Self::Platform(message) => {
                write!(formatter, "platform security backend failed: {message}")
            }
        }
    }
}

impl std::error::Error for SecurityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Invalid(_) | Self::Security(_) | Self::Platform(_) => None,
        }
    }
}

#[derive(Debug)]
pub enum ReplacementError {
    BeforePublication(SecurityError),
    PublicationAmbiguous(SecurityError),
}

impl fmt::Display for ReplacementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforePublication(error) => {
                write!(formatter, "replacement failed before publication: {error}")
            }
            Self::PublicationAmbiguous(error) => {
                write!(formatter, "replacement publication is ambiguous: {error}")
            }
        }
    }
}

impl std::error::Error for ReplacementError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BeforePublication(error) | Self::PublicationAmbiguous(error) => Some(error),
        }
    }
}

impl ReplacementError {
    #[cfg(unix)]
    fn into_security_error(self) -> SecurityError {
        match self {
            Self::BeforePublication(error) => error,
            Self::PublicationAmbiguous(error) => {
                SecurityError::Security(format!("replacement publication is ambiguous: {error}"))
            }
        }
    }
}

impl From<SecurityError> for ReplacementError {
    fn from(error: SecurityError) -> Self {
        Self::BeforePublication(error)
    }
}

impl From<io::Error> for ReplacementError {
    fn from(error: io::Error) -> Self {
        Self::BeforePublication(SecurityError::Io(error))
    }
}

#[cfg(unix)]
impl From<rustix::io::Errno> for ReplacementError {
    fn from(error: rustix::io::Errno) -> Self {
        Self::BeforePublication(SecurityError::from(error))
    }
}

impl From<io::Error> for SecurityError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(unix)]
impl From<rustix::io::Errno> for SecurityError {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(error.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryDurability {
    Durable,
    BestEffort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurabilityReport {
    pub directory_entry: DirectoryDurability,
}

pub struct SecureRuntime {
    root: PathBuf,
    #[cfg(unix)]
    directory: unix::RuntimeDir,
    #[cfg(windows)]
    directory: windows_backend::RuntimeDir,
}

impl SecureRuntime {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SecurityError> {
        let root = path.as_ref().to_owned();
        #[cfg(unix)]
        let directory = unix::RuntimeDir::open(&root)?;
        #[cfg(windows)]
        let directory = windows_backend::RuntimeDir::open(&root).map_err(map_windows_error)?;
        Ok(Self { root, directory })
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn read_private(&self, name: &str) -> Result<Option<Vec<u8>>, SecurityError> {
        self.read_private_bounded(name, MAX_PRIVATE_READ_BYTES)
    }

    pub fn read_private_bounded(
        &self,
        name: &str,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, SecurityError> {
        let Some(mut file) = self.open_private(name, false)? else {
            return Ok(None);
        };
        Ok(Some(file.read_to_end(max_bytes)?))
    }

    pub fn open_private(
        &self,
        name: &str,
        write: bool,
    ) -> Result<Option<PrivateFile>, SecurityError> {
        validate_child_name(name)?;
        #[cfg(unix)]
        let file = self.directory.open_private(name, write)?;
        #[cfg(windows)]
        let file = self
            .directory
            .open_private(name, write)
            .map_err(map_windows_error)?;
        Ok(file.map(|inner| PrivateFile { inner }))
    }

    pub fn replace_private(
        &self,
        name: &str,
        contents: &[u8],
    ) -> Result<DurabilityReport, SecurityError> {
        #[cfg(unix)]
        {
            let temporary_name = format!(
                ".{name}.{}.{}.tmp",
                std::process::id(),
                TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            self.replace_private_validated(name, &temporary_name, contents, |_| Ok(()))
                .map_err(ReplacementError::into_security_error)
        }
        #[cfg(windows)]
        {
            self.directory
                .replace_private(name, contents)
                .map(|report| DurabilityReport {
                    directory_entry: match report.directory_entry {
                        windows_backend::DirectoryDurability::BestEffort => {
                            DirectoryDurability::BestEffort
                        }
                    },
                })
                .map_err(map_windows_error)
        }
    }

    pub fn replace_private_validated<F>(
        &self,
        name: &str,
        temporary_name: &str,
        contents: &[u8],
        validate: F,
    ) -> Result<DurabilityReport, ReplacementError>
    where
        F: FnOnce(&[u8]) -> Result<(), String>,
    {
        validate_child_name(name)?;
        validate_child_name(temporary_name)?;
        if name == temporary_name {
            return Err(ReplacementError::BeforePublication(SecurityError::Invalid(
                "replacement temporary name must differ from the target".to_owned(),
            )));
        }
        #[cfg(unix)]
        {
            self.directory
                .replace_private_validated(name, temporary_name, contents, validate)
        }
        #[cfg(windows)]
        {
            self.directory
                .replace_private_validated(name, temporary_name, contents, validate)
                .map(|report| DurabilityReport {
                    directory_entry: match report.directory_entry {
                        windows_backend::DirectoryDurability::BestEffort => {
                            DirectoryDurability::BestEffort
                        }
                    },
                })
                .map_err(map_windows_replacement_error)
        }
    }

    pub fn lock(&self, name: &str) -> Result<LockGuard, SecurityError> {
        validate_child_name(name)?;
        #[cfg(unix)]
        let inner = self.directory.lock(name)?;
        #[cfg(windows)]
        let inner = self
            .directory
            .lock(name)
            .map_err(map_windows_security_error)?;
        Ok(LockGuard { inner })
    }

    pub fn remove_private(&self, name: &str) -> Result<DurabilityReport, SecurityError> {
        validate_child_name(name)?;
        #[cfg(unix)]
        {
            self.directory.remove_private(name)
        }
        #[cfg(windows)]
        {
            self.directory
                .remove_private(name)
                .map(|report| DurabilityReport {
                    directory_entry: match report.directory_entry {
                        windows_backend::DirectoryDurability::BestEffort => {
                            DirectoryDurability::BestEffort
                        }
                    },
                })
                .map_err(map_windows_error)
        }
    }
}

pub struct PrivateFile {
    #[cfg(unix)]
    inner: unix::PrivateFile,
    #[cfg(windows)]
    inner: windows_backend::PrivateFile,
}

impl PrivateFile {
    pub fn read_to_end(&mut self, max_bytes: usize) -> Result<Vec<u8>, SecurityError> {
        #[cfg(unix)]
        {
            self.inner
                .read_to_end(max_bytes)
                .map_err(SecurityError::from)
        }
        #[cfg(windows)]
        {
            self.inner.read_to_end(max_bytes).map_err(map_windows_error)
        }
    }
}

pub struct LockGuard {
    #[cfg(unix)]
    inner: unix::LockGuard,
    #[cfg(windows)]
    inner: windows_backend::LockGuard,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        self.inner.unlock();
        #[cfg(windows)]
        let _ = &self.inner;
    }
}

impl LockGuard {
    /// Return the sentinel length through the already-held lock handle.
    ///
    /// Windows may reject opening the same locked file through a second
    /// handle, so callers that already own the lock must use this method
    /// rather than reopening the protected child.
    pub fn file_len(&self) -> Result<u64, SecurityError> {
        #[cfg(unix)]
        {
            self.inner.file_len().map_err(SecurityError::from)
        }
        #[cfg(windows)]
        {
            self.inner.file_len().map_err(map_windows_error)
        }
    }
}

fn validate_child_name(name: &str) -> Result<(), SecurityError> {
    let mut components = Path::new(name).components();
    if name.is_empty()
        || name.contains('\0')
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(SecurityError::Invalid(
            "protected runtime names must be single path components".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn map_windows_error(error: windows_backend::SecurityError) -> SecurityError {
    SecurityError::Platform(error.to_string())
}

#[cfg(windows)]
fn map_windows_security_error(error: windows_backend::SecurityError) -> SecurityError {
    match error {
        windows_backend::SecurityError::Io(error) => SecurityError::Io(error),
        windows_backend::SecurityError::Invalid(message) => SecurityError::Invalid(message),
        windows_backend::SecurityError::Security(message) => SecurityError::Security(message),
    }
}

#[cfg(windows)]
fn map_windows_replacement_error(error: windows_backend::ReplacementError) -> ReplacementError {
    match error {
        windows_backend::ReplacementError::BeforePublication(error) => {
            ReplacementError::BeforePublication(map_windows_security_error(error))
        }
    }
}

#[cfg(unix)]
mod unix {
    use super::{
        Component, DirectoryDurability, DurabilityReport, File, Path, ReplacementError,
        SecurityError,
    };
    use fs2::FileExt;
    use rustix::fd::AsFd;
    use rustix::fs::{self as rfs, AtFlags, Mode, OFlags, CWD};
    use rustix::process::geteuid;
    use std::collections::VecDeque;
    use std::ffi::{OsStr, OsString};
    use std::fs as std_fs;
    use std::io::{self, Read, Seek, SeekFrom, Write};
    #[cfg(target_os = "macos")]
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    const S_IFMT: u32 = 0o170000;
    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;

    pub(super) struct RuntimeDir {
        directory: File,
    }

    fn open_directory_root(absolute: bool) -> Result<File, SecurityError> {
        Ok(if absolute {
            rfs::openat(
                CWD,
                Path::new("/"),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?
            .into()
        } else {
            rfs::openat(
                CWD,
                Path::new("."),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?
            .into()
        })
    }

    fn runtime_components(path: &Path) -> Result<VecDeque<OsString>, SecurityError> {
        let mut components = VecDeque::new();
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => components.push_back(name.to_owned()),
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(SecurityError::Invalid(
                        "runtime paths cannot contain parent or prefix components".to_owned(),
                    ));
                }
            }
        }
        if components.is_empty() {
            return Err(SecurityError::Invalid(
                "runtime path must name a directory".to_owned(),
            ));
        }
        Ok(components)
    }

    #[cfg(target_os = "macos")]
    fn macos_system_alias_target(
        directory: &File,
        name: &OsStr,
    ) -> Result<Option<Vec<OsString>>, SecurityError> {
        // macOS exposes the ordinary temporary roots through these two
        // root-level aliases. They are outside the caller-controlled runtime
        // tree; resolve only these fixed system aliases by reading the link
        // relative to the already-opened root descriptor. Every component of
        // the resolved target and every component below it is still opened
        // with NOFOLLOW and validated through its descriptor.
        let expected_target = if name == OsStr::new("var") {
            b"private/var".as_slice()
        } else if name == OsStr::new("tmp") {
            b"private/tmp".as_slice()
        } else {
            return Ok(None);
        };
        let target = match rfs::readlinkat(directory.as_fd(), Path::new(name), Vec::new()) {
            Ok(target) => target,
            Err(_) => return Ok(None),
        };
        if target.as_bytes() != expected_target {
            return Ok(None);
        }
        let target = Path::new(OsStr::from_bytes(target.as_bytes()));
        Ok(Some(runtime_components(target)?.into_iter().collect()))
    }

    #[cfg(not(target_os = "macos"))]
    fn macos_system_alias_target(
        _directory: &File,
        _name: &OsStr,
    ) -> Result<Option<Vec<OsString>>, SecurityError> {
        Ok(None)
    }

    fn open_or_create_directory_path(path: &Path) -> Result<File, SecurityError> {
        let absolute = path.is_absolute();
        let mut current = open_directory_root(absolute)?;
        let mut components = runtime_components(path)?;
        let mut first_component = true;
        while let Some(name) = components.pop_front() {
            let child = Path::new(&name);
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
            let next = match rfs::openat(current.as_fd(), child, flags, Mode::empty()) {
                Ok(fd) => fd,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    match rfs::mkdirat(current.as_fd(), child, Mode::from_raw_mode(0o700)) {
                        Ok(()) => rfs::openat(current.as_fd(), child, flags, Mode::empty())?,
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                            rfs::openat(current.as_fd(), child, flags, Mode::empty())?
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error)
                    if absolute
                        && first_component
                        && (error == rustix::io::Errno::NOTDIR
                            || error == rustix::io::Errno::LOOP) =>
                {
                    let Some(alias_components) = macos_system_alias_target(&current, &name)? else {
                        return Err(error.into());
                    };
                    for alias_component in alias_components.into_iter().rev() {
                        components.push_front(alias_component);
                    }
                    first_component = false;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let next: File = next.into();
            validate_directory_component(&next)?;
            current = next;
            first_component = false;
        }
        Ok(current)
    }

    impl RuntimeDir {
        pub(super) fn open(path: &Path) -> Result<Self, SecurityError> {
            let directory = open_or_create_directory_path(path)?;
            directory.set_permissions(std_fs::Permissions::from_mode(0o700))?;
            validate_directory(&directory)?;
            Ok(Self { directory })
        }

        pub(super) fn open_private(
            &self,
            name: &str,
            write: bool,
        ) -> Result<Option<PrivateFile>, SecurityError> {
            let flags = if write { OFlags::RDWR } else { OFlags::RDONLY };
            let fd = match rfs::openat(
                self.directory.as_fd(),
                Path::new(name),
                flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            let file: File = fd.into();
            validate_file(&file)?;
            Ok(Some(PrivateFile { file }))
        }

        pub(super) fn replace_private_validated<F>(
            &self,
            name: &str,
            temporary_name: &str,
            contents: &[u8],
            validate: F,
        ) -> Result<DurabilityReport, ReplacementError>
        where
            F: FnOnce(&[u8]) -> Result<(), String>,
        {
            self.remove_private(temporary_name)?;
            let result: Result<DurabilityReport, ReplacementError> = (|| {
                let fd = rfs::openat(
                    self.directory.as_fd(),
                    Path::new(temporary_name),
                    OFlags::RDWR
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )?;
                let mut file: File = fd.into();
                file.set_permissions(std_fs::Permissions::from_mode(0o600))?;
                validate_file(&file)?;
                file.write_all(contents)?;
                file.sync_all()?;
                file.seek(SeekFrom::Start(0))?;
                let mut candidate = Vec::with_capacity(contents.len());
                std::io::Read::by_ref(&mut file)
                    .take(contents.len() as u64 + 1)
                    .read_to_end(&mut candidate)?;
                if candidate.len() != contents.len() {
                    return Err(ReplacementError::BeforePublication(SecurityError::Invalid(
                        "replacement candidate changed while being read".to_owned(),
                    )));
                }
                validate(&candidate).map_err(|error| {
                    ReplacementError::BeforePublication(SecurityError::Invalid(error))
                })?;
                drop(file);
                rfs::renameat(
                    self.directory.as_fd(),
                    Path::new(temporary_name),
                    self.directory.as_fd(),
                    Path::new(name),
                )
                .map_err(|error| ReplacementError::BeforePublication(error.into()))?;
                rfs::fsync(self.directory.as_fd())
                    .map_err(|error| ReplacementError::PublicationAmbiguous(error.into()))?;
                Ok(DurabilityReport {
                    directory_entry: DirectoryDurability::Durable,
                })
            })();
            if result.is_err() {
                let _ = self.remove_private(temporary_name);
            }
            result
        }

        pub(super) fn lock(&self, name: &str) -> Result<LockGuard, SecurityError> {
            let fd = match rfs::openat(
                self.directory.as_fd(),
                Path::new(name),
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(error) if error.kind() == io::ErrorKind::NotFound => rfs::openat(
                    self.directory.as_fd(),
                    Path::new(name),
                    OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )?,
                Err(error) => return Err(error.into()),
            };
            let file: File = fd.into();
            validate_file(&file)?;
            match file.try_lock_exclusive() {
                Ok(()) => Ok(LockGuard { file }),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(
                    SecurityError::Security("runtime instance lock is already held".to_owned()),
                ),
                Err(error) => Err(error.into()),
            }
        }

        pub(super) fn remove_private(&self, name: &str) -> Result<DurabilityReport, SecurityError> {
            let Some(file) = self.open_private(name, false)? else {
                return Ok(DurabilityReport {
                    directory_entry: DirectoryDurability::Durable,
                });
            };
            drop(file);
            rfs::unlinkat(self.directory.as_fd(), Path::new(name), AtFlags::empty())?;
            rfs::fsync(self.directory.as_fd())?;
            Ok(DurabilityReport {
                directory_entry: DirectoryDurability::Durable,
            })
        }
    }

    pub(super) struct PrivateFile {
        file: File,
    }

    impl PrivateFile {
        pub(super) fn read_to_end(&mut self, max_bytes: usize) -> io::Result<Vec<u8>> {
            const MAX_PRIVATE_READ_BYTES: usize = 1024 * 1024;
            if max_bytes > MAX_PRIVATE_READ_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "protected read bound is too large",
                ));
            }
            let length = self.file.metadata()?.len();
            if length > max_bytes as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protected file is larger than its read bound",
                ));
            }
            let capacity = usize::try_from(length).unwrap_or(max_bytes);
            let mut bytes = Vec::with_capacity(capacity.min(max_bytes));
            Read::by_ref(&mut self.file)
                .take(max_bytes as u64 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > max_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protected file grew beyond its read bound",
                ));
            }
            Ok(bytes)
        }
    }

    pub(super) struct LockGuard {
        file: File,
    }

    impl LockGuard {
        pub(super) fn unlock(&mut self) {
            let _ = fs2::FileExt::unlock(&self.file);
        }

        pub(super) fn file_len(&self) -> io::Result<u64> {
            self.file.metadata().map(|metadata| metadata.len())
        }
    }

    fn validate_directory(file: &File) -> Result<(), SecurityError> {
        let stat = rfs::fstat(file.as_fd())?;
        let mode = stat.st_mode as u32;
        if stat.st_uid != geteuid().as_raw()
            || mode & S_IFMT != S_IFDIR
            || mode & 0o077 != 0
            || stat.st_nlink < 2
        {
            return Err(SecurityError::Security(
                "runtime directory failed descriptor owner/mode/type validation".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_directory_component(file: &File) -> Result<(), SecurityError> {
        let stat = rfs::fstat(file.as_fd())?;
        let mode = stat.st_mode as u32;
        if mode & S_IFMT != S_IFDIR || stat.st_nlink < 2 {
            return Err(SecurityError::Security(
                "runtime path component failed descriptor type/link validation".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_file(file: &File) -> Result<(), SecurityError> {
        let stat = rfs::fstat(file.as_fd())?;
        let mode = stat.st_mode as u32;
        if stat.st_uid != geteuid().as_raw()
            || mode & S_IFMT != S_IFREG
            || mode & 0o077 != 0
            || stat.st_nlink != 1
        {
            return Err(SecurityError::Security(
                "runtime file failed descriptor owner/mode/type/link validation".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{ReplacementError, SecureRuntime, SecurityError};
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory(label: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(format!(
            ".gorce-platform-{label}-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn descriptor_relative_replacement_survives_runtime_path_swap() {
        let root = temporary_directory("anchored");
        let moved = temporary_directory("moved");
        let outside = temporary_directory("outside");
        fs::create_dir_all(&outside).unwrap();
        let runtime = SecureRuntime::open(&root).unwrap();

        fs::rename(&root, &moved).unwrap();
        symlink(&outside, &root).unwrap();

        runtime.replace_private("identity", b"anchored").unwrap();
        assert_eq!(fs::read(moved.join("identity")).unwrap(), b"anchored");
        assert!(!outside.join("identity").exists());

        drop(runtime);
        fs::remove_file(&root).unwrap();
        fs::remove_dir_all(moved).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn descriptor_relative_open_rejects_child_symlink() {
        let root = temporary_directory("symlink");
        let target = temporary_directory("target");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("secret"), b"outside").unwrap();
        let runtime = SecureRuntime::open(&root).unwrap();
        symlink(target.join("secret"), root.join("secret")).unwrap();

        assert!(runtime.open_private("secret", false).is_err());

        drop(runtime);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(target).unwrap();
    }

    #[test]
    fn nested_root_traversal_and_bounded_reads_are_descriptor_relative() {
        let parent = temporary_directory("nested");
        let root = parent.join("one").join("two");
        let runtime = SecureRuntime::open(&root).unwrap();

        runtime.replace_private("bounded", b"too-large").unwrap();
        assert!(runtime.read_private_bounded("bounded", 4).is_err());

        drop(runtime);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn held_lock_exposes_sentinel_length_without_reopening_it() {
        let root = temporary_directory("held-lock");
        let runtime = SecureRuntime::open(&root).unwrap();
        let lock = runtime.lock("LOCK").unwrap();

        assert_eq!(lock.file_len().unwrap(), 0);
        assert_eq!(runtime.read_private("LOCK").unwrap(), Some(Vec::new()));

        drop(lock);
        assert_eq!(runtime.read_private("LOCK").unwrap(), Some(Vec::new()));
        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replacement_candidate_is_read_and_validated_before_rename() {
        let root = temporary_directory("validated-replacement");
        let runtime = SecureRuntime::open(&root).unwrap();
        runtime.replace_private("registry", b"old").unwrap();

        let validation =
            runtime.replace_private_validated("registry", ".registry.tmp", b"new", |candidate| {
                assert_eq!(candidate, b"new");
                Err("reject before rename".to_owned())
            });
        assert!(matches!(
            validation,
            Err(ReplacementError::BeforePublication(SecurityError::Invalid(
                _
            )))
        ));
        assert_eq!(
            runtime.read_private("registry").unwrap(),
            Some(b"old".to_vec())
        );
        assert!(!root.join(".registry.tmp").exists());

        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replacement_call_failure_after_validation_preserves_the_old_file() {
        let root = temporary_directory("prepublication-io");
        let runtime = SecureRuntime::open(&root).unwrap();
        runtime.replace_private("registry", b"old").unwrap();
        let mut validated = false;

        let failure =
            runtime.replace_private_validated("registry", ".registry.io", b"new", |candidate| {
                assert_eq!(candidate, b"new");
                validated = true;
                fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).unwrap();
                Ok(())
            });
        assert!(matches!(
            failure,
            Err(ReplacementError::BeforePublication(_))
        ));
        assert!(validated);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            runtime.read_private("registry").unwrap(),
            Some(b"old".to_vec())
        );

        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nested_absolute_temp_root_is_acquired_with_missing_components() {
        let root = std::env::temp_dir()
            .join(format!(
                "gorce-platform-absolute-{}-{}",
                std::process::id(),
                TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
            ))
            .join("one")
            .join("two");
        let runtime = SecureRuntime::open(&root).unwrap();

        runtime.replace_private("acquired", b"ok").unwrap();
        assert_eq!(
            runtime.read_private("acquired").unwrap().as_deref(),
            Some(&b"ok"[..])
        );

        drop(runtime);
        fs::remove_dir_all(root.parent().unwrap().parent().unwrap()).unwrap();
    }

    #[test]
    fn intermediate_root_symlink_is_rejected_without_outside_creation() {
        let trusted = temporary_directory("symlink-component");
        let outside = temporary_directory("symlink-outside");
        fs::create_dir_all(&trusted).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let requested = trusted.join("intermediate").join("runtime");
        symlink(&outside, trusted.join("intermediate")).unwrap();

        assert!(SecureRuntime::open(&requested).is_err());
        assert!(!outside.join("runtime").exists());

        fs::remove_file(trusted.join("intermediate")).unwrap();
        fs::remove_dir_all(trusted).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }
}
