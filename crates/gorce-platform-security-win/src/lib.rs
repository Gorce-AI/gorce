#![cfg(windows)]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Windows-only capability implementation for `gorce-platform-security`.
//!
//! The only unsafe code in this crate is contained in `ffi`. That module owns
//! all Win32 pointers and handles: every successful `CreateFileW` handle is
//! transferred exactly once into `std::fs::File`, temporary rename buffers are
//! borrowed only for the duration of `NtSetInformationFile`, and security
//! descriptor allocations are released with `LocalFree` before returning.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use fs2::FileExt;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum SecurityError {
    Io(io::Error),
    Invalid(String),
    Security(String),
}

impl fmt::Display for SecurityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "Windows security I/O error: {error}"),
            Self::Invalid(message) => {
                write!(formatter, "invalid protected runtime object: {message}")
            }
            Self::Security(message) => {
                write!(formatter, "Windows security validation failed: {message}")
            }
        }
    }
}

impl std::error::Error for SecurityError {}

impl From<io::Error> for SecurityError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug)]
pub enum ReplacementError {
    BeforePublication(SecurityError),
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

impl ReplacementError {
    fn into_security_error(self) -> SecurityError {
        match self {
            Self::BeforePublication(error) => error,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryDurability {
    BestEffort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurabilityReport {
    pub directory_entry: DirectoryDurability,
}

pub struct RuntimeDir {
    directory: File,
    identity: ffi::CurrentIdentity,
}

impl RuntimeDir {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SecurityError> {
        let root = path.as_ref().to_owned();
        let identity = ffi::current_identity()?;
        let created = ffi::create_directory(&root, &identity)?;
        let directory = match ffi::open_directory(&root, created) {
            Ok(directory) => directory,
            Err(error) => {
                if created {
                    let _ = ffi::remove_directory(&root);
                }
                return Err(error);
            }
        };
        if let Err(error) = ffi::validate_directory(&directory, &identity) {
            if created {
                let _ = ffi::dispose(&directory);
            }
            return Err(error);
        }
        Ok(Self {
            directory,
            identity,
        })
    }

    pub fn read_private(&self, name: &str) -> Result<Option<Vec<u8>>, SecurityError> {
        let Some(mut file) = self.open_private(name, false)? else {
            return Ok(None);
        };
        file.read_to_end(1024 * 1024).map(Some)
    }

    pub fn read_private_bounded(
        &self,
        name: &str,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, SecurityError> {
        let Some(mut file) = self.open_private(name, false)? else {
            return Ok(None);
        };
        file.read_to_end(max_bytes).map(Some)
    }

    pub fn open_private(
        &self,
        name: &str,
        write: bool,
    ) -> Result<Option<PrivateFile>, SecurityError> {
        validate_child_name(name)?;
        let file = match ffi::open_child(&self.directory, name, write, false, false, &self.identity)
        {
            Ok(file) => file,
            Err(SecurityError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        ffi::validate(&file, &self.identity)?;
        Ok(Some(PrivateFile { file }))
    }

    pub fn replace_private(
        &self,
        name: &str,
        contents: &[u8],
    ) -> Result<DurabilityReport, SecurityError> {
        validate_child_name(name)?;
        let temporary_name = format!(
            ".{name}.{}.{}.tmp",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        self.replace_private_validated(name, &temporary_name, contents, |_| Ok(()))
            .map_err(ReplacementError::into_security_error)
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
        self.remove_private(temporary_name)?;
        let result: Result<DurabilityReport, ReplacementError> = (|| {
            let mut file = ffi::open_child(
                &self.directory,
                temporary_name,
                true,
                true,
                true,
                &self.identity,
            )?;
            ffi::validate(&file, &self.identity)?;
            file.write_all(contents)?;
            file.sync_all()?;
            file.seek(SeekFrom::Start(0))?;
            let mut candidate = Vec::with_capacity(contents.len());
            Read::by_ref(&mut file)
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
            ffi::replace(&self.directory, &file, name)
                .map_err(ReplacementError::BeforePublication)?;
            drop(file);
            Ok(DurabilityReport {
                directory_entry: DirectoryDurability::BestEffort,
            })
        })();
        if result.is_err() {
            let _ = self.remove_private(temporary_name);
        }
        result
    }

    pub fn lock(&self, name: &str) -> Result<LockGuard, SecurityError> {
        validate_child_name(name)?;
        let file = match ffi::open_child(&self.directory, name, true, false, false, &self.identity)
        {
            Ok(file) => file,
            Err(SecurityError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                ffi::open_child(&self.directory, name, true, true, false, &self.identity)?
            }
            Err(error) => return Err(error),
        };
        ffi::validate(&file, &self.identity)?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(LockGuard { file }),
            Err(error) if lock_contended(&error) => Err(SecurityError::Security(
                "runtime instance lock is already held".to_owned(),
            )),
            Err(error) => Err(error.into()),
        }
    }

    pub fn remove_private(&self, name: &str) -> Result<DurabilityReport, SecurityError> {
        validate_child_name(name)?;
        if self.open_private(name, false)?.is_none() {
            return Ok(DurabilityReport {
                directory_entry: DirectoryDurability::BestEffort,
            });
        }
        let file = ffi::open_child(&self.directory, name, true, false, true, &self.identity)?;
        ffi::validate(&file, &self.identity)?;
        ffi::dispose(&file)?;
        drop(file);
        Ok(DurabilityReport {
            directory_entry: DirectoryDurability::BestEffort,
        })
    }
}

fn assert_runtime_dir_send_sync() {
    fn assert<T: Send + Sync>() {}
    assert::<RuntimeDir>();
}

const _: fn() = assert_runtime_dir_send_sync;

pub struct PrivateFile {
    file: File,
}

impl PrivateFile {
    pub fn read_to_end(&mut self, max_bytes: usize) -> Result<Vec<u8>, SecurityError> {
        const MAX_PRIVATE_READ_BYTES: usize = 1024 * 1024;
        if max_bytes > MAX_PRIVATE_READ_BYTES {
            return Err(SecurityError::Invalid(
                "protected read bound is too large".to_owned(),
            ));
        }
        let length = self.file.metadata()?.len();
        if length > max_bytes as u64 {
            return Err(SecurityError::Invalid(
                "protected file is larger than its read bound".to_owned(),
            ));
        }
        let capacity = usize::try_from(length).unwrap_or(max_bytes);
        let mut bytes = Vec::with_capacity(capacity.min(max_bytes));
        Read::by_ref(&mut self.file)
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes {
            return Err(SecurityError::Invalid(
                "protected file grew beyond its read bound".to_owned(),
            ));
        }
        Ok(bytes)
    }
}

pub struct LockGuard {
    file: File,
}

impl LockGuard {
    pub fn file_len(&self) -> Result<u64, SecurityError> {
        Ok(self.file.metadata()?.len())
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

fn lock_contended(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
        || error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
        || error.raw_os_error() == Some(33)
}

fn validate_child_name(name: &str) -> Result<(), SecurityError> {
    let mut components = Path::new(name).components();
    if name.is_empty()
        || name.contains('\0')
        || !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(SecurityError::Invalid(
            "protected runtime names must be single path components".to_owned(),
        ));
    }
    Ok(())
}

// This is the sole unsafe module in the crate. It exposes only safe wrappers.
#[allow(unsafe_code)]
mod ffi {
    use super::{File, Path, SecurityError};
    use std::ffi::c_void;
    use std::io;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr::null_mut;
    #[cfg(test)]
    use std::sync::atomic::{AtomicBool, Ordering};

    use std::mem::align_of;
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        NtCreateFile, NtSetInformationFile, FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_RENAME_INFORMATION_0,
        FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_THROUGH,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, RtlNtStatusToDosError, ERROR_ALREADY_EXISTS, ERROR_NO_TOKEN,
        GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, PSID, TRUE, UNICODE_STRING,
    };
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        AclSizeInformation, AddAccessAllowedAce, CopySid, EqualSid, GetAce, GetAclInformation,
        GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl,
        InitializeSecurityDescriptor, IsValidSid, SetSecurityDescriptorControl,
        SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TokenUser, ACCESS_ALLOWED_ACE,
        ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE,
        DACL_SECURITY_INFORMATION, INHERITED_ACE, INHERIT_ONLY_ACE, NO_PROPAGATE_INHERIT_ACE,
        OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        SECURITY_DESCRIPTOR, SE_DACL_PROTECTED, SID, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, FileAttributeTagInfo, FileBasicInfo, FileDispositionInfo,
        GetFileInformationByHandleEx, RemoveDirectoryW, SetFileInformationByHandle, DELETE,
        FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_DISPOSITION_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_UNKNOWN, OPEN_EXISTING,
        READ_CONTROL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
    };
    use windows_sys::Win32::System::Kernel::OBJ_CASE_INSENSITIVE;
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
    use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
    };
    use windows_sys::Win32::System::WindowsProgramming::FILE_INFORMATION_CLASS;
    use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, IO_STATUS_BLOCK_0};

    const FILE_RENAME_INFORMATION_CLASS: FILE_INFORMATION_CLASS = 10;

    #[cfg(test)]
    static FAIL_NEXT_REPLACE_CALL: AtomicBool = AtomicBool::new(false);

    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: this wrapper is constructed only for an owned token
                // handle; the pseudo-handle returned by GetCurrentProcess is
                // never wrapped or closed.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    pub(super) struct CurrentIdentity {
        sid: Box<[u32]>,
        sid_len: u32,
    }

    impl CurrentIdentity {
        fn sid_ptr(&self) -> PSID {
            self.sid.as_ptr().cast_mut().cast()
        }
    }

    struct ProtectedSecurity {
        _owner: Box<[u32]>,
        descriptor: Box<[usize]>,
        _acl: Box<[u32]>,
    }

    impl ProtectedSecurity {
        fn descriptor(&mut self) -> PSECURITY_DESCRIPTOR {
            self.descriptor.as_mut_ptr().cast()
        }

        fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.descriptor().cast(),
                bInheritHandle: 0,
            }
        }
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn handle(file: &File) -> HANDLE {
        file.as_raw_handle() as HANDLE
    }

    pub(super) fn current_identity() -> Result<CurrentIdentity, SecurityError> {
        let token = unsafe {
            let mut token = 0;
            if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &mut token) != 0 {
                token
            } else {
                if GetLastError() != ERROR_NO_TOKEN
                    || OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0
                {
                    return Err(SecurityError::Io(io::Error::last_os_error()));
                }
                token
            }
        };
        let token = OwnedHandle(token);
        let mut needed = 0;
        unsafe {
            let _ = GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed);
        }
        if needed == 0 {
            return Err(SecurityError::Security(
                "could not size effective TokenUser information".to_owned(),
            ));
        }
        let word_count = (needed as usize).div_ceil(size_of::<usize>());
        let mut user = vec![0_usize; word_count];
        let user_capacity = user.len().checked_mul(size_of::<usize>()).ok_or_else(|| {
            SecurityError::Security("effective TokenUser buffer size overflowed".to_owned())
        })?;
        if user_capacity > u32::MAX as usize {
            return Err(SecurityError::Security(
                "effective TokenUser buffer is too large".to_owned(),
            ));
        }
        let mut returned = 0;
        unsafe {
            if GetTokenInformation(
                token.0,
                TokenUser,
                user.as_mut_ptr().cast(),
                user_capacity as u32,
                &mut returned,
            ) == 0
            {
                return Err(SecurityError::Security(
                    "could not read effective TokenUser information".to_owned(),
                ));
            }
        }
        let used = usize::try_from(returned).map_err(|_| {
            SecurityError::Security("effective TokenUser size was invalid".to_owned())
        })?;
        let (sid, sid_len) = copy_token_user_sid(&user, used, user_capacity)?;
        drop(user);
        drop(token);
        Ok(CurrentIdentity { sid, sid_len })
    }

    fn copy_token_user_sid(
        user: &[usize],
        used: usize,
        capacity: usize,
    ) -> Result<(Box<[u32]>, u32), SecurityError> {
        if used < size_of::<TOKEN_USER>() || used > capacity || user.is_empty() {
            return Err(SecurityError::Security(
                "effective TokenUser buffer bounds are invalid".to_owned(),
            ));
        }
        let start = user.as_ptr() as usize;
        let end = start.checked_add(used).ok_or_else(|| {
            SecurityError::Security("effective TokenUser address overflowed".to_owned())
        })?;
        let source = unsafe { (&*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        if source.is_null() {
            return Err(SecurityError::Security(
                "effective TokenUser SID is missing".to_owned(),
            ));
        }
        let source_start = source as usize;
        let minimum_sid_len = size_of::<SID>() - size_of::<u32>();
        if source_start < start
            || !source_start.is_multiple_of(align_of::<u32>())
            || match source_start.checked_add(minimum_sid_len) {
                Some(value) => value > end,
                None => true,
            }
        {
            return Err(SecurityError::Security(
                "effective TokenUser SID is outside its buffer".to_owned(),
            ));
        }
        let sub_authority_count = unsafe { *((source_start + 1) as *const u8) } as usize;
        let expected_len = minimum_sid_len
            .checked_add(
                sub_authority_count
                    .checked_mul(size_of::<u32>())
                    .ok_or_else(|| {
                        SecurityError::Security(
                            "effective TokenUser SID length overflowed".to_owned(),
                        )
                    })?,
            )
            .ok_or_else(|| {
                SecurityError::Security("effective TokenUser SID length overflowed".to_owned())
            })?;
        let source_end = source_start.checked_add(expected_len).ok_or_else(|| {
            SecurityError::Security("effective TokenUser SID bounds overflowed".to_owned())
        })?;
        if source_end > end || expected_len > u32::MAX as usize {
            return Err(SecurityError::Security(
                "effective TokenUser SID exceeds its buffer".to_owned(),
            ));
        }
        unsafe {
            if IsValidSid(source) == 0 || GetLengthSid(source) as usize != expected_len {
                return Err(SecurityError::Security(
                    "effective TokenUser SID failed validation".to_owned(),
                ));
            }
        }
        let sid_len = expected_len as u32;
        let mut owned = vec![0_u32; expected_len.div_ceil(size_of::<u32>())].into_boxed_slice();
        let destination = owned.as_mut_ptr().cast();
        unsafe {
            if CopySid(sid_len, destination, source) == 0
                || IsValidSid(destination) == 0
                || GetLengthSid(destination) != sid_len
            {
                return Err(SecurityError::Security(
                    "copied effective TokenUser SID failed validation".to_owned(),
                ));
            }
        }
        Ok((owned, sid_len))
    }

    fn protected_security(identity: &CurrentIdentity) -> Result<ProtectedSecurity, SecurityError> {
        unsafe {
            let sid_length = identity.sid_len;
            if sid_length == 0 {
                return Err(SecurityError::Security(
                    "effective TokenUser SID is invalid".to_owned(),
                ));
            }
            let mut owner =
                vec![0_u32; (sid_length as usize).div_ceil(size_of::<u32>())].into_boxed_slice();
            let owner_sid = owner.as_mut_ptr().cast();
            if CopySid(sid_length, owner_sid, identity.sid_ptr()) == 0
                || IsValidSid(owner_sid) == 0
                || GetLengthSid(owner_sid) != sid_length
            {
                return Err(SecurityError::Security(
                    "could not clone effective TokenUser SID".to_owned(),
                ));
            }
            let acl_length = size_of::<ACL>()
                .saturating_add(size_of::<ACCESS_ALLOWED_ACE>())
                .saturating_sub(size_of::<u32>())
                .saturating_add(sid_length as usize);
            let mut acl = vec![0_u32; acl_length.div_ceil(size_of::<u32>())];
            let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
            let mut descriptor =
                vec![0_usize; size_of::<SECURITY_DESCRIPTOR>().div_ceil(size_of::<usize>())];
            let descriptor_ptr = descriptor.as_mut_ptr().cast::<SECURITY_DESCRIPTOR>();
            if InitializeAcl(acl_ptr, acl_length as u32, ACL_REVISION) == 0
                || AddAccessAllowedAce(acl_ptr, ACL_REVISION, FILE_ALL_ACCESS, owner_sid) == 0
                || InitializeSecurityDescriptor(descriptor_ptr.cast(), SECURITY_DESCRIPTOR_REVISION)
                    == 0
                || SetSecurityDescriptorOwner(descriptor_ptr.cast(), owner_sid, 0) == 0
                || SetSecurityDescriptorDacl(descriptor_ptr.cast(), TRUE, acl_ptr, 0) == 0
                || SetSecurityDescriptorControl(
                    descriptor_ptr.cast(),
                    SE_DACL_PROTECTED,
                    SE_DACL_PROTECTED,
                ) == 0
            {
                return Err(SecurityError::Security(
                    "could not build protected current-user security descriptor".to_owned(),
                ));
            }
            Ok(ProtectedSecurity {
                _owner: owner,
                descriptor: descriptor.into_boxed_slice(),
                _acl: acl.into_boxed_slice(),
            })
        }
    }

    pub(super) fn create_directory(
        path: &Path,
        identity: &CurrentIdentity,
    ) -> Result<bool, SecurityError> {
        let path = wide(path);
        let mut security = protected_security(identity)?;
        let attributes = security.attributes();
        let created = unsafe { CreateDirectoryW(path.as_ptr(), &attributes) };
        if created != 0 {
            return Ok(true);
        }
        let error = unsafe { GetLastError() };
        if error == ERROR_ALREADY_EXISTS {
            Ok(false)
        } else {
            Err(SecurityError::Io(io::Error::from_raw_os_error(
                error as i32,
            )))
        }
    }

    pub(super) fn remove_directory(path: &Path) -> Result<(), SecurityError> {
        let path = wide(path);
        if unsafe { RemoveDirectoryW(path.as_ptr()) } == 0 {
            return Err(SecurityError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    pub(super) fn open_directory(path: &Path, write_owner: bool) -> Result<File, SecurityError> {
        open(path, false, true, write_owner)
    }

    pub(super) fn open_child(
        directory: &File,
        name: &str,
        write: bool,
        create_new: bool,
        delete: bool,
        identity: &CurrentIdentity,
    ) -> Result<File, SecurityError> {
        let mut name = name.encode_utf16().collect::<Vec<_>>();
        if name.is_empty() || name.len() >= (u16::MAX as usize / 2) {
            return Err(SecurityError::Invalid(
                "protected runtime child name is too long".to_owned(),
            ));
        }
        let name_bytes = name.len() * size_of::<u16>();
        name.push(0);
        let unicode = UNICODE_STRING {
            Length: name_bytes as u16,
            MaximumLength: (name_bytes + size_of::<u16>()) as u16,
            Buffer: name.as_ptr().cast_mut(),
        };
        let mut security = if create_new {
            Some(protected_security(identity)?)
        } else {
            None
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: handle(directory),
            ObjectName: &unicode,
            Attributes: OBJ_CASE_INSENSITIVE as u32,
            SecurityDescriptor: security.as_mut().map_or(std::ptr::null(), |security| {
                security.descriptor().cast_const()
            }),
            SecurityQualityOfService: std::ptr::null(),
        };
        let access = GENERIC_READ
            | READ_CONTROL
            | SYNCHRONIZE
            | WRITE_DAC
            | if write { GENERIC_WRITE } else { 0 }
            | if delete { DELETE } else { 0 }
            | if create_new { WRITE_OWNER } else { 0 };
        // FILE_OPEN_REPARSE_POINT is for opening an existing reparse point;
        // combining it with FILE_CREATE is rejected by Windows on the
        // create-new path. FILE_CREATE cannot follow an existing final name,
        // while existing opens retain the no-follow behavior below.
        let options = FILE_NON_DIRECTORY_FILE
            | if create_new {
                0
            } else {
                FILE_OPEN_REPARSE_POINT
            }
            | FILE_SYNCHRONOUS_IO_NONALERT
            | FILE_WRITE_THROUGH;
        let disposition = if create_new { FILE_CREATE } else { FILE_OPEN };
        let mut child: HANDLE = 0;
        let mut status = IO_STATUS_BLOCK {
            Anonymous: IO_STATUS_BLOCK_0 { Status: 0 },
            Information: 0,
        };
        // SAFETY: all pointers refer to live, immutable Rust buffers for the
        // duration of the synchronous NtCreateFile call. RootDirectory is the
        // retained directory capability and no raw handle escapes this module.
        let result = unsafe {
            NtCreateFile(
                &mut child,
                access,
                &attributes,
                &mut status,
                std::ptr::null(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                disposition,
                options,
                std::ptr::null(),
                0,
            )
        };
        if result < 0 {
            return Err(nt_status_error(result));
        }
        if child == 0 || child == INVALID_HANDLE_VALUE {
            return Err(SecurityError::Security(
                "Windows returned an invalid child handle".to_owned(),
            ));
        }
        // SAFETY: NtCreateFile returned an owned kernel handle exactly once;
        // File takes ownership and closes it exactly once on Drop.
        Ok(unsafe { File::from_raw_handle(child as _) })
    }

    fn open(
        path: &Path,
        write: bool,
        directory: bool,
        write_owner: bool,
    ) -> Result<File, SecurityError> {
        let path = wide(path);
        let access = GENERIC_READ
            | READ_CONTROL
            | WRITE_DAC
            | DELETE
            | if write { GENERIC_WRITE } else { 0 }
            | if write_owner { WRITE_OWNER } else { 0 };
        let flags = FILE_FLAG_OPEN_REPARSE_POINT
            | FILE_FLAG_WRITE_THROUGH
            | if directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            };
        // SAFETY: the UTF-16 buffer is NUL-terminated and remains alive for
        // the synchronous CreateFileW call. A successful handle is transferred
        // exactly once into File below.
        let file = unsafe {
            let handle = CreateFileW(
                path.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null_mut(),
                OPEN_EXISTING,
                flags,
                0,
            );
            if handle == INVALID_HANDLE_VALUE || handle == 0 {
                return Err(SecurityError::Io(std::io::Error::last_os_error()));
            }
            File::from_raw_handle(handle as _)
        };
        Ok(file)
    }

    fn nt_status_error(status: i32) -> SecurityError {
        match status as u32 {
            0xC000_0034 | 0xC000_003A => SecurityError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "protected child is missing",
            )),
            0xC000_0035 => SecurityError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "protected child already exists",
            )),
            _ => SecurityError::Io(io::Error::other(format!(
                "NtCreateFile failed with NTSTATUS 0x{status:08x}"
            ))),
        }
    }

    fn reject_reparse(file: &File) -> Result<(), SecurityError> {
        unsafe {
            let mut info = FILE_ATTRIBUTE_TAG_INFO {
                FileAttributes: 0,
                ReparseTag: 0,
            };
            if GetFileInformationByHandleEx(
                handle(file),
                FileAttributeTagInfo,
                (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast::<c_void>(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            ) == 0
            {
                return Err(SecurityError::Security(
                    "could not inspect Windows reparse attributes".to_owned(),
                ));
            }
            if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(SecurityError::Security(
                    "Windows reparse point is rejected".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn validate(file: &File, identity: &CurrentIdentity) -> Result<(), SecurityError> {
        reject_reparse(file)?;
        if unsafe { windows_sys::Win32::Storage::FileSystem::GetFileType(handle(file)) }
            == FILE_TYPE_UNKNOWN
        {
            return Err(SecurityError::Security(
                "opened Windows handle has no file type".to_owned(),
            ));
        }
        let sid = identity.sid_ptr();
        unsafe {
            let mut owner: PSID = null_mut();
            let mut dacl: *mut ACL = null_mut();
            let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
            if GetSecurityInfo(
                handle(file),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            ) != 0
            {
                return Err(SecurityError::Security(
                    "could not read Windows owner/DACL".to_owned(),
                ));
            }
            let result = if owner.is_null() || dacl.is_null() || descriptor.is_null() {
                Err(SecurityError::Security(
                    "Windows owner/DACL is missing".to_owned(),
                ))
            } else if EqualSid(owner, sid) == 0 {
                Err(SecurityError::Security(
                    "Windows owner is not the current user".to_owned(),
                ))
            } else {
                let mut control = 0_u16;
                let mut revision = 0_u32;
                if GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0
                    || control & SE_DACL_PROTECTED == 0
                {
                    Err(SecurityError::Security(
                        "Windows DACL is not protected".to_owned(),
                    ))
                } else {
                    let mut info = ACL_SIZE_INFORMATION {
                        AceCount: 0,
                        AclBytesInUse: 0,
                        AclBytesFree: 0,
                    };
                    if GetAclInformation(
                        dacl,
                        (&mut info as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
                        size_of::<ACL_SIZE_INFORMATION>() as u32,
                        AclSizeInformation,
                    ) == 0
                        || info.AceCount == 0
                    {
                        Err(SecurityError::Security("Windows DACL is empty".to_owned()))
                    } else {
                        let acl_start = dacl as usize;
                        let acl_size = (*dacl).AclSize as usize;
                        let acl_bytes = info.AclBytesInUse as usize;
                        let acl_end = acl_start.checked_add(acl_bytes);
                        if acl_size < size_of::<ACL>()
                            || acl_bytes < size_of::<ACL>()
                            || acl_bytes > acl_size
                            || acl_end.is_none()
                        {
                            Err(SecurityError::Security(
                                "Windows DACL bounds are invalid".to_owned(),
                            ))
                        } else {
                            let mut valid = true;
                            let mut full_access = false;
                            let acl_end = acl_end.unwrap_or(acl_start);
                            for index in 0..info.AceCount {
                                let mut ace_ptr: *mut c_void = null_mut();
                                if GetAce(dacl, index, &mut ace_ptr) == 0 || ace_ptr.is_null() {
                                    valid = false;
                                    break;
                                }
                                let ace_sid = match validated_ace_sid(ace_ptr, acl_end) {
                                    Ok(ace_sid) => ace_sid,
                                    Err(_) => {
                                        valid = false;
                                        break;
                                    }
                                };
                                let ace = &*(ace_ptr.cast::<ACCESS_ALLOWED_ACE>());
                                if EqualSid(ace_sid, sid) == 0 {
                                    valid = false;
                                    break;
                                }
                                if ace.Mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS {
                                    full_access = true;
                                }
                            }
                            if valid && full_access {
                                Ok(())
                            } else {
                                Err(SecurityError::Security(
                                    "Windows DACL is not current-user-only".to_owned(),
                                ))
                            }
                        }
                    }
                }
            };
            if !descriptor.is_null() {
                let _ = windows_sys::Win32::Foundation::LocalFree(descriptor.cast());
            }
            result
        }
    }

    fn validated_ace_sid(ace_ptr: *mut c_void, acl_end: usize) -> Result<PSID, SecurityError> {
        let ace_start = ace_ptr as usize;
        let header_end = ace_start
            .checked_add(size_of::<ACE_HEADER>())
            .ok_or_else(|| {
                SecurityError::Security("Windows ACE header bounds overflowed".to_owned())
            })?;
        if header_end > acl_end {
            return Err(SecurityError::Security(
                "Windows ACE header exceeds the DACL".to_owned(),
            ));
        }
        let header = unsafe { &*(ace_ptr.cast::<ACE_HEADER>()) };
        let forbidden_flags = (CONTAINER_INHERIT_ACE
            | INHERITED_ACE
            | INHERIT_ONLY_ACE
            | NO_PROPAGATE_INHERIT_ACE
            | OBJECT_INHERIT_ACE) as u8;
        let ace_size = header.AceSize as usize;
        let ace_end = ace_start
            .checked_add(ace_size)
            .ok_or_else(|| SecurityError::Security("Windows ACE bounds overflowed".to_owned()))?;
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
            || header.AceFlags & forbidden_flags != 0
            || ace_size < size_of::<ACCESS_ALLOWED_ACE>()
            || ace_end > acl_end
        {
            return Err(SecurityError::Security(
                "Windows ACE header or inheritance is invalid".to_owned(),
            ));
        }
        let sid_offset = size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>();
        let sid_start = ace_start.checked_add(sid_offset).ok_or_else(|| {
            SecurityError::Security("Windows ACE SID offset overflowed".to_owned())
        })?;
        let minimum_sid_len = size_of::<SID>() - size_of::<u32>();
        let sid_header_end = sid_start.checked_add(minimum_sid_len).ok_or_else(|| {
            SecurityError::Security("Windows ACE SID bounds overflowed".to_owned())
        })?;
        if sid_start % align_of::<u32>() != 0 || sid_header_end > ace_end {
            return Err(SecurityError::Security(
                "Windows ACE SID is outside the ACE".to_owned(),
            ));
        }
        let sub_authority_count = unsafe { *((sid_start + 1) as *const u8) } as usize;
        let sid_len = minimum_sid_len
            .checked_add(
                sub_authority_count
                    .checked_mul(size_of::<u32>())
                    .ok_or_else(|| {
                        SecurityError::Security("Windows ACE SID length overflowed".to_owned())
                    })?,
            )
            .ok_or_else(|| {
                SecurityError::Security("Windows ACE SID length overflowed".to_owned())
            })?;
        let sid_end = sid_start.checked_add(sid_len).ok_or_else(|| {
            SecurityError::Security("Windows ACE SID bounds overflowed".to_owned())
        })?;
        if sid_end > ace_end || sid_len > u32::MAX as usize {
            return Err(SecurityError::Security(
                "Windows ACE SID exceeds its ACE".to_owned(),
            ));
        }
        let sid = sid_start as PSID;
        unsafe {
            if IsValidSid(sid) == 0 || GetLengthSid(sid) as usize != sid_len {
                return Err(SecurityError::Security(
                    "Windows ACE SID failed validation".to_owned(),
                ));
            }
        }
        Ok(sid)
    }

    pub(super) fn validate_directory(
        file: &File,
        identity: &CurrentIdentity,
    ) -> Result<(), SecurityError> {
        validate(file, identity)?;
        unsafe {
            let mut info = FILE_BASIC_INFO {
                CreationTime: 0,
                LastAccessTime: 0,
                LastWriteTime: 0,
                ChangeTime: 0,
                FileAttributes: 0,
            };
            if GetFileInformationByHandleEx(
                handle(file),
                FileBasicInfo,
                (&mut info as *mut FILE_BASIC_INFO).cast::<c_void>(),
                size_of::<FILE_BASIC_INFO>() as u32,
            ) == 0
                || info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            {
                return Err(SecurityError::Security(
                    "opened Windows runtime handle is not a directory".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn rename_info_buffer(destination: &str) -> Result<(Vec<usize>, u32, u32), SecurityError> {
        let mut name: Vec<u16> = std::ffi::OsStr::new(destination).encode_wide().collect();
        if name.is_empty() {
            return Err(SecurityError::Invalid(
                "protected replacement name is invalid".to_owned(),
            ));
        }
        let name_bytes = name.len().checked_mul(size_of::<u16>()).ok_or_else(|| {
            SecurityError::Invalid("protected replacement name is too long".to_owned())
        })?;
        let file_name_length = u32::try_from(name_bytes).map_err(|_| {
            SecurityError::Invalid("protected replacement name is too long".to_owned())
        })?;
        name.push(0);
        let size = size_of::<FILE_RENAME_INFORMATION>()
            .checked_add(name_bytes)
            .ok_or_else(|| {
                SecurityError::Invalid("protected rename buffer is too large".to_owned())
            })?;
        let buffer_size = u32::try_from(size).map_err(|_| {
            SecurityError::Invalid("protected rename buffer is too large".to_owned())
        })?;
        let words = size.checked_add(size_of::<usize>() - 1).ok_or_else(|| {
            SecurityError::Invalid("protected rename buffer is too large".to_owned())
        })? / size_of::<usize>();
        let mut buffer = vec![0_usize; words];
        unsafe {
            let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
            (*info).Anonymous = FILE_RENAME_INFORMATION_0 { ReplaceIfExists: 1 };
            (*info).RootDirectory = 0;
            (*info).FileNameLength = file_name_length;
            let file_name = buffer
                .as_mut_ptr()
                .cast::<u8>()
                .add(std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName))
                .cast::<u16>();
            std::ptr::copy_nonoverlapping(name.as_ptr(), file_name, name.len());
        }
        Ok((buffer, file_name_length, buffer_size))
    }

    pub(super) fn replace(
        directory: &File,
        source: &File,
        destination: &str,
    ) -> Result<(), SecurityError> {
        let (mut buffer, _file_name_length, buffer_size) = rename_info_buffer(destination)?;
        #[cfg(test)]
        let source_handle =
            if destination == "registry" && FAIL_NEXT_REPLACE_CALL.swap(false, Ordering::SeqCst) {
                INVALID_HANDLE_VALUE
            } else {
                handle(source)
            };
        #[cfg(not(test))]
        let source_handle = handle(source);
        let mut status = IO_STATUS_BLOCK {
            Anonymous: IO_STATUS_BLOCK_0 { Status: 0 },
            Information: 0,
        };
        unsafe {
            let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
            (*info).RootDirectory = handle(directory);
            let result = NtSetInformationFile(
                source_handle,
                &mut status,
                info.cast(),
                buffer_size,
                FILE_RENAME_INFORMATION_CLASS,
            );
            if result < 0 {
                let error = RtlNtStatusToDosError(result);
                return Err(SecurityError::Io(io::Error::from_raw_os_error(
                    error as i32,
                )));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn fail_next_replace_call() {
        FAIL_NEXT_REPLACE_CALL.store(true, Ordering::SeqCst);
    }

    pub(super) fn dispose(file: &File) -> Result<(), SecurityError> {
        unsafe {
            let info = FILE_DISPOSITION_INFO { DeleteFile: 1 };
            if SetFileInformationByHandle(
                handle(file),
                FileDispositionInfo,
                (&info as *const FILE_DISPOSITION_INFO).cast::<c_void>(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            ) == 0
            {
                return Err(SecurityError::Io(std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rename_info_buffer_has_checked_layout_and_trailing_zero() {
            let expected_name: Vec<u16> = std::ffi::OsStr::new("identity").encode_wide().collect();
            let (buffer, file_name_length, declared_size) = rename_info_buffer("identity").unwrap();
            let allocation_size = buffer.len() * size_of::<usize>();
            let file_name_offset = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
            let file_name_end = file_name_offset
                .checked_add(file_name_length as usize)
                .unwrap();
            let trailing_end = file_name_end.checked_add(size_of::<u16>()).unwrap();

            assert_eq!(
                file_name_length as usize,
                expected_name.len() * size_of::<u16>()
            );
            assert_eq!(
                declared_size as usize,
                size_of::<FILE_RENAME_INFORMATION>() + file_name_length as usize
            );
            assert!(allocation_size >= declared_size as usize);
            assert!(file_name_end <= allocation_size);
            assert!(trailing_end <= allocation_size);

            unsafe {
                let info = buffer.as_ptr().cast::<FILE_RENAME_INFORMATION>();
                assert_eq!((*info).FileNameLength, file_name_length);
                assert_eq!((*info).Anonymous.ReplaceIfExists, 1);
                assert_eq!((*info).RootDirectory, 0);
                let file_name = buffer
                    .as_ptr()
                    .cast::<u8>()
                    .add(file_name_offset)
                    .cast::<u16>();
                for (index, expected) in expected_name.iter().enumerate() {
                    assert_eq!(*file_name.add(index), *expected);
                }
                assert_eq!(*file_name.add(expected_name.len()), 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DirectoryDurability, ReplacementError, RuntimeDir, SecurityError};
    use std::fs;
    use std::os::windows::fs::symlink_file;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
    // The replace fault seam is intentionally process-global inside `ffi`.
    // Serialize the tests using its destination so parallel tests cannot
    // consume one another's injected fault.
    static REGISTRY_REPLACEMENT_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn temporary_directory(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "gorce-platform-win-{label}-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn native_create_new_reopen_replace_dispose_and_durability() {
        let root = temporary_directory("native");
        let runtime = RuntimeDir::open(&root).unwrap();

        let lock = runtime.lock("created").unwrap();
        drop(lock);
        assert_eq!(runtime.read_private("created").unwrap().unwrap(), b"");

        let first = runtime.replace_private("identity", b"first").unwrap();
        assert_eq!(first.directory_entry, DirectoryDurability::BestEffort);
        assert_eq!(runtime.read_private("identity").unwrap().unwrap(), b"first");
        let second = runtime.replace_private("identity", b"second").unwrap();
        assert_eq!(second.directory_entry, DirectoryDurability::BestEffort);
        assert_eq!(
            runtime.read_private("identity").unwrap().unwrap(),
            b"second"
        );
        assert_eq!(
            runtime.remove_private("identity").unwrap().directory_entry,
            DirectoryDurability::BestEffort
        );
        assert_eq!(
            runtime.remove_private("created").unwrap().directory_entry,
            DirectoryDurability::BestEffort
        );
        assert!(runtime.read_private("identity").unwrap().is_none());
        assert!(runtime.read_private("created").unwrap().is_none());

        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn held_lock_uses_its_handle_for_sentinel_length() {
        let root = temporary_directory("held-lock");
        let runtime = RuntimeDir::open(&root).unwrap();
        let lock = runtime.lock("LOCK").unwrap();

        assert_eq!(lock.file_len().unwrap(), 0);
        let second_handle = runtime.read_private("LOCK");
        assert!(matches!(
            second_handle,
            Err(SecurityError::Io(error)) if error.raw_os_error() == Some(33)
        ));

        drop(lock);
        assert_eq!(runtime.read_private("LOCK").unwrap(), Some(Vec::new()));
        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_reparse_child_is_rejected_after_open() {
        let root = temporary_directory("reparse");
        let target = temporary_directory("target");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("secret"), b"outside").unwrap();
        let runtime = RuntimeDir::open(&root).unwrap();
        symlink_file(target.join("secret"), root.join("secret")).unwrap();
        assert!(runtime.open_private("secret", false).is_err());

        drop(runtime);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(target).unwrap();
    }

    #[test]
    fn validated_rejection_preserves_the_old_file_before_rename() {
        let _test_lock = REGISTRY_REPLACEMENT_TEST_LOCK.lock().unwrap();
        let root = temporary_directory("validated-rejection");
        let runtime = RuntimeDir::open(&root).unwrap();
        runtime.replace_private("registry", b"old").unwrap();

        let failure =
            runtime.replace_private_validated("registry", ".registry.tmp", b"new", |_| {
                Err("reject before rename".to_owned())
            });
        assert!(matches!(
            failure,
            Err(ReplacementError::BeforePublication(SecurityError::Invalid(
                _
            )))
        ));
        assert_eq!(
            runtime.read_private("registry").unwrap(),
            Some(b"old".to_vec())
        );

        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prepublication_io_failure_preserves_the_old_file() {
        let _test_lock = REGISTRY_REPLACEMENT_TEST_LOCK.lock().unwrap();
        let root = temporary_directory("prepublication-io");
        let runtime = RuntimeDir::open(&root).unwrap();
        runtime.replace_private("registry", b"old").unwrap();
        fs::create_dir(root.join(".registry.io")).unwrap();

        let failure =
            runtime.replace_private_validated("registry", ".registry.io", b"new", |_| Ok(()));
        assert!(matches!(
            failure,
            Err(ReplacementError::BeforePublication(_))
        ));
        assert_eq!(
            runtime.read_private("registry").unwrap(),
            Some(b"old".to_vec())
        );

        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replacement_call_failure_after_validation_preserves_the_old_file() {
        let _test_lock = REGISTRY_REPLACEMENT_TEST_LOCK.lock().unwrap();
        let root = temporary_directory("replacement-call-failure");
        let runtime = RuntimeDir::open(&root).unwrap();
        runtime.replace_private("registry", b"old").unwrap();
        let mut validated = false;
        super::ffi::fail_next_replace_call();

        let failure =
            runtime.replace_private_validated("registry", ".registry.tmp", b"new", |candidate| {
                assert_eq!(candidate, b"new");
                validated = true;
                Ok(())
            });
        assert!(matches!(
            failure,
            Err(ReplacementError::BeforePublication(SecurityError::Io(_)))
        ));
        assert!(validated);
        assert_eq!(
            runtime.read_private("registry").unwrap(),
            Some(b"old".to_vec())
        );

        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn existing_default_acl_runtime_root_is_rejected() {
        let root = temporary_directory("broad");
        fs::create_dir_all(&root).unwrap();
        assert!(RuntimeDir::open(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_dir_moves_across_threads_with_private_state() {
        let root = temporary_directory("threaded");
        let runtime = RuntimeDir::open(&root).unwrap();
        let worker = std::thread::spawn(move || {
            runtime.replace_private("threaded", b"ok").unwrap();
            runtime.read_private("threaded").unwrap().unwrap()
        });
        assert_eq!(worker.join().unwrap(), b"ok");
        fs::remove_dir_all(root).unwrap();
    }
}
