#![cfg(windows)]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Windows-only capability implementation for `gorce-platform-security`.
//!
//! The only unsafe code in this crate is contained in `ffi`. That module owns
//! all Win32 pointers and handles: every successful `CreateFileW` handle is
//! transferred exactly once into `std::fs::File`, temporary rename buffers are
//! borrowed only for the duration of `SetFileInformationByHandle`, and security
//! descriptor allocations are released with `LocalFree` before returning.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
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
}

impl RuntimeDir {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SecurityError> {
        let root = path.as_ref().to_owned();
        fs::create_dir_all(&root)?;
        let directory = ffi::open_directory(&root)?;
        ffi::secure(&directory)?;
        ffi::validate_directory(&directory)?;
        Ok(Self { directory })
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
        let file = match ffi::open_child(&self.directory, name, write, false, false) {
            Ok(file) => file,
            Err(SecurityError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        ffi::validate(&file)?;
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
        validate_child_name(&temporary_name)?;
        let result = (|| {
            let mut file = ffi::open_child(&self.directory, &temporary_name, true, true, true)?;
            ffi::secure(&file)?;
            ffi::validate(&file)?;
            file.write_all(contents)?;
            file.sync_all()?;
            ffi::replace(&self.directory, &file, name)?;
            drop(file);
            Ok(DurabilityReport {
                directory_entry: DirectoryDurability::BestEffort,
            })
        })();
        if result.is_err() {
            if let Ok(file) = ffi::open_child(&self.directory, &temporary_name, true, false, true) {
                let _ = ffi::dispose(&file);
            }
        }
        result
    }

    pub fn lock(&self, name: &str) -> Result<LockGuard, SecurityError> {
        validate_child_name(name)?;
        let file = match ffi::open_child(&self.directory, name, true, false, false) {
            Ok(file) => file,
            Err(SecurityError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                ffi::open_child(&self.directory, name, true, true, false)?
            }
            Err(error) => return Err(error),
        };
        ffi::secure(&file)?;
        ffi::validate(&file)?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(LockGuard { file }),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(
                SecurityError::Security("runtime instance lock is already held".to_owned()),
            ),
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
        let file = ffi::open_child(&self.directory, name, true, false, true)?;
        ffi::validate(&file)?;
        ffi::dispose(&file)?;
        drop(file);
        Ok(DurabilityReport {
            directory_entry: DirectoryDurability::BestEffort,
        })
    }
}

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

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
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

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        NtCreateFile, FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
        FILE_RENAME_REPLACE_IF_EXISTS, FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_THROUGH,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, PSID,
        UNICODE_STRING,
    };
    use windows_sys::Win32::Security::Authorization::{
        GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        AclSizeInformation, AddAccessAllowedAce, EqualSid, GetAce, GetAclInformation, GetLengthSid,
        GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl, TokenUser,
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION,
        DACL_SECURITY_INFORMATION, INHERITED_ACE, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FileAttributeTagInfo, FileBasicInfo, FileDispositionInfo, FileRenameInfo,
        GetFileInformationByHandleEx, SetFileInformationByHandle, CREATE_NEW, DELETE,
        FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_DISPOSITION_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
        FILE_RENAME_INFO, FILE_RENAME_INFO_0, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_TYPE_UNKNOWN, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
    };
    use windows_sys::Win32::System::Kernel::OBJ_CASE_INSENSITIVE;
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, IO_STATUS_BLOCK_0};

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

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn handle(file: &File) -> HANDLE {
        file.as_raw_handle() as HANDLE
    }

    pub(super) fn open_directory(path: &Path) -> Result<File, SecurityError> {
        open(path, false, false, true)
    }

    pub(super) fn open_child(
        directory: &File,
        name: &str,
        write: bool,
        create_new: bool,
        delete: bool,
    ) -> Result<File, SecurityError> {
        let name = name.encode_utf16().collect::<Vec<_>>();
        if name.is_empty() || name.len() > (u16::MAX as usize / 2) {
            return Err(SecurityError::Invalid(
                "protected runtime child name is too long".to_owned(),
            ));
        }
        let mut unicode = UNICODE_STRING {
            Length: (name.len() * size_of::<u16>()) as u16,
            MaximumLength: (name.len() * size_of::<u16>()) as u16,
            Buffer: name.as_ptr().cast_mut(),
        };
        let object_name = &mut unicode;
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: handle(directory),
            ObjectName: object_name as *const UNICODE_STRING,
            Attributes: OBJ_CASE_INSENSITIVE as u32,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let access = GENERIC_READ
            | READ_CONTROL
            | WRITE_DAC
            | if write { GENERIC_WRITE } else { 0 }
            | if delete { DELETE } else { 0 };
        let options = FILE_NON_DIRECTORY_FILE
            | FILE_OPEN_REPARSE_POINT
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
        create_new: bool,
        directory: bool,
    ) -> Result<File, SecurityError> {
        let path = wide(path);
        let access = GENERIC_READ
            | READ_CONTROL
            | WRITE_DAC
            | DELETE
            | if write { GENERIC_WRITE } else { 0 };
        let creation = if create_new {
            CREATE_NEW
        } else {
            OPEN_EXISTING
        };
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
                creation,
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

    fn current_sid() -> Result<(OwnedHandle, Vec<usize>, PSID), SecurityError> {
        unsafe {
            let mut token: HANDLE = 0;
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(SecurityError::Security(
                    "could not open current Windows token".to_owned(),
                ));
            }
            let token = OwnedHandle(token);
            let mut needed = 0;
            let _ = GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed);
            if needed == 0 {
                return Err(SecurityError::Security(
                    "could not size current Windows token".to_owned(),
                ));
            }
            let mut buffer = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
            if GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * size_of::<usize>()) as u32,
                &mut needed,
            ) == 0
            {
                return Err(SecurityError::Security(
                    "could not read current Windows token".to_owned(),
                ));
            }
            let user = &*(buffer.as_ptr().cast::<TOKEN_USER>());
            Ok((token, buffer, user.User.Sid))
        }
    }

    pub(super) fn validate(file: &File) -> Result<(), SecurityError> {
        reject_reparse(file)?;
        if unsafe { windows_sys::Win32::Storage::FileSystem::GetFileType(handle(file)) }
            == FILE_TYPE_UNKNOWN
        {
            return Err(SecurityError::Security(
                "opened Windows handle has no file type".to_owned(),
            ));
        }
        let (_token, _buffer, sid) = current_sid()?;
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
                        let mut valid = true;
                        let mut full_access = false;
                        for index in 0..info.AceCount {
                            let mut ace_ptr: *mut c_void = null_mut();
                            if GetAce(dacl, index, &mut ace_ptr) == 0 || ace_ptr.is_null() {
                                valid = false;
                                break;
                            }
                            let header = &*(ace_ptr.cast::<ACE_HEADER>());
                            let ace = &*(ace_ptr.cast::<ACCESS_ALLOWED_ACE>());
                            if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
                                || (header.AceFlags as u32) & INHERITED_ACE != 0
                                || header.AceSize < size_of::<ACCESS_ALLOWED_ACE>() as u16
                                || EqualSid((&ace.SidStart as *const u32).cast_mut().cast(), sid)
                                    == 0
                            {
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
            };
            if !descriptor.is_null() {
                let _ = windows_sys::Win32::Foundation::LocalFree(descriptor.cast());
            }
            result
        }
    }

    pub(super) fn validate_directory(file: &File) -> Result<(), SecurityError> {
        validate(file)?;
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

    pub(super) fn secure(file: &File) -> Result<(), SecurityError> {
        reject_reparse(file)?;
        let (_token, _buffer, sid) = current_sid()?;
        unsafe {
            let sid_length = GetLengthSid(sid);
            let acl_length = (size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>()
                + sid_length as usize) as u32;
            let mut acl_buffer = vec![0_u32; (acl_length as usize).div_ceil(size_of::<u32>())];
            let acl = acl_buffer.as_mut_ptr().cast();
            if sid_length == 0
                || InitializeAcl(acl, acl_length, ACL_REVISION) == 0
                || AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, sid) == 0
                || SetSecurityInfo(
                    handle(file),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    acl,
                    null_mut(),
                ) != 0
            {
                return Err(SecurityError::Security(
                    "could not apply Windows current-user DACL".to_owned(),
                ));
            }
        }
        validate(file)
    }

    pub(super) fn replace(
        directory: &File,
        source: &File,
        destination: &str,
    ) -> Result<(), SecurityError> {
        let name: Vec<u16> = std::ffi::OsStr::new(destination).encode_wide().collect();
        if name.is_empty() || name.len() > u32::MAX as usize / size_of::<u16>() {
            return Err(SecurityError::Invalid(
                "protected replacement name is invalid".to_owned(),
            ));
        }
        let size = size_of::<FILE_RENAME_INFO>() + name.len().saturating_sub(1) * size_of::<u16>();
        let mut buffer = vec![0_usize; size.div_ceil(size_of::<usize>())];
        unsafe {
            let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
            (*info).Anonymous = FILE_RENAME_INFO_0 {
                Flags: FILE_RENAME_REPLACE_IF_EXISTS,
            };
            (*info).RootDirectory = handle(directory);
            (*info).FileNameLength = (name.len() * size_of::<u16>()) as u32;
            std::ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
            if SetFileInformationByHandle(
                handle(source),
                FileRenameInfo,
                info.cast::<c_void>(),
                size as u32,
            ) == 0
            {
                return Err(SecurityError::Io(std::io::Error::last_os_error()));
            }
        }
        Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::{DirectoryDurability, RuntimeDir};
    use std::fs;
    use std::os::windows::fs::symlink_file;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "gorce-platform-win-{label}-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn native_handle_relative_replace_dispose_and_durability() {
        let root = temporary_directory("native");
        let runtime = RuntimeDir::open(&root).unwrap();

        let first = runtime.replace_private("identity", b"first").unwrap();
        assert_eq!(first.directory_entry, DirectoryDurability::BestEffort);
        assert_eq!(runtime.read_private("identity").unwrap().unwrap(), b"first");
        runtime.replace_private("identity", b"second").unwrap();
        assert_eq!(
            runtime.read_private("identity").unwrap().unwrap(),
            b"second"
        );
        runtime.remove_private("identity").unwrap();
        assert!(runtime.read_private("identity").unwrap().is_none());

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
        symlink_file(target.join("secret"), root.join("secret")).expect(
            "required Windows reparse-point prerequisite unavailable; native reparse coverage is inconclusive",
        );
        assert!(runtime.open_private("secret", false).is_err());

        drop(runtime);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(target).unwrap();
    }
}
