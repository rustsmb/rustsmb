//! NT_STATUS codes for SMB protocol responses.

use crate::error::VfsError;

/// NT_STATUS codes as defined in MS-ERREF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u32)]
pub enum NtStatus {
    // Success codes
    /// The operation completed successfully.
    #[default]
    Success = 0x00000000,
    /// The operation is pending.
    Pending = 0x00000103,

    // Information codes
    /// More data is available.
    BufferOverflow = 0x80000005,
    /// No more files found.
    NoMoreFiles = 0x80000006,

    // Warning codes
    /// More processing is required to complete the operation.
    MoreProcessingRequired = 0xC0000016,

    // Error codes
    /// The request is not supported.
    NotImplemented = 0xC0000002,
    /// An invalid parameter was passed to a function.
    InvalidParameter = 0xC000000D,
    /// The file does not exist.
    NoSuchFile = 0xC000000F,
    /// Invalid handle.
    InvalidHandle = 0xC0000008,
    /// Invalid device request (e.g., read on directory).
    InvalidDeviceRequest = 0xC0000010,
    /// End of file was reached.
    EndOfFile = 0xC0000011,
    /// Access is denied.
    AccessDenied = 0xC0000022,
    /// The buffer is too small.
    BufferTooSmall = 0xC0000023,
    /// The object name is not found.
    ObjectNameNotFound = 0xC0000034,
    /// The object name already exists.
    ObjectNameCollision = 0xC0000035,
    /// The object path is not found.
    ObjectPathNotFound = 0xC000003A,
    /// The object path syntax is invalid.
    ObjectPathSyntaxBad = 0xC000003B,
    /// A sharing violation occurred.
    SharingViolation = 0xC0000043,
    /// A file lock conflict occurred.
    FileLockConflict = 0xC0000054,
    /// A requested read/write lock cannot be granted (FAIL_IMMEDIATELY).
    LockNotGranted = 0xC0000055,
    /// The lock range is invalid.
    InvalidLockRange = 0xC00001A1,
    /// The disk is full.
    DiskFull = 0xC000007F,
    /// The requested operation is not supported.
    NotSupported = 0xC00000BB,
    /// The network name cannot be found.
    BadNetworkName = 0xC00000CC,
    /// The request was not accepted.
    RequestNotAccepted = 0xC00000D0,
    /// An internal error occurred.
    InternalError = 0xC00000E5,
    /// The user session was deleted.
    UserSessionDeleted = 0xC0000203,
    /// The network session has expired.
    NetworkSessionExpired = 0xC000035C,
    /// The file is a directory.
    FileIsADirectory = 0xC00000BA,
    /// The directory is not empty.
    DirectoryNotEmpty = 0xC0000101,
    /// Not a directory.
    NotADirectory = 0xC0000103,
    /// The file is too large.
    FileTooLarge = 0xC0000904,
    /// Cross-device operation not allowed.
    NotSameDevice = 0xC00000D4,
    /// The file is read-only.
    MediaWriteProtected = 0xC00000A2,
    /// The name is too long.
    NameTooLong = 0xC0000106,
    /// The file has been closed.
    FileClosed = 0xC0000128,
    /// The network name was deleted (tree disconnected).
    NetworkNameDeleted = 0xC00000C9,

    // SMB-specific
    /// Invalid SMB.
    InvalidSmb = 0x00010002,
    /// SMB bad command.
    SmbBadCommand = 0x00160002,

    // Logon errors
    /// Logon failure.
    LogonFailure = 0xC000006D,
    /// Account disabled.
    AccountDisabled = 0xC0000072,
    /// Account locked out.
    AccountLockedOut = 0xC0000234,
    /// Password expired.
    PasswordExpired = 0xC0000071,

    // Impersonation errors
    /// Bad impersonation level.
    BadImpersonationLevel = 0xC00000A5,
}

impl NtStatus {
    /// Returns the raw u32 value of this status code.
    #[inline]
    pub fn code(self) -> u32 {
        self as u32
    }

    /// Returns true if this is a success status.
    #[inline]
    pub fn is_success(self) -> bool {
        (self as u32) < 0x80000000
    }

    /// Returns true if this is an error status.
    #[inline]
    pub fn is_error(self) -> bool {
        (self as u32) >= 0xC0000000
    }

    /// Returns true if this is a warning status.
    #[inline]
    pub fn is_warning(self) -> bool {
        let code = self as u32;
        (0x80000000..0xC0000000).contains(&code)
    }

    /// Create NtStatus from raw code.
    pub fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            0x00000000 => Self::Success,
            0x00000103 => Self::Pending,
            0x80000005 => Self::BufferOverflow,
            0x80000006 => Self::NoMoreFiles,
            0xC0000016 => Self::MoreProcessingRequired,
            0xC0000002 => Self::NotImplemented,
            0xC000000D => Self::InvalidParameter,
            0xC000000F => Self::NoSuchFile,
            0xC0000008 => Self::InvalidHandle,
            0xC0000010 => Self::InvalidDeviceRequest,
            0xC0000011 => Self::EndOfFile,
            0xC0000022 => Self::AccessDenied,
            0xC0000023 => Self::BufferTooSmall,
            0xC0000034 => Self::ObjectNameNotFound,
            0xC0000035 => Self::ObjectNameCollision,
            0xC000003A => Self::ObjectPathNotFound,
            0xC000003B => Self::ObjectPathSyntaxBad,
            0xC0000043 => Self::SharingViolation,
            0xC0000054 => Self::FileLockConflict,
            0xC0000055 => Self::LockNotGranted,
            0xC00001A1 => Self::InvalidLockRange,
            0xC000007F => Self::DiskFull,
            0xC00000BB => Self::NotSupported,
            0xC00000CC => Self::BadNetworkName,
            0xC00000D0 => Self::RequestNotAccepted,
            0xC00000E5 => Self::InternalError,
            0xC0000203 => Self::UserSessionDeleted,
            0xC000035C => Self::NetworkSessionExpired,
            0xC00000BA => Self::FileIsADirectory,
            0xC0000101 => Self::DirectoryNotEmpty,
            0xC0000103 => Self::NotADirectory,
            0xC0000904 => Self::FileTooLarge,
            0xC00000D4 => Self::NotSameDevice,
            0xC00000A2 => Self::MediaWriteProtected,
            0xC0000106 => Self::NameTooLong,
            0xC0000128 => Self::FileClosed,
            0xC00000C9 => Self::NetworkNameDeleted,
            0x00010002 => Self::InvalidSmb,
            0x00160002 => Self::SmbBadCommand,
            0xC000006D => Self::LogonFailure,
            0xC0000072 => Self::AccountDisabled,
            0xC0000234 => Self::AccountLockedOut,
            0xC0000071 => Self::PasswordExpired,
            0xC00000A5 => Self::BadImpersonationLevel,
            _ => return None,
        })
    }
}

impl From<&VfsError> for NtStatus {
    fn from(err: &VfsError) -> Self {
        match err {
            VfsError::NotFound(_) => Self::ObjectNameNotFound,
            VfsError::AccessDenied(_) => Self::AccessDenied,
            VfsError::AlreadyExists(_) => Self::ObjectNameCollision,
            VfsError::NotADirectory(_) => Self::NotADirectory,
            VfsError::IsADirectory(_) => Self::FileIsADirectory,
            VfsError::DirectoryNotEmpty(_) => Self::DirectoryNotEmpty,
            VfsError::InvalidPath(_) => Self::ObjectPathSyntaxBad,
            VfsError::DiskFull => Self::DiskFull,
            VfsError::FileTooLarge => Self::FileTooLarge,
            VfsError::SharingViolation(_) => Self::SharingViolation,
            VfsError::LockConflict => Self::FileLockConflict,
            VfsError::InvalidHandle => Self::InvalidHandle,
            VfsError::NotSupported(_) => Self::NotSupported,
            VfsError::ReadOnly => Self::MediaWriteProtected,
            VfsError::CrossDevice => Self::NotSameDevice,
            VfsError::NameTooLong(_) => Self::NameTooLong,
            VfsError::Backend(_) | VfsError::Io(_) => Self::InternalError,
        }
    }
}

impl From<VfsError> for NtStatus {
    fn from(err: VfsError) -> Self {
        Self::from(&err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_codes() {
        assert_eq!(NtStatus::Success.code(), 0x00000000);
        assert_eq!(NtStatus::AccessDenied.code(), 0xC0000022);
    }

    #[test]
    fn test_is_success() {
        assert!(NtStatus::Success.is_success());
        assert!(!NtStatus::AccessDenied.is_success());
    }

    #[test]
    fn test_is_error() {
        assert!(!NtStatus::Success.is_error());
        assert!(NtStatus::AccessDenied.is_error());
    }

    #[test]
    fn test_is_warning() {
        assert!(!NtStatus::Success.is_warning());
        // BufferOverflow (0x80000005) is in the warning range (0x80000000 - 0xBFFFFFFF)
        assert!(NtStatus::BufferOverflow.is_warning());
        // MoreProcessingRequired (0xC0000016) is actually an error, not a warning
        assert!(!NtStatus::MoreProcessingRequired.is_warning());
        assert!(!NtStatus::AccessDenied.is_warning());
    }

    #[test]
    fn test_from_code() {
        assert_eq!(NtStatus::from_code(0x00000000), Some(NtStatus::Success));
        assert_eq!(
            NtStatus::from_code(0xC0000022),
            Some(NtStatus::AccessDenied)
        );
        assert_eq!(NtStatus::from_code(0xDEADBEEF), None);
    }

    #[test]
    fn test_vfs_error_to_status() {
        let err = VfsError::NotFound("test".to_string());
        assert_eq!(NtStatus::from(&err), NtStatus::ObjectNameNotFound);

        let err = VfsError::AccessDenied("test".to_string());
        assert_eq!(NtStatus::from(&err), NtStatus::AccessDenied);
    }
}
