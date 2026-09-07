use std::fs::{self, File};
use std::io;
use std::path::Path;

pub(crate) type FileIdentity = (u64, u64);

#[cfg(unix)]
pub(crate) fn identity_from_path_metadata(
    _path: &Path,
    metadata: &fs::Metadata,
) -> io::Result<FileIdentity> {
    unix_identity(metadata)
}

#[cfg(unix)]
pub(crate) fn identity_from_file_metadata(
    _file: &File,
    metadata: &fs::Metadata,
) -> io::Result<FileIdentity> {
    unix_identity(metadata)
}

#[cfg(unix)]
fn unix_identity(metadata: &fs::Metadata) -> io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
pub(crate) fn identity_from_path_metadata(
    path: &Path,
    _metadata: &fs::Metadata,
) -> io::Result<FileIdentity> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let file = OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    windows_identity(&file)
}

#[cfg(windows)]
pub(crate) fn identity_from_file_metadata(
    file: &File,
    _metadata: &fs::Metadata,
) -> io::Result<FileIdentity> {
    windows_identity(file)
}

#[cfg(windows)]
fn windows_identity(file: &File) -> io::Result<FileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns a live Windows handle for the duration of the call,
    // and `information` is a valid writable output buffer of the required type.
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut information) };
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    let file_index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((u64::from(information.dwVolumeSerialNumber), file_index))
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn identity_from_path_metadata(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> io::Result<FileIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native file identity is unavailable on this platform",
    ))
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn identity_from_file_metadata(
    _file: &File,
    _metadata: &fs::Metadata,
) -> io::Result<FileIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native file identity is unavailable on this platform",
    ))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn windows_path_and_file_handle_identities_match() {
        let directory = tempfile::tempdir().expect("create Windows identity fixture");
        let path = directory.path().join("identity.txt");
        fs::write(&path, b"identity\n").expect("write Windows identity fixture");
        let path_metadata = fs::symlink_metadata(&path).expect("inspect identity fixture path");
        let file = File::open(&path).expect("open identity fixture");
        let file_metadata = file.metadata().expect("inspect identity fixture handle");

        assert_eq!(
            identity_from_path_metadata(&path, &path_metadata)
                .expect("obtain Windows path identity"),
            identity_from_file_metadata(&file, &file_metadata)
                .expect("obtain Windows handle identity")
        );
        assert!(identity_from_path_metadata(
            directory.path(),
            &fs::metadata(directory.path()).unwrap()
        )
        .is_ok());
    }
}
