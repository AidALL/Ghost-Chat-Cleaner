//! Persistent app-owned browser storage. This module never reads browser credentials.
//!
//! An active-browser marker survives crashes and unconfirmed shutdowns. Such a
//! v2 record can recover only when the recorded process definitively no longer
//! exists. Pending, legacy, malformed, alive, and uncertain records stay blocked.

use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use crate::file_guard::{identity_from_file_metadata, identity_from_path_metadata, FileIdentity};

const OWNER_FILE: &str = ".ghost-chat-cleaner-profile";
const READY_FILE: &str = ".ghost-chat-cleaner-ready";
const ACTIVE_FILE: &str = ".ghost-chat-cleaner-browser-active";
const OWNER_MARKER: &[u8] = b"ghost-chat-cleaner/browser-profile/v1\n";
const READY_MARKER: &[u8] = b"ghost-chat-cleaner/browser-ready/v1\n";
const ACTIVE_MARKER: &[u8] = b"ghost-chat-cleaner/browser-active/v1\n";
const ACTIVE_PID_PREFIX: &str = "ghost-chat-cleaner/browser-active/v2\npid=";
const MAX_ACTIVE_MARKER_BYTES: u64 = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileError {
    UnsupportedProduct,
    MissingDataDirectory,
    UnsafePath,
    InUse,
    UnconfirmedExit,
    InvalidMarker,
    Io,
}

impl ProfileError {
    pub fn message_for(&self, language: crate::i18n::Language) -> &'static str {
        let (korean, english) = match self {
            Self::UnsupportedProduct => (
                "기본 브라우저를 Chrome·Edge·Chromium 중 하나로 설정해야 함",
                "Set Chrome, Edge, or Chromium as your default browser",
            ),
            Self::MissingDataDirectory => (
                "로그인을 저장할 위치를 찾지 못함",
                "Could not find a location to save the sign-in",
            ),
            Self::UnsafePath => (
                "저장된 로그인을 안전하게 사용할 수 없음",
                "The saved sign-in cannot be used safely",
            ),
            Self::InUse => (
                "다른 앱 창에서 로그인 사용 중",
                "Another app window is using the saved sign-in",
            ),
            Self::UnconfirmedExit => (
                "이전 브라우저 종료를 확인하지 못함",
                "Could not confirm that the previous browser has closed",
            ),
            Self::InvalidMarker => (
                "저장된 로그인 상태를 확인하지 못함",
                "Could not verify the saved sign-in state",
            ),
            Self::Io => (
                "저장된 로그인에 접근하지 못함",
                "Could not access the saved sign-in",
            ),
        };
        language.text(korean, english)
    }
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message_for(crate::i18n::Language::Korean))
    }
}

impl std::error::Error for ProfileError {}

#[derive(Debug)]
struct ProfileLock(File);

impl ProfileLock {
    fn acquire(file: File) -> Result<Self, ProfileError> {
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => ProfileError::InUse,
            std::fs::TryLockError::Error(_) => ProfileError::Io,
        })?;
        Ok(Self(file))
    }
}

impl Drop for ProfileLock {
    fn drop(&mut self) {
        // A concurrent spawn may temporarily inherit this open-file description
        // before exec closes it. End this owner's lock explicitly rather than
        // waiting for the last inherited descriptor to close. This also covers
        // validation failures after lock acquisition, without touching markers.
        let _ = self.0.unlock();
    }
}

#[derive(Debug)]
pub struct BrowserProfile {
    path: PathBuf,
    directories: Vec<PathGuard>,
    lock_path: PathBuf,
    _lock: ProfileLock,
}

impl BrowserProfile {
    #[cfg(test)]
    pub(crate) fn open_test(root: &Path, product: &str) -> Result<Self, ProfileError> {
        Self::open_at(root, product, true)?.ok_or(ProfileError::Io)
    }

    pub fn open(product: &str) -> Result<Self, ProfileError> {
        Self::open_at(&application_root()?, product, true)?.ok_or(ProfileError::Io)
    }

    /// Missing storage returns `None` without creating any directories or files.
    pub fn open_existing(product: &str) -> Result<Option<Self>, ProfileError> {
        Self::open_at(&application_root()?, product, false)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Persist before spawning a browser. A failure must prevent the spawn.
    pub fn begin_browser_use(&self) -> Result<(), ProfileError> {
        self.validate()?;
        self.ensure_browser_idle()?;
        create_marker(&self.path.join(ACTIVE_FILE), ACTIVE_MARKER)?;
        self.sync_directory()
    }

    /// Record the newly spawned owned child before any other browser operation.
    /// The pre-spawn marker remains blocking if this atomic update is interrupted.
    pub fn record_browser_pid(&self, pid: u32) -> Result<(), ProfileError> {
        self.validate()?;
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(ProfileError::InvalidMarker);
        }
        let path = self.path.join(ACTIVE_FILE);
        let active = read_active_marker(&path)?.ok_or(ProfileError::InvalidMarker)?;
        if active.record != ActiveRecord::Pending {
            return Err(ProfileError::InvalidMarker);
        }
        let mut replacement = tempfile::Builder::new()
            .prefix(".browser-active-")
            .tempfile_in(&self.path)
            .map_err(|_| ProfileError::Io)?;
        replacement
            .write_all(format!("{ACTIVE_PID_PREFIX}{pid}\n").as_bytes())
            .and_then(|()| replacement.as_file().sync_all())
            .map_err(|_| ProfileError::Io)?;
        self.validate()?;
        validate_open_file(&path, &active.file)?;
        validate_open_file(replacement.path(), replacement.as_file())?;
        let recorded = persist_active_marker(replacement, &path)?;
        validate_open_file(&path, &recorded)?;
        self.sync_directory()
    }

    /// Call only after confirmed owned-child exit, or a failed spawn. Merely
    /// losing the connection, timing out, or dropping an owner is insufficient.
    pub fn end_browser_use(&self) -> Result<(), ProfileError> {
        self.validate()?;
        let path = self.path.join(ACTIVE_FILE);
        if let Some(active) = read_active_marker(&path)? {
            if active.record == ActiveRecord::Unknown {
                return Err(ProfileError::InvalidMarker);
            }
            validate_open_file(&path, &active.file)?;
            fs::remove_file(&path).map_err(|_| ProfileError::Io)?;
            self.sync_directory()?;
        }
        Ok(())
    }

    pub fn is_ready(&self) -> Result<bool, ProfileError> {
        self.validate()?;
        marker_matches(&self.path.join(READY_FILE), READY_MARKER)
    }

    /// Call only after a successful authenticated collector result. The marker
    /// contains a format version only; it is neither credentials nor repair proof.
    pub fn mark_ready(&self) -> Result<(), ProfileError> {
        self.validate()?;
        let path = self.path.join(READY_FILE);
        if !marker_matches(&path, READY_MARKER)? {
            create_marker(&path, READY_MARKER)?;
        }
        Ok(())
    }

    /// Explicit disconnect only. The caller must first stop the owned browser.
    /// Keep the sibling lock file: unlinking it would allow a second lock inode.
    pub fn clear(self) -> Result<(), ProfileError> {
        self.validate()?;
        self.ensure_browser_idle()?;
        fs::remove_dir_all(&self.path).map_err(|_| ProfileError::Io)
    }

    fn open_at(root: &Path, product: &str, create: bool) -> Result<Option<Self>, ProfileError> {
        if !matches!(product, "edge" | "chrome" | "chromium") {
            return Err(ProfileError::UnsupportedProduct);
        }
        check_absolute_path(root)?;
        let profiles = root.join("browser-profiles");
        let locks = root.join("browser-locks");
        let path = profiles.join(product);
        if !ensure_directory(root, create, true)? || !ensure_directory(&profiles, create, true)? {
            return Ok(None);
        }
        // A resume request must not create even the lock hierarchy when absent.
        if !create && metadata_if_present(&path)?.is_none() {
            return Ok(None);
        }
        if !ensure_directory(&locks, create, true)? {
            return Err(ProfileError::UnsafePath);
        }
        let lock_path = locks.join(format!("{product}.lock"));
        let lock = ProfileLock::acquire(open_control_file(&lock_path, create)?)?;
        let existed = metadata_if_present(&path)?.is_some();
        if !ensure_directory(&path, create, true)? {
            return Ok(None);
        }
        if existed {
            if !marker_matches(&path.join(OWNER_FILE), OWNER_MARKER)? {
                return Err(ProfileError::InvalidMarker);
            }
        } else {
            create_marker(&path.join(OWNER_FILE), OWNER_MARKER)?;
        }
        let directories = [root, &profiles, &locks, &path]
            .into_iter()
            .map(PathGuard::capture)
            .collect::<Result<Vec<_>, _>>()?;
        let profile = Self {
            path,
            directories,
            lock_path,
            _lock: lock,
        };
        profile.validate()?;
        profile.recover_browser_exit_with(process_definitively_absent)?;
        profile.ensure_browser_idle()?;
        Ok(Some(profile))
    }

    fn ensure_browser_idle(&self) -> Result<(), ProfileError> {
        if let Some(metadata) = metadata_if_present(&self.path.join(ACTIVE_FILE))? {
            validate_shape(&metadata, false, true)?;
            // Even an incomplete/unknown marker blocks reuse. Do not interpret
            // missing or malformed contents as proof of browser termination.
            return Err(ProfileError::UnconfirmedExit);
        }
        Ok(())
    }

    fn recover_browser_exit_with(
        &self,
        absent: impl FnOnce(u32) -> bool,
    ) -> Result<(), ProfileError> {
        self.validate()?;
        let path = self.path.join(ACTIVE_FILE);
        let Some(active) = read_active_marker(&path)? else {
            return Ok(());
        };
        let ActiveRecord::Pid(pid) = active.record else {
            return Err(ProfileError::UnconfirmedExit);
        };
        if !absent(pid) {
            return Err(ProfileError::UnconfirmedExit);
        }
        // The app lock is held throughout the OS check and marker removal. Verify
        // the same owned paths and marker inode again before changing anything.
        self.validate()?;
        validate_open_file(&path, &active.file)?;
        fs::remove_file(&path).map_err(|_| ProfileError::Io)?;
        self.sync_directory()
    }

    fn sync_directory(&self) -> Result<(), ProfileError> {
        #[cfg(unix)]
        File::open(&self.path)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ProfileError::Io)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), ProfileError> {
        for directory in &self.directories {
            directory.validate()?;
        }
        validate_open_file(&self.lock_path, &self._lock.0)?;
        if !marker_matches(&self.path.join(OWNER_FILE), OWNER_MARKER)? {
            return Err(ProfileError::InvalidMarker);
        }
        Ok(())
    }
}

fn persist_active_marker(
    replacement: tempfile::NamedTempFile,
    path: &Path,
) -> Result<File, ProfileError> {
    #[cfg(windows)]
    {
        // tempfile's MoveFileExW cannot replace the still-open validated marker.
        // std::fs::rename also supports Windows POSIX replacement semantics.
        // Keep clears the temporary attribute; TempPath retains failure cleanup.
        let (file, temporary_path) = replacement.keep().map_err(|_| ProfileError::Io)?;
        let mut temporary_path =
            tempfile::TempPath::try_from_path(temporary_path).map_err(|_| ProfileError::Io)?;
        fs::rename(&temporary_path, path).map_err(|_| ProfileError::Io)?;
        temporary_path.disable_cleanup(true);
        Ok(file)
    }
    #[cfg(not(windows))]
    replacement.persist(path).map_err(|_| ProfileError::Io)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActiveRecord {
    Pending,
    Pid(u32),
    Unknown,
}

struct ActiveMarkerFile {
    file: File,
    record: ActiveRecord,
}

fn read_active_marker(path: &Path) -> Result<Option<ActiveMarkerFile>, ProfileError> {
    if metadata_if_present(path)?.is_none() {
        return Ok(None);
    }
    let mut file = open_control_file(path, false)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_ACTIVE_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProfileError::Io)?;
    validate_open_file(path, &file)?;
    let record = if bytes == ACTIVE_MARKER {
        ActiveRecord::Pending
    } else {
        std::str::from_utf8(&bytes)
            .ok()
            .filter(|_| bytes.len() as u64 <= MAX_ACTIVE_MARKER_BYTES)
            .and_then(|text| text.strip_prefix(ACTIVE_PID_PREFIX))
            .and_then(|text| text.strip_suffix('\n'))
            .and_then(|text| {
                text.parse::<u32>()
                    .ok()
                    .filter(|pid| *pid > 0 && *pid <= i32::MAX as u32 && pid.to_string() == text)
            })
            .map_or(ActiveRecord::Unknown, ActiveRecord::Pid)
    };
    Ok(Some(ActiveMarkerFile { file, record }))
}

#[cfg(unix)]
fn process_definitively_absent(pid: u32) -> bool {
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    // Signal zero only checks existence/permission; it delivers no signal.
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

#[cfg(not(unix))]
fn process_definitively_absent(_pid: u32) -> bool {
    // No equally definitive platform check has been implemented here.
    false
}

// ProfileLock Drop releases the exclusive lock. There is no profile cleanup
// in Drop: an ordinary cleaner exit must preserve the user's browser login.

#[derive(Debug)]
struct PathGuard {
    path: PathBuf,
    identity: FileIdentity,
}

impl PathGuard {
    fn capture(path: &Path) -> Result<Self, ProfileError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| ProfileError::Io)?;
        validate_shape(&metadata, true, true)?;
        let identity =
            identity_from_path_metadata(path, &metadata).map_err(|_| ProfileError::Io)?;
        Ok(Self {
            path: path.to_owned(),
            identity,
        })
    }

    fn validate(&self) -> Result<(), ProfileError> {
        check_absolute_path(&self.path)?;
        let current = Self::capture(&self.path)?;
        if current.identity != self.identity {
            return Err(ProfileError::UnsafePath);
        }
        Ok(())
    }
}

fn application_root() -> Result<PathBuf, ProfileError> {
    platform_root(
        std::env::consts::OS,
        std::env::var_os("HOME").map(PathBuf::from),
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
        std::env::var_os("XDG_DATA_HOME").map(PathBuf::from),
    )
}

fn platform_root(
    platform: &str,
    home: Option<PathBuf>,
    local_app_data: Option<PathBuf>,
    xdg_data_home: Option<PathBuf>,
) -> Result<PathBuf, ProfileError> {
    let absolute = |path: &PathBuf| path.is_absolute();
    let root = match platform {
        "macos" => home
            .filter(absolute)
            .map(|path| path.join("Library/Application Support/Ghost Chat Cleaner")),
        "windows" => local_app_data
            .filter(absolute)
            .map(|path| path.join("Ghost Chat Cleaner")),
        "linux" => xdg_data_home
            .filter(absolute)
            .or_else(|| home.filter(absolute).map(|path| path.join(".local/share")))
            .map(|path| path.join("ghost-chat-cleaner")),
        _ => None,
    };
    root.ok_or(ProfileError::MissingDataDirectory)
}

fn check_absolute_path(path: &Path) -> Result<(), ProfileError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(ProfileError::UnsafePath);
    }
    // Validate each existing ancestor; never resolve a link into another location.
    for ancestor in path.ancestors() {
        if let Some(metadata) = metadata_if_present(ancestor)? {
            validate_shape(&metadata, true, false)?;
        }
    }
    Ok(())
}

fn metadata_if_present(path: &Path) -> Result<Option<Metadata>, ProfileError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ProfileError::Io),
    }
}

fn ensure_directory(path: &Path, create: bool, private: bool) -> Result<bool, ProfileError> {
    if let Some(metadata) = metadata_if_present(path)? {
        validate_shape(&metadata, true, private)?;
        return Ok(true);
    }
    if !create {
        return Ok(false);
    }
    let parent = path.parent().ok_or(ProfileError::UnsafePath)?;
    ensure_directory(parent, true, false)?;
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(ProfileError::Io),
    }
    validate_shape(
        &fs::symlink_metadata(path).map_err(|_| ProfileError::Io)?,
        true,
        private,
    )?;
    Ok(true)
}

fn validate_shape(metadata: &Metadata, directory: bool, private: bool) -> Result<(), ProfileError> {
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(ProfileError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (private && metadata.mode() & 0o077 != 0) || (!directory && metadata.nlink() != 1) {
            return Err(ProfileError::UnsafePath);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ProfileError::UnsafePath);
        }
        let _ = private;
    }
    Ok(())
}

fn control_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn open_control_file(path: &Path, create: bool) -> Result<File, ProfileError> {
    if let Some(metadata) = metadata_if_present(path)? {
        validate_shape(&metadata, false, true)?;
    } else if create {
        match control_options().create_new(true).open(path) {
            Ok(file) => {
                validate_open_file(path, &file)?;
                return Ok(file);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(ProfileError::Io),
        }
    } else {
        return Err(ProfileError::UnsafePath);
    }
    let file = control_options().open(path).map_err(|_| ProfileError::Io)?;
    validate_open_file(path, &file)?;
    Ok(file)
}

fn validate_open_file(path: &Path, file: &File) -> Result<(), ProfileError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ProfileError::Io)?;
    let opened = file.metadata().map_err(|_| ProfileError::Io)?;
    validate_shape(&metadata, false, true)?;
    validate_shape(&opened, false, true)?;
    let path_identity =
        identity_from_path_metadata(path, &metadata).map_err(|_| ProfileError::Io)?;
    let file_identity = identity_from_file_metadata(file, &opened).map_err(|_| ProfileError::Io)?;
    if path_identity != file_identity {
        return Err(ProfileError::UnsafePath);
    }
    Ok(())
}

fn marker_matches(path: &Path, expected: &[u8]) -> Result<bool, ProfileError> {
    let Some(metadata) = metadata_if_present(path)? else {
        return Ok(false);
    };
    validate_shape(&metadata, false, true)?;
    if metadata.len() != expected.len() as u64 {
        return Err(ProfileError::InvalidMarker);
    }
    let mut file = open_control_file(path, false)?;
    let mut content = Vec::new();
    (&mut file)
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut content)
        .map_err(|_| ProfileError::Io)?;
    if content != expected {
        return Err(ProfileError::InvalidMarker);
    }
    validate_open_file(path, &file)?;
    Ok(true)
}

fn create_marker(path: &Path, content: &[u8]) -> Result<(), ProfileError> {
    let mut file = control_options()
        .create_new(true)
        .open(path)
        .map_err(|_| ProfileError::Io)?;
    validate_open_file(path, &file)?;
    file.write_all(content)
        .and_then(|()| file.sync_all())
        .map_err(|_| ProfileError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(temp: &tempfile::TempDir) -> PathBuf {
        temp.path().canonicalize().unwrap().join("app-data")
    }

    #[cfg(unix)]
    #[test]
    fn recorded_browser_reopens_only_after_real_child_exit() {
        use std::process::{Command, Stdio};
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let profile = BrowserProfile::open_at(&root, "edge", true)
            .unwrap()
            .unwrap();
        profile.mark_ready().unwrap();
        profile.begin_browser_use().unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", "read input; exit 0"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let path = profile.path().to_owned();
        fs::write(
            path.join(ACTIVE_FILE),
            format!("ghost-chat-cleaner/browser-active/v2\npid={}\n", child.id()),
        )
        .unwrap();
        drop(profile);
        let while_alive = BrowserProfile::open_at(&root, "edge", false);
        input.write_all(b"finish\n").unwrap();
        child.wait().unwrap();
        assert_eq!(while_alive.unwrap_err(), ProfileError::UnconfirmedExit);
        let reopened = BrowserProfile::open_at(&root, "edge", false)
            .unwrap()
            .unwrap();
        assert!(reopened.is_ready().unwrap());
        assert!(!path.join(ACTIVE_FILE).exists());
        assert_eq!(
            BrowserProfile::open_at(&root, "edge", false).unwrap_err(),
            ProfileError::InUse
        );
        reopened.clear().unwrap();
    }

    #[test]
    fn record_browser_pid_atomically_replaces_pending_private_marker() {
        let temp = tempfile::tempdir().unwrap();
        let profile = BrowserProfile::open_at(&root(&temp), "edge", true)
            .unwrap()
            .unwrap();
        assert_eq!(
            profile.record_browser_pid(std::process::id()),
            Err(ProfileError::InvalidMarker)
        );
        profile.begin_browser_use().unwrap();
        let mut previous = File::open(profile.path().join(ACTIVE_FILE)).unwrap();
        profile.record_browser_pid(std::process::id()).unwrap();
        let mut old_bytes = Vec::new();
        previous.read_to_end(&mut old_bytes).unwrap();
        assert_eq!(
            old_bytes, ACTIVE_MARKER,
            "record replacement must not modify the prior inode"
        );
        assert_eq!(
            fs::read(profile.path().join(ACTIVE_FILE)).unwrap(),
            format!(
                "ghost-chat-cleaner/browser-active/v2\npid={}\n",
                std::process::id()
            )
            .as_bytes()
        );
        assert_eq!(
            profile.record_browser_pid(std::process::id()),
            Err(ProfileError::InvalidMarker)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                fs::metadata(profile.path().join(ACTIVE_FILE))
                    .unwrap()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        profile.end_browser_use().unwrap();
        assert!(!profile.path().join(ACTIVE_FILE).exists());
    }

    #[test]
    fn malformed_or_unrecorded_browser_pid_never_recovers() {
        for bytes in [
            ACTIVE_MARKER.to_vec(),
            Vec::new(),
            b"ghost-chat-cleaner/browser-active/v2\n".to_vec(),
            b"ghost-chat-cleaner/browser-active/v2\npid=0\n".to_vec(),
            b"ghost-chat-cleaner/browser-active/v2\npid=-1\n".to_vec(),
            b"ghost-chat-cleaner/browser-active/v2\npid=01\n".to_vec(),
            b"ghost-chat-cleaner/browser-active/v2\npid=2147483648\n".to_vec(),
            b"ghost-chat-cleaner/browser-active/v2\npid=42\nextra\n".to_vec(),
            b"ghost-chat-cleaner/browser-active/v2\npid=42\npid=43\n".to_vec(),
            vec![b'x'; 1024],
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = root(&temp);
            let profile = BrowserProfile::open_at(&root, "edge", true)
                .unwrap()
                .unwrap();
            profile.begin_browser_use().unwrap();
            let path = profile.path().join(ACTIVE_FILE);
            fs::write(&path, &bytes).unwrap();
            drop(profile);
            assert_eq!(
                BrowserProfile::open_at(&root, "edge", false).unwrap_err(),
                ProfileError::UnconfirmedExit
            );
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn uncertain_exit_does_not_change_a_recorded_marker() {
        let temp = tempfile::tempdir().unwrap();
        let profile = BrowserProfile::open_at(&root(&temp), "edge", true)
            .unwrap()
            .unwrap();
        profile.begin_browser_use().unwrap();
        profile.record_browser_pid(std::process::id()).unwrap();
        let path = profile.path().join(ACTIVE_FILE);
        let before = fs::read(&path).unwrap();
        // False includes alive, reused PID, denied permission, and unsupported OS.
        assert_eq!(
            profile.recover_browser_exit_with(|_| false),
            Err(ProfileError::UnconfirmedExit)
        );
        assert_eq!(fs::read(path).unwrap(), before);
    }

    #[test]
    fn recovery_rejects_a_marker_replaced_during_the_process_check() {
        let temp = tempfile::tempdir().unwrap();
        let profile = BrowserProfile::open_at(&root(&temp), "edge", true)
            .unwrap()
            .unwrap();
        profile.begin_browser_use().unwrap();
        profile.record_browser_pid(std::process::id()).unwrap();
        let path = profile.path().join(ACTIVE_FILE);
        assert_eq!(
            profile.recover_browser_exit_with(|_| {
                fs::rename(&path, profile.path().join("old-active-fixture")).unwrap();
                create_marker(&path, ACTIVE_MARKER).unwrap();
                true
            }),
            Err(ProfileError::UnsafePath)
        );
        assert_eq!(fs::read(path).unwrap(), ACTIVE_MARKER);
    }

    #[test]
    fn active_browser_marker_survives_drop_and_blocks_both_open_modes() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let profile = BrowserProfile::open_at(&root, "edge", true)
            .unwrap()
            .unwrap();
        let path = profile.path().to_owned();
        profile.begin_browser_use().unwrap();
        // The current owner can still save verified authentication while active.
        profile.mark_ready().unwrap();
        assert!(profile.is_ready().unwrap());
        drop(profile);
        for create in [false, true] {
            assert_eq!(
                BrowserProfile::open_at(&root, "edge", create).unwrap_err(),
                ProfileError::UnconfirmedExit
            );
        }
        assert!(path.join(ACTIVE_FILE).is_file());
    }

    #[test]
    fn active_browser_marker_blocks_explicit_clear() {
        let temp = tempfile::tempdir().unwrap();
        let profile = BrowserProfile::open_at(&root(&temp), "edge", true)
            .unwrap()
            .unwrap();
        let path = profile.path().to_owned();
        profile.begin_browser_use().unwrap();
        assert_eq!(profile.clear(), Err(ProfileError::UnconfirmedExit));
        assert!(path.join(ACTIVE_FILE).is_file());
    }

    #[test]
    fn confirmed_browser_end_allows_reuse_and_explicit_clear() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let profile = BrowserProfile::open_at(&root, "edge", true)
            .unwrap()
            .unwrap();
        let path = profile.path().to_owned();
        profile.begin_browser_use().unwrap();
        assert!(path.join(ACTIVE_FILE).is_file());
        profile.end_browser_use().unwrap();
        profile.end_browser_use().unwrap();
        assert!(!path.join(ACTIVE_FILE).exists());
        profile.begin_browser_use().unwrap();
        profile.end_browser_use().unwrap();
        drop(profile);
        let idle = BrowserProfile::open_at(&root, "edge", false)
            .unwrap()
            .unwrap();
        idle.clear().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn repeated_browser_begin_requires_a_confirmed_end() {
        let temp = tempfile::tempdir().unwrap();
        let profile = BrowserProfile::open_at(&root(&temp), "edge", true)
            .unwrap()
            .unwrap();
        profile.begin_browser_use().unwrap();
        assert_eq!(
            profile.begin_browser_use(),
            Err(ProfileError::UnconfirmedExit)
        );
    }

    #[test]
    fn browser_use_methods_keep_validating_ownership() {
        let temp = tempfile::tempdir().unwrap();
        let profile = BrowserProfile::open_at(&root(&temp), "edge", true)
            .unwrap()
            .unwrap();
        profile.begin_browser_use().unwrap();
        fs::write(profile.path().join(OWNER_FILE), "unexpected").unwrap();
        assert_eq!(profile.end_browser_use(), Err(ProfileError::InvalidMarker));
        assert_eq!(profile.mark_ready(), Err(ProfileError::InvalidMarker));
        assert!(profile.path().join(ACTIVE_FILE).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn browser_use_marker_is_private() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let profile = BrowserProfile::open_at(&root(&temp), "edge", true)
            .unwrap()
            .unwrap();
        profile.begin_browser_use().unwrap();
        assert_eq!(
            fs::metadata(profile.path().join(ACTIVE_FILE))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn incomplete_browser_use_marker_still_blocks_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let profile = BrowserProfile::open_at(&root, "edge", true)
            .unwrap()
            .unwrap();
        profile.begin_browser_use().unwrap();
        fs::write(profile.path().join(ACTIVE_FILE), b"").unwrap();
        assert_eq!(profile.end_browser_use(), Err(ProfileError::InvalidMarker));
        drop(profile);
        assert_eq!(
            BrowserProfile::open_at(&root, "edge", false).unwrap_err(),
            ProfileError::UnconfirmedExit
        );
    }

    #[test]
    fn drop_retains_profile_and_ready_state_for_next_launch() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let profile = BrowserProfile::open_at(&root, "edge", true)
            .unwrap()
            .unwrap();
        assert!(!profile.is_ready().unwrap());
        let path = profile.path().to_owned();
        fs::write(path.join("synthetic-session"), "fixture").unwrap();
        profile.mark_ready().unwrap();
        drop(profile);
        assert!(path.join("synthetic-session").is_file());
        let reopened = BrowserProfile::open_at(&root, "edge", false)
            .unwrap()
            .unwrap();
        assert_eq!(reopened.path(), path);
        assert!(reopened.is_ready().unwrap());
    }

    #[test]
    fn absent_saved_session_does_not_create_directories() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        assert!(BrowserProfile::open_at(&root, "chrome", false)
            .unwrap()
            .is_none());
        assert!(!root.exists());
    }

    #[test]
    fn same_product_is_exclusive_and_other_products_are_independent() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let first = BrowserProfile::open_at(&root, "edge", true)
            .unwrap()
            .unwrap();
        assert_eq!(
            BrowserProfile::open_at(&root, "edge", true).unwrap_err(),
            ProfileError::InUse
        );
        let other = BrowserProfile::open_at(&root, "chrome", true)
            .unwrap()
            .unwrap();
        assert_ne!(first.path(), other.path());
        drop(first);
        assert!(BrowserProfile::open_at(&root, "edge", false)
            .unwrap()
            .is_some());
    }

    #[test]
    fn explicit_clear_removes_only_owned_profile_and_allows_fresh_login() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let first = BrowserProfile::open_at(&root, "edge", true)
            .unwrap()
            .unwrap();
        let path = first.path().to_owned();
        let other = BrowserProfile::open_at(&root, "chrome", true)
            .unwrap()
            .unwrap();
        first.mark_ready().unwrap();
        first.clear().unwrap();
        assert!(!path.exists());
        assert!(other.path().exists());
        assert!(BrowserProfile::open_at(&root, "edge", false)
            .unwrap()
            .is_none());
        let fresh = BrowserProfile::open_at(&root, "edge", true)
            .unwrap()
            .unwrap();
        assert!(!fresh.is_ready().unwrap());
    }

    #[test]
    fn unknown_product_cannot_escape_the_app_directory() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        for product in ["", "../edge", "/edge", "Edge", "firefox"] {
            assert_eq!(
                BrowserProfile::open_at(&root, product, true).unwrap_err(),
                ProfileError::UnsupportedProduct
            );
        }
        assert!(!root.exists());
    }

    #[test]
    fn platform_paths_use_per_user_application_storage() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let home = base.join("home");
        let data = base.join("data");
        assert_eq!(
            platform_root("macos", Some(home.clone()), None, None).unwrap(),
            home.join("Library/Application Support/Ghost Chat Cleaner")
        );
        assert_eq!(
            platform_root("windows", Some(home.clone()), Some(data.clone()), None).unwrap(),
            data.join("Ghost Chat Cleaner")
        );
        assert_eq!(
            platform_root("linux", Some(home.clone()), None, Some(data.clone())).unwrap(),
            data.join("ghost-chat-cleaner")
        );
        assert_eq!(
            platform_root(
                "linux",
                Some(home.clone()),
                None,
                Some(PathBuf::from("relative"))
            )
            .unwrap(),
            home.join(".local/share/ghost-chat-cleaner")
        );
        assert_eq!(
            platform_root("windows", Some(home), None, None),
            Err(ProfileError::MissingDataDirectory)
        );
        assert_eq!(
            platform_root("macos", None, None, None),
            Err(ProfileError::MissingDataDirectory)
        );
        assert!(!data.exists());
    }

    #[test]
    fn unverified_login_is_retained_without_becoming_ready() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let profile = BrowserProfile::open_at(&root, "chromium", true)
            .unwrap()
            .unwrap();
        drop(profile);
        let reopened = BrowserProfile::open_at(&root, "chromium", false)
            .unwrap()
            .unwrap();
        assert!(!reopened.is_ready().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn owner_drop_releases_lock_even_while_a_spawn_inherits_the_handle() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let profile = BrowserProfile::open_at(&root, "chromium", true)
            .unwrap()
            .unwrap();
        // dup and fork reference the same flock. Keep a duplicate alive to make
        // the pre-exec child descriptor window deterministic without unsafe fork.
        let inherited = profile._lock.0.try_clone().unwrap();
        assert_eq!(
            BrowserProfile::open_at(&root, "chromium", false).unwrap_err(),
            ProfileError::InUse
        );
        drop(profile);
        let reopened = BrowserProfile::open_at(&root, "chromium", false);
        drop(inherited);
        let reopened = reopened
            .expect("the owning profile has ended its lock lifetime")
            .unwrap();
        assert!(!reopened.is_ready().unwrap());
        assert_eq!(
            BrowserProfile::open_at(&root, "chromium", false).unwrap_err(),
            ProfileError::InUse
        );
    }

    #[cfg(unix)]
    #[test]
    fn owner_drop_keeps_active_browser_blocked_despite_inherited_lock_handle() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let profile = BrowserProfile::open_at(&root, "chromium", true)
            .unwrap()
            .unwrap();
        profile.begin_browser_use().unwrap();
        let path = profile.path().to_owned();
        let inherited = profile._lock.0.try_clone().unwrap();
        drop(profile);
        let blocked = BrowserProfile::open_at(&root, "chromium", false);
        drop(inherited);
        assert_eq!(blocked.unwrap_err(), ProfileError::UnconfirmedExit);
        assert_eq!(fs::read(path.join(ACTIVE_FILE)).unwrap(), ACTIVE_MARKER);
    }

    #[test]
    #[ignore = "subprocess fixture used by profile_lock_excludes_another_process"]
    fn locked_profile_child_fixture() {
        let root = PathBuf::from(std::env::var_os("GHOST_PROFILE_LOCK_FIXTURE").unwrap());
        assert_eq!(
            BrowserProfile::open_at(&root, "edge", true).unwrap_err(),
            ProfileError::InUse
        );
    }

    #[test]
    fn profile_lock_excludes_another_process() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let _profile = BrowserProfile::open_at(&root, "edge", true)
            .unwrap()
            .unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "browser_profile::tests::locked_profile_child_fixture",
                "--ignored",
            ])
            .env("GHOST_PROFILE_LOCK_FIXTURE", &root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "synthetic lock child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn existing_unowned_directory_is_never_adopted_or_deleted() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let profile = BrowserProfile::open_at(&root, "edge", true)
            .unwrap()
            .unwrap();
        let path = profile.path().to_owned();
        drop(profile);
        fs::remove_file(path.join(".ghost-chat-cleaner-profile")).unwrap();
        fs::write(path.join("keep"), "unrelated fixture").unwrap();
        assert_eq!(
            BrowserProfile::open_at(&root, "edge", true).unwrap_err(),
            ProfileError::InvalidMarker
        );
        assert!(path.join("keep").is_file());
    }

    #[test]
    fn modified_ownership_marker_blocks_clear() {
        let temp = tempfile::tempdir().unwrap();
        let profile = BrowserProfile::open_at(&root(&temp), "edge", true)
            .unwrap()
            .unwrap();
        let path = profile.path().to_owned();
        fs::write(path.join(".ghost-chat-cleaner-profile"), "unexpected").unwrap();
        assert_eq!(profile.clear(), Err(ProfileError::InvalidMarker));
        assert!(path.is_dir());
    }

    #[test]
    fn malformed_ready_marker_cannot_resume_a_session() {
        let temp = tempfile::tempdir().unwrap();
        let profile = BrowserProfile::open_at(&root(&temp), "edge", true)
            .unwrap()
            .unwrap();
        profile.mark_ready().unwrap();
        fs::write(
            profile.path().join(".ghost-chat-cleaner-ready"),
            "unexpected",
        )
        .unwrap();
        assert_eq!(profile.is_ready(), Err(ProfileError::InvalidMarker));
    }

    #[cfg(unix)]
    #[test]
    fn profile_lock_and_markers_are_private_and_loose_permissions_are_rejected() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let profile = BrowserProfile::open_at(&root, "edge", true)
            .unwrap()
            .unwrap();
        profile.mark_ready().unwrap();
        for directory in [
            &root,
            &root.join("browser-locks"),
            &root.join("browser-profiles"),
            profile.path(),
        ] {
            assert_eq!(fs::metadata(directory).unwrap().mode() & 0o777, 0o700);
        }
        for file in [
            root.join("browser-locks/edge.lock"),
            profile.path().join(".ghost-chat-cleaner-profile"),
            profile.path().join(".ghost-chat-cleaner-ready"),
        ] {
            assert_eq!(fs::metadata(file).unwrap().mode() & 0o777, 0o600);
        }
        let path = profile.path().to_owned();
        drop(profile);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            BrowserProfile::open_at(&root, "edge", true).unwrap_err(),
            ProfileError::UnsafePath
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_profile_and_lock_are_rejected_without_touching_targets() {
        use std::os::unix::fs::symlink;
        for replace_lock in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = root(&temp);
            let profile = BrowserProfile::open_at(&root, "edge", true)
                .unwrap()
                .unwrap();
            let path = profile.path().to_owned();
            profile.clear().unwrap();
            let external = temp.path().join("external");
            fs::create_dir(&external).unwrap();
            fs::write(external.join("keep"), "fixture").unwrap();
            if replace_lock {
                let lock = root.join("browser-locks/edge.lock");
                fs::remove_file(&lock).unwrap();
                symlink(external.join("keep"), lock).unwrap();
            } else {
                symlink(&external, &path).unwrap();
            }
            assert_eq!(
                BrowserProfile::open_at(&root, "edge", true).unwrap_err(),
                ProfileError::UnsafePath
            );
            assert_eq!(
                fs::read_to_string(external.join("keep")).unwrap(),
                "fixture"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn replacing_a_held_profile_directory_blocks_clear() {
        let temp = tempfile::tempdir().unwrap();
        let profile = BrowserProfile::open_at(&root(&temp), "edge", true)
            .unwrap()
            .unwrap();
        let path = profile.path().to_owned();
        let moved = path.with_extension("moved");
        fs::rename(&path, &moved).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep"), "replacement").unwrap();
        assert_eq!(profile.clear(), Err(ProfileError::UnsafePath));
        assert!(path.join("keep").is_file());
        assert!(moved.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_app_root_is_rejected_without_creation() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().canonicalize().unwrap().join("target");
        fs::create_dir(&target).unwrap();
        let root = root(&temp);
        symlink(&target, &root).unwrap();
        assert_eq!(
            BrowserProfile::open_at(&root, "edge", true).unwrap_err(),
            ProfileError::UnsafePath
        );
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_lock_and_marker_shapes_fail_closed() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        for kind in [
            "lock-directory",
            "lock-permissions",
            "marker-link",
            "marker-hardlink",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = root(&temp);
            let profile = BrowserProfile::open_at(&root, "edge", true)
                .unwrap()
                .unwrap();
            profile.mark_ready().unwrap();
            let marker = profile.path().join(READY_FILE);
            let lock = root.join("browser-locks/edge.lock");
            match kind {
                "lock-directory" => {
                    drop(profile);
                    fs::remove_file(&lock).unwrap();
                    fs::create_dir(&lock).unwrap();
                    assert_eq!(
                        BrowserProfile::open_at(&root, "edge", true).unwrap_err(),
                        ProfileError::UnsafePath
                    );
                }
                "lock-permissions" => {
                    drop(profile);
                    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
                    assert_eq!(
                        BrowserProfile::open_at(&root, "edge", true).unwrap_err(),
                        ProfileError::UnsafePath
                    );
                }
                "marker-link" => {
                    fs::remove_file(&marker).unwrap();
                    symlink(profile.path().join(OWNER_FILE), marker).unwrap();
                    assert_eq!(profile.is_ready(), Err(ProfileError::UnsafePath));
                }
                _ => {
                    fs::hard_link(&marker, profile.path().join("extra-link")).unwrap();
                    assert_eq!(profile.is_ready(), Err(ProfileError::UnsafePath));
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn clear_never_follows_browser_internal_links_outside_the_owned_profile() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let profile = BrowserProfile::open_at(&root, "edge", true)
            .unwrap()
            .unwrap();
        let external = temp.path().join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("keep"), "fixture").unwrap();
        symlink(&external, profile.path().join("browser-link")).unwrap();
        profile.clear().unwrap();
        assert_eq!(
            fs::read_to_string(external.join("keep")).unwrap(),
            "fixture"
        );
    }
}
