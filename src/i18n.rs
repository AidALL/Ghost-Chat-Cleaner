//! UI language and app-owned preferences, separate from browser session storage.

use std::fs::{self, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

const PREFERENCES_FILE: &str = "ui-preferences.json";
const MAX_PREFERENCES_BYTES: u64 = 1024;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum Language {
    #[default]
    #[serde(rename = "ko")]
    Korean,
    #[serde(rename = "en")]
    English,
}

impl Language {
    pub fn text<'a>(self, korean: &'a str, english: &'a str) -> &'a str {
        match self {
            Self::Korean => korean,
            Self::English => english,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Preferences {
    language: Language,
}

/// Missing, inaccessible, unsafe, or malformed preferences use Korean.
/// Reading never creates application storage.
pub fn load_language() -> Language {
    application_root()
        .map(|root| load_language_at(&root))
        .unwrap_or_default()
}

/// Persist only the language choice; callers decide whether persistence is appropriate.
pub fn save_language(language: Language) -> io::Result<()> {
    save_language_at(&application_root()?, language)
}

fn load_language_at(root: &Path) -> Language {
    read_preferences(root)
        .map(|preferences| preferences.language)
        .unwrap_or_default()
}

fn read_preferences(root: &Path) -> io::Result<Preferences> {
    validate_directory_path(root)?;
    let path = root.join(PREFERENCES_FILE);
    validate_file(&fs::symlink_metadata(&path)?)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    validate_file(&file.metadata()?)?;
    let mut bytes = Vec::new();
    file.take(MAX_PREFERENCES_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PREFERENCES_BYTES {
        return Err(invalid_path("preferences exceed the size limit"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn save_language_at(root: &Path, language: Language) -> io::Result<()> {
    validate_directory_path(root)?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        // The browser profile shares this root and requires private storage.
        builder.mode(0o700);
    }
    builder.create(root)?;
    validate_directory_path(root)?;
    let path = root.join(PREFERENCES_FILE);
    validate_existing_target(&path)?;
    let bytes = serde_json::to_vec(&Preferences { language })
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".ui-preferences-")
        .tempfile_in(root)?;
    temporary.write_all(&bytes)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    validate_directory_path(root)?;
    validate_existing_target(&path)?;
    // Replace the directory entry, never truncate or open the existing file for
    // writing. The same-directory tempfile also removes itself on failure.
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn validate_existing_target(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_file(&metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn validate_directory_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(invalid_path(
            "preferences need an absolute application path",
        ));
    }
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.is_dir() && !is_link(&metadata) => {}
            Ok(_) => return Err(invalid_path("preferences directory is unsafe")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn validate_file(metadata: &Metadata) -> io::Result<()> {
    if !metadata.is_file() || is_link(metadata) {
        return Err(invalid_path("preferences must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(invalid_path("preferences must not be hard-linked"));
        }
    }
    Ok(())
}

fn is_link(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    metadata.file_type().is_symlink()
}

fn invalid_path(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn application_root() -> io::Result<PathBuf> {
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
) -> io::Result<PathBuf> {
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
    root.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "application data directory unavailable",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn root(temp: &tempfile::TempDir) -> std::path::PathBuf {
        temp.path()
            .canonicalize()
            .unwrap()
            .join("Ghost Chat Cleaner")
    }

    #[test]
    fn language_selects_borrowed_text_and_defaults_to_korean() {
        assert_eq!(Language::default(), Language::Korean);
        assert_eq!(Language::Korean.text("한국어", "English"), "한국어");
        assert_eq!(Language::English.text("한국어", "English"), "English");
    }

    #[test]
    fn preference_locations_use_platform_application_storage() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let home = base.join("home");
        let data = base.join("data");
        assert_eq!(
            platform_root("macos", Some(home.clone()), None, None).unwrap(),
            home.join("Library/Application Support/Ghost Chat Cleaner")
        );
        assert_eq!(
            platform_root("windows", None, Some(data.clone()), None).unwrap(),
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
        assert!(platform_root("windows", Some(home), None, None).is_err());
        assert!(platform_root("macos", None, None, None).is_err());
        assert!(!data.exists());
    }

    #[test]
    fn missing_preferences_default_without_creating_storage() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        assert_eq!(load_language_at(&root), Language::Korean);
        assert!(!root.exists());
    }

    #[test]
    fn saved_language_round_trips_and_replaces_previous_choice() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        for language in [Language::English, Language::Korean, Language::English] {
            save_language_at(&root, language).unwrap();
            assert_eq!(load_language_at(&root), language);
        }
        let json: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join(PREFERENCES_FILE)).unwrap()).unwrap();
        assert_eq!(json, serde_json::json!({"language": "en"}));
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    }

    #[test]
    fn existing_english_preference_is_loaded() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        fs::create_dir(&root).unwrap();
        fs::write(root.join(PREFERENCES_FILE), r#"{"language":"en"}"#).unwrap();
        assert_eq!(load_language_at(&root), Language::English);
    }

    #[test]
    fn malformed_unknown_and_oversized_preferences_default() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        fs::create_dir(&root).unwrap();
        for bytes in [
            "".to_owned(),
            "invalid JSON".to_owned(),
            r#"{"language":"fr"}"#.to_owned(),
            r#"{}"#.to_owned(),
            r#"{"language":"en","unexpected":true}"#.to_owned(),
            format!(
                r#"{{"language":"en"}}{}"#,
                " ".repeat(MAX_PREFERENCES_BYTES as usize)
            ),
        ] {
            fs::write(root.join(PREFERENCES_FILE), bytes).unwrap();
            assert_eq!(load_language_at(&root), Language::Korean);
        }
    }

    #[test]
    fn saving_preferences_preserves_browser_session_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let session = root.join("browser-profiles/chrome/Cookies");
        fs::create_dir_all(session.parent().unwrap()).unwrap();
        fs::write(&session, "synthetic session fixture").unwrap();
        save_language_at(&root, Language::English).unwrap();
        assert_eq!(
            fs::read_to_string(session).unwrap(),
            "synthetic session fixture"
        );
    }

    #[test]
    fn save_failure_keeps_existing_non_file_target() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let target = root.join(PREFERENCES_FILE);
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("keep"), "fixture").unwrap();
        assert!(save_language_at(&root, Language::English).is_err());
        assert_eq!(fs::read_to_string(target.join("keep")).unwrap(), "fixture");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    }

    #[test]
    fn save_failure_keeps_parent_file() {
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        fs::write(&root, "fixture").unwrap();
        assert!(save_language_at(&root, Language::English).is_err());
        assert_eq!(fs::read_to_string(root).unwrap(), "fixture");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_preferences_are_neither_read_nor_written() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        fs::create_dir(&root).unwrap();
        let external = temp.path().join("credential-fixture");
        let original = r#"{"language":"en"}"#;
        fs::write(&external, original).unwrap();
        let target = root.join(PREFERENCES_FILE);
        symlink(&external, &target).unwrap();
        assert_eq!(load_language_at(&root), Language::Korean);
        assert!(save_language_at(&root, Language::Korean).is_err());
        assert_eq!(fs::read_to_string(external).unwrap(), original);
        assert!(fs::symlink_metadata(target)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_app_directory_is_not_followed() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = root(&temp);
        let external = temp.path().join("outside");
        fs::create_dir(&external).unwrap();
        fs::write(external.join(PREFERENCES_FILE), r#"{"language":"en"}"#).unwrap();
        symlink(&external, &root).unwrap();
        assert_eq!(load_language_at(&root), Language::Korean);
        assert!(save_language_at(&root, Language::Korean).is_err());
        assert_eq!(
            fs::read_to_string(external.join(PREFERENCES_FILE)).unwrap(),
            r#"{"language":"en"}"#
        );
    }
}
