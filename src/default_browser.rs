//! Identify the system's default HTTPS browser without opening it or reading profiles.

use std::fmt;
#[cfg(any(target_os = "macos", test))]
use std::path::Path;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefaultBrowserError {
    DetectionFailed,
    UnsupportedDefaultBrowser,
    UnsupportedInstallation,
    DetectionTimedOut,
    ResponseLimit,
}

impl fmt::Display for DefaultBrowserError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DetectionFailed => "기본 브라우저를 확인하지 못함",
            Self::UnsupportedDefaultBrowser => {
                "기본 브라우저를 Chrome·Edge·Chromium 중 하나로 설정해야 함"
            }
            Self::UnsupportedInstallation => {
                "Chrome·Edge·Chromium을 설치한 뒤 기본 브라우저로 설정해야 함"
            }
            Self::DetectionTimedOut => "기본 브라우저 확인이 오래 걸림. 다시 시도해야 함",
            Self::ResponseLimit => "기본 브라우저 정보를 확인하지 못함",
        })
    }
}

impl std::error::Error for DefaultBrowserError {}

/// Resolves only the default HTTPS handler. It never opens a browser, reads a
/// browser profile, changes the default, or falls back to a different browser.
pub fn resolve_default_browser() -> Result<PathBuf, DefaultBrowserError> {
    let path = platform_default_browser()?;
    if !path.is_absolute() || !path.is_file() {
        return Err(DefaultBrowserError::UnsupportedInstallation);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path
            .metadata()
            .map_err(|_| DefaultBrowserError::UnsupportedInstallation)?
            .permissions()
            .mode()
            & 0o111
            == 0
        {
            return Err(DefaultBrowserError::UnsupportedInstallation);
        }
    }
    Ok(path)
}

#[cfg(any(target_os = "macos", test))]
fn macos_selection(bundle_id: &str, executable: &Path) -> Result<PathBuf, DefaultBrowserError> {
    let expected_name = match bundle_id {
        "com.microsoft.edgemac" => "Microsoft Edge",
        "com.google.Chrome" => "Google Chrome",
        "org.chromium.Chromium" => "Chromium",
        _ => return Err(DefaultBrowserError::UnsupportedDefaultBrowser),
    };
    if !executable.is_absolute()
        || executable.file_name().and_then(|name| name.to_str()) != Some(expected_name)
    {
        return Err(DefaultBrowserError::UnsupportedInstallation);
    }
    Ok(executable.to_path_buf())
}

#[cfg(target_os = "macos")]
fn platform_default_browser() -> Result<PathBuf, DefaultBrowserError> {
    use objc2::rc::autoreleasepool;
    use objc2_app_kit::NSWorkspace;
    use objc2_foundation::{NSBundle, NSString, NSURL};

    autoreleasepool(|_| {
        // A neutral HTTPS URL queries the scheme handler without targeting an
        // installed site's associated application. This API does not open it.
        let url = NSURL::URLWithString(&NSString::from_str("https://example.invalid/"))
            .ok_or(DefaultBrowserError::DetectionFailed)?;
        let application = NSWorkspace::sharedWorkspace()
            .URLForApplicationToOpenURL(&url)
            .ok_or(DefaultBrowserError::DetectionFailed)?;
        let bundle =
            NSBundle::bundleWithURL(&application).ok_or(DefaultBrowserError::DetectionFailed)?;
        let identity = bundle
            .bundleIdentifier()
            .ok_or(DefaultBrowserError::DetectionFailed)?;
        let executable = bundle
            .executablePath()
            .ok_or(DefaultBrowserError::UnsupportedInstallation)?;
        macos_selection(&identity.to_string(), Path::new(&executable.to_string()))
    })
}

#[cfg(any(target_os = "linux", test))]
fn linux_selection(desktop_id: &str) -> Result<&'static [&'static str], DefaultBrowserError> {
    match desktop_id {
        "google-chrome.desktop" => Ok(&[
            "/opt/google/chrome/chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/google-chrome",
        ]),
        "microsoft-edge.desktop" => Ok(&[
            "/opt/microsoft/msedge/msedge",
            "/usr/bin/microsoft-edge-stable",
            "/usr/bin/microsoft-edge",
        ]),
        "chromium.desktop" | "chromium-browser.desktop" => Ok(&[
            "/usr/lib/chromium/chromium",
            "/usr/lib64/chromium-browser/chromium-browser",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
        ]),
        _ => Err(DefaultBrowserError::UnsupportedDefaultBrowser),
    }
}

#[cfg(any(target_os = "windows", test))]
fn windows_selection(executable_name: &str) -> Result<(), DefaultBrowserError> {
    if ["chrome.exe", "msedge.exe", "chromium.exe"]
        .iter()
        .any(|name| executable_name.eq_ignore_ascii_case(name))
    {
        Ok(())
    } else {
        Err(DefaultBrowserError::UnsupportedDefaultBrowser)
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_desktop_id(output: &[u8]) -> Result<&str, DefaultBrowserError> {
    let identity = std::str::from_utf8(output)
        .map_err(|_| DefaultBrowserError::DetectionFailed)?
        .trim_end_matches(['\r', '\n']);
    if identity.is_empty()
        || identity.len() > 256
        || !identity.ends_with(".desktop")
        || !identity
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(DefaultBrowserError::DetectionFailed);
    }
    Ok(identity)
}

#[cfg(target_os = "windows")]
fn platform_default_browser() -> Result<PathBuf, DefaultBrowserError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::UI::Shell::{
        AssocQueryStringW, ASSOCF_IS_PROTOCOL, ASSOCF_NOFIXUPS, ASSOCF_NOTRUNCATE,
        ASSOCSTR_EXECUTABLE,
    };

    const MAX_PATH_UNITS: u32 = 32768;
    const E_POINTER: i32 = 0x80004003_u32 as i32;
    let scheme: Vec<u16> = "https\0".encode_utf16().collect();
    let verb: Vec<u16> = "open\0".encode_utf16().collect();
    let flags = ASSOCF_IS_PROTOCOL | ASSOCF_NOTRUNCATE | ASSOCF_NOFIXUPS;
    let mut size = 0;
    // Query only the executable association. Never parse an association command
    // line or request fixups to the user's association settings.
    let status = unsafe {
        AssocQueryStringW(
            flags,
            ASSOCSTR_EXECUTABLE,
            scheme.as_ptr(),
            verb.as_ptr(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if status != 1 || size == 0 || size > MAX_PATH_UNITS {
        return Err(DefaultBrowserError::DetectionFailed);
    }
    for _ in 0..2 {
        let mut buffer = vec![0_u16; size as usize];
        let status = unsafe {
            AssocQueryStringW(
                flags,
                ASSOCSTR_EXECUTABLE,
                scheme.as_ptr(),
                verb.as_ptr(),
                buffer.as_mut_ptr(),
                &mut size,
            )
        };
        if status == E_POINTER && size > buffer.len() as u32 && size <= MAX_PATH_UNITS {
            continue;
        }
        if status != 0 || size == 0 || size as usize > buffer.len() {
            return Err(DefaultBrowserError::DetectionFailed);
        }
        let end = buffer[..size as usize]
            .iter()
            .position(|unit| *unit == 0)
            .ok_or(DefaultBrowserError::DetectionFailed)?;
        let path = PathBuf::from(OsString::from_wide(&buffer[..end]));
        let local_drive = matches!(path.components().next(), Some(std::path::Component::Prefix(prefix)) if matches!(prefix.kind(), std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)));
        if !path.is_absolute() || !local_drive {
            return Err(DefaultBrowserError::UnsupportedInstallation);
        }
        windows_selection(
            path.file_name()
                .and_then(|name| name.to_str())
                .ok_or(DefaultBrowserError::UnsupportedInstallation)?,
        )?;
        return Ok(path);
    }
    Err(DefaultBrowserError::DetectionFailed)
}

#[cfg(target_os = "linux")]
fn platform_default_browser() -> Result<PathBuf, DefaultBrowserError> {
    let output = bounded_query(
        "/usr/bin/xdg-settings",
        &["get", "default-url-scheme-handler", "https"],
        std::time::Duration::from_secs(2),
    )?;
    let candidates = linux_selection(parse_desktop_id(&output)?)?;
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| native_linux_executable(path))
        .ok_or(DefaultBrowserError::UnsupportedInstallation)
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn platform_default_browser() -> Result<PathBuf, DefaultBrowserError> {
    Err(DefaultBrowserError::UnsupportedDefaultBrowser)
}

#[cfg(any(target_os = "linux", all(unix, test)))]
fn bounded_query(
    program: &str,
    arguments: &[&str],
    timeout: std::time::Duration,
) -> Result<Vec<u8>, DefaultBrowserError> {
    use std::io::{ErrorKind, Read};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let (mut receiver, sender) =
        UnixStream::pair().map_err(|_| DefaultBrowserError::DetectionFailed)?;
    receiver
        .set_nonblocking(true)
        .map_err(|_| DefaultBrowserError::DetectionFailed)?;
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(sender)))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| DefaultBrowserError::DetectionFailed)?;
    let deadline = Instant::now() + timeout;
    let result = (|| {
        let mut output = Vec::new();
        let mut complete = false;
        loop {
            let mut buffer = [0_u8; 512];
            match receiver.read(&mut buffer) {
                Ok(0) => complete = true,
                Ok(count) => {
                    if output.len() + count > 4096 {
                        return Err(DefaultBrowserError::ResponseLimit);
                    }
                    output.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(_) => return Err(DefaultBrowserError::DetectionFailed),
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|_| DefaultBrowserError::DetectionFailed)?
            {
                if !status.success() {
                    return Err(DefaultBrowserError::DetectionFailed);
                }
                if complete {
                    return Ok(output);
                }
            }
            if Instant::now() >= deadline {
                return Err(DefaultBrowserError::DetectionTimedOut);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    // Nonblocking capture never waits on a descendant that inherited stdout.
    // Only this owned query process is terminated, never an existing browser.
    if result.is_err() {
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}

#[cfg(any(target_os = "linux", test))]
fn native_linux_executable(path: &std::path::Path) -> bool {
    use std::io::Read;

    // Reject shell, Snap, and Flatpak launchers: their child/profile ownership
    // does not match the directly owned native browser transport.
    let mut header = [0_u8; 4];
    path.is_file()
        && std::fs::File::open(path)
            .and_then(|mut file| file.read_exact(&mut header))
            .is_ok()
        && header == *b"\x7fELF"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_wrappers_are_not_treated_as_owned_native_browsers() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("chromium");
        std::fs::write(&executable, b"\x7fELFsynthetic").unwrap();
        assert!(native_linux_executable(&executable));
        std::fs::write(&executable, b"#!/bin/sh\nexec snap run chromium\n").unwrap();
        assert!(!native_linux_executable(&executable));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_query_collects_only_stdout() {
        assert_eq!(
            bounded_query(
                "/usr/bin/printf",
                &["microsoft-edge.desktop\\n"],
                std::time::Duration::from_secs(1)
            ),
            Ok(b"microsoft-edge.desktop\n".to_vec())
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_query_limits_output_and_time() {
        let large = "x".repeat(8192);
        assert_eq!(
            bounded_query(
                "/usr/bin/printf",
                &[&large],
                std::time::Duration::from_secs(1)
            ),
            Err(DefaultBrowserError::ResponseLimit)
        );
        let started = std::time::Instant::now();
        assert_eq!(
            bounded_query("/bin/sleep", &["5"], std::time::Duration::from_millis(30)),
            Err(DefaultBrowserError::DetectionTimedOut)
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn edge_default_selects_its_resolved_bundle() {
        let path = std::env::temp_dir().join("Microsoft Edge.app/Contents/MacOS/Microsoft Edge");
        assert_eq!(macos_selection("com.microsoft.edgemac", &path), Ok(path));
    }

    #[test]
    fn unsupported_default_never_uses_an_installed_chrome() {
        let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
        for id in [
            "com.apple.Safari",
            "org.mozilla.firefox",
            "com.example.browserchooser",
        ] {
            assert_eq!(
                macos_selection(id, chrome),
                Err(DefaultBrowserError::UnsupportedDefaultBrowser)
            );
        }
        assert_eq!(
            linux_selection("firefox.desktop"),
            Err(DefaultBrowserError::UnsupportedDefaultBrowser)
        );
        assert_eq!(
            windows_selection("firefox.exe"),
            Err(DefaultBrowserError::UnsupportedDefaultBrowser)
        );
    }

    #[test]
    fn inconsistent_macos_bundle_executable_is_rejected() {
        let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
        assert_eq!(
            macos_selection("com.microsoft.edgemac", chrome),
            Err(DefaultBrowserError::UnsupportedInstallation)
        );
    }

    #[test]
    fn linux_default_limits_candidates_to_the_selected_product() {
        let edge = linux_selection("microsoft-edge.desktop").unwrap();
        assert!(edge.iter().any(|candidate| candidate.ends_with("msedge")));
        assert!(edge
            .iter()
            .all(|candidate| !candidate.contains("chrome") && !candidate.contains("chromium")));
        assert_eq!(
            linux_selection("com.microsoft.Edge.desktop"),
            Err(DefaultBrowserError::UnsupportedDefaultBrowser)
        );
    }

    #[test]
    fn desktop_query_rejects_commands_and_multiple_results() {
        assert_eq!(
            parse_desktop_id(b"microsoft-edge.desktop\n"),
            Ok("microsoft-edge.desktop")
        );
        for output in [
            b"google-chrome.desktop\nfirefox.desktop".as_slice(),
            b"/tmp/google-chrome.desktop",
            b"google-chrome.desktop --incognito",
            b"",
            b"google-chrome.desktop\0",
        ] {
            assert_eq!(
                parse_desktop_id(output),
                Err(DefaultBrowserError::DetectionFailed)
            );
        }
    }

    #[test]
    fn windows_identity_is_an_executable_name_not_a_command_line() {
        assert_eq!(windows_selection("MSEDGE.EXE"), Ok(()));
        assert_eq!(windows_selection("chrome.exe"), Ok(()));
        assert_eq!(
            windows_selection("chrome.exe --user-data-dir=existing"),
            Err(DefaultBrowserError::UnsupportedDefaultBrowser)
        );
    }
}
