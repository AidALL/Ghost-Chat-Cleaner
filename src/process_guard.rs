use std::path::Path;

use sysinfo::{get_current_pid, ProcessesToUpdate, System, IS_SUPPORTED_SYSTEM};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessPresence {
    Stopped,
    Running,
    Unknown,
}

pub trait ProcessProbe {
    fn chatgpt_presence(&self) -> ProcessPresence;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SysinfoProcessProbe;

impl ProcessProbe for SysinfoProcessProbe {
    fn chatgpt_presence(&self) -> ProcessPresence {
        let mut system = System::new_all();
        let refreshed = system.refresh_processes(ProcessesToUpdate::All, true);
        let self_visible = get_current_pid()
            .ok()
            .and_then(|pid| system.process(pid))
            .is_some();

        classify_snapshot(
            IS_SUPPORTED_SYSTEM,
            refreshed,
            self_visible,
            system
                .processes()
                .values()
                .map(|process| (process.name().to_string_lossy(), process.exe())),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoppedProcessGuard(());

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProcessGuardError {
    #[error("ChatGPT is running")]
    Running,
    #[error("ChatGPT process state could not be determined")]
    Unknown,
}

pub fn ensure_chatgpt_stopped(
    probe: &impl ProcessProbe,
) -> Result<StoppedProcessGuard, ProcessGuardError> {
    match probe.chatgpt_presence() {
        ProcessPresence::Stopped => Ok(StoppedProcessGuard(())),
        ProcessPresence::Running => Err(ProcessGuardError::Running),
        ProcessPresence::Unknown => Err(ProcessGuardError::Unknown),
    }
}

fn process_mentions_chatgpt(name: &str, executable: Option<&Path>) -> bool {
    if is_desktop_executable_name(name) {
        return true;
    }
    let Some(executable) = executable else {
        return false;
    };
    // Check executable roles, not arbitrary user directories or bundled tools.
    // Both separators are accepted so Windows paths retain their meaning in tests.
    let normalized = executable
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let components = normalized.split('/').collect::<Vec<_>>();
    if components
        .last()
        .is_some_and(|name| is_desktop_executable_name(name))
    {
        return true;
    }
    let Some(bundle) = components
        .windows(2)
        .position(|parts| parts == ["chatgpt.app", "contents"])
    else {
        return false;
    };
    let role = &components[bundle + 2..];
    match role {
        ["macos", executable] => !executable.is_empty(),
        ["frameworks", helper @ ..] => {
            matches!(helper, [.., bundle, "contents", "macos", executable]
                if bundle.ends_with(".app") && !executable.is_empty())
        }
        // Resources includes CUA node runtimes and Codex, which can outlive the app.
        _ => false,
    }
}

fn is_desktop_executable_name(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    let stem = normalized.strip_suffix(".exe").unwrap_or(&normalized);
    matches!(stem, "chatgpt" | "chatgpt helper" | "chatgpthelper")
        || (stem.starts_with("chatgpt helper (") && stem.ends_with(')'))
}

fn classify_snapshot<N, P, I>(
    supported: bool,
    refreshed: usize,
    self_visible: bool,
    processes: I,
) -> ProcessPresence
where
    N: AsRef<str>,
    P: AsRef<Path>,
    I: IntoIterator<Item = (N, Option<P>)>,
{
    if processes.into_iter().any(|(name, executable)| {
        process_mentions_chatgpt(name.as_ref(), executable.as_ref().map(|path| path.as_ref()))
    }) {
        ProcessPresence::Running
    } else if !supported || refreshed == 0 || !self_visible {
        ProcessPresence::Unknown
    } else {
        ProcessPresence::Stopped
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn production_matcher_detects_names_and_helper_executables_case_insensitively() {
        assert!(process_mentions_chatgpt("ChatGPT", None));
        assert!(process_mentions_chatgpt(
            "helper",
            Some(Path::new("/Applications/CHATGPT.app/Contents/MacOS/helper")),
        ));
        assert!(!process_mentions_chatgpt(
            "unrelated-helper",
            Some(Path::new("/Applications/Other.app/Contents/MacOS/helper")),
        ));
    }

    #[test]
    fn browser_extensions_and_bundled_coding_runtimes_do_not_count_as_the_desktop_app() {
        for (name, executable) in [
            (
                "ChatGPT for Chrome",
                "/Users/fixture/.codex/plugins/chrome/ChatGPT for Chrome",
            ),
            (
                "node",
                "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node",
            ),
            (
                "node_repl",
                "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node_repl",
            ),
            (
                "codex",
                "/Applications/ChatGPT.app/Contents/Resources/codex",
            ),
            (
                "browser",
                "/Users/chatgpt/Applications/Browser.app/Contents/MacOS/browser",
            ),
            (
                "unrelated",
                "/Applications/ChatGPT Notes.app/Contents/MacOS/unrelated",
            ),
            ("chatgpt-exporter", "/usr/local/bin/chatgpt-exporter"),
            ("node.exe", r"C:\Users\chatgpt\tools\node.exe"),
            ("browser.exe", r"C:\Program Files\ChatGPT Tools\browser.exe"),
        ] {
            assert!(
                !process_mentions_chatgpt(name, Some(Path::new(executable))),
                "{name}: {executable}"
            );
        }
    }

    #[test]
    fn desktop_main_and_native_helpers_remain_protected_after_bundle_rename() {
        for (name, executable) in [
            ("ChatGPT", "/Applications/Renamed.app/Contents/MacOS/ChatGPT"),
            ("helper", "/Applications/ChatGPT.app/Contents/MacOS/helper"),
            ("helper", "/Applications/ChatGPT.app/Contents/Frameworks/Native Helper.app/Contents/MacOS/helper"),
            ("ChatGPT Helper (Renderer)", "/Applications/Renamed.app/Contents/Frameworks/ChatGPT Helper (Renderer).app/Contents/MacOS/ChatGPT Helper (Renderer)"),
            ("ChatGPT.exe", r"C:\Program Files\WindowsApps\OpenAI.ChatGPT_fixture\app\ChatGPT.exe"),
            ("helper", r"C:\Program Files\ChatGPT\ChatGPT Helper.exe"),
            ("ChatGPT Helper (GPU).exe", r"C:\Program Files\Renamed\ChatGPT Helper (GPU).exe"),
        ] {
            assert!(process_mentions_chatgpt(name, Some(Path::new(executable))), "{name}: {executable}");
        }
    }

    #[test]
    fn extension_only_snapshot_is_stopped_only_when_the_snapshot_is_trustworthy() {
        let processes = [("ChatGPT for Chrome", None::<&Path>)];
        assert_eq!(
            classify_snapshot(true, 1, true, processes),
            ProcessPresence::Stopped
        );
        assert_eq!(
            classify_snapshot(true, 1, false, processes),
            ProcessPresence::Unknown
        );
    }

    #[test]
    fn snapshot_is_unknown_when_sysinfo_is_unsupported_or_untrustworthy() {
        let no_processes = std::iter::empty::<(&str, Option<&Path>)>();
        assert_eq!(
            classify_snapshot(false, 1, true, no_processes),
            ProcessPresence::Unknown
        );
        assert_eq!(
            classify_snapshot(true, 0, true, std::iter::empty::<(&str, Option<&Path>)>()),
            ProcessPresence::Unknown
        );
        assert_eq!(
            classify_snapshot(true, 1, false, std::iter::empty::<(&str, Option<&Path>)>()),
            ProcessPresence::Unknown
        );
    }

    #[test]
    fn snapshot_is_stopped_only_after_a_supported_self_visible_refresh() {
        assert_eq!(
            classify_snapshot(true, 1, true, [("unrelated", None::<&Path>)]),
            ProcessPresence::Stopped
        );
    }

    #[test]
    fn observed_chatgpt_process_is_running_even_in_an_incomplete_snapshot() {
        assert_eq!(
            classify_snapshot(false, 0, false, [("ChatGPT Helper", None::<&Path>)]),
            ProcessPresence::Running
        );
    }
}
