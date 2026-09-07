//! An owned browser with a persistent app-only profile and loopback-only CDP.
//!
//! Authentication stays in the browser. Callers must supply only the bundled collector
//! expression, returning sanitized metadata, never cookies, tokens, storage, or headers.
//! This transport never logs CDP payloads or includes them in errors. The browser itself
//! stores login state in its own managed profile. Normal shutdown retains this profile;
//! only explicit disconnection removes it after the owned browser has stopped.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::browser_profile::{BrowserProfile, ProfileError};
use serde_json::{json, Value};
#[cfg(test)]
use tempfile::TempDir;
use tungstenite::client::client_with_config;
use tungstenite::handshake::HandshakeError;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Message, WebSocket};

const LAUNCH_TIMEOUT: Duration = Duration::from_secs(15);
const LOGIN_EXIT_TIMEOUT: Duration = Duration::from_secs(30);
const EVALUATION_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_ACTIVE_PORT_BYTES: usize = 1024;
const MAX_EXPRESSION_BYTES: usize = 512 * 1024;
const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_COMMAND_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESPONSE_MESSAGES: usize = 256;
const IO_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Errors deliberately omit browser responses, expressions, profile paths, and credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserError {
    LaunchFailed,
    StartupTimeout,
    InvalidEndpoint,
    ConnectionFailed,
    TimedOut,
    ResponseLimit,
    InvalidResponse,
    CommandFailed,
    NoChatGptTarget,
    AmbiguousTarget,
    TargetChanged,
    EvaluationFailed,
    PageNotReady,
    SyntaxError,
    ReferenceError,
    TypeError,
    ExpressionTooLarge,
    Closed,
    LoginBrowserStillOpen,
    LoginInterrupted,
    LoginRequired,
    AuthorizationDenied,
    AccountChanged,
    SessionUserMismatch,
    AccountMatchMismatch,
    AccountMatchNone,
    AccountMatchMultiple,
    OrderedPersonalAccountIdMissing,
    OrderedPersonalAccountIdMissingBound,
    OrderedPersonalAccountIdMissingUnbound,
    AccountUserMismatch,
    FinalIdentityChanged,
    UnsupportedAccount,
    ResponseSchemaChanged,
    RateLimited,
    WebUnavailable,
    InvalidCollectorRequest,
    Profile(ProfileError),
    DefaultBrowser(crate::default_browser::DefaultBrowserError),
}

impl fmt::Display for BrowserError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LaunchFailed => "브라우저를 열지 못함",
            Self::StartupTimeout => "브라우저 연결이 오래 걸림. 다시 시도해야 함",
            Self::InvalidEndpoint => "브라우저에 연결하지 못함",
            Self::ConnectionFailed => "브라우저 연결에 실패함",
            Self::TimedOut => "웹 확인 시간이 초과됨. 다시 시도해야 함",
            Self::ResponseLimit => "웹 응답을 모두 확인하지 못함",
            Self::InvalidResponse => "웹 응답을 확인하지 못함",
            Self::CommandFailed => "브라우저에서 요청을 처리하지 못함",
            Self::NoChatGptTarget => "앱이 연 브라우저에서 ChatGPT에 로그인해야 함",
            Self::AmbiguousTarget => "앱이 연 브라우저에 ChatGPT 탭을 하나만 남겨야 함",
            Self::TargetChanged => "대조 중 ChatGPT 탭이 바뀌거나 닫힘",
            Self::EvaluationFailed => "현재 ChatGPT 페이지에서 웹 대조를 실행하지 못함",
            Self::PageNotReady => "ChatGPT 페이지가 아직 준비되지 않음",
            Self::SyntaxError => "웹 확인 코드에 문법 오류가 있음",
            Self::ReferenceError => "웹 확인에 필요한 항목을 찾지 못함",
            Self::TypeError => "웹 확인 중 자료 처리 오류가 발생함",
            Self::ExpressionTooLarge => "웹 대조 요청량이 너무 많음",
            Self::Closed => "브라우저 연결이 끊김",
            Self::LoginBrowserStillOpen => "로그인한 브라우저를 먼저 종료해야 함",
            Self::LoginInterrupted => "로그인 중 브라우저가 예기치 않게 종료됨",
            Self::DefaultBrowser(error) => return error.fmt(formatter),
            Self::Profile(error) => return error.fmt(formatter),
            Self::LoginRequired => "로그인 필요",
            Self::AuthorizationDenied => "ChatGPT에서 연결 확인을 거부함",
            Self::AccountChanged => "로그인 계정을 확인하지 못함",
            Self::SessionUserMismatch => "로그인 세션과 인증 사용자 정보가 일치하지 않음",
            Self::AccountMatchMismatch => "로그인 계정과 일치하는 계정을 확정하지 못함",
            Self::AccountMatchNone => "로그인 계정에 맞는 계정 항목이 없음",
            Self::AccountMatchMultiple => "로그인 계정에 맞는 계정 항목이 여러 개임",
            Self::OrderedPersonalAccountIdMissing => "개인 계정 항목에 계정 ID가 없음",
            Self::OrderedPersonalAccountIdMissingBound => "개인 계정 ID 없음 · 로그인 계정 일치",
            Self::OrderedPersonalAccountIdMissingUnbound => {
                "개인 계정 ID 없음 · 로그인 계정 미확인"
            }
            Self::AccountUserMismatch => "계정과 로그인 사용자 연결이 일치하지 않음",
            Self::FinalIdentityChanged => "확인 중 로그인 계정이 바뀜",
            Self::UnsupportedAccount => "현재 계정 유형은 지원하지 않음",
            Self::ResponseSchemaChanged => "ChatGPT 응답 형식이 예상과 다름",
            Self::RateLimited => "요청이 많아 잠시 후 다시 확인 필요",
            Self::WebUnavailable => "ChatGPT 응답을 받지 못함",
            Self::InvalidCollectorRequest => "웹 확인 요청을 처리할 수 없음",
        })
    }
}

impl std::error::Error for BrowserError {}

#[derive(Clone, Debug, PartialEq)]
struct BrowserEndpoint {
    port: u16,
    path: String,
}

fn parse_active_port(text: &str) -> Result<BrowserEndpoint, BrowserError> {
    if text.len() > MAX_ACTIVE_PORT_BYTES {
        return Err(BrowserError::InvalidEndpoint);
    }
    let mut lines = text.lines();
    let port = lines
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or(BrowserError::InvalidEndpoint)?;
    let path = lines.next().ok_or(BrowserError::InvalidEndpoint)?;
    let id = path
        .strip_prefix("/devtools/browser/")
        .ok_or(BrowserError::InvalidEndpoint)?;
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || lines.next().is_some()
    {
        return Err(BrowserError::InvalidEndpoint);
    }
    Ok(BrowserEndpoint {
        port,
        path: path.to_owned(),
    })
}

fn chatgpt_url_is_allowed(url: &str) -> bool {
    if url.bytes().any(|byte| byte.is_ascii_control()) {
        return false;
    }
    url.strip_prefix("https://chatgpt.com")
        .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with(['/', '?', '#']))
}

struct DeadlineStream {
    socket: TcpStream,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
    remaining_read_bytes: usize,
}

fn time_left(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
}

impl DeadlineStream {
    fn check_cancelled(&self) -> io::Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(io::Error::from(io::ErrorKind::ConnectionAborted))
        } else {
            Ok(())
        }
    }

    fn check_ready(&self) -> io::Result<Duration> {
        self.check_cancelled()?;
        time_left(self.deadline)
    }

    fn wait_for_io(&self) -> io::Result<()> {
        thread::sleep(self.check_ready()?.min(IO_POLL_INTERVAL));
        Ok(())
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining_read_bytes == 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let limit = buffer.len().min(self.remaining_read_bytes);
        loop {
            self.check_ready()?;
            match self.socket.read(&mut buffer[..limit]) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.wait_for_io()?,
                result => {
                    let count = result?;
                    self.remaining_read_bytes -= count;
                    return Ok(count);
                }
            }
        }
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        loop {
            self.check_ready()?;
            match self.socket.write(buffer) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.wait_for_io()?,
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check_ready()?;
        self.socket.flush()
    }
}

fn socket_error(error: tungstenite::Error) -> BrowserError {
    match error {
        tungstenite::Error::Io(error) => match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => BrowserError::TimedOut,
            io::ErrorKind::InvalidData => BrowserError::ResponseLimit,
            _ => BrowserError::ConnectionFailed,
        },
        tungstenite::Error::Capacity(_) => BrowserError::ResponseLimit,
        _ => BrowserError::ConnectionFailed,
    }
}

struct CdpConnection {
    socket: WebSocket<DeadlineStream>,
    endpoint: BrowserEndpoint,
    next_id: u64,
    healthy: bool,
}

impl CdpConnection {
    #[cfg(test)]
    fn cancellation_handle(
        &self,
        browser_owner: Arc<Mutex<Option<OwnedBrowser>>>,
    ) -> Result<BrowserCancellation, BrowserError> {
        self.socket
            .get_ref()
            .socket
            .try_clone()
            .map(|socket| BrowserCancellation {
                socket: Arc::new(Mutex::new(Some(socket))),
                cancelled: Arc::clone(&self.socket.get_ref().cancelled),
                browser_owner,
            })
            .map_err(|_| BrowserError::ConnectionFailed)
    }

    fn connect(
        endpoint: &BrowserEndpoint,
        deadline: Instant,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self, BrowserError> {
        if cancelled.load(Ordering::Acquire) {
            return Err(BrowserError::ConnectionFailed);
        }
        // The address is constructed here, never taken from browser JSON or a URL.
        let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, endpoint.port));
        let timeout = time_left(deadline).map_err(|_| BrowserError::TimedOut)?;
        let socket = TcpStream::connect_timeout(&address, timeout)
            .map_err(|_| BrowserError::ConnectionFailed)?;
        socket
            .set_nonblocking(true)
            .map_err(|_| BrowserError::ConnectionFailed)?;
        let stream = DeadlineStream {
            socket,
            cancelled,
            deadline,
            remaining_read_bytes: 64 * 1024,
        };
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE_BYTES))
            .max_frame_size(Some(MAX_MESSAGE_BYTES))
            .write_buffer_size(0)
            .max_write_buffer_size(MAX_EXPRESSION_BYTES * 4);
        let url = format!("ws://127.0.0.1:{}{}", endpoint.port, endpoint.path);
        let (socket, _) =
            client_with_config(url, stream, Some(config)).map_err(|error| match error {
                HandshakeError::Failure(error) => socket_error(error),
                HandshakeError::Interrupted(_) => BrowserError::TimedOut,
            })?;
        Ok(Self {
            socket,
            endpoint: endpoint.clone(),
            next_id: 0,
            healthy: true,
        })
    }

    fn command(
        &mut self,
        method: &str,
        params: Value,
        session: Option<&str>,
        deadline: Instant,
    ) -> Result<Value, BrowserError> {
        if !self.healthy {
            return Err(BrowserError::Closed);
        }
        let result = self.send_and_receive(method, params, session, deadline);
        if result.is_err() {
            self.healthy = false;
            let _ = self.socket.get_ref().socket.shutdown(Shutdown::Both);
        }
        result
    }

    fn send_and_receive(
        &mut self,
        method: &str,
        params: Value,
        session: Option<&str>,
        deadline: Instant,
    ) -> Result<Value, BrowserError> {
        self.socket
            .get_ref()
            .check_cancelled()
            .map_err(|_| BrowserError::ConnectionFailed)?;
        time_left(deadline).map_err(|_| BrowserError::TimedOut)?;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(BrowserError::ResponseLimit)?;
        let id = self.next_id;
        let mut request = json!({ "id": id, "method": method, "params": params });
        if let Some(session) = session {
            request["sessionId"] = json!(session);
        }
        let encoded = request.to_string();
        if encoded.len() > MAX_EXPRESSION_BYTES * 4 {
            return Err(BrowserError::ExpressionTooLarge);
        }
        let stream = self.socket.get_mut();
        stream.deadline = deadline;
        stream.remaining_read_bytes = MAX_COMMAND_BYTES;
        self.socket
            .send(Message::Text(encoded.into()))
            .map_err(socket_error)?;
        for _ in 0..MAX_RESPONSE_MESSAGES {
            self.socket
                .get_ref()
                .check_cancelled()
                .map_err(|_| BrowserError::ConnectionFailed)?;
            time_left(deadline).map_err(|_| BrowserError::TimedOut)?;
            let message = self.socket.read().map_err(socket_error)?;
            self.socket
                .get_ref()
                .check_cancelled()
                .map_err(|_| BrowserError::ConnectionFailed)?;
            match message {
                Message::Text(text) => {
                    let response: Value =
                        serde_json::from_str(&text).map_err(|_| BrowserError::InvalidResponse)?;
                    if response.get("id").and_then(Value::as_u64) != Some(id)
                        || response.get("sessionId").and_then(Value::as_str) != session
                    {
                        continue;
                    }
                    if response.get("error").is_some() {
                        return Err(BrowserError::CommandFailed);
                    }
                    return response
                        .get("result")
                        .cloned()
                        .ok_or(BrowserError::InvalidResponse);
                }
                Message::Ping(_) => self.socket.flush().map_err(socket_error)?,
                Message::Pong(_) => {}
                Message::Close(_) => return Err(BrowserError::Closed),
                _ => return Err(BrowserError::InvalidResponse),
            }
        }
        Err(BrowserError::ResponseLimit)
    }
}

struct OwnedBrowser {
    child: OwnedChild,
    _profile: Arc<ProfileStorage>,
    executable: PathBuf,
    comparison_started: bool,
    owns_active_lease: bool,
}

fn browser_command(executable: &Path, profile: &Path, login_only: bool) -> Command {
    let mut command = Command::new(executable);
    if login_only {
        command.arg("--new-window");
    } else {
        command.args([
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=0",
        ]);
    }
    command
        .arg(format!("--user-data-dir={}", profile.display()))
        .args([
            "--no-first-run",
            "--no-default-browser-check",
            "https://chatgpt.com",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

impl OwnedBrowser {
    fn end_browser_use(&mut self) -> Result<(), BrowserError> {
        if self.owns_active_lease {
            self._profile.end_browser_use()?;
            self.owns_active_lease = false;
        }
        Ok(())
    }
}

impl Drop for OwnedBrowser {
    fn drop(&mut self) {
        if self.child.stop().is_ok() {
            let _ = self.end_browser_use();
        }
        // If stop is unconfirmed, the durable use marker survives app-lock release.
        // Another cleaner must refuse to reopen or clear that profile.
    }
}

struct OwnedChild(Child);

impl std::ops::Deref for OwnedChild {
    type Target = Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for OwnedChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl OwnedChild {
    fn stop(&mut self) -> Result<(), BrowserError> {
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            if self
                .0
                .try_wait()
                .map_err(|_| BrowserError::Closed)?
                .is_some()
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(25));
        }
        // Only the owned child; profile clearing requires confirmed termination.
        self.0.kill().map_err(|_| BrowserError::Closed)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if self
                .0
                .try_wait()
                .map_err(|_| BrowserError::Closed)?
                .is_some()
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(25));
        }
        Err(BrowserError::Closed)
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

enum ProfileStorage {
    Persistent(BrowserProfile),
    #[cfg(test)]
    Temporary(TempDir),
}
impl ProfileStorage {
    fn path(&self) -> &Path {
        match self {
            Self::Persistent(profile) => profile.path(),
            #[cfg(test)]
            Self::Temporary(profile) => profile.path(),
        }
    }
    fn begin_browser_use(&self) -> Result<(), BrowserError> {
        match self {
            Self::Persistent(profile) => profile.begin_browser_use().map_err(BrowserError::Profile),
            #[cfg(test)]
            Self::Temporary(_) => Ok(()),
        }
    }
    fn record_browser_pid(&self, pid: u32) -> Result<(), BrowserError> {
        match self {
            Self::Persistent(profile) => profile
                .record_browser_pid(pid)
                .map_err(BrowserError::Profile),
            #[cfg(test)]
            Self::Temporary(_) => Ok(()),
        }
    }
    fn end_browser_use(&self) -> Result<(), BrowserError> {
        match self {
            Self::Persistent(profile) => profile.end_browser_use().map_err(BrowserError::Profile),
            #[cfg(test)]
            Self::Temporary(_) => Ok(()),
        }
    }
    fn mark_ready(&self) -> Result<(), BrowserError> {
        match self {
            Self::Persistent(profile) => profile.mark_ready().map_err(BrowserError::Profile),
            #[cfg(test)]
            Self::Temporary(_) => Ok(()),
        }
    }
    fn clear(self) -> Result<(), BrowserError> {
        match self {
            Self::Persistent(profile) => profile.clear().map_err(BrowserError::Profile),
            #[cfg(test)]
            Self::Temporary(profile) => profile.close().map_err(|_| BrowserError::Closed),
        }
    }
}

fn browser_product(executable: &Path) -> Result<&'static str, BrowserError> {
    match executable
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "microsoft edge" | "msedge.exe" | "msedge" | "microsoft-edge" | "microsoft-edge-stable" => {
            Ok("edge")
        }
        "google chrome" | "chrome.exe" | "chrome" | "google-chrome" | "google-chrome-stable" => {
            Ok("chrome")
        }
        "chromium" | "chromium.exe" | "chromium-browser" => Ok("chromium"),
        _ => Err(BrowserError::Profile(ProfileError::UnsupportedProduct)),
    }
}

struct AttachedTarget {
    target_id: String,
    session_id: Option<String>,
}

/// Owns only the newly launched browser and its app-managed persistent profile.
pub struct BrowserSession {
    connection: Option<CdpConnection>,
    target: Option<AttachedTarget>,
    browser_owner: Arc<Mutex<Option<OwnedBrowser>>>,
    cancellation_socket: Arc<Mutex<Option<TcpStream>>>,
    cancelled: Arc<AtomicBool>,
}

/// A cross-thread cancellation capability for this isolated browser connection only.
pub struct BrowserCancellation {
    socket: Arc<Mutex<Option<TcpStream>>>,
    cancelled: Arc<AtomicBool>,
    browser_owner: Arc<Mutex<Option<OwnedBrowser>>>,
}

impl BrowserCancellation {
    /// Wakes blocked CDP I/O and releases the owned browser even if the worker
    /// is currently blocked on an unrelated operation such as catalog scanning.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(socket) = self.socket.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        release_browser(&self.browser_owner);
    }
}

impl BrowserSession {
    /// Give this handle to the shutdown path before starting any long evaluation.
    pub fn cancellation_handle(&self) -> Result<BrowserCancellation, BrowserError> {
        Ok(BrowserCancellation {
            socket: Arc::clone(&self.cancellation_socket),
            cancelled: Arc::clone(&self.cancelled),
            browser_owner: Arc::clone(&self.browser_owner),
        })
    }

    /// Opens the app-owned persistent profile for normal interactive sign-in.
    pub fn launch() -> Result<Self, BrowserError> {
        let executable = crate::default_browser::resolve_default_browser()
            .map_err(BrowserError::DefaultBrowser)?;
        let profile =
            BrowserProfile::open(browser_product(&executable)?).map_err(BrowserError::Profile)?;
        Self::start(executable, ProfileStorage::Persistent(profile), true)
    }

    /// Revalidate any existing idle app-owned profile, including unfinished login.
    /// The worker must authenticate with the server before reporting Connected.
    pub fn restore() -> Result<Option<Self>, BrowserError> {
        let executable = crate::default_browser::resolve_default_browser()
            .map_err(BrowserError::DefaultBrowser)?;
        let profile = BrowserProfile::open_existing(browser_product(&executable)?)
            .map_err(BrowserError::Profile)?;
        Self::restore_existing(executable, profile)
    }

    fn restore_existing(
        executable: PathBuf,
        profile: Option<BrowserProfile>,
    ) -> Result<Option<Self>, BrowserError> {
        let Some(profile) = profile else {
            return Ok(None);
        };
        // An absent marker can mean the previous initial check was interrupted.
        // Still reject a malformed marker; previous readiness is not authentication.
        profile.is_ready().map_err(BrowserError::Profile)?;
        Self::start(executable, ProfileStorage::Persistent(profile), false).map(Some)
    }

    fn start(
        executable: PathBuf,
        profile: ProfileStorage,
        login_only: bool,
    ) -> Result<Self, BrowserError> {
        if !login_only {
            remove_stale_endpoint(profile.path())?;
        }
        let child = spawn_browser_child(&executable, &profile, login_only)?;
        Ok(Self {
            connection: None,
            target: None,
            browser_owner: Arc::new(Mutex::new(Some(OwnedBrowser {
                child,
                _profile: Arc::new(profile),
                executable,
                comparison_started: !login_only,
                owns_active_lease: true,
            }))),
            cancellation_socket: Arc::new(Mutex::new(None)),
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn login_window_closed(&mut self) -> Result<bool, BrowserError> {
        let mut owner = self
            .browser_owner
            .lock()
            .map_err(|_| BrowserError::Closed)?;
        let browser = owner.as_mut().ok_or(BrowserError::Closed)?;
        if browser.comparison_started {
            return Ok(true);
        }
        match browser
            .child
            .try_wait()
            .map_err(|_| BrowserError::LaunchFailed)?
        {
            None => Ok(false),
            Some(status) if status.success() => Ok(true),
            Some(_) => Err(BrowserError::LoginInterrupted),
        }
    }

    /// Inspects only the owned comparison child. Initial login exit is handled
    /// separately; this probe never starts a browser or changes profile storage.
    pub fn comparison_browser_closed(&self) -> Result<bool, BrowserError> {
        let mut owner = self
            .browser_owner
            .lock()
            .map_err(|_| BrowserError::Closed)?;
        let browser = owner.as_mut().ok_or(BrowserError::Closed)?;
        if !browser.comparison_started {
            return Ok(false);
        }
        browser
            .child
            .try_wait()
            .map(|status| status.is_some())
            .map_err(|_| BrowserError::LaunchFailed)
    }

    /// Authentication-only results never constitute inventory or repair evidence.
    pub fn authenticate(&mut self) -> Result<(), BrowserError> {
        finish_login(
            &self.browser_owner,
            request_owned_browser_quit,
            Instant::now() + LOGIN_EXIT_TIMEOUT,
        )?;
        let expression = format!(
            "(async()=>{{ {}; return await collectChatMetadata([],true); }})()",
            include_str!("../assets/web/collect.js")
        );
        let value = self.evaluate(&expression)?;
        validate_authentication(&value)?;
        let owner = self
            .browser_owner
            .lock()
            .map_err(|_| BrowserError::Closed)?;
        owner
            .as_ref()
            .ok_or(BrowserError::Closed)?
            ._profile
            .mark_ready()
    }

    /// Explicit user disconnection only; ordinary shutdown retains the profile.
    pub fn disconnect(mut self) -> Result<(), BrowserError> {
        self.close_connection();
        let owner = self
            .browser_owner
            .lock()
            .map_err(|_| BrowserError::Closed)?
            .take();
        if let Some(mut browser) = owner {
            browser.child.stop()?;
            browser.end_browser_use()?;
            let profile = Arc::clone(&browser._profile);
            drop(browser);
            Arc::try_unwrap(profile)
                .map_err(|_| BrowserError::Closed)?
                .clear()?;
        }
        Ok(())
    }

    pub fn forget_saved() -> Result<(), BrowserError> {
        let executable = crate::default_browser::resolve_default_browser()
            .map_err(BrowserError::DefaultBrowser)?;
        if let Some(profile) = BrowserProfile::open_existing(browser_product(&executable)?)
            .map_err(BrowserError::Profile)?
        {
            profile.clear().map_err(BrowserError::Profile)?;
        }
        Ok(())
    }

    fn close_connection(&mut self) {
        if let Some(mut connection) = self.connection.take() {
            let _ = connection.command(
                "Browser.close",
                json!({}),
                None,
                Instant::now() + Duration::from_millis(500),
            );
        }
    }

    /// Interactive login runs without CDP. Its owned child must exit normally
    /// before comparison can reopen the same profile in the normal browser.
    fn prepare_comparison(&mut self) -> Result<(), BrowserError> {
        if self
            .connection
            .as_ref()
            .is_some_and(|connection| connection.healthy)
        {
            if self.comparison_browser_closed()? {
                return Err(BrowserError::Closed);
            }
            return Ok(());
        }
        {
            let mut owner = self
                .browser_owner
                .lock()
                .map_err(|_| BrowserError::Closed)?;
            let browser = owner.as_mut().ok_or(BrowserError::Closed)?;
            if !browser.comparison_started {
                begin_comparison(browser)?;
            }
        }
        let deadline = Instant::now() + LAUNCH_TIMEOUT;
        loop {
            let mut owner = self
                .browser_owner
                .lock()
                .map_err(|_| BrowserError::Closed)?;
            let browser = owner.as_mut().ok_or(BrowserError::Closed)?;
            if browser
                .child
                .try_wait()
                .map_err(|_| BrowserError::LaunchFailed)?
                .is_some()
            {
                return Err(BrowserError::LaunchFailed);
            }
            if Instant::now() >= deadline {
                return Err(BrowserError::StartupTimeout);
            }
            let active_port_path = browser._profile.path().join("DevToolsActivePort");
            let endpoint = read_active_port(&active_port_path)?;
            drop(owner);
            if let Some(endpoint) = endpoint {
                // A failed command is retried only by a later caller action. Keep
                // the original endpoint until a replacement connection succeeds.
                if self
                    .connection
                    .as_ref()
                    .is_some_and(|connection| connection.endpoint != endpoint)
                {
                    return Err(BrowserError::InvalidEndpoint);
                }
                let connection =
                    CdpConnection::connect(&endpoint, deadline, Arc::clone(&self.cancelled))?;
                let socket = connection
                    .socket
                    .get_ref()
                    .socket
                    .try_clone()
                    .map_err(|_| BrowserError::ConnectionFailed)?;
                let mut owner = self
                    .browser_owner
                    .lock()
                    .map_err(|_| BrowserError::Closed)?;
                let browser = owner.as_mut().ok_or(BrowserError::Closed)?;
                if browser
                    .child
                    .try_wait()
                    .map_err(|_| BrowserError::LaunchFailed)?
                    .is_some()
                {
                    return Err(BrowserError::Closed);
                }
                *self
                    .cancellation_socket
                    .lock()
                    .map_err(|_| BrowserError::Closed)? = Some(socket);
                if let Some(target) = self.target.as_mut() {
                    // Target identity survives reconnects; CDP attachment does not.
                    target.session_id = None;
                }
                self.connection = Some(connection);
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Evaluates the trusted collector on the selected chatgpt.com page.
    ///
    /// Do not pass user-supplied scripts or expressions that return authentication material.
    /// The caller must validate the returned metadata schema before authorizing any cleanup.
    pub fn evaluate(&mut self, expression: &str) -> Result<Value, BrowserError> {
        if expression.len() > MAX_EXPRESSION_BYTES {
            return Err(BrowserError::ExpressionTooLarge);
        }
        self.prepare_comparison()?;
        evaluate_on_target(
            self.connection.as_mut().ok_or(BrowserError::Closed)?,
            &mut self.target,
            expression,
            Instant::now() + EVALUATION_TIMEOUT,
        )
    }
}

/// Browser-controlled exception details never become diagnostic text.
fn evaluation_error(details: &Value) -> BrowserError {
    let exception = &details["exception"];
    match exception["className"].as_str() {
        Some("Error") => match exception["description"]
            .as_str()
            .and_then(|description| description.lines().next())
        {
            Some("Error: wrong origin") => BrowserError::PageNotReady,
            Some("Error: changed origin") => BrowserError::TargetChanged,
            _ => BrowserError::EvaluationFailed,
        },
        Some("SyntaxError") => BrowserError::SyntaxError,
        Some("ReferenceError") => BrowserError::ReferenceError,
        Some("TypeError") => BrowserError::TypeError,
        _ => BrowserError::EvaluationFailed,
    }
}

fn readiness_pause(deadline: Instant) -> Result<(), BrowserError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(BrowserError::PageNotReady)?;
    thread::sleep(remaining.min(Duration::from_millis(50)));
    if Instant::now() >= deadline {
        return Err(BrowserError::PageNotReady);
    }
    Ok(())
}

fn wait_for_chatgpt_target(
    connection: &mut CdpConnection,
    selected: Option<&str>,
    deadline: Instant,
) -> Result<String, BrowserError> {
    loop {
        let targets = connection.command("Target.getTargets", json!({}), None, deadline)?;
        match select_chatgpt_target(&targets, selected) {
            Err(BrowserError::NoChatGptTarget) if selected.is_none() => {}
            result => return result,
        }
        let pages = targets["targetInfos"]
            .as_array()
            .ok_or(BrowserError::InvalidResponse)?
            .iter()
            .filter(|target| target["type"] == "page")
            .collect::<Vec<_>>();
        if pages.len() > 1 {
            return Err(BrowserError::AmbiguousTarget);
        }
        if let Some(page) = pages.first() {
            checked_identifier(page.get("targetId"))?;
            if page["url"] != "about:blank" {
                return Err(BrowserError::NoChatGptTarget);
            }
        }
        // Only an empty page list or the initial blank page can become ready.
        readiness_pause(deadline)?;
    }
}

fn wait_for_ready_context(
    connection: &mut CdpConnection,
    target: &AttachedTarget,
    deadline: Instant,
) -> Result<(), BrowserError> {
    let session_id = target
        .session_id
        .as_deref()
        .ok_or(BrowserError::TargetChanged)?;
    loop {
        let evaluated = connection.command("Runtime.evaluate", json!({
            "expression":"({origin:location.origin,top:window.top===window,readyState:document.readyState,aboutBlank:location.href==='about:blank'})",
            "returnByValue":true,
            "timeout":deadline.saturating_duration_since(Instant::now()).as_millis() as u64,
        }), Some(session_id), deadline)?;
        if let Some(details) = evaluated.get("exceptionDetails") {
            return Err(evaluation_error(details));
        }
        let state = &evaluated["result"]["value"];
        let top = state["top"]
            .as_bool()
            .ok_or(BrowserError::InvalidResponse)?;
        let blank = state["aboutBlank"]
            .as_bool()
            .ok_or(BrowserError::InvalidResponse)?;
        let origin = state["origin"]
            .as_str()
            .ok_or(BrowserError::InvalidResponse)?;
        let ready = state["readyState"]
            .as_str()
            .ok_or(BrowserError::InvalidResponse)?;
        if !matches!(ready, "loading" | "interactive" | "complete") {
            return Err(BrowserError::InvalidResponse);
        }
        if !top || (origin != "https://chatgpt.com" && !(blank && origin == "null")) {
            return Err(BrowserError::TargetChanged);
        }
        if !blank && origin == "https://chatgpt.com" && matches!(ready, "interactive" | "complete")
        {
            return Ok(());
        }
        readiness_pause(deadline)?;
        // Revalidate the pinned target during startup; never switch to another tab.
        wait_for_chatgpt_target(connection, Some(&target.target_id), deadline)?;
    }
}

fn evaluate_on_target(
    connection: &mut CdpConnection,
    target: &mut Option<AttachedTarget>,
    expression: &str,
    deadline: Instant,
) -> Result<Value, BrowserError> {
    if expression.len() > MAX_EXPRESSION_BYTES {
        return Err(BrowserError::ExpressionTooLarge);
    }
    let readiness_deadline = deadline.min(Instant::now() + LAUNCH_TIMEOUT);
    let selected = wait_for_chatgpt_target(
        connection,
        target.as_ref().map(|target| target.target_id.as_str()),
        readiness_deadline,
    )?;
    if target.is_none() {
        // Pin the selected page before attachment, including an attachment timeout.
        *target = Some(AttachedTarget {
            target_id: selected,
            session_id: None,
        });
    }
    let attached_target = target.as_mut().ok_or(BrowserError::TargetChanged)?;
    if attached_target.session_id.is_none() {
        let attached = connection.command(
            "Target.attachToTarget",
            json!({"targetId": attached_target.target_id, "flatten": true}),
            None,
            deadline,
        )?;
        let session_id = checked_identifier(attached.get("sessionId"))?;
        attached_target.session_id = Some(session_id);
    }
    let attached = target.as_ref().ok_or(BrowserError::TargetChanged)?;
    wait_for_ready_context(connection, attached, readiness_deadline)?;
    let session = attached
        .session_id
        .as_deref()
        .ok_or(BrowserError::TargetChanged)?
        .to_owned();
    let wrapped = format!(
        "(async()=>{{if(location.origin!=='https://chatgpt.com'||window.top!==window)throw new Error('wrong origin');const value=await ({expression});if(location.origin!=='https://chatgpt.com')throw new Error('changed origin');return value;}})()"
    );
    let evaluated = connection.command(
        "Runtime.evaluate",
        json!({
            "expression": wrapped,
            "awaitPromise": true,
            "returnByValue": true,
            "timeout": EVALUATION_TIMEOUT.as_millis() as u64,
        }),
        Some(&session),
        deadline,
    )?;
    if let Some(details) = evaluated.get("exceptionDetails") {
        return Err(evaluation_error(details));
    }
    let targets = connection.command("Target.getTargets", json!({}), None, deadline)?;
    select_chatgpt_target(
        &targets,
        target.as_ref().map(|target| target.target_id.as_str()),
    )?;
    evaluated
        .get("result")
        .and_then(|result| result.get("value"))
        .cloned()
        .ok_or(BrowserError::InvalidResponse)
}

impl Drop for BrowserSession {
    fn drop(&mut self) {
        self.close_connection();
        release_browser(&self.browser_owner);
    }
}

fn validate_authentication(value: &Value) -> Result<(), BrowserError> {
    let object = value
        .as_object()
        .filter(|object| object.len() == 1)
        .ok_or(BrowserError::InvalidResponse)?;
    if object.get("authenticated") == Some(&Value::Bool(true)) {
        return Ok(());
    }
    match object.get("error").and_then(Value::as_str) {
        Some("login_required") => Err(BrowserError::LoginRequired),
        Some("authorization_failed") => Err(BrowserError::AuthorizationDenied),
        Some("wrong_origin") => Err(BrowserError::PageNotReady),
        Some("invalid_request") => Err(BrowserError::InvalidCollectorRequest),
        Some("account_changed") => Err(BrowserError::AccountChanged),
        Some("session_user_mismatch") => Err(BrowserError::SessionUserMismatch),
        Some("account_match_mismatch") => Err(BrowserError::AccountMatchMismatch),
        Some("account_match_none") => Err(BrowserError::AccountMatchNone),
        Some("account_match_multiple") => Err(BrowserError::AccountMatchMultiple),
        Some("ordered_personal_account_id_missing_bound") => {
            Err(BrowserError::OrderedPersonalAccountIdMissingBound)
        }
        Some("ordered_personal_account_id_missing_unbound") => {
            Err(BrowserError::OrderedPersonalAccountIdMissingUnbound)
        }
        Some("ordered_personal_account_id_missing") => {
            Err(BrowserError::OrderedPersonalAccountIdMissing)
        }
        Some("account_user_mismatch") => Err(BrowserError::AccountUserMismatch),
        Some("final_identity_changed") => Err(BrowserError::FinalIdentityChanged),
        Some("unsupported_account") => Err(BrowserError::UnsupportedAccount),
        Some("response_schema_changed") => Err(BrowserError::ResponseSchemaChanged),
        Some("rate_limited") => Err(BrowserError::RateLimited),
        Some("web_unavailable") => Err(BrowserError::WebUnavailable),
        Some("collection_timeout") => Err(BrowserError::TimedOut),
        _ => Err(BrowserError::InvalidResponse),
    }
}

fn remove_stale_endpoint(profile: &Path) -> Result<(), BrowserError> {
    match fs::remove_file(profile.join("DevToolsActivePort")) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(BrowserError::InvalidEndpoint),
    }
}

fn finish_login(
    owner: &Mutex<Option<OwnedBrowser>>,
    request_quit: impl FnOnce(u32) -> bool,
    deadline: Instant,
) -> Result<(), BrowserError> {
    {
        let mut owner = owner.lock().map_err(|_| BrowserError::Closed)?;
        let browser = owner.as_mut().ok_or(BrowserError::Closed)?;
        if browser.comparison_started {
            return Ok(());
        }
        match browser
            .child
            .try_wait()
            .map_err(|_| BrowserError::LaunchFailed)?
        {
            Some(status) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(BrowserError::LoginInterrupted)
                }
            }
            None => {
                // Keep ownership locked through the request. The unreaped child PID
                // cannot be reused, and cancellation cannot replace this owner.
                if !request_quit(browser.child.id()) {
                    return match browser
                        .child
                        .try_wait()
                        .map_err(|_| BrowserError::LaunchFailed)?
                    {
                        Some(status) if status.success() => Ok(()),
                        Some(_) => Err(BrowserError::LoginInterrupted),
                        None => Err(BrowserError::LoginBrowserStillOpen),
                    };
                }
            }
        }
    }
    loop {
        {
            let mut owner = owner.lock().map_err(|_| BrowserError::Closed)?;
            let browser = owner.as_mut().ok_or(BrowserError::Closed)?;
            match browser
                .child
                .try_wait()
                .map_err(|_| BrowserError::LaunchFailed)?
            {
                Some(status) if status.success() => return Ok(()),
                Some(_) => return Err(BrowserError::LoginInterrupted),
                None => {}
            }
        }
        if Instant::now() >= deadline {
            // Handoff never force-kills: the user can still quit normally and retry.
            return Err(BrowserError::LoginBrowserStillOpen);
        }
        // Cancellation can take ownership while this wait is in progress.
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(target_os = "macos")]
fn request_owned_browser_quit(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    objc2_app_kit::NSRunningApplication::runningApplicationWithProcessIdentifier(pid)
        .is_some_and(|application| application.terminate())
}

#[cfg(not(target_os = "macos"))]
fn request_owned_browser_quit(_pid: u32) -> bool {
    // Without a verified normal-quit primitive, preserve the manual-close guard.
    false
}

fn spawn_browser_child(
    executable: &Path,
    profile: &ProfileStorage,
    login_only: bool,
) -> Result<OwnedChild, BrowserError> {
    profile.begin_browser_use()?;
    let mut child = OwnedChild(
        match browser_command(executable, profile.path(), login_only).spawn() {
            Ok(child) => child,
            Err(_) => {
                profile.end_browser_use()?;
                return Err(BrowserError::LaunchFailed);
            }
        },
    );
    if let Err(error) = profile.record_browser_pid(child.id()) {
        // Never leave an untracked browser running after a failed durable record.
        // An unconfirmed stop retains the pending marker and stays fail-closed.
        if child.stop().is_ok() {
            let _ = profile.end_browser_use();
        }
        return Err(error);
    }
    Ok(child)
}

fn begin_comparison(browser: &mut OwnedBrowser) -> Result<(), BrowserError> {
    begin_comparison_with(browser, spawn_browser_child)
}

fn begin_comparison_with(
    browser: &mut OwnedBrowser,
    spawn: impl FnOnce(&Path, &ProfileStorage, bool) -> Result<OwnedChild, BrowserError>,
) -> Result<(), BrowserError> {
    if !browser.owns_active_lease {
        return Err(BrowserError::Profile(ProfileError::UnconfirmedExit));
    }
    let status = browser
        .child
        .try_wait()
        .map_err(|_| BrowserError::LaunchFailed)?
        .ok_or(BrowserError::LoginBrowserStillOpen)?;
    if !status.success() {
        return Err(BrowserError::LoginInterrupted);
    }
    // Relinquish the old child's cleanup authority before any replacement step
    // can create a marker. A failed replacement must keep its own marker intact.
    browser.end_browser_use()?;
    remove_stale_endpoint(browser._profile.path())?;
    // Preserve the same browser profile and its exclusive application lock.
    browser.child = spawn(&browser.executable, &browser._profile, false)?;
    browser.owns_active_lease = true;
    browser.comparison_started = true;
    Ok(())
}

fn release_browser(owner: &Mutex<Option<OwnedBrowser>>) {
    let browser = owner
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    // Release the lock before process shutdown and profile cleanup. A competing
    // cancellation or session drop sees None and cannot kill the child twice.
    drop(browser);
}

fn checked_identifier(value: Option<&Value>) -> Result<String, BrowserError> {
    let value = value
        .and_then(Value::as_str)
        .ok_or(BrowserError::InvalidResponse)?;
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(BrowserError::InvalidResponse);
    }
    Ok(value.to_owned())
}

fn select_chatgpt_target(targets: &Value, selected: Option<&str>) -> Result<String, BrowserError> {
    let infos = targets
        .get("targetInfos")
        .and_then(Value::as_array)
        .ok_or(BrowserError::InvalidResponse)?;
    if infos.len() > 128 {
        return Err(BrowserError::ResponseLimit);
    }
    let mut found = None;
    for target in infos {
        if target.get("type").and_then(Value::as_str) != Some("page")
            || !target
                .get("url")
                .and_then(Value::as_str)
                .is_some_and(chatgpt_url_is_allowed)
        {
            continue;
        }
        let id = checked_identifier(target.get("targetId"))?;
        if let Some(selected) = selected {
            if id == selected {
                return Ok(id);
            }
        } else if found.replace(id).is_some() {
            return Err(BrowserError::AmbiguousTarget);
        }
    }
    if selected.is_some() {
        Err(BrowserError::TargetChanged)
    } else {
        found.ok_or(BrowserError::NoChatGptTarget)
    }
}

fn read_active_port(path: &Path) -> Result<Option<BrowserEndpoint>, BrowserError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(BrowserError::InvalidEndpoint),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_ACTIVE_PORT_BYTES as u64
    {
        return Err(BrowserError::InvalidEndpoint);
    }
    let mut text = String::new();
    File::open(path)
        .map_err(|_| BrowserError::InvalidEndpoint)?
        .take(MAX_ACTIVE_PORT_BYTES as u64 + 1)
        .read_to_string(&mut text)
        .map_err(|_| BrowserError::InvalidEndpoint)?;
    // Chrome writes this file during startup; retry a still-empty or single-line file.
    if text.lines().count() < 2 {
        return Ok(None);
    }
    parse_active_port(&text).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::{Duration, Instant};
    use tungstenite::{Message, WebSocket};

    #[test]
    fn interactive_login_has_no_debugging_or_automation_flags() {
        let command = browser_command(Path::new("browser"), Path::new("private-profile"), true);
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();
        assert!(
            args.iter()
                .all(|arg| !arg.contains("remote-debugging") && !arg.contains("automation")),
            "interactive authentication must start without an automation/debug endpoint: {args:?}"
        );
        assert!(!args.iter().any(|arg| arg.starts_with("--headless")));
        assert!(args.iter().any(|arg| arg == "--new-window"));
        assert!(args
            .iter()
            .any(|arg| arg == "--user-data-dir=private-profile"));
        assert_eq!(args.last().unwrap(), "https://chatgpt.com");
    }

    #[test]
    fn comparison_uses_normal_browser_with_owned_loopback_endpoint() {
        let command = browser_command(Path::new("browser"), Path::new("private-profile"), false);
        let args = command.get_args().collect::<Vec<_>>();
        assert!(!args
            .iter()
            .any(|arg| arg.to_string_lossy().starts_with("--headless")));
        assert!(!args.contains(&std::ffi::OsStr::new("--new-window")));
        assert!(args.contains(&std::ffi::OsStr::new(
            "--remote-debugging-address=127.0.0.1"
        )));
        assert!(args.contains(&std::ffi::OsStr::new("--remote-debugging-port=0")));
        assert!(args.contains(&std::ffi::OsStr::new("--user-data-dir=private-profile")));
    }

    #[test]
    fn authentication_requires_exact_sanitized_server_confirmation() {
        assert_eq!(
            validate_authentication(&json!({"authenticated":true})),
            Ok(())
        );
        for value in [
            json!({}),
            json!({"authenticated":false}),
            json!({"authenticated":"true"}),
            json!({"authenticated":true,"accessToken":"fixture-must-not-cross"}),
            json!({"complete":true,"items":[]}),
        ] {
            assert!(validate_authentication(&value).is_err());
        }
        assert_eq!(
            validate_authentication(&json!({"error":"login_required"})),
            Err(BrowserError::LoginRequired)
        );
        assert_eq!(
            format!(
                "{:?}",
                validate_authentication(&json!({"error":"authorization_failed"})).unwrap_err()
            ),
            "AuthorizationDenied"
        );
        assert_eq!(
            validate_authentication(&json!({"error":"web_unavailable"})),
            Err(BrowserError::WebUnavailable)
        );
    }

    #[test]
    fn authentication_reports_only_allowlisted_collector_failures() {
        for (code, expected) in [
            ("wrong_origin", BrowserError::PageNotReady),
            ("invalid_request", BrowserError::InvalidCollectorRequest),
            ("account_changed", BrowserError::AccountChanged),
            ("session_user_mismatch", BrowserError::SessionUserMismatch),
            ("account_match_mismatch", BrowserError::AccountMatchMismatch),
            ("account_match_none", BrowserError::AccountMatchNone),
            ("account_match_multiple", BrowserError::AccountMatchMultiple),
            (
                "ordered_personal_account_id_missing_bound",
                BrowserError::OrderedPersonalAccountIdMissingBound,
            ),
            (
                "ordered_personal_account_id_missing_unbound",
                BrowserError::OrderedPersonalAccountIdMissingUnbound,
            ),
            (
                "ordered_personal_account_id_missing",
                BrowserError::OrderedPersonalAccountIdMissing,
            ),
            ("account_user_mismatch", BrowserError::AccountUserMismatch),
            ("final_identity_changed", BrowserError::FinalIdentityChanged),
            ("unsupported_account", BrowserError::UnsupportedAccount),
            (
                "response_schema_changed",
                BrowserError::ResponseSchemaChanged,
            ),
            ("rate_limited", BrowserError::RateLimited),
            ("web_unavailable", BrowserError::WebUnavailable),
            ("collection_timeout", BrowserError::TimedOut),
        ] {
            assert_eq!(
                validate_authentication(&json!({"error": code})),
                Err(expected)
            );
        }
        for value in [
            json!({"error":"fixture-secret-message"}),
            json!({"error":"rate_limited", "body":"fixture-secret-body"}),
            json!({"error":"login_required", "accessToken":"fixture-secret-token"}),
            json!({"error":"inventory_changed"}),
        ] {
            let error = validate_authentication(&value).unwrap_err();
            assert_eq!(error, BrowserError::InvalidResponse);
            assert!(!format!("{error} {error:?}").contains("fixture-secret"));
        }
    }

    #[test]
    fn profile_product_follows_the_selected_browser() {
        assert_eq!(browser_product(Path::new("Microsoft Edge")), Ok("edge"));
        assert_eq!(browser_product(Path::new("chrome.exe")), Ok("chrome"));
        assert_eq!(browser_product(Path::new("chromium")), Ok("chromium"));
        assert!(browser_product(Path::new("safari")).is_err());
    }

    fn mock_connection(
        handler: impl FnOnce(WebSocket<TcpStream>) + Send + 'static,
    ) -> (CdpConnection, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind synthetic server");
        let port = listener.local_addr().expect("local port").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept synthetic connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            handler(tungstenite::accept(stream).expect("synthetic handshake"));
        });
        let connection = CdpConnection::connect(
            &BrowserEndpoint {
                port,
                path: "/devtools/browser/test".to_owned(),
            },
            Instant::now() + Duration::from_secs(2),
            Arc::new(AtomicBool::new(false)),
        )
        .expect("connect synthetic browser");
        (connection, server)
    }

    #[test]
    fn command_ignores_events_and_other_sessions() {
        let (mut connection, server) = mock_connection(|mut socket| {
            let request: serde_json::Value =
                serde_json::from_str(socket.read().unwrap().to_text().unwrap()).unwrap();
            let id = request["id"].as_u64().unwrap();
            for message in [
                json!({"method":"Target.targetInfoChanged","params":{}}),
                json!({"id":id,"sessionId":"another-session","result":{"unexpected":true}}),
                json!({"id":id,"sessionId":"selected-session","result":{"safe":true}}),
            ] {
                socket
                    .send(Message::Text(message.to_string().into()))
                    .unwrap();
            }
        });
        let result = connection.command(
            "Runtime.evaluate",
            json!({}),
            Some("selected-session"),
            Instant::now() + Duration::from_secs(2),
        );
        assert_eq!(result, Ok(json!({"safe":true})));
        server.join().unwrap();
    }

    #[test]
    fn silent_peer_is_bounded_by_the_command_deadline() {
        let (mut connection, server) = mock_connection(|mut socket| {
            let _ = socket.read().unwrap();
            thread::sleep(Duration::from_millis(150));
        });
        let started = Instant::now();
        assert!(connection
            .command(
                "Target.getTargets",
                json!({}),
                None,
                started + Duration::from_millis(40)
            )
            .is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!connection.healthy);
        server.join().unwrap();
    }

    #[test]
    fn cross_thread_cancellation_interrupts_a_pending_response() {
        assert_pending_response_is_cancelled(true);
    }

    #[test]
    fn cancellation_does_not_depend_on_socket_shutdown_waking_the_reader() {
        assert_pending_response_is_cancelled(false);
    }

    fn assert_pending_response_is_cancelled(keep_shutdown_socket: bool) {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (mut connection, server) = mock_connection(move |mut socket| {
            let _ = socket.read().unwrap();
            started_tx.send(()).unwrap();
            // Keep the silent peer open until the cancellation outcome is observed.
            // A peer timeout or close must not masquerade as successful cancellation.
            let _ = release_rx.recv();
        });
        let cancellation = connection
            .cancellation_handle(Arc::new(Mutex::new(None)))
            .unwrap();
        if !keep_shutdown_socket {
            cancellation.socket.lock().unwrap().take();
        }
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let operation = thread::spawn(move || {
            let result = connection.command(
                "Runtime.evaluate",
                json!({}),
                None,
                Instant::now() + Duration::from_secs(10),
            );
            finished_tx.send(result).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        cancellation.cancel();
        let result = finished_rx.recv_timeout(Duration::from_secs(2));
        release_tx.send(()).unwrap();
        operation.join().unwrap();
        server.join().unwrap();
        assert!(
            matches!(result, Ok(Err(BrowserError::ConnectionFailed))),
            "cancellation must interrupt the response before peer release or command deadline: {result:?}"
        );
    }

    #[test]
    fn cancellation_before_command_prevents_io_without_a_shutdown_socket() {
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        let (mut connection, server) = mock_connection(move |mut socket| {
            let _ = release_rx.recv();
            request_tx
                .send(matches!(socket.read(), Ok(Message::Text(_))))
                .unwrap();
        });
        let cancellation = connection
            .cancellation_handle(Arc::new(Mutex::new(None)))
            .unwrap();
        cancellation.socket.lock().unwrap().take();
        cancellation.cancel();
        let result = connection.command(
            "Runtime.evaluate",
            json!({}),
            None,
            Instant::now() + Duration::from_millis(100),
        );
        release_tx.send(()).unwrap();
        server.join().unwrap();
        assert_eq!(result, Err(BrowserError::ConnectionFailed));
        assert!(
            !request_rx.recv().unwrap(),
            "cancelled command must not reach the peer"
        );
    }

    #[test]
    fn cancellation_interrupts_a_silent_websocket_handshake() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = BrowserEndpoint {
            port: listener.local_addr().unwrap().port(),
            path: "/devtools/browser/test".to_owned(),
        };
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0; 1024];
            assert!(stream.read(&mut request).unwrap() > 0);
            started_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancellation = BrowserCancellation {
            socket: Arc::new(Mutex::new(None)),
            cancelled: Arc::clone(&cancelled),
            browser_owner: Arc::new(Mutex::new(None)),
        };
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let operation = thread::spawn(move || {
            let error = CdpConnection::connect(
                &endpoint,
                Instant::now() + Duration::from_secs(10),
                cancelled,
            )
            .err();
            finished_tx.send(error).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        cancellation.cancel();
        let result = finished_rx.recv_timeout(Duration::from_secs(2));
        release_tx.send(()).unwrap();
        operation.join().unwrap();
        server.join().unwrap();
        assert_eq!(result, Ok(Some(BrowserError::ConnectionFailed)));
    }

    #[test]
    fn delayed_peer_preserves_complete_command_and_response() {
        let expression = "x".repeat(MAX_EXPRESSION_BYTES / 2);
        let expected = expression.clone();
        let (mut connection, server) = mock_connection(move |mut socket| {
            thread::sleep(Duration::from_millis(150));
            let request: Value =
                serde_json::from_str(socket.read().unwrap().to_text().unwrap()).unwrap();
            assert_eq!(request["params"]["expression"], expected);
            let response = json!({"id": request["id"], "result": {"complete": true}}).to_string();
            assert!(response.len() < 126);
            let stream = socket.get_mut();
            // Split an unmasked server frame across its header and payload.
            stream.write_all(&[0x81]).unwrap();
            thread::sleep(Duration::from_millis(50));
            stream.write_all(&[response.len() as u8]).unwrap();
            let middle = response.len() / 2;
            stream.write_all(&response.as_bytes()[..middle]).unwrap();
            thread::sleep(Duration::from_millis(50));
            stream.write_all(&response.as_bytes()[middle..]).unwrap();
        });
        let result = connection.command(
            "Runtime.evaluate",
            json!({"expression": expression}),
            None,
            Instant::now() + Duration::from_secs(5),
        );
        server.join().unwrap();
        assert_eq!(result, Ok(json!({"complete": true})));
    }

    #[test]
    #[ignore = "fixture child spawned by cancellation test"]
    fn owned_browser_fixture_process() {
        thread::sleep(Duration::from_secs(30));
    }

    fn assert_persistent_profile_reopens_after_shutdown(cancel: bool) {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().canonicalize().unwrap().join("app-data");
        let profile = BrowserProfile::open_test(&root, "edge").unwrap();
        let path = profile.path().to_owned();
        profile.mark_ready().unwrap();
        profile.begin_browser_use().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "browser_transport::tests::owned_browser_fixture_process",
                "--ignored",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert!(child.try_wait().unwrap().is_none());
        let mut child_output = child.stdout.take().unwrap();
        let (exited_tx, exited_rx) = std::sync::mpsc::channel();
        let output_reader = thread::spawn(move || {
            let _ = io::copy(&mut child_output, &mut io::sink());
            let _ = exited_tx.send(());
        });
        let session = BrowserSession {
            connection: None,
            target: None,
            browser_owner: Arc::new(Mutex::new(Some(OwnedBrowser {
                child: OwnedChild(child),
                _profile: Arc::new(ProfileStorage::Persistent(profile)),
                executable: PathBuf::from("unused-persistent-fixture"),
                comparison_started: true,
                owns_active_lease: true,
            }))),
            cancellation_socket: Arc::new(Mutex::new(None)),
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        let cancellation = session.cancellation_handle().unwrap();
        assert_eq!(
            BrowserProfile::open_test(&root, "edge").unwrap_err(),
            ProfileError::InUse
        );
        assert!(path.join(".ghost-chat-cleaner-browser-active").is_file());
        let retained_session = if cancel {
            cancellation.cancel();
            Some(session)
        } else {
            drop(session);
            None
        };
        // EOF from the fixture child independently confirms termination.
        assert!(exited_rx.recv_timeout(Duration::from_secs(1)).is_ok());
        output_reader.join().unwrap();
        assert!(
            path.is_dir(),
            "normal shutdown must retain saved login storage"
        );
        assert!(!path.join(".ghost-chat-cleaner-browser-active").exists());
        let reopened = BrowserProfile::open_test(&root, "edge").unwrap();
        assert_eq!(reopened.path(), path);
        assert!(
            reopened.is_ready().unwrap(),
            "the saved ready marker must survive"
        );
        // The old cancellation handle/session must not own or clear the new lease.
        cancellation.cancel();
        drop(retained_session);
        assert!(reopened.is_ready().unwrap());
    }

    #[test]
    fn persistent_profile_survives_cancellation_and_reopens() {
        assert_persistent_profile_reopens_after_shutdown(true);
    }

    #[test]
    fn persistent_profile_survives_session_drop_and_reopens() {
        assert_persistent_profile_reopens_after_shutdown(false);
    }

    #[test]
    fn persistent_profile_is_reusable_after_start_spawn_failure() {
        for login_only in [true, false] {
            let fixture = tempfile::tempdir().unwrap();
            let root = fixture.path().canonicalize().unwrap().join("app-data");
            let profile = BrowserProfile::open_test(&root, "edge").unwrap();
            let path = profile.path().to_owned();
            profile.mark_ready().unwrap();
            let result = BrowserSession::start(
                fixture.path().join("nonexistent-browser-fixture"),
                ProfileStorage::Persistent(profile),
                login_only,
            );
            assert!(matches!(result, Err(BrowserError::LaunchFailed)));
            assert!(path.is_dir());
            assert!(!path.join(".ghost-chat-cleaner-browser-active").exists());
            let reopened = BrowserProfile::open_test(&root, "edge").unwrap();
            assert!(reopened.is_ready().unwrap());
            reopened.clear().unwrap();
            assert!(!path.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn persistent_start_records_each_owned_browser_pid() {
        use std::os::unix::fs::PermissionsExt;
        for login_only in [true, false] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap().join("app-data");
            let profile = BrowserProfile::open_test(&root, "edge").unwrap();
            let path = profile.path().to_owned();
            let executable = temp.path().join("browser");
            fs::write(&executable, "#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            let session =
                BrowserSession::start(executable, ProfileStorage::Persistent(profile), login_only)
                    .unwrap();
            let pid = session
                .browser_owner
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .child
                .id();
            let marker = fs::read(path.join(".ghost-chat-cleaner-browser-active")).unwrap();
            drop(session);
            assert_eq!(
                marker,
                format!("ghost-chat-cleaner/browser-active/v2\npid={pid}\n").as_bytes()
            );
            let reopened = BrowserProfile::open_test(&root, "edge").unwrap();
            assert!(reopened.path().is_dir());
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_replacement_lease_survives_old_owner_cleanup() {
        for disconnect in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap().join("app-data");
            let profile = BrowserProfile::open_test(&root, "edge").unwrap();
            let path = profile.path().to_owned();
            profile.begin_browser_use().unwrap();
            let mut old_child = Command::new("/usr/bin/true").spawn().unwrap();
            assert!(old_child.wait().unwrap().success());
            let mut browser = OwnedBrowser {
                child: OwnedChild(old_child),
                _profile: Arc::new(ProfileStorage::Persistent(profile)),
                executable: PathBuf::from("fixture-only"),
                comparison_started: false,
                owns_active_lease: true,
            };
            let mut replacement = None;
            let result = begin_comparison_with(&mut browser, |_, profile, _| {
                profile.begin_browser_use()?;
                let child = Command::new("/bin/sleep")
                    .arg("30")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                replacement = Some(OwnedChild(child));
                profile.record_browser_pid(replacement.as_ref().unwrap().id())?;
                // Model a durable-record failure after replacement and a stop
                // that cannot confirm exit. The real fixture child stays alive.
                Err(BrowserError::Profile(ProfileError::Io))
            });
            assert_eq!(result, Err(BrowserError::Profile(ProfileError::Io)));
            let session = BrowserSession {
                connection: None,
                target: None,
                browser_owner: Arc::new(Mutex::new(Some(browser))),
                cancellation_socket: Arc::new(Mutex::new(None)),
                cancelled: Arc::new(AtomicBool::new(false)),
            };
            let disconnected = if disconnect {
                Some(session.disconnect())
            } else {
                session.cancellation_handle().unwrap().cancel();
                drop(session);
                None
            };
            let retained = path.join(".ghost-chat-cleaner-browser-active").exists();
            let blocked = BrowserProfile::open_test(&root, "edge").is_err();
            let mut replacement = replacement.unwrap();
            let still_alive = replacement.try_wait().unwrap().is_none();
            // Always reap the synthetic child before reporting an assertion.
            replacement.kill().unwrap();
            replacement.wait().unwrap();
            assert!(still_alive);
            assert!(
                retained,
                "old child exit cannot clear a replacement browser lease"
            );
            assert!(
                blocked,
                "surviving replacement must prevent profile reopening"
            );
            if let Some(result) = disconnected {
                assert_eq!(
                    result,
                    Err(BrowserError::Profile(ProfileError::UnconfirmedExit))
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn persistent_comparison_restart_records_the_new_owned_pid() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("app-data");
        let profile = BrowserProfile::open_test(&root, "edge").unwrap();
        let path = profile.path().to_owned();
        let executable = temp.path().join("browser");
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let session = BrowserSession::start(
            executable.clone(),
            ProfileStorage::Persistent(profile),
            true,
        )
        .unwrap();
        let marker;
        let new_pid;
        {
            let mut owner = session.browser_owner.lock().unwrap();
            let browser = owner.as_mut().unwrap();
            let previous_pid = browser.child.id();
            assert!(browser.child.wait().unwrap().success());
            fs::write(&executable, "#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
            begin_comparison(browser).unwrap();
            new_pid = browser.child.id();
            assert_ne!(previous_pid, new_pid);
            marker = fs::read(path.join(".ghost-chat-cleaner-browser-active")).unwrap();
        }
        drop(session);
        assert_eq!(
            marker,
            format!("ghost-chat-cleaner/browser-active/v2\npid={new_pid}\n").as_bytes()
        );
        assert!(BrowserProfile::open_test(&root, "edge").is_ok());
    }

    #[test]
    fn restore_existing_unready_profile_attempts_browser_start() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().canonicalize().unwrap().join("app-data");
        let profile = BrowserProfile::open_test(&root, "edge").unwrap();
        assert!(!profile.is_ready().unwrap());
        let result = BrowserSession::restore_existing(
            fixture.path().join("nonexistent-browser-fixture"),
            Some(profile),
        );
        assert!(
            matches!(result, Err(BrowserError::LaunchFailed)),
            "an existing idle profile without a ready marker must reach browser startup"
        );
    }

    #[test]
    fn restore_existing_missing_profile_remains_disconnected() {
        let fixture = tempfile::tempdir().unwrap();
        let result = BrowserSession::restore_existing(
            fixture.path().join("nonexistent-browser-fixture"),
            None,
        );
        assert!(matches!(result, Ok(None)));
        assert_eq!(fs::read_dir(fixture.path()).unwrap().count(), 0);
    }

    #[test]
    fn restore_existing_rejects_a_malformed_ready_marker() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().canonicalize().unwrap().join("app-data");
        let profile = BrowserProfile::open_test(&root, "edge").unwrap();
        profile.mark_ready().unwrap();
        fs::write(profile.path().join(".ghost-chat-cleaner-ready"), "invalid").unwrap();
        let result = BrowserSession::restore_existing(
            fixture.path().join("nonexistent-browser-fixture"),
            Some(profile),
        );
        assert!(matches!(
            result,
            Err(BrowserError::Profile(ProfileError::InvalidMarker))
        ));
    }

    #[test]
    fn cancellation_releases_owned_child_and_profile_while_session_is_retained() {
        let (connection, server) = mock_connection(|mut socket| {
            let _ = socket.read();
        });
        let profile = tempfile::tempdir().unwrap();
        let profile_path = profile.path().to_owned();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "browser_transport::tests::owned_browser_fixture_process",
                "--ignored",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut child_output = child.stdout.take().unwrap();
        let (exited_tx, exited_rx) = std::sync::mpsc::channel();
        let output_reader = thread::spawn(move || {
            let _ = io::copy(&mut child_output, &mut io::sink());
            let _ = exited_tx.send(());
        });
        let session = BrowserSession {
            cancelled: Arc::clone(&connection.socket.get_ref().cancelled),
            cancellation_socket: Arc::new(Mutex::new(Some(
                connection.socket.get_ref().socket.try_clone().unwrap(),
            ))),
            connection: Some(connection),
            target: None,
            browser_owner: Arc::new(Mutex::new(Some(OwnedBrowser {
                child: OwnedChild(child),
                _profile: Arc::new(ProfileStorage::Temporary(profile)),
                executable: PathBuf::from("unused-fixture"),
                comparison_started: true,
                owns_active_lease: true,
            }))),
        };
        let cancellation = session.cancellation_handle().unwrap();
        let started = Instant::now();
        cancellation.cancel();
        let cancellation_time = started.elapsed();
        let profile_removed = !profile_path.exists();
        let child_exited = exited_rx.recv_timeout(Duration::from_millis(200)).is_ok();
        // Clean the synthetic fixture even when the regression assertion fails.
        drop(session);
        server.join().unwrap();
        output_reader.join().unwrap();
        assert!(
            profile_removed,
            "cancellation must clean the profile without waiting for the worker"
        );
        assert!(
            child_exited,
            "cancellation must stop the owned child while session is retained"
        );
        assert!(cancellation_time < Duration::from_secs(2));
        cancellation.cancel();
    }

    #[test]
    fn comparison_cannot_interrupt_interactive_login() {
        let profile = tempfile::tempdir().unwrap();
        let profile_path = profile.path().to_owned();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "browser_transport::tests::owned_browser_fixture_process",
                "--ignored",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut session = BrowserSession {
            connection: None,
            target: None,
            browser_owner: Arc::new(Mutex::new(Some(OwnedBrowser {
                child: OwnedChild(child),
                _profile: Arc::new(ProfileStorage::Temporary(profile)),
                executable: PathBuf::from("must-not-launch"),
                comparison_started: false,
                owns_active_lease: true,
            }))),
            cancellation_socket: Arc::new(Mutex::new(None)),
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        assert_eq!(
            session.evaluate("({})"),
            Err(BrowserError::LoginBrowserStillOpen)
        );
        assert!(profile_path.is_dir());
        assert!(session
            .browser_owner
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .child
            .try_wait()
            .unwrap()
            .is_none());
        session.cancellation_handle().unwrap().cancel();
        assert!(!profile_path.exists());
        assert_eq!(session.evaluate("({})"), Err(BrowserError::Closed));
    }

    #[cfg(unix)]
    fn login_handoff_fixture() -> (BrowserSession, std::process::ChildStdin) {
        let profile = tempfile::tempdir().unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", "read input; exit 0"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let session = BrowserSession {
            connection: None,
            target: None,
            browser_owner: Arc::new(Mutex::new(Some(OwnedBrowser {
                child: OwnedChild(child),
                _profile: Arc::new(ProfileStorage::Temporary(profile)),
                executable: PathBuf::from("must-not-launch"),
                comparison_started: false,
                owns_active_lease: true,
            }))),
            cancellation_socket: Arc::new(Mutex::new(None)),
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        (session, input)
    }

    #[cfg(unix)]
    #[test]
    fn comparison_exit_probe_ignores_the_initial_login_phase() {
        let (session, mut input) = login_handoff_fixture();
        assert_eq!(session.comparison_browser_closed(), Ok(false));
        input.write_all(b"finish\n").unwrap();
        assert!(session
            .browser_owner
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .child
            .wait()
            .unwrap()
            .success());
        assert_eq!(session.comparison_browser_closed(), Ok(false));
        assert!(
            !session
                .browser_owner
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .comparison_started
        );
    }

    #[cfg(unix)]
    fn timed_out_session_fixture(
        target_id: &str,
        target_url: &str,
    ) -> (
        BrowserSession,
        std::process::ChildStdin,
        Arc<std::sync::atomic::AtomicUsize>,
        thread::JoinHandle<Vec<String>>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = BrowserEndpoint {
            port: listener.local_addr().unwrap().port(),
            path: "/devtools/browser/retry-fixture".into(),
        };
        let targets =
            json!({"targetInfos":[{"type":"page","targetId":target_id,"url":target_url}]});
        let connections = Arc::new(AtomicUsize::new(0));
        let observed_connections = Arc::clone(&connections);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut socket = tungstenite::accept(stream).unwrap();
            observed_connections.fetch_add(1, Ordering::SeqCst);
            // The expired command shuts down the original connection.
            let _ = socket.read();
            drop(socket);
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Vec::new();
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("synthetic accept failed: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut socket = tungstenite::accept(stream).unwrap();
            observed_connections.fetch_add(1, Ordering::SeqCst);
            let mut methods = Vec::new();
            let mut target_reads = 0;
            while let Ok(message) = socket.read() {
                let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                let method = request["method"].as_str().unwrap();
                methods.push(method.to_owned());
                let result = match method {
                    "Target.getTargets" => {
                        target_reads += 1;
                        targets.clone()
                    }
                    "Target.attachToTarget" => {
                        assert_eq!(request["params"]["targetId"], "pinned-tab");
                        json!({"sessionId":"fresh-session"})
                    }
                    "Runtime.evaluate" => {
                        assert_eq!(request["sessionId"], "fresh-session");
                        if request["params"]["expression"]
                            .as_str()
                            .unwrap()
                            .contains("readyState")
                        {
                            json!({"result":{"value":{"origin":"https://chatgpt.com","top":true,"readyState":"complete","aboutBlank":false}}})
                        } else {
                            json!({"result":{"value":{"safe":true}}})
                        }
                    }
                    "Browser.close" => break,
                    _ => panic!("unexpected synthetic command"),
                };
                let mut response = json!({"id":request["id"],"result":result});
                if let Some(session_id) = request.get("sessionId") {
                    response["sessionId"] = session_id.clone();
                }
                socket
                    .send(Message::Text(response.to_string().into()))
                    .unwrap();
                if target_reads == 2 {
                    break;
                }
            }
            methods
        });
        let (mut session, input) = login_handoff_fixture();
        let mut connection = CdpConnection::connect(
            &endpoint,
            Instant::now() + Duration::from_secs(2),
            Arc::clone(&session.cancelled),
        )
        .unwrap();
        {
            let mut owner = session.browser_owner.lock().unwrap();
            let browser = owner.as_mut().unwrap();
            browser.comparison_started = true;
            fs::write(
                browser._profile.path().join("DevToolsActivePort"),
                format!("{}\n{}\n", endpoint.port, endpoint.path),
            )
            .unwrap();
        }
        assert_eq!(
            connection.command(
                "Target.getTargets",
                json!({}),
                None,
                Instant::now() - Duration::from_millis(1)
            ),
            Err(BrowserError::TimedOut)
        );
        assert!(!connection.healthy);
        session.connection = Some(connection);
        session.target = Some(AttachedTarget {
            target_id: "pinned-tab".into(),
            session_id: Some("old-session".into()),
        });
        (session, input, connections, server)
    }

    #[cfg(unix)]
    #[test]
    fn explicit_retry_reconnects_same_browser_and_reattaches_pinned_target() {
        use std::sync::atomic::Ordering;
        let (mut session, _input, connections, server) =
            timed_out_session_fixture("pinned-tab", "https://chatgpt.com/");
        let pid = session
            .browser_owner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .child
            .id();
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        let result = session.evaluate("Promise.resolve({safe:true})");
        let same_pid = session
            .browser_owner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .child
            .id()
            == pid;
        let target_id = session.target.as_ref().unwrap().target_id.clone();
        drop(session);
        let methods = server.join().unwrap();
        assert_eq!(
            result,
            Ok(json!({"safe":true})),
            "connections={}, methods={methods:?}",
            connections.load(Ordering::SeqCst)
        );
        assert!(same_pid);
        assert_eq!(target_id, "pinned-tab");
        assert_eq!(connections.load(Ordering::SeqCst), 2);
        assert_eq!(
            methods
                .iter()
                .filter(|method| *method == "Target.attachToTarget")
                .count(),
            1
        );
        assert_eq!(
            methods
                .iter()
                .filter(|method| *method == "Runtime.evaluate")
                .count(),
            2
        );
    }

    #[cfg(unix)]
    #[test]
    fn explicit_retry_never_switches_a_missing_or_foreign_pinned_target() {
        for (target_id, url) in [
            ("different-tab", "https://chatgpt.com/"),
            ("pinned-tab", "https://example.invalid/"),
        ] {
            let (mut session, _input, _, server) = timed_out_session_fixture(target_id, url);
            let result = session.evaluate("Promise.resolve({safe:true})");
            drop(session);
            let methods = server.join().unwrap();
            assert_eq!(result, Err(BrowserError::TargetChanged));
            assert!(!methods
                .iter()
                .any(|method| method == "Runtime.evaluate" || method == "Target.attachToTarget"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn explicit_retry_requires_the_same_living_owned_browser() {
        use std::sync::atomic::Ordering;
        for cancelled in [false, true] {
            let (mut session, mut input, connections, server) =
                timed_out_session_fixture("pinned-tab", "https://chatgpt.com/");
            if cancelled {
                session.cancellation_handle().unwrap().cancel();
            } else {
                input.write_all(b"finish\n").unwrap();
                session
                    .browser_owner
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .child
                    .wait()
                    .unwrap();
            }
            assert!(session.evaluate("Promise.resolve({safe:true})").is_err());
            drop(session);
            assert!(server.join().unwrap().is_empty());
            assert_eq!(connections.load(Ordering::SeqCst), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn comparison_exit_probe_detects_exit_without_reopening_or_changing_profile() {
        for normal_exit in [true, false] {
            let (session, mut input) = login_handoff_fixture();
            let (pid, profile_path) = {
                let mut owner = session.browser_owner.lock().unwrap();
                let browser = owner.as_mut().unwrap();
                browser.comparison_started = true;
                (browser.child.id(), browser._profile.path().to_owned())
            };
            fs::write(profile_path.join("fixture-marker"), b"retained").unwrap();
            assert_eq!(session.comparison_browser_closed(), Ok(false));
            if normal_exit {
                input.write_all(b"finish\n").unwrap();
            } else {
                session
                    .browser_owner
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .child
                    .kill()
                    .unwrap();
            }
            let status = session
                .browser_owner
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .child
                .wait()
                .unwrap();
            assert_eq!(status.success(), normal_exit);
            for _ in 0..2 {
                assert_eq!(session.comparison_browser_closed(), Ok(true));
                assert!(session.connection.is_none());
                let owner = session.browser_owner.lock().unwrap();
                let browser = owner.as_ref().unwrap();
                assert_eq!(browser.child.id(), pid);
                assert!(browser.comparison_started);
                assert!(browser.owns_active_lease);
                assert_eq!(
                    fs::read(profile_path.join("fixture-marker")).unwrap(),
                    b"retained"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn comparison_exit_probe_reports_cancellation_as_closed() {
        let (session, _input) = login_handoff_fixture();
        session.cancellation_handle().unwrap().cancel();
        assert_eq!(
            session.comparison_browser_closed(),
            Err(BrowserError::Closed)
        );
    }

    #[cfg(unix)]
    #[test]
    fn finish_login_waits_for_owned_child_normal_exit() {
        let (session, mut input) = login_handoff_fixture();
        let (unrelated, _unrelated_input) = login_handoff_fixture();
        let expected_pid = session
            .browser_owner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .child
            .id();
        assert_eq!(
            finish_login(
                &session.browser_owner,
                |pid| {
                    assert_eq!(pid, expected_pid);
                    input.write_all(b"finish\n").unwrap();
                    true
                },
                Instant::now() + Duration::from_secs(2)
            ),
            Ok(())
        );
        let mut owner = session.browser_owner.lock().unwrap();
        let browser = owner.as_mut().unwrap();
        assert!(browser.child.try_wait().unwrap().unwrap().success());
        assert!(!browser.comparison_started);
        assert!(browser._profile.path().is_dir());
        assert!(unrelated
            .browser_owner
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .child
            .try_wait()
            .unwrap()
            .is_none());
    }

    #[cfg(unix)]
    #[test]
    fn finish_login_does_not_force_quit_on_refusal_or_timeout() {
        for accepted in [false, true] {
            let (session, _input) = login_handoff_fixture();
            let started = Instant::now();
            assert_eq!(
                finish_login(
                    &session.browser_owner,
                    |_| accepted,
                    started + Duration::from_millis(50)
                ),
                Err(BrowserError::LoginBrowserStillOpen)
            );
            assert!(started.elapsed() < Duration::from_secs(1));
            let mut owner = session.browser_owner.lock().unwrap();
            let browser = owner.as_mut().unwrap();
            assert!(browser.child.try_wait().unwrap().is_none());
            assert!(!browser.comparison_started);
            assert!(browser._profile.path().is_dir());
        }
    }

    #[cfg(unix)]
    #[test]
    fn finish_login_does_not_request_quit_after_normal_exit_or_cancellation() {
        let (session, mut input) = login_handoff_fixture();
        input.write_all(b"finish\n").unwrap();
        session
            .browser_owner
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .child
            .wait()
            .unwrap();
        assert_eq!(
            finish_login(
                &session.browser_owner,
                |_| panic!("already exited"),
                Instant::now() + Duration::from_secs(2)
            ),
            Ok(())
        );
        session.cancellation_handle().unwrap().cancel();
        assert_eq!(
            finish_login(
                &session.browser_owner,
                |_| panic!("ownership cancelled"),
                Instant::now() + Duration::from_secs(2)
            ),
            Err(BrowserError::Closed)
        );
    }

    #[cfg(unix)]
    #[test]
    fn finish_login_cancellation_interrupts_wait_without_restarting() {
        let (session, _input) = login_handoff_fixture();
        let cancellation = session.cancellation_handle().unwrap();
        let (requested_tx, requested_rx) = std::sync::mpsc::channel();
        let operation = thread::spawn(move || {
            finish_login(
                &session.browser_owner,
                |_| {
                    requested_tx.send(()).unwrap();
                    true
                },
                Instant::now() + Duration::from_secs(2),
            )
        });
        requested_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        cancellation.cancel();
        assert_eq!(operation.join().unwrap(), Err(BrowserError::Closed));
    }

    #[cfg(unix)]
    #[test]
    fn comparison_restarts_only_after_clean_exit_and_keeps_the_login_profile() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = tempfile::tempdir().unwrap();
        let executable = fixture.path().join("browser");
        fs::write(&executable, "#!/bin/sh\nfor arg in \"$@\"; do\n case \"$arg\" in --user-data-dir=*) profile=${arg#--user-data-dir=};; esac\ndone\ntest -f \"$profile/login-marker\" || exit 3\ntest ! -e \"$profile/DevToolsActivePort\" || exit 4\nprintf '%s\\n' \"$@\" > \"$profile/restart-args\"\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let profile = tempfile::tempdir().unwrap();
        fs::write(profile.path().join("login-marker"), "synthetic-only").unwrap();
        fs::write(profile.path().join("DevToolsActivePort"), "stale").unwrap();
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        assert!(child.wait().unwrap().success());
        let mut owned = OwnedBrowser {
            child: OwnedChild(child),
            _profile: Arc::new(ProfileStorage::Temporary(profile)),
            executable,
            comparison_started: false,
            owns_active_lease: true,
        };
        begin_comparison(&mut owned).unwrap();
        assert!(owned.child.wait().unwrap().success());
        let args = fs::read_to_string(owned._profile.path().join("restart-args")).unwrap();
        assert!(args.contains("--remote-debugging-port=0\n"));
        assert!(args.contains(&format!(
            "--user-data-dir={}\n",
            owned._profile.path().display()
        )));
        assert!(owned._profile.path().join("login-marker").exists());

        let mut child = Command::new("/usr/bin/false").spawn().unwrap();
        assert!(!child.wait().unwrap().success());
        owned.child = OwnedChild(child);
        owned.comparison_started = false;
        assert_eq!(
            begin_comparison(&mut owned),
            Err(BrowserError::LoginInterrupted)
        );
        assert!(!owned.comparison_started);
    }

    #[test]
    fn too_many_events_close_the_connection_without_a_result() {
        let (mut connection, server) = mock_connection(|mut socket| {
            let _ = socket.read().unwrap();
            for _ in 0..=MAX_RESPONSE_MESSAGES {
                if socket
                    .send(Message::Text(
                        json!({"method":"Target.targetInfoChanged"})
                            .to_string()
                            .into(),
                    ))
                    .is_err()
                {
                    break;
                }
            }
        });
        assert_eq!(
            connection.command(
                "Target.getTargets",
                json!({}),
                None,
                Instant::now() + Duration::from_secs(2)
            ),
            Err(BrowserError::ResponseLimit)
        );
        assert!(!connection.healthy);
        server.join().unwrap();
    }

    #[test]
    fn oversized_frame_cannot_enter_a_json_response() {
        let (mut connection, server) = mock_connection(|mut socket| {
            let _ = socket.read().unwrap();
            let _ = socket.send(Message::Text("x".repeat(MAX_MESSAGE_BYTES + 1).into()));
        });
        assert_eq!(
            connection.command(
                "Target.getTargets",
                json!({}),
                None,
                Instant::now() + Duration::from_secs(2)
            ),
            Err(BrowserError::ResponseLimit)
        );
        server.join().unwrap();
    }

    #[test]
    fn target_selection_does_not_switch_to_another_tab() {
        let targets = json!({"targetInfos":[
            {"targetId":"selected","type":"page","url":"https://example.org/"},
            {"targetId":"other","type":"page","url":"https://chatgpt.com/"},
            {"targetId":"worker","type":"worker","url":"https://chatgpt.com/"}
        ]});
        assert_eq!(
            select_chatgpt_target(&targets, Some("selected")),
            Err(BrowserError::TargetChanged)
        );
        assert_eq!(
            select_chatgpt_target(&targets, None),
            Ok("other".to_owned())
        );
        let ambiguous = json!({"targetInfos":[
            {"targetId":"one","type":"page","url":"https://chatgpt.com/"},
            {"targetId":"two","type":"page","url":"https://chatgpt.com/"}
        ]});
        assert_eq!(
            select_chatgpt_target(&ambiguous, None),
            Err(BrowserError::AmbiguousTarget)
        );
    }

    #[test]
    fn evaluation_waits_for_committed_ready_context_before_running_collector() {
        let target =
            json!({"targetInfos":[{"targetId":"page","type":"page","url":"https://chatgpt.com/"}]});
        let blank_target =
            json!({"targetInfos":[{"targetId":"page","type":"page","url":"about:blank"}]});
        let foreign_target =
            json!({"targetInfos":[{"targetId":"page","type":"page","url":"https://example.org/"}]});
        let ready = json!({"origin":"https://chatgpt.com","top":true,"readyState":"interactive","aboutBlank":false});
        let blank = json!({"origin":"null","top":true,"readyState":"complete","aboutBlank":true});
        let loading = json!({"origin":"https://chatgpt.com","top":true,"readyState":"loading","aboutBlank":false});
        let foreign = json!({"origin":"https://example.org","top":true,"readyState":"complete","aboutBlank":false});
        let frame = json!({"origin":"https://chatgpt.com","top":false,"readyState":"complete","aboutBlank":false});
        let cases = [
            (
                vec![target.clone()],
                vec![blank.clone(), loading, ready.clone()],
                false,
                Ok(json!({"safe":true})),
                1,
            ),
            (
                vec![target.clone()],
                vec![foreign],
                false,
                Err(BrowserError::TargetChanged),
                0,
            ),
            (
                vec![target.clone()],
                vec![frame],
                false,
                Err(BrowserError::TargetChanged),
                0,
            ),
            (
                vec![json!({"targetInfos":[]}), blank_target, target.clone()],
                vec![ready.clone()],
                false,
                Ok(json!({"safe":true})),
                1,
            ),
            (
                vec![foreign_target.clone()],
                vec![ready.clone()],
                false,
                Err(BrowserError::NoChatGptTarget),
                0,
            ),
            (
                vec![target.clone(), foreign_target],
                vec![blank.clone()],
                false,
                Err(BrowserError::TargetChanged),
                0,
            ),
            (
                vec![target.clone()],
                vec![blank],
                false,
                Err(BrowserError::PageNotReady),
                0,
            ),
            (
                vec![target],
                vec![ready],
                true,
                Err(BrowserError::TargetChanged),
                1,
            ),
        ];
        for (targets, states, changed_during_collection, expected, expected_collections) in cases {
            // Readiness success tests ordering, not a subsecond performance limit.
            // Only the permanently blank case intentionally exhausts its deadline.
            let timeout = if expected == Err(BrowserError::PageNotReady) {
                Duration::from_millis(350)
            } else {
                Duration::from_secs(5)
            };
            let collections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed_collections = Arc::clone(&collections);
            let slow_startup = expected.is_ok();
            let (mut connection, server) = mock_connection(move |mut socket| {
                let mut target_queries = 0;
                let mut probes = 0;
                while let Ok(Message::Text(text)) = socket.read() {
                    let request: Value = serde_json::from_str(&text).unwrap();
                    let result = match request["method"].as_str().unwrap() {
                        "Target.getTargets" => {
                            let result = targets[target_queries.min(targets.len() - 1)].clone();
                            target_queries += 1;
                            result
                        }
                        "Target.attachToTarget" => json!({"sessionId":"session"}),
                        "Runtime.evaluate" => {
                            let expression = request["params"]["expression"].as_str().unwrap();
                            if expression.contains("trustedCollectorFixture") {
                                observed_collections
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                if probes < states.len() || changed_during_collection {
                                    json!({"exceptionDetails":{"exception":{"className":"Error","description":if probes < states.len() { "Error: context not ready" } else { "Error: changed origin" }}}})
                                } else {
                                    json!({"result":{"value":{"safe":true}}})
                                }
                            } else {
                                assert!(expression.contains("document.readyState"));
                                assert!(!expression.contains("fetch("));
                                let value = states[probes.min(states.len() - 1)].clone();
                                probes += 1;
                                json!({"result":{"value":value}})
                            }
                        }
                        _ => panic!("unexpected method"),
                    };
                    let mut response = json!({"id":request["id"],"result":result});
                    if let Some(session) = request.get("sessionId") {
                        response["sessionId"] = session.clone();
                    }
                    if slow_startup {
                        // Exercise readiness ordering with nontrivial IPC latency.
                        thread::sleep(Duration::from_millis(60));
                    }
                    if socket
                        .send(Message::Text(response.to_string().into()))
                        .is_err()
                    {
                        break;
                    }
                }
            });
            let deadline = Instant::now() + timeout;
            let result = evaluate_on_target(
                &mut connection,
                &mut None,
                "({trustedCollectorFixture:true})",
                deadline,
            );
            let deadline_expired = Instant::now() >= deadline;
            drop(connection);
            server.join().unwrap();
            if expected == Err(BrowserError::PageNotReady) {
                // The absolute deadline may expire in a readiness RPC or its
                // retry pause. Both must stop before the collector can run.
                assert!(
                    deadline_expired,
                    "blank context must retain its readiness window"
                );
                assert!(
                    matches!(
                        result,
                        Err(BrowserError::PageNotReady | BrowserError::TimedOut)
                    ),
                    "unexpected readiness failure: {result:?}"
                );
            } else {
                assert_eq!(result, expected);
            }
            assert_eq!(
                collections.load(std::sync::atomic::Ordering::SeqCst),
                expected_collections
            );
        }
    }

    #[test]
    fn elapsed_readiness_pause_reports_page_not_ready() {
        assert_eq!(
            readiness_pause(Instant::now() - Duration::from_millis(1)),
            Err(BrowserError::PageNotReady)
        );
    }

    #[test]
    fn silent_readiness_request_times_out_without_selecting_or_collecting() {
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (mut connection, server) = mock_connection(move |mut socket| {
            let request: Value =
                serde_json::from_str(socket.read().unwrap().to_text().unwrap()).unwrap();
            request_tx
                .send(request["method"].as_str().unwrap().to_owned())
                .unwrap();
            let _ = release_rx.recv();
        });
        let mut target = None;
        let deadline = Instant::now() + Duration::from_millis(350);
        let result = evaluate_on_target(
            &mut connection,
            &mut target,
            "({trustedCollectorFixture:true})",
            deadline,
        );
        let deadline_expired = Instant::now() >= deadline;
        let request = request_rx.recv_timeout(Duration::from_secs(2));
        release_tx.send(()).unwrap();
        drop(connection);
        server.join().unwrap();
        assert_eq!(result, Err(BrowserError::TimedOut));
        assert!(deadline_expired);
        assert!(target.is_none());
        assert_eq!(request.as_deref(), Ok("Target.getTargets"));
    }

    #[test]
    fn evaluation_uses_flattened_session_and_rechecks_origin_before_returning() {
        for moved in [false, true] {
            let (mut connection, server) = mock_connection(move |mut socket| {
                for step in 0..5 {
                    let request: Value =
                        serde_json::from_str(socket.read().unwrap().to_text().unwrap()).unwrap();
                    let result = match step {
                        0 => {
                            assert_eq!(request["method"], "Target.getTargets");
                            json!({"targetInfos":[{"targetId":"page","type":"page","url":"https://chatgpt.com/"}]})
                        }
                        1 => {
                            assert_eq!(request["method"], "Target.attachToTarget");
                            assert_eq!(
                                request["params"],
                                json!({"targetId":"page","flatten":true})
                            );
                            json!({"sessionId":"session"})
                        }
                        2 => {
                            assert_eq!(request["method"], "Runtime.evaluate");
                            json!({"result":{"value":{"origin":"https://chatgpt.com","top":true,"readyState":"complete","aboutBlank":false}}})
                        }
                        3 => {
                            assert_eq!(request["method"], "Runtime.evaluate");
                            assert_eq!(request["sessionId"], "session");
                            assert_eq!(request["params"]["awaitPromise"], true);
                            assert_eq!(request["params"]["returnByValue"], true);
                            let expression = request["params"]["expression"].as_str().unwrap();
                            assert!(expression.contains("location.origin!=='https://chatgpt.com'"));
                            json!({"result":{"type":"object","value":{"safe":true}}})
                        }
                        _ => {
                            assert_eq!(request["method"], "Target.getTargets");
                            json!({"targetInfos":[{"targetId":"page","type":"page","url":if moved {"https://example.org/"} else {"https://chatgpt.com/"}}]})
                        }
                    };
                    let mut response = json!({"id":request["id"],"result":result});
                    if let Some(session) = request.get("sessionId") {
                        response["sessionId"] = session.clone();
                    }
                    socket
                        .send(Message::Text(response.to_string().into()))
                        .unwrap();
                }
            });
            let result = evaluate_on_target(
                &mut connection,
                &mut None,
                "({safe:true})",
                Instant::now() + Duration::from_secs(2),
            );
            assert_eq!(
                result,
                if moved {
                    Err(BrowserError::TargetChanged)
                } else {
                    Ok(json!({"safe":true}))
                }
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn evaluation_exceptions_expose_only_static_diagnostics() {
        const PRIVATE_DETAIL: &str = "synthetic-private-token-do-not-display";
        let cases = [
            ("Error", PRIVATE_DETAIL, "EvaluationFailed"),
            ("Error", "Error: wrong origin suffix", "EvaluationFailed"),
            ("OtherError", "Error: wrong origin", "EvaluationFailed"),
            ("Error", "Error: wrong origin", "PageNotReady"),
            ("Error", "Error: changed origin", "TargetChanged"),
            ("SyntaxError", PRIVATE_DETAIL, "SyntaxError"),
            ("ReferenceError", PRIVATE_DETAIL, "ReferenceError"),
            ("TypeError", PRIVATE_DETAIL, "TypeError"),
        ];
        for (class, first_line, expected) in cases {
            let (mut connection, server) = mock_connection(move |mut socket| {
                for step in 0..4 {
                    let request: Value =
                        serde_json::from_str(socket.read().unwrap().to_text().unwrap()).unwrap();
                    let result = match step {
                        0 => {
                            json!({"targetInfos":[{"targetId":"page","type":"page","url":"https://chatgpt.com/"}]})
                        }
                        1 => json!({"sessionId":"session"}),
                        2 => {
                            json!({"result":{"value":{"origin":"https://chatgpt.com","top":true,"readyState":"complete","aboutBlank":false}}})
                        }
                        _ => {
                            assert_eq!(request["method"], "Runtime.evaluate");
                            json!({"exceptionDetails":{"text":"Uncaught","exception":{
                                "type":"object","subtype":"error","className":class,
                                "description":format!("{first_line}\n    at {PRIVATE_DETAIL}")
                            }}})
                        }
                    };
                    let mut response = json!({"id":request["id"],"result":result});
                    if let Some(session) = request.get("sessionId") {
                        response["sessionId"] = session.clone();
                    }
                    socket
                        .send(Message::Text(response.to_string().into()))
                        .unwrap();
                }
            });
            let error = evaluate_on_target(
                &mut connection,
                &mut None,
                "({safe:true})",
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap_err();
            server.join().unwrap();
            assert!(!error.to_string().contains(PRIVATE_DETAIL));
            assert!(!format!("{error:?}").contains(PRIVATE_DETAIL));
            assert_eq!(format!("{error:?}"), expected);
        }
    }

    #[test]
    fn collector_for_ten_thousand_ids_fits_transport_request() {
        let ids = (0..10_000)
            .map(|id| format!("11111111-1111-4111-8111-{id:012x}"))
            .collect::<Vec<_>>();
        let expression = format!(
            "(async () => {{ {}; return await collectChatMetadata({}); }})()",
            include_str!("../assets/web/collect.js"),
            serde_json::to_string(&ids).unwrap()
        );
        let (mut connection, server) = mock_connection(|mut socket| {
            for step in 0..5 {
                let Ok(Message::Text(text)) = socket.read() else {
                    return;
                };
                let request: Value = serde_json::from_str(&text).unwrap();
                let result = match step {
                    0 | 4 => {
                        json!({"targetInfos":[{"targetId":"page","type":"page","url":"https://chatgpt.com/"}]})
                    }
                    1 => json!({"sessionId":"session"}),
                    2 => {
                        json!({"result":{"value":{"origin":"https://chatgpt.com","top":true,"readyState":"complete","aboutBlank":false}}})
                    }
                    _ => {
                        let sent = request["params"]["expression"].as_str().unwrap();
                        assert!(sent.contains("11111111-1111-4111-8111-00000000270f"));
                        json!({"result":{"type":"object","value":{"safe":true}}})
                    }
                };
                let mut response = json!({"id":request["id"],"result":result});
                if let Some(session) = request.get("sessionId") {
                    response["sessionId"] = session.clone();
                }
                socket
                    .send(Message::Text(response.to_string().into()))
                    .unwrap();
            }
        });
        let result = evaluate_on_target(
            &mut connection,
            &mut None,
            &expression,
            Instant::now() + Duration::from_secs(2),
        );
        drop(connection);
        server.join().unwrap();
        assert_eq!(result, Ok(json!({"safe":true})));
    }

    #[test]
    fn active_port_accepts_only_a_port_and_browser_path() {
        assert_eq!(
            parse_active_port("43210\n/devtools/browser/01234567-abcd\n"),
            Ok(BrowserEndpoint {
                port: 43210,
                path: "/devtools/browser/01234567-abcd".to_owned(),
            })
        );
        for invalid in [
            "0\n/devtools/browser/id",
            "65536\n/devtools/browser/id",
            "43210\nws://remote.example/devtools/browser/id",
            "43210\n//remote.example/devtools/browser/id",
            "43210\n/devtools/page/id",
            "43210\n/devtools/browser/",
            "43210\n/devtools/browser/id?redirect=elsewhere",
            "43210\n/devtools/browser/../page/id",
            "43210\n/devtools/browser/id\nextra",
        ] {
            assert!(parse_active_port(invalid).is_err());
        }
    }

    #[test]
    fn target_url_requires_exact_chatgpt_https_origin() {
        for valid in [
            "https://chatgpt.com",
            "https://chatgpt.com/",
            "https://chatgpt.com/c/id",
        ] {
            assert!(chatgpt_url_is_allowed(valid));
        }
        for invalid in [
            "http://chatgpt.com/",
            "https://chatgpt.com.evil.example/",
            "https://chatgpt.com@evil.example/",
            "https://evil.example/chatgpt.com",
            "https://chatgpt.com:8443/",
            "devtools://devtools/",
            "https://chatgpt.com\\@evil.example/",
        ] {
            assert!(!chatgpt_url_is_allowed(invalid));
        }
    }
}
