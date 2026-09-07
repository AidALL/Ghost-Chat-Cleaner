use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use crate::app_state::{AppError, JobEvent, JobId, RunMode};
use crate::browser_transport::{BrowserCancellation, BrowserError, BrowserSession};
use crate::catalog::scan_catalog;
use crate::evidence::EvidenceScanConfig;
use crate::i18n::Language;
use crate::model::{ScanReport, ThreadIdentity};
use crate::platform::{discover_catalog_paths, CatalogPathInputs, PlatformPolicy};
use crate::process_guard::{ProcessProbe, SysinfoProcessProbe};
use crate::repair::{repair, RepairError, RepairRequest, RepairSelection};
use crate::web::WebComparison;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanInputs {
    pub database_path: String,
    pub log_roots: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerRequest {
    pub kind: WorkerRequestKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerRequestKind {
    OpenBrowser,
    RestoreBrowser,
    CheckLoginWindow,
    CheckBrowserWindow,
    AuthenticateBrowser,
    DisconnectBrowser,
    CompareWeb {
        report: ScanReport,
    },
    Discover {
        inputs: CatalogPathInputs,
    },
    Scan {
        database_path: PathBuf,
        log_roots: Vec<PathBuf>,
        platform: PlatformPolicy,
    },
    CheckProcess,
    Repair {
        report: ScanReport,
        log_roots: Vec<PathBuf>,
        selected: Vec<RepairSelection>,
        backup_directory: PathBuf,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerInputError {
    MissingDatabasePath,
    MissingBackupDirectory,
    MissingSelection,
}

impl WorkerInputError {
    pub fn message_for(&self, language: Language) -> &'static str {
        match self {
            Self::MissingDatabasePath => language.text(
                "대화 목록 파일 경로를 입력해야 함",
                "Enter the conversation catalog path",
            ),
            Self::MissingBackupDirectory => {
                language.text("백업 폴더 경로를 입력해야 함", "Enter a backup folder path")
            }
            Self::MissingSelection => language.text(
                "정리할 대화를 하나 이상 선택해야 함",
                "Select at least one conversation to clean up",
            ),
        }
    }
}

impl fmt::Display for WorkerInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDatabasePath => formatter.write_str("database path is required"),
            Self::MissingBackupDirectory => formatter.write_str("backup directory is required"),
            Self::MissingSelection => formatter.write_str("at least one thread must be selected"),
        }
    }
}

impl std::error::Error for WorkerInputError {}

impl WorkerRequest {
    pub fn restore_browser() -> Self {
        Self {
            kind: WorkerRequestKind::RestoreBrowser,
        }
    }

    pub fn check_login_window() -> Self {
        Self {
            kind: WorkerRequestKind::CheckLoginWindow,
        }
    }

    pub fn check_browser_window() -> Self {
        Self {
            kind: WorkerRequestKind::CheckBrowserWindow,
        }
    }

    pub fn authenticate_browser() -> Self {
        Self {
            kind: WorkerRequestKind::AuthenticateBrowser,
        }
    }

    pub fn disconnect_browser() -> Self {
        Self {
            kind: WorkerRequestKind::DisconnectBrowser,
        }
    }

    pub fn open_browser() -> Self {
        Self {
            kind: WorkerRequestKind::OpenBrowser,
        }
    }

    pub fn compare_web(report: ScanReport) -> Self {
        Self {
            kind: WorkerRequestKind::CompareWeb { report },
        }
    }
    pub fn discover(inputs: CatalogPathInputs) -> Self {
        Self {
            kind: WorkerRequestKind::Discover { inputs },
        }
    }

    pub fn scan(inputs: ScanInputs, platform: PlatformPolicy) -> Result<Self, WorkerInputError> {
        let database_path = inputs.database_path.trim();
        if database_path.is_empty() {
            return Err(WorkerInputError::MissingDatabasePath);
        }
        let log_roots = inputs
            .log_roots
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(PathBuf::from)
            .collect();
        Ok(Self {
            kind: WorkerRequestKind::Scan {
                database_path: PathBuf::from(database_path),
                log_roots,
                platform,
            },
        })
    }

    pub fn check_process() -> Self {
        Self {
            kind: WorkerRequestKind::CheckProcess,
        }
    }

    pub fn repair(
        report: ScanReport,
        log_roots_input: &str,
        selected: &HashSet<ThreadIdentity>,
        reviewed: &HashSet<ThreadIdentity>,
        backup_directory_input: &str,
    ) -> Result<Self, WorkerInputError> {
        if selected.is_empty() {
            return Err(WorkerInputError::MissingSelection);
        }
        let backup_directory = backup_directory_input.trim();
        if backup_directory.is_empty() {
            return Err(WorkerInputError::MissingBackupDirectory);
        }

        let mut identities = selected.iter().cloned().collect::<Vec<_>>();
        identities.sort_by(|left, right| {
            (&left.host_id, &left.thread_id).cmp(&(&right.host_id, &right.thread_id))
        });
        let selected = identities
            .into_iter()
            .map(|identity| {
                let review_authorized = reviewed.contains(&identity);
                RepairSelection::new(identity, review_authorized)
            })
            .collect();

        Ok(Self {
            kind: WorkerRequestKind::Repair {
                report,
                log_roots: parse_log_roots(log_roots_input),
                selected,
                backup_directory: PathBuf::from(backup_directory),
            },
        })
    }
}

pub fn backend_for_mode<T, F>(mode: RunMode, create_live: F) -> Option<T>
where
    F: FnOnce() -> T,
{
    match mode {
        RunMode::Live => Some(create_live()),
        RunMode::Demo => None,
    }
}

#[derive(Debug)]
struct QueuedRequest {
    job_id: JobId,
    request: WorkerRequest,
}

#[derive(Debug)]
pub struct WorkerDisconnected;

impl fmt::Display for WorkerDisconnected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("background worker is unavailable")
    }
}

impl std::error::Error for WorkerDisconnected {}

pub struct LiveWorker {
    requests: Option<Sender<QueuedRequest>>,
    events: Receiver<JobEvent>,
    join: Option<JoinHandle<()>>,
    cancelled: Arc<AtomicBool>,
    browser_cancellation: Arc<Mutex<Option<BrowserCancellation>>>,
}

impl LiveWorker {
    pub fn spawn(repaint: impl Fn() + Send + 'static) -> io::Result<Self> {
        let (request_tx, request_rx) = mpsc::channel::<QueuedRequest>();
        let (event_tx, event_rx) = mpsc::channel::<JobEvent>();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let browser_cancellation = Arc::new(Mutex::new(None));
        let worker_browser_cancellation = Arc::clone(&browser_cancellation);
        let join = thread::Builder::new()
            .name("ghost-chat-cleaner-worker".to_owned())
            .spawn(move || {
                let mut browser = None;
                run_worker_loop(
                    request_rx,
                    event_tx,
                    &worker_cancelled,
                    |id, request| {
                        execute(
                            id,
                            request,
                            &mut browser,
                            &worker_browser_cancellation,
                            &worker_cancelled,
                        )
                    },
                    repaint,
                );
            })?;
        Ok(Self {
            requests: Some(request_tx),
            events: event_rx,
            join: Some(join),
            cancelled,
            browser_cancellation,
        })
    }

    pub fn submit(&self, job_id: JobId, request: WorkerRequest) -> Result<(), WorkerDisconnected> {
        self.requests
            .as_ref()
            .ok_or(WorkerDisconnected)?
            .send(QueuedRequest { job_id, request })
            .map_err(|_| WorkerDisconnected)
    }

    pub fn try_recv(&self) -> Result<Option<JobEvent>, WorkerDisconnected> {
        match self.events.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(WorkerDisconnected),
        }
    }

    /// Stops queued work and releases the UI without waiting for an active request.
    ///
    /// A scanner already executing inside the synchronous core cannot be forcibly
    /// interrupted. Its detached thread finishes the call when the process remains
    /// alive; normal process exit terminates that thread with the process.
    pub fn shutdown(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Ok(mut handle) = self.browser_cancellation.lock() {
            if let Some(handle) = handle.take() {
                handle.cancel();
            }
        }
        self.requests.take();
        if let Some(join) = self.join.take() {
            // Cancellation wakes any pending browser socket read, allowing its
            // owned child to close before app exit. The saved app-owned login
            // profile is retained until an explicit Disconnect request.
            let deadline = Instant::now() + std::time::Duration::from_secs(2);
            while !join.is_finished() && Instant::now() < deadline {
                thread::sleep(std::time::Duration::from_millis(10));
            }
            if join.is_finished() {
                let _ = join.join();
            }
        }
    }
}

impl Drop for LiveWorker {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn run_worker_loop(
    requests: Receiver<QueuedRequest>,
    events: Sender<JobEvent>,
    cancelled: &AtomicBool,
    mut execute_request: impl FnMut(JobId, WorkerRequest) -> JobEvent,
    mut repaint: impl FnMut(),
) {
    while let Ok(queued) = requests.recv() {
        if cancelled.load(Ordering::Acquire) {
            break;
        }
        let event = execute_request(queued.job_id, queued.request);
        if events.send(event).is_err() {
            break;
        }
        repaint();
        if cancelled.load(Ordering::Acquire) {
            break;
        }
    }
}

fn execute(
    job_id: JobId,
    request: WorkerRequest,
    browser: &mut Option<BrowserSession>,
    cancellation: &Mutex<Option<BrowserCancellation>>,
    cancelled: &AtomicBool,
) -> JobEvent {
    match request.kind {
        WorkerRequestKind::OpenBrowser => {
            if let Ok(mut slot) = cancellation.lock() {
                slot.take();
            }
            browser.take();
            let result = BrowserSession::launch()
                .and_then(|session| {
                    install_cancellation(&session, cancellation, cancelled)?;
                    *browser = Some(session);
                    Ok(())
                })
                .map_err(map_browser_error);
            JobEvent::BrowserOpened { job_id, result }
        }
        WorkerRequestKind::RestoreBrowser => {
            let result = (|| {
                let Some(session) = BrowserSession::restore()? else {
                    return Ok(false);
                };
                install_cancellation(&session, cancellation, cancelled)?;
                *browser = Some(session);
                let session = browser.as_mut().ok_or(BrowserError::Closed)?;
                session.authenticate()?;
                install_cancellation(session, cancellation, cancelled)?;
                Ok(true)
            })()
            .map_err(|error| {
                map_browser_failure(error, || {
                    browser
                        .as_ref()
                        .ok_or(BrowserError::Closed)?
                        .comparison_browser_closed()
                })
            });
            JobEvent::BrowserRestored { job_id, result }
        }
        WorkerRequestKind::CheckLoginWindow => {
            let result = browser
                .as_mut()
                .ok_or(BrowserError::Closed)
                .and_then(BrowserSession::login_window_closed)
                .map_err(map_browser_error);
            JobEvent::LoginWindowChecked { job_id, result }
        }
        WorkerRequestKind::CheckBrowserWindow => {
            let result = browser
                .as_ref()
                .ok_or(BrowserError::Closed)
                .and_then(BrowserSession::comparison_browser_closed)
                .map_err(map_browser_error);
            JobEvent::BrowserWindowChecked { job_id, result }
        }
        WorkerRequestKind::AuthenticateBrowser => {
            let result = (|| {
                let session = browser.as_mut().ok_or(BrowserError::Closed)?;
                session.authenticate()?;
                install_cancellation(session, cancellation, cancelled)
            })()
            .map_err(|error| {
                map_browser_failure(error, || {
                    browser
                        .as_ref()
                        .ok_or(BrowserError::Closed)?
                        .comparison_browser_closed()
                })
            });
            JobEvent::BrowserAuthenticated { job_id, result }
        }
        WorkerRequestKind::DisconnectBrowser => {
            if let Ok(mut slot) = cancellation.lock() {
                slot.take();
            }
            let result = match browser.take() {
                Some(session) => session.disconnect(),
                None => BrowserSession::forget_saved(),
            }
            .map_err(map_browser_error);
            JobEvent::BrowserDisconnected { job_id, result }
        }
        WorkerRequestKind::CompareWeb { report } => JobEvent::WebCompared {
            job_id,
            result: collect_web(browser, &report),
        },
        WorkerRequestKind::Discover { inputs } => JobEvent::DiscoveryFinished {
            job_id,
            result: discover_catalog_paths(&inputs).map_err(map_catalog_path_error),
        },
        WorkerRequestKind::Scan {
            database_path,
            log_roots,
            platform,
        } => {
            let evidence_config = evidence_config(log_roots);
            JobEvent::ScanFinished {
                job_id,
                result: scan_catalog(&database_path, platform, &evidence_config)
                    .map_err(map_scan_error),
            }
        }
        WorkerRequestKind::CheckProcess => {
            let result = Ok(SysinfoProcessProbe.chatgpt_presence());
            JobEvent::ProcessChecked {
                job_id,
                observed_at: Instant::now(),
                result,
            }
        }
        WorkerRequestKind::Repair {
            report,
            log_roots,
            selected,
            backup_directory,
        } => {
            let evidence_config = evidence_config(log_roots);
            // Recollect immediately before calling the write-capable core.
            // No browser failure can reach backup creation or DB mutation.
            let result = collect_web(browser, &report).and_then(|proof| {
                repair(
                    RepairRequest {
                        scan_report: &report,
                        evidence_config: &evidence_config,
                        selected: &selected,
                        backup_directory: &backup_directory,
                    },
                    &proof,
                )
                .map_err(map_repair_error)
            });
            JobEvent::RepairFinished { job_id, result }
        }
    }
}

fn install_cancellation(
    session: &BrowserSession,
    cancellation: &Mutex<Option<BrowserCancellation>>,
    cancelled: &AtomicBool,
) -> Result<(), BrowserError> {
    let handle = session.cancellation_handle()?;
    register_cancellation(handle, cancellation, cancelled, |handle| handle.cancel())
}

fn register_cancellation<T>(
    handle: T,
    cancellation: &Mutex<Option<T>>,
    cancelled: &AtomicBool,
    cancel: impl FnOnce(T),
) -> Result<(), BrowserError> {
    let mut slot = cancellation.lock().map_err(|_| BrowserError::Closed)?;
    // Shutdown sets this flag before taking this same slot. It either receives
    // the published handle, or registration observes shutdown and cancels it.
    if cancelled.load(Ordering::Acquire) {
        drop(slot);
        cancel(handle);
        return Err(BrowserError::Closed);
    }
    *slot = Some(handle);
    Ok(())
}

fn map_browser_error(error: BrowserError) -> AppError {
    let message = error.message_for(Language::Korean);
    match error {
        BrowserError::LoginRequired => {
            return AppError::login_required("ChatGPT 로그인 필요")
                .with_english("Sign in to ChatGPT")
        }
        BrowserError::LoginBrowserStillOpen => return AppError::login_browser_still_open(),
        BrowserError::TargetChanged
        | BrowserError::NoChatGptTarget
        | BrowserError::AmbiguousTarget => AppError::browser_reconnect_required(message),
        BrowserError::PageNotReady
        | BrowserError::AuthorizationDenied
        | BrowserError::RateLimited
        | BrowserError::WebUnavailable => AppError::retryable_authentication(message),
        _ => AppError::no_data_change(message),
    }
    .with_english(error.message_for(Language::English))
}

fn map_browser_failure(
    error: BrowserError,
    probe: impl FnOnce() -> Result<bool, BrowserError>,
) -> AppError {
    if matches!(probe(), Ok(true)) {
        AppError::browser_closed()
    } else {
        map_browser_error(error)
    }
}

fn collect_web(
    browser: &mut Option<BrowserSession>,
    report: &ScanReport,
) -> Result<WebComparison, AppError> {
    let session = browser.as_mut().ok_or_else(|| {
        AppError::no_data_change("브라우저 로그인을 먼저 열어야 함")
            .with_english("Open browser sign-in first")
    })?;
    let expression = web_collector_expression(report)?;
    let value = session
        .evaluate(&expression)
        .map_err(|error| map_browser_failure(error, || session.comparison_browser_closed()))?;
    if let Some(error) = value.get("error").and_then(serde_json::Value::as_str) {
        return Err(map_collector_error(error));
    }
    WebComparison::from_value(report, value).map_err(map_web_error)
}

fn web_collector_expression(report: &ScanReport) -> Result<String, AppError> {
    // Bound the report before deduplication: one ID can belong to many hosts.
    // Never truncate a host group or export its host/account identifier.
    if report.threads.is_empty() || report.threads.len() > 10_000 {
        return Err(
            AppError::no_data_change("웹 대조 대상은 1~10,000개 범위여야 함")
                .with_english("Web comparison requires between 1 and 10,000 conversations"),
        );
    }
    let mut ids = BTreeSet::new();
    let mut groups = BTreeMap::<&str, BTreeSet<&str>>::new();
    for thread in report
        .threads
        .iter()
        .filter(|thread| thread.source_kind() == "chatgpt")
    {
        let identity = thread.identity();
        ids.insert(identity.thread_id.as_str());
        groups
            .entry(identity.host_id.as_str())
            .or_default()
            .insert(identity.thread_id.as_str());
    }
    if ids.is_empty() {
        return Err(
            AppError::no_data_change("웹 대조 대상은 1~10,000개 범위여야 함")
                .with_english("Web comparison requires between 1 and 10,000 conversations"),
        );
    }
    let groups = groups.into_values().collect::<Vec<_>>();
    let ids = serde_json::to_string(&ids).map_err(|error| {
        AppError::no_data_change("웹 요청을 만들지 못함. 다시 대조해야 함")
            .with_english("Could not build the web request. Compare again")
            .with_details(error.to_string())
    })?;
    let groups = serde_json::to_string(&groups).map_err(|error| {
        AppError::no_data_change("웹 요청을 만들지 못함. 다시 대조해야 함")
            .with_english("Could not build the web request. Compare again")
            .with_details(error.to_string())
    })?;
    Ok(format!(
        "(async () => {{ {}; return await collectChatMetadata({ids},false,{groups}); }})()",
        include_str!("../assets/web/collect.js")
    ))
}

fn evidence_config(log_roots: Vec<PathBuf>) -> EvidenceScanConfig {
    EvidenceScanConfig::new(Vec::new(), log_roots)
}

fn map_collector_error(error: &str) -> AppError {
    if error == "login_required" {
        return AppError::login_required("ChatGPT 로그인 필요").with_english("Sign in to ChatGPT");
    }
    let (korean, english) = match error {
        "authorization_failed" => ("웹 접근 권한을 확인하지 못함. 로그인 상태 확인 후 다시 대조해야 함", "Could not verify web access. Check sign-in and compare again"),
        "account_changed" => ("조회 중 계정이 달라졌거나 계정 정보를 검증하지 못함", "The account changed during lookup or its identity could not be verified"),
        "session_user_mismatch" => ("로그인 세션과 인증 사용자 정보가 일치하지 않음", "The sign-in session and authenticated user do not match"),
        "account_match_mismatch" => ("로그인 계정과 일치하는 계정을 확정하지 못함", "Could not identify an account matching the signed-in account"),
        "account_match_none" => ("로그인 계정에 맞는 계정 항목이 없음", "No account entry matches the signed-in account"),
        "account_match_multiple" => ("로그인 계정에 맞는 계정 항목이 여러 개임", "Multiple account entries match the signed-in account"),
        "ordered_personal_account_id_missing" => ("개인 계정 항목에 계정 ID가 없음", "The personal account entry has no account ID"),
        "ordered_personal_account_id_missing_bound" => ("개인 계정 ID 없음 · 로그인 계정 일치", "Personal account ID missing; signed-in account matches"),
        "ordered_personal_account_id_missing_unbound" => ("개인 계정 ID 없음 · 로그인 계정 미확인", "Personal account ID missing; signed-in account unverified"),
        "account_user_mismatch" => ("계정과 로그인 사용자 연결이 일치하지 않음", "The account and signed-in user association do not match"),
        "final_identity_changed" => ("확인 중 로그인 계정이 바뀜", "The signed-in account changed during verification"),
        "unsupported_account" => ("현재 버전은 개인 계정만 지원. Workspace 계정은 정리 차단", "This version supports personal accounts only. Workspace cleanup is blocked"),
        "rate_limited" => ("웹 조회 횟수 제한에 도달함. 잠시 후 다시 시도해야 함", "The web request limit was reached. Wait a moment, then try again"),
        "collection_timeout" => ("웹 확인 시간이 초과됨. 다시 시도해야 함", "Web verification timed out. Try again"),
        "no_positive_control" => ("이 계정에서 확인 가능한 로컬 대화를 찾지 못해 대조 기준을 확립하지 못함", "No local conversation could be verified in this account to establish a comparison reference"),
        "inventory_changed" => ("조회 중 웹 대화 목록이 바뀜", "The web conversation list changed during lookup"),
        "inventory_total_changed" => ("조회 중 대화 총개수가 바뀜", "The conversation total changed during lookup"),
        "inventory_duplicate" => ("같은 목록에서 대화가 중복됨", "A conversation appears more than once in the same list"),
        "inventory_partition_overlap" => ("보관된 대화와 일반 대화 목록이 겹침", "The archived and regular conversation lists overlap"),
        "inventory_count_overflow" => ("받은 대화 수가 조회 범위를 초과함", "The conversation count exceeded the requested range"),
        "inventory_invalid_pagination" => ("다음 대화 목록 위치가 올바르지 않음", "The next conversation list position is invalid"),
        "positive_control_missing" => ("확인했던 대화를 다시 조회하지 못함", "A previously verified conversation could not be checked again"),
        "inventory_head_changed" => ("재확인한 대화 목록의 처음 부분이 바뀜", "The beginning of the conversation list changed when rechecked"),
        "incomplete_inventory" => ("전체 개수보다 적은 대화 목록을 받음", "Fewer conversations were received than the reported total"),
        "limit_exceeded" => ("대화 목록 조회 횟수 한도를 초과함", "The conversation list request limit was exceeded"),
        "invalid_request" => ("로컬 대화 ID 형식 또는 개수가 웹 조회 조건과 맞지 않음", "The local conversation ID format or count does not meet the web request requirements"),
        "wrong_origin" => ("앱이 연 브라우저에서 ChatGPT를 연 뒤 다시 대조해야 함", "Open ChatGPT in the browser opened by this app, then compare again"),
        "web_unavailable" => ("ChatGPT 응답을 받지 못함. 네트워크 확인 후 다시 시도해야 함", "No response received from ChatGPT. Check the network and try again"),
        "response_schema_changed" => ("ChatGPT 응답 형식이 예상과 다름. 나중에 다시 시도해야 함", "The ChatGPT response format differs from the expected format. Try again later"),
        _ => ("웹 조회를 완료하지 못함. 로그인 상태·네트워크·웹 응답 형식을 확인해야 함", "Could not finish the web lookup. Check sign-in, the network, and the web response format"),
    };
    AppError::no_data_change(korean).with_english(english)
}

fn parse_log_roots(input: &str) -> Vec<PathBuf> {
    input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn map_catalog_path_error(error: crate::platform::PathDiscoveryError) -> AppError {
    AppError::no_data_change("대화 목록 파일 위치를 확인하지 못함. 경로와 접근 권한을 확인해야 함")
        .with_english(
            "Could not locate the conversation catalog. Check the path and access permissions",
        )
        .with_details(error.to_string())
}

fn map_scan_error(error: crate::catalog::CatalogScanError) -> AppError {
    AppError::no_data_change("대화 목록을 읽지 못함. 세부 정보의 경로와 오류를 확인한 뒤 다시 스캔해야 함")
        .with_english("Could not read the conversation catalog. Check the path and error in Details, then scan again")
        .with_details(error.to_string())
}

fn map_web_error(error: crate::web::WebError) -> AppError {
    AppError::no_data_change(
        "웹 대조 결과를 검증하지 못함. 로그인 상태를 확인한 뒤 다시 대조해야 함",
    )
    .with_english("Could not validate the web comparison. Check sign-in, then compare again")
    .with_details(error.to_string())
}

fn map_repair_error(error: RepairError) -> AppError {
    let mapped = match &error {
        RepairError::RollbackFailed { .. }
        | RepairError::CommitFailed { .. }
        | RepairError::CommitOutcomeInvalid { .. } => AppError::outcome_uncertain(
            "정리 결과를 확인하지 못함. 계속하기 전에 세부 정보에서 보존된 백업을 확인해야 함",
        ).with_english("Could not confirm the cleanup result. Check Details for the preserved backup before proceeding"),
        _ => AppError::no_data_change("정리를 완료하지 못함. 세부 정보를 확인한 뒤 다시 스캔해야 함")
            .with_english("Could not complete cleanup. Review Details, then scan again"),
    };
    mapped.with_details(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::app_state::{AppState, ErrorOutcome, Operation};
    use crate::model::{CatalogThread, LocalPath, SchemaReport};

    #[test]
    fn localized_browser_failures_cover_every_variant_and_preserve_korean_display() {
        use crate::browser_profile::ProfileError;
        use crate::default_browser::DefaultBrowserError;
        let mut errors = vec![
            BrowserError::LaunchFailed,
            BrowserError::StartupTimeout,
            BrowserError::InvalidEndpoint,
            BrowserError::ConnectionFailed,
            BrowserError::TimedOut,
            BrowserError::ResponseLimit,
            BrowserError::InvalidResponse,
            BrowserError::CommandFailed,
            BrowserError::NoChatGptTarget,
            BrowserError::AmbiguousTarget,
            BrowserError::TargetChanged,
            BrowserError::EvaluationFailed,
            BrowserError::PageNotReady,
            BrowserError::SyntaxError,
            BrowserError::ReferenceError,
            BrowserError::TypeError,
            BrowserError::ExpressionTooLarge,
            BrowserError::Closed,
            BrowserError::LoginBrowserStillOpen,
            BrowserError::LoginInterrupted,
            BrowserError::LoginRequired,
            BrowserError::AuthorizationDenied,
            BrowserError::AccountChanged,
            BrowserError::SessionUserMismatch,
            BrowserError::AccountMatchMismatch,
            BrowserError::AccountMatchNone,
            BrowserError::AccountMatchMultiple,
            BrowserError::OrderedPersonalAccountIdMissing,
            BrowserError::OrderedPersonalAccountIdMissingBound,
            BrowserError::OrderedPersonalAccountIdMissingUnbound,
            BrowserError::AccountUserMismatch,
            BrowserError::FinalIdentityChanged,
            BrowserError::UnsupportedAccount,
            BrowserError::ResponseSchemaChanged,
            BrowserError::RateLimited,
            BrowserError::WebUnavailable,
            BrowserError::InvalidCollectorRequest,
        ];
        errors.extend(
            [
                ProfileError::UnsupportedProduct,
                ProfileError::MissingDataDirectory,
                ProfileError::UnsafePath,
                ProfileError::InUse,
                ProfileError::UnconfirmedExit,
                ProfileError::InvalidMarker,
                ProfileError::Io,
            ]
            .map(BrowserError::Profile),
        );
        errors.extend(
            [
                DefaultBrowserError::DetectionFailed,
                DefaultBrowserError::UnsupportedDefaultBrowser,
                DefaultBrowserError::UnsupportedInstallation,
                DefaultBrowserError::DetectionTimedOut,
                DefaultBrowserError::ResponseLimit,
            ]
            .map(BrowserError::DefaultBrowser),
        );
        for error in errors {
            assert_eq!(error.message_for(Language::Korean), error.to_string());
            let mapped = map_browser_error(error);
            let english = mapped.message_for(Language::English);
            assert!(!english.is_empty(), "{error:?}");
            assert!(
                english.is_ascii(),
                "missing English for {error:?}: {english}"
            );
            assert_ne!(english, mapped.message_for(Language::Korean), "{error:?}");
            assert_eq!(mapped.outcome, ErrorOutcome::NoDataChange);
        }
    }

    #[test]
    fn localized_collector_failures_have_english_and_keep_untrusted_text_private() {
        for code in [
            "login_required",
            "authorization_failed",
            "account_changed",
            "session_user_mismatch",
            "account_match_mismatch",
            "account_match_none",
            "account_match_multiple",
            "ordered_personal_account_id_missing",
            "ordered_personal_account_id_missing_bound",
            "ordered_personal_account_id_missing_unbound",
            "account_user_mismatch",
            "final_identity_changed",
            "unsupported_account",
            "rate_limited",
            "collection_timeout",
            "no_positive_control",
            "inventory_changed",
            "inventory_total_changed",
            "inventory_duplicate",
            "inventory_partition_overlap",
            "inventory_count_overflow",
            "inventory_invalid_pagination",
            "positive_control_missing",
            "inventory_head_changed",
            "incomplete_inventory",
            "limit_exceeded",
            "invalid_request",
            "wrong_origin",
            "web_unavailable",
            "response_schema_changed",
            "fixture-secret-response-body",
        ] {
            let error = map_collector_error(code);
            assert!(error.message_for(Language::English).is_ascii(), "{code}");
            assert_ne!(
                error.message_for(Language::English),
                error.message_for(Language::Korean),
                "{code}"
            );
            assert_eq!(error.authentication_expired, code == "login_required");
            assert_eq!(error.outcome, ErrorOutcome::NoDataChange);
            assert!(!format!("{error:?}").contains("fixture-secret"));
        }
        let error = web_collector_expression(&collector_report(Vec::new())).unwrap_err();
        assert!(error.message_for(Language::English).contains("10,000"));
    }

    #[test]
    fn localized_technical_failures_preserve_original_details_and_repair_outcome() {
        let path = PathBuf::from("/synthetic/원본 catalog.db");
        let discovery = crate::platform::PathDiscoveryError::SymlinkRefused { path: path.clone() };
        let details = discovery.to_string();
        let error = map_catalog_path_error(discovery);
        assert_eq!(error.details.as_deref(), Some(details.as_str()));
        assert!(error.message_for(Language::English).is_ascii());
        let scan = crate::catalog::CatalogScanError::PathNotFound { path: path.clone() };
        let details = scan.to_string();
        let error = map_scan_error(scan);
        assert_eq!(error.details.as_deref(), Some(details.as_str()));
        assert!(error.message_for(Language::English).is_ascii());
        let web = crate::web::WebError::Malformed;
        let details = web.to_string();
        let error = map_web_error(web);
        assert_eq!(error.details.as_deref(), Some(details.as_str()));
        assert!(error.message_for(Language::English).is_ascii());
        for repair in [
            RepairError::EmptyPlan,
            RepairError::CommitOutcomeInvalid {
                backup_path: path.clone(),
            },
            RepairError::CommitFailed {
                backup_path: path.clone(),
                source: rusqlite::Error::InvalidQuery,
            },
            RepairError::RollbackFailed {
                backup_path: path,
                original: Box::new(RepairError::EmptyPlan),
                rollback: rusqlite::Error::InvalidQuery,
            },
        ] {
            let expected_outcome = if matches!(repair, RepairError::EmptyPlan) {
                ErrorOutcome::NoDataChange
            } else {
                ErrorOutcome::OutcomeUncertain
            };
            let details = repair.to_string();
            let error = map_repair_error(repair);
            assert_eq!(error.details.as_deref(), Some(details.as_str()));
            assert_eq!(error.outcome, expected_outcome);
            assert!(error.message_for(Language::English).is_ascii());
            assert_ne!(
                error.message_for(Language::English),
                error.message_for(Language::Korean)
            );
        }
    }

    fn collector_report(threads: Vec<CatalogThread>) -> ScanReport {
        ScanReport::new(
            LocalPath::try_from(std::path::Path::new("/synthetic/catalog.db")).unwrap(),
            "synthetic",
            SchemaReport {
                write_capable: false,
                reason: "request fixture".to_owned(),
                fingerprint: "synthetic".to_owned(),
                columns: Vec::new(),
            },
            threads,
            true,
        )
    }

    fn collector_row(host: &str, id: &str, source: &str) -> CatalogThread {
        CatalogThread::preserved(
            ThreadIdentity::new(host, id),
            "fixture",
            source,
            false,
            None,
            None,
        )
    }

    #[test]
    fn collector_request_groups_exact_hosts_without_exporting_host_identifiers() {
        let host_a = "chatgpt:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:user-private-a";
        let host_b = "chatgpt:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb:user-private-b";
        let shared = "11111111-1111-1111-1111-111111111111";
        let only_b = "22222222-2222-2222-2222-222222222222";
        let only_a = "33333333-3333-3333-3333-333333333333";
        let excluded = "44444444-4444-4444-4444-444444444444";
        let report = collector_report(vec![
            collector_row(host_b, only_b, "chatgpt"),
            collector_row(host_a, only_a, "chatgpt"),
            collector_row(host_b, shared, "chatgpt"),
            collector_row(host_a, shared, "chatgpt"),
            collector_row(host_a, shared, "chatgpt"),
            collector_row(host_a, excluded, "other"),
        ]);
        let expression = web_collector_expression(&report).unwrap();
        let arguments = expression
            .rsplit_once("return await collectChatMetadata(")
            .unwrap()
            .1
            .strip_suffix("); })()")
            .unwrap();
        let actual: serde_json::Value = serde_json::from_str(&format!("[{arguments}]")).unwrap();
        assert_eq!(
            actual,
            serde_json::json!([
                [shared, only_b, only_a],
                false,
                [[shared, only_a], [shared, only_b]]
            ])
        );
        assert!(!expression.contains(host_a));
        assert!(!expression.contains(host_b));
        assert!(!expression.contains(excluded));
    }

    #[test]
    fn collector_request_bounds_host_group_members_without_truncating_shared_ids() {
        let shared = "11111111-1111-1111-1111-111111111111";
        let mut report = collector_report(
            (0..10_000)
                .map(|index| collector_row(&format!("host-{index}"), shared, "chatgpt"))
                .collect(),
        );
        assert!(web_collector_expression(&report).is_ok());
        report
            .threads
            .push(collector_row("host-overflow", shared, "chatgpt"));
        let error = web_collector_expression(&report).unwrap_err();
        assert_eq!(error.outcome, ErrorOutcome::NoDataChange);
        assert!(!error.authentication_retryable);
    }

    #[test]
    fn lost_or_ambiguous_target_requires_reconnection_without_claiming_process_exit() {
        for error in [
            BrowserError::TargetChanged,
            BrowserError::NoChatGptTarget,
            BrowserError::AmbiguousTarget,
        ] {
            let mapped = map_browser_failure(error, || Ok(false));
            assert!(mapped.browser_reconnect_required);
            assert!(!mapped.browser_closed);
            assert!(!mapped.authentication_expired);
            assert!(!mapped.authentication_retryable);
            assert_eq!(mapped.outcome, ErrorOutcome::NoDataChange);
        }
        for error in [
            BrowserError::PageNotReady,
            BrowserError::TimedOut,
            BrowserError::LoginRequired,
            BrowserError::ConnectionFailed,
        ] {
            assert!(!map_browser_error(error).browser_reconnect_required);
        }
    }

    #[test]
    fn browser_failure_claims_closed_only_after_definitive_owned_process_exit() {
        let closed = map_browser_failure(BrowserError::ConnectionFailed, || Ok(true));
        assert!(closed.browser_closed);
        assert!(!closed.authentication_expired);
        assert!(!closed.authentication_retryable);
        for probe in [
            Ok(false),
            Err(BrowserError::Closed),
            Err(BrowserError::LaunchFailed),
        ] {
            let error = map_browser_failure(BrowserError::ConnectionFailed, || probe);
            assert!(!error.browser_closed);
            assert!(!error.authentication_expired);
        }
    }

    #[test]
    fn inventory_errors_have_distinct_static_messages_and_never_authorize() {
        let mut messages = std::collections::HashSet::new();
        for code in [
            "inventory_total_changed",
            "inventory_duplicate",
            "inventory_partition_overlap",
            "inventory_count_overflow",
            "inventory_invalid_pagination",
            "positive_control_missing",
            "inventory_head_changed",
            "incomplete_inventory",
            "limit_exceeded",
        ] {
            let error = map_collector_error(code);
            assert_eq!(error.outcome, ErrorOutcome::NoDataChange);
            assert!(!error.authentication_expired);
            assert!(!error.authentication_retryable);
            assert!(!error.login_browser_still_open);
            assert!(
                messages.insert(error.message),
                "distinct message needed for {code}"
            );
        }
        let unknown = map_collector_error("fixture-secret-response-body");
        assert!(!unknown.message.contains("fixture-secret"));
    }

    #[test]
    fn only_known_page_authentication_errors_offer_session_verification_retry() {
        for error in [
            BrowserError::PageNotReady,
            BrowserError::AuthorizationDenied,
            BrowserError::RateLimited,
            BrowserError::WebUnavailable,
        ] {
            let mapped = map_browser_error(error);
            assert!(mapped.authentication_retryable);
            assert!(!mapped.authentication_expired);
            assert!(!mapped.login_browser_still_open);
            assert_eq!(mapped.outcome, ErrorOutcome::NoDataChange);
        }
        for error in [
            BrowserError::TargetChanged,
            BrowserError::NoChatGptTarget,
            BrowserError::AmbiguousTarget,
            BrowserError::LoginRequired,
            BrowserError::LoginBrowserStillOpen,
            BrowserError::TimedOut,
            BrowserError::EvaluationFailed,
            BrowserError::Closed,
            BrowserError::AccountChanged,
            BrowserError::SessionUserMismatch,
            BrowserError::AccountMatchMismatch,
            BrowserError::AccountMatchNone,
            BrowserError::AccountMatchMultiple,
            BrowserError::OrderedPersonalAccountIdMissing,
            BrowserError::OrderedPersonalAccountIdMissingBound,
            BrowserError::OrderedPersonalAccountIdMissingUnbound,
            BrowserError::AccountUserMismatch,
            BrowserError::FinalIdentityChanged,
            BrowserError::UnsupportedAccount,
            BrowserError::ResponseSchemaChanged,
            BrowserError::InvalidCollectorRequest,
        ] {
            assert!(!map_browser_error(error).authentication_retryable);
        }
    }

    #[test]
    fn only_an_open_login_browser_error_preserves_login_retry() {
        let pending = map_browser_error(BrowserError::LoginBrowserStillOpen);
        assert!(pending.login_browser_still_open);
        assert_eq!(pending.outcome, ErrorOutcome::NoDataChange);
        assert!(!pending.authentication_expired);
        assert_eq!(
            pending.message,
            "로그인한 브라우저를 닫은 뒤 목록 확인 필요"
        );
        for error in [
            BrowserError::LoginRequired,
            BrowserError::TimedOut,
            BrowserError::EvaluationFailed,
            BrowserError::Closed,
        ] {
            assert!(!map_browser_error(error).login_browser_still_open);
        }
    }

    fn job_id() -> JobId {
        AppState::new(RunMode::Live, PlatformPolicy::MacOs).begin(Operation::Discovering)
    }

    fn queued_discovery(job_id: JobId) -> QueuedRequest {
        QueuedRequest {
            job_id,
            request: WorkerRequest::discover(CatalogPathInputs::default()),
        }
    }

    fn completed_discovery(job_id: JobId) -> JobEvent {
        JobEvent::DiscoveryFinished {
            job_id,
            result: Ok(Vec::new()),
        }
    }

    #[test]
    fn cancellation_before_a_queued_request_prevents_execution() {
        let (request_tx, request_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();
        let cancelled = AtomicBool::new(true);
        let executions = Cell::new(0);
        request_tx
            .send(queued_discovery(job_id()))
            .expect("queue synthetic request");
        drop(request_tx);

        run_worker_loop(
            request_rx,
            event_tx,
            &cancelled,
            |job_id, _request| {
                executions.set(executions.get() + 1);
                completed_discovery(job_id)
            },
            || {},
        );

        assert_eq!(executions.get(), 0);
        assert!(event_rx.try_recv().is_err());
    }

    #[test]
    fn cancellation_between_requests_skips_the_remaining_queue() {
        let (request_tx, request_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();
        let cancelled = AtomicBool::new(false);
        let executions = Cell::new(0);
        let repaints = Cell::new(0);
        request_tx
            .send(queued_discovery(job_id()))
            .expect("queue first synthetic request");
        request_tx
            .send(queued_discovery(job_id()))
            .expect("queue second synthetic request");
        drop(request_tx);

        run_worker_loop(
            request_rx,
            event_tx,
            &cancelled,
            |job_id, _request| {
                executions.set(executions.get() + 1);
                cancelled.store(true, Ordering::Release);
                completed_discovery(job_id)
            },
            || repaints.set(repaints.get() + 1),
        );

        assert_eq!(executions.get(), 1);
        assert_eq!(repaints.get(), 1);
        assert!(event_rx.try_recv().is_ok());
        assert!(event_rx.try_recv().is_err());
    }

    #[test]
    fn cancellation_registration_after_shutdown_rejects_and_cancels_the_new_handle() {
        use std::sync::atomic::AtomicUsize;

        let cancelled = Arc::new(AtomicBool::new(false));
        let slot = Arc::new(Mutex::new(None::<usize>));
        let cancelled_handles = Arc::new(AtomicUsize::new(0));
        let (created_tx, created_rx) = mpsc::channel();
        let (continue_tx, continue_rx) = mpsc::channel();
        let worker_cancelled = Arc::clone(&cancelled);
        let worker_slot = Arc::clone(&slot);
        let worker_cancelled_handles = Arc::clone(&cancelled_handles);
        let registration = thread::spawn(move || {
            // A browser has been created, but its cancellation handle is not yet published.
            created_tx.send(()).unwrap();
            continue_rx.recv().unwrap();
            register_cancellation(7, &worker_slot, &worker_cancelled, |handle| {
                assert_eq!(handle, 7);
                assert!(
                    worker_slot.try_lock().is_ok(),
                    "release the slot before cancellation"
                );
                worker_cancelled_handles.fetch_add(1, Ordering::SeqCst);
            })
        });
        created_rx.recv().unwrap();
        cancelled.store(true, Ordering::Release);
        assert!(slot.lock().unwrap().take().is_none());
        continue_tx.send(()).unwrap();
        let result = registration.join().unwrap();

        assert_eq!(result, Err(BrowserError::Closed));
        assert!(slot.lock().unwrap().is_none());
        assert_eq!(cancelled_handles.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancellation_registration_before_shutdown_publishes_the_handle_for_shutdown() {
        let cancelled = AtomicBool::new(false);
        let slot = Mutex::new(None);
        assert_eq!(
            register_cancellation(9, &slot, &cancelled, |_| {
                panic!("a running worker must retain its cancellation handle");
            }),
            Ok(())
        );
        cancelled.store(true, Ordering::Release);
        assert_eq!(slot.lock().unwrap().take(), Some(9));
        assert!(slot.lock().unwrap().is_none());
    }
}
