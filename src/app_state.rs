#[cfg(test)]
use std::cell::Cell;
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::i18n::Language;
use crate::model::{Classification, RepairReceipt, ScanReport, ThreadIdentity};
use crate::platform::PlatformPolicy;
use crate::process_guard::ProcessPresence;
use crate::web::{WebComparison, WebVerdict};

#[derive(Clone, Copy, Debug)]
struct IndexedThread {
    classification: Classification,
    repair_eligible: bool,
    web_review_eligible: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunMode {
    Live,
    Demo,
}

impl RunMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Live => "Live",
            Self::Demo => "Demo",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Operation {
    #[default]
    Idle,
    Discovering,
    Scanning,
    RestoringBrowser,
    OpeningBrowser,
    CheckingLogin,
    CheckingBrowser,
    AuthenticatingBrowser,
    DisconnectingBrowser,
    ComparingWeb,
    Checking,
    Repairing,
}

impl Operation {
    pub const fn is_busy(self) -> bool {
        !matches!(self, Self::Idle)
    }

    /// Internal exit probes serialize worker requests without changing the UI.
    /// A user action may supersede a probe; its late result is rejected by job ID.
    pub const fn is_foreground(self) -> bool {
        !matches!(
            self,
            Self::Idle | Self::CheckingLogin | Self::CheckingBrowser | Self::Checking
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BrowserState {
    #[default]
    Disconnected,
    LoginOpen,
    Connecting,
    AwaitingVerification,
    Connected,
    Expired,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProcessState {
    #[default]
    NotChecked,
    Running,
    StoppedVerified,
    Unknown,
}

pub const PROCESS_PROOF_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairBlocker {
    Busy,
    Platform,
    Report,
    Selection,
    WebVerification,
    BackupDirectory,
    DesktopProcess,
}

/// A dialog authorizes only the context for which it was opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairConfirmation {
    revision: u64,
    selected_count: usize,
}

impl RepairConfirmation {
    pub const fn selected_count(self) -> usize {
        self.selected_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairReadiness {
    pub platform_allowed: bool,
    pub report_ready: bool,
    pub selection_valid: bool,
    pub process_stopped: bool,
    pub web_verified: bool,
    pub backup_directory_present: bool,
    pub idle: bool,
}

impl RepairReadiness {
    pub const fn can_repair(self) -> bool {
        self.blocker().is_none()
    }

    /// The button and its instruction use this same ordered prerequisite check.
    pub const fn blocker(self) -> Option<RepairBlocker> {
        if !self.idle {
            Some(RepairBlocker::Busy)
        } else if !self.platform_allowed {
            Some(RepairBlocker::Platform)
        } else if !self.report_ready {
            Some(RepairBlocker::Report)
        } else if !self.selection_valid {
            Some(RepairBlocker::Selection)
        } else if !self.web_verified {
            Some(RepairBlocker::WebVerification)
        } else if !self.backup_directory_present {
            Some(RepairBlocker::BackupDirectory)
        } else if !self.process_stopped {
            Some(RepairBlocker::DesktopProcess)
        } else {
            None
        }
    }
}

impl From<ProcessPresence> for ProcessState {
    fn from(value: ProcessPresence) -> Self {
        match value {
            ProcessPresence::Stopped => Self::StoppedVerified,
            ProcessPresence::Running => Self::Running,
            ProcessPresence::Unknown => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct JobId(u64);

impl JobId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorOutcome {
    NoDataChange,
    OutcomeUncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppError {
    /// Default Korean text retained for callers that do not select a language.
    pub message: String,
    pub message_en: Option<String>,
    pub details: Option<String>,
    pub outcome: ErrorOutcome,
    pub authentication_expired: bool,
    pub authentication_retryable: bool,
    pub login_browser_still_open: bool,
    pub browser_closed: bool,
    pub browser_reconnect_required: bool,
}

impl AppError {
    pub fn with_english(mut self, message: impl Into<String>) -> Self {
        self.message_en = Some(message.into());
        self
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    pub fn message_for(&self, language: Language) -> &str {
        match language {
            Language::Korean => &self.message,
            Language::English => self.message_en.as_deref().unwrap_or(&self.message),
        }
    }

    pub fn no_data_change(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            message_en: None,
            details: None,
            outcome: ErrorOutcome::NoDataChange,
            authentication_expired: false,
            authentication_retryable: false,
            login_browser_still_open: false,
            browser_closed: false,
            browser_reconnect_required: false,
        }
    }

    pub fn outcome_uncertain(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            message_en: None,
            details: None,
            outcome: ErrorOutcome::OutcomeUncertain,
            authentication_expired: false,
            authentication_retryable: false,
            login_browser_still_open: false,
            browser_closed: false,
            browser_reconnect_required: false,
        }
    }

    pub fn login_required(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            message_en: None,
            details: None,
            outcome: ErrorOutcome::NoDataChange,
            authentication_expired: true,
            authentication_retryable: false,
            login_browser_still_open: false,
            browser_closed: false,
            browser_reconnect_required: false,
        }
    }

    pub fn login_browser_still_open() -> Self {
        Self {
            login_browser_still_open: true,
            ..Self::no_data_change("로그인한 브라우저를 닫은 뒤 목록 확인 필요")
                .with_english("Close the login browser, then check the conversation list")
        }
    }

    pub fn retryable_authentication(message: impl Into<String>) -> Self {
        Self {
            authentication_retryable: true,
            ..Self::no_data_change(message)
        }
    }

    pub fn browser_closed() -> Self {
        Self {
            browser_closed: true,
            ..Self::no_data_change("브라우저가 종료됨").with_english("The browser has closed")
        }
    }

    pub fn browser_reconnect_required(message: impl Into<String>) -> Self {
        Self {
            browser_reconnect_required: true,
            ..Self::no_data_change(message)
        }
    }
}

#[derive(Clone, Debug)]
pub enum JobEvent {
    BrowserRestored {
        job_id: JobId,
        result: Result<bool, AppError>,
    },
    BrowserOpened {
        job_id: JobId,
        result: Result<(), AppError>,
    },
    LoginWindowChecked {
        job_id: JobId,
        result: Result<bool, AppError>,
    },
    BrowserWindowChecked {
        job_id: JobId,
        result: Result<bool, AppError>,
    },
    BrowserAuthenticated {
        job_id: JobId,
        result: Result<(), AppError>,
    },
    BrowserDisconnected {
        job_id: JobId,
        result: Result<(), AppError>,
    },
    WebCompared {
        job_id: JobId,
        result: Result<WebComparison, AppError>,
    },
    DiscoveryFinished {
        job_id: JobId,
        result: Result<Vec<PathBuf>, AppError>,
    },
    ScanFinished {
        job_id: JobId,
        result: Result<ScanReport, AppError>,
    },
    ProcessChecked {
        job_id: JobId,
        observed_at: Instant,
        result: Result<ProcessPresence, AppError>,
    },
    RepairFinished {
        job_id: JobId,
        result: Result<RepairReceipt, AppError>,
    },
}

impl JobEvent {
    pub const fn job_id(&self) -> JobId {
        match self {
            Self::DiscoveryFinished { job_id, .. }
            | Self::ScanFinished { job_id, .. }
            | Self::ProcessChecked { job_id, .. }
            | Self::RepairFinished { job_id, .. } => *job_id,
            Self::BrowserRestored { job_id, .. }
            | Self::BrowserOpened { job_id, .. }
            | Self::LoginWindowChecked { job_id, .. }
            | Self::BrowserWindowChecked { job_id, .. }
            | Self::BrowserAuthenticated { job_id, .. }
            | Self::BrowserDisconnected { job_id, .. }
            | Self::WebCompared { job_id, .. } => *job_id,
        }
    }
}

#[derive(Debug)]
pub struct AppState {
    run_mode: RunMode,
    platform: PlatformPolicy,
    operation: Operation,
    active_job: Option<JobId>,
    next_job: u64,
    database_input: String,
    log_roots_input: String,
    backup_directory_input: String,
    discovered_paths: Vec<PathBuf>,
    report: Option<ScanReport>,
    browser_state: BrowserState,
    // AwaitingVerification can also mean a closed initial login window. Only
    // an attempted comparison phase is eligible for the read-only exit probe.
    comparison_browser_started: bool,
    web_comparison: Option<WebComparison>,
    web_selection_valid: bool,
    report_index: HashMap<ThreadIdentity, IndexedThread>,
    reviewed: HashSet<ThreadIdentity>,
    selected: HashSet<ThreadIdentity>,
    repair_revision: u64,
    process_state: ProcessState,
    process_proof_observed_at: Option<Instant>,
    receipt: Option<RepairReceipt>,
    error: Option<AppError>,
    #[cfg(test)]
    index_lookup_count: Cell<usize>,
}

impl AppState {
    pub fn new(run_mode: RunMode, platform: PlatformPolicy) -> Self {
        Self {
            run_mode,
            platform,
            operation: Operation::Idle,
            active_job: None,
            next_job: 1,
            database_input: String::new(),
            log_roots_input: String::new(),
            backup_directory_input: String::new(),
            discovered_paths: Vec::new(),
            report: None,
            browser_state: BrowserState::Disconnected,
            comparison_browser_started: false,
            web_comparison: None,
            web_selection_valid: false,
            report_index: HashMap::new(),
            reviewed: HashSet::new(),
            selected: HashSet::new(),
            repair_revision: 0,
            process_state: ProcessState::NotChecked,
            process_proof_observed_at: None,
            receipt: None,
            error: None,
            #[cfg(test)]
            index_lookup_count: Cell::new(0),
        }
    }

    pub const fn run_mode(&self) -> RunMode {
        self.run_mode
    }

    pub const fn platform(&self) -> PlatformPolicy {
        self.platform
    }

    pub const fn operation(&self) -> Operation {
        self.operation
    }

    pub const fn active_job(&self) -> Option<JobId> {
        self.active_job
    }

    pub fn database_input(&self) -> &str {
        &self.database_input
    }

    pub fn log_roots_input(&self) -> &str {
        &self.log_roots_input
    }

    pub fn backup_directory_input(&self) -> &str {
        &self.backup_directory_input
    }

    pub fn discovered_paths(&self) -> &[PathBuf] {
        &self.discovered_paths
    }

    pub fn report(&self) -> Option<&ScanReport> {
        self.report.as_ref()
    }

    pub const fn browser_ready(&self) -> bool {
        matches!(self.browser_state, BrowserState::Connected)
    }

    pub const fn browser_state(&self) -> BrowserState {
        self.browser_state
    }

    pub const fn should_monitor_comparison(&self) -> bool {
        self.comparison_browser_started
            && matches!(
                self.browser_state,
                BrowserState::Connected | BrowserState::AwaitingVerification
            )
    }

    pub fn web_comparison(&self) -> Option<&WebComparison> {
        self.web_comparison.as_ref()
    }

    pub fn web_verdict(&self, identity: &ThreadIdentity) -> WebVerdict {
        self.web_comparison
            .as_ref()
            .map_or(WebVerdict::Unknown, |proof| proof.verdict(identity))
    }

    pub fn install_web_comparison(&mut self, proof: WebComparison) {
        self.clear_authorization();
        if self
            .report
            .as_ref()
            .is_some_and(|report| proof.matches_report(report))
        {
            self.web_comparison = Some(proof);
        } else {
            self.web_comparison = None;
            self.error = Some(
                AppError::no_data_change("웹 대조 중 로컬 스캔 결과가 바뀜. 다시 대조해야 함")
                    .with_english("The local scan changed during web comparison. Compare again"),
            );
        }
    }

    pub fn reviewed(&self) -> &HashSet<ThreadIdentity> {
        &self.reviewed
    }

    pub fn selected(&self) -> &HashSet<ThreadIdentity> {
        &self.selected
    }

    pub fn process_state(&self) -> ProcessState {
        self.process_state_at(Instant::now())
    }

    pub fn process_state_at(&self, now: Instant) -> ProcessState {
        if self.process_state == ProcessState::StoppedVerified
            && !self.process_proof_is_valid_at(now)
        {
            ProcessState::NotChecked
        } else {
            self.process_state
        }
    }

    pub fn process_proof_remaining_at(&self, now: Instant) -> Option<Duration> {
        if self.process_state != ProcessState::StoppedVerified {
            return None;
        }
        let age = now.checked_duration_since(self.process_proof_observed_at?)?;
        PROCESS_PROOF_TTL
            .checked_sub(age)
            .filter(|remaining| !remaining.is_zero())
    }

    pub fn process_proof_expired_at(&self, now: Instant) -> bool {
        self.process_state == ProcessState::StoppedVerified && !self.process_proof_is_valid_at(now)
    }

    pub fn receipt(&self) -> Option<&RepairReceipt> {
        self.receipt.as_ref()
    }

    pub fn error(&self) -> Option<&AppError> {
        self.error.as_ref()
    }

    pub fn clear_error(&mut self) {
        self.error = None;
    }

    pub fn set_error(&mut self, error: AppError) {
        if error.browser_closed || error.browser_reconnect_required {
            self.browser_state = BrowserState::Disconnected;
            self.comparison_browser_started = false;
            self.clear_web_authorization();
        } else if error.authentication_expired {
            self.browser_state = BrowserState::Expired;
            self.comparison_browser_started = false;
            self.clear_web_authorization();
        }
        self.error = Some(error);
    }

    pub fn set_database_input(&mut self, value: impl Into<String>) {
        let value = value.into();
        if self.database_input != value {
            self.database_input = value;
            self.invalidate_source_context();
        }
    }

    pub fn set_log_roots_input(&mut self, value: impl Into<String>) {
        let value = value.into();
        if self.log_roots_input != value {
            self.log_roots_input = value;
            self.invalidate_source_context();
        }
    }

    pub fn set_backup_directory_input(&mut self, value: impl Into<String>) {
        let value = value.into();
        if self.backup_directory_input != value {
            self.backup_directory_input = value;
            self.invalidate_repair_confirmation();
            self.clear_process_proof();
            self.receipt = None;
        }
    }

    pub fn install_report(&mut self, report: ScanReport) {
        let mut report_index = HashMap::with_capacity(report.threads.len());
        for thread in &report.threads {
            let indexed = IndexedThread {
                classification: thread.classification(),
                web_review_eligible: thread.source_kind() == "chatgpt"
                    && thread.project_id().is_none()
                    && thread.cwd().is_none(),
                repair_eligible: thread.source_kind() == "chatgpt"
                    && thread.project_id().is_none()
                    && thread.cwd().is_none()
                    && thread.classification() != Classification::Preserved,
            };
            match report_index.entry(thread.identity().clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(indexed);
                }
                Entry::Occupied(mut entry) => {
                    entry.get_mut().repair_eligible = false;
                    entry.get_mut().web_review_eligible = false;
                }
            }
        }
        self.database_input = report
            .database_path
            .as_path()
            .to_string_lossy()
            .into_owned();
        self.report = Some(report);
        self.web_comparison = None;
        self.report_index = report_index;
        self.clear_authorization();
        self.receipt = None;
        self.error = None;
    }

    pub fn set_process_state(&mut self, process_state: ProcessState) {
        self.set_process_state_at(process_state, Instant::now());
    }

    pub fn set_process_state_at(&mut self, process_state: ProcessState, now: Instant) {
        self.process_state = process_state;
        self.process_proof_observed_at = if process_state == ProcessState::StoppedVerified {
            Some(now)
        } else {
            None
        };
    }

    pub fn begin(&mut self, operation: Operation) -> JobId {
        debug_assert!(operation.is_busy(), "begin requires a busy operation");
        let job_id = JobId(self.next_job);
        self.next_job = self.next_job.wrapping_add(1).max(1);
        self.operation = operation;
        self.active_job = Some(job_id);
        let quiet_check = (operation == Operation::CheckingLogin
            && self.browser_state == BrowserState::LoginOpen)
            || (operation == Operation::CheckingBrowser && self.should_monitor_comparison())
            || operation == Operation::Checking;
        if !quiet_check {
            self.error = None;
        }
        if matches!(
            operation,
            Operation::RestoringBrowser
                | Operation::OpeningBrowser
                | Operation::CheckingLogin
                | Operation::AuthenticatingBrowser
                | Operation::DisconnectingBrowser
                | Operation::ComparingWeb
        ) && !quiet_check
        {
            self.clear_web_authorization();
        }
        match operation {
            Operation::RestoringBrowser | Operation::AuthenticatingBrowser => {
                self.browser_state = BrowserState::Connecting;
            }
            Operation::OpeningBrowser | Operation::CheckingLogin => {
                self.browser_state = BrowserState::LoginOpen;
                self.comparison_browser_started = false;
            }
            Operation::DisconnectingBrowser => {
                self.browser_state = BrowserState::Disconnected;
                self.comparison_browser_started = false;
            }
            _ => {}
        }
        if operation == Operation::Repairing {
            self.receipt = None;
        }
        job_id
    }

    pub fn apply_job_event(&mut self, event: JobEvent) -> bool {
        if self.active_job != Some(event.job_id()) {
            return false;
        }

        self.operation = Operation::Idle;
        self.active_job = None;

        if matches!(
            &event,
            JobEvent::BrowserRestored { .. }
                | JobEvent::BrowserOpened { .. }
                | JobEvent::BrowserAuthenticated { .. }
                | JobEvent::BrowserDisconnected { .. }
        ) {
            self.clear_web_authorization();
        }

        match event {
            JobEvent::BrowserRestored { result, .. } => match result {
                Ok(restored) => {
                    self.comparison_browser_started = restored;
                    self.browser_state = if restored {
                        BrowserState::Connected
                    } else {
                        BrowserState::Disconnected
                    };
                }
                Err(error) => self.authentication_failed(error),
            },
            JobEvent::BrowserOpened { result, .. } => match result {
                Ok(()) => {
                    self.browser_state = BrowserState::LoginOpen;
                    self.comparison_browser_started = false;
                }
                Err(error) => self.browser_failed(error),
            },
            JobEvent::LoginWindowChecked { result, .. } => match result {
                Ok(closed) => {
                    if closed {
                        self.clear_web_authorization();
                        self.error = None;
                    }
                    self.comparison_browser_started = false;
                    self.browser_state = if closed {
                        BrowserState::AwaitingVerification
                    } else {
                        BrowserState::LoginOpen
                    };
                }
                Err(error) => self.browser_failed(error),
            },
            JobEvent::BrowserAuthenticated { result, .. } => match result {
                Ok(()) => {
                    self.browser_state = BrowserState::Connected;
                    self.comparison_browser_started = true;
                }
                Err(error)
                    if error.login_browser_still_open
                        && !error.authentication_expired
                        && error.outcome == ErrorOutcome::NoDataChange =>
                {
                    self.browser_state = BrowserState::LoginOpen;
                    self.comparison_browser_started = false;
                    self.set_error(error);
                }
                Err(error) => self.authentication_failed(error),
            },
            JobEvent::BrowserWindowChecked { result, .. } => match result {
                Ok(false) => {}
                Ok(true) => {
                    self.browser_state = BrowserState::Disconnected;
                    self.comparison_browser_started = false;
                    self.clear_web_authorization();
                    self.error = None;
                }
                Err(error) => self.browser_failed(error),
            },
            JobEvent::BrowserDisconnected { result, .. } => {
                self.browser_state = BrowserState::Disconnected;
                self.comparison_browser_started = false;
                self.error = result.err();
            }
            JobEvent::WebCompared { result, .. } => match result {
                Ok(proof) => self.install_web_comparison(proof),
                Err(error) => {
                    self.clear_web_authorization();
                    self.set_error(error);
                }
            },
            JobEvent::DiscoveryFinished { result, .. } => match result {
                Ok(paths) => {
                    let first = paths
                        .first()
                        .map(|path| path.to_string_lossy().into_owned());
                    if let Some(first) = first {
                        self.set_database_input(first);
                    }
                    self.discovered_paths = paths;
                }
                Err(error) => self.set_error(error),
            },
            JobEvent::ScanFinished { result, .. } => match result {
                Ok(report) => self.install_report(report),
                Err(error) => {
                    self.clear_report();
                    self.clear_authorization();
                    self.receipt = None;
                    self.set_error(error);
                }
            },
            JobEvent::ProcessChecked {
                observed_at,
                result,
                ..
            } => match result {
                Ok(presence) => self.set_process_state_at(presence.into(), observed_at),
                Err(error) => {
                    self.set_process_state(ProcessState::Unknown);
                    self.set_error(error);
                }
            },
            JobEvent::RepairFinished { result, .. } => match result {
                Ok(receipt) => {
                    self.clear_report();
                    self.receipt = Some(receipt);
                    self.clear_authorization();
                }
                Err(error) => {
                    if error.outcome == ErrorOutcome::OutcomeUncertain {
                        self.clear_report();
                    }
                    self.clear_authorization();
                    self.set_error(error);
                }
            },
        }
        true
    }

    pub fn fail_active(&mut self, job_id: JobId, error: AppError) -> bool {
        if self.active_job != Some(job_id) {
            return false;
        }
        let disconnecting = self.operation == Operation::DisconnectingBrowser;
        match self.operation {
            Operation::RestoringBrowser
            | Operation::OpeningBrowser
            | Operation::CheckingLogin
            | Operation::CheckingBrowser
            | Operation::AuthenticatingBrowser
            | Operation::DisconnectingBrowser => {
                self.clear_web_authorization();
                self.browser_state = BrowserState::Disconnected;
                self.comparison_browser_started = false;
            }
            Operation::ComparingWeb => self.clear_web_authorization(),
            Operation::Scanning => {
                self.clear_report();
                self.clear_authorization();
                self.receipt = None;
            }
            Operation::Checking => {
                self.set_process_state(ProcessState::Unknown);
            }
            Operation::Repairing => {
                if error.outcome == ErrorOutcome::OutcomeUncertain {
                    self.clear_report();
                }
                self.clear_authorization();
            }
            Operation::Idle | Operation::Discovering => {}
        }
        self.operation = Operation::Idle;
        self.active_job = None;
        if disconnecting {
            self.error = Some(error);
        } else {
            self.set_error(error);
        }
        true
    }

    pub fn is_selectable(&self, identity: &ThreadIdentity) -> bool {
        if self.web_verdict(identity) == WebVerdict::Present {
            return false;
        }
        self.indexed_thread(identity).is_some_and(|thread| {
            (thread.repair_eligible
                || (thread.web_review_eligible
                    && self.web_verdict(identity) == WebVerdict::Unavailable))
                && match self.effective_classification(identity) {
                    Classification::ConfirmedDeleted => true,
                    Classification::ReviewRequired => self.reviewed.contains(identity),
                    Classification::Preserved => false,
                }
        })
    }

    pub fn effective_classification(&self, identity: &ThreadIdentity) -> Classification {
        self.report_index
            .get(identity)
            .map_or(Classification::Preserved, |thread| {
                if thread.classification == Classification::Preserved
                    && thread.web_review_eligible
                    && self.web_verdict(identity) == WebVerdict::Unavailable
                {
                    Classification::ReviewRequired
                } else {
                    thread.classification
                }
            })
    }

    pub fn set_reviewed(&mut self, identity: &ThreadIdentity, reviewed: bool) -> bool {
        let review_required = self.indexed_thread(identity).is_some_and(|thread| {
            (thread.repair_eligible || thread.web_review_eligible)
                && self.effective_classification(identity) == Classification::ReviewRequired
        });
        if !review_required {
            return false;
        }

        let mut selection_changed = false;
        let changed = if reviewed {
            self.reviewed.insert(identity.clone())
        } else {
            let review_changed = self.reviewed.remove(identity);
            selection_changed = self.selected.remove(identity);
            review_changed || selection_changed
        };
        if changed {
            self.invalidate_repair_confirmation();
        }
        if selection_changed {
            self.clear_process_proof();
            self.refresh_web_selection();
        }
        changed
    }

    pub fn set_selected(&mut self, identity: &ThreadIdentity, selected: bool) -> bool {
        let changed = if selected {
            if !self.is_selectable(identity) {
                return false;
            }
            self.selected.insert(identity.clone())
        } else {
            self.selected.remove(identity)
        };
        if changed {
            self.invalidate_repair_confirmation();
            self.clear_process_proof();
            self.refresh_web_selection();
        }
        changed
    }

    pub fn select_all_confirmed(&mut self) {
        let confirmed = self
            .report
            .as_ref()
            .map(|_| {
                self.report_index
                    .iter()
                    .filter(|(identity, thread)| {
                        thread.repair_eligible
                            && thread.classification == Classification::ConfirmedDeleted
                            && self.web_verdict(identity) != WebVerdict::Present
                    })
                    .map(|(identity, _)| identity.clone())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        if self.selected != confirmed {
            self.selected = confirmed;
            self.invalidate_repair_confirmation();
            self.clear_process_proof();
            self.refresh_web_selection();
        }
    }

    pub fn clear_selection(&mut self) {
        if !self.selected.is_empty() {
            self.selected.clear();
            self.invalidate_repair_confirmation();
            self.clear_process_proof();
            self.web_selection_valid = false;
        }
    }

    pub fn can_repair(&self) -> bool {
        self.repair_readiness().can_repair()
    }

    pub fn can_repair_at(&self, now: Instant) -> bool {
        self.repair_readiness_at(now).can_repair()
    }

    pub fn prepare_repair_confirmation(&self) -> Option<RepairConfirmation> {
        self.can_repair().then_some(RepairConfirmation {
            revision: self.repair_revision,
            selected_count: self.selected.len(),
        })
    }

    pub fn can_confirm_repair_at(&self, confirmation: RepairConfirmation, now: Instant) -> bool {
        confirmation.revision == self.repair_revision
            && confirmation.selected_count == self.selected.len()
            && self.can_repair_at(now)
    }

    pub fn repair_readiness(&self) -> RepairReadiness {
        self.repair_readiness_at(Instant::now())
    }

    pub fn repair_readiness_at(&self, now: Instant) -> RepairReadiness {
        RepairReadiness {
            platform_allowed: self.platform.allows_mutation(),
            report_ready: self
                .report
                .as_ref()
                .is_some_and(|report| report.schema.write_capable && report.integrity_ok),
            // Selection mutators admit only indexed eligible identities, and every
            // report/review invalidation removes identities that cease to be valid.
            selection_valid: !self.selected.is_empty(),
            process_stopped: self.process_proof_is_valid_at(now),
            web_verified: self.run_mode == RunMode::Demo
                || (self.web_selection_valid
                    && self
                        .web_comparison
                        .as_ref()
                        .is_some_and(|proof| proof.is_fresh_at(now))),
            // Filesystem and platform-specific path safety remain worker checks.
            backup_directory_present: !self.backup_directory_input.trim().is_empty(),
            idle: !self.operation.is_foreground(),
        }
    }

    fn invalidate_source_context(&mut self) {
        self.clear_report();
        self.discovered_paths.clear();
        self.clear_authorization();
        self.receipt = None;
        self.error = None;
    }

    fn clear_authorization(&mut self) {
        self.web_selection_valid = false;
        self.reviewed.clear();
        self.selected.clear();
        self.invalidate_repair_confirmation();
        self.clear_process_proof();
    }

    fn invalidate_repair_confirmation(&mut self) {
        self.repair_revision = self.repair_revision.wrapping_add(1);
    }

    fn clear_web_authorization(&mut self) {
        self.web_comparison = None;
        self.clear_authorization();
    }

    fn browser_failed(&mut self, error: AppError) {
        self.browser_state = BrowserState::Disconnected;
        self.comparison_browser_started = false;
        self.clear_web_authorization();
        self.set_error(error);
    }

    fn authentication_failed(&mut self, error: AppError) {
        if error.authentication_retryable
            && !error.authentication_expired
            && !error.login_browser_still_open
            && !error.browser_closed
            && !error.browser_reconnect_required
            && error.outcome == ErrorOutcome::NoDataChange
        {
            self.browser_state = BrowserState::AwaitingVerification;
            self.comparison_browser_started = true;
            self.clear_web_authorization();
            self.set_error(error);
        } else {
            self.browser_failed(error);
        }
    }

    fn clear_report(&mut self) {
        self.report = None;
        self.web_comparison = None;
        self.web_selection_valid = false;
        self.report_index.clear();
    }

    fn indexed_thread(&self, identity: &ThreadIdentity) -> Option<&IndexedThread> {
        #[cfg(test)]
        self.index_lookup_count
            .set(self.index_lookup_count.get().saturating_add(1));
        self.report_index.get(identity)
    }

    fn refresh_web_selection(&mut self) {
        self.web_selection_valid = self.report.as_ref().is_some_and(|report| {
            self.web_comparison.as_ref().is_some_and(|proof| {
                let identities = self.selected.iter().cloned().collect::<Vec<_>>();
                proof.permits(report, &identities, Instant::now())
            })
        });
    }

    fn clear_process_proof(&mut self) {
        self.process_state = ProcessState::NotChecked;
        self.process_proof_observed_at = None;
    }

    fn process_proof_is_valid_at(&self, now: Instant) -> bool {
        self.process_proof_remaining_at(now).is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::model::{CatalogThread, DeletionEvidence, LocalPath, SchemaReport};

    #[test]
    fn stored_error_switches_language_without_changing_flags_or_details() {
        let mut state = AppState::new(RunMode::Demo, PlatformPolicy::MacOs);
        let error = AppError::outcome_uncertain("정리 결과를 확인하지 못함")
            .with_english("Could not confirm the cleanup result")
            .with_details("preserved backup: /synthetic/backups/catalog.db");
        state.set_error(error.clone());
        let stored = state.error().unwrap();
        assert_eq!(stored.message_for(Language::Korean), error.message);
        assert_eq!(
            stored.message_for(Language::English),
            "Could not confirm the cleanup result"
        );
        assert_eq!(state.error(), Some(&error));
        assert_eq!(stored.outcome, ErrorOutcome::OutcomeUncertain);
        assert_eq!(
            stored.details.as_deref(),
            Some("preserved backup: /synthetic/backups/catalog.db")
        );
        for error in [
            AppError::login_required("로그인 필요"),
            AppError::retryable_authentication("다시 확인 필요"),
            AppError::login_browser_still_open(),
            AppError::browser_closed(),
            AppError::browser_reconnect_required("다시 연결 필요"),
        ] {
            let localized = error.clone().with_english("English explanation");
            assert_eq!(
                localized.message_for(Language::English),
                "English explanation"
            );
            assert_eq!(localized.outcome, error.outcome);
            assert_eq!(
                localized.authentication_expired,
                error.authentication_expired
            );
            assert_eq!(
                localized.authentication_retryable,
                error.authentication_retryable
            );
            assert_eq!(
                localized.login_browser_still_open,
                error.login_browser_still_open
            );
            assert_eq!(localized.browser_closed, error.browser_closed);
            assert_eq!(
                localized.browser_reconnect_required,
                error.browser_reconnect_required
            );
        }
    }

    #[test]
    fn untranslated_custom_error_keeps_its_original_text() {
        let error = AppError::no_data_change("custom diagnostic");
        assert_eq!(error.message_for(Language::Korean), "custom diagnostic");
        assert_eq!(error.message_for(Language::English), "custom diagnostic");
        assert_eq!(error.details, None);
    }

    fn large_report(count: usize) -> ScanReport {
        let evidence_path = LocalPath::try_from(Path::new("/synthetic/deletion.log"))
            .expect("synthetic path is UTF-8");
        let threads = (0..count)
            .map(|index| {
                CatalogThread::confirmed_deleted(
                    ThreadIdentity::new("host-performance", format!("thread-{index}")),
                    format!("성능 행 {index}"),
                    "chatgpt",
                    true,
                    None,
                    None,
                    DeletionEvidence {
                        source_path: evidence_path.clone(),
                        reason: "synthetic exact deletion marker".to_owned(),
                    },
                )
                .expect("synthetic confirmed row is valid")
            })
            .collect();
        ScanReport::new(
            LocalPath::try_from(Path::new("/synthetic/codex-dev.db"))
                .expect("synthetic path is UTF-8"),
            PlatformPolicy::MacOs.label(),
            SchemaReport {
                write_capable: true,
                reason: "synthetic supported schema".to_owned(),
                fingerprint: "synthetic-performance".to_owned(),
                columns: vec!["host_id".to_owned(), "thread_id".to_owned()],
            },
            threads,
            true,
        )
    }

    #[test]
    fn ten_thousand_point_queries_are_linear_and_repair_gate_is_constant() {
        const ROW_COUNT: usize = 10_000;
        let mut state = AppState::new(RunMode::Demo, PlatformPolicy::MacOs);
        state.install_report(large_report(ROW_COUNT));
        state.set_backup_directory_input("/synthetic/backups");
        assert_eq!(state.report_index.len(), ROW_COUNT);

        state.index_lookup_count.set(0);
        for index in 0..ROW_COUNT {
            assert!(state.is_selectable(&ThreadIdentity::new(
                "host-performance",
                format!("thread-{index}"),
            )));
        }
        assert_eq!(state.index_lookup_count.get(), ROW_COUNT);

        state.select_all_confirmed();
        state.set_process_state(ProcessState::StoppedVerified);

        state.index_lookup_count.set(0);

        assert!(state.can_repair());
        assert_eq!(state.index_lookup_count.get(), 0);
    }
}
