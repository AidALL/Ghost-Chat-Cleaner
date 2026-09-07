use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};

use crate::app_state::{
    AppError, AppState, BrowserState, ErrorOutcome, JobEvent, JobId, Operation, ProcessState,
    RepairBlocker, RepairConfirmation, RunMode,
};
use crate::model::{
    CatalogThread, Classification, DeletionEvidence, LocalPath, RepairReceipt, ScanReport,
    SchemaReport, ThreadIdentity,
};
use crate::platform::{CatalogPathInputs, PlatformPolicy};
use crate::process_guard::ProcessPresence;
use crate::web::WebVerdict;
use crate::worker::{backend_for_mode, LiveWorker, ScanInputs, WorkerRequest};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ResultFilter {
    #[default]
    All,
    Confirmed,
    Review,
    Preserved,
}

impl ResultFilter {
    const ALL: [Self; 4] = [Self::All, Self::Confirmed, Self::Review, Self::Preserved];

    const fn label(self) -> &'static str {
        match self {
            Self::All => "전체",
            Self::Confirmed => "삭제 기록",
            Self::Review => "검토 필요",
            Self::Preserved => "유지",
        }
    }

    const fn includes(self, classification: Classification) -> bool {
        match self {
            Self::All => true,
            Self::Confirmed => matches!(classification, Classification::ConfirmedDeleted),
            Self::Review => matches!(classification, Classification::ReviewRequired),
            Self::Preserved => matches!(classification, Classification::Preserved),
        }
    }
}

pub struct GhostChatApp {
    state: AppState,
    worker: Option<LiveWorker>,
    filter: ResultFilter,
    worker_disconnected: bool,
    next_login_check: Instant,
    next_process_check: Instant,
    pending_list_check: bool,
    repair_confirmation: Option<RepairConfirmation>,
}

impl GhostChatApp {
    pub fn new(ctx: &egui::Context, run_mode: RunMode) -> io::Result<Self> {
        install_fonts(ctx);
        let platform = PlatformPolicy::current();
        let repaint_context = ctx.clone();
        let worker = backend_for_mode(run_mode, move || {
            LiveWorker::spawn(move || repaint_context.request_repaint())
        })
        .transpose()?;

        let mut state = AppState::new(run_mode, platform);
        if run_mode == RunMode::Demo {
            state.set_log_roots_input("/demo/logs\n/demo/audit");
            state.install_report(demo_report(platform));
            state.set_backup_directory_input("/demo/backups");
        }

        let mut app = Self {
            state,
            worker,
            filter: ResultFilter::All,
            worker_disconnected: false,
            next_login_check: Instant::now(),
            next_process_check: Instant::now(),
            pending_list_check: false,
            repair_confirmation: None,
        };
        if run_mode == RunMode::Live {
            let job_id = app.state.begin(Operation::RestoringBrowser);
            app.submit_live(job_id, WorkerRequest::restore_browser());
        }
        Ok(app)
    }

    fn poll_worker(&mut self) {
        loop {
            let received = match self.worker.as_ref() {
                Some(worker) => worker.try_recv(),
                None => return,
            };
            match received {
                Ok(Some(event)) => self.accept_event(event),
                Ok(None) => return,
                Err(error) => {
                    if !self.worker_disconnected {
                        self.worker_disconnected = true;
                        self.pending_list_check = false;
                        let app_error = if self.state.operation() == Operation::Repairing {
                            AppError::outcome_uncertain(format!("정리 중 작업이 중단됨: {error}"))
                        } else {
                            AppError::no_data_change(format!(
                                "백그라운드 작업 연결이 종료됨: {error}"
                            ))
                        };
                        if let Some(job_id) = self.state.active_job() {
                            self.state.fail_active(job_id, app_error);
                        } else {
                            self.state.set_error(app_error);
                        }
                    }
                    return;
                }
            }
        }
    }

    fn accept_event(&mut self, event: JobEvent) {
        if let Some((job_id, request)) = self.apply_event(event) {
            self.submit_live(job_id, request);
        }
    }

    fn apply_event(&mut self, event: JobEvent) -> Option<(JobId, WorkerRequest)> {
        let login_closed = matches!(
            &event,
            JobEvent::LoginWindowChecked {
                result: Ok(true),
                ..
            }
        );
        let comparison_closed = matches!(
            &event,
            JobEvent::BrowserWindowChecked {
                result: Ok(true),
                ..
            }
        );
        let compare_after = matches!(
            &event,
            JobEvent::BrowserAuthenticated { result: Ok(()), .. }
                | JobEvent::BrowserRestored {
                    result: Ok(true),
                    ..
                }
                | JobEvent::ScanFinished { result: Ok(_), .. }
        );
        let discovery_count = match &event {
            JobEvent::DiscoveryFinished {
                result: Ok(paths), ..
            } => Some(paths.len()),
            _ => None,
        };
        let failed = matches!(
            &event,
            JobEvent::BrowserRestored { result: Err(_), .. }
                | JobEvent::BrowserOpened { result: Err(_), .. }
                | JobEvent::LoginWindowChecked { result: Err(_), .. }
                | JobEvent::BrowserWindowChecked { result: Err(_), .. }
                | JobEvent::BrowserAuthenticated { result: Err(_), .. }
                | JobEvent::BrowserDisconnected { result: Err(_), .. }
                | JobEvent::WebCompared { result: Err(_), .. }
                | JobEvent::DiscoveryFinished { result: Err(_), .. }
                | JobEvent::ScanFinished { result: Err(_), .. }
                | JobEvent::ProcessChecked { result: Err(_), .. }
                | JobEvent::RepairFinished { result: Err(_), .. }
        );
        let scanned_path = match &event {
            JobEvent::ScanFinished {
                result: Ok(report), ..
            } => Some(report.database_path.as_path().to_path_buf()),
            _ => None,
        };
        let process_checked = matches!(&event, JobEvent::ProcessChecked { .. });
        if !self.state.apply_job_event(event) {
            return None;
        }
        if process_checked {
            self.next_process_check = Instant::now() + Duration::from_secs(1);
        }
        if failed || login_closed || comparison_closed {
            self.pending_list_check = false;
            return None;
        }
        if discovery_count == Some(0) {
            self.state
                .set_error(AppError::no_data_change("대화 목록 파일을 찾지 못함"));
        }
        if let Some(database_path) = scanned_path {
            if self.state.backup_directory_input().trim().is_empty() {
                let backup = default_backup_directory(&database_path, self.state.platform());
                self.state
                    .set_backup_directory_input(backup.to_string_lossy());
            }
        }
        if let Some(count) = discovery_count.filter(|_| self.pending_list_check) {
            if count == 1 && self.state.browser_ready() {
                return self.prepare_scan();
            }
            self.pending_list_check = false;
            if count > 1 {
                self.state.set_error(AppError::no_data_change(
                    "찾은 파일 중 하나를 선택한 뒤 목록 확인 필요",
                ));
            }
            return None;
        }
        if compare_after && self.state.browser_ready() {
            if self.pending_list_check {
                return self.continue_list_check();
            }
            return self.prepare_web_comparison();
        }
        None
    }

    fn submit_live(&mut self, job_id: JobId, request: WorkerRequest) {
        let result = self
            .worker
            .as_ref()
            .ok_or_else(|| "작업을 시작할 수 없음".to_owned())
            .and_then(|worker| {
                worker
                    .submit(job_id, request)
                    .map_err(|error| error.to_string())
            });
        if let Err(error) = result {
            self.pending_list_check = false;
            self.state.fail_active(
                job_id,
                AppError::no_data_change(format!("백그라운드 작업을 시작하지 못함: {error}")),
            );
        }
    }

    fn request_discovery(&mut self) {
        self.pending_list_check = false;
        if self.state.run_mode() == RunMode::Demo {
            let job_id = self.state.begin(Operation::Discovering);
            self.accept_event(JobEvent::DiscoveryFinished {
                job_id,
                result: Ok(vec![PathBuf::from("/demo/codex-dev.db")]),
            });
            return;
        }

        let (job_id, request) = self.prepare_discovery();
        self.submit_live(job_id, request);
    }

    fn prepare_discovery(&mut self) -> (JobId, WorkerRequest) {
        let explicit_path = nonempty_path(self.state.database_input());
        let inputs = CatalogPathInputs {
            explicit_path,
            codex_home: std::env::var_os("CODEX_HOME").map(PathBuf::from),
            home: std::env::var_os("HOME").map(PathBuf::from),
        };
        let job_id = self.state.begin(Operation::Discovering);
        (job_id, WorkerRequest::discover(inputs))
    }

    fn request_scan(&mut self) {
        self.pending_list_check = false;
        if self.state.run_mode() == RunMode::Demo {
            let job_id = self.state.begin(Operation::Scanning);
            self.accept_event(JobEvent::ScanFinished {
                job_id,
                result: Ok(demo_report(self.state.platform())),
            });
            return;
        }

        if let Some((job_id, request)) = self.prepare_scan() {
            self.submit_live(job_id, request);
        }
    }

    fn prepare_scan(&mut self) -> Option<(JobId, WorkerRequest)> {
        let request = WorkerRequest::scan(
            ScanInputs {
                database_path: self.state.database_input().to_owned(),
                log_roots: self.state.log_roots_input().to_owned(),
            },
            self.state.platform(),
        );
        match request {
            Ok(request) => {
                let job_id = self.state.begin(Operation::Scanning);
                Some((job_id, request))
            }
            Err(error) => {
                self.pending_list_check = false;
                self.state
                    .set_error(AppError::no_data_change(error.to_string()));
                None
            }
        }
    }

    fn poll_process(&mut self, ctx: &egui::Context) {
        if self.state.selected().is_empty() || self.worker_disconnected {
            return;
        }
        let now = Instant::now();
        if !self.state.operation().is_busy() && now >= self.next_process_check {
            self.request_process_check();
        }
        ctx.request_repaint_after(
            self.next_process_check
                .saturating_duration_since(now)
                .max(Duration::from_millis(100)),
        );
    }

    fn request_process_check(&mut self) {
        self.next_process_check = Instant::now() + Duration::from_secs(1);
        if self.state.run_mode() == RunMode::Demo {
            let job_id = self.state.begin(Operation::Checking);
            self.accept_event(JobEvent::ProcessChecked {
                job_id,
                observed_at: std::time::Instant::now(),
                result: Ok(ProcessPresence::Stopped),
            });
            return;
        }

        let job_id = self.state.begin(Operation::Checking);
        self.submit_live(job_id, WorkerRequest::check_process());
    }

    fn request_browser_login(&mut self) {
        self.pending_list_check = false;
        if self.state.run_mode() == RunMode::Demo {
            self.state
                .set_error(AppError::no_data_change("예시 화면에서는 로그인할 수 없음"));
            return;
        }
        let job_id = self.state.begin(Operation::OpeningBrowser);
        self.submit_live(job_id, WorkerRequest::open_browser());
        self.next_login_check = Instant::now() + Duration::from_millis(500);
    }

    fn prepare_web_comparison(&mut self) -> Option<(JobId, WorkerRequest)> {
        if self.state.run_mode() == RunMode::Demo
            || !self.state.browser_ready()
            || self.state.operation().is_foreground()
        {
            return None;
        }
        let report = self.state.report().cloned()?;
        self.pending_list_check = false;
        let job_id = self.state.begin(Operation::ComparingWeb);
        Some((job_id, WorkerRequest::compare_web(report)))
    }

    fn can_check_list(&self) -> bool {
        self.state.run_mode() == RunMode::Live
            && !self.state.operation().is_foreground()
            && matches!(
                self.state.browser_state(),
                BrowserState::LoginOpen
                    | BrowserState::AwaitingVerification
                    | BrowserState::Connected
            )
    }

    fn prepare_list_check(&mut self) -> Option<(JobId, WorkerRequest)> {
        if !self.can_check_list() {
            return None;
        }
        self.pending_list_check = true;
        self.continue_list_check()
    }

    fn continue_list_check(&mut self) -> Option<(JobId, WorkerRequest)> {
        if matches!(
            self.state.browser_state(),
            BrowserState::LoginOpen | BrowserState::AwaitingVerification
        ) {
            let job_id = self.state.begin(Operation::AuthenticatingBrowser);
            Some((job_id, WorkerRequest::authenticate_browser()))
        } else if self.state.browser_ready() {
            if self.state.report().is_some() {
                self.prepare_web_comparison()
            } else if nonempty_path(self.state.database_input()).is_some() {
                self.prepare_scan()
            } else {
                Some(self.prepare_discovery())
            }
        } else {
            self.pending_list_check = false;
            None
        }
    }

    fn request_list_check(&mut self) {
        if let Some((job_id, request)) = self.prepare_list_check() {
            self.submit_live(job_id, request);
        }
    }

    fn set_database_source(&mut self, input: impl Into<String>) {
        self.pending_list_check = false;
        self.state.set_database_input(input);
    }

    fn request_browser_disconnect(&mut self) {
        if self.state.run_mode() == RunMode::Demo || self.state.operation().is_foreground() {
            return;
        }
        self.pending_list_check = false;
        let job_id = self.state.begin(Operation::DisconnectingBrowser);
        self.submit_live(job_id, WorkerRequest::disconnect_browser());
    }

    fn poll_login(&mut self, ctx: &egui::Context) {
        if self.state.run_mode() != RunMode::Live
            || self.worker_disconnected
            || (self.state.browser_state() != BrowserState::LoginOpen
                && !self.state.should_monitor_comparison())
        {
            return;
        }
        let now = Instant::now();
        if let Some((job_id, request)) = self.prepare_browser_check() {
            self.submit_live(job_id, request);
        }
        ctx.request_repaint_after(
            self.next_login_check
                .saturating_duration_since(now)
                .max(Duration::from_millis(50)),
        );
    }

    fn prepare_browser_check(&mut self) -> Option<(JobId, WorkerRequest)> {
        let now = Instant::now();
        if self.state.run_mode() != RunMode::Live
            || self.worker_disconnected
            || self.state.operation().is_busy()
            || now < self.next_login_check
        {
            return None;
        }
        let (operation, request) = if self.state.browser_state() == BrowserState::LoginOpen {
            (
                Operation::CheckingLogin,
                WorkerRequest::check_login_window(),
            )
        } else if self.state.should_monitor_comparison() {
            (
                Operation::CheckingBrowser,
                WorkerRequest::check_browser_window(),
            )
        } else {
            return None;
        };
        self.next_login_check = now + Duration::from_millis(500);
        Some((self.state.begin(operation), request))
    }

    fn request_repair(&mut self) {
        self.repair_confirmation = self.state.prepare_repair_confirmation();
        if self.repair_confirmation.is_none() {
            self.state.set_error(AppError::no_data_change(
                self.repair_instruction(Instant::now())
                    .unwrap_or_else(|| "현재 선택한 항목을 정리할 수 없음".to_owned()),
            ));
        }
    }

    fn cancel_repair_confirmation(&mut self) {
        self.repair_confirmation = None;
    }

    fn invalidate_repair_confirmation(&mut self) {
        self.cancel_repair_confirmation();
        self.state.set_error(AppError::no_data_change(
            self.repair_instruction(Instant::now())
                .unwrap_or_else(|| "선택 또는 정리 조건이 바뀜 · 다시 확인 필요".to_owned()),
        ));
    }

    fn accept_repair_confirmation(&mut self) {
        let Some(confirmation) = self.repair_confirmation.take() else {
            return;
        };
        if !self
            .state
            .can_confirm_repair_at(confirmation, Instant::now())
        {
            self.invalidate_repair_confirmation();
            return;
        }

        if self.state.run_mode() == RunMode::Demo {
            let job_id = self.state.begin(Operation::Repairing);
            let mut removed = self.state.selected().iter().cloned().collect::<Vec<_>>();
            removed.sort_by(|left, right| {
                (&left.host_id, &left.thread_id).cmp(&(&right.host_id, &right.thread_id))
            });
            let before_count = self
                .state
                .report()
                .map_or(0, |report| report.threads.len() as u64);
            let receipt = RepairReceipt::new(
                demo_path("/demo/codex-dev.db"),
                demo_path("/demo/backups/ghost-chat-cleaner-demo.backup.db"),
                self.state.platform().label(),
                "d3b07384d113edec49eaa6238ad5ff00d1094fd873076e4f9dfe92c5f1d7c80b",
                removed,
                before_count,
                before_count.saturating_sub(self.state.selected().len() as u64),
            );
            self.accept_event(JobEvent::RepairFinished {
                job_id,
                result: Ok(receipt),
            });
            return;
        }

        let Some(report) = self.state.report().cloned() else {
            self.state
                .set_error(AppError::no_data_change("불러온 대화 없음"));
            return;
        };
        let request = WorkerRequest::repair(
            report,
            self.state.log_roots_input(),
            self.state.selected(),
            self.state.reviewed(),
            self.state.backup_directory_input(),
        );
        match request {
            Ok(request) => {
                let job_id = self.state.begin(Operation::Repairing);
                self.submit_live(job_id, request);
            }
            Err(error) => self
                .state
                .set_error(AppError::no_data_change(error.to_string())),
        }
    }

    fn render_header(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Ghost Chat Cleaner");
            if self.state.run_mode() == RunMode::Demo {
                ui.label("예시 데이터");
            }
            if self.state.operation().is_foreground() {
                ui.spinner();
                ui.label(operation_label(self.state.operation()));
            }
        });
        if self.state.platform() == PlatformPolicy::Linux {
            ui.label("Linux · 조회만 가능");
        }
    }

    fn render_source(&mut self, ui: &mut egui::Ui) {
        let busy = self.state.operation().is_foreground();
        section(ui, "대화 목록 파일", |ui| {
            ui.horizontal(|ui| {
                let mut database = self.state.database_input().to_owned();
                let response = ui.add_enabled(
                    !busy,
                    egui::TextEdit::singleline(&mut database)
                        .desired_width((ui.available_width() - 190.0).max(120.0))
                        .hint_text("파일 경로"),
                );
                if response.changed() {
                    self.set_database_source(database);
                }
                if ui
                    .add_enabled(!busy, egui::Button::new("자동 찾기"))
                    .clicked()
                {
                    self.request_discovery();
                }
                if ui
                    .add_enabled(!busy, egui::Button::new("불러오기"))
                    .clicked()
                {
                    self.request_scan();
                }
            });

            if self.state.discovered_paths().len() > 1 {
                let paths = self.state.discovered_paths().to_vec();
                ui.horizontal_wrapped(|ui| {
                    ui.label("찾은 파일:");
                    for path in paths {
                        let text = path.to_string_lossy();
                        if ui
                            .add_enabled(!busy, egui::Button::new(text.as_ref()).small())
                            .on_hover_text(text.as_ref())
                            .clicked()
                        {
                            self.set_database_source(text.into_owned());
                        }
                    }
                });
            }

            ui.collapsing("추가 설정", |ui| {
                ui.label("삭제 기록 폴더 (선택)");
                let mut log_roots = self.state.log_roots_input().to_owned();
                let response = ui.add_enabled(
                    !busy,
                    egui::TextEdit::multiline(&mut log_roots)
                        .desired_rows(2)
                        .desired_width(f32::INFINITY)
                        .hint_text("경로를 한 줄에 하나씩 입력"),
                );
                if response.changed() {
                    self.pending_list_check = false;
                    self.state.set_log_roots_input(log_roots);
                }
            });
        });
    }

    fn render_results(&mut self, ui: &mut egui::Ui) {
        section(ui, "대화 목록", |ui| {
            let Some(thread_count) = self.state.report().map(|report| report.threads.len()) else {
                ui.label("불러온 대화 없음");
                return;
            };

            ui.horizontal_wrapped(|ui| {
                ui.label(format!(
                    "전체 {}개 · 선택 {}개",
                    thread_count,
                    self.state.selected().len()
                ));
                ui.separator();
                egui::ComboBox::from_id_salt("result-filter")
                    .selected_text(self.filter.label())
                    .show_ui(ui, |ui| {
                        for filter in ResultFilter::ALL {
                            ui.selectable_value(&mut self.filter, filter, filter.label());
                        }
                    });
                if ui
                    .add_enabled(
                        !self.state.operation().is_foreground(),
                        egui::Button::new("자동 선택"),
                    )
                    .on_hover_text("삭제 기록이 있는 정리 후보 선택 · 웹에 있는 대화 제외")
                    .clicked()
                {
                    self.state.select_all_confirmed();
                }
                if ui
                    .add_enabled(
                        !self.state.operation().is_foreground()
                            && !self.state.selected().is_empty(),
                        egui::Button::new("선택 해제"),
                    )
                    .clicked()
                {
                    self.state.clear_selection();
                }
            });
            let filter = self.filter;
            let state = &self.state;
            let rows = state
                .report()
                .expect("report was present for this render")
                .threads
                .iter()
                .filter(|thread| filter.includes(state.effective_classification(thread.identity())))
                .collect::<Vec<_>>();
            let mut review_changes = Vec::new();
            let mut selection_changes = Vec::new();

            TableBuilder::new(ui)
                .id_salt("classified-threads")
                .striped(true)
                .resizable(false)
                .min_scrolled_height(0.0)
                .auto_shrink([false, false])
                .column(Column::initial(64.0).at_least(60.0).clip(true))
                .column(Column::initial(42.0).at_least(38.0).clip(true))
                .column(Column::remainder().at_least(160.0).clip(true))
                .column(Column::initial(88.0).at_least(76.0).clip(true))
                .column(Column::initial(90.0).at_least(76.0).clip(true))
                .header(24.0, |mut header| {
                    for title in ["검토", "선택", "제목", "상태", "웹 확인"] {
                        header.col(|ui| {
                            ui.strong(title);
                        });
                    }
                })
                .body(|body| {
                    body.rows(28.0, rows.len(), |mut row| {
                        let thread = rows[row.index()];
                        let identity = thread.identity();
                        let classification = state.effective_classification(identity);
                        row.col(|ui| match classification {
                            Classification::ReviewRequired => {
                                let mut reviewed = state.reviewed().contains(identity);
                                let label = review_checkbox_label(thread);
                                let response = ui
                                    .push_id(
                                        ("review", &identity.host_id, &identity.thread_id),
                                        |ui| {
                                            ui.add_enabled(
                                                !state.operation().is_foreground(),
                                                egui::Checkbox::new(&mut reviewed, "확인"),
                                            )
                                        },
                                    )
                                    .inner;
                                response.widget_info(|| {
                                    egui::WidgetInfo::selected(
                                        egui::WidgetType::Checkbox,
                                        !state.operation().is_foreground(),
                                        reviewed,
                                        &label,
                                    )
                                });
                                if response
                                    .on_hover_text(format!(
                                        "{label}\n내용을 직접 검토했다는 별도 확인"
                                    ))
                                    .changed()
                                {
                                    review_changes.push((identity.clone(), reviewed));
                                }
                            }
                            Classification::ConfirmedDeleted | Classification::Preserved => {
                                ui.label("—");
                            }
                        });
                        row.col(|ui| {
                            let mut selected = state.selected().contains(identity);
                            let enabled =
                                !state.operation().is_foreground() && state.is_selectable(identity);
                            let label = selection_checkbox_label(thread);
                            let response = ui
                                .push_id(("select", &identity.host_id, &identity.thread_id), |ui| {
                                    ui.add_enabled(
                                        enabled,
                                        egui::Checkbox::without_text(&mut selected),
                                    )
                                })
                                .inner;
                            response.widget_info(|| {
                                egui::WidgetInfo::selected(
                                    egui::WidgetType::Checkbox,
                                    enabled,
                                    selected,
                                    &label,
                                )
                            });
                            if response
                                .on_hover_text(if enabled {
                                    format!("{label}\n정리할 항목 선택")
                                } else {
                                    format!("{label}\n검토 확인이 필요하거나 선택할 수 없는 항목")
                                })
                                .changed()
                            {
                                selection_changes.push((identity.clone(), selected));
                            }
                        });
                        row.col(|ui| {
                            let mut details = format!(
                                "{}\n{}\n{}",
                                thread.display_title(),
                                identity.host_id,
                                identity.thread_id
                            );
                            if let Some(evidence) = thread.evidence() {
                                details.push_str(&format!(
                                    "\n{}\n{}",
                                    evidence.reason,
                                    evidence.source_path.as_path().display()
                                ));
                            }
                            ui.add(egui::Label::new(thread.display_title()).truncate())
                                .on_hover_text(details);
                        });
                        row.col(|ui| {
                            if classification != thread.classification() {
                                ui.label("검토 필요");
                            } else {
                                classification_label(ui, classification);
                            }
                        });
                        row.col(|ui| {
                            ui.label(if state.run_mode() == RunMode::Demo {
                                "—"
                            } else {
                                match state.web_verdict(identity) {
                                    WebVerdict::Present => "웹에 있음",
                                    WebVerdict::Unavailable => "조회 불가",
                                    WebVerdict::Unknown => "미확인",
                                }
                            });
                        });
                    });
                });

            for (identity, reviewed) in review_changes {
                self.state.set_reviewed(&identity, reviewed);
            }
            for (identity, selected) in selection_changes {
                self.state.set_selected(&identity, selected);
            }
        });
    }

    fn render_web(&mut self, ui: &mut egui::Ui) {
        let busy = self.state.operation().is_foreground();
        let demo = self.state.run_mode() == RunMode::Demo;
        egui::Frame::group(ui.style())
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_wrapped(|ui| {
                    ui.heading("ChatGPT 연결");
                    if ui
                        .add_enabled(
                            !busy
                                && !demo
                                && matches!(
                                    self.state.browser_state(),
                                    BrowserState::Disconnected
                                        | BrowserState::Expired
                                        | BrowserState::AwaitingVerification
                                ),
                            egui::Button::new("로그인"),
                        )
                        .clicked()
                    {
                        self.request_browser_login();
                    }
                    if ui
                        .add_enabled(self.can_check_list(), egui::Button::new("목록 확인"))
                        .clicked()
                    {
                        self.request_list_check();
                    }
                    if ui
                        .add_enabled(!busy && !demo, egui::Button::new("연결 해제"))
                        .on_hover_text("전용 브라우저를 닫고 이 앱에 저장된 로그인 삭제")
                        .clicked()
                    {
                        self.request_browser_disconnect();
                    }
                    if !demo {
                        ui.label(match self.state.browser_state() {
                            BrowserState::Disconnected => "연결 안 됨",
                            BrowserState::LoginOpen => "확인 대기",
                            BrowserState::Connecting => "연결 중",
                            BrowserState::AwaitingVerification => "연결 확인 필요",
                            BrowserState::Connected => "연결됨",
                            BrowserState::Expired => "로그인 필요",
                        });
                    }
                });
            });
    }

    fn render_repair(&mut self, ui: &mut egui::Ui) {
        if self.state.report().is_none() {
            return;
        }
        let busy = self.state.operation().is_foreground();
        let now = Instant::now();
        let selected = self.state.selected().len();
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.strong("선택 항목 정리");
                if selected > 0 {
                    ui.label(format!(
                        "ChatGPT 데스크톱 앱 · {}",
                        process_label(self.state.process_state_at(now))
                    ));
                } else {
                    ui.label("정리할 항목을 선택");
                }
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let label = if selected == 0 {
                    "선택 항목 정리".to_owned()
                } else {
                    format!("선택 {selected}개 정리")
                };
                let button =
                    egui::Button::new(RichText::new(label).size(16.0).color(Color32::WHITE))
                        .min_size(egui::vec2(168.0, 38.0))
                        .fill(Color32::from_rgb(160, 42, 42));
                if ui
                    .add_enabled(self.state.can_repair_at(now), button)
                    .on_hover_text("이 기기의 대화 목록에서 선택 항목을 제거한다")
                    .clicked()
                {
                    self.request_repair();
                }
            });
        });
        if selected > 0 {
            ui.horizontal(|ui| {
                ui.menu_button("백업 위치", |ui| {
                    ui.set_min_width(360.0);
                    let mut backup = self.state.backup_directory_input().to_owned();
                    if ui
                        .add_enabled(
                            !busy,
                            egui::TextEdit::singleline(&mut backup)
                                .desired_width(f32::INFINITY)
                                .hint_text("백업을 저장할 폴더 경로"),
                        )
                        .changed()
                    {
                        self.state.set_backup_directory_input(backup);
                    }
                });
                if let Some(instruction) = self.repair_instruction(now) {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(instruction);
                        if self.state.repair_readiness_at(now).blocker()
                            == Some(RepairBlocker::WebVerification)
                            && self.state.browser_ready()
                            && ui
                                .add_enabled(self.can_check_list(), egui::Button::new("목록 확인"))
                                .clicked()
                        {
                            self.request_list_check();
                        }
                        if self.state.process_state_at(now) == ProcessState::Unknown
                            && ui
                                .add_enabled(!busy, egui::Button::new("다시 확인"))
                                .clicked()
                        {
                            self.request_process_check();
                        }
                    });
                }
            });
        }
    }

    fn repair_instruction(&self, now: Instant) -> Option<String> {
        let instruction = match self.state.repair_readiness_at(now).blocker()? {
            RepairBlocker::Busy => "진행 중인 작업 완료 대기",
            RepairBlocker::Platform => "이 운영체제에서는 조회만 가능",
            RepairBlocker::Report => "이 파일은 정리할 수 없음 · 대화 목록 파일 확인 필요",
            RepairBlocker::Selection => "검토 확인 후 정리할 항목 선택 필요",
            RepairBlocker::WebVerification => {
                if self.state.browser_ready() {
                    if self
                        .state
                        .web_comparison()
                        .is_some_and(|proof| !proof.is_fresh_at(now))
                    {
                        "웹 확인이 만료됨 · 「목록 확인」을 다시 실행"
                    } else {
                        "선택 항목의 웹 확인 필요 · 「목록 확인」을 다시 실행"
                    }
                } else if matches!(
                    self.state.browser_state(),
                    BrowserState::Disconnected | BrowserState::Expired
                ) {
                    "「로그인」 후 「목록 확인」 필요"
                } else {
                    "「목록 확인」으로 ChatGPT 연결 확인 필요"
                }
            }
            RepairBlocker::BackupDirectory => "「백업 위치」에서 저장할 폴더 지정 필요",
            RepairBlocker::DesktopProcess => {
                if self.state.process_proof_expired_at(now) {
                    "ChatGPT 데스크톱 앱 상태 확인 중"
                } else if self.state.process_state_at(now) == ProcessState::Unknown {
                    "ChatGPT 데스크톱 앱 상태 확인 불가"
                } else if self.state.process_state_at(now) == ProcessState::Running {
                    "ChatGPT 데스크톱 앱을 종료하면 정리 가능 · 브라우저는 열어 둠"
                } else {
                    "ChatGPT 데스크톱 앱 상태 확인 중"
                }
            }
        };
        Some(instruction.to_owned())
    }

    fn render_repair_confirmation(&mut self, ctx: &egui::Context) {
        let Some(confirmation) = self.repair_confirmation else {
            return;
        };
        if !self
            .state
            .can_confirm_repair_at(confirmation, Instant::now())
        {
            self.invalidate_repair_confirmation();
            return;
        }
        let mut accept = false;
        let modal = egui::Modal::new(egui::Id::new("confirm-selected-cleanup")).show(ctx, |ui| {
            ui.set_width(360.0);
            ui.heading(format!(
                "선택 {}개 정리 확인",
                confirmation.selected_count()
            ));
            ui.add_space(8.0);
            ui.label("백업을 만든 뒤 이 기기의 대화 목록에서 선택 항목을 제거한다.");
            ui.label("ChatGPT 웹 대화는 삭제하지 않는다.");
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("취소").clicked() {
                    ui.close();
                }
                if ui
                    .button(format!("{}개 정리", confirmation.selected_count()))
                    .clicked()
                {
                    accept = true;
                }
            });
        });
        if modal.should_close() {
            self.cancel_repair_confirmation();
        } else if accept {
            self.accept_repair_confirmation();
        }
    }

    fn render_receipt(&self, ui: &mut egui::Ui) {
        if let Some(receipt) = self.state.receipt() {
            section(ui, "정리 완료", |ui| {
                ui.label(format!("{}개 정리됨", receipt.removed_identities.len()));
                ui.horizontal(|ui| {
                    ui.label("백업:");
                    clipped_label(ui, &receipt.backup_path.as_path().to_string_lossy());
                });
                ui.collapsing("상세 정보", |ui| {
                    ui.label(format!(
                        "대화 수: {} → {}",
                        receipt.before_count, receipt.after_count
                    ));
                    ui.horizontal(|ui| {
                        ui.label("SHA-256:");
                        clipped_label(ui, &receipt.backup_hash);
                    });
                });
            });
        }
    }

    fn render_error(&mut self, ui: &mut egui::Ui) {
        let Some(error) = self.state.error().cloned() else {
            return;
        };
        let (heading, color) = match error.outcome {
            ErrorOutcome::NoDataChange => ("작업 실패 · 데이터 변경 없음", Color32::DARK_RED),
            ErrorOutcome::OutcomeUncertain => ("결과 불확실 · 백업 확인 필요", Color32::RED),
        };
        egui::Frame::group(ui.style())
            .fill(color.gamma_multiply(0.18))
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.strong(heading);
                    if ui.button("닫기").clicked() {
                        self.state.clear_error();
                    }
                });
                ui.label(error.message);
            });
    }
}

impl eframe::App for GhostChatApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        self.poll_process(ctx);
        self.poll_login(ctx);
        if let Some(remaining) = self.state.process_proof_remaining_at(Instant::now()) {
            ctx.request_repaint_after(remaining);
        }
        if matches!(
            self.state.operation(),
            Operation::Repairing
                | Operation::OpeningBrowser
                | Operation::RestoringBrowser
                | Operation::DisconnectingBrowser
        ) && ctx.input(|input| input.viewport().close_requested())
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.state.report().is_some() {
            egui::Panel::bottom("cleanup-actions")
                .resizable(false)
                .exact_size(96.0)
                .frame(
                    egui::Frame::new()
                        .fill(ui.visuals().panel_fill)
                        .inner_margin(12.0),
                )
                .show(ui, |ui| self.render_repair(ui));
        }
        let controls_height = (ui.available_height() - 160.0).max(0.0);
        egui::ScrollArea::vertical()
            .id_salt("setup-controls")
            .max_height(controls_height)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add_space(8.0);
                self.render_header(ui);
                ui.add_space(8.0);
                self.render_source(ui);
                ui.add_space(8.0);
                self.render_web(ui);
                if self.state.error().is_some() {
                    ui.add_space(8.0);
                    self.render_error(ui);
                }
                if self.state.receipt().is_some() {
                    ui.add_space(8.0);
                    self.render_receipt(ui);
                }
            });
        ui.add_space(8.0);
        self.render_results(ui);
        self.render_repair_confirmation(ui.ctx());
    }
}

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let korean_font = "NanumGothic";
    fonts.font_data.insert(
        korean_font.to_owned(),
        egui::FontData::from_static(include_bytes!(
            "../assets/fonts/nanumgothic/NanumGothic-Regular.ttf"
        ))
        .into(),
    );
    // Keep the default Latin fonts and use the embedded font for Korean text.
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .push(korean_font.to_owned());
    }
    ctx.set_fonts(fonts);
}

fn section(ui: &mut egui::Ui, title: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::group(ui.style())
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.heading(title);
            ui.add_space(4.0);
            add_contents(ui);
        });
}

fn clipped_label(ui: &mut egui::Ui, value: &str) {
    ui.add(egui::Label::new(value).truncate())
        .on_hover_text(value);
}

fn selection_checkbox_label(thread: &CatalogThread) -> String {
    row_checkbox_label("선택", thread)
}

fn review_checkbox_label(thread: &CatalogThread) -> String {
    row_checkbox_label("검토 확인", thread)
}

fn row_checkbox_label(action: &str, thread: &CatalogThread) -> String {
    let identity = thread.identity();
    format!(
        "{action}: {} — {}/{}",
        thread.display_title(),
        identity.host_id,
        identity.thread_id
    )
}

fn classification_label(ui: &mut egui::Ui, classification: Classification) {
    let (text, color) = match classification {
        Classification::ConfirmedDeleted => ("삭제 기록", Color32::from_rgb(180, 54, 54)),
        Classification::ReviewRequired => ("검토 필요", Color32::from_rgb(196, 126, 16)),
        Classification::Preserved => ("유지", Color32::from_rgb(50, 130, 82)),
    };
    ui.label(RichText::new(text).color(color));
}

const fn operation_label(operation: Operation) -> &'static str {
    match operation {
        Operation::Idle => "대기",
        Operation::Discovering => "파일 찾는 중",
        Operation::Scanning => "대화 불러오는 중",
        Operation::OpeningBrowser => "브라우저 여는 중",
        Operation::RestoringBrowser | Operation::AuthenticatingBrowser => "연결 중",
        Operation::CheckingLogin | Operation::CheckingBrowser => "",
        Operation::DisconnectingBrowser => "연결 해제 중",
        Operation::ComparingWeb => "목록 확인 중",
        Operation::Checking => "ChatGPT 데스크톱 앱 종료 확인 중",
        Operation::Repairing => "정리 중",
    }
}

const fn process_label(state: ProcessState) -> &'static str {
    match state {
        ProcessState::NotChecked => "확인 전",
        ProcessState::Running => "실행 중",
        ProcessState::StoppedVerified => "종료 확인됨",
        ProcessState::Unknown => "확인 불가",
    }
}

fn nonempty_path(input: &str) -> Option<PathBuf> {
    let input = input.trim();
    (!input.is_empty()).then(|| PathBuf::from(input))
}

fn default_backup_directory(database_path: &Path, platform: PlatformPolicy) -> PathBuf {
    let parent = database_path.parent().unwrap_or_else(|| Path::new("."));
    if platform == PlatformPolicy::Windows {
        parent.to_path_buf()
    } else {
        parent.join("ghost-chat-cleaner-backups")
    }
}

fn demo_path(value: &str) -> LocalPath {
    LocalPath::try_from(Path::new(value)).expect("fixed demo paths are UTF-8")
}

fn demo_report(platform: PlatformPolicy) -> ScanReport {
    let confirmed = [
        ("thread-demo-confirmed-1", "정리된 여행 계획"),
        ("thread-demo-confirmed-2", "완료된 코드 검토"),
    ]
    .into_iter()
    .map(|(thread_id, title)| {
        CatalogThread::confirmed_deleted(
            ThreadIdentity::new("chatgpt:demo", thread_id),
            title,
            "chatgpt",
            true,
            None,
            None,
            DeletionEvidence {
                source_path: demo_path("/demo/logs/events.jsonl"),
                reason: "exact same-line deletion marker".to_owned(),
            },
        )
        .expect("fixed confirmed demo row is valid")
    });
    let review = [
        ("thread-demo-review-1", "제목 없는 이전 대화"),
        ("thread-demo-review-2", "로그 근거가 없는 후보"),
    ]
    .into_iter()
    .map(|(thread_id, title)| {
        CatalogThread::review_required(
            ThreadIdentity::new("chatgpt:demo", thread_id),
            title,
            "chatgpt",
            true,
            None,
            None,
        )
        .expect("fixed review demo row is valid")
    });
    let preserved = [
        ("thread-demo-preserved-1", "현재 프로젝트 대화"),
        ("thread-demo-preserved-2", "정상 보존 대화"),
    ]
    .into_iter()
    .map(|(thread_id, title)| {
        CatalogThread::preserved(
            ThreadIdentity::new("chatgpt:demo", thread_id),
            title,
            "chatgpt",
            false,
            Some("demo-project".to_owned()),
            None,
        )
    });

    ScanReport::new(
        demo_path("/demo/codex-dev.db"),
        platform.label(),
        SchemaReport {
            write_capable: platform.allows_mutation(),
            reason: if platform.allows_mutation() {
                "demo write-capable profile".to_owned()
            } else {
                "demo platform policy is scan-only".to_owned()
            },
            fingerprint: "demo-fixed-schema-v1".to_owned(),
            columns: vec![
                "host_id".to_owned(),
                "thread_id".to_owned(),
                "display_title".to_owned(),
            ],
        },
        confirmed.chain(review).chain(preserved).collect(),
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::WorkerRequestKind;

    fn isolated_login_app(connected: bool) -> GhostChatApp {
        let mut app = isolated_demo_app(PlatformPolicy::MacOs);
        app.state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
        let job_id = app.state.begin(Operation::OpeningBrowser);
        app.state.apply_job_event(JobEvent::BrowserOpened {
            job_id,
            result: Ok(()),
        });
        if connected {
            let job_id = app.state.begin(Operation::AuthenticatingBrowser);
            app.state.apply_job_event(JobEvent::BrowserAuthenticated {
                job_id,
                result: Ok(()),
            });
        }
        app
    }

    #[test]
    fn list_check_is_available_without_a_report_and_during_a_quiet_probe() {
        for connected in [false, true] {
            let mut app = isolated_login_app(connected);
            assert!(app.state.report().is_none());
            assert!(app.can_check_list());
            if !connected {
                app.state.begin(Operation::CheckingLogin);
                assert!(app.can_check_list());
            }
            app.state.begin(Operation::AuthenticatingBrowser);
            assert!(!app.can_check_list());
        }
        assert!(!isolated_demo_app(PlatformPolicy::MacOs).can_check_list());
    }

    #[test]
    fn closing_login_waits_for_explicit_list_check_without_reopening_or_polling() {
        let mut app = isolated_login_app(false);
        let job_id = app.state.begin(Operation::CheckingLogin);
        assert!(app
            .apply_event(JobEvent::LoginWindowChecked {
                job_id,
                result: Ok(true)
            })
            .is_none());
        assert_eq!(
            app.state.browser_state(),
            BrowserState::AwaitingVerification
        );
        assert!(!app.state.should_monitor_comparison());
        assert!(!app.pending_list_check);
        app.next_login_check = Instant::now();
        assert!(app.prepare_browser_check().is_none());
        let (_, request) = app
            .prepare_list_check()
            .expect("explicit handoff remains available");
        assert_eq!(request.kind, WorkerRequestKind::AuthenticateBrowser);
    }

    #[test]
    fn connected_list_check_preempts_exit_probe_and_rejects_its_stale_result() {
        let mut app = isolated_login_app(true);
        app.state.install_report(demo_report(PlatformPolicy::MacOs));
        let (probe_id, probe) = app
            .prepare_browser_check()
            .expect("connected browser is monitored");
        assert_eq!(probe.kind, WorkerRequestKind::CheckBrowserWindow);
        let (compare_id, request) = app
            .prepare_list_check()
            .expect("probe must not swallow list click");
        assert!(matches!(request.kind, WorkerRequestKind::CompareWeb { .. }));
        assert!(app
            .apply_event(JobEvent::BrowserWindowChecked {
                job_id: probe_id,
                result: Ok(true)
            })
            .is_none());
        assert_eq!(app.state.active_job(), Some(compare_id));
        assert_eq!(app.state.browser_state(), BrowserState::Connected);
    }

    #[test]
    fn retryable_authentication_waits_for_an_explicit_list_check_then_resumes() {
        let mut app = isolated_login_app(false);
        let (failed_id, _) = app.prepare_list_check().expect("starts authentication");
        assert!(app
            .apply_event(JobEvent::BrowserAuthenticated {
                job_id: failed_id,
                result: Err(AppError::retryable_authentication(
                    "synthetic page transition"
                )),
            })
            .is_none());
        assert_eq!(
            app.state.browser_state(),
            BrowserState::AwaitingVerification
        );
        assert!(!app.pending_list_check);
        assert!(!app.state.browser_ready());
        assert!(app.can_check_list());
        app.next_login_check = Instant::now();
        let (probe_id, request) = app
            .prepare_browser_check()
            .expect("comparison exit is monitored");
        assert_eq!(request.kind, WorkerRequestKind::CheckBrowserWindow);
        assert!(
            app.apply_event(JobEvent::BrowserWindowChecked {
                job_id: probe_id,
                result: Ok(false),
            })
            .is_none(),
            "read-only exit check cannot retry authentication"
        );
        assert!(app.state.error().is_some());
        let (retry_id, request) = app
            .prepare_list_check()
            .expect("explicit retry remains available");
        assert_eq!(
            request.kind,
            WorkerRequestKind::AuthenticateBrowser,
            "reuse the owned browser"
        );
        assert!(app
            .apply_event(JobEvent::BrowserAuthenticated {
                job_id: failed_id,
                result: Err(AppError::retryable_authentication("late first attempt")),
            })
            .is_none());
        assert_eq!(app.state.active_job(), Some(retry_id));
        let (_, request) = app
            .apply_event(JobEvent::BrowserAuthenticated {
                job_id: retry_id,
                result: Ok(()),
            })
            .expect("successful explicit retry resumes source discovery");
        assert!(matches!(request.kind, WorkerRequestKind::Discover { .. }));
        assert!(app.worker.is_none());
    }

    #[test]
    fn list_check_authenticates_discovers_loads_and_compares_once() {
        let mut app = isolated_login_app(false);
        let (auth_id, request) = app.prepare_list_check().expect("login can continue");
        assert_eq!(request.kind, WorkerRequestKind::AuthenticateBrowser);
        assert!(app.pending_list_check);
        let (discovery_id, request) = app
            .apply_event(JobEvent::BrowserAuthenticated {
                job_id: auth_id,
                result: Ok(()),
            })
            .expect("no source triggers discovery");
        assert!(matches!(request.kind, WorkerRequestKind::Discover { .. }));
        let (scan_id, request) = app
            .apply_event(JobEvent::DiscoveryFinished {
                job_id: discovery_id,
                result: Ok(vec![PathBuf::from("/demo/codex-dev.db")]),
            })
            .expect("sole source is loaded");
        assert!(
            matches!(request.kind, WorkerRequestKind::Scan { database_path, .. }
            if database_path == Path::new("/demo/codex-dev.db"))
        );
        let report = demo_report(PlatformPolicy::MacOs);
        let (comparison_id, request) = app
            .apply_event(JobEvent::ScanFinished {
                job_id: scan_id,
                result: Ok(report.clone()),
            })
            .expect("loaded report is compared");
        assert_eq!(
            request.kind,
            WorkerRequestKind::CompareWeb {
                report: report.clone()
            }
        );
        assert!(!app.pending_list_check);
        assert!(app
            .apply_event(JobEvent::ScanFinished {
                job_id: scan_id,
                result: Ok(report),
            })
            .is_none());
        assert_eq!(app.state.active_job(), Some(comparison_id));
        assert!(app.worker.is_none());
    }

    #[test]
    fn list_check_loads_an_explicit_source_without_discovery() {
        let mut app = isolated_login_app(true);
        app.set_database_source("/synthetic/chosen.db");
        let (_, request) = app
            .prepare_list_check()
            .expect("connected button loads source");
        assert!(
            matches!(request.kind, WorkerRequestKind::Scan { database_path, .. }
            if database_path == Path::new("/synthetic/chosen.db"))
        );
        assert!(app.pending_list_check);
    }

    #[test]
    fn list_check_preempts_a_quiet_probe_without_accepting_its_late_result() {
        let mut app = isolated_login_app(false);
        let probe_id = app.state.begin(Operation::CheckingLogin);
        let (auth_id, request) = app
            .prepare_list_check()
            .expect("quiet probe does not swallow click");
        assert_ne!(auth_id, probe_id);
        assert_eq!(request.kind, WorkerRequestKind::AuthenticateBrowser);
        assert!(app
            .apply_event(JobEvent::LoginWindowChecked {
                job_id: probe_id,
                result: Ok(true),
            })
            .is_none());
        assert_eq!(app.state.active_job(), Some(auth_id));
        assert!(app.pending_list_check);
    }

    #[test]
    fn list_check_stops_at_ambiguous_or_failed_discovery() {
        for result in [
            Ok(vec![]),
            Ok(vec![
                PathBuf::from("/synthetic/a.db"),
                PathBuf::from("/synthetic/b.db"),
            ]),
            Err(AppError::no_data_change("synthetic discovery failure")),
        ] {
            let mut app = isolated_login_app(true);
            let (job_id, _) = app.prepare_list_check().expect("starts discovery");
            assert!(app
                .apply_event(JobEvent::DiscoveryFinished { job_id, result })
                .is_none());
            assert!(!app.pending_list_check);
            assert_eq!(app.state.operation(), Operation::Idle);
            assert!(app.state.error().is_some());
        }
    }

    #[test]
    fn list_check_intent_is_cancelled_by_source_edits_disconnect_or_failure() {
        let mut app = isolated_login_app(true);
        app.pending_list_check = true;
        app.set_database_source("/synthetic/replacement.db");
        assert!(!app.pending_list_check);
        app.pending_list_check = true;
        app.request_browser_disconnect();
        assert!(!app.pending_list_check);

        let mut app = isolated_login_app(false);
        let (job_id, _) = app.prepare_list_check().expect("starts authentication");
        assert!(app
            .apply_event(JobEvent::BrowserAuthenticated {
                job_id,
                result: Err(AppError::no_data_change("synthetic authentication failure")),
            })
            .is_none());
        assert!(!app.pending_list_check);
        assert_eq!(app.state.operation(), Operation::Idle);
    }

    #[test]
    fn empty_live_screen_shows_basic_actions_without_jargon_or_cleanup() {
        let ctx = egui::Context::default();
        install_fonts(&ctx);
        let mut app = isolated_demo_app(PlatformPolicy::MacOs);
        app.state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1200.0, 1600.0),
                )),
                ..Default::default()
            },
            |ui| {
                app.render_header(ui);
                app.render_source(ui);
                app.render_web(ui);
                app.render_results(ui);
                app.render_repair(ui);
                app.render_receipt(ui);
            },
        );
        let text = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text) => Some(text.galley.job.text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        output.drop_without_applying_deltas();
        for expected in [
            "대화 목록 파일",
            "자동 찾기",
            "불러오기",
            "ChatGPT 연결",
            "불러온 대화 없음",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in {text}");
        }
        for hidden in [
            "Live",
            "OS:",
            "catalog",
            "DB",
            "evidence",
            "무결성",
            "쓰기 프로필",
            "로그 루트",
            "DELETE",
            "선택 항목 정리",
            "복구 전제 조건",
        ] {
            assert!(!text.contains(hidden), "unexpected {hidden:?} in {text}");
        }
        assert!(app.worker.is_none());
    }

    #[test]
    fn compact_screen_shows_failure_above_the_populated_conversation_table() {
        let ctx = egui::Context::default();
        let mut app = GhostChatApp::new(&ctx, RunMode::Demo).expect("in-memory demo");
        let message = "ChatGPT에서 연결 확인을 거부함";
        app.state.set_error(AppError::no_data_change(message));
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(840.0, 660.0));
        let mut frame = eframe::Frame::_new_kittest();
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(screen),
                ..Default::default()
            },
            |ui| eframe::App::ui(&mut app, ui, &mut frame),
        );
        let text_rect = |expected: &str| {
            output
                .shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    egui::Shape::Text(text) if text.galley.job.text == expected => {
                        Some(egui::Rect::from_min_size(text.pos, text.galley.size()))
                    }
                    _ => None,
                })
                .unwrap_or_else(|| panic!("missing rendered text: {expected}"))
        };
        let failure = text_rect(message);
        let connection = text_rect("ChatGPT 연결");
        let table = text_rect("대화 목록");
        output.drop_without_applying_deltas();
        assert!(failure.top() > connection.bottom());
        assert!(
            failure.bottom() < table.top(),
            "failure must appear before the table: {failure:?}"
        );
        assert!(
            screen.contains_rect(failure),
            "failure must be visible without scrolling"
        );
    }

    fn isolated_demo_app(platform: PlatformPolicy) -> GhostChatApp {
        GhostChatApp {
            state: AppState::new(RunMode::Demo, platform),
            worker: None,
            filter: ResultFilter::All,
            worker_disconnected: false,
            next_login_check: Instant::now(),
            next_process_check: Instant::now(),
            pending_list_check: false,
            repair_confirmation: None,
        }
    }

    fn populated_demo_app(ctx: &egui::Context) -> GhostChatApp {
        install_fonts(ctx);
        let mut app = isolated_demo_app(PlatformPolicy::MacOs);
        app.state.install_report(demo_report(PlatformPolicy::MacOs));
        app.state.set_backup_directory_input("/demo/backups");
        app
    }

    fn render_test_frame(
        app: &mut GhostChatApp,
        ctx: &egui::Context,
        size: egui::Vec2,
        events: Vec<egui::Event>,
    ) -> Vec<(String, egui::Rect)> {
        let mut frame = eframe::Frame::_new_kittest();
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events,
                ..Default::default()
            },
            |ui| eframe::App::ui(app, ui, &mut frame),
        );
        let rendered = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text) => Some((
                    text.galley.job.text.clone(),
                    egui::Rect::from_min_size(text.pos, text.galley.size()),
                )),
                _ => None,
            })
            .collect();
        output.drop_without_applying_deltas();
        rendered
    }

    fn click_test_button(
        app: &mut GhostChatApp,
        ctx: &egui::Context,
        size: egui::Vec2,
        label: &str,
    ) {
        // The first modal frame measures the centered area before it is painted.
        render_test_frame(app, ctx, size, vec![]);
        let rendered = render_test_frame(app, ctx, size, vec![]);
        let pos = rendered
            .iter()
            .find(|(text, _)| text == label)
            .unwrap_or_else(|| panic!("missing button {label:?}"))
            .1
            .center();
        for pressed in [true, false] {
            render_test_frame(
                app,
                ctx,
                size,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
        }
    }

    #[test]
    fn desktop_exit_is_refreshed_without_a_manual_button_click() {
        let ctx = egui::Context::default();
        let mut app = populated_demo_app(&ctx);
        app.state.select_all_confirmed();
        app.state.set_process_state(ProcessState::Running);
        let mut frame = eframe::Frame::_new_kittest();
        eframe::App::logic(&mut app, &ctx, &mut frame);
        assert_eq!(app.state.process_state(), ProcessState::StoppedVerified);
        assert!(app.state.can_repair());
    }

    #[test]
    fn slow_process_refresh_yields_time_to_browser_monitoring() {
        let ctx = egui::Context::default();
        let mut app = populated_demo_app(&ctx);
        app.state.select_all_confirmed();
        let job_id = app.state.begin(Operation::Checking);
        app.next_process_check = Instant::now() - Duration::from_secs(1);
        app.apply_event(JobEvent::ProcessChecked {
            job_id,
            observed_at: Instant::now(),
            result: Ok(ProcessPresence::Running),
        });
        app.poll_process(&ctx);
        assert_eq!(
            app.state.process_state(),
            ProcessState::Running,
            "completion must leave time for other worker requests before the next process poll"
        );
    }

    #[test]
    fn process_refresh_preserves_user_errors_and_does_not_flash_busy_ui() {
        let ctx = egui::Context::default();
        let mut app = populated_demo_app(&ctx);
        app.state
            .set_error(AppError::no_data_change("keep this failure"));
        app.state.begin(Operation::Checking);
        assert!(!app.state.operation().is_foreground());
        assert_eq!(
            app.state.error().map(|error| error.message.as_str()),
            Some("keep this failure")
        );
    }

    #[test]
    fn compact_cleanup_shows_current_desktop_instruction_without_typing() {
        for size in [egui::vec2(840.0, 660.0), egui::vec2(720.0, 580.0)] {
            let ctx = egui::Context::default();
            let mut app = populated_demo_app(&ctx);
            app.state.select_all_confirmed();
            assert_eq!(app.state.selected().len(), 2);
            let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, size);
            let mut frame = eframe::Frame::_new_kittest();
            let output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                },
                |ui| eframe::App::ui(&mut app, ui, &mut frame),
            );
            let rendered = output
                .shapes
                .iter()
                .filter_map(|shape| match &shape.shape {
                    egui::Shape::Text(text) => Some((
                        text.galley.job.text.clone(),
                        shape.clip_rect,
                        egui::Rect::from_min_size(text.pos, text.galley.size()),
                    )),
                    _ => None,
                })
                .collect::<Vec<_>>();
            output.drop_without_applying_deltas();
            for expected in [
                "ChatGPT 데스크톱 앱 · 확인 전",
                "선택 2개 정리",
                "ChatGPT 데스크톱 앱 상태 확인 중",
            ] {
                let (_, clip, rect) = rendered
                    .iter()
                    .find(|(text, _, _)| text == expected)
                    .unwrap_or_else(|| panic!("missing {expected:?} at {size:?}"));
                assert!(
                    screen.intersect(*clip).contains_rect(*rect),
                    "{expected:?} must be visible at {size:?}: {rect:?}"
                );
            }
            assert!(!app.state.can_repair());
            assert!(app.worker.is_none());
            assert!(rendered.iter().all(|(text, _, _)| !text.contains("DELETE")));
        }
    }

    #[test]
    fn fixed_cleanup_footer_does_not_block_table_controls() {
        let ctx = egui::Context::default();
        let mut app = populated_demo_app(&ctx);
        click_test_button(&mut app, &ctx, egui::vec2(840.0, 660.0), "자동 선택");
        assert_eq!(app.state.selected().len(), 2);
    }

    #[test]
    fn cleanup_button_stays_visible_when_other_content_overflows() {
        let ctx = egui::Context::default();
        let mut app = populated_demo_app(&ctx);
        app.state.select_all_confirmed();
        app.state.set_error(AppError::no_data_change(
            "A long actionable error\n".repeat(15),
        ));
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(720.0, 580.0));
        let mut frame = eframe::Frame::_new_kittest();
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(screen),
                ..Default::default()
            },
            |ui| eframe::App::ui(&mut app, ui, &mut frame),
        );
        let button = output.shapes.iter().find_map(|shape| match &shape.shape {
            egui::Shape::Text(text) if text.galley.job.text == "선택 2개 정리" => Some((
                shape.clip_rect,
                egui::Rect::from_min_size(text.pos, text.galley.size()),
            )),
            _ => None,
        });
        output.drop_without_applying_deltas();
        let button = button.expect("cleanup action must render despite overflowing content");
        assert!(
            screen.intersect(button.0).contains_rect(button.1),
            "cleanup action is clipped: {button:?}"
        );
    }

    #[test]
    fn first_cleanup_click_only_opens_a_confirmation_dialog() {
        let ctx = egui::Context::default();
        let mut app = populated_demo_app(&ctx);
        app.state.select_all_confirmed();
        app.state.set_process_state(ProcessState::StoppedVerified);
        app.request_repair();
        assert!(
            app.state.receipt().is_none(),
            "opening the dialog must not clean entries"
        );
        assert_eq!(app.state.operation(), Operation::Idle);
        assert_eq!(app.state.selected().len(), 2);
        let size = egui::vec2(720.0, 580.0);
        render_test_frame(&mut app, &ctx, size, vec![]);
        let modal_text = render_test_frame(&mut app, &ctx, size, vec![]);
        assert!(
            modal_text
                .iter()
                .any(|(text, _)| text == "선택 2개 정리 확인"),
            "modal must be rendered by the production UI path"
        );
    }

    #[test]
    fn canceling_cleanup_dialog_preserves_selection_without_cleaning() {
        let ctx = egui::Context::default();
        let mut app = populated_demo_app(&ctx);
        app.state.select_all_confirmed();
        app.state.set_process_state(ProcessState::StoppedVerified);
        app.request_repair();
        assert!(app.repair_confirmation.is_some());
        click_test_button(&mut app, &ctx, egui::vec2(720.0, 580.0), "취소");
        assert!(app.repair_confirmation.is_none());
        assert!(app.state.receipt().is_none());
        assert_eq!(app.state.selected().len(), 2);
        assert_eq!(app.state.operation(), Operation::Idle);
    }

    #[test]
    fn compact_modal_requires_its_confirm_button_before_demo_cleanup() {
        for size in [egui::vec2(840.0, 660.0), egui::vec2(720.0, 580.0)] {
            let ctx = egui::Context::default();
            let mut app = populated_demo_app(&ctx);
            app.state.select_all_confirmed();
            app.state.set_process_state(ProcessState::StoppedVerified);
            click_test_button(&mut app, &ctx, size, "선택 2개 정리");
            assert!(app.state.receipt().is_none());
            render_test_frame(&mut app, &ctx, size, vec![]);
            let rendered = render_test_frame(&mut app, &ctx, size, vec![]);
            let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, size);
            for expected in [
                "선택 2개 정리 확인",
                "백업을 만든 뒤 이 기기의 대화 목록에서 선택 항목을 제거한다.",
                "ChatGPT 웹 대화는 삭제하지 않는다.",
                "취소",
                "2개 정리",
            ] {
                let (_, rect) = rendered
                    .iter()
                    .find(|(text, _)| text == expected)
                    .unwrap_or_else(|| panic!("missing {expected:?}"));
                assert!(screen.contains_rect(*rect), "{expected:?}: {rect:?}");
            }
            assert!(rendered.iter().all(|(text, _)| !text.contains("DELETE")));
            click_test_button(&mut app, &ctx, size, "2개 정리");
            assert!(app.repair_confirmation.is_none());
            assert_eq!(
                app.state
                    .receipt()
                    .expect("explicit demo acceptance")
                    .removed_identities
                    .len(),
                2
            );
            assert!(app.worker.is_none());
        }
    }

    #[test]
    fn escape_dismisses_cleanup_modal_without_cleaning() {
        let ctx = egui::Context::default();
        let mut app = populated_demo_app(&ctx);
        app.state.select_all_confirmed();
        app.state.set_process_state(ProcessState::StoppedVerified);
        app.request_repair();
        let size = egui::vec2(720.0, 580.0);
        render_test_frame(&mut app, &ctx, size, vec![]);
        render_test_frame(
            &mut app,
            &ctx,
            size,
            vec![egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert!(app.repair_confirmation.is_none());
        assert!(app.state.receipt().is_none());
        assert_eq!(app.state.selected().len(), 2);
    }

    #[test]
    fn connected_missing_web_proof_shows_direct_list_retry() {
        let ctx = egui::Context::default();
        install_fonts(&ctx);
        let mut app = isolated_login_app(true);
        app.state.install_report(demo_report(PlatformPolicy::MacOs));
        app.state.select_all_confirmed();
        let rendered = render_test_frame(&mut app, &ctx, egui::vec2(840.0, 660.0), vec![]);
        assert!(rendered
            .iter()
            .any(|(text, _)| text == "선택 항목의 웹 확인 필요 · 「목록 확인」을 다시 실행"));
        assert_eq!(
            rendered
                .iter()
                .filter(|(text, _)| text == "목록 확인")
                .count(),
            2,
            "header and direct cleanup retry"
        );
        assert!(rendered
            .iter()
            .all(|(text, _)| !text.contains("ChatGPT 연결 후")));
        assert!(!app.state.can_repair());
    }

    #[test]
    fn cleanup_instruction_tracks_the_single_current_process_backup_or_busy_blocker() {
        let ctx = egui::Context::default();
        let mut app = populated_demo_app(&ctx);
        app.state.select_all_confirmed();
        app.state.set_backup_directory_input("");
        assert_eq!(
            app.repair_instruction(Instant::now()).as_deref(),
            Some("「백업 위치」에서 저장할 폴더 지정 필요")
        );
        app.state.set_backup_directory_input("/demo/backups");
        app.state.set_process_state(ProcessState::Unknown);
        assert_eq!(
            app.repair_instruction(Instant::now()).as_deref(),
            Some("ChatGPT 데스크톱 앱 상태 확인 불가")
        );
        let now = Instant::now();
        app.state
            .set_process_state_at(ProcessState::StoppedVerified, now);
        assert!(app.repair_instruction(now).is_none());
        assert_eq!(
            app.repair_instruction(now + Duration::from_secs(30))
                .as_deref(),
            Some("ChatGPT 데스크톱 앱 상태 확인 중")
        );
        app.state.begin(Operation::Scanning);
        assert_eq!(
            app.repair_instruction(now).as_deref(),
            Some("진행 중인 작업 완료 대기")
        );
    }

    #[test]
    fn accepting_cleanup_dialog_rejects_changed_selection_and_rechecks_prerequisites() {
        for stale_selection in [false, true] {
            let ctx = egui::Context::default();
            let mut app = populated_demo_app(&ctx);
            app.state.select_all_confirmed();
            app.state.set_process_state(ProcessState::StoppedVerified);
            app.request_repair();
            if stale_selection {
                app.state.clear_selection();
                app.state.select_all_confirmed();
                app.state.set_process_state(ProcessState::StoppedVerified);
            } else {
                app.state.set_process_state(ProcessState::Running);
            }
            app.accept_repair_confirmation();
            assert!(app.repair_confirmation.is_none());
            assert!(app.state.receipt().is_none());
            assert!(app.state.error().is_some());
            assert_eq!(app.state.operation(), Operation::Idle);
        }
    }

    #[test]
    fn disconnect_is_accepted_while_an_internal_login_check_is_pending() {
        let mut app = isolated_demo_app(PlatformPolicy::MacOs);
        app.state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
        let check = app.state.begin(Operation::CheckingLogin);
        app.request_browser_disconnect();
        assert_eq!(app.state.browser_state(), BrowserState::Disconnected);
        assert_ne!(app.state.active_job(), Some(check));
        // No worker is installed; this tests UI dispatch without touching a profile.
        assert!(app.state.error().is_some());
    }

    #[test]
    fn login_wait_header_does_not_flash_a_progress_message() {
        fn header_text(operation: Operation) -> Vec<String> {
            let ctx = egui::Context::default();
            let mut app = isolated_demo_app(PlatformPolicy::MacOs);
            if operation != Operation::Idle {
                app.state.begin(operation);
            }
            let output = ctx.run_ui(egui::RawInput::default(), |ui| app.render_header(ui));
            let texts = output
                .shapes
                .iter()
                .filter_map(|shape| match &shape.shape {
                    egui::Shape::Text(text) => Some(text.galley.job.text.clone()),
                    _ => None,
                })
                .collect();
            output.drop_without_applying_deltas();
            texts
        }
        let idle = header_text(Operation::Idle);
        assert!(!idle.is_empty());
        assert_eq!(header_text(Operation::CheckingLogin), idle);
        assert_eq!(header_text(Operation::CheckingBrowser), idle);
        assert_ne!(header_text(Operation::AuthenticatingBrowser), idle);
    }

    #[test]
    fn demo_constructor_does_not_create_a_live_worker() {
        let app = GhostChatApp::new(&egui::Context::default(), RunMode::Demo)
            .expect("demo construction is in-memory");

        assert!(app.worker.is_none());
        assert_eq!(
            app.state.report().map(|report| report.threads.len()),
            Some(6)
        );
    }

    #[test]
    fn first_frame_has_korean_glyphs_for_ui_and_conversation_titles() {
        let ctx = egui::Context::default();
        let app = GhostChatApp::new(&ctx, RunMode::Demo).expect("demo construction is in-memory");
        let mut labels = vec!["경로 탐색 스캔 복구 백업 검토 확인 선택 한글 ㄱㅎㅏ"];
        labels.extend(ResultFilter::ALL.map(ResultFilter::label));
        labels.extend(
            app.state
                .report()
                .expect("demo report")
                .threads
                .iter()
                .map(CatalogThread::display_title),
        );

        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            app.render_header(ui);
            ui.fonts_mut(|fonts| {
                for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                    let font_id = egui::FontId::new(14.0, family);
                    for label in &labels {
                        for character in label.chars().filter(|value| !value.is_whitespace()) {
                            assert!(
                                fonts.has_glyph(&font_id, character),
                                "missing glyph {character:?} in {:?} for {label:?}",
                                font_id.family
                            );
                        }
                    }
                }
            });
        });
        output.drop_without_applying_deltas();
    }

    #[test]
    fn demo_commands_complete_as_deterministic_in_memory_events() {
        let mut app = isolated_demo_app(PlatformPolicy::MacOs);
        app.state.set_backup_directory_input("/demo/backups");

        app.request_discovery();
        assert_eq!(
            app.state.discovered_paths(),
            &[PathBuf::from("/demo/codex-dev.db")]
        );

        app.request_scan();
        let identity = app
            .state
            .report()
            .and_then(|report| {
                report
                    .threads
                    .iter()
                    .find(|thread| thread.classification() == Classification::ConfirmedDeleted)
            })
            .map(|thread| thread.identity().clone())
            .expect("demo has a confirmed row");
        assert!(app.state.set_selected(&identity, true));

        app.request_process_check();
        assert!(app.state.can_repair());

        app.request_repair();
        assert!(app.state.receipt().is_none());
        app.accept_repair_confirmation();
        let receipt = app.state.receipt().expect("demo installs a receipt");
        assert_eq!(receipt.removed_identities, vec![identity]);
        assert_eq!((receipt.before_count, receipt.after_count), (6, 5));
    }

    #[test]
    fn row_checkbox_labels_are_unique_and_include_visible_identity() {
        let report = demo_report(PlatformPolicy::MacOs);
        let first = &report.threads[0];
        let second = &report.threads[1];

        let first_selection = selection_checkbox_label(first);
        let second_selection = selection_checkbox_label(second);
        assert_ne!(first_selection, second_selection);
        assert!(first_selection.contains(first.display_title()));
        assert!(first_selection.contains(&first.identity().thread_id));

        let review = review_checkbox_label(first);
        assert!(review.contains(first.display_title()));
        assert!(review.contains(&first.identity().thread_id));
        assert_ne!(review, first_selection);
    }
}
