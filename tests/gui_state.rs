use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ghost_chat_cleaner::app_state::{
    AppError, AppState, BrowserState, ErrorOutcome, JobEvent, Operation, ProcessState, RunMode,
};
use ghost_chat_cleaner::model::{
    CatalogThread, Classification, DeletionEvidence, LocalPath, RepairReceipt, ScanReport,
    SchemaReport, ThreadIdentity,
};
use ghost_chat_cleaner::platform::{CatalogPathInputs, PlatformPolicy};
use ghost_chat_cleaner::process_guard::ProcessPresence;
use ghost_chat_cleaner::worker::{backend_for_mode, ScanInputs, WorkerRequest, WorkerRequestKind};

fn local_path(path: &str) -> LocalPath {
    LocalPath::try_from(Path::new(path)).expect("synthetic path is UTF-8")
}

fn install_valid_web(state: &mut AppState) {
    let proof = ghost_chat_cleaner::web::WebComparison::from_value(state.report().unwrap(), serde_json::json!({
        "schema_version":3,"kind":"requested_metadata_checks","user_id":"user-fixture","account_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "account_user_id":"user-fixture","account_structure":"personal","complete":true,
        "controls":[preserved_identity().thread_id],
        "checks":[{"id":confirmed_identity().thread_id,"evidence":"authenticated_json_get_404"},{"id":review_identity().thread_id,"evidence":"authenticated_json_get_404"},{"id":preserved_identity().thread_id,"evidence":"authenticated_json_get_200"}]
    })).unwrap();
    state.install_web_comparison(proof);
}

#[test]
fn opening_a_login_window_does_not_authenticate_the_browser() {
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
    state.set_backup_directory_input("/synthetic/backups");
    let job_id = state.begin(Operation::OpeningBrowser);
    assert!(!state.browser_ready());
    assert!(state.apply_job_event(JobEvent::BrowserOpened {
        job_id,
        result: Ok(()),
    }));
    assert!(
        !state.browser_ready(),
        "an open login window is not an authenticated session"
    );
}

#[test]
fn retryable_authentication_retains_only_an_unverified_session() {
    for restoring in [false, true] {
        let mut state = connected_ready_state();
        let job_id = state.begin(if restoring {
            Operation::RestoringBrowser
        } else {
            Operation::AuthenticatingBrowser
        });
        let error = AppError::retryable_authentication("synthetic page transition");
        let event = if restoring {
            JobEvent::BrowserRestored {
                job_id,
                result: Err(error),
            }
        } else {
            JobEvent::BrowserAuthenticated {
                job_id,
                result: Err(error),
            }
        };
        assert!(state.apply_job_event(event));
        assert_eq!(state.browser_state(), BrowserState::AwaitingVerification);
        assert_eq!(state.operation(), Operation::Idle);
        assert!(!state.browser_ready());
        assert!(state.web_comparison().is_none());
        assert!(state.selected().is_empty());
        assert!(state.reviewed().is_empty());

        assert_eq!(state.process_state(), ProcessState::NotChecked);
        assert!(!state.can_repair());
        assert!(state.error().unwrap().authentication_retryable);
    }
}

#[test]
fn retryable_authentication_does_not_assume_opened_or_disconnected_sessions() {
    let mut state = connected_ready_state();
    let opening = state.begin(Operation::OpeningBrowser);
    state.apply_job_event(JobEvent::BrowserOpened {
        job_id: opening,
        result: Err(AppError::retryable_authentication(
            "synthetic opening failure",
        )),
    });
    assert_eq!(state.browser_state(), BrowserState::Disconnected);

    for restoring in [false, true] {
        let failed = state.begin(if restoring {
            Operation::RestoringBrowser
        } else {
            Operation::AuthenticatingBrowser
        });
        let disconnect = state.begin(Operation::DisconnectingBrowser);
        let error = AppError::retryable_authentication("synthetic stale failure");
        let event = if restoring {
            JobEvent::BrowserRestored {
                job_id: failed,
                result: Err(error),
            }
        } else {
            JobEvent::BrowserAuthenticated {
                job_id: failed,
                result: Err(error),
            }
        };
        assert!(!state.apply_job_event(event));
        assert_eq!(state.browser_state(), BrowserState::Disconnected);
        assert_eq!(state.active_job(), Some(disconnect));
        assert!(state.error().is_none());
        assert!(!state.can_repair());
    }
}

#[test]
fn pending_login_handoff_retains_polling_and_retry_without_authorization() {
    let mut state = connected_ready_state();
    let job_id = state.begin(Operation::AuthenticatingBrowser);
    assert!(state.apply_job_event(JobEvent::BrowserAuthenticated {
        job_id,
        result: Err(AppError::login_browser_still_open()),
    }));
    assert_eq!(state.browser_state(), BrowserState::LoginOpen);
    assert_eq!(state.operation(), Operation::Idle);
    assert!(!state.browser_ready());
    assert!(state.web_comparison().is_none());
    assert!(state.selected().is_empty());
    assert!(state.reviewed().is_empty());

    assert_eq!(state.process_state(), ProcessState::NotChecked);
    assert!(!state.can_repair());
    let error = state
        .error()
        .cloned()
        .expect("actionable pending-login error");
    assert!(error.login_browser_still_open);

    let job_id = state.begin(Operation::CheckingLogin);
    state.apply_job_event(JobEvent::LoginWindowChecked {
        job_id,
        result: Ok(false),
    });
    assert_eq!(state.browser_state(), BrowserState::LoginOpen);
    assert_eq!(state.error(), Some(&error));

    let job_id = state.begin(Operation::AuthenticatingBrowser);
    state.apply_job_event(JobEvent::BrowserAuthenticated {
        job_id,
        result: Ok(()),
    });
    assert_eq!(state.browser_state(), BrowserState::Connected);
    assert!(state.web_comparison().is_none());
    assert!(!state.can_repair());
}

#[test]
fn stale_pending_login_handoff_cannot_reopen_a_disconnected_session() {
    let mut state = connected_ready_state();
    let auth_id = state.begin(Operation::AuthenticatingBrowser);
    let disconnect_id = state.begin(Operation::DisconnectingBrowser);
    assert!(!state.apply_job_event(JobEvent::BrowserAuthenticated {
        job_id: auth_id,
        result: Err(AppError::login_browser_still_open()),
    }));
    assert_eq!(state.browser_state(), BrowserState::Disconnected);
    assert_eq!(state.active_job(), Some(disconnect_id));
    assert!(!state.can_repair());
}

#[test]
fn waiting_login_check_preserves_visible_error_and_process_status() {
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
    state.set_backup_directory_input("/synthetic/backups");
    let open = state.begin(Operation::OpeningBrowser);
    state.apply_job_event(JobEvent::BrowserOpened {
        job_id: open,
        result: Ok(()),
    });
    state.set_error(AppError::no_data_change("Keep this actionable error"));
    state.set_process_state(ProcessState::StoppedVerified);
    let pending = state.begin(Operation::CheckingLogin);
    assert_eq!(state.error().unwrap().message, "Keep this actionable error");
    assert_eq!(state.process_state(), ProcessState::StoppedVerified);
    state.apply_job_event(JobEvent::LoginWindowChecked {
        job_id: pending,
        result: Ok(false),
    });
    assert_eq!(state.error().unwrap().message, "Keep this actionable error");
    assert_eq!(state.process_state(), ProcessState::StoppedVerified);
    assert_eq!(state.browser_state(), BrowserState::LoginOpen);
    assert!(!state.browser_ready());
}

#[test]
fn user_action_supersedes_an_internal_login_check() {
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
    state.set_backup_directory_input("/synthetic/backups");
    let check = state.begin(Operation::CheckingLogin);
    let disconnect = state.begin(Operation::DisconnectingBrowser);
    assert!(!state.apply_job_event(JobEvent::LoginWindowChecked {
        job_id: check,
        result: Ok(true)
    }));
    assert_eq!(state.active_job(), Some(disconnect));
    assert_eq!(state.browser_state(), BrowserState::Disconnected);
}

#[test]
fn login_progress_requires_authentication_before_connected() {
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
    state.set_backup_directory_input("/synthetic/backups");
    assert_eq!(state.browser_state(), BrowserState::Disconnected);
    let open = state.begin(Operation::OpeningBrowser);
    assert_eq!(state.browser_state(), BrowserState::LoginOpen);
    state.apply_job_event(JobEvent::BrowserOpened {
        job_id: open,
        result: Ok(()),
    });
    let pending = state.begin(Operation::CheckingLogin);
    assert_eq!(state.browser_state(), BrowserState::LoginOpen);
    state.apply_job_event(JobEvent::LoginWindowChecked {
        job_id: pending,
        result: Ok(false),
    });
    assert_eq!(state.browser_state(), BrowserState::LoginOpen);
    assert!(!state.browser_ready());
    let finished = state.begin(Operation::CheckingLogin);
    state.apply_job_event(JobEvent::LoginWindowChecked {
        job_id: finished,
        result: Ok(true),
    });
    assert_eq!(state.browser_state(), BrowserState::AwaitingVerification);
    assert!(!state.browser_ready());
    let auth = state.begin(Operation::AuthenticatingBrowser);
    assert_eq!(state.browser_state(), BrowserState::Connecting);
    state.apply_job_event(JobEvent::BrowserAuthenticated {
        job_id: auth,
        result: Ok(()),
    });
    assert_eq!(state.browser_state(), BrowserState::Connected);
    assert!(state.browser_ready());
    assert!(state.web_comparison().is_none());
    assert!(!state.can_repair());
}

#[test]
fn missing_saved_session_restores_silently_and_saved_session_connects() {
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::Windows);
    let missing = state.begin(Operation::RestoringBrowser);
    assert_eq!(state.browser_state(), BrowserState::Connecting);
    state.apply_job_event(JobEvent::BrowserRestored {
        job_id: missing,
        result: Ok(false),
    });
    assert_eq!(state.browser_state(), BrowserState::Disconnected);
    assert_eq!(state.operation(), Operation::Idle);
    assert!(state.error().is_none());
    let saved = state.begin(Operation::RestoringBrowser);
    state.apply_job_event(JobEvent::BrowserRestored {
        job_id: saved,
        result: Ok(true),
    });
    assert_eq!(state.browser_state(), BrowserState::Connected);
    assert!(state.browser_ready());
    assert!(state.web_comparison().is_none());
}

#[test]
fn comparison_exit_probe_preserves_readiness_until_confirmed_exit() {
    let mut state = connected_ready_state();
    state.set_error(AppError::no_data_change("existing error"));
    assert!(state.can_repair());
    assert!(state.should_monitor_comparison());
    let probe = state.begin(Operation::CheckingBrowser);
    assert!(!state.operation().is_foreground());
    assert!(
        state.can_repair(),
        "quiet monitoring must not flash the cleanup action"
    );
    state.apply_job_event(JobEvent::BrowserWindowChecked {
        job_id: probe,
        result: Ok(false),
    });
    assert!(state.can_repair());
    assert_eq!(state.error().unwrap().message, "existing error");
    let probe = state.begin(Operation::CheckingBrowser);
    state.apply_job_event(JobEvent::BrowserWindowChecked {
        job_id: probe,
        result: Ok(true),
    });
    assert_eq!(state.browser_state(), BrowserState::Disconnected);
    assert!(!state.should_monitor_comparison());
    assert!(!state.browser_ready());
    assert!(state.web_comparison().is_none());
    assert!(state.selected().is_empty());
    assert!(state.reviewed().is_empty());

    assert_eq!(state.process_state(), ProcessState::NotChecked);
    assert!(!state.can_repair());
    assert!(state.error().is_none());
}

#[test]
fn closed_browser_error_disconnects_without_claiming_login_expiry() {
    let mut state = connected_ready_state();
    let job_id = state.begin(Operation::ComparingWeb);
    state.apply_job_event(JobEvent::WebCompared {
        job_id,
        result: Err(AppError::browser_closed()),
    });
    assert_eq!(state.browser_state(), BrowserState::Disconnected);
    assert!(!state.should_monitor_comparison());
    assert!(state.error().unwrap().browser_closed);
    assert!(!state.error().unwrap().authentication_expired);
    assert!(state.web_comparison().is_none());
    assert!(!state.can_repair());
}

#[test]
fn target_loss_allows_explicit_login_without_process_exit_or_automatic_reopen() {
    for operation in [
        Operation::ComparingWeb,
        Operation::AuthenticatingBrowser,
        Operation::RestoringBrowser,
    ] {
        let mut state = connected_ready_state();
        let job_id = state.begin(operation);
        let error = AppError {
            browser_reconnect_required: true,
            ..AppError::no_data_change("synthetic changed target")
        };
        let event = match operation {
            Operation::ComparingWeb => JobEvent::WebCompared {
                job_id,
                result: Err(error),
            },
            Operation::AuthenticatingBrowser => JobEvent::BrowserAuthenticated {
                job_id,
                result: Err(error),
            },
            Operation::RestoringBrowser => JobEvent::BrowserRestored {
                job_id,
                result: Err(error),
            },
            _ => unreachable!(),
        };
        state.apply_job_event(event);
        assert_eq!(state.browser_state(), BrowserState::Disconnected);
        assert_eq!(state.operation(), Operation::Idle);
        assert!(!state.should_monitor_comparison());
        assert!(state.web_comparison().is_none());
        assert!(state.selected().is_empty());
        assert!(state.reviewed().is_empty());

        assert_eq!(state.process_state(), ProcessState::NotChecked);
        assert!(!state.can_repair());
        let error = state.error().unwrap();
        assert!(error.browser_reconnect_required);
        assert!(!error.browser_closed);
        assert!(!error.authentication_expired);
    }
}

#[test]
fn stale_target_loss_cannot_interrupt_an_explicit_new_login() {
    let mut state = connected_ready_state();
    let old = state.begin(Operation::ComparingWeb);
    let login = state.begin(Operation::OpeningBrowser);
    assert!(!state.apply_job_event(JobEvent::WebCompared {
        job_id: old,
        result: Err(AppError {
            browser_reconnect_required: true,
            ..AppError::no_data_change("synthetic stale target")
        }),
    }));
    assert_eq!(state.browser_state(), BrowserState::LoginOpen);
    assert_eq!(state.active_job(), Some(login));
    assert!(state.error().is_none());
}

fn connected_ready_state() -> AppState {
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
    state.set_backup_directory_input("/synthetic/backups");
    let restore = state.begin(Operation::RestoringBrowser);
    state.apply_job_event(JobEvent::BrowserRestored {
        job_id: restore,
        result: Ok(true),
    });
    state.install_report(report(PlatformPolicy::MacOs, true, true));
    install_valid_web(&mut state);
    state.set_selected(&confirmed_identity(), true);
    state.set_process_state(ProcessState::StoppedVerified);

    state
}

#[test]
fn transient_compare_failure_keeps_session_for_retry_but_revokes_proof() {
    let mut state = connected_ready_state();
    assert!(state.can_repair());
    let compare = state.begin(Operation::ComparingWeb);
    state.apply_job_event(JobEvent::WebCompared {
        job_id: compare,
        result: Err(AppError::no_data_change("temporary network failure")),
    });
    assert_eq!(state.browser_state(), BrowserState::Connected);
    assert!(state.browser_ready());
    assert!(state.web_comparison().is_none());
    assert!(state.selected().is_empty());
    assert!(!state.can_repair());
    let retry = state.begin(Operation::ComparingWeb);
    install_valid_web(&mut state);
    let proof = state.web_comparison().unwrap().clone();
    state.apply_job_event(JobEvent::WebCompared {
        job_id: retry,
        result: Ok(proof),
    });
    assert!(state.browser_ready());
    assert!(state.web_comparison().is_some());
}

#[test]
fn expired_comparison_requires_login_and_clears_authorization() {
    let mut state = connected_ready_state();
    let compare = state.begin(Operation::ComparingWeb);
    state.apply_job_event(JobEvent::WebCompared {
        job_id: compare,
        result: Err(AppError::login_required("session expired")),
    });
    assert_eq!(state.browser_state(), BrowserState::Expired);
    assert!(!state.browser_ready());
    assert!(state.error().unwrap().authentication_expired);
    assert!(state.web_comparison().is_none());
    assert!(state.selected().is_empty());

    assert_eq!(state.process_state(), ProcessState::NotChecked);
}

#[test]
fn expired_authentication_during_repair_preflight_revokes_web_proof() {
    for worker_disconnected in [false, true] {
        let mut state = ready_state(PlatformPolicy::MacOs);
        let job_id = state.begin(Operation::Repairing);
        let error = AppError::login_required("repair preflight requires login");
        if worker_disconnected {
            assert!(state.fail_active(job_id, error));
        } else {
            assert!(state.apply_job_event(JobEvent::RepairFinished {
                job_id,
                result: Err(error),
            }));
        }
        assert!(state.web_comparison().is_none());
        assert_eq!(state.browser_state(), BrowserState::Expired);
        assert!(
            state.report().is_some(),
            "no-data-change preflight preserves the scan"
        );
        assert!(state.selected().is_empty());
        assert!(!state.can_repair());
    }
}

#[test]
fn disconnect_immediately_revokes_all_authorization_even_if_cleanup_fails() {
    let mut state = connected_ready_state();
    state.set_reviewed(&review_identity(), true);
    let disconnect = state.begin(Operation::DisconnectingBrowser);
    assert_eq!(state.browser_state(), BrowserState::Disconnected);
    assert!(!state.browser_ready());
    assert!(state.web_comparison().is_none());
    assert!(state.reviewed().is_empty());
    assert!(state.selected().is_empty());

    assert_eq!(state.process_state(), ProcessState::NotChecked);
    state.apply_job_event(JobEvent::BrowserDisconnected {
        job_id: disconnect,
        result: Err(AppError::login_required("profile cleanup failed")),
    });
    assert_eq!(state.browser_state(), BrowserState::Disconnected);
    assert!(!state.can_repair());
    assert!(state.error().is_some());
}

#[test]
fn disconnect_rejects_a_stale_comparison_completion() {
    let mut state = connected_ready_state();
    let old_proof = state.web_comparison().unwrap().clone();
    let compare = state.begin(Operation::ComparingWeb);
    let disconnect = state.begin(Operation::DisconnectingBrowser);
    assert!(!state.apply_job_event(JobEvent::WebCompared {
        job_id: compare,
        result: Ok(old_proof)
    }));
    assert_eq!(state.operation(), Operation::DisconnectingBrowser);
    assert!(state.web_comparison().is_none());
    state.apply_job_event(JobEvent::BrowserDisconnected {
        job_id: disconnect,
        result: Ok(()),
    });
    assert_eq!(state.browser_state(), BrowserState::Disconnected);
    assert!(!state.apply_job_event(JobEvent::BrowserAuthenticated {
        job_id: compare,
        result: Ok(())
    }));
    assert!(!state.browser_ready());
}

#[test]
fn report_refresh_invalidates_proof_without_changing_browser_connection() {
    let mut state = connected_ready_state();
    state.install_report(report(PlatformPolicy::MacOs, true, true));
    assert_eq!(state.browser_state(), BrowserState::Connected);
    assert!(state.browser_ready());
    assert!(state.web_comparison().is_none());
    assert!(!state.can_repair());
}

#[test]
fn failed_browser_operations_distinguish_expired_from_transient_errors() {
    for operation in [
        Operation::RestoringBrowser,
        Operation::OpeningBrowser,
        Operation::AuthenticatingBrowser,
        Operation::CheckingLogin,
        Operation::ComparingWeb,
        Operation::DisconnectingBrowser,
    ] {
        for expired in [false, true] {
            let mut state = connected_ready_state();
            let job = state.begin(operation);
            let error = if expired {
                AppError::login_required("expired")
            } else {
                AppError::no_data_change("transient")
            };
            assert!(state.fail_active(job, error));
            let expected = if operation == Operation::DisconnectingBrowser {
                BrowserState::Disconnected
            } else if expired {
                BrowserState::Expired
            } else if operation == Operation::ComparingWeb {
                BrowserState::Connected
            } else {
                BrowserState::Disconnected
            };
            assert_eq!(
                state.browser_state(),
                expected,
                "{operation:?}, expired={expired}"
            );
            assert!(state.web_comparison().is_none());
            assert!(state.selected().is_empty());
            assert!(!state.can_repair());
        }
    }
}

#[test]
fn browser_result_errors_revoke_proof_and_show_the_correct_session_state() {
    for operation in [
        Operation::RestoringBrowser,
        Operation::OpeningBrowser,
        Operation::AuthenticatingBrowser,
        Operation::CheckingLogin,
    ] {
        for expired in [false, true] {
            let mut state = connected_ready_state();
            let job_id = state.begin(operation);
            let error = if expired {
                AppError::login_required("expired")
            } else {
                AppError::no_data_change("unavailable")
            };
            let event = match operation {
                Operation::RestoringBrowser => JobEvent::BrowserRestored {
                    job_id,
                    result: Err(error),
                },
                Operation::OpeningBrowser => JobEvent::BrowserOpened {
                    job_id,
                    result: Err(error),
                },
                Operation::AuthenticatingBrowser => JobEvent::BrowserAuthenticated {
                    job_id,
                    result: Err(error),
                },
                Operation::CheckingLogin => JobEvent::LoginWindowChecked {
                    job_id,
                    result: Err(error),
                },
                _ => unreachable!(),
            };
            assert!(state.apply_job_event(event));
            assert_eq!(
                state.browser_state(),
                if expired {
                    BrowserState::Expired
                } else {
                    BrowserState::Disconnected
                },
                "{operation:?}, expired={expired}"
            );
            assert!(state.web_comparison().is_none());
            assert!(state.selected().is_empty());
            assert!(state.error().is_some());
        }
    }
}

#[test]
fn demo_repair_authority_does_not_require_a_browser_session() {
    let mut state = AppState::new(RunMode::Demo, PlatformPolicy::MacOs);
    state.set_backup_directory_input("/synthetic/backups");
    state.install_report(report(PlatformPolicy::MacOs, true, true));
    state.set_selected(&confirmed_identity(), true);
    state.set_process_state(ProcessState::StoppedVerified);

    assert_eq!(state.browser_state(), BrowserState::Disconnected);
    assert!(!state.browser_ready());
    assert!(state.can_repair());
    assert!(!AppError::no_data_change("ordinary").authentication_expired);
    assert!(!AppError::outcome_uncertain("uncertain").authentication_expired);
}

#[test]
fn web_failure_and_source_changes_remove_live_authorization() {
    let mut state = ready_state(PlatformPolicy::MacOs);
    assert!(state.can_repair());
    let job_id = state.begin(Operation::ComparingWeb);
    assert!(state.web_comparison().is_none());
    assert!(!state.can_repair());
    state.apply_job_event(JobEvent::WebCompared {
        job_id,
        result: Err(AppError::no_data_change("fixture unauthorized")),
    });
    assert!(state.selected().is_empty());
    assert!(state.web_comparison().is_none());
    install_valid_web(&mut state);
    state.set_database_input("/different.db");
    assert!(state.web_comparison().is_none());
}

#[test]
fn web_proof_expiry_blocks_live_repair_even_with_fresh_process_check() {
    let mut state = ready_state(PlatformPolicy::MacOs);
    let later = state.web_comparison().unwrap().observed_at() + Duration::from_secs(300);
    state.set_process_state_at(ProcessState::StoppedVerified, later);
    assert!(!state.can_repair_at(later));
}

#[test]
fn web_present_cannot_be_selected_even_with_local_deleted_marker() {
    let mut state = ready_state(PlatformPolicy::MacOs);
    let proof = ghost_chat_cleaner::web::WebComparison::from_value(state.report().unwrap(), serde_json::json!({
        "schema_version":3,"kind":"requested_metadata_checks","user_id":"user-fixture","account_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "account_user_id":"user-fixture","account_structure":"personal","complete":true,
        "controls":[confirmed_identity().thread_id],
        "checks":[{"id":confirmed_identity().thread_id,"evidence":"authenticated_json_get_200"},{"id":review_identity().thread_id,"evidence":"authenticated_json_get_200"},{"id":preserved_identity().thread_id,"evidence":"authenticated_json_get_200"}]
    })).unwrap();
    state.install_web_comparison(proof);
    assert!(state.selected().is_empty());
    assert!(!state.set_selected(&confirmed_identity(), true));
    state.select_all_confirmed();
    assert!(state.selected().is_empty());
}

#[test]
fn web_unavailable_plain_row_requires_review_without_local_missing_flag() {
    let mut source = report(PlatformPolicy::MacOs, true, true);
    source.threads[0] = CatalogThread::preserved(
        confirmed_identity(),
        "웹 불일치",
        "chatgpt",
        false,
        None,
        None,
    );
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
    state.set_backup_directory_input("/synthetic/backups");
    state.install_report(source);
    install_valid_web(&mut state);
    assert!(!state.set_selected(&confirmed_identity(), true));
    assert!(state.set_reviewed(&confirmed_identity(), true));
    assert!(state.set_selected(&confirmed_identity(), true));
    state.set_process_state(ProcessState::StoppedVerified);

    assert!(state.can_repair());
    // The original report is retained for the fresh database equality check.
    assert_eq!(
        state.report().unwrap().threads[0].classification(),
        Classification::Preserved
    );
    assert!(!state.set_reviewed(&preserved_identity(), true));
}

fn confirmed_identity() -> ThreadIdentity {
    ThreadIdentity::new(
        "chatgpt:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:user-fixture",
        "00000000-0000-0000-0000-000000000001",
    )
}

fn review_identity() -> ThreadIdentity {
    ThreadIdentity::new(
        "chatgpt:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:user-fixture",
        "00000000-0000-0000-0000-000000000002",
    )
}

fn preserved_identity() -> ThreadIdentity {
    ThreadIdentity::new(
        "chatgpt:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:user-fixture",
        "00000000-0000-0000-0000-000000000003",
    )
}

fn report(platform: PlatformPolicy, write_capable: bool, integrity_ok: bool) -> ScanReport {
    let confirmed = CatalogThread::confirmed_deleted(
        confirmed_identity(),
        "확정 삭제 후보",
        "chatgpt",
        true,
        None,
        None,
        DeletionEvidence {
            source_path: local_path("/synthetic/deletion.log"),
            reason: "exact same-line deletion marker".to_owned(),
        },
    )
    .expect("valid confirmed row");
    let review = CatalogThread::review_required(
        review_identity(),
        "수동 검토 후보",
        "chatgpt",
        true,
        None,
        None,
    )
    .expect("valid review row");
    let preserved = CatalogThread::preserved(
        preserved_identity(),
        "보존 항목",
        "chatgpt",
        false,
        Some("project-a".to_owned()),
        None,
    );

    ScanReport::new(
        local_path("/synthetic/codex-dev.db"),
        platform.label(),
        SchemaReport {
            write_capable,
            reason: "synthetic supported schema".to_owned(),
            fingerprint: "synthetic-fingerprint".to_owned(),
            columns: vec!["host_id".to_owned(), "thread_id".to_owned()],
        },
        vec![confirmed, review, preserved],
        integrity_ok,
    )
}

fn ready_state(platform: PlatformPolicy) -> AppState {
    let mut state = AppState::new(RunMode::Live, platform);
    state.set_backup_directory_input("/synthetic/backups");
    state.install_report(report(platform, true, true));
    install_valid_web(&mut state);
    assert!(state.set_selected(&confirmed_identity(), true));
    state.set_process_state(ProcessState::StoppedVerified);

    state
}

#[test]
fn live_cleanup_without_web_proof_is_blocked() {
    let mut state = ready_state(PlatformPolicy::MacOs);
    state.install_report(report(PlatformPolicy::MacOs, true, true));
    state.set_selected(&confirmed_identity(), true);
    state.set_process_state(ProcessState::StoppedVerified);

    assert!(
        !state.can_repair(),
        "local evidence alone must never enable Live repair"
    );
}

#[test]
fn report_and_input_changes_invalidate_authorization_and_proof() {
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
    state.set_backup_directory_input("/synthetic/backups");
    state.install_report(report(PlatformPolicy::MacOs, true, true));
    assert!(state.set_reviewed(&review_identity(), true));
    assert!(state.set_selected(&review_identity(), true));

    state.set_process_state(ProcessState::StoppedVerified);

    state.install_report(report(PlatformPolicy::MacOs, true, true));
    assert!(state.reviewed().is_empty());
    assert!(state.selected().is_empty());

    assert_eq!(state.process_state(), ProcessState::NotChecked);

    assert!(state.set_selected(&confirmed_identity(), true));

    state.set_process_state(ProcessState::StoppedVerified);
    state.set_database_input("/different/catalog.db");
    assert!(state.report().is_none());
    assert!(state.selected().is_empty());

    assert_eq!(state.process_state(), ProcessState::NotChecked);

    state.install_report(report(PlatformPolicy::MacOs, true, true));
    assert!(state.set_selected(&confirmed_identity(), true));
    state.set_process_state(ProcessState::StoppedVerified);
    state.set_log_roots_input("/different/log/root");
    assert!(state.report().is_none());
    assert!(state.selected().is_empty());
    assert_eq!(state.process_state(), ProcessState::NotChecked);
}

#[test]
fn classification_controls_selectability() {
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
    state.set_backup_directory_input("/synthetic/backups");
    state.install_report(report(PlatformPolicy::MacOs, true, true));

    assert!(state.is_selectable(&confirmed_identity()));
    assert!(!state.is_selectable(&review_identity()));
    assert!(!state.is_selectable(&preserved_identity()));
    assert!(state.set_selected(&confirmed_identity(), true));
    assert!(!state.set_selected(&review_identity(), true));
    assert!(!state.set_selected(&preserved_identity(), true));
}

#[test]
fn review_required_uses_review_then_separate_selection() {
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::Windows);
    state.install_report(report(PlatformPolicy::Windows, true, true));

    assert!(!state.set_selected(&review_identity(), true));
    assert!(state.set_reviewed(&review_identity(), true));
    assert!(!state.selected().contains(&review_identity()));
    assert!(state.set_selected(&review_identity(), true));
    assert!(state.selected().contains(&review_identity()));

    assert!(state.set_reviewed(&review_identity(), false));
    assert!(!state.selected().contains(&review_identity()));
}

#[test]
fn select_all_replaces_selection_with_confirmed_rows_only() {
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
    state.set_backup_directory_input("/synthetic/backups");
    state.install_report(report(PlatformPolicy::MacOs, true, true));
    assert!(state.set_reviewed(&review_identity(), true));
    assert!(state.set_selected(&review_identity(), true));

    state.select_all_confirmed();

    assert_eq!(state.selected().len(), 1);
    assert!(state.selected().contains(&confirmed_identity()));
    assert!(!state.selected().contains(&review_identity()));
    assert!(!state.selected().contains(&preserved_identity()));
}

#[test]
fn cleanup_prerequisites_do_not_require_typing_a_confirmation_phrase() {
    let mut state = AppState::new(RunMode::Demo, PlatformPolicy::MacOs);
    state.set_backup_directory_input("/synthetic/backups");
    state.install_report(report(PlatformPolicy::MacOs, true, true));
    state.set_backup_directory_input("/synthetic/backups");
    assert!(state.set_selected(&confirmed_identity(), true));
    state.set_process_state(ProcessState::StoppedVerified);
    assert!(
        state.can_repair(),
        "the next step is the confirmation dialog"
    );
}

#[test]
fn empty_backup_directory_blocks_otherwise_authorized_cleanup() {
    let mut state = ready_state(PlatformPolicy::MacOs);
    state.set_backup_directory_input("   ");
    state.set_process_state(ProcessState::StoppedVerified);

    assert!(
        !state.can_repair(),
        "the state gate must enforce the same backup prerequisite as the cleanup button"
    );
}

#[test]
fn modal_confirmation_is_revoked_by_each_cleanup_context_change() {
    for change in [
        "selection",
        "review",
        "backup",
        "report",
        "database",
        "logs",
        "web",
    ] {
        let mut state = ready_state(PlatformPolicy::MacOs);
        let confirmation = state.prepare_repair_confirmation().expect("ready state");
        match change {
            "selection" => {
                state.clear_selection();
                state.set_selected(&confirmed_identity(), true);
            }
            "review" => {
                state.set_reviewed(&review_identity(), true);
            }
            "backup" => {
                state.set_backup_directory_input("/synthetic/other-backups");
            }
            "report" => {
                state.install_report(report(PlatformPolicy::MacOs, true, true));
            }
            "database" => {
                state.set_database_input("/synthetic/other.db");
            }
            "logs" => {
                state.set_log_roots_input("/synthetic/other-logs");
            }
            "web" => {
                install_valid_web(&mut state);
            }
            _ => unreachable!(),
        }
        // Restore only the prerequisites invalidated by this particular change.
        if state.report().is_none() {
            state.install_report(report(PlatformPolicy::MacOs, true, true));
        }
        if state.web_comparison().is_none() {
            install_valid_web(&mut state);
        }
        state.set_selected(&confirmed_identity(), true);
        state.set_process_state(ProcessState::StoppedVerified);
        assert!(state.can_repair());
        assert!(
            !state.can_confirm_repair_at(confirmation, Instant::now()),
            "{change}"
        );
    }
}

#[test]
fn modal_acceptance_rechecks_process_web_expiry_and_busy_state() {
    let mut state = ready_state(PlatformPolicy::MacOs);
    let confirmation = state.prepare_repair_confirmation().expect("ready state");
    let now = Instant::now();
    state.set_process_state_at(ProcessState::StoppedVerified, now);
    assert!(state.can_confirm_repair_at(confirmation, now));
    assert!(!state.can_confirm_repair_at(confirmation, now + Duration::from_secs(30)));
    let web_expired = state.web_comparison().unwrap().observed_at() + Duration::from_secs(300);
    state.set_process_state_at(ProcessState::StoppedVerified, web_expired);
    assert!(!state.can_confirm_repair_at(confirmation, web_expired));
    state.set_process_state(ProcessState::Running);
    assert!(!state.can_confirm_repair_at(confirmation, Instant::now()));
    state.set_process_state(ProcessState::StoppedVerified);
    state.begin(Operation::Scanning);
    assert!(!state.can_confirm_repair_at(confirmation, Instant::now()));
}

#[test]
fn stopped_process_proof_expires_after_thirty_seconds_without_sleeping() {
    let verified_at = Instant::now();
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
    state.set_backup_directory_input("/synthetic/backups");
    state.install_report(report(PlatformPolicy::MacOs, true, true));
    install_valid_web(&mut state);
    assert!(state.set_selected(&confirmed_identity(), true));
    state.set_process_state_at(ProcessState::StoppedVerified, verified_at);

    assert!(!state.can_repair_at(
        verified_at
            .checked_sub(Duration::from_secs(1))
            .expect("Instant supports the synthetic earlier point"),
    ));
    assert_eq!(
        state.process_proof_remaining_at(verified_at + Duration::from_secs(29)),
        Some(Duration::from_secs(1))
    );
    let still_valid = state.repair_readiness_at(verified_at + Duration::from_secs(29));
    assert!(still_valid.process_stopped);
    assert!(still_valid.can_repair());
    assert!(state.can_repair_at(verified_at + Duration::from_secs(29)));

    let expired = state.repair_readiness_at(verified_at + Duration::from_secs(30));
    assert!(!expired.process_stopped);
    assert!(!expired.can_repair());
    assert!(!state.can_repair_at(verified_at + Duration::from_secs(30)));
    assert_eq!(
        state.process_proof_remaining_at(verified_at + Duration::from_secs(30)),
        None
    );
}

#[test]
fn process_event_uses_the_worker_observation_time_for_expiry() {
    let observed_at = Instant::now();
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
    state.set_backup_directory_input("/synthetic/backups");
    state.install_report(report(PlatformPolicy::MacOs, true, true));
    install_valid_web(&mut state);
    assert!(state.set_selected(&confirmed_identity(), true));

    let job_id = state.begin(Operation::Checking);

    assert!(state.apply_job_event(JobEvent::ProcessChecked {
        job_id,
        observed_at,
        result: Ok(ProcessPresence::Stopped),
    }));
    assert!(state.can_repair_at(observed_at + Duration::from_secs(29)));
    assert!(!state.can_repair_at(observed_at + Duration::from_secs(30)));
}

#[test]
fn selection_change_clears_stopped_process_proof() {
    let verified_at = Instant::now();
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
    state.set_backup_directory_input("/synthetic/backups");
    state.install_report(report(PlatformPolicy::MacOs, true, true));
    assert!(state.set_selected(&confirmed_identity(), true));
    state.set_process_state_at(ProcessState::StoppedVerified, verified_at);

    assert!(state.set_selected(&confirmed_identity(), false));

    assert_eq!(
        state.process_state_at(verified_at),
        ProcessState::NotChecked
    );
}

#[test]
fn backup_directory_change_clears_stopped_process_proof() {
    let verified_at = Instant::now();
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::Windows);
    state.install_report(report(PlatformPolicy::Windows, true, true));
    assert!(state.set_selected(&confirmed_identity(), true));
    state.set_process_state_at(ProcessState::StoppedVerified, verified_at);

    state.set_backup_directory_input("/different/backup");

    assert_eq!(
        state.process_state_at(verified_at),
        ProcessState::NotChecked
    );
}

#[test]
fn report_health_busy_state_and_linux_policy_deny_repair() {
    assert!(!ready_state(PlatformPolicy::Linux).can_repair());

    let mut read_only = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
    read_only.install_report(report(PlatformPolicy::MacOs, false, true));
    assert!(read_only.set_selected(&confirmed_identity(), true));
    read_only.set_process_state(ProcessState::StoppedVerified);

    assert!(!read_only.can_repair());

    let mut corrupt = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
    corrupt.install_report(report(PlatformPolicy::MacOs, true, false));
    assert!(corrupt.set_selected(&confirmed_identity(), true));
    corrupt.set_process_state(ProcessState::StoppedVerified);

    assert!(!corrupt.can_repair());

    let mut busy = ready_state(PlatformPolicy::Windows);
    let _job = busy.begin(Operation::Scanning);
    assert!(!busy.can_repair());
}

#[test]
fn stale_job_events_are_ignored() {
    let mut state = AppState::new(RunMode::Live, PlatformPolicy::MacOs);
    state.set_backup_directory_input("/synthetic/backups");
    let stale = state.begin(Operation::Scanning);
    let current = state.begin(Operation::Checking);

    assert!(!state.apply_job_event(JobEvent::ProcessChecked {
        job_id: stale,
        observed_at: Instant::now(),
        result: Ok(ProcessPresence::Stopped),
    }));
    assert_eq!(state.operation(), Operation::Checking);
    assert_eq!(state.process_state(), ProcessState::NotChecked);

    assert!(state.apply_job_event(JobEvent::ProcessChecked {
        job_id: current,
        observed_at: Instant::now(),
        result: Ok(ProcessPresence::Stopped),
    }));
    assert_eq!(state.operation(), Operation::Idle);
    assert_eq!(state.process_state(), ProcessState::StoppedVerified);
}

#[test]
fn demo_backend_boundary_performs_zero_live_calls() {
    let backend = backend_for_mode::<(), _>(RunMode::Demo, || {
        panic!("demo must never construct a live backend")
    });
    assert!(backend.is_none());
}

#[test]
fn worker_request_construction_never_turns_discovery_into_scan() {
    let inputs = ScanInputs {
        database_path: "/explicit/catalog.db".to_owned(),
        log_roots: "/logs/a\n\n/logs/b".to_owned(),
    };
    let path_inputs = CatalogPathInputs {
        explicit_path: Some(PathBuf::from("/explicit/catalog.db")),
        codex_home: Some(PathBuf::from("/codex-home")),
        home: Some(PathBuf::from("/home")),
    };

    let discover = WorkerRequest::discover(path_inputs.clone());
    assert!(matches!(
        discover.kind,
        WorkerRequestKind::Discover { inputs } if inputs == path_inputs
    ));

    let scan = WorkerRequest::scan(inputs, PlatformPolicy::MacOs).expect("valid scan inputs");
    match scan.kind {
        WorkerRequestKind::Scan {
            database_path,
            log_roots,
            platform,
        } => {
            assert_eq!(database_path, PathBuf::from("/explicit/catalog.db"));
            assert_eq!(
                log_roots,
                vec![PathBuf::from("/logs/a"), PathBuf::from("/logs/b")]
            );
            assert_eq!(platform, PlatformPolicy::MacOs);
        }
        other => panic!("expected a scan request, got {other:?}"),
    }
}

#[test]
fn repair_request_owns_inputs_and_marks_only_reviewed_authorization() {
    let scan_report = report(PlatformPolicy::MacOs, true, true);
    let selected = HashSet::from([confirmed_identity(), review_identity()]);
    let reviewed = HashSet::from([review_identity()]);

    let request = WorkerRequest::repair(
        scan_report,
        " /logs/a\n\n/logs/b ",
        &selected,
        &reviewed,
        " /backups ",
    )
    .expect("valid repair inputs");

    let WorkerRequestKind::Repair {
        report,
        log_roots,
        selected,
        backup_directory,
    } = request.kind
    else {
        panic!("expected a repair request");
    };
    assert_eq!(report.database_path, local_path("/synthetic/codex-dev.db"));
    assert_eq!(
        log_roots,
        vec![PathBuf::from("/logs/a"), PathBuf::from("/logs/b")]
    );
    assert_eq!(backup_directory, PathBuf::from("/backups"));
    assert_eq!(selected.len(), 2);
    assert!(selected.iter().any(|selection| {
        selection.identity == confirmed_identity() && !selection.review_authorized
    }));
    assert!(selected.iter().any(|selection| {
        selection.identity == review_identity() && selection.review_authorized
    }));
}

#[test]
fn repair_event_installs_a_receipt_and_returns_to_idle() {
    let mut state = ready_state(PlatformPolicy::MacOs);
    let job_id = state.begin(Operation::Repairing);
    let receipt = RepairReceipt::new(
        local_path("/synthetic/codex-dev.db"),
        local_path("/synthetic/backup.db"),
        "macos",
        "abc123",
        vec![confirmed_identity()],
        3,
        2,
    );

    assert!(state.apply_job_event(JobEvent::RepairFinished {
        job_id,
        result: Ok(receipt.clone()),
    }));
    assert_eq!(state.operation(), Operation::Idle);
    assert_eq!(state.receipt(), Some(&receipt));
    assert!(state.report().is_none());
    assert!(state.selected().is_empty());

    assert!(!state.set_selected(&confirmed_identity(), true));
}

#[test]
fn uncertain_worker_failure_invalidates_repair_authorization_and_report() {
    let mut state = ready_state(PlatformPolicy::MacOs);
    let job_id = state.begin(Operation::Repairing);

    assert!(state.fail_active(
        job_id,
        AppError::outcome_uncertain("worker disconnected during repair"),
    ));
    assert_eq!(state.operation(), Operation::Idle);
    assert!(state.report().is_none());
    assert!(state.reviewed().is_empty());
    assert!(state.selected().is_empty());

    assert_eq!(state.process_state(), ProcessState::NotChecked);
    assert_eq!(
        state.error().map(|error| error.outcome),
        Some(ErrorOutcome::OutcomeUncertain)
    );
}

#[test]
fn failed_rescan_discards_stale_report_authorization_and_process_proof() {
    let mut state = ready_state(PlatformPolicy::MacOs);
    let job_id = state.begin(Operation::Scanning);

    assert!(state.apply_job_event(JobEvent::ScanFinished {
        job_id,
        result: Err(AppError::no_data_change("synthetic scan failure")),
    }));
    assert!(state.report().is_none());
    assert!(state.reviewed().is_empty());
    assert!(state.selected().is_empty());

    assert_eq!(state.process_state(), ProcessState::NotChecked);
    assert!(!state.can_repair());
}

#[test]
fn disconnected_process_check_invalidates_an_older_stopped_proof() {
    let mut state = ready_state(PlatformPolicy::Windows);
    let job_id = state.begin(Operation::Checking);

    assert!(state.fail_active(
        job_id,
        AppError::no_data_change("worker disconnected during process check"),
    ));
    assert_eq!(state.process_state(), ProcessState::Unknown);
    assert!(!state.can_repair());
}

#[test]
fn discovery_path_change_clears_a_receipt_from_the_previous_database() {
    let mut state = ready_state(PlatformPolicy::MacOs);
    let repair_job = state.begin(Operation::Repairing);
    let receipt = RepairReceipt::new(
        local_path("/synthetic/codex-dev.db"),
        local_path("/synthetic/backup.db"),
        "macos",
        "abc123",
        vec![confirmed_identity()],
        3,
        2,
    );
    assert!(state.apply_job_event(JobEvent::RepairFinished {
        job_id: repair_job,
        result: Ok(receipt),
    }));
    assert!(state.receipt().is_some());

    let discovery_job = state.begin(Operation::Discovering);
    assert!(state.apply_job_event(JobEvent::DiscoveryFinished {
        job_id: discovery_job,
        result: Ok(vec![PathBuf::from("/different/codex-dev.db")]),
    }));
    assert_eq!(state.database_input(), "/different/codex-dev.db");
    assert!(state.receipt().is_none());
}

#[test]
fn synthetic_report_contains_all_three_classifications() {
    let report = report(PlatformPolicy::MacOs, true, true);
    assert_eq!(
        report.threads[0].classification(),
        Classification::ConfirmedDeleted
    );
    assert_eq!(
        report.threads[1].classification(),
        Classification::ReviewRequired
    );
    assert_eq!(
        report.threads[2].classification(),
        Classification::Preserved
    );
}
