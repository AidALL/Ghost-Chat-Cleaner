use ghost_chat_cleaner::process_guard::{
    ensure_chatgpt_stopped, ProcessGuardError, ProcessPresence, ProcessProbe,
};

#[derive(Clone, Copy)]
struct FakeProbe(ProcessPresence);

impl ProcessProbe for FakeProbe {
    fn chatgpt_presence(&self) -> ProcessPresence {
        self.0
    }
}

fn comparison_fixture() -> (
    ghost_chat_cleaner::model::ScanReport,
    ghost_chat_cleaner::web::WebComparison,
) {
    use ghost_chat_cleaner::model::{
        CatalogThread, LocalPath, ScanReport, SchemaReport, ThreadIdentity,
    };
    use ghost_chat_cleaner::web::WebComparison;
    use serde_json::json;
    use std::path::Path;

    let host = "chatgpt:11111111-1111-4111-8111-111111111111:user-fixture";
    let control = "22222222-2222-4222-8222-222222222222";
    let missing = "33333333-3333-4333-8333-333333333333";
    let report = ScanReport::new(
        LocalPath::try_from(Path::new("/nonexistent-ghost-web-proof-fixture/catalog.db")).unwrap(),
        "macos",
        SchemaReport {
            write_capable: true,
            reason: "fixture".into(),
            fingerprint: "fixture".into(),
            columns: vec![],
        },
        [control, missing]
            .into_iter()
            .map(|id| {
                CatalogThread::review_required(
                    ThreadIdentity::new(host, id),
                    "fixture",
                    "chatgpt",
                    true,
                    None,
                    None,
                )
                .unwrap()
            })
            .collect(),
        true,
    );
    let proof = WebComparison::from_value(
        &report,
        json!({
            "schema_version": 3, "kind": "requested_metadata_checks", "user_id": "user-fixture",
            "account_id": "44444444-4444-4444-8444-444444444444",
            "account_user_id": "user-fixture", "account_structure": "personal", "complete": true,
            "checks": [
                {"id": control, "evidence": "authenticated_list_item"},
                {"id": missing, "evidence": "authenticated_json_get_404"}
            ],
            "controls": [control]
        }),
    )
    .unwrap();
    (report, proof)
}

#[test]
fn public_repair_rejects_present_and_mismatched_proof_before_source_access() {
    use ghost_chat_cleaner::evidence::EvidenceScanConfig;
    use ghost_chat_cleaner::repair::{repair, RepairError, RepairRequest, RepairSelection};

    let (report, proof) = comparison_fixture();
    let directory = tempfile::tempdir().unwrap();
    let backup = directory.path().join("must-not-exist");
    let evidence = EvidenceScanConfig::new(vec![], vec![]);
    let present = [RepairSelection::new(
        report.threads[0].identity().clone(),
        true,
    )];
    let request = RepairRequest {
        scan_report: &report,
        evidence_config: &evidence,
        selected: &present,
        backup_directory: &backup,
    };
    assert!(matches!(
        repair(request, &proof),
        Err(RepairError::WebComparisonRequired)
    ));

    let mut changed = report.clone();
    changed.schema.fingerprint.push_str("-changed");
    let selected = [RepairSelection::new(
        report.threads[1].identity().clone(),
        true,
    )];
    let request = RepairRequest {
        scan_report: &changed,
        evidence_config: &evidence,
        selected: &selected,
        backup_directory: &backup,
    };
    assert!(matches!(
        repair(request, &proof),
        Err(RepairError::WebComparisonRequired)
    ));
    assert!(!backup.exists());
    assert!(!report.database_path.as_path().exists());
}

#[test]
fn process_guard_allows_only_a_definite_stopped_result() {
    ensure_chatgpt_stopped(&FakeProbe(ProcessPresence::Stopped))
        .expect("a definite stopped observation is safe");

    assert!(matches!(
        ensure_chatgpt_stopped(&FakeProbe(ProcessPresence::Running)),
        Err(ProcessGuardError::Running)
    ));
    assert!(matches!(
        ensure_chatgpt_stopped(&FakeProbe(ProcessPresence::Unknown)),
        Err(ProcessGuardError::Unknown)
    ));
}

#[test]
fn process_probe_contract_does_not_require_a_real_process() {
    let probe = FakeProbe(ProcessPresence::Stopped);
    assert_eq!(probe.chatgpt_presence(), ProcessPresence::Stopped);
}

#[cfg(target_os = "linux")]
#[test]
fn production_repair_is_scan_only_before_any_path_access_on_linux() {
    use ghost_chat_cleaner::evidence::EvidenceScanConfig;
    use ghost_chat_cleaner::repair::{repair, RepairError, RepairRequest, RepairSelection};

    let directory = tempfile::tempdir().expect("create Linux policy fixture");
    let backup = directory.path().join("must-not-be-created");
    let (report, proof) = comparison_fixture();
    let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
    let selected = [RepairSelection::new(
        report.threads[1].identity().clone(),
        true,
    )];

    assert!(matches!(
        repair(
            RepairRequest {
                scan_report: &report,
                evidence_config: &evidence,
                selected: &selected,
                backup_directory: backup.as_path(),
            },
            &proof
        ),
        Err(RepairError::PlatformReadOnly { .. })
    ));
    assert!(!report.database_path.as_path().exists());
    assert!(!backup.exists());
}
