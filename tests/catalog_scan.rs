mod fixtures;

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use fixtures::{
    create_sparse_evidence, write_evidence, CatalogFixture, CorruptFixture, SUPPORTED_SCHEMA,
};
use ghost_chat_cleaner::catalog::{scan_catalog, CatalogScanError};
use ghost_chat_cleaner::evidence::{
    discover_evidence_files, scan_deletion_evidence, EvidenceError, EvidenceScanConfig,
    DEFAULT_EVIDENCE_MAX_AGE, DELETION_EVIDENCE_REASON, MAX_EVIDENCE_FILE_BYTES,
    MAX_TOTAL_EVIDENCE_BYTES,
};
use ghost_chat_cleaner::model::Classification;
use ghost_chat_cleaner::platform::{
    discover_database_candidates, CatalogPathInputs, PlatformPolicy,
};

fn no_evidence() -> EvidenceScanConfig {
    EvidenceScanConfig::new(Vec::new(), Vec::new())
}

#[test]
fn platform_policy_has_stable_labels_and_fail_closed_mutation_rules() {
    assert_eq!(PlatformPolicy::Windows.label(), "windows");
    assert_eq!(PlatformPolicy::MacOs.label(), "macos");
    assert_eq!(PlatformPolicy::Linux.label(), "linux");
    assert_eq!(PlatformPolicy::Unsupported.label(), "unsupported");
    assert!(PlatformPolicy::Windows.allows_mutation());
    assert!(PlatformPolicy::MacOs.allows_mutation());
    assert!(!PlatformPolicy::Linux.allows_mutation());
    assert!(!PlatformPolicy::Unsupported.allows_mutation());

    #[cfg(target_os = "windows")]
    assert_eq!(PlatformPolicy::current(), PlatformPolicy::Windows);
    #[cfg(target_os = "macos")]
    assert_eq!(PlatformPolicy::current(), PlatformPolicy::MacOs);
    #[cfg(target_os = "linux")]
    assert_eq!(PlatformPolicy::current(), PlatformPolicy::Linux);
}

#[test]
fn path_discovery_is_existing_only_bounded_and_deduplicated() {
    let root = tempfile::tempdir().expect("create discovery fixture");
    let missing = root.path().join("missing.db");
    let codex_home = root.path().join("configured-codex-home");
    let home = root.path().join("home");

    let absent = discover_database_candidates(&CatalogPathInputs {
        explicit_path: Some(missing.clone()),
        codex_home: Some(codex_home.clone()),
        home: Some(home.clone()),
    })
    .expect("missing candidates are ignored");
    assert!(absent.is_empty());
    assert!(
        !missing.exists(),
        "discovery must never create an explicit path"
    );
    assert!(
        !codex_home.exists(),
        "discovery must never create CODEX_HOME"
    );
    assert!(
        !home.exists(),
        "discovery must never create a home directory"
    );

    let configured_database = codex_home.join("sqlite/codex-dev.db");
    fs::create_dir_all(configured_database.parent().expect("database parent"))
        .expect("create configured fixture path");
    fs::write(&configured_database, b"fixture").expect("write configured fixture");

    let paths = discover_database_candidates(&CatalogPathInputs {
        explicit_path: Some(configured_database.clone()),
        codex_home: Some(codex_home),
        home: Some(home),
    })
    .expect("discover configured database");
    assert_eq!(
        paths,
        vec![fs::canonicalize(configured_database).expect("canonical database path")]
    );
}

#[cfg(unix)]
#[test]
fn catalog_discovery_deduplicates_explicit_codex_home_and_home_ancestor_aliases() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("create discovery alias fixture");
    let codex_home = root.path().join("real-codex-home");
    let database = codex_home.join("sqlite/codex-dev.db");
    fs::create_dir_all(database.parent().expect("database parent"))
        .expect("create real database parent");
    fs::write(&database, b"fixture").expect("write database fixture");

    let codex_home_alias = root.path().join("codex-home-alias");
    symlink(&codex_home, &codex_home_alias).expect("create CODEX_HOME ancestor alias");
    let home = root.path().join("home");
    fs::create_dir(&home).expect("create injected home");
    symlink(&codex_home, home.join(".codex")).expect("create home ancestor alias");

    let paths = discover_database_candidates(&CatalogPathInputs {
        explicit_path: Some(codex_home_alias.join("sqlite/codex-dev.db")),
        codex_home: Some(codex_home),
        home: Some(home),
    })
    .expect("ancestor aliases are accepted");
    assert_eq!(
        paths,
        vec![fs::canonicalize(database).expect("canonical database path")]
    );
}

#[cfg(unix)]
#[test]
fn catalog_discovery_and_scan_refuse_symlinks() {
    use std::os::unix::fs::symlink;

    use ghost_chat_cleaner::platform::PathDiscoveryError;

    let fixture = CatalogFixture::supported();
    let directory = tempfile::tempdir().expect("create symlink fixture directory");
    let link = directory.path().join("catalog-link.db");
    symlink(fixture.path(), &link).expect("create catalog symlink");

    assert!(matches!(
        discover_database_candidates(&CatalogPathInputs {
            explicit_path: Some(link.clone()),
            codex_home: None,
            home: None,
        }),
        Err(PathDiscoveryError::SymlinkRefused { .. })
    ));
    assert!(matches!(
        scan_catalog(&link, PlatformPolicy::MacOs, &no_evidence()),
        Err(CatalogScanError::SymlinkRefused { .. })
    ));
}

#[cfg(unix)]
#[test]
fn scan_accepts_an_ancestor_symlink_alias_and_reports_the_canonical_target() {
    use std::os::unix::fs::symlink;

    let fixture = CatalogFixture::supported();
    let alias_directory = tempfile::tempdir().expect("create ancestor alias fixture");
    let parent_alias = alias_directory.path().join("catalog-parent-alias");
    symlink(
        fixture.path().parent().expect("fixture database parent"),
        &parent_alias,
    )
    .expect("create ancestor directory symlink");
    let aliased_database = parent_alias.join(
        fixture
            .path()
            .file_name()
            .expect("fixture database file name"),
    );

    let report = scan_catalog(&aliased_database, PlatformPolicy::MacOs, &no_evidence())
        .expect("ancestor symlink aliases are resolved before NOFOLLOW open");
    assert_eq!(
        report.database_path.as_path(),
        fs::canonicalize(fixture.path()).expect("canonical fixture path")
    );
}

#[test]
fn evidence_requires_a_recent_supported_regular_file_and_same_line_exact_id() {
    let directory = tempfile::tempdir().expect("create evidence fixture directory");
    let good_path = write_evidence(
        directory.path(),
        "events.jsonl",
        concat!(
            "conversation_deleted thread-exact\n",
            "conversation_deleted thread-exact-suffix\n",
            "conversation deleted\n",
            "thread-split\n",
            "conversation deleted thread-space\n",
            "not_conversation_deleted thread-marker-prefix\n",
            "conversation_deleted_backup thread-marker-suffix\n",
            "notconversation deleted thread-phrase-prefix\n",
            "conversation deleted_backup thread-phrase-suffix\n"
        ),
    );
    write_evidence(
        directory.path(),
        "ignored.bin",
        "conversation_deleted thread-ignored\n",
    );

    let config = EvidenceScanConfig::new(vec![directory.path().to_path_buf()], Vec::new());
    let files = discover_evidence_files(&config).expect("discover evidence files");
    assert_eq!(files, vec![good_path.clone()]);

    let index = scan_deletion_evidence(
        &config,
        &[
            "thread-exact",
            "thread-exact-suffix",
            "thread-split",
            "thread-space",
            "thread-ignored",
            "thread-marker-prefix",
            "thread-marker-suffix",
            "thread-phrase-prefix",
            "thread-phrase-suffix",
        ],
    )
    .expect("scan evidence");
    assert_eq!(
        index
            .evidence_for("thread-exact")
            .expect("exact same-line marker")
            .source_path
            .as_path(),
        good_path
    );
    assert!(index.evidence_for("thread-exact-suffix").is_some());
    assert!(index.evidence_for("thread-space").is_some());
    assert!(index.evidence_for("thread-split").is_none());
    assert!(index.evidence_for("thread-ignored").is_none());
    assert!(index.evidence_for("thread-marker-prefix").is_none());
    assert!(index.evidence_for("thread-marker-suffix").is_none());
    assert!(index.evidence_for("thread-phrase-prefix").is_none());
    assert!(index.evidence_for("thread-phrase-suffix").is_none());
    assert_eq!(
        index.evidence_for("thread-exact").expect("evidence").reason,
        DELETION_EVIDENCE_REASON
    );
}

#[test]
fn evidence_age_identifier_file_and_total_limits_are_enforced() {
    assert_eq!(
        DEFAULT_EVIDENCE_MAX_AGE,
        Duration::from_secs(7 * 24 * 60 * 60)
    );
    assert_eq!(MAX_EVIDENCE_FILE_BYTES, 25 * 1024 * 1024);
    assert_eq!(MAX_TOTAL_EVIDENCE_BYTES, 80 * 1024 * 1024);

    let old_root = tempfile::tempdir().expect("create old evidence fixture");
    write_evidence(
        old_root.path(),
        "old.log",
        "conversation_deleted thread-old\n",
    );
    let future_now = SystemTime::now() + DEFAULT_EVIDENCE_MAX_AGE + Duration::from_secs(60);
    let old_config = EvidenceScanConfig::new(vec![old_root.path().to_path_buf()], Vec::new())
        .at_time(future_now);
    assert!(discover_evidence_files(&old_config)
        .expect("old files are skipped")
        .is_empty());

    let invalid_id_config = EvidenceScanConfig::new(Vec::new(), Vec::new());
    for invalid in ["", "contains whitespace", "非ascii", &"a".repeat(129)] {
        assert!(matches!(
            scan_deletion_evidence(&invalid_id_config, &[invalid]),
            Err(EvidenceError::InvalidThreadId { .. })
        ));
    }

    let large_root = tempfile::tempdir().expect("create large evidence fixture");
    create_sparse_evidence(
        large_root.path(),
        "too-large.log",
        MAX_EVIDENCE_FILE_BYTES + 1,
    );
    let large_config = EvidenceScanConfig::new(vec![large_root.path().to_path_buf()], Vec::new());
    assert!(matches!(
        discover_evidence_files(&large_config),
        Err(EvidenceError::FileTooLarge { .. })
    ));

    let total_root = tempfile::tempdir().expect("create capped evidence fixture");
    for index in 0..4 {
        create_sparse_evidence(
            total_root.path(),
            &format!("part-{index}.log"),
            21 * 1024 * 1024,
        );
    }
    let total_config = EvidenceScanConfig::new(vec![total_root.path().to_path_buf()], Vec::new());
    assert!(matches!(
        discover_evidence_files(&total_config),
        Err(EvidenceError::TotalSizeExceeded { .. })
    ));
}

#[cfg(unix)]
#[test]
fn evidence_discovery_refuses_symlinks() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("create evidence symlink fixture");
    let target = write_evidence(directory.path(), "target.log", "nothing sensitive\n");
    let link = directory.path().join("linked.log");
    symlink(target, link).expect("create evidence symlink");
    let config = EvidenceScanConfig::new(vec![directory.path().to_path_buf()], Vec::new());
    assert!(matches!(
        discover_evidence_files(&config),
        Err(EvidenceError::SymlinkRefused { .. })
    ));
}

#[test]
fn supported_profile_scans_only_chatgpt_and_classifies_conservatively() {
    let fixture = CatalogFixture::supported();
    fixture.insert_thread(
        "host-a",
        "thread-confirmed",
        "Confirmed",
        "chatgpt",
        None,
        None,
        0,
        1.0,
    );
    fixture.insert_thread(
        "host-a",
        "thread-review",
        "Review",
        "chatgpt",
        None,
        None,
        1,
        2.0,
    );
    fixture.insert_thread(
        "host-a",
        "thread-project",
        "Project",
        "chatgpt",
        Some("project-1"),
        None,
        1,
        3.0,
    );
    fixture.insert_thread(
        "host-a",
        "thread-cwd",
        "Working directory",
        "chatgpt",
        None,
        Some("/workspace/project"),
        1,
        4.0,
    );
    fixture.insert_thread(
        "host-a",
        "thread-empty-project",
        "Empty project",
        "chatgpt",
        Some(""),
        None,
        1,
        5.0,
    );
    fixture.insert_thread(
        "host-a",
        "thread-empty-cwd",
        "Empty working directory",
        "chatgpt",
        None,
        Some(""),
        1,
        6.0,
    );
    fixture.insert_thread(
        "host-a",
        "thread-other-source",
        "Other source",
        "project",
        None,
        None,
        1,
        7.0,
    );

    let logs = tempfile::tempdir().expect("create catalog evidence root");
    let evidence_path = write_evidence(
        logs.path(),
        "deletions.jsonl",
        concat!(
            "{\"event\":\"conversation_deleted\",\"thread_id\":\"thread-confirmed\"}\n",
            "{\"event\":\"conversation_deleted\",\"thread_id\":\"thread-project\"}\n"
        ),
    );
    let evidence = EvidenceScanConfig::new(vec![logs.path().to_path_buf()], Vec::new());

    let report = scan_catalog(fixture.path(), PlatformPolicy::MacOs, &evidence)
        .expect("scan supported catalog");
    assert!(report.integrity_ok);
    assert!(report.schema.write_capable);
    assert_eq!(report.platform_label, "macos");
    assert_eq!(report.threads.len(), 6, "non-chatgpt rows are excluded");
    assert_eq!(report.schema.fingerprint.len(), 64);
    assert!(report
        .schema
        .fingerprint
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit()));

    let classification = |id: &str| {
        report
            .threads
            .iter()
            .find(|thread| thread.identity().thread_id == id)
            .expect("thread in report")
            .classification()
    };
    assert_eq!(
        classification("thread-confirmed"),
        Classification::ConfirmedDeleted
    );
    assert_eq!(
        classification("thread-review"),
        Classification::ReviewRequired
    );
    assert_eq!(classification("thread-project"), Classification::Preserved);
    assert_eq!(classification("thread-cwd"), Classification::Preserved);
    assert_eq!(
        classification("thread-empty-project"),
        Classification::Preserved
    );
    assert_eq!(
        classification("thread-empty-cwd"),
        Classification::Preserved
    );

    let confirmed = report
        .threads
        .iter()
        .find(|thread| thread.identity().thread_id == "thread-confirmed")
        .expect("confirmed thread");
    let stored_evidence = confirmed.evidence().expect("deletion evidence");
    assert_eq!(stored_evidence.source_path.as_path(), evidence_path);
    assert_eq!(stored_evidence.reason, DELETION_EVIDENCE_REASON);
}

#[test]
fn duplicate_thread_ids_across_hosts_are_never_confirmed_from_thread_only_evidence() {
    let fixture = CatalogFixture::supported();
    for host_id in ["host-a", "host-b"] {
        fixture.insert_thread(
            host_id,
            "thread-collision-marker",
            "Marker collision",
            "chatgpt",
            None,
            None,
            0,
            1.0,
        );
        fixture.insert_thread(
            host_id,
            "thread-collision-none",
            "No-signal collision",
            "chatgpt",
            None,
            None,
            0,
            2.0,
        );
    }
    fixture.insert_thread(
        "host-a",
        "thread-collision-missing",
        "Missing collision",
        "chatgpt",
        None,
        None,
        1,
        3.0,
    );
    fixture.insert_thread(
        "host-b",
        "thread-collision-missing",
        "Non-missing collision",
        "chatgpt",
        None,
        None,
        0,
        4.0,
    );

    let logs = tempfile::tempdir().expect("create collision evidence root");
    write_evidence(
        logs.path(),
        "deletions.log",
        "conversation_deleted thread-collision-marker\n",
    );
    let evidence = EvidenceScanConfig::new(vec![logs.path().to_path_buf()], Vec::new());
    let report = scan_catalog(fixture.path(), PlatformPolicy::MacOs, &evidence)
        .expect("scan colliding thread identifiers");

    let rows_for = |thread_id: &str| {
        report
            .threads
            .iter()
            .filter(|thread| thread.identity().thread_id == thread_id)
            .collect::<Vec<_>>()
    };
    let marker_rows = rows_for("thread-collision-marker");
    assert_eq!(marker_rows.len(), 2);
    assert!(marker_rows.iter().all(|thread| {
        thread.classification() == Classification::ReviewRequired && thread.evidence().is_none()
    }));

    let missing_rows = rows_for("thread-collision-missing");
    assert_eq!(missing_rows.len(), 2);
    assert_eq!(missing_rows[0].identity().host_id, "host-a");
    assert_eq!(
        missing_rows[0].classification(),
        Classification::ReviewRequired
    );
    assert_eq!(missing_rows[1].identity().host_id, "host-b");
    assert_eq!(missing_rows[1].classification(), Classification::Preserved);

    let no_signal_rows = rows_for("thread-collision-none");
    assert_eq!(no_signal_rows.len(), 2);
    assert!(no_signal_rows
        .iter()
        .all(|thread| thread.classification() == Classification::Preserved));
}

#[test]
fn schema_object_limit_accepts_the_boundary_and_rejects_one_more() {
    const SCHEMA_OBJECT_LIMIT: usize = 4_096;

    let schema_with_total_objects = |total: usize| {
        let mut schema = SUPPORTED_SCHEMA.to_owned();
        for index in 1..total {
            schema.push_str(&format!(
                "CREATE VIEW bounded_schema_object_{index} AS SELECT {index} AS value;\n"
            ));
        }
        schema
    };

    let at_limit = CatalogFixture::with_schema(&schema_with_total_objects(SCHEMA_OBJECT_LIMIT));
    let report = scan_catalog(at_limit.path(), PlatformPolicy::MacOs, &no_evidence())
        .expect("the exact schema object limit is accepted");
    assert!(report.schema.write_capable);

    let above_limit =
        CatalogFixture::with_schema(&schema_with_total_objects(SCHEMA_OBJECT_LIMIT + 1));
    assert!(matches!(
        scan_catalog(above_limit.path(), PlatformPolicy::MacOs, &no_evidence()),
        Err(CatalogScanError::SchemaTooLarge { .. })
    ));
}

#[test]
fn oversized_sqlite_master_definition_returns_typed_schema_error() {
    let padding = "x".repeat(70 * 1024);
    let schema = format!(
        "{SUPPORTED_SCHEMA}\nCREATE TABLE oversized_definition (value TEXT DEFAULT '{padding}');"
    );
    let fixture = CatalogFixture::with_schema(&schema);
    assert!(matches!(
        scan_catalog(fixture.path(), PlatformPolicy::MacOs, &no_evidence()),
        Err(CatalogScanError::SchemaTooLarge { .. })
    ));
}

#[test]
fn unknown_or_read_incompatible_schema_is_non_writable_without_querying_rows() {
    for schema in [
        "CREATE TABLE unrelated (id TEXT PRIMARY KEY);",
        "CREATE TABLE local_thread_catalog (host_id TEXT, thread_id TEXT, display_title TEXT);",
        "CREATE TABLE local_thread_catalog (host_id BLOB, thread_id TEXT, display_title TEXT, source_kind TEXT);",
    ] {
        let fixture = CatalogFixture::with_schema(schema);
        let report = scan_catalog(fixture.path(), PlatformPolicy::MacOs, &no_evidence())
            .expect("unknown schemas return a fail-closed report");
        assert!(!report.schema.write_capable);
        assert!(report.threads.is_empty());
    }
}

#[test]
fn every_structural_mismatch_disables_writes_but_keeps_safe_read_profile() {
    let cases = [
        (
            "missing column",
            SUPPORTED_SCHEMA.replace("        source_recency_at REAL,\n", ""),
        ),
        (
            "retyped column",
            SUPPORTED_SCHEMA.replace("missing_candidate INTEGER", "missing_candidate TEXT"),
        ),
        (
            "ambiguous type follows SQLite BLOB precedence",
            SUPPORTED_SCHEMA.replace("source_recency_at REAL", "source_recency_at REAL BLOB"),
        ),
        (
            "reversed primary key",
            SUPPORTED_SCHEMA.replace(
                "PRIMARY KEY (host_id, thread_id)",
                "PRIMARY KEY (thread_id, host_id)",
            ),
        ),
        (
            "target trigger",
            format!(
                "{SUPPORTED_SCHEMA}\nCREATE TRIGGER local_thread_touch AFTER UPDATE ON local_thread_catalog BEGIN SELECT 1; END;"
            ),
        ),
        (
            "outbound foreign key",
            r#"
                CREATE TABLE projects (id TEXT PRIMARY KEY);
                CREATE TABLE local_thread_catalog (
                    host_id TEXT NOT NULL,
                    thread_id TEXT NOT NULL,
                    display_title TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    project_id TEXT REFERENCES projects(id),
                    cwd TEXT,
                    missing_candidate INTEGER NOT NULL DEFAULT 0,
                    source_recency_at REAL,
                    PRIMARY KEY (host_id, thread_id)
                ) WITHOUT ROWID;
            "#
            .to_owned(),
        ),
        (
            "inbound foreign key",
            format!(
                "{SUPPORTED_SCHEMA}\nCREATE TABLE child (host_id TEXT, thread_id TEXT, FOREIGN KEY (host_id, thread_id) REFERENCES local_thread_catalog(host_id, thread_id));"
            ),
        ),
        (
            "case-insensitive inbound foreign key",
            format!(
                "{SUPPORTED_SCHEMA}\nCREATE TABLE child (host_id TEXT, thread_id TEXT, FOREIGN KEY (host_id, thread_id) REFERENCES LOCAL_THREAD_CATALOG(host_id, thread_id));"
            ),
        ),
    ];

    for (name, schema) in cases {
        let fixture = CatalogFixture::with_schema(&schema);
        let report = scan_catalog(fixture.path(), PlatformPolicy::MacOs, &no_evidence())
            .unwrap_or_else(|error| panic!("{name} should remain read-capable: {error}"));
        assert!(!report.schema.write_capable, "{name} must disable writes");
    }
}

#[test]
fn platform_policy_is_an_additional_write_gate() {
    let fixture = CatalogFixture::supported();
    let macos = scan_catalog(fixture.path(), PlatformPolicy::MacOs, &no_evidence())
        .expect("scan macOS policy");
    let windows = scan_catalog(fixture.path(), PlatformPolicy::Windows, &no_evidence())
        .expect("scan Windows policy");
    let linux = scan_catalog(fixture.path(), PlatformPolicy::Linux, &no_evidence())
        .expect("scan Linux policy");
    let unsupported = scan_catalog(fixture.path(), PlatformPolicy::Unsupported, &no_evidence())
        .expect("scan unsupported policy");

    assert!(macos.schema.write_capable);
    assert!(windows.schema.write_capable);
    assert!(!linux.schema.write_capable);
    assert!(!unsupported.schema.write_capable);
    assert_eq!(macos.schema.fingerprint, windows.schema.fingerprint);
}

#[test]
fn missing_and_corrupt_catalogs_return_typed_errors_without_creation() {
    let directory = tempfile::tempdir().expect("create missing catalog fixture");
    let missing = directory.path().join("missing.db");
    assert!(matches!(
        scan_catalog(&missing, PlatformPolicy::MacOs, &no_evidence()),
        Err(CatalogScanError::PathNotFound { .. })
    ));
    assert!(
        !missing.exists(),
        "read-only scan must never create the file"
    );

    let corrupt = CorruptFixture::create();
    assert!(matches!(
        scan_catalog(corrupt.path(), PlatformPolicy::MacOs, &no_evidence()),
        Err(CatalogScanError::InvalidDatabase { .. })
    ));
}

#[test]
fn full_integrity_check_rejects_a_logically_damaged_database() {
    let fixture = CatalogFixture::supported();
    fixture.damage_integrity();
    assert!(matches!(
        scan_catalog(fixture.path(), PlatformPolicy::MacOs, &no_evidence()),
        Err(CatalogScanError::IntegrityCheckFailed { .. })
    ));
}

#[test]
fn explicit_evidence_roots_are_included_and_deduplicated() {
    let allowlisted = tempfile::tempdir().expect("create allowlisted root");
    let explicit = tempfile::tempdir().expect("create explicit root");
    let allowlisted_file = write_evidence(allowlisted.path(), "one.log", "no marker\n");
    let explicit_file = write_evidence(explicit.path(), "two.txt", "no marker\n");
    let config = EvidenceScanConfig::new(
        vec![allowlisted.path().to_path_buf()],
        vec![
            explicit.path().to_path_buf(),
            allowlisted.path().to_path_buf(),
        ],
    );
    let mut files = discover_evidence_files(&config).expect("discover both root classes");
    files.sort();
    let mut expected = vec![allowlisted_file, explicit_file];
    expected.sort();
    assert_eq!(files, expected);
}

#[test]
fn canonical_catalog_path_is_reported_through_the_existing_typed_invariant() {
    let fixture = CatalogFixture::supported();
    let report = scan_catalog(fixture.path(), PlatformPolicy::MacOs, &no_evidence())
        .expect("temporary fixture path is UTF-8");
    let path: PathBuf = report.database_path.as_path().to_path_buf();
    assert_eq!(
        path,
        fs::canonicalize(fixture.path()).expect("canonical fixture path")
    );
}
