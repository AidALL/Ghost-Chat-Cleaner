use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::backup::{Backup, StepResult};
use rusqlite::config::DbConfig;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::catalog::{scan_catalog, scan_catalog_connection, CatalogScanError};
use crate::evidence::EvidenceScanConfig;
use crate::model::{
    Classification, LocalPath, NonUtf8PathError, RepairReceipt, ScanReport, ThreadIdentity,
};
use crate::platform::PlatformPolicy;
use crate::process_guard::{
    ensure_chatgpt_stopped, ProcessGuardError, ProcessProbe, SysinfoProcessProbe,
};
use crate::web::WebComparison;

pub const MAX_REPAIR_TARGETS: usize = 10_000;
const BACKUP_PAGES_PER_STEP: i32 = 128;
const MAX_BACKUP_STEPS: usize = 1_000_000;
const MAX_BACKUP_BUSY_RETRIES: usize = 40;
const BACKUP_BUSY_PAUSE: Duration = Duration::from_millis(25);
static BACKUP_COUNTER: AtomicU64 = AtomicU64::new(0);

trait DurabilitySync {
    fn sync_file(&self, file: &File) -> io::Result<()>;
    fn sync_directory(&self, path: &Path) -> io::Result<()>;
}

struct OsDurabilitySync;

impl DurabilitySync for OsDurabilitySync {
    fn sync_file(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            File::open(path)?.sync_all()
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "directory sync is not available on this platform",
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackupDirectoryPolicy {
    UnixPrivate,
    WindowsSourceParent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedBackup {
    path: PathBuf,
    sha256: String,
}

impl VerifiedBackup {
    fn verify_unchanged(&self) -> Result<(), RepairError> {
        let metadata = fs::symlink_metadata(&self.path).map_err(|source| RepairError::Io {
            operation: "reinspect verified backup",
            path: self.path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(RepairError::BackupHashChanged);
        }
        if hash_file(&self.path)? != self.sha256 {
            return Err(RepairError::BackupHashChanged);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairSelection {
    pub identity: ThreadIdentity,
    pub review_authorized: bool,
}

impl RepairSelection {
    pub fn new(identity: ThreadIdentity, review_authorized: bool) -> Self {
        Self {
            identity,
            review_authorized,
        }
    }
}

pub struct RepairRequest<'a> {
    pub scan_report: &'a ScanReport,
    pub evidence_config: &'a EvidenceScanConfig,
    pub selected: &'a [RepairSelection],
    pub backup_directory: &'a Path,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    AfterPlanLoaded,
    AfterDelete,
}

pub(crate) trait FaultInjector {
    fn hit(
        &self,
        _point: FaultPoint,
        _connection: &rusqlite::Connection,
    ) -> Result<(), RepairError> {
        Ok(())
    }
}

pub(crate) struct NoFaultInjector;

impl FaultInjector for NoFaultInjector {}

#[derive(Debug, Error)]
pub enum RepairError {
    #[error("repair requires a fresh matching browser comparison with unavailable selected conversations")]
    WebComparisonRequired,
    #[error("platform policy {platform} is scan-only")]
    PlatformReadOnly { platform: String },
    #[error("repair plan is empty")]
    EmptyPlan,
    #[error("repair plan contains a duplicate target at index {index}")]
    DuplicateTarget { index: usize },
    #[error("repair plan exceeds the {limit}-target limit")]
    PlanTooLarge { limit: usize },
    #[error("selected thread at index {index} is absent from the scan report")]
    SelectedThreadMissing { index: usize },
    #[error("selected thread at index {index} requires explicit review authorization")]
    ReviewAuthorizationRequired { index: usize },
    #[error("selected thread at index {index} is not eligible for repair")]
    ThreadNotEligible { index: usize },
    #[error("scan report failed its {check} precondition")]
    InvalidScanReport { check: &'static str },
    #[error("scan report platform does not match the repair platform")]
    PlatformMismatch,
    #[error("scan report database path is not the canonical source path")]
    DatabasePathMismatch,
    #[error("fresh catalog state differs from the supplied scan report")]
    StaleScanReport,
    #[error("catalog contains an unexpected attached database")]
    AttachedDatabase,
    #[error("catalog connection is read-only")]
    ReadOnlyConnection,
    #[error("catalog pragma {pragma} did not retain the required value")]
    PragmaNotApplied { pragma: &'static str },
    #[error("journal mode {mode} is unsafe or unsupported for repair")]
    UnsafeJournalMode { mode: String },
    #[error("synchronous=OFF is unsafe for repair")]
    UnsafeSynchronous,
    #[error("catalog data changed across a repair boundary")]
    DataVersionChanged,
    #[error("backup destination already exists")]
    BackupAlreadyExists,
    #[error("backup directory {path:?} is unsafe: {reason}")]
    UnsafeBackupDirectory { path: PathBuf, reason: &'static str },
    #[error("backup could not complete within bounded retries")]
    BackupTimeout,
    #[error("backup hash changed while the backup was verified")]
    BackupHashChanged,
    #[error("backup validation did not match the source snapshot")]
    BackupValidationFailed,
    #[error("row count guard {stage} expected {expected} rows but observed {actual}")]
    CountMismatch {
        stage: &'static str,
        expected: u64,
        actual: u64,
    },
    #[error("SQLite integrity_check did not return exactly one ok row")]
    IntegrityCheckFailed,
    #[error("SQLite foreign_key_check returned a violation")]
    ForeignKeyCheckFailed,
    #[error("repair fault injected at {point:?}")]
    FaultInjected { point: FaultPoint },
    #[error(
        "rollback failed after {original}; verified backup preserved at {backup_path:?}: {rollback}"
    )]
    RollbackFailed {
        backup_path: PathBuf,
        original: Box<RepairError>,
        #[source]
        rollback: rusqlite::Error,
    },
    #[error("commit failed; restore from preserved backup {backup_path:?}: {source}")]
    CommitFailed {
        backup_path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("post-commit verification failed; restore from preserved backup {backup_path:?}")]
    CommitOutcomeInvalid { backup_path: PathBuf },
    #[error("filesystem operation {operation} failed for {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Catalog(#[from] CatalogScanError),
    #[error(transparent)]
    Process(#[from] ProcessGuardError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    NonUtf8Path(#[from] NonUtf8PathError),
}

fn validate_plan_shape(selected: &[RepairSelection]) -> Result<(), RepairError> {
    if selected.is_empty() {
        return Err(RepairError::EmptyPlan);
    }
    if selected.len() > MAX_REPAIR_TARGETS {
        return Err(RepairError::PlanTooLarge {
            limit: MAX_REPAIR_TARGETS,
        });
    }
    let mut identities = HashSet::with_capacity(selected.len());
    for (index, selection) in selected.iter().enumerate() {
        if !identities.insert(&selection.identity) {
            return Err(RepairError::DuplicateTarget { index });
        }
    }
    Ok(())
}

#[cfg(test)]
fn validate_authorizations(
    report: &ScanReport,
    selected: &[RepairSelection],
) -> Result<(), RepairError> {
    validate_authorizations_with_web(report, selected, None)
}

fn validate_authorizations_with_web(
    report: &ScanReport,
    selected: &[RepairSelection],
    web_proof: Option<&WebComparison>,
) -> Result<(), RepairError> {
    let proof_bound = web_proof
        .is_some_and(|proof| proof.matches_report(report) && proof.is_fresh_at(Instant::now()));
    let threads = report
        .threads
        .iter()
        .map(|thread| (thread.identity(), thread))
        .collect::<HashMap<_, _>>();
    for (index, selection) in selected.iter().enumerate() {
        let thread = threads
            .get(&selection.identity)
            .copied()
            .ok_or(RepairError::SelectedThreadMissing { index })?;
        if thread.source_kind() != "chatgpt"
            || thread.project_id().is_some()
            || thread.cwd().is_some()
        {
            return Err(RepairError::ThreadNotEligible { index });
        }
        match thread.classification() {
            Classification::ConfirmedDeleted => {}
            Classification::ReviewRequired if selection.review_authorized => {}
            Classification::ReviewRequired => {
                return Err(RepairError::ReviewAuthorizationRequired { index });
            }
            Classification::Preserved
                if proof_bound
                    && web_proof.is_some_and(|proof| {
                        proof.verdict(&selection.identity) == crate::web::WebVerdict::Unavailable
                    }) =>
            {
                if !selection.review_authorized {
                    return Err(RepairError::ReviewAuthorizationRequired { index });
                }
            }
            Classification::Preserved => {
                return Err(RepairError::ThreadNotEligible { index });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn execute_repair_with(
    request: RepairRequest<'_>,
    platform: PlatformPolicy,
    probe: &impl ProcessProbe,
    faults: &impl FaultInjector,
) -> Result<RepairReceipt, RepairError> {
    execute_repair_with_sync(request, platform, probe, faults, &OsDurabilitySync)
}

#[cfg(test)]
fn execute_repair_with_sync(
    request: RepairRequest<'_>,
    platform: PlatformPolicy,
    probe: &impl ProcessProbe,
    faults: &impl FaultInjector,
    durability: &impl DurabilitySync,
) -> Result<RepairReceipt, RepairError> {
    execute_repair_guarded(
        request,
        platform,
        probe,
        faults,
        durability,
        &|| Ok(()),
        None,
    )
}

fn execute_repair_guarded(
    request: RepairRequest<'_>,
    platform: PlatformPolicy,
    probe: &impl ProcessProbe,
    faults: &impl FaultInjector,
    durability: &impl DurabilitySync,
    authorize: &impl Fn() -> Result<(), RepairError>,
    web_proof: Option<&WebComparison>,
) -> Result<RepairReceipt, RepairError> {
    authorize()?;
    if !platform.allows_mutation() {
        return Err(RepairError::PlatformReadOnly {
            platform: platform.label().to_owned(),
        });
    }
    validate_plan_shape(request.selected)?;
    validate_report_preconditions(request.scan_report, platform)?;
    validate_authorizations_with_web(request.scan_report, request.selected, web_proof)?;
    ensure_chatgpt_stopped(probe)?;

    let database_path = canonical_report_path(request.scan_report)?;
    let fresh_report = scan_catalog(&database_path, platform, request.evidence_config)?;
    validate_fresh_report(
        request.scan_report,
        &fresh_report,
        request.selected,
        web_proof,
    )?;

    let mut source = open_source(&database_path)?;
    harden_source(&source)?;
    validate_connection_environment(&source)?;
    let initial_data_version = read_data_version(&source)?;

    authorize()?;
    let backup = create_verified_backup(
        &source,
        &fresh_report,
        request.selected,
        request.evidence_config,
        request.backup_directory,
        platform,
        durability,
        web_proof,
    )?;
    if read_data_version(&source)? != initial_data_version {
        return Err(RepairError::DataVersionChanged);
    }
    ensure_chatgpt_stopped(probe)?;
    backup.verify_unchanged()?;

    authorize()?;
    let transaction = source.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let operation = prepare_commit(
        &transaction,
        &database_path,
        &fresh_report,
        &request,
        platform,
        probe,
        faults,
        initial_data_version,
        &backup,
        web_proof,
    );
    let receipt = match operation.and_then(|receipt| {
        authorize()?;
        Ok(receipt)
    }) {
        Ok(receipt) => receipt,
        Err(error) => {
            return match transaction.rollback() {
                Ok(()) => Err(error),
                Err(rollback) => Err(RepairError::RollbackFailed {
                    backup_path: backup.path.clone(),
                    original: Box::new(error),
                    rollback,
                }),
            };
        }
    };
    transaction
        .commit()
        .map_err(|source| RepairError::CommitFailed {
            backup_path: backup.path.clone(),
            source,
        })?;

    verify_committed_state(
        &database_path,
        &fresh_report,
        request.selected,
        request.evidence_config,
        platform,
        &backup,
    )?;
    Ok(receipt)
}

/// A validated browser comparison is mandatory for the public mutation path.
///
/// ```compile_fail
/// use ghost_chat_cleaner::repair::{repair, RepairRequest};
/// fn without_browser_proof(request: RepairRequest<'_>) {
///     let _ = repair(request);
/// }
/// ```
pub fn repair(
    request: RepairRequest<'_>,
    proof: &WebComparison,
) -> Result<RepairReceipt, RepairError> {
    let report = request.scan_report;
    let selected = request.selected;
    execute_repair_guarded(
        request,
        PlatformPolicy::current(),
        &SysinfoProcessProbe,
        &NoFaultInjector,
        &OsDurabilitySync,
        &|| require_web_comparison(report, selected, proof, Instant::now()),
        Some(proof),
    )
}

fn require_web_comparison(
    report: &ScanReport,
    selected: &[RepairSelection],
    proof: &WebComparison,
    now: Instant,
) -> Result<(), RepairError> {
    let identities = selected
        .iter()
        .map(|selection| selection.identity.clone())
        .collect::<Vec<_>>();
    if proof.permits(report, &identities, now) {
        Ok(())
    } else {
        Err(RepairError::WebComparisonRequired)
    }
}

fn validate_report_preconditions(
    report: &ScanReport,
    platform: PlatformPolicy,
) -> Result<(), RepairError> {
    if !report.integrity_ok {
        return Err(RepairError::InvalidScanReport { check: "integrity" });
    }
    if !report.schema.write_capable {
        return Err(RepairError::InvalidScanReport {
            check: "write_capable",
        });
    }
    if report.platform_label != platform.label() {
        return Err(RepairError::PlatformMismatch);
    }
    Ok(())
}

fn canonical_report_path(report: &ScanReport) -> Result<PathBuf, RepairError> {
    let path = report.database_path.as_path();
    let metadata = fs::symlink_metadata(path).map_err(|source| RepairError::Io {
        operation: "inspect source",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RepairError::DatabasePathMismatch);
    }
    let canonical = fs::canonicalize(path).map_err(|source| RepairError::Io {
        operation: "canonicalize source",
        path: path.to_path_buf(),
        source,
    })?;
    if canonical != path {
        return Err(RepairError::DatabasePathMismatch);
    }
    Ok(canonical)
}

fn validate_fresh_report(
    expected: &ScanReport,
    actual: &ScanReport,
    selected: &[RepairSelection],
    web_proof: Option<&WebComparison>,
) -> Result<(), RepairError> {
    if expected.database_path != actual.database_path
        || expected.platform_label != actual.platform_label
        || expected.schema != actual.schema
        || expected.integrity_ok != actual.integrity_ok
        || expected.threads != actual.threads
    {
        return Err(RepairError::StaleScanReport);
    }
    validate_authorizations_with_web(actual, selected, web_proof)
}

fn open_source(path: &Path) -> Result<Connection, RepairError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags(path, flags)?;
    if connection.is_readonly("main")? {
        return Err(RepairError::ReadOnlyConnection);
    }
    connection.busy_timeout(Duration::from_secs(5))?;
    Ok(connection)
}

fn harden_source(connection: &Connection) -> Result<(), RepairError> {
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "mmap_size", 0_i64)?;
    let trusted_schema: i64 =
        connection.pragma_query_value(None, "trusted_schema", |row| row.get(0))?;
    if trusted_schema != 0 {
        return Err(RepairError::PragmaNotApplied {
            pragma: "trusted_schema",
        });
    }
    let foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    if foreign_keys != 1 {
        return Err(RepairError::PragmaNotApplied {
            pragma: "foreign_keys",
        });
    }
    Ok(())
}

fn validate_connection_environment(connection: &Connection) -> Result<(), RepairError> {
    let attached: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_database_list WHERE name NOT IN ('main', 'temp')",
        [],
        |row| row.get(0),
    )?;
    if attached != 0 {
        return Err(RepairError::AttachedDatabase);
    }
    let journal_mode: String =
        connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let journal_mode = journal_mode.to_ascii_lowercase();
    if !matches!(
        journal_mode.as_str(),
        "delete" | "truncate" | "persist" | "wal"
    ) {
        return Err(RepairError::UnsafeJournalMode { mode: journal_mode });
    }
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    if synchronous == 0 {
        return Err(RepairError::UnsafeSynchronous);
    }
    Ok(())
}

fn read_data_version(connection: &Connection) -> Result<i64, RepairError> {
    connection
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(RepairError::from)
}

#[allow(clippy::too_many_arguments)]
fn prepare_commit(
    transaction: &rusqlite::Transaction<'_>,
    database_path: &Path,
    fresh_report: &ScanReport,
    request: &RepairRequest<'_>,
    platform: PlatformPolicy,
    probe: &impl ProcessProbe,
    faults: &impl FaultInjector,
    initial_data_version: i64,
    backup: &VerifiedBackup,
    web_proof: Option<&WebComparison>,
) -> Result<RepairReceipt, RepairError> {
    if read_data_version(transaction)? != initial_data_version {
        return Err(RepairError::DataVersionChanged);
    }
    let transaction_report = scan_catalog_connection(
        transaction,
        database_path,
        platform,
        request.evidence_config,
    )?;
    validate_fresh_report(
        fresh_report,
        &transaction_report,
        request.selected,
        web_proof,
    )?;

    transaction.execute_batch(
        "CREATE TEMP TABLE expected_delete (
            host_id TEXT NOT NULL,
            thread_id TEXT NOT NULL,
            PRIMARY KEY (host_id, thread_id)
         ) WITHOUT ROWID;",
    )?;
    {
        let mut insert = transaction
            .prepare("INSERT INTO expected_delete (host_id, thread_id) VALUES (?1, ?2)")?;
        for selection in request.selected {
            insert.execute(params![
                selection.identity.host_id,
                selection.identity.thread_id
            ])?;
        }
    }
    faults.hit(FaultPoint::AfterPlanLoaded, transaction)?;

    let planned = request.selected.len() as u64;
    let before_count = table_count(transaction)?;
    let joined = planned_join_count(transaction)?;
    require_count("predelete plan join", planned, joined)?;

    let deleted = transaction.execute(
        "DELETE FROM local_thread_catalog
         WHERE EXISTS (
             SELECT 1 FROM expected_delete AS expected
             WHERE local_thread_catalog.host_id COLLATE BINARY =
                   expected.host_id COLLATE BINARY
               AND local_thread_catalog.thread_id COLLATE BINARY =
                   expected.thread_id COLLATE BINARY
         )",
        [],
    )? as u64;
    let changed = transaction.changes();
    require_count("delete execute", planned, deleted)?;
    require_count("delete changes", planned, changed)?;
    faults.hit(FaultPoint::AfterDelete, transaction)?;

    let remaining = planned_join_count(transaction)?;
    require_count("remaining plan join", 0, remaining)?;
    let after_count = table_count(transaction)?;
    require_count(
        "total row delta",
        before_count.saturating_sub(planned),
        after_count,
    )?;
    run_integrity_check(transaction)?;
    run_foreign_key_check(transaction)?;
    ensure_chatgpt_stopped(probe)?;
    backup.verify_unchanged()?;

    Ok(RepairReceipt::new(
        LocalPath::try_from(database_path)?,
        LocalPath::try_from(backup.path.as_path())?,
        platform.label(),
        backup.sha256.clone(),
        request
            .selected
            .iter()
            .map(|selection| selection.identity.clone())
            .collect(),
        before_count,
        after_count,
    ))
}

fn table_count(connection: &Connection) -> Result<u64, RepairError> {
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM local_thread_catalog", [], |row| {
            row.get(0)
        })?;
    u64::try_from(count).map_err(|_| RepairError::CountMismatch {
        stage: "negative table count",
        expected: 0,
        actual: 0,
    })
}

fn planned_join_count(connection: &Connection) -> Result<u64, RepairError> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*)
         FROM local_thread_catalog AS catalog
         JOIN expected_delete AS expected
           ON catalog.host_id COLLATE BINARY = expected.host_id COLLATE BINARY
          AND catalog.thread_id COLLATE BINARY = expected.thread_id COLLATE BINARY",
        [],
        |row| row.get(0),
    )?;
    Ok(count as u64)
}

fn require_count(stage: &'static str, expected: u64, actual: u64) -> Result<(), RepairError> {
    if expected == actual {
        Ok(())
    } else {
        Err(RepairError::CountMismatch {
            stage,
            expected,
            actual,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn create_verified_backup(
    source: &Connection,
    source_report: &ScanReport,
    selected: &[RepairSelection],
    evidence_config: &EvidenceScanConfig,
    backup_directory: &Path,
    platform: PlatformPolicy,
    durability: &impl DurabilitySync,
    web_proof: Option<&WebComparison>,
) -> Result<VerifiedBackup, RepairError> {
    let directory = prepare_backup_directory(
        backup_directory,
        source_report.database_path.as_path(),
        platform,
        durability,
    )?;
    let backup_path = create_backup_file(&directory, durability)?;
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let mut destination = Connection::open_with_flags(&backup_path, flags)?;
    {
        let backup = Backup::new(source, &mut destination)?;
        let mut busy_retries = 0_usize;
        let mut complete = false;
        for _ in 0..MAX_BACKUP_STEPS {
            match backup.step(BACKUP_PAGES_PER_STEP)? {
                StepResult::Done => {
                    complete = true;
                    break;
                }
                StepResult::More => {}
                StepResult::Busy | StepResult::Locked => {
                    busy_retries += 1;
                    if busy_retries > MAX_BACKUP_BUSY_RETRIES {
                        return Err(RepairError::BackupTimeout);
                    }
                    thread::sleep(BACKUP_BUSY_PAUSE);
                }
                _ => return Err(RepairError::BackupTimeout),
            }
        }
        if !complete {
            return Err(RepairError::BackupTimeout);
        }
    }
    destination
        .close()
        .map_err(|(_, source)| RepairError::Sqlite(source))?;
    sync_completed_backup(
        &backup_path,
        &directory,
        backup_directory_policy(platform),
        durability,
    )?;

    let initial_hash = hash_file(&backup_path)?;
    let backup_report = scan_catalog(&backup_path, platform, evidence_config)?;
    if backup_report.schema != source_report.schema
        || backup_report.integrity_ok != source_report.integrity_ok
        || backup_report.threads != source_report.threads
    {
        return Err(RepairError::BackupValidationFailed);
    }
    // The verified copy has a different path. Its schema/rows must match above;
    // browser authorization remains bound to the unchanged source report.
    validate_authorizations_with_web(source_report, selected, web_proof)?;
    let backup_connection = open_read_only(&backup_path)?;
    run_foreign_key_check(&backup_connection)?;
    backup_connection
        .close()
        .map_err(|(_, source)| RepairError::Sqlite(source))?;
    if hash_file(&backup_path)? != initial_hash {
        return Err(RepairError::BackupHashChanged);
    }
    Ok(VerifiedBackup {
        path: backup_path,
        sha256: initial_hash,
    })
}

fn backup_directory_policy(platform: PlatformPolicy) -> BackupDirectoryPolicy {
    match platform {
        PlatformPolicy::Windows => BackupDirectoryPolicy::WindowsSourceParent,
        _ => BackupDirectoryPolicy::UnixPrivate,
    }
}

/// Validates already-canonical paths. Windows cannot portably prove a directory fsync, so its
/// backup must remain in the canonical source parent and inherit the source's ACL exposure scope.
fn validate_backup_directory_policy(
    policy: BackupDirectoryPolicy,
    database_path: &Path,
    backup_directory: &Path,
) -> Result<(), RepairError> {
    if policy == BackupDirectoryPolicy::WindowsSourceParent
        && database_path.parent() != Some(backup_directory)
    {
        return Err(RepairError::UnsafeBackupDirectory {
            path: backup_directory.to_path_buf(),
            reason: "Windows backups must use the canonical source database parent",
        });
    }
    Ok(())
}

fn prepare_backup_directory(
    path: &Path,
    database_path: &Path,
    platform: PlatformPolicy,
    durability: &impl DurabilitySync,
) -> Result<PathBuf, RepairError> {
    let policy = backup_directory_policy(platform);
    let mut created = false;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(RepairError::UnsafeBackupDirectory {
                    path: path.to_path_buf(),
                    reason: "path is a symlink or is not a directory",
                });
            }
        }
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && policy == BackupDirectoryPolicy::UnixPrivate =>
        {
            create_private_directory(path)?;
            created = true;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(RepairError::UnsafeBackupDirectory {
                path: path.to_path_buf(),
                reason: "Windows backup directory must already be the source database parent",
            });
        }
        Err(source) => {
            return Err(RepairError::Io {
                operation: "inspect backup directory",
                path: path.to_path_buf(),
                source,
            });
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| RepairError::Io {
        operation: "reinspect backup directory",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RepairError::UnsafeBackupDirectory {
            path: path.to_path_buf(),
            reason: "path is a symlink or is not a directory",
        });
    }
    if policy == BackupDirectoryPolicy::UnixPrivate {
        require_private_directory(path)?;
    }
    let canonical = fs::canonicalize(path).map_err(|source| RepairError::Io {
        operation: "canonicalize backup directory",
        path: path.to_path_buf(),
        source,
    })?;
    validate_backup_directory_policy(policy, database_path, &canonical)?;

    if created {
        durability
            .sync_directory(&canonical)
            .map_err(|source| RepairError::Io {
                operation: "sync new backup directory",
                path: canonical.clone(),
                source,
            })?;
        let parent = canonical
            .parent()
            .ok_or_else(|| RepairError::UnsafeBackupDirectory {
                path: canonical.clone(),
                reason: "new backup directory has no parent to synchronize",
            })?;
        durability
            .sync_directory(parent)
            .map_err(|source| RepairError::Io {
                operation: "sync new backup directory parent",
                path: parent.to_path_buf(),
                source,
            })?;
    }

    Ok(canonical)
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), RepairError> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).map_err(|source| RepairError::Io {
        operation: "create backup directory",
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<(), RepairError> {
    fs::create_dir(path).map_err(|source| RepairError::Io {
        operation: "create backup directory",
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
fn require_private_directory(path: &Path) -> Result<(), RepairError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)
        .map_err(|source| RepairError::Io {
            operation: "inspect backup directory permissions",
            path: path.to_path_buf(),
            source,
        })?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(RepairError::UnsafeBackupDirectory {
            path: path.to_path_buf(),
            reason: "Unix backup directory permissions must exclude group and other access",
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private_directory(_path: &Path) -> Result<(), RepairError> {
    Ok(())
}

fn configure_backup_open_options(options: &mut OpenOptions, create_new: bool) {
    options.read(true).write(true).create_new(create_new);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_WRITE_THROUGH;

        options.custom_flags(FILE_FLAG_WRITE_THROUGH);
    }
}

fn create_backup_file(
    directory: &Path,
    durability: &impl DurabilitySync,
) -> Result<PathBuf, RepairError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = BACKUP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = directory.join(format!(
        "ghost-chat-cleaner-{timestamp}-{}-{counter}.backup.db",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    configure_backup_open_options(&mut options, true);
    match options.open(&path) {
        Ok(file) => {
            durability
                .sync_file(&file)
                .map_err(|source| RepairError::Io {
                    operation: "sync new backup file",
                    path: path.clone(),
                    source,
                })?;
            Ok(path)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            Err(RepairError::BackupAlreadyExists)
        }
        Err(source) => Err(RepairError::Io {
            operation: "create backup file",
            path,
            source,
        }),
    }
}

fn sync_completed_backup(
    backup_path: &Path,
    directory: &Path,
    policy: BackupDirectoryPolicy,
    durability: &impl DurabilitySync,
) -> Result<(), RepairError> {
    let mut options = OpenOptions::new();
    configure_backup_open_options(&mut options, false);
    let file = options
        .open(backup_path)
        .map_err(|source| RepairError::Io {
            operation: "open completed backup for sync",
            path: backup_path.to_path_buf(),
            source,
        })?;
    durability
        .sync_file(&file)
        .map_err(|source| RepairError::Io {
            operation: "sync completed backup",
            path: backup_path.to_path_buf(),
            source,
        })?;

    if policy == BackupDirectoryPolicy::UnixPrivate {
        durability
            .sync_directory(directory)
            .map_err(|source| RepairError::Io {
                operation: "sync backup directory entry",
                path: directory.to_path_buf(),
                source,
            })?;
    } else {
        // Windows has no portable directory-fsync equivalent. This branch makes no directory
        // durability claim: same-parent policy limits ACL exposure, while the create-new
        // write-through file handle and sync_all above provide the available file guarantee.
    }
    Ok(())
}

fn open_read_only(path: &Path) -> Result<Connection, RepairError> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(RepairError::from)
}

fn hash_file(path: &Path) -> Result<String, RepairError> {
    let mut file = File::open(path).map_err(|source| RepairError::Io {
        operation: "open backup for hashing",
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|source| RepairError::Io {
            operation: "read backup for hashing",
            path: path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn run_integrity_check(connection: &Connection) -> Result<(), RepairError> {
    let mut statement = connection.prepare("PRAGMA integrity_check")?;
    let values = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() == 1 && values[0] == "ok" {
        Ok(())
    } else {
        Err(RepairError::IntegrityCheckFailed)
    }
}

fn run_foreign_key_check(connection: &Connection) -> Result<(), RepairError> {
    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    let mut rows = statement.query([])?;
    if rows.next()?.is_none() {
        Ok(())
    } else {
        Err(RepairError::ForeignKeyCheckFailed)
    }
}

fn verify_committed_state(
    database_path: &Path,
    before_report: &ScanReport,
    selected: &[RepairSelection],
    evidence_config: &EvidenceScanConfig,
    platform: PlatformPolicy,
    backup: &VerifiedBackup,
) -> Result<(), RepairError> {
    backup
        .verify_unchanged()
        .map_err(|_| RepairError::CommitOutcomeInvalid {
            backup_path: backup.path.clone(),
        })?;
    let after = scan_catalog(database_path, platform, evidence_config).map_err(|_| {
        RepairError::CommitOutcomeInvalid {
            backup_path: backup.path.clone(),
        }
    })?;
    if after.schema != before_report.schema
        || !after.integrity_ok
        || selected.iter().any(|selection| {
            after
                .threads
                .iter()
                .any(|thread| thread.identity() == &selection.identity)
        })
    {
        return Err(RepairError::CommitOutcomeInvalid {
            backup_path: backup.path.clone(),
        });
    }
    let connection =
        open_read_only(database_path).map_err(|_| RepairError::CommitOutcomeInvalid {
            backup_path: backup.path.clone(),
        })?;
    run_integrity_check(&connection).map_err(|_| RepairError::CommitOutcomeInvalid {
        backup_path: backup.path.clone(),
    })?;
    run_foreign_key_check(&connection).map_err(|_| RepairError::CommitOutcomeInvalid {
        backup_path: backup.path.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    #[cfg(unix)]
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    use rusqlite::{params, Connection};

    use crate::catalog::scan_catalog;
    use crate::evidence::EvidenceScanConfig;
    use crate::model::{
        CatalogThread, DeletionEvidence, LocalPath, ScanReport, SchemaReport, ThreadIdentity,
    };
    use crate::platform::PlatformPolicy;
    use crate::process_guard::{ProcessGuardError, ProcessPresence, ProcessProbe};

    use super::*;

    type LogicalRow = (
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        i64,
        Option<f64>,
    );

    struct PanicProbe;

    impl ProcessProbe for PanicProbe {
        fn chatgpt_presence(&self) -> ProcessPresence {
            panic!("the process probe must not run on a scan-only platform")
        }
    }

    #[derive(Clone, Copy)]
    struct FakeProbe(ProcessPresence);

    impl ProcessProbe for FakeProbe {
        fn chatgpt_presence(&self) -> ProcessPresence {
            self.0
        }
    }

    struct FailAfterDelete;

    impl FaultInjector for FailAfterDelete {
        fn hit(&self, point: FaultPoint, _connection: &Connection) -> Result<(), RepairError> {
            if point == FaultPoint::AfterDelete {
                Err(RepairError::FaultInjected { point })
            } else {
                Ok(())
            }
        }
    }

    struct AbortTransactionThenFail;

    impl FaultInjector for AbortTransactionThenFail {
        fn hit(&self, point: FaultPoint, connection: &Connection) -> Result<(), RepairError> {
            if point == FaultPoint::AfterDelete {
                connection.execute_batch("ROLLBACK")?;
                return Err(RepairError::FaultInjected { point });
            }
            Ok(())
        }
    }

    #[cfg(unix)]
    struct FailDirectorySync;

    #[cfg(unix)]
    impl DurabilitySync for FailDirectorySync {
        fn sync_file(&self, file: &File) -> io::Result<()> {
            file.sync_all()
        }

        fn sync_directory(&self, _path: &Path) -> io::Result<()> {
            Err(io::Error::other("injected directory sync failure"))
        }
    }

    #[cfg(unix)]
    #[derive(Default)]
    struct RecordingSync {
        directories: RefCell<Vec<PathBuf>>,
    }

    #[cfg(unix)]
    impl DurabilitySync for RecordingSync {
        fn sync_file(&self, file: &File) -> io::Result<()> {
            file.sync_all()
        }

        fn sync_directory(&self, path: &Path) -> io::Result<()> {
            self.directories.borrow_mut().push(path.to_path_buf());
            Ok(())
        }
    }

    struct RemoveTargetAfterPlan;

    impl FaultInjector for RemoveTargetAfterPlan {
        fn hit(&self, point: FaultPoint, connection: &Connection) -> Result<(), RepairError> {
            if point == FaultPoint::AfterPlanLoaded {
                connection.execute(
                    "DELETE FROM local_thread_catalog
                     WHERE host_id = 'host-a' AND thread_id = 'thread-a'",
                    [],
                )?;
            }
            Ok(())
        }
    }

    struct SequencedProbe {
        calls: Cell<usize>,
        states: Vec<ProcessPresence>,
    }

    impl SequencedProbe {
        fn new(states: Vec<ProcessPresence>) -> Self {
            Self {
                calls: Cell::new(0),
                states,
            }
        }
    }

    impl ProcessProbe for SequencedProbe {
        fn chatgpt_presence(&self) -> ProcessPresence {
            let index = self.calls.get();
            self.calls.set(index + 1);
            self.states
                .get(index)
                .copied()
                .unwrap_or(ProcessPresence::Unknown)
        }
    }

    fn local_path(path: &Path) -> LocalPath {
        LocalPath::try_from(path).expect("synthetic test path is UTF-8")
    }

    fn mutation_test_platform() -> PlatformPolicy {
        if cfg!(windows) {
            PlatformPolicy::Windows
        } else {
            // Linux still exercises the mutation algorithm on isolated fixtures;
            // its public entry point is separately checked to remain scan-only.
            PlatformPolicy::MacOs
        }
    }

    fn mutation_test_backup_directory(database: &Path) -> PathBuf {
        let parent = database.parent().expect("synthetic catalog has a parent");
        if cfg!(windows) {
            parent.to_path_buf()
        } else {
            parent.join("backups")
        }
    }

    fn backup_artifacts(directory: &Path) -> Vec<PathBuf> {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
            Err(error) => panic!("inspect synthetic backup directory: {error}"),
        };
        entries
            .map(|entry| entry.expect("read synthetic backup entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".backup.db"))
            })
            .collect()
    }

    fn assert_no_mutation_test_backup(directory: &Path) {
        assert!(backup_artifacts(directory).is_empty());
        #[cfg(unix)]
        assert!(!directory.exists());
    }

    fn synthetic_report(path: &Path) -> ScanReport {
        ScanReport::new(
            local_path(path),
            "linux",
            SchemaReport {
                write_capable: true,
                reason: "synthetic report".to_owned(),
                fingerprint: "synthetic".to_owned(),
                columns: Vec::new(),
            },
            Vec::new(),
            true,
        )
    }

    fn report_with_threads(path: &Path, threads: Vec<CatalogThread>) -> ScanReport {
        ScanReport::new(
            local_path(path),
            "macos",
            SchemaReport {
                write_capable: true,
                reason: "supported structural profile and platform policy".to_owned(),
                fingerprint: "synthetic".to_owned(),
                columns: Vec::new(),
            },
            threads,
            true,
        )
    }

    fn confirmed(identity: ThreadIdentity) -> CatalogThread {
        CatalogThread::confirmed_deleted(
            identity,
            "private title",
            "chatgpt",
            true,
            None,
            None,
            DeletionEvidence {
                source_path: local_path(Path::new("/synthetic/evidence.json")),
                reason: "synthetic evidence".to_owned(),
            },
        )
        .expect("construct confirmed synthetic row")
    }

    #[test]
    fn stale_comparison_is_rejected_at_the_repair_boundary() {
        let host = "chatgpt:11111111-1111-4111-8111-111111111111:user-fixture";
        let control = ThreadIdentity::new(host, "22222222-2222-4222-8222-222222222222");
        let missing = ThreadIdentity::new(host, "33333333-3333-4333-8333-333333333333");
        let report = report_with_threads(
            Path::new("/synthetic/catalog.db"),
            vec![review(control.clone()), review(missing.clone())],
        );
        let proof = WebComparison::from_value(&report, serde_json::json!({
            "schema_version": 3, "kind": "requested_metadata_checks", "user_id": "user-fixture",
            "account_id": "44444444-4444-4444-8444-444444444444",
            "account_user_id": "user-fixture", "account_structure": "personal", "complete": true,
            "checks": [
                {"id": control.thread_id, "evidence": "authenticated_list_item"},
                {"id": missing.thread_id, "evidence": "authenticated_json_get_404"}
            ],
            "controls": [control.thread_id]
        })).unwrap();
        let selected = [RepairSelection::new(missing, true)];
        assert!(require_web_comparison(&report, &selected, &proof, proof.observed_at()).is_ok());
        assert!(matches!(
            require_web_comparison(
                &report,
                &selected,
                &proof,
                proof.observed_at() + crate::web::WEB_COMPARISON_TTL
            ),
            Err(RepairError::WebComparisonRequired)
        ));
    }

    fn review(identity: ThreadIdentity) -> CatalogThread {
        CatalogThread::review_required(identity, "private title", "chatgpt", true, None, None)
            .expect("construct review synthetic row")
    }

    fn create_supported_catalog(path: &Path, rows: &[(&str, &str, &str)]) {
        let connection = Connection::open(path).expect("create synthetic catalog");
        connection
            .execute_batch(
                "CREATE TABLE local_thread_catalog (
                    host_id TEXT NOT NULL,
                    thread_id TEXT NOT NULL,
                    display_title TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    project_id TEXT,
                    cwd TEXT,
                    missing_candidate INTEGER NOT NULL DEFAULT 0,
                    source_recency_at REAL,
                    PRIMARY KEY (host_id, thread_id)
                ) WITHOUT ROWID;",
            )
            .expect("create supported synthetic schema");
        for (host_id, thread_id, title) in rows {
            connection
                .execute(
                    "INSERT INTO local_thread_catalog (
                        host_id, thread_id, display_title, source_kind,
                        project_id, cwd, missing_candidate, source_recency_at
                     ) VALUES (?1, ?2, ?3, 'chatgpt', NULL, NULL, 1, 1.0)",
                    params![host_id, thread_id, title],
                )
                .expect("insert synthetic catalog row");
        }
    }

    fn row_exists(path: &Path, identity: &ThreadIdentity) -> bool {
        Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open synthetic catalog read-only")
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM local_thread_catalog
                    WHERE host_id = ?1 AND thread_id = ?2
                 )",
                params![identity.host_id, identity.thread_id],
                |row| row.get(0),
            )
            .expect("query synthetic row")
    }

    fn logical_rows(path: &Path) -> Vec<LogicalRow> {
        let connection =
            Connection::open(path).expect("open synthetic catalog for logical snapshot");
        let mut statement = connection
            .prepare(
                "SELECT host_id, thread_id, display_title, source_kind,
                        project_id, cwd, missing_candidate, source_recency_at
                 FROM local_thread_catalog ORDER BY host_id, thread_id",
            )
            .expect("prepare logical snapshot");
        statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })
            .expect("query logical snapshot")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect logical snapshot")
    }

    #[test]
    fn linux_is_denied_before_source_backup_or_process_access() {
        let directory = tempfile::tempdir().expect("create synthetic root");
        let source = directory.path().join("missing.db");
        let backup = directory.path().join("not-created");
        let report = synthetic_report(&source);
        let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
        let selected = [RepairSelection::new(
            ThreadIdentity::new("host-a", "thread-a"),
            false,
        )];

        let error = execute_repair_with(
            RepairRequest {
                scan_report: &report,
                evidence_config: &evidence,
                selected: &selected,
                backup_directory: &backup,
            },
            PlatformPolicy::Linux,
            &PanicProbe,
            &NoFaultInjector,
        )
        .expect_err("Linux must remain scan-only");

        assert!(matches!(error, RepairError::PlatformReadOnly { .. }));
        assert!(!source.exists());
        assert!(!backup.exists());
    }

    #[test]
    fn repair_plan_rejects_empty_duplicate_and_oversized_inputs() {
        assert!(matches!(
            validate_plan_shape(&[]),
            Err(RepairError::EmptyPlan)
        ));

        let duplicate = [
            RepairSelection::new(ThreadIdentity::new("host-a", "thread-a"), false),
            RepairSelection::new(ThreadIdentity::new("host-a", "thread-a"), true),
        ];
        assert!(matches!(
            validate_plan_shape(&duplicate),
            Err(RepairError::DuplicateTarget { .. })
        ));

        let oversized = (0..=MAX_REPAIR_TARGETS)
            .map(|index| {
                RepairSelection::new(
                    ThreadIdentity::new("host-a", format!("thread-{index}")),
                    false,
                )
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            validate_plan_shape(&oversized),
            Err(RepairError::PlanTooLarge { limit: 10_000 })
        ));
    }

    #[test]
    fn windows_backup_policy_accepts_only_the_canonical_source_parent() {
        let database = Path::new("/private/catalog.db");

        validate_backup_directory_policy(
            BackupDirectoryPolicy::WindowsSourceParent,
            database,
            Path::new("/private"),
        )
        .expect("the source parent keeps Windows ACL inheritance in one exposure scope");

        assert!(matches!(
            validate_backup_directory_policy(
                BackupDirectoryPolicy::WindowsSourceParent,
                database,
                Path::new("/elsewhere")
            ),
            Err(RepairError::UnsafeBackupDirectory { .. })
        ));
    }

    #[test]
    fn windows_repair_rejects_other_backup_directories_without_mutation() {
        for existing in [false, true] {
            let directory = tempfile::tempdir().expect("create Windows backup-policy fixture");
            let database = directory.path().join("catalog.db");
            let backup_directory = directory.path().join("elsewhere");
            create_supported_catalog(&database, &[("host-a", "thread-a", "private title")]);
            if existing {
                fs::create_dir(&backup_directory).expect("create a different backup directory");
            }
            let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
            let report = scan_catalog(&database, PlatformPolicy::Windows, &evidence)
                .expect("scan Windows backup-policy fixture");
            let selected = [RepairSelection::new(
                ThreadIdentity::new("host-a", "thread-a"),
                true,
            )];
            let before = logical_rows(&database);

            let error = execute_repair_with(
                RepairRequest {
                    scan_report: &report,
                    evidence_config: &evidence,
                    selected: &selected,
                    backup_directory: &backup_directory,
                },
                PlatformPolicy::Windows,
                &FakeProbe(ProcessPresence::Stopped),
                &NoFaultInjector,
            )
            .expect_err("Windows backup must stay in the source database parent");

            assert!(matches!(error, RepairError::UnsafeBackupDirectory { .. }));
            assert_eq!(logical_rows(&database), before);
            assert_eq!(backup_directory.exists(), existing);
            assert!(backup_artifacts(&backup_directory).is_empty());
            assert!(backup_artifacts(directory.path()).is_empty());
        }
    }

    #[test]
    fn unix_backup_policy_allows_a_separate_private_directory() {
        validate_backup_directory_policy(
            BackupDirectoryPolicy::UnixPrivate,
            Path::new("/source/catalog.db"),
            Path::new("/private-backups"),
        )
        .expect("Unix privacy is enforced by directory type and mode");
    }

    #[cfg(unix)]
    #[test]
    fn creating_a_backup_directory_syncs_it_and_its_parent() {
        let root = tempfile::tempdir().expect("create directory-sync fixture");
        let database = root.path().join("catalog.db");
        let backup_directory = root.path().join("backups");
        let sync = RecordingSync::default();

        let canonical =
            prepare_backup_directory(&backup_directory, &database, PlatformPolicy::MacOs, &sync)
                .expect("prepare private backup directory");
        let canonical_parent = canonical
            .parent()
            .expect("canonical backup directory has a parent")
            .to_path_buf();

        assert_eq!(
            sync.directories.into_inner(),
            vec![canonical, canonical_parent]
        );
    }

    #[test]
    fn confirmed_and_explicitly_reviewed_rows_are_authorized_per_identity() {
        let path = Path::new("/synthetic/catalog.db");
        let confirmed_id = ThreadIdentity::new("host-a", "thread-confirmed");
        let review_id = ThreadIdentity::new("host-a", "thread-review");
        let report = report_with_threads(
            path,
            vec![confirmed(confirmed_id.clone()), review(review_id.clone())],
        );

        validate_authorizations(
            &report,
            &[
                RepairSelection::new(confirmed_id, false),
                RepairSelection::new(review_id.clone(), true),
            ],
        )
        .expect("confirmed and explicitly reviewed rows are authorized");

        assert!(matches!(
            validate_authorizations(&report, &[RepairSelection::new(review_id, false)],),
            Err(RepairError::ReviewAuthorizationRequired { index: 0 })
        ));
    }

    #[test]
    fn preserved_project_rows_are_never_authorized() {
        let identity = ThreadIdentity::new("host-a", "thread-project");
        let report = report_with_threads(
            Path::new("/synthetic/catalog.db"),
            vec![CatalogThread::preserved(
                identity.clone(),
                "private project title",
                "chatgpt",
                true,
                Some("project-a".to_owned()),
                None,
            )],
        );

        assert!(matches!(
            validate_authorizations(&report, &[RepairSelection::new(identity, true)],),
            Err(RepairError::ThreadNotEligible { index: 0 })
        ));
    }

    #[test]
    fn stopped_repair_deletes_only_the_exact_composite_identity_after_backup() {
        let directory = tempfile::tempdir().expect("create synthetic repair root");
        let database = directory.path().join("catalog.db");
        let backup_directory = mutation_test_backup_directory(&database);
        create_supported_catalog(
            &database,
            &[
                ("host-a", "shared-thread", "private target title"),
                ("host-b", "shared-thread", "private preserved title"),
            ],
        );
        let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
        let report = scan_catalog(&database, mutation_test_platform(), &evidence)
            .expect("scan synthetic source");
        let target = ThreadIdentity::new("host-a", "shared-thread");
        let preserved = ThreadIdentity::new("host-b", "shared-thread");
        let selected = [RepairSelection::new(target.clone(), true)];

        let receipt = execute_repair_with(
            RepairRequest {
                scan_report: &report,
                evidence_config: &evidence,
                selected: &selected,
                backup_directory: &backup_directory,
            },
            mutation_test_platform(),
            &FakeProbe(ProcessPresence::Stopped),
            &NoFaultInjector,
        )
        .expect("repair exact synthetic identity");

        assert!(!row_exists(&database, &target));
        assert!(row_exists(&database, &preserved));
        assert_eq!(receipt.removed_identities, vec![target]);
        assert_eq!((receipt.before_count, receipt.after_count), (2, 1));
        assert!(receipt.backup_path.as_path().is_file());
        assert_eq!(receipt.backup_hash.len(), 64);
        assert_eq!(
            receipt.backup_hash,
            hash_file(receipt.backup_path.as_path()).expect("rehash receipt backup")
        );

        #[cfg(windows)]
        assert_eq!(
            receipt.backup_path.as_path().parent(),
            fs::canonicalize(&database)
                .expect("canonicalize synthetic source")
                .parent()
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let directory_mode = fs::metadata(&backup_directory)
                .expect("inspect backup directory mode")
                .permissions()
                .mode();
            let file_mode = fs::metadata(receipt.backup_path.as_path())
                .expect("inspect backup file mode")
                .permissions()
                .mode();
            assert_eq!(directory_mode & 0o077, 0);
            assert_eq!(file_mode & 0o077, 0);
        }

        let backup = Connection::open_with_flags(
            receipt.backup_path.as_path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open verified backup");
        let integrity: String = backup
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .expect("check backup integrity");
        assert_eq!(integrity, "ok");
        assert!(backup
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM local_thread_catalog
                    WHERE host_id = 'host-a' AND thread_id = 'shared-thread'
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )
            .expect("backup retains target row"));
    }

    #[test]
    fn web_review_authorizes_plain_preserved_rows_without_local_missing_flag() {
        for reviewed in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let database = directory.path().join("catalog.db");
            let backup = mutation_test_backup_directory(&database);
            let host = "chatgpt:11111111-1111-4111-8111-111111111111:user-fixture";
            let control = "22222222-2222-4222-8222-222222222222";
            let missing = "33333333-3333-4333-8333-333333333333";
            create_supported_catalog(
                &database,
                &[(host, control, "control"), (host, missing, "target")],
            );
            Connection::open(&database)
                .unwrap()
                .execute("UPDATE local_thread_catalog SET missing_candidate=0", [])
                .unwrap();
            let evidence = EvidenceScanConfig::new(vec![], vec![]);
            let report = scan_catalog(&database, mutation_test_platform(), &evidence).unwrap();
            assert!(report.threads.iter().all(|thread| thread.classification()
                == Classification::Preserved
                && !thread.missing_candidate()));
            let proof = WebComparison::from_value(&report, serde_json::json!({
                "schema_version": 3, "kind": "requested_metadata_checks", "user_id": "user-fixture",
                "account_id": "44444444-4444-4444-8444-444444444444",
                "account_user_id": "user-fixture", "account_structure": "personal", "complete": true,
                "checks": [
                    {"id": control, "evidence": "authenticated_list_item"},
                    {"id": missing, "evidence": "authenticated_json_get_404"}
                ],
                "controls": [control]
            })).unwrap();
            let selected = [RepairSelection::new(
                ThreadIdentity::new(host, missing),
                reviewed,
            )];
            let request = || RepairRequest {
                scan_report: &report,
                evidence_config: &evidence,
                selected: &selected,
                backup_directory: &backup,
            };
            assert!(matches!(
                execute_repair_with(
                    request(),
                    mutation_test_platform(),
                    &PanicProbe,
                    &NoFaultInjector
                ),
                Err(RepairError::ThreadNotEligible { .. })
            ));
            assert_no_mutation_test_backup(&backup);
            let result = execute_repair_guarded(
                request(),
                mutation_test_platform(),
                &FakeProbe(ProcessPresence::Stopped),
                &NoFaultInjector,
                &OsDurabilitySync,
                &|| require_web_comparison(&report, &selected, &proof, Instant::now()),
                Some(&proof),
            );
            if reviewed {
                let receipt = result.expect("reviewed plain row with browser proof is repairable");
                assert!(!row_exists(&database, &selected[0].identity));
                assert!(row_exists(&database, &ThreadIdentity::new(host, control)));
                assert!(receipt.backup_path.as_path().is_file());
                assert_eq!((receipt.before_count, receipt.after_count), (2, 1));
            } else {
                assert!(matches!(
                    result,
                    Err(RepairError::ReviewAuthorizationRequired { index: 0 })
                ));
                assert_no_mutation_test_backup(&backup);
                assert!(row_exists(&database, &selected[0].identity));
            }
            assert!(report
                .threads
                .iter()
                .all(|thread| thread.classification() == Classification::Preserved));
        }
    }

    #[test]
    fn running_or_unknown_process_denies_repair_without_creating_backup() {
        for presence in [ProcessPresence::Running, ProcessPresence::Unknown] {
            let directory = tempfile::tempdir().expect("create process-guard fixture");
            let database = directory.path().join("catalog.db");
            let backup_directory = mutation_test_backup_directory(&database);
            create_supported_catalog(&database, &[("host-a", "thread-a", "private title")]);
            let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
            let report = scan_catalog(&database, mutation_test_platform(), &evidence)
                .expect("scan process-guard fixture");
            let identity = ThreadIdentity::new("host-a", "thread-a");
            let selected = [RepairSelection::new(identity.clone(), true)];

            let error = execute_repair_with(
                RepairRequest {
                    scan_report: &report,
                    evidence_config: &evidence,
                    selected: &selected,
                    backup_directory: &backup_directory,
                },
                mutation_test_platform(),
                &FakeProbe(presence),
                &NoFaultInjector,
            )
            .expect_err("non-stopped process state must deny repair");

            assert!(matches!(
                (presence, error),
                (
                    ProcessPresence::Running,
                    RepairError::Process(ProcessGuardError::Running)
                ) | (
                    ProcessPresence::Unknown,
                    RepairError::Process(ProcessGuardError::Unknown)
                )
            ));
            assert!(row_exists(&database, &identity));
            assert_no_mutation_test_backup(&backup_directory);
        }
    }

    #[test]
    fn stale_schema_or_classification_is_rejected_before_backup() {
        for change in ["schema", "classification"] {
            let directory = tempfile::tempdir().expect("create stale fixture");
            let database = directory.path().join("catalog.db");
            let backup_directory = mutation_test_backup_directory(&database);
            create_supported_catalog(&database, &[("host-a", "thread-a", "private title")]);
            let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
            let report = scan_catalog(&database, mutation_test_platform(), &evidence)
                .expect("scan stale fixture");
            let connection = Connection::open(&database).expect("open stale fixture writer");
            if change == "schema" {
                connection
                    .execute_batch("ALTER TABLE local_thread_catalog ADD COLUMN drift TEXT;")
                    .expect("drift schema");
            } else {
                connection
                    .execute(
                        "UPDATE local_thread_catalog SET project_id = 'project-a'
                         WHERE host_id = 'host-a' AND thread_id = 'thread-a'",
                        [],
                    )
                    .expect("drift classification");
            }
            drop(connection);
            let selected = [RepairSelection::new(
                ThreadIdentity::new("host-a", "thread-a"),
                true,
            )];

            let error = execute_repair_with(
                RepairRequest {
                    scan_report: &report,
                    evidence_config: &evidence,
                    selected: &selected,
                    backup_directory: &backup_directory,
                },
                mutation_test_platform(),
                &FakeProbe(ProcessPresence::Stopped),
                &NoFaultInjector,
            )
            .expect_err("stale report must be rejected");

            assert!(matches!(error, RepairError::StaleScanReport));
            assert_no_mutation_test_backup(&backup_directory);
        }
    }

    #[test]
    fn trigger_and_foreign_key_schema_changes_fail_closed() {
        for change in ["trigger", "foreign-key"] {
            let directory = tempfile::tempdir().expect("create unsafe-schema fixture");
            let database = directory.path().join("catalog.db");
            let backup_directory = mutation_test_backup_directory(&database);
            create_supported_catalog(&database, &[("host-a", "thread-a", "private title")]);
            let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
            let report = scan_catalog(&database, mutation_test_platform(), &evidence)
                .expect("scan safe schema");
            let connection = Connection::open(&database).expect("open schema mutator");
            if change == "trigger" {
                connection
                    .execute_batch(
                        "CREATE TRIGGER unsafe_delete AFTER DELETE ON local_thread_catalog
                         BEGIN SELECT 1; END;",
                    )
                    .expect("add target trigger");
            } else {
                connection
                    .execute_batch(
                        "CREATE TABLE inbound_reference (
                            host_id TEXT NOT NULL,
                            thread_id TEXT NOT NULL,
                            FOREIGN KEY (host_id, thread_id)
                                REFERENCES local_thread_catalog(host_id, thread_id)
                         );",
                    )
                    .expect("add inbound foreign key");
            }
            drop(connection);
            let selected = [RepairSelection::new(
                ThreadIdentity::new("host-a", "thread-a"),
                true,
            )];

            let error = execute_repair_with(
                RepairRequest {
                    scan_report: &report,
                    evidence_config: &evidence,
                    selected: &selected,
                    backup_directory: &backup_directory,
                },
                mutation_test_platform(),
                &FakeProbe(ProcessPresence::Stopped),
                &NoFaultInjector,
            )
            .expect_err("trigger/FK drift must fail closed");

            assert!(matches!(error, RepairError::StaleScanReport));
            assert_no_mutation_test_backup(&backup_directory);
        }
    }

    #[test]
    fn unsafe_journal_modes_are_rejected() {
        for mode in ["OFF", "MEMORY"] {
            let connection = Connection::open_in_memory().expect("create journal fixture");
            connection
                .pragma_update(None, "journal_mode", mode)
                .expect("set unsafe journal mode");
            assert!(matches!(
                validate_connection_environment(&connection),
                Err(RepairError::UnsafeJournalMode { .. })
            ));
        }
    }

    #[test]
    fn after_delete_fault_rolls_back_the_complete_transaction() {
        let directory = tempfile::tempdir().expect("create rollback fixture");
        let database = directory.path().join("catalog.db");
        let backup_directory = mutation_test_backup_directory(&database);
        create_supported_catalog(&database, &[("host-a", "thread-a", "private title")]);
        let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
        let report = scan_catalog(&database, mutation_test_platform(), &evidence)
            .expect("scan rollback fixture");
        let identity = ThreadIdentity::new("host-a", "thread-a");
        let selected = [RepairSelection::new(identity.clone(), true)];
        let before = logical_rows(&database);

        let error = execute_repair_with(
            RepairRequest {
                scan_report: &report,
                evidence_config: &evidence,
                selected: &selected,
                backup_directory: &backup_directory,
            },
            mutation_test_platform(),
            &FakeProbe(ProcessPresence::Stopped),
            &FailAfterDelete,
        )
        .expect_err("AfterDelete fault must abort repair");

        assert!(matches!(
            error,
            RepairError::FaultInjected {
                point: FaultPoint::AfterDelete
            }
        ));
        assert!(row_exists(&database, &identity));
        assert_eq!(logical_rows(&database), before);
        assert_eq!(backup_artifacts(&backup_directory).len(), 1);
    }

    #[test]
    fn rollback_failure_preserves_backup_original_and_sqlite_errors() {
        let directory = tempfile::tempdir().expect("create rollback-failure fixture");
        let database = directory.path().join("catalog.db");
        let backup_directory = mutation_test_backup_directory(&database);
        create_supported_catalog(&database, &[("host-a", "thread-a", "private title")]);
        let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
        let report = scan_catalog(&database, mutation_test_platform(), &evidence)
            .expect("scan rollback-failure fixture");
        let identity = ThreadIdentity::new("host-a", "thread-a");
        let selected = [RepairSelection::new(identity.clone(), true)];

        let error = execute_repair_with(
            RepairRequest {
                scan_report: &report,
                evidence_config: &evidence,
                selected: &selected,
                backup_directory: &backup_directory,
            },
            mutation_test_platform(),
            &FakeProbe(ProcessPresence::Stopped),
            &AbortTransactionThenFail,
        )
        .expect_err("a second rollback must surface both failures");
        let rendered = error.to_string();

        match &error {
            RepairError::RollbackFailed {
                backup_path,
                original,
                rollback,
            } => {
                assert!(backup_path.is_file());
                assert!(matches!(
                    original.as_ref(),
                    RepairError::FaultInjected {
                        point: FaultPoint::AfterDelete
                    }
                ));
                assert!(!rollback.to_string().is_empty());
            }
            other => panic!("expected RollbackFailed, got {other:?}"),
        }
        assert!(rendered.contains("AfterDelete"));
        assert!(rendered.contains("backup"));
        assert!(row_exists(&database, &identity));
    }

    #[cfg(unix)]
    #[test]
    fn backup_directory_sync_failure_prevents_source_mutation() {
        let directory = tempfile::tempdir().expect("create durability fixture");
        let database = directory.path().join("catalog.db");
        let backup_directory = directory.path().join("backups");
        create_private_directory(&backup_directory).expect("create existing private backup dir");
        create_supported_catalog(&database, &[("host-a", "thread-a", "private title")]);
        let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
        let report = scan_catalog(&database, PlatformPolicy::MacOs, &evidence)
            .expect("scan durability fixture");
        let identity = ThreadIdentity::new("host-a", "thread-a");
        let selected = [RepairSelection::new(identity.clone(), true)];

        let error = execute_repair_with_sync(
            RepairRequest {
                scan_report: &report,
                evidence_config: &evidence,
                selected: &selected,
                backup_directory: &backup_directory,
            },
            PlatformPolicy::MacOs,
            &FakeProbe(ProcessPresence::Stopped),
            &NoFaultInjector,
            &FailDirectorySync,
        )
        .expect_err("directory sync failure must abort before deletion");

        assert!(matches!(
            error,
            RepairError::Io {
                operation: "sync backup directory entry",
                ..
            }
        ));
        assert!(row_exists(&database, &identity));
    }

    #[test]
    fn count_mismatch_rolls_back_fault_injected_row_change() {
        let directory = tempfile::tempdir().expect("create count fixture");
        let database = directory.path().join("catalog.db");
        let backup_directory = mutation_test_backup_directory(&database);
        create_supported_catalog(&database, &[("host-a", "thread-a", "private title")]);
        let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
        let report = scan_catalog(&database, mutation_test_platform(), &evidence)
            .expect("scan count fixture");
        let identity = ThreadIdentity::new("host-a", "thread-a");
        let selected = [RepairSelection::new(identity.clone(), true)];

        let error = execute_repair_with(
            RepairRequest {
                scan_report: &report,
                evidence_config: &evidence,
                selected: &selected,
                backup_directory: &backup_directory,
            },
            mutation_test_platform(),
            &FakeProbe(ProcessPresence::Stopped),
            &RemoveTargetAfterPlan,
        )
        .expect_err("fault-injected count mismatch must abort repair");

        assert!(matches!(
            error,
            RepairError::CountMismatch {
                stage: "predelete plan join",
                expected: 1,
                actual: 0
            }
        ));
        assert!(row_exists(&database, &identity));
    }

    #[test]
    fn receipt_serialization_excludes_titles_cwd_and_messages() {
        let directory = tempfile::tempdir().expect("create receipt fixture");
        let database = directory.path().join("catalog.db");
        let backup_directory = mutation_test_backup_directory(&database);
        create_supported_catalog(&database, &[("host-a", "thread-a", "very private title")]);
        let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
        let report = scan_catalog(&database, mutation_test_platform(), &evidence)
            .expect("scan receipt fixture");
        let selected = [RepairSelection::new(
            ThreadIdentity::new("host-a", "thread-a"),
            true,
        )];

        let receipt = execute_repair_with(
            RepairRequest {
                scan_report: &report,
                evidence_config: &evidence,
                selected: &selected,
                backup_directory: &backup_directory,
            },
            mutation_test_platform(),
            &FakeProbe(ProcessPresence::Stopped),
            &NoFaultInjector,
        )
        .expect("create receipt fixture");
        let json = serde_json::to_string(&receipt).expect("serialize receipt");

        assert!(!json.contains("very private title"));
        assert!(!json.contains("display_title"));
        assert!(!json.contains("cwd"));
        assert!(!json.contains("message"));
    }

    #[test]
    fn invalid_scan_integrity_or_write_capability_is_rejected_before_probe() {
        let path = Path::new("/synthetic/not-accessed.db");
        for (integrity_ok, write_capable, expected_check) in
            [(false, true, "integrity"), (true, false, "write_capable")]
        {
            let mut report = synthetic_report(path);
            report.integrity_ok = integrity_ok;
            report.schema.write_capable = write_capable;
            report.platform_label = "macos".to_owned();
            let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
            let selected = [RepairSelection::new(
                ThreadIdentity::new("host-a", "thread-a"),
                false,
            )];

            assert!(matches!(
                execute_repair_with(
                    RepairRequest {
                        scan_report: &report,
                        evidence_config: &evidence,
                        selected: &selected,
                        backup_directory: Path::new("/synthetic/not-created"),
                    },
                    PlatformPolicy::MacOs,
                    &PanicProbe,
                    &NoFaultInjector,
                ),
                Err(RepairError::InvalidScanReport { check }) if check == expected_check
            ));
        }
    }

    #[test]
    fn process_appearing_after_backup_aborts_before_transaction() {
        let directory = tempfile::tempdir().expect("create process-race fixture");
        let database = directory.path().join("catalog.db");
        let backup_directory = mutation_test_backup_directory(&database);
        create_supported_catalog(&database, &[("host-a", "thread-a", "private title")]);
        let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
        let report = scan_catalog(&database, mutation_test_platform(), &evidence)
            .expect("scan process-race fixture");
        let identity = ThreadIdentity::new("host-a", "thread-a");
        let selected = [RepairSelection::new(identity.clone(), true)];
        let probe = SequencedProbe::new(vec![ProcessPresence::Stopped, ProcessPresence::Running]);

        let error = execute_repair_with(
            RepairRequest {
                scan_report: &report,
                evidence_config: &evidence,
                selected: &selected,
                backup_directory: &backup_directory,
            },
            mutation_test_platform(),
            &probe,
            &NoFaultInjector,
        )
        .expect_err("process race must abort repair");

        assert!(matches!(
            error,
            RepairError::Process(ProcessGuardError::Running)
        ));
        assert_eq!(probe.calls.get(), 2);
        assert!(row_exists(&database, &identity));
        assert_eq!(backup_artifacts(&backup_directory).len(), 1);
    }

    #[test]
    fn process_appearing_before_commit_rolls_back_the_delete() {
        let directory = tempfile::tempdir().expect("create precommit-process fixture");
        let database = directory.path().join("catalog.db");
        let backup_directory = mutation_test_backup_directory(&database);
        create_supported_catalog(&database, &[("host-a", "thread-a", "private title")]);
        let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
        let report = scan_catalog(&database, mutation_test_platform(), &evidence)
            .expect("scan precommit-process fixture");
        let identity = ThreadIdentity::new("host-a", "thread-a");
        let selected = [RepairSelection::new(identity.clone(), true)];
        let probe = SequencedProbe::new(vec![
            ProcessPresence::Stopped,
            ProcessPresence::Stopped,
            ProcessPresence::Running,
        ]);

        let error = execute_repair_with(
            RepairRequest {
                scan_report: &report,
                evidence_config: &evidence,
                selected: &selected,
                backup_directory: &backup_directory,
            },
            mutation_test_platform(),
            &probe,
            &NoFaultInjector,
        )
        .expect_err("precommit process race must roll back");

        assert!(matches!(
            error,
            RepairError::Process(ProcessGuardError::Running)
        ));
        assert_eq!(probe.calls.get(), 3);
        assert!(row_exists(&database, &identity));
        assert_eq!(backup_artifacts(&backup_directory).len(), 1);
    }

    #[test]
    fn attached_database_and_synchronous_off_are_rejected() {
        let attached = Connection::open_in_memory().expect("create attached-db fixture");
        attached
            .execute_batch("ATTACH DATABASE ':memory:' AS unexpected;")
            .expect("attach synthetic database");
        assert!(matches!(
            validate_connection_environment(&attached),
            Err(RepairError::AttachedDatabase)
        ));

        let directory = tempfile::tempdir().expect("create sync fixture root");
        let synchronous_off =
            Connection::open(directory.path().join("sync.db")).expect("create sync fixture");
        synchronous_off
            .pragma_update(None, "synchronous", "OFF")
            .expect("disable synchronous for fixture");
        assert!(matches!(
            validate_connection_environment(&synchronous_off),
            Err(RepairError::UnsafeSynchronous)
        ));
    }

    #[test]
    fn read_write_source_open_never_creates_a_missing_database() {
        let directory = tempfile::tempdir().expect("create missing-source root");
        let path = directory.path().join("missing.db");

        assert!(open_source(&path).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn verified_backup_seal_rejects_content_changed_after_validation() {
        let directory = tempfile::tempdir().expect("create backup-seal fixture");
        let path = directory.path().join("backup.db");
        fs::write(&path, b"validated backup bytes").expect("write validated fixture");
        let backup = VerifiedBackup {
            path: path.clone(),
            sha256: hash_file(&path).expect("hash validated fixture"),
        };

        fs::write(&path, b"changed backup bytes").expect("replace validated fixture bytes");

        assert!(matches!(
            backup.verify_unchanged(),
            Err(RepairError::BackupHashChanged)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_backup_directory_is_rejected_without_source_mutation() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("create symlink fixture");
        let database = directory.path().join("catalog.db");
        let real_backup = directory.path().join("real-backup");
        fs::create_dir(&real_backup).expect("create real backup directory");
        let backup_link = directory.path().join("backup-link");
        symlink(&real_backup, &backup_link).expect("create backup symlink");
        create_supported_catalog(&database, &[("host-a", "thread-a", "private title")]);
        let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());
        let report = scan_catalog(&database, PlatformPolicy::MacOs, &evidence)
            .expect("scan symlink fixture");
        let identity = ThreadIdentity::new("host-a", "thread-a");
        let selected = [RepairSelection::new(identity.clone(), true)];

        assert!(matches!(
            execute_repair_with(
                RepairRequest {
                    scan_report: &report,
                    evidence_config: &evidence,
                    selected: &selected,
                    backup_directory: &backup_link,
                },
                PlatformPolicy::MacOs,
                &FakeProbe(ProcessPresence::Stopped),
                &NoFaultInjector,
            ),
            Err(RepairError::UnsafeBackupDirectory { .. })
        ));
        assert!(row_exists(&database, &identity));
        assert_eq!(
            fs::read_dir(&real_backup)
                .expect("inspect real backup")
                .count(),
            0
        );
    }
}
