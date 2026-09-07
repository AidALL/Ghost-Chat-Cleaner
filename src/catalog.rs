use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rusqlite::types::Value;
use rusqlite::{params, Connection, ErrorCode, OpenFlags, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::evidence::{
    is_valid_thread_id, scan_deletion_evidence, EvidenceError, EvidenceScanConfig,
};
use crate::file_guard::{identity_from_path_metadata, FileIdentity};
use crate::model::{
    CatalogThread, CatalogThreadError, LocalPath, NonUtf8PathError, ScanReport, SchemaReport,
    ThreadIdentity,
};
use crate::platform::PlatformPolicy;

const TARGET_TABLE: &str = "local_thread_catalog";
const MAX_SCHEMA_OBJECTS: usize = 4_096;
const MAX_SCHEMA_DEFINITION_BYTES: usize = 64 * 1024;
const MAX_CATALOG_ROWS: usize = 10_000;
const SCHEMA_QUERY_LIMIT: i64 = MAX_SCHEMA_OBJECTS as i64 + 1;
const SCHEMA_DEFINITION_QUERY_LIMIT: i64 = MAX_SCHEMA_DEFINITION_BYTES as i64;
const CATALOG_QUERY_LIMIT: i64 = MAX_CATALOG_ROWS as i64 + 1;
const REQUIRED_READ_COLUMNS: [(&str, Affinity); 4] = [
    ("host_id", Affinity::Text),
    ("thread_id", Affinity::Text),
    ("display_title", Affinity::Text),
    ("source_kind", Affinity::Text),
];
const REQUIRED_WRITE_COLUMNS: [(&str, Affinity); 4] = [
    ("project_id", Affinity::Text),
    ("cwd", Affinity::Text),
    ("missing_candidate", Affinity::Integer),
    ("source_recency_at", Affinity::Real),
];
const READ_THREADS_BASIC: &str = "SELECT host_id, thread_id, display_title, source_kind \
    FROM local_thread_catalog WHERE source_kind = 'chatgpt' ORDER BY host_id, thread_id LIMIT ?1";
const READ_THREADS_WITH_CLASSIFICATION: &str =
    "SELECT host_id, thread_id, display_title, source_kind, project_id, cwd, missing_candidate \
     FROM local_thread_catalog WHERE source_kind = 'chatgpt' ORDER BY host_id, thread_id LIMIT ?1";

#[derive(Debug, Error)]
pub enum CatalogScanError {
    #[error("catalog path does not exist: {path:?}")]
    PathNotFound { path: PathBuf },
    #[error("catalog path is a symlink: {path:?}")]
    SymlinkRefused { path: PathBuf },
    #[error("catalog path is not a regular file: {path:?}")]
    NotRegularFile { path: PathBuf },
    #[error("native file identity is unavailable for catalog path {path:?}: {source}")]
    FileIdentityUnavailable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not inspect catalog path {path:?}: {source}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("catalog is not a valid SQLite database: {path:?}")]
    InvalidDatabase {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("read-only catalog operation failed for {path:?}: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("catalog integrity check failed for {path:?}: {details:?}")]
    IntegrityCheckFailed { path: PathBuf, details: Vec<String> },
    #[error("catalog schema exceeds the {limit}-object inspection limit")]
    SchemaTooLarge { limit: usize },
    #[error("catalog exceeds the {limit}-row inspection limit")]
    CatalogTooLarge { limit: usize },
    #[error("catalog file changed while it was being scanned: {path:?}")]
    CatalogChangedDuringScan { path: PathBuf },
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
    #[error(transparent)]
    NonUtf8Path(#[from] NonUtf8PathError),
    #[error(transparent)]
    CatalogThread(#[from] CatalogThreadError),
}

pub fn scan_catalog(
    database_path: &Path,
    platform: PlatformPolicy,
    evidence_config: &EvidenceScanConfig,
) -> Result<ScanReport, CatalogScanError> {
    scan_catalog_with_after_snapshot(database_path, platform, evidence_config, || {})
}

fn scan_catalog_with_after_snapshot<F>(
    database_path: &Path,
    platform: PlatformPolicy,
    evidence_config: &EvidenceScanConfig,
    after_snapshot: F,
) -> Result<ScanReport, CatalogScanError>
where
    F: FnOnce(),
{
    let database_path = resolve_catalog_path(database_path)?;
    let initial_file_metadata = CatalogFileMetadataSnapshot::capture(&database_path)?;
    let mut connection = open_read_only(&database_path)?;
    harden_connection(&connection, &database_path)?;
    let initial_data_version = read_data_version(&connection, &database_path)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|source| map_sqlite_error(&database_path, source))?;
    let CatalogReadSnapshot {
        fingerprint,
        schema,
        rows,
    } = read_catalog_snapshot(&transaction, &database_path)?;
    transaction
        .commit()
        .map_err(|source| map_sqlite_error(&database_path, source))?;
    after_snapshot();

    let report = build_scan_report(
        &database_path,
        platform,
        evidence_config,
        CatalogReadSnapshot {
            fingerprint,
            schema,
            rows,
        },
    )?;
    if read_data_version(&connection, &database_path)? != initial_data_version {
        return Err(CatalogScanError::CatalogChangedDuringScan {
            path: database_path,
        });
    }
    initial_file_metadata.verify_unchanged(&database_path)?;

    Ok(report)
}

pub(crate) fn scan_catalog_connection(
    connection: &Connection,
    database_path: &Path,
    platform: PlatformPolicy,
    evidence_config: &EvidenceScanConfig,
) -> Result<ScanReport, CatalogScanError> {
    let snapshot = read_catalog_snapshot_connection(connection, database_path)?;
    build_scan_report(database_path, platform, evidence_config, snapshot)
}

fn build_scan_report(
    database_path: &Path,
    platform: PlatformPolicy,
    evidence_config: &EvidenceScanConfig,
    snapshot: CatalogReadSnapshot,
) -> Result<ScanReport, CatalogScanError> {
    let CatalogReadSnapshot {
        fingerprint,
        schema,
        rows,
    } = snapshot;

    let write_capable = schema.structurally_write_capable && platform.allows_mutation();
    let reason = if !schema.read_capable || !schema.structurally_write_capable {
        schema.reason
    } else if !platform.allows_mutation() {
        format!("platform policy {} disables mutation", platform.label())
    } else {
        "supported structural profile and platform policy".to_owned()
    };

    let colliding_thread_ids = colliding_thread_ids(&rows);
    let evidence = {
        let mut seen_thread_ids = HashSet::new();
        let mut valid_thread_ids = Vec::new();
        for row in &rows {
            if row.classification_inputs_trusted
                && is_valid_thread_id(&row.thread_id)
                && seen_thread_ids.insert(row.thread_id.as_str())
            {
                valid_thread_ids.push(row.thread_id.as_str());
            }
        }
        scan_deletion_evidence(evidence_config, &valid_thread_ids)?
    };
    let mut threads = Vec::with_capacity(rows.len());
    for row in rows {
        let identity = ThreadIdentity::new(row.host_id, row.thread_id.clone());
        let project_id = row.project_id;
        let cwd = row
            .cwd
            .map(|value| LocalPath::try_from(PathBuf::from(value)))
            .transpose()?;
        let has_context = project_id.is_some() || cwd.is_some();

        let thread = if !row.classification_inputs_trusted
            || !is_valid_thread_id(&row.thread_id)
            || has_context
        {
            CatalogThread::preserved(
                identity,
                row.display_title,
                row.source_kind,
                row.missing_candidate,
                project_id,
                cwd,
            )
        } else if colliding_thread_ids.contains(&row.thread_id) {
            if row.missing_candidate || evidence.evidence_for(&row.thread_id).is_some() {
                CatalogThread::review_required(
                    identity,
                    row.display_title,
                    row.source_kind,
                    row.missing_candidate,
                    None,
                    None,
                )?
            } else {
                CatalogThread::preserved(
                    identity,
                    row.display_title,
                    row.source_kind,
                    false,
                    None,
                    None,
                )
            }
        } else if let Some(deletion_evidence) = evidence.evidence_for(&row.thread_id).cloned() {
            CatalogThread::confirmed_deleted(
                identity,
                row.display_title,
                row.source_kind,
                row.missing_candidate,
                None,
                None,
                deletion_evidence,
            )?
        } else if row.missing_candidate {
            CatalogThread::review_required(
                identity,
                row.display_title,
                row.source_kind,
                true,
                None,
                None,
            )?
        } else {
            CatalogThread::preserved(
                identity,
                row.display_title,
                row.source_kind,
                false,
                None,
                None,
            )
        };
        threads.push(thread);
    }

    Ok(ScanReport::new(
        LocalPath::try_from(database_path)?,
        platform.label(),
        SchemaReport {
            write_capable,
            reason,
            fingerprint,
            columns: schema.columns,
        },
        threads,
        true,
    ))
}

fn read_catalog_snapshot(
    transaction: &Transaction<'_>,
    path: &Path,
) -> Result<CatalogReadSnapshot, CatalogScanError> {
    // Keeping every database read behind this transaction-typed boundary prevents
    // attestation and row classification from observing different snapshots.
    read_catalog_snapshot_connection(transaction, path)
}

fn read_catalog_snapshot_connection(
    connection: &Connection,
    path: &Path,
) -> Result<CatalogReadSnapshot, CatalogScanError> {
    run_integrity_check(connection, path)?;
    let fingerprint = schema_fingerprint(connection, path)?;
    let schema = inspect_schema(connection, path)?;
    let rows = if schema.read_capable {
        read_threads(connection, path, schema.classification_columns_usable)?
    } else {
        Vec::new()
    };
    Ok(CatalogReadSnapshot {
        fingerprint,
        schema,
        rows,
    })
}

fn colliding_thread_ids(rows: &[RawThread]) -> HashSet<String> {
    let mut first_host_by_thread = HashMap::new();
    let mut collisions = HashSet::new();
    for row in rows {
        match first_host_by_thread.get(row.thread_id.as_str()) {
            Some(first_host) if *first_host != row.host_id.as_str() => {
                collisions.insert(row.thread_id.clone());
            }
            Some(_) => {}
            None => {
                first_host_by_thread.insert(row.thread_id.as_str(), row.host_id.as_str());
            }
        }
    }
    collisions
}

fn resolve_catalog_path(path: &Path) -> Result<PathBuf, CatalogScanError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(CatalogScanError::PathNotFound {
                path: path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(CatalogScanError::Metadata {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(CatalogScanError::SymlinkRefused {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_file() {
        return Err(CatalogScanError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }

    let canonical_path = fs::canonicalize(path).map_err(|source| CatalogScanError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    let canonical_metadata =
        fs::symlink_metadata(&canonical_path).map_err(|source| CatalogScanError::Metadata {
            path: canonical_path.clone(),
            source,
        })?;
    if canonical_metadata.file_type().is_symlink() {
        return Err(CatalogScanError::SymlinkRefused {
            path: canonical_path,
        });
    }
    if !canonical_metadata.is_file() {
        return Err(CatalogScanError::NotRegularFile {
            path: canonical_path,
        });
    }
    Ok(canonical_path)
}

fn open_read_only(path: &Path) -> Result<Connection, CatalogScanError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    Connection::open_with_flags(path, flags).map_err(|source| map_sqlite_error(path, source))
}

fn harden_connection(connection: &Connection, path: &Path) -> Result<(), CatalogScanError> {
    connection
        .pragma_update(None, "trusted_schema", "OFF")
        .and_then(|()| connection.pragma_update(None, "query_only", "ON"))
        .and_then(|()| connection.pragma_update(None, "mmap_size", 0_i64))
        .map_err(|source| map_sqlite_error(path, source))
}

fn read_data_version(connection: &Connection, path: &Path) -> Result<i64, CatalogScanError> {
    connection
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|source| map_sqlite_error(path, source))
}

fn run_integrity_check(connection: &Connection, path: &Path) -> Result<(), CatalogScanError> {
    let mut statement = connection
        .prepare("PRAGMA integrity_check")
        .map_err(|source| map_integrity_error(path, source))?;
    let values = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|source| map_integrity_error(path, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| map_integrity_error(path, source))?;
    if values.len() == 1 && values[0] == "ok" {
        Ok(())
    } else {
        Err(CatalogScanError::IntegrityCheckFailed {
            path: path.to_path_buf(),
            details: values,
        })
    }
}

fn schema_fingerprint(connection: &Connection, path: &Path) -> Result<String, CatalogScanError> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, \
                    length(CAST(COALESCE(sql, '') AS BLOB)), \
                    CASE \
                        WHEN length(CAST(COALESCE(sql, '') AS BLOB)) <= ?2 \
                        THEN COALESCE(sql, '') \
                        ELSE '' \
                    END \
             FROM sqlite_master \
             ORDER BY type, name, tbl_name \
             LIMIT ?1",
        )
        .map_err(|source| map_sqlite_error(path, source))?;
    let mut rows = statement
        .query(params![SCHEMA_QUERY_LIMIT, SCHEMA_DEFINITION_QUERY_LIMIT])
        .map_err(|source| map_sqlite_error(path, source))?;
    let mut hasher = Sha256::new();
    let mut object_count = 0_usize;
    while let Some(row) = rows
        .next()
        .map_err(|source| map_sqlite_error(path, source))?
    {
        object_count += 1;
        if object_count > MAX_SCHEMA_OBJECTS {
            return Err(CatalogScanError::SchemaTooLarge {
                limit: MAX_SCHEMA_OBJECTS,
            });
        }
        let definition_bytes: i64 = row
            .get(3)
            .map_err(|source| map_sqlite_error(path, source))?;
        let definition_too_large = usize::try_from(definition_bytes)
            .map(|length| length > MAX_SCHEMA_DEFINITION_BYTES)
            .unwrap_or(true);
        if definition_too_large {
            return Err(CatalogScanError::SchemaTooLarge {
                limit: MAX_SCHEMA_DEFINITION_BYTES,
            });
        }
        let object_type: String = row
            .get(0)
            .map_err(|source| map_sqlite_error(path, source))?;
        let name: String = row
            .get(1)
            .map_err(|source| map_sqlite_error(path, source))?;
        let table_name: String = row
            .get(2)
            .map_err(|source| map_sqlite_error(path, source))?;
        let sql: String = row
            .get(4)
            .map_err(|source| map_sqlite_error(path, source))?;
        for part in [object_type, name, table_name, normalize_sql(&sql)] {
            hasher.update(part.as_bytes());
            hasher.update([0]);
        }
        hasher.update([0xff]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn normalize_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn inspect_schema(
    connection: &Connection,
    path: &Path,
) -> Result<SchemaInspection, CatalogScanError> {
    let table_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master \
             WHERE type = 'table' AND name = ?1 LIMIT 1)",
            [TARGET_TABLE],
            |row| row.get(0),
        )
        .map_err(|source| map_sqlite_error(path, source))?;
    if !table_exists {
        return Ok(SchemaInspection::unsupported(
            "local_thread_catalog table is missing",
        ));
    }

    let mut statement = connection
        .prepare(
            "SELECT name, type, pk FROM pragma_table_info('local_thread_catalog') \
             ORDER BY cid LIMIT ?1",
        )
        .map_err(|source| map_sqlite_error(path, source))?;
    let mut column_rows = statement
        .query([SCHEMA_QUERY_LIMIT])
        .map_err(|source| map_sqlite_error(path, source))?;
    let mut columns = Vec::new();
    while let Some(row) = column_rows
        .next()
        .map_err(|source| map_sqlite_error(path, source))?
    {
        columns.push(ColumnInfo {
            name: row
                .get(0)
                .map_err(|source| map_sqlite_error(path, source))?,
            declared_type: row
                .get(1)
                .map_err(|source| map_sqlite_error(path, source))?,
            primary_key_position: row
                .get(2)
                .map_err(|source| map_sqlite_error(path, source))?,
        });
        if columns.len() > MAX_SCHEMA_OBJECTS {
            return Err(CatalogScanError::SchemaTooLarge {
                limit: MAX_SCHEMA_OBJECTS,
            });
        }
    }
    let column_names = columns.iter().map(|column| column.name.clone()).collect();

    let read_capable = REQUIRED_READ_COLUMNS
        .iter()
        .all(|(name, affinity)| column_has_affinity(&columns, name, *affinity));
    if !read_capable {
        return Ok(SchemaInspection {
            read_capable: false,
            classification_columns_usable: false,
            structurally_write_capable: false,
            reason: "required read column is missing or has an incompatible declared type"
                .to_owned(),
            columns: column_names,
        });
    }

    let classification_columns_usable = REQUIRED_WRITE_COLUMNS[..3]
        .iter()
        .all(|(name, affinity)| column_has_affinity(&columns, name, *affinity));
    let write_columns_valid = REQUIRED_WRITE_COLUMNS
        .iter()
        .all(|(name, affinity)| column_has_affinity(&columns, name, *affinity));
    let primary_key_valid = has_exact_primary_key(&columns);
    let has_target_trigger: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master \
             WHERE type = 'trigger' AND tbl_name = ?1 LIMIT 1)",
            [TARGET_TABLE],
            |row| row.get(0),
        )
        .map_err(|source| map_sqlite_error(path, source))?;
    let has_outbound_foreign_key = has_outbound_foreign_key(connection, path)?;
    let has_inbound_foreign_key = has_inbound_foreign_key(connection, path)?;

    let failures = [
        (!write_columns_valid).then_some("write column mismatch"),
        (!primary_key_valid).then_some("primary key mismatch"),
        has_target_trigger.then_some("target trigger present"),
        has_outbound_foreign_key.then_some("outbound foreign key present"),
        has_inbound_foreign_key.then_some("inbound foreign key present"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let structurally_write_capable = failures.is_empty();
    let reason = if structurally_write_capable {
        "supported structural profile".to_owned()
    } else {
        failures.join(", ")
    };

    Ok(SchemaInspection {
        read_capable: true,
        classification_columns_usable,
        structurally_write_capable,
        reason,
        columns: column_names,
    })
}

fn has_outbound_foreign_key(
    connection: &Connection,
    path: &Path,
) -> Result<bool, CatalogScanError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_list(?1) LIMIT 1)",
            [TARGET_TABLE],
            |row| row.get(0),
        )
        .map_err(|source| map_sqlite_error(path, source))
}

fn has_inbound_foreign_key(connection: &Connection, path: &Path) -> Result<bool, CatalogScanError> {
    let mut statement = connection
        .prepare(
            "SELECT name FROM sqlite_master \
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
             ORDER BY name LIMIT ?1",
        )
        .map_err(|source| map_sqlite_error(path, source))?;
    let mut table_rows = statement
        .query([SCHEMA_QUERY_LIMIT])
        .map_err(|source| map_sqlite_error(path, source))?;
    let mut table_names = Vec::new();
    while let Some(row) = table_rows
        .next()
        .map_err(|source| map_sqlite_error(path, source))?
    {
        table_names.push(
            row.get::<_, String>(0)
                .map_err(|source| map_sqlite_error(path, source))?,
        );
        if table_names.len() > MAX_SCHEMA_OBJECTS {
            return Err(CatalogScanError::SchemaTooLarge {
                limit: MAX_SCHEMA_OBJECTS,
            });
        }
    }

    for table_name in table_names {
        if table_name == TARGET_TABLE {
            continue;
        }
        let references_target: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_list(?1) \
                 WHERE \"table\" = ?2 COLLATE NOCASE LIMIT 1)",
                [&table_name, TARGET_TABLE],
                |row| row.get(0),
            )
            .map_err(|source| map_sqlite_error(path, source))?;
        if references_target {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_threads(
    connection: &Connection,
    path: &Path,
    classification_columns_usable: bool,
) -> Result<Vec<RawThread>, CatalogScanError> {
    let sql = if classification_columns_usable {
        READ_THREADS_WITH_CLASSIFICATION
    } else {
        READ_THREADS_BASIC
    };
    let mut statement = connection
        .prepare(sql)
        .map_err(|source| map_sqlite_error(path, source))?;
    let mut query = statement
        .query([CATALOG_QUERY_LIMIT])
        .map_err(|source| map_sqlite_error(path, source))?;
    let mut rows = Vec::new();
    while let Some(row) = query
        .next()
        .map_err(|source| map_sqlite_error(path, source))?
    {
        if rows.len() == MAX_CATALOG_ROWS {
            return Err(CatalogScanError::CatalogTooLarge {
                limit: MAX_CATALOG_ROWS,
            });
        }
        rows.push(
            read_thread_row(row, classification_columns_usable)
                .map_err(|source| map_sqlite_error(path, source))?,
        );
    }
    Ok(rows)
}

fn read_thread_row(
    row: &rusqlite::Row<'_>,
    classification_columns_usable: bool,
) -> rusqlite::Result<RawThread> {
    let mut raw = RawThread {
        host_id: row.get(0)?,
        thread_id: row.get(1)?,
        display_title: row.get(2)?,
        source_kind: row.get(3)?,
        project_id: None,
        cwd: None,
        missing_candidate: false,
        classification_inputs_trusted: classification_columns_usable,
    };
    if classification_columns_usable {
        let (project_id, project_valid) = optional_text(row.get(4)?);
        let (cwd, cwd_valid) = optional_text(row.get(5)?);
        let missing_value: Value = row.get(6)?;
        let (missing_candidate, missing_valid) = match missing_value {
            Value::Integer(value) => (value == 1, true),
            _ => (false, false),
        };
        raw.project_id = project_id;
        raw.cwd = cwd;
        raw.missing_candidate = missing_candidate;
        raw.classification_inputs_trusted = project_valid && cwd_valid && missing_valid;
    }
    Ok(raw)
}

fn optional_text(value: Value) -> (Option<String>, bool) {
    match value {
        Value::Null => (None, true),
        Value::Text(value) => (Some(value), true),
        _ => (None, false),
    }
}

fn column_has_affinity(columns: &[ColumnInfo], name: &str, expected: Affinity) -> bool {
    columns
        .iter()
        .any(|column| column.name == name && declared_affinity(&column.declared_type) == expected)
}

fn has_exact_primary_key(columns: &[ColumnInfo]) -> bool {
    let primary_key_columns = columns
        .iter()
        .filter(|column| column.primary_key_position > 0)
        .collect::<Vec<_>>();
    primary_key_columns.len() == 2
        && primary_key_columns
            .iter()
            .any(|column| column.name == "host_id" && column.primary_key_position == 1)
        && primary_key_columns
            .iter()
            .any(|column| column.name == "thread_id" && column.primary_key_position == 2)
}

fn declared_affinity(declared_type: &str) -> Affinity {
    let declared_type = declared_type.to_ascii_uppercase();
    if declared_type.contains("INT") {
        Affinity::Integer
    } else if declared_type.contains("CHAR")
        || declared_type.contains("CLOB")
        || declared_type.contains("TEXT")
    {
        Affinity::Text
    } else if declared_type.is_empty() || declared_type.contains("BLOB") {
        Affinity::Blob
    } else if declared_type.contains("REAL")
        || declared_type.contains("FLOA")
        || declared_type.contains("DOUB")
    {
        Affinity::Real
    } else {
        Affinity::Numeric
    }
}

fn map_integrity_error(path: &Path, source: rusqlite::Error) -> CatalogScanError {
    if source.sqlite_error_code() == Some(ErrorCode::NotADatabase) {
        CatalogScanError::InvalidDatabase {
            path: path.to_path_buf(),
            source,
        }
    } else {
        CatalogScanError::IntegrityCheckFailed {
            path: path.to_path_buf(),
            details: vec!["integrity check could not complete".to_owned()],
        }
    }
}

fn map_sqlite_error(path: &Path, source: rusqlite::Error) -> CatalogScanError {
    if matches!(
        source.sqlite_error_code(),
        Some(ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt)
    ) {
        CatalogScanError::InvalidDatabase {
            path: path.to_path_buf(),
            source,
        }
    } else {
        CatalogScanError::Sqlite {
            path: path.to_path_buf(),
            source,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogFileMetadataSnapshot {
    identity: FileIdentity,
    length: u64,
    modified: SystemTime,
}

impl CatalogFileMetadataSnapshot {
    fn capture(path: &Path) -> Result<Self, CatalogScanError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(CatalogScanError::PathNotFound {
                    path: path.to_path_buf(),
                });
            }
            Err(source) => {
                return Err(CatalogScanError::Metadata {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(CatalogScanError::SymlinkRefused {
                path: path.to_path_buf(),
            });
        }
        if !metadata.is_file() {
            return Err(CatalogScanError::NotRegularFile {
                path: path.to_path_buf(),
            });
        }
        let modified = metadata
            .modified()
            .map_err(|source| CatalogScanError::Metadata {
                path: path.to_path_buf(),
                source,
            })?;
        Ok(Self {
            identity: identity_from_path_metadata(path, &metadata).map_err(|source| {
                CatalogScanError::FileIdentityUnavailable {
                    path: path.to_path_buf(),
                    source,
                }
            })?,
            length: metadata.len(),
            modified,
        })
    }

    fn verify_unchanged(&self, path: &Path) -> Result<(), CatalogScanError> {
        match Self::capture(path) {
            Ok(current) if current == *self => Ok(()),
            Ok(_) | Err(_) => Err(CatalogScanError::CatalogChangedDuringScan {
                path: path.to_path_buf(),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Affinity {
    Text,
    Integer,
    Real,
    Blob,
    Numeric,
}

#[derive(Debug)]
struct ColumnInfo {
    name: String,
    declared_type: String,
    primary_key_position: i64,
}

#[derive(Debug)]
struct SchemaInspection {
    read_capable: bool,
    classification_columns_usable: bool,
    structurally_write_capable: bool,
    reason: String,
    columns: Vec<String>,
}

#[derive(Debug)]
struct CatalogReadSnapshot {
    fingerprint: String,
    schema: SchemaInspection,
    rows: Vec<RawThread>,
}

impl SchemaInspection {
    fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            read_capable: false,
            classification_columns_usable: false,
            structurally_write_capable: false,
            reason: reason.into(),
            columns: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct RawThread {
    host_id: String,
    thread_id: String,
    display_title: String,
    source_kind: String,
    project_id: Option<String>,
    cwd: Option<String>,
    missing_candidate: bool,
    classification_inputs_trusted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thread_fixture(classification_columns: bool, row_count: usize) -> Connection {
        let mut connection = Connection::open_in_memory().expect("create row-limit fixture");
        if classification_columns {
            connection
                .execute_batch(
                    "CREATE TABLE local_thread_catalog (
                        host_id TEXT NOT NULL,
                        thread_id TEXT NOT NULL,
                        display_title TEXT NOT NULL,
                        source_kind TEXT NOT NULL,
                        project_id TEXT,
                        cwd TEXT,
                        missing_candidate INTEGER NOT NULL,
                        source_recency_at REAL
                    );",
                )
                .expect("create full row-limit fixture schema");
        } else {
            connection
                .execute_batch(
                    "CREATE TABLE local_thread_catalog (
                        host_id TEXT NOT NULL,
                        thread_id TEXT NOT NULL,
                        display_title TEXT NOT NULL,
                        source_kind TEXT NOT NULL
                    );",
                )
                .expect("create basic row-limit fixture schema");
        }

        let transaction = connection
            .transaction()
            .expect("begin row-limit fixture transaction");
        let insert_sql = if classification_columns {
            "INSERT INTO local_thread_catalog VALUES (?1, ?2, ?3, 'chatgpt', NULL, NULL, 0, 1.0)"
        } else {
            "INSERT INTO local_thread_catalog VALUES (?1, ?2, ?3, 'chatgpt')"
        };
        {
            let mut insert = transaction
                .prepare(insert_sql)
                .expect("prepare row-limit fixture insert");
            for index in 0..row_count {
                insert
                    .execute(params![
                        "host-a",
                        format!("thread-{index:05}"),
                        format!("Thread {index}")
                    ])
                    .expect("insert row-limit fixture row");
            }
        }
        transaction.commit().expect("commit row-limit fixture rows");
        connection
    }

    #[test]
    fn catalog_file_snapshot_rejects_length_or_modified_time_changes() {
        let directory = tempfile::tempdir().expect("create metadata fixture directory");
        let path = directory.path().join("catalog.db");
        fs::write(&path, b"first").expect("write initial fixture");
        let before = CatalogFileMetadataSnapshot::capture(&path).expect("capture initial metadata");

        fs::write(&path, b"second version").expect("change fixture");
        assert!(matches!(
            before.verify_unchanged(&path),
            Err(CatalogScanError::CatalogChangedDuringScan { .. })
        ));
    }

    #[test]
    fn catalog_snapshot_reader_requires_an_explicit_transaction() {
        let reader: for<'connection> fn(
            &rusqlite::Transaction<'connection>,
            &Path,
        ) -> Result<CatalogReadSnapshot, CatalogScanError> = read_catalog_snapshot;
        let _ = reader;
    }

    #[test]
    fn wal_commit_after_snapshot_is_detected_on_the_same_scan_connection() {
        let directory = tempfile::tempdir().expect("create WAL fixture directory");
        let path = directory.path().join("catalog.db");
        let writer = Connection::open(&path).expect("create WAL fixture database");
        writer
            .pragma_update(None, "journal_mode", "WAL")
            .expect("enable WAL mode");
        writer
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
                ) WITHOUT ROWID;
                INSERT INTO local_thread_catalog VALUES
                    ('host-a', 'thread-a', 'Before', 'chatgpt', NULL, NULL, 0, 1.0);",
            )
            .expect("create WAL fixture contents");
        let evidence = EvidenceScanConfig::new(Vec::new(), Vec::new());

        let result =
            scan_catalog_with_after_snapshot(&path, PlatformPolicy::MacOs, &evidence, || {
                writer
                    .execute(
                        "UPDATE local_thread_catalog SET display_title = 'After' \
                         WHERE host_id = 'host-a' AND thread_id = 'thread-a'",
                        [],
                    )
                    .expect("commit through separate WAL writer");
            });
        assert!(matches!(
            result,
            Err(CatalogScanError::CatalogChangedDuringScan { .. })
        ));
    }

    #[test]
    fn basic_catalog_row_limit_accepts_the_exact_boundary() {
        let connection = thread_fixture(false, 10_000);

        let rows = read_threads(&connection, Path::new("basic-row-limit.db"), false)
            .expect("accept exactly the catalog row limit");
        assert_eq!(rows.len(), 10_000);
    }

    #[test]
    fn basic_catalog_row_limit_rejects_cap_plus_one() {
        let connection = thread_fixture(false, 10_001);

        assert!(matches!(
            read_threads(&connection, Path::new("basic-row-limit.db"), false),
            Err(CatalogScanError::CatalogTooLarge { limit: 10_000 })
        ));
    }

    #[test]
    fn full_catalog_row_limit_accepts_the_exact_boundary() {
        let connection = thread_fixture(true, 10_000);

        let rows = read_threads(&connection, Path::new("full-row-limit.db"), true)
            .expect("accept exactly the catalog row limit");
        assert_eq!(rows.len(), 10_000);
    }

    #[test]
    fn full_catalog_row_limit_rejects_cap_plus_one() {
        let connection = thread_fixture(true, 10_001);

        assert!(matches!(
            read_threads(&connection, Path::new("full-row-limit.db"), true),
            Err(CatalogScanError::CatalogTooLarge { limit: 10_000 })
        ));
    }
}
