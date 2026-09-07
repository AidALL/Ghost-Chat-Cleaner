#![allow(dead_code)]

use std::fs::{self, File};
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};
use tempfile::TempDir;

pub const SUPPORTED_SCHEMA: &str = r#"
    CREATE TABLE local_thread_catalog (
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
"#;

pub struct CatalogFixture {
    _directory: TempDir,
    path: PathBuf,
}

impl CatalogFixture {
    pub fn with_schema(schema: &str) -> Self {
        let directory = tempfile::tempdir().expect("create catalog fixture directory");
        let path = directory.path().join("codex-dev.db");
        let connection = Connection::open(&path).expect("create catalog fixture database");
        connection
            .execute_batch(schema)
            .expect("create catalog fixture schema");
        drop(connection);
        Self {
            _directory: directory,
            path,
        }
    }

    pub fn supported() -> Self {
        Self::with_schema(SUPPORTED_SCHEMA)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_thread(
        &self,
        host_id: &str,
        thread_id: &str,
        display_title: &str,
        source_kind: &str,
        project_id: Option<&str>,
        cwd: Option<&str>,
        missing_candidate: i64,
        source_recency_at: f64,
    ) {
        let connection = Connection::open(&self.path).expect("open catalog fixture database");
        connection
            .execute(
                "INSERT INTO local_thread_catalog \
                 (host_id, thread_id, display_title, source_kind, project_id, cwd, \
                  missing_candidate, source_recency_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    host_id,
                    thread_id,
                    display_title,
                    source_kind,
                    project_id,
                    cwd,
                    missing_candidate,
                    source_recency_at
                ],
            )
            .expect("insert catalog fixture row");
    }

    pub fn damage_integrity(&self) {
        let connection = Connection::open(&self.path).expect("open catalog fixture database");
        connection
            .execute_batch(
                "PRAGMA writable_schema = ON;
                 UPDATE sqlite_schema
                 SET rootpage = 0
                 WHERE type = 'table' AND name = 'local_thread_catalog';
                 PRAGMA writable_schema = OFF;",
            )
            .expect("damage fixture schema root page");
    }
}

pub struct CorruptFixture {
    _directory: TempDir,
    path: PathBuf,
}

impl CorruptFixture {
    pub fn create() -> Self {
        let directory = tempfile::tempdir().expect("create corrupt fixture directory");
        let path = directory.path().join("codex-dev.db");
        fs::write(&path, b"this is not a sqlite database").expect("write corrupt database fixture");
        Self {
            _directory: directory,
            path,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn write_evidence(root: &Path, name: &str, contents: &str) -> PathBuf {
    fs::create_dir_all(root).expect("create evidence root");
    let path = root.join(name);
    fs::write(&path, contents).expect("write evidence fixture");
    path
}

pub fn create_sparse_evidence(root: &Path, name: &str, length: u64) -> PathBuf {
    fs::create_dir_all(root).expect("create evidence root");
    let path = root.join(name);
    File::create(&path)
        .and_then(|file| file.set_len(length))
        .expect("write sparse evidence fixture");
    path
}
