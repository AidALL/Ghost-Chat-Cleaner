use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ThreadIdentity {
    pub host_id: String,
    pub thread_id: String,
}

impl ThreadIdentity {
    pub fn new(host_id: impl Into<String>, thread_id: impl Into<String>) -> Self {
        Self {
            host_id: host_id.into(),
            thread_id: thread_id.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    ConfirmedDeleted,
    ReviewRequired,
    Preserved,
}

impl Classification {
    pub const fn is_selectable(self) -> bool {
        matches!(self, Self::ConfirmedDeleted | Self::ReviewRequired)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
/// A UTF-8 path serialized exactly as written by its producing platform.
///
/// Foreign-platform path strings are preserved for transport and comparison,
/// but native filesystem operations through [`Self::as_path`] are valid only
/// on the platform that produced the value.
pub struct LocalPath(String);

impl LocalPath {
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }
}

impl AsRef<Path> for LocalPath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl TryFrom<&Path> for LocalPath {
    type Error = NonUtf8PathError;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        path.to_str()
            .map(|value| Self(value.to_owned()))
            .ok_or_else(|| NonUtf8PathError {
                path: path.to_owned(),
            })
    }
}

impl TryFrom<PathBuf> for LocalPath {
    type Error = NonUtf8PathError;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        match path.into_os_string().into_string() {
            Ok(value) => Ok(Self(value)),
            Err(value) => Err(NonUtf8PathError {
                path: PathBuf::from(value),
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonUtf8PathError {
    path: PathBuf,
}

impl NonUtf8PathError {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Display for NonUtf8PathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("path is not valid UTF-8")
    }
}

impl Error for NonUtf8PathError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DeletionEvidence {
    pub source_path: LocalPath,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CatalogThread {
    identity: ThreadIdentity,
    display_title: String,
    source_kind: String,
    project_id: Option<String>,
    cwd: Option<LocalPath>,
    missing_candidate: bool,
    classification: Classification,
    evidence: Option<DeletionEvidence>,
}

impl CatalogThread {
    pub fn preserved(
        identity: ThreadIdentity,
        display_title: impl Into<String>,
        source_kind: impl Into<String>,
        missing_candidate: bool,
        project_id: Option<String>,
        cwd: Option<LocalPath>,
    ) -> Self {
        Self {
            identity,
            display_title: display_title.into(),
            source_kind: source_kind.into(),
            project_id,
            cwd,
            missing_candidate,
            classification: Classification::Preserved,
            evidence: None,
        }
    }

    pub fn review_required(
        identity: ThreadIdentity,
        display_title: impl Into<String>,
        source_kind: impl Into<String>,
        missing_candidate: bool,
        project_id: Option<String>,
        cwd: Option<LocalPath>,
    ) -> Result<Self, CatalogThreadError> {
        Self::build(
            identity,
            display_title.into(),
            source_kind.into(),
            project_id,
            cwd,
            missing_candidate,
            Classification::ReviewRequired,
            None,
        )
    }

    pub fn confirmed_deleted(
        identity: ThreadIdentity,
        display_title: impl Into<String>,
        source_kind: impl Into<String>,
        missing_candidate: bool,
        project_id: Option<String>,
        cwd: Option<LocalPath>,
        evidence: DeletionEvidence,
    ) -> Result<Self, CatalogThreadError> {
        Self::build(
            identity,
            display_title.into(),
            source_kind.into(),
            project_id,
            cwd,
            missing_candidate,
            Classification::ConfirmedDeleted,
            Some(evidence),
        )
    }

    pub fn identity(&self) -> &ThreadIdentity {
        &self.identity
    }

    pub fn display_title(&self) -> &str {
        &self.display_title
    }

    pub fn source_kind(&self) -> &str {
        &self.source_kind
    }

    pub fn project_id(&self) -> Option<&str> {
        self.project_id.as_deref()
    }

    pub fn cwd(&self) -> Option<&LocalPath> {
        self.cwd.as_ref()
    }

    pub const fn missing_candidate(&self) -> bool {
        self.missing_candidate
    }

    pub const fn classification(&self) -> Classification {
        self.classification
    }

    pub fn evidence(&self) -> Option<&DeletionEvidence> {
        self.evidence.as_ref()
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        identity: ThreadIdentity,
        display_title: String,
        source_kind: String,
        project_id: Option<String>,
        cwd: Option<LocalPath>,
        missing_candidate: bool,
        classification: Classification,
        evidence: Option<DeletionEvidence>,
    ) -> Result<Self, CatalogThreadError> {
        if classification.is_selectable() && source_kind != "chatgpt" {
            return Err(CatalogThreadError::SelectableSourceKind { source_kind });
        }

        if classification.is_selectable() && (project_id.is_some() || cwd.is_some()) {
            return Err(CatalogThreadError::ProjectContextRequiresPreserved);
        }

        match (classification, evidence.is_some()) {
            (Classification::ConfirmedDeleted, false) => {
                return Err(CatalogThreadError::MissingDeletionEvidence);
            }
            (Classification::ConfirmedDeleted, true) | (_, false) => {}
            (_, true) => {
                return Err(CatalogThreadError::UnexpectedDeletionEvidence { classification });
            }
        }

        Ok(Self {
            identity,
            display_title,
            source_kind,
            project_id,
            cwd,
            missing_candidate,
            classification,
            evidence,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogThreadError {
    SelectableSourceKind { source_kind: String },
    ProjectContextRequiresPreserved,
    MissingDeletionEvidence,
    UnexpectedDeletionEvidence { classification: Classification },
}

impl fmt::Display for CatalogThreadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectableSourceKind { source_kind } => write!(
                formatter,
                "selectable threads require source_kind chatgpt, got {source_kind}"
            ),
            Self::ProjectContextRequiresPreserved => {
                formatter.write_str("threads with project context must be preserved")
            }
            Self::MissingDeletionEvidence => {
                formatter.write_str("confirmed deletion requires evidence")
            }
            Self::UnexpectedDeletionEvidence { classification } => write!(
                formatter,
                "deletion evidence is not valid for {classification:?}"
            ),
        }
    }
}

impl Error for CatalogThreadError {}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct CatalogThreadWire {
    identity: ThreadIdentity,
    display_title: String,
    source_kind: String,
    project_id: Option<String>,
    cwd: Option<LocalPath>,
    missing_candidate: bool,
    classification: Classification,
    evidence: Option<DeletionEvidence>,
}

impl<'de> Deserialize<'de> for CatalogThread {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CatalogThreadWire::deserialize(deserializer)?;
        Self::build(
            wire.identity,
            wire.display_title,
            wire.source_kind,
            wire.project_id,
            wire.cwd,
            wire.missing_candidate,
            wire.classification,
            wire.evidence,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SchemaReport {
    pub write_capable: bool,
    pub reason: String,
    pub fingerprint: String,
    pub columns: Vec<String>,
}

pub const SCAN_REPORT_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ScanReport {
    format_version: u32,
    pub database_path: LocalPath,
    pub platform_label: String,
    pub schema: SchemaReport,
    pub threads: Vec<CatalogThread>,
    pub integrity_ok: bool,
}

impl ScanReport {
    pub fn new(
        database_path: LocalPath,
        platform_label: impl Into<String>,
        schema: SchemaReport,
        threads: Vec<CatalogThread>,
        integrity_ok: bool,
    ) -> Self {
        Self {
            format_version: SCAN_REPORT_FORMAT_VERSION,
            database_path,
            platform_label: platform_label.into(),
            schema,
            threads,
            integrity_ok,
        }
    }

    pub fn try_new(
        format_version: u32,
        database_path: LocalPath,
        platform_label: impl Into<String>,
        schema: SchemaReport,
        threads: Vec<CatalogThread>,
        integrity_ok: bool,
    ) -> Result<Self, UnsupportedFormatVersionError> {
        validate_format_version("scan_report", format_version, SCAN_REPORT_FORMAT_VERSION)?;
        Ok(Self {
            format_version,
            database_path,
            platform_label: platform_label.into(),
            schema,
            threads,
            integrity_ok,
        })
    }

    pub const fn format_version(&self) -> u32 {
        self.format_version
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct ScanReportWire {
    format_version: u32,
    database_path: LocalPath,
    platform_label: String,
    schema: SchemaReport,
    threads: Vec<CatalogThread>,
    integrity_ok: bool,
}

impl<'de> Deserialize<'de> for ScanReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ScanReportWire::deserialize(deserializer)?;
        Self::try_new(
            wire.format_version,
            wire.database_path,
            wire.platform_label,
            wire.schema,
            wire.threads,
            wire.integrity_ok,
        )
        .map_err(de::Error::custom)
    }
}

pub const REPAIR_RECEIPT_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RepairReceipt {
    format_version: u32,
    pub database_path: LocalPath,
    pub backup_path: LocalPath,
    pub origin_platform: String,
    pub backup_hash: String,
    pub removed_identities: Vec<ThreadIdentity>,
    pub before_count: u64,
    pub after_count: u64,
}

impl RepairReceipt {
    pub fn new(
        database_path: LocalPath,
        backup_path: LocalPath,
        origin_platform: impl Into<String>,
        backup_hash: impl Into<String>,
        removed_identities: Vec<ThreadIdentity>,
        before_count: u64,
        after_count: u64,
    ) -> Self {
        Self {
            format_version: REPAIR_RECEIPT_FORMAT_VERSION,
            database_path,
            backup_path,
            origin_platform: origin_platform.into(),
            backup_hash: backup_hash.into(),
            removed_identities,
            before_count,
            after_count,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        format_version: u32,
        database_path: LocalPath,
        backup_path: LocalPath,
        origin_platform: impl Into<String>,
        backup_hash: impl Into<String>,
        removed_identities: Vec<ThreadIdentity>,
        before_count: u64,
        after_count: u64,
    ) -> Result<Self, UnsupportedFormatVersionError> {
        validate_format_version(
            "repair_receipt",
            format_version,
            REPAIR_RECEIPT_FORMAT_VERSION,
        )?;
        Ok(Self {
            format_version,
            database_path,
            backup_path,
            origin_platform: origin_platform.into(),
            backup_hash: backup_hash.into(),
            removed_identities,
            before_count,
            after_count,
        })
    }

    pub const fn format_version(&self) -> u32 {
        self.format_version
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct RepairReceiptWire {
    format_version: u32,
    database_path: LocalPath,
    backup_path: LocalPath,
    origin_platform: String,
    backup_hash: String,
    removed_identities: Vec<ThreadIdentity>,
    before_count: u64,
    after_count: u64,
}

impl<'de> Deserialize<'de> for RepairReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RepairReceiptWire::deserialize(deserializer)?;
        Self::try_new(
            wire.format_version,
            wire.database_path,
            wire.backup_path,
            wire.origin_platform,
            wire.backup_hash,
            wire.removed_identities,
            wire.before_count,
            wire.after_count,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedFormatVersionError {
    artifact: &'static str,
    actual: u32,
    supported: u32,
}

impl UnsupportedFormatVersionError {
    pub const fn artifact(&self) -> &'static str {
        self.artifact
    }

    pub const fn actual(&self) -> u32 {
        self.actual
    }

    pub const fn supported(&self) -> u32 {
        self.supported
    }
}

impl fmt::Display for UnsupportedFormatVersionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported {} format version {}; expected {}",
            self.artifact, self.actual, self.supported
        )
    }
}

impl Error for UnsupportedFormatVersionError {}

fn validate_format_version(
    artifact: &'static str,
    actual: u32,
    supported: u32,
) -> Result<(), UnsupportedFormatVersionError> {
    if actual == supported {
        Ok(())
    } else {
        Err(UnsupportedFormatVersionError {
            artifact,
            actual,
            supported,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};

    use super::*;

    fn identity() -> ThreadIdentity {
        ThreadIdentity::new("host-a", "thread-1")
    }

    fn local_path(value: &str) -> LocalPath {
        LocalPath::try_from(Path::new(value)).expect("test path must be UTF-8")
    }

    fn evidence() -> DeletionEvidence {
        DeletionEvidence {
            source_path: local_path("/tmp/deletion-evidence.json"),
            reason: "missing from authoritative history".to_owned(),
        }
    }

    #[test]
    fn thread_identity_equality_is_the_exact_host_and_thread_pair() {
        let identity = ThreadIdentity::new("host-a", "thread-1");
        let same_identity = ThreadIdentity::new("host-a", "thread-1");
        let different_host = ThreadIdentity::new("host-b", "thread-1");
        let different_thread = ThreadIdentity::new("host-a", "thread-2");

        assert_eq!(identity, same_identity);
        assert_ne!(identity, different_host);
        assert_ne!(identity, different_thread);

        let identities = HashSet::from([identity, same_identity, different_host, different_thread]);
        assert_eq!(identities.len(), 3);
    }

    #[test]
    fn preserved_threads_are_not_selectable() {
        assert!(Classification::ConfirmedDeleted.is_selectable());
        assert!(Classification::ReviewRequired.is_selectable());
        assert!(!Classification::Preserved.is_selectable());
    }

    #[test]
    fn catalog_thread_constructors_enforce_safety_invariants() {
        let preserved = CatalogThread::preserved(
            identity(),
            "Project thread",
            "project",
            false,
            Some("project-1".to_owned()),
            Some(local_path("/workspace/project")),
        );

        assert_eq!(preserved.identity(), &identity());
        assert_eq!(preserved.display_title(), "Project thread");
        assert_eq!(preserved.source_kind(), "project");
        assert_eq!(preserved.project_id(), Some("project-1"));
        assert_eq!(
            preserved.cwd().map(LocalPath::as_path),
            Some(Path::new("/workspace/project"))
        );
        assert!(!preserved.missing_candidate());
        assert_eq!(preserved.classification(), Classification::Preserved);
        assert_eq!(preserved.evidence(), None);

        for error in [
            CatalogThread::review_required(identity(), "Review", "project", true, None, None)
                .expect_err("non-chatgpt review must be rejected"),
            CatalogThread::confirmed_deleted(
                identity(),
                "Confirmed",
                "project",
                true,
                None,
                None,
                evidence(),
            )
            .expect_err("non-chatgpt confirmation must be rejected"),
        ] {
            assert!(matches!(
                error,
                CatalogThreadError::SelectableSourceKind { .. }
            ));
        }

        for project_id in [Some(String::new()), Some("project-1".to_owned())] {
            assert_eq!(
                CatalogThread::review_required(
                    identity(),
                    "Review",
                    "chatgpt",
                    true,
                    project_id,
                    None,
                ),
                Err(CatalogThreadError::ProjectContextRequiresPreserved)
            );
        }

        for cwd in [Some(local_path("")), Some(local_path("/workspace/project"))] {
            assert_eq!(
                CatalogThread::confirmed_deleted(
                    identity(),
                    "Confirmed",
                    "chatgpt",
                    true,
                    None,
                    cwd,
                    evidence(),
                ),
                Err(CatalogThreadError::ProjectContextRequiresPreserved)
            );
        }
    }

    #[test]
    fn catalog_thread_deserialization_rejects_contradictory_states() {
        let missing_evidence = serde_json::json!({
            "identity": { "host_id": "host-a", "thread_id": "thread-1" },
            "display_title": "Confirmed",
            "source_kind": "chatgpt",
            "project_id": null,
            "cwd": null,
            "missing_candidate": true,
            "classification": "confirmed_deleted",
            "evidence": null
        });
        assert!(serde_json::from_value::<CatalogThread>(missing_evidence).is_err());

        for context in [
            serde_json::json!({ "project_id": "", "cwd": null }),
            serde_json::json!({ "project_id": "project-1", "cwd": null }),
            serde_json::json!({ "project_id": null, "cwd": "" }),
            serde_json::json!({ "project_id": null, "cwd": "/workspace/project" }),
        ] {
            let mut contradictory = serde_json::json!({
                "identity": { "host_id": "host-a", "thread_id": "thread-1" },
                "display_title": "Review",
                "source_kind": "chatgpt",
                "project_id": null,
                "cwd": null,
                "missing_candidate": true,
                "classification": "review_required",
                "evidence": null
            });
            contradictory["project_id"] = context["project_id"].clone();
            contradictory["cwd"] = context["cwd"].clone();
            assert!(serde_json::from_value::<CatalogThread>(contradictory).is_err());
        }

        let preserved_with_evidence = serde_json::json!({
            "identity": { "host_id": "host-a", "thread_id": "thread-1" },
            "display_title": "Preserved",
            "source_kind": "chatgpt",
            "project_id": null,
            "cwd": null,
            "missing_candidate": false,
            "classification": "preserved",
            "evidence": {
                "source_path": "/tmp/deletion-evidence.json",
                "reason": "contradictory"
            }
        });
        assert!(serde_json::from_value::<CatalogThread>(preserved_with_evidence).is_err());
    }

    #[test]
    fn local_path_round_trips_stable_utf8_strings() {
        for value in [
            "/tmp/chatgpt/catalog.db",
            r"C:\Users\Alice\ChatGPT\catalog.db",
            r"\\server\share\ChatGPT\catalog.db",
        ] {
            let path = local_path(value);
            assert_eq!(path.as_path(), Path::new(value));

            let json = serde_json::to_string(&path).expect("path must serialize");
            assert_eq!(
                serde_json::from_str::<String>(&json).expect("string must deserialize"),
                value
            );
            assert_eq!(
                serde_json::from_str::<LocalPath>(&json).expect("path must deserialize"),
                path
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn local_path_rejects_non_utf8_unix_paths_with_typed_error() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = PathBuf::from(OsString::from_vec(vec![b'/', b't', b'm', b'p', b'/', 0xff]));
        let error = LocalPath::try_from(path.clone()).expect_err("non-UTF-8 path must fail");

        assert_eq!(error.path(), path.as_path());
    }

    #[test]
    fn persisted_reports_round_trip_versioned_snake_case_wire_format() {
        let thread = CatalogThread::confirmed_deleted(
            identity(),
            "Deleted thread",
            "chatgpt",
            true,
            None,
            None,
            evidence(),
        )
        .expect("valid confirmation");
        let scan = ScanReport::new(
            local_path("/tmp/catalog.db"),
            "codex",
            SchemaReport {
                write_capable: true,
                reason: "known schema".to_owned(),
                fingerprint: "threads:v1".to_owned(),
                columns: vec!["id".to_owned(), "title".to_owned()],
            },
            vec![thread],
            true,
        );

        let scan_json = serde_json::to_value(&scan).expect("scan must serialize");
        assert_eq!(scan.format_version(), SCAN_REPORT_FORMAT_VERSION);
        assert_eq!(scan_json["format_version"], scan.format_version());
        assert_eq!(
            scan_json["threads"][0]["classification"],
            "confirmed_deleted"
        );
        assert_eq!(
            serde_json::from_value::<ScanReport>(scan_json).expect("scan must deserialize"),
            scan
        );

        let receipt = RepairReceipt::new(
            local_path("/tmp/catalog.db"),
            local_path("/tmp/catalog.db.backup"),
            "macos",
            "sha256:abc",
            vec![identity()],
            2,
            1,
        );
        let receipt_json = serde_json::to_value(&receipt).expect("receipt must serialize");
        assert_eq!(receipt.format_version(), REPAIR_RECEIPT_FORMAT_VERSION);
        assert_eq!(receipt_json["format_version"], receipt.format_version());
        assert_eq!(receipt_json["origin_platform"], "macos");
        assert_eq!(
            serde_json::from_value::<RepairReceipt>(receipt_json)
                .expect("receipt must deserialize"),
            receipt
        );
    }

    #[test]
    fn persisted_report_constructors_reject_unsupported_versions() {
        for version in [0, SCAN_REPORT_FORMAT_VERSION + 1] {
            assert!(ScanReport::try_new(
                version,
                local_path("/tmp/catalog.db"),
                "codex",
                SchemaReport {
                    write_capable: false,
                    reason: "test".to_owned(),
                    fingerprint: "test:v1".to_owned(),
                    columns: Vec::new(),
                },
                Vec::new(),
                true,
            )
            .is_err());
        }

        for version in [0, REPAIR_RECEIPT_FORMAT_VERSION + 1] {
            assert!(RepairReceipt::try_new(
                version,
                local_path("/tmp/catalog.db"),
                local_path("/tmp/catalog.db.backup"),
                "macos",
                "sha256:abc",
                Vec::new(),
                1,
                1,
            )
            .is_err());
        }
    }

    #[test]
    fn persisted_reports_accept_current_and_reject_unsupported_literal_fixtures() {
        const CURRENT_SCAN: &str = r#"{"format_version":1,"database_path":"/tmp/catalog.db","platform_label":"codex","schema":{"write_capable":false,"reason":"test","fingerprint":"test:v1","columns":[]},"threads":[],"integrity_ok":true}"#;
        const ZERO_SCAN: &str = r#"{"format_version":0,"database_path":"/tmp/catalog.db","platform_label":"codex","schema":{"write_capable":false,"reason":"test","fingerprint":"test:v1","columns":[]},"threads":[],"integrity_ok":true}"#;
        const FUTURE_SCAN: &str = r#"{"format_version":2,"database_path":"/tmp/catalog.db","platform_label":"codex","schema":{"write_capable":false,"reason":"test","fingerprint":"test:v1","columns":[]},"threads":[],"integrity_ok":true}"#;
        const CURRENT_RECEIPT: &str = r#"{"format_version":1,"database_path":"/tmp/catalog.db","backup_path":"/tmp/catalog.db.backup","origin_platform":"macos","backup_hash":"sha256:abc","removed_identities":[],"before_count":1,"after_count":1}"#;
        const ZERO_RECEIPT: &str = r#"{"format_version":0,"database_path":"/tmp/catalog.db","backup_path":"/tmp/catalog.db.backup","origin_platform":"macos","backup_hash":"sha256:abc","removed_identities":[],"before_count":1,"after_count":1}"#;
        const FUTURE_RECEIPT: &str = r#"{"format_version":2,"database_path":"/tmp/catalog.db","backup_path":"/tmp/catalog.db.backup","origin_platform":"macos","backup_hash":"sha256:abc","removed_identities":[],"before_count":1,"after_count":1}"#;

        let scan = serde_json::from_str::<ScanReport>(CURRENT_SCAN).expect("current scan version");
        assert_eq!(scan.format_version(), SCAN_REPORT_FORMAT_VERSION);
        assert!(serde_json::from_str::<ScanReport>(ZERO_SCAN).is_err());
        assert!(serde_json::from_str::<ScanReport>(FUTURE_SCAN).is_err());

        let receipt = serde_json::from_str::<RepairReceipt>(CURRENT_RECEIPT)
            .expect("current receipt version");
        assert_eq!(receipt.format_version(), REPAIR_RECEIPT_FORMAT_VERSION);
        assert_eq!(receipt.origin_platform, "macos");
        assert!(serde_json::from_str::<RepairReceipt>(ZERO_RECEIPT).is_err());
        assert!(serde_json::from_str::<RepairReceipt>(FUTURE_RECEIPT).is_err());
    }
}
