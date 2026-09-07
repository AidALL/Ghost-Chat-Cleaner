use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use thiserror::Error;

use crate::file_guard::{identity_from_file_metadata, identity_from_path_metadata, FileIdentity};
use crate::model::{DeletionEvidence, LocalPath, NonUtf8PathError};

pub const DEFAULT_EVIDENCE_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
pub const MAX_EVIDENCE_FILE_BYTES: u64 = 25 * 1024 * 1024;
pub const MAX_TOTAL_EVIDENCE_BYTES: u64 = 80 * 1024 * 1024;
pub const DELETION_EVIDENCE_REASON: &str = "exact same-line deletion marker";

const MAX_THREAD_ID_BYTES: usize = 128;
const MAX_THREAD_IDS: usize = 10_000;
const MAX_DISCOVERED_ENTRIES: usize = 100_000;
const MAX_BOUNDARY_VALIDATIONS: usize = MAX_DISCOVERED_ENTRIES * 3;
const ALLOWED_EXTENSIONS: [&str; 5] = ["log", "txt", "json", "jsonl", "ndjson"];

#[derive(Clone, Debug)]
pub struct EvidenceScanConfig {
    allowlisted_roots: Vec<PathBuf>,
    explicit_roots: Vec<PathBuf>,
    now: SystemTime,
    max_age: Duration,
}

impl EvidenceScanConfig {
    pub fn new(allowlisted_roots: Vec<PathBuf>, explicit_roots: Vec<PathBuf>) -> Self {
        Self {
            allowlisted_roots,
            explicit_roots,
            now: SystemTime::now(),
            max_age: DEFAULT_EVIDENCE_MAX_AGE,
        }
    }

    pub fn at_time(mut self, now: SystemTime) -> Self {
        self.now = now;
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct EvidenceIndex {
    by_thread_id: BTreeMap<String, DeletionEvidence>,
}

impl EvidenceIndex {
    pub fn evidence_for(&self, thread_id: &str) -> Option<&DeletionEvidence> {
        self.by_thread_id.get(thread_id)
    }

    pub fn is_empty(&self) -> bool {
        self.by_thread_id.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_thread_id.len()
    }
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("could not inspect evidence path {path:?}: {source}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not enumerate evidence directory {path:?}: {source}")]
    ReadDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("evidence path is a symlink: {path:?}")]
    SymlinkRefused { path: PathBuf },
    #[error("evidence root is neither a regular file nor a directory: {path:?}")]
    UnsupportedRootType { path: PathBuf },
    #[error("native file identity is unavailable for evidence path {path:?}: {source}")]
    FileIdentityUnavailable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("evidence file {path:?} exceeds the {limit}-byte per-file limit")]
    FileTooLarge {
        path: PathBuf,
        size: u64,
        limit: u64,
    },
    #[error("eligible evidence files exceed the {limit}-byte total limit")]
    TotalSizeExceeded { total: u64, limit: u64 },
    #[error("evidence traversal exceeded the {limit}-entry limit")]
    TooManyEntries { limit: usize },
    #[error("evidence boundary validation exceeded the {limit}-operation limit")]
    BoundaryValidationLimitExceeded { limit: usize },
    #[error("evidence path changed during traversal: {path:?}")]
    PathChanged { path: PathBuf },
    #[error("evidence path {path:?} escaped canonical root {root:?}")]
    EscapedRoot { path: PathBuf, root: PathBuf },
    #[error("evidence file changed after discovery: {path:?}")]
    FileChangedAfterDiscovery { path: PathBuf },
    #[error("reading evidence file {path:?} exceeded the {limit}-byte per-file limit")]
    FileReadLimitExceeded { path: PathBuf, limit: u64 },
    #[error("reading evidence files exceeded the {limit}-byte aggregate limit")]
    TotalReadLimitExceeded { limit: u64 },
    #[error("could not read evidence file {path:?}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("thread identifier is not a bounded ASCII identifier (length {length})")]
    InvalidThreadId { length: usize },
    #[error("too many thread identifiers; maximum is {limit}")]
    TooManyThreadIds { limit: usize },
    #[error(transparent)]
    NonUtf8Path(#[from] NonUtf8PathError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EvidenceFileMetadataSnapshot {
    identity: FileIdentity,
    length: u64,
    modified: SystemTime,
}

#[derive(Clone, Debug)]
struct DiscoveredEvidenceFile {
    path: PathBuf,
    canonical_path: PathBuf,
    canonical_root: PathBuf,
    directory_guard: Option<Arc<EvidenceDirectoryGuard>>,
    metadata: EvidenceFileMetadataSnapshot,
}

#[derive(Clone, Debug)]
struct EvidenceDirectoryGuard {
    path: PathBuf,
    canonical_path: PathBuf,
    metadata: EvidenceFileMetadataSnapshot,
    parent: Option<Arc<EvidenceDirectoryGuard>>,
}

#[derive(Debug)]
struct EvidenceTraversalEntry {
    path: PathBuf,
    canonical_path: PathBuf,
    canonical_root: PathBuf,
    directory_guard: Option<Arc<EvidenceDirectoryGuard>>,
    metadata: fs::Metadata,
}

pub fn discover_evidence_files(config: &EvidenceScanConfig) -> Result<Vec<PathBuf>, EvidenceError> {
    Ok(
        discover_evidence_records_with_limit(config, MAX_DISCOVERED_ENTRIES)?
            .into_iter()
            .map(|record| record.path)
            .collect(),
    )
}

fn discover_evidence_records_with_limit(
    config: &EvidenceScanConfig,
    max_entries: usize,
) -> Result<Vec<DiscoveredEvidenceFile>, EvidenceError> {
    discover_evidence_records_with_limit_and_before_read_dir(config, max_entries, |_| {})
}

fn discover_evidence_records_with_limit_and_before_read_dir<F>(
    config: &EvidenceScanConfig,
    max_entries: usize,
    mut before_read_dir: F,
) -> Result<Vec<DiscoveredEvidenceFile>, EvidenceError>
where
    F: FnMut(&Path),
{
    let mut roots =
        Vec::with_capacity(config.allowlisted_roots.len() + config.explicit_roots.len());
    roots.extend(config.allowlisted_roots.iter().cloned());
    roots.extend(config.explicit_roots.iter().cloned());

    let mut seen_roots = HashSet::with_capacity(roots.len());
    roots.retain(|path| seen_roots.insert(path.clone()));

    let mut stack = Vec::new();
    let mut inspected_entries = 0_usize;
    for root in roots {
        let metadata = match fs::symlink_metadata(&root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => return Err(EvidenceError::Metadata { path: root, source }),
        };
        charge_entry_budget(&mut inspected_entries, max_entries)?;
        if metadata.file_type().is_symlink() {
            return Err(EvidenceError::SymlinkRefused { path: root });
        }
        if !metadata.is_dir() && !metadata.is_file() {
            return Err(EvidenceError::UnsupportedRootType { path: root });
        }
        let canonical_root = canonicalize_evidence_path(&root)?;
        let canonical_path = canonical_root.clone();
        let directory_guard = if metadata.is_dir() {
            Some(Arc::new(EvidenceDirectoryGuard {
                path: root.clone(),
                canonical_path: canonical_path.clone(),
                metadata: EvidenceFileMetadataSnapshot::from_path_metadata(&root, &metadata)?,
                parent: None,
            }))
        } else {
            None
        };
        stack.push(EvidenceTraversalEntry {
            path: root,
            canonical_path,
            canonical_root,
            directory_guard,
            metadata,
        });
    }

    let mut seen_paths = HashSet::new();
    let mut files = Vec::new();
    let mut total_size = 0_u64;

    while let Some(entry) = stack.pop() {
        let EvidenceTraversalEntry {
            path,
            canonical_path,
            canonical_root,
            directory_guard,
            metadata,
        } = entry;
        if !seen_paths.insert(path.clone()) {
            continue;
        }

        if metadata.file_type().is_symlink() {
            return Err(EvidenceError::SymlinkRefused { path });
        }
        if metadata.is_dir() {
            before_read_dir(&path);
            let current_directory_guard = directory_guard
                .as_deref()
                .ok_or_else(|| EvidenceError::PathChanged { path: path.clone() })?;
            validate_directory_guard(current_directory_guard, &canonical_root)?;
            let entries = fs::read_dir(&path).map_err(|source| EvidenceError::ReadDirectory {
                path: path.clone(),
                source,
            })?;
            let mut children = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|source| EvidenceError::ReadDirectory {
                    path: path.clone(),
                    source,
                })?;
                charge_entry_budget(&mut inspected_entries, max_entries)?;
                let child_path = entry.path();
                let child_metadata = fs::symlink_metadata(&child_path).map_err(|source| {
                    EvidenceError::Metadata {
                        path: child_path.clone(),
                        source,
                    }
                })?;
                if child_metadata.file_type().is_symlink() {
                    return Err(EvidenceError::SymlinkRefused { path: child_path });
                }
                let child_canonical_path = canonicalize_within_root(&child_path, &canonical_root)?;
                let child_directory_guard = if child_metadata.is_dir() {
                    Some(Arc::new(EvidenceDirectoryGuard {
                        path: child_path.clone(),
                        canonical_path: child_canonical_path.clone(),
                        metadata: EvidenceFileMetadataSnapshot::from_path_metadata(
                            &child_path,
                            &child_metadata,
                        )?,
                        parent: directory_guard.clone(),
                    }))
                } else {
                    directory_guard.clone()
                };
                children.push(EvidenceTraversalEntry {
                    path: child_path,
                    canonical_path: child_canonical_path,
                    canonical_root: canonical_root.clone(),
                    directory_guard: child_directory_guard,
                    metadata: child_metadata,
                });
            }
            children.sort_by(|left, right| left.path.cmp(&right.path));
            stack.extend(children.into_iter().rev());
            continue;
        }
        if !metadata.is_file() || !has_allowed_extension(&path) {
            continue;
        }

        let metadata = EvidenceFileMetadataSnapshot::from_path_metadata(&path, &metadata)?;
        let age = config
            .now
            .duration_since(metadata.modified)
            .unwrap_or(Duration::ZERO);
        if age > config.max_age {
            continue;
        }

        let size = metadata.length;
        if size > MAX_EVIDENCE_FILE_BYTES {
            return Err(EvidenceError::FileTooLarge {
                path,
                size,
                limit: MAX_EVIDENCE_FILE_BYTES,
            });
        }
        total_size = total_size
            .checked_add(size)
            .ok_or(EvidenceError::TotalSizeExceeded {
                total: u64::MAX,
                limit: MAX_TOTAL_EVIDENCE_BYTES,
            })?;
        if total_size > MAX_TOTAL_EVIDENCE_BYTES {
            return Err(EvidenceError::TotalSizeExceeded {
                total: total_size,
                limit: MAX_TOTAL_EVIDENCE_BYTES,
            });
        }
        files.push(DiscoveredEvidenceFile {
            path,
            canonical_path,
            canonical_root,
            directory_guard,
            metadata,
        });
    }

    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

pub fn scan_deletion_evidence(
    config: &EvidenceScanConfig,
    thread_ids: &[&str],
) -> Result<EvidenceIndex, EvidenceError> {
    scan_deletion_evidence_with_boundary_limit(config, thread_ids, MAX_BOUNDARY_VALIDATIONS)
}

fn scan_deletion_evidence_with_boundary_limit(
    config: &EvidenceScanConfig,
    thread_ids: &[&str],
    boundary_validation_limit: usize,
) -> Result<EvidenceIndex, EvidenceError> {
    if thread_ids.len() > MAX_THREAD_IDS {
        return Err(EvidenceError::TooManyThreadIds {
            limit: MAX_THREAD_IDS,
        });
    }

    let mut wanted = HashSet::with_capacity(thread_ids.len());
    for thread_id in thread_ids {
        if !is_valid_thread_id(thread_id) {
            return Err(EvidenceError::InvalidThreadId {
                length: thread_id.len(),
            });
        }
        wanted.insert((*thread_id).to_owned());
    }

    let mut by_thread_id = BTreeMap::new();
    let mut total_bytes_read = 0_u64;
    let mut boundary_budget = BoundaryValidationBudget::new(boundary_validation_limit);
    for discovered in discover_evidence_records_with_limit(config, MAX_DISCOVERED_ENTRIES)? {
        if by_thread_id.len() == wanted.len() {
            break;
        }
        let path = &discovered.path;
        let file =
            open_validated_evidence_file_with_budget(&discovered, config, &mut boundary_budget)?;
        let remaining_total = MAX_TOTAL_EVIDENCE_BYTES.saturating_sub(total_bytes_read);
        let read_limit = MAX_EVIDENCE_FILE_BYTES.min(remaining_total);
        let limited_file = file.take(read_limit + 1);
        let mut reader = BufReader::new(limited_file);
        let mut file_bytes_read = 0_u64;
        let mut line = String::new();
        loop {
            line.clear();
            let bytes = reader
                .read_line(&mut line)
                .map_err(|source| EvidenceError::ReadFile {
                    path: path.clone(),
                    source,
                })?;
            if bytes == 0 {
                break;
            }
            let bytes = bytes as u64;
            file_bytes_read = file_bytes_read.saturating_add(bytes);
            total_bytes_read = total_bytes_read.saturating_add(bytes);
            if file_bytes_read > MAX_EVIDENCE_FILE_BYTES {
                return Err(EvidenceError::FileReadLimitExceeded {
                    path: path.clone(),
                    limit: MAX_EVIDENCE_FILE_BYTES,
                });
            }
            if total_bytes_read > MAX_TOTAL_EVIDENCE_BYTES {
                return Err(EvidenceError::TotalReadLimitExceeded {
                    limit: MAX_TOTAL_EVIDENCE_BYTES,
                });
            }
            if !has_deletion_marker(&line) {
                continue;
            }

            for token in line.split(|character: char| !is_identifier_character(character)) {
                if wanted.contains(token) && !by_thread_id.contains_key(token) {
                    by_thread_id.insert(
                        token.to_owned(),
                        DeletionEvidence {
                            source_path: LocalPath::try_from(path.as_path())?,
                            reason: DELETION_EVIDENCE_REASON.to_owned(),
                        },
                    );
                }
            }
        }
        let file = reader.into_inner().into_inner();
        verify_open_evidence_file_unchanged(&discovered, &file, config, &mut boundary_budget)?;
    }

    Ok(EvidenceIndex { by_thread_id })
}

fn charge_entry_budget(count: &mut usize, limit: usize) -> Result<(), EvidenceError> {
    *count = count.saturating_add(1);
    if *count > limit {
        Err(EvidenceError::TooManyEntries { limit })
    } else {
        Ok(())
    }
}

struct BoundaryValidationBudget {
    used: usize,
    limit: usize,
}

impl BoundaryValidationBudget {
    fn new(limit: usize) -> Self {
        Self { used: 0, limit }
    }

    fn charge(&mut self) -> Result<(), EvidenceError> {
        self.used = self.used.saturating_add(1);
        if self.used > self.limit {
            Err(EvidenceError::BoundaryValidationLimitExceeded { limit: self.limit })
        } else {
            Ok(())
        }
    }
}

fn canonicalize_evidence_path(path: &Path) -> Result<PathBuf, EvidenceError> {
    fs::canonicalize(path).map_err(|_| EvidenceError::PathChanged {
        path: path.to_path_buf(),
    })
}

fn canonicalize_within_root(path: &Path, canonical_root: &Path) -> Result<PathBuf, EvidenceError> {
    let canonical_path = canonicalize_evidence_path(path)?;
    if canonical_path.starts_with(canonical_root) {
        Ok(canonical_path)
    } else {
        Err(EvidenceError::EscapedRoot {
            path: path.to_path_buf(),
            root: canonical_root.to_path_buf(),
        })
    }
}

fn validate_directory_guard(
    guard: &EvidenceDirectoryGuard,
    canonical_root: &Path,
) -> Result<(), EvidenceError> {
    // This binds each queued directory to the best portable path and metadata
    // signals available. It narrows ancestor-swap races but is not an atomic
    // directory-handle traversal guarantee.
    let canonical_path = canonicalize_within_root(&guard.path, canonical_root)?;
    if canonical_path != guard.canonical_path {
        return Err(EvidenceError::PathChanged {
            path: guard.path.clone(),
        });
    }
    let metadata = fs::symlink_metadata(&guard.path).map_err(|_| EvidenceError::PathChanged {
        path: guard.path.clone(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(EvidenceError::PathChanged {
            path: guard.path.clone(),
        });
    }
    if EvidenceFileMetadataSnapshot::from_path_metadata(&guard.path, &metadata)? != guard.metadata {
        return Err(EvidenceError::PathChanged {
            path: guard.path.clone(),
        });
    }
    Ok(())
}

fn validate_discovered_canonical_path(
    discovered: &DiscoveredEvidenceFile,
) -> Result<(), EvidenceError> {
    let canonical_path = canonicalize_within_root(&discovered.path, &discovered.canonical_root)?;
    if canonical_path != discovered.canonical_path {
        return Err(EvidenceError::PathChanged {
            path: discovered.path.clone(),
        });
    }
    Ok(())
}

fn validate_discovered_directories(
    discovered: &DiscoveredEvidenceFile,
    boundary_budget: &mut BoundaryValidationBudget,
) -> Result<(), EvidenceError> {
    let mut current = discovered.directory_guard.as_deref();
    while let Some(guard) = current {
        boundary_budget.charge()?;
        validate_directory_guard(guard, &discovered.canonical_root)?;
        current = guard.parent.as_deref();
    }
    Ok(())
}

#[cfg(test)]
fn open_validated_evidence_file(
    discovered: &DiscoveredEvidenceFile,
    config: &EvidenceScanConfig,
) -> Result<File, EvidenceError> {
    let mut boundary_budget = BoundaryValidationBudget::new(MAX_BOUNDARY_VALIDATIONS);
    open_validated_evidence_file_with_budget(discovered, config, &mut boundary_budget)
}

fn open_validated_evidence_file_with_budget(
    discovered: &DiscoveredEvidenceFile,
    config: &EvidenceScanConfig,
    boundary_budget: &mut BoundaryValidationBudget,
) -> Result<File, EvidenceError> {
    validate_discovered_canonical_path(discovered)?;
    let path_metadata = metadata_immediately_before_open(&discovered.path, config)?;
    if path_metadata != discovered.metadata {
        return Err(EvidenceError::FileChangedAfterDiscovery {
            path: discovered.path.clone(),
        });
    }
    validate_discovered_directories(discovered, boundary_budget)?;

    let file = File::open(&discovered.path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            EvidenceError::FileChangedAfterDiscovery {
                path: discovered.path.clone(),
            }
        } else {
            EvidenceError::ReadFile {
                path: discovered.path.clone(),
                source,
            }
        }
    })?;
    verify_open_evidence_file_unchanged(discovered, &file, config, boundary_budget)?;
    Ok(file)
}

fn verify_open_evidence_file_unchanged(
    discovered: &DiscoveredEvidenceFile,
    file: &File,
    config: &EvidenceScanConfig,
    boundary_budget: &mut BoundaryValidationBudget,
) -> Result<(), EvidenceError> {
    validate_discovered_canonical_path(discovered)?;
    let handle_metadata = file.metadata().map_err(|source| EvidenceError::ReadFile {
        path: discovered.path.clone(),
        source,
    })?;
    if !handle_metadata.is_file() {
        return Err(EvidenceError::FileChangedAfterDiscovery {
            path: discovered.path.clone(),
        });
    }
    let handle_metadata =
        EvidenceFileMetadataSnapshot::from_file_metadata(&discovered.path, file, &handle_metadata)?;
    let path_metadata = metadata_immediately_before_open(&discovered.path, config)?;
    if handle_metadata != discovered.metadata || path_metadata != discovered.metadata {
        return Err(EvidenceError::FileChangedAfterDiscovery {
            path: discovered.path.clone(),
        });
    }
    validate_discovered_directories(discovered, boundary_budget)?;
    Ok(())
}

fn metadata_immediately_before_open(
    path: &Path,
    config: &EvidenceScanConfig,
) -> Result<EvidenceFileMetadataSnapshot, EvidenceError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(EvidenceError::FileChangedAfterDiscovery {
                path: path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(EvidenceError::Metadata {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(EvidenceError::SymlinkRefused {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_file() {
        return Err(EvidenceError::FileChangedAfterDiscovery {
            path: path.to_path_buf(),
        });
    }
    let metadata = EvidenceFileMetadataSnapshot::from_path_metadata(path, &metadata)?;
    if metadata.length > MAX_EVIDENCE_FILE_BYTES {
        return Err(EvidenceError::FileTooLarge {
            path: path.to_path_buf(),
            size: metadata.length,
            limit: MAX_EVIDENCE_FILE_BYTES,
        });
    }
    let age = config
        .now
        .duration_since(metadata.modified)
        .unwrap_or(Duration::ZERO);
    if age > config.max_age {
        return Err(EvidenceError::FileChangedAfterDiscovery {
            path: path.to_path_buf(),
        });
    }
    Ok(metadata)
}

impl EvidenceFileMetadataSnapshot {
    fn from_path_metadata(path: &Path, metadata: &fs::Metadata) -> Result<Self, EvidenceError> {
        let modified = metadata
            .modified()
            .map_err(|source| EvidenceError::Metadata {
                path: path.to_path_buf(),
                source,
            })?;
        Ok(Self {
            identity: identity_from_path_metadata(path, metadata).map_err(|source| {
                EvidenceError::FileIdentityUnavailable {
                    path: path.to_path_buf(),
                    source,
                }
            })?,
            length: metadata.len(),
            modified,
        })
    }

    fn from_file_metadata(
        path: &Path,
        file: &File,
        metadata: &fs::Metadata,
    ) -> Result<Self, EvidenceError> {
        let modified = metadata
            .modified()
            .map_err(|source| EvidenceError::Metadata {
                path: path.to_path_buf(),
                source,
            })?;
        Ok(Self {
            identity: identity_from_file_metadata(file, metadata).map_err(|source| {
                EvidenceError::FileIdentityUnavailable {
                    path: path.to_path_buf(),
                    source,
                }
            })?,
            length: metadata.len(),
            modified,
        })
    }
}

pub fn is_valid_thread_id(thread_id: &str) -> bool {
    !thread_id.is_empty()
        && thread_id.len() <= MAX_THREAD_ID_BYTES
        && thread_id.bytes().all(is_identifier_byte)
}

fn has_allowed_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            ALLOWED_EXTENSIONS
                .iter()
                .any(|allowed| extension.eq_ignore_ascii_case(allowed))
        })
        .unwrap_or(false)
}

fn has_deletion_marker(line: &str) -> bool {
    contains_bounded_marker(line, "conversation_deleted")
        || contains_bounded_marker(line, "conversation deleted")
}

fn contains_bounded_marker(line: &str, marker: &str) -> bool {
    line.match_indices(marker).any(|(start, _)| {
        let end = start + marker.len();
        let starts_at_boundary = line[..start]
            .chars()
            .next_back()
            .map(|character| !is_identifier_character(character))
            .unwrap_or(true);
        let ends_at_boundary = line[end..]
            .chars()
            .next()
            .map(|character| !is_identifier_character(character))
            .unwrap_or(true);
        starts_at_boundary && ends_at_boundary
    })
}

fn is_identifier_character(character: char) -> bool {
    character.is_ascii() && is_identifier_byte(character as u8)
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(root: &Path) -> EvidenceScanConfig {
        EvidenceScanConfig::new(vec![root.to_path_buf()], Vec::new())
    }

    #[test]
    fn evidence_open_rejects_replacement_after_discovery() {
        let directory = tempfile::tempdir().expect("create evidence replacement fixture");
        let path = directory.path().join("events.log");
        fs::write(&path, b"original\n").expect("write original evidence");
        let config = config(directory.path());
        let discovered =
            discover_evidence_records_with_limit(&config, 10).expect("discover original evidence");

        // Keep the original allocated so the replacement cannot reuse its identity.
        fs::rename(&path, directory.path().join("original-evidence"))
            .expect("move original evidence aside");
        fs::write(&path, b"replaced\n").expect("write replacement evidence");
        File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(discovered[0].metadata.modified))
            .expect("match original evidence modification time");
        let replacement_metadata =
            metadata_immediately_before_open(&path, &config).expect("inspect replacement evidence");
        assert_ne!(
            replacement_metadata.identity, discovered[0].metadata.identity,
            "replacement fixture must have a distinct native file identity"
        );
        assert_eq!(replacement_metadata.length, discovered[0].metadata.length);
        assert_eq!(
            replacement_metadata.modified,
            discovered[0].metadata.modified
        );

        let result = open_validated_evidence_file(&discovered[0], &config);
        assert!(
            matches!(result, Err(EvidenceError::FileChangedAfterDiscovery { .. })),
            "distinct-identity replacement must be rejected: {result:?}"
        );
    }

    #[test]
    fn evidence_open_rejects_file_that_grew_past_limit_after_discovery() {
        let directory = tempfile::tempdir().expect("create evidence growth fixture");
        let path = directory.path().join("events.log");
        fs::write(&path, b"small\n").expect("write initial evidence");
        let config = config(directory.path());
        let discovered =
            discover_evidence_records_with_limit(&config, 10).expect("discover initial evidence");

        File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_len(MAX_EVIDENCE_FILE_BYTES + 1))
            .expect("grow evidence past limit");
        assert!(matches!(
            open_validated_evidence_file(&discovered[0], &config),
            Err(EvidenceError::FileTooLarge { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn evidence_open_rejects_an_ancestor_swapped_to_an_external_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("create ancestor-swap fixture");
        let root = directory.path().join("root");
        let original = root.join("nested");
        let external = directory.path().join("external");
        fs::create_dir_all(&original).expect("create original evidence directory");
        fs::create_dir_all(&external).expect("create external evidence directory");
        fs::write(original.join("events.log"), b"original\n").expect("write original evidence");
        fs::write(external.join("events.log"), b"external\n").expect("write external evidence");
        let config = config(&root);
        let discovered =
            discover_evidence_records_with_limit(&config, 10).expect("discover original evidence");

        fs::rename(&original, root.join("original-nested")).expect("move original directory aside");
        symlink(&external, &original).expect("replace ancestor with external symlink");

        assert!(matches!(
            open_validated_evidence_file(&discovered[0], &config),
            Err(EvidenceError::EscapedRoot { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn evidence_discovery_rejects_a_directory_swapped_before_read_dir() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("create read-dir swap fixture");
        let root = directory.path().join("root");
        let nested = root.join("nested");
        let external = directory.path().join("external");
        fs::create_dir_all(&nested).expect("create nested evidence directory");
        fs::create_dir_all(&external).expect("create external evidence directory");
        fs::write(nested.join("events.log"), b"original\n").expect("write nested evidence");
        fs::write(external.join("events.log"), b"external\n").expect("write external evidence");
        let config = config(&root);
        let mut swapped = false;

        let result = discover_evidence_records_with_limit_and_before_read_dir(
            &config,
            10,
            |directory_path| {
                if !swapped && directory_path == nested {
                    fs::rename(&nested, root.join("original-nested"))
                        .expect("move nested directory aside");
                    symlink(&external, &nested).expect("replace nested directory with symlink");
                    swapped = true;
                }
            },
        );
        assert!(swapped, "fixture hook must run for the queued directory");
        assert!(matches!(result, Err(EvidenceError::EscapedRoot { .. })));
    }

    #[test]
    fn boundary_validation_budget_is_shared_across_a_scan() {
        let directory = tempfile::tempdir().expect("create validation-budget fixture");
        let path = directory.path().join("events.log");
        fs::write(&path, b"conversation_deleted thread-a\n")
            .expect("write validation-budget evidence");
        let config = config(directory.path());

        scan_deletion_evidence_with_boundary_limit(&config, &["thread-a"], 3)
            .expect("three root validations are the exact one-file boundary");
        assert!(matches!(
            scan_deletion_evidence_with_boundary_limit(&config, &["thread-a"], 2),
            Err(EvidenceError::BoundaryValidationLimitExceeded { limit: 2 })
        ));
    }

    #[test]
    fn directory_entry_budget_accepts_boundary_and_rejects_cap_plus_one() {
        let directory = tempfile::tempdir().expect("create entry budget fixture");
        fs::write(directory.path().join("one.log"), b"one\n").expect("write first evidence");
        fs::write(directory.path().join("two.log"), b"two\n").expect("write second evidence");
        let config = config(directory.path());

        assert_eq!(
            discover_evidence_records_with_limit(&config, 3)
                .expect("root plus two entries is the boundary")
                .len(),
            2
        );
        assert!(matches!(
            discover_evidence_records_with_limit(&config, 2),
            Err(EvidenceError::TooManyEntries { limit: 2 })
        ));
    }
}
