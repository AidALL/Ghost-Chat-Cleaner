use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::PathBuf;

use thiserror::Error;

const CATALOG_RELATIVE_PATH: &str = "sqlite/codex-dev.db";
const HOME_CATALOG_RELATIVE_PATH: &str = ".codex/sqlite/codex-dev.db";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PlatformPolicy {
    Windows,
    MacOs,
    Linux,
    Unsupported,
}

impl PlatformPolicy {
    pub const fn current() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(target_os = "macos")]
        {
            Self::MacOs
        }
        #[cfg(target_os = "linux")]
        {
            Self::Linux
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            Self::Unsupported
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::MacOs => "macos",
            Self::Linux => "linux",
            Self::Unsupported => "unsupported",
        }
    }

    pub const fn allows_mutation(self) -> bool {
        matches!(self, Self::Windows | Self::MacOs)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CatalogPathInputs {
    pub explicit_path: Option<PathBuf>,
    pub codex_home: Option<PathBuf>,
    pub home: Option<PathBuf>,
}

#[derive(Debug, Error)]
pub enum PathDiscoveryError {
    #[error("could not inspect catalog candidate {path:?}: {source}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("catalog candidate is a symlink: {path:?}")]
    SymlinkRefused { path: PathBuf },
    #[error("catalog candidate is not a regular file: {path:?}")]
    NotRegularFile { path: PathBuf },
}

pub fn discover_database_candidates(
    inputs: &CatalogPathInputs,
) -> Result<Vec<PathBuf>, PathDiscoveryError> {
    let mut candidates = Vec::with_capacity(3);
    if let Some(path) = &inputs.explicit_path {
        candidates.push(path.clone());
    }
    if let Some(codex_home) = &inputs.codex_home {
        candidates.push(codex_home.join(CATALOG_RELATIVE_PATH));
    }
    if let Some(home) = &inputs.home {
        candidates.push(home.join(HOME_CATALOG_RELATIVE_PATH));
    }

    let mut seen_inputs = HashSet::with_capacity(candidates.len());
    let mut seen_targets = HashSet::with_capacity(candidates.len());
    let mut discovered = Vec::with_capacity(candidates.len());
    for path in candidates {
        if !seen_inputs.insert(path.clone()) {
            continue;
        }

        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => return Err(PathDiscoveryError::Metadata { path, source }),
        };
        if metadata.file_type().is_symlink() {
            return Err(PathDiscoveryError::SymlinkRefused { path });
        }
        if !metadata.is_file() {
            return Err(PathDiscoveryError::NotRegularFile { path });
        }

        let canonical_path =
            fs::canonicalize(&path).map_err(|source| PathDiscoveryError::Metadata {
                path: path.clone(),
                source,
            })?;
        let canonical_metadata = fs::symlink_metadata(&canonical_path).map_err(|source| {
            PathDiscoveryError::Metadata {
                path: canonical_path.clone(),
                source,
            }
        })?;
        if canonical_metadata.file_type().is_symlink() {
            return Err(PathDiscoveryError::SymlinkRefused {
                path: canonical_path,
            });
        }
        if !canonical_metadata.is_file() {
            return Err(PathDiscoveryError::NotRegularFile {
                path: canonical_path,
            });
        }
        if seen_targets.insert(canonical_path.clone()) {
            discovered.push(canonical_path);
        }
    }

    Ok(discovered)
}

pub fn discover_catalog_paths(
    inputs: &CatalogPathInputs,
) -> Result<Vec<PathBuf>, PathDiscoveryError> {
    discover_database_candidates(inputs)
}
