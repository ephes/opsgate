//! Path containment of step logs (`rust/PLAN.md` 4.12), ported from
//! `app.py:session_artifacts_root_for_ticket`, `is_path_within_root` and
//! `resolve_session_log_path`, with Python's non-strict `Path.resolve()`
//! (`posixpath.realpath(strict=False)` of CPython 3.14, the production
//! interpreter).
//!
//! The resolution walks the path one component at a time like CPython: `..`
//! removes the last resolved component, every other component is looked up
//! with `lstat`, a symbolic link is replaced by its (recursively resolved)
//! target, and a component that cannot be looked up (missing, permission
//! denied, not a directory) is appended as it is, so later components and
//! `..` are still processed. A symbolic link loop leaves the looping link
//! unresolved. This is what "canonicalise the longest existing prefix" in
//! PLAN.md 6.2 has to mean in detail: a missing component followed by `..`
//! must not hide a symbolic link after it.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crate::pytext;

/// Why a step log cannot be shown; the store/web layer maps it to the
/// `ServiceError` of `resolve_session_log_path`.
#[derive(Debug)]
pub enum LogPathError {
    /// 404 `log_not_found`: blank `log_path`, or the resolved path is not an
    /// existing regular file.
    NotFound,
    /// 400 `invalid_log_path`: the resolved path is outside the ticket's
    /// artifact directory.
    OutsideRoot,
    /// The path could not be resolved at all (a NUL character, an unreadable
    /// working directory). Python raises an unhandled exception here, so the
    /// request answers 500.
    Unresolvable(io::Error),
}

impl LogPathError {
    /// The `error` code of the 4xx cases.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::NotFound => Some("log_not_found"),
            Self::OutsideRoot => Some("invalid_log_path"),
            Self::Unresolvable(_) => None,
        }
    }

    /// The HTTP status Python answers with.
    pub fn status(&self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::OutsideRoot => 400,
            Self::Unresolvable(_) => 500,
        }
    }
}

impl fmt::Display for LogPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("Log file is not available for this step"),
            Self::OutsideRoot => f.write_str("Log file path is outside the ticket artifact root"),
            Self::Unresolvable(error) => write!(f, "Log file path cannot be resolved: {error}"),
        }
    }
}

impl std::error::Error for LogPathError {}

/// Python `Path(path).resolve()` (non-strict): absolute, symbolic links
/// resolved where they exist, `.`/`..`/empty components removed. Relative
/// paths are resolved against the current working directory.
pub fn resolve(path: &Path) -> io::Result<PathBuf> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&0) {
        // os.lstat raises ValueError("embedded null byte"), which realpath
        // does not ignore.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL byte",
        ));
    }
    let mut resolved: Vec<u8> = if bytes.starts_with(b"/") {
        b"/".to_vec()
    } else {
        std::env::current_dir()?.into_os_string().into_vec()
    };

    // Unprocessed components in reverse order; `Marker` follows a symbolic
    // link's own path and records its resolution once its target is done.
    enum Part {
        Name(Vec<u8>),
        Marker(Vec<u8>),
    }
    let mut rest: Vec<Part> = bytes
        .split(|b| *b == b'/')
        .rev()
        .map(|part| Part::Name(part.to_vec()))
        .collect();
    // Symbolic link path → fully resolved target, `None` while resolving.
    let mut seen: HashMap<Vec<u8>, Option<Vec<u8>>> = HashMap::new();

    while let Some(part) = rest.pop() {
        let name = match part {
            Part::Marker(link) => {
                seen.insert(link, Some(resolved.clone()));
                continue;
            }
            Part::Name(name) => name,
        };
        if name.is_empty() || name == b"." {
            continue;
        }
        if name == b".." {
            let cut = resolved.iter().rposition(|b| *b == b'/').unwrap_or(0);
            resolved.truncate(cut.max(1));
            continue;
        }
        let mut candidate = resolved.clone();
        if candidate != b"/" {
            candidate.push(b'/');
        }
        candidate.extend_from_slice(&name);
        let candidate_path = Path::new(OsStr::from_bytes(&candidate));
        let metadata = match std::fs::symlink_metadata(candidate_path) {
            Ok(metadata) => metadata,
            Err(_) => {
                // Non-strict: an error is ignored and the component kept.
                resolved = candidate;
                continue;
            }
        };
        if !metadata.file_type().is_symlink() {
            resolved = candidate;
            continue;
        }
        if let Some(known) = seen.get(&candidate) {
            // `None`: a loop; keep the link path unresolved.
            resolved = known.clone().unwrap_or(candidate);
            continue;
        }
        let target = match std::fs::read_link(candidate_path) {
            Ok(target) => target.into_os_string().into_vec(),
            Err(_) => {
                resolved = candidate;
                continue;
            }
        };
        if target.starts_with(b"/") {
            resolved = b"/".to_vec();
        }
        seen.insert(candidate.clone(), None);
        rest.push(Part::Marker(candidate));
        rest.extend(
            target
                .split(|b| *b == b'/')
                .rev()
                .map(|part| Part::Name(part.to_vec())),
        );
    }
    Ok(PathBuf::from(OsString::from_vec(resolved)))
}

/// `PurePath.relative_to` succeeding: `candidate` is `root` or below it,
/// compared component by component.
pub fn is_path_within_root(root: &Path, candidate: &Path) -> bool {
    candidate.starts_with(root)
}

/// `(Path(execution_data_dir) / "sessions" / ticket_id).resolve()`. As with
/// Python's `/`, an absolute `ticket_id` replaces the base.
pub fn session_artifacts_root(execution_data_dir: &str, ticket_id: &str) -> io::Result<PathBuf> {
    resolve(
        &Path::new(execution_data_dir)
            .join("sessions")
            .join(ticket_id),
    )
}

/// `resolve_session_log_path`: `raw_log_path` is the session entry's
/// `log_path` after Python's `str()` (the caller converts the JSON value; an
/// absent key is `""`). Order (P1): blank → not found; resolve; outside the
/// ticket's artifact root → outside; not an existing regular file → not
/// found.
pub fn resolve_session_log_path(
    execution_data_dir: &str,
    ticket_id: &str,
    raw_log_path: &str,
) -> Result<PathBuf, LogPathError> {
    let raw = pytext::strip(raw_log_path);
    if raw.is_empty() {
        return Err(LogPathError::NotFound);
    }
    let log_path = resolve(Path::new(raw)).map_err(LogPathError::Unresolvable)?;
    let root = session_artifacts_root(execution_data_dir, ticket_id)
        .map_err(LogPathError::Unresolvable)?;
    if !is_path_within_root(&root, &log_path) {
        return Err(LogPathError::OutsideRoot);
    }
    // `exists()` and `is_file()` follow symbolic links and treat every error
    // as false.
    match std::fs::metadata(&log_path) {
        Ok(metadata) if metadata.is_file() => Ok(log_path),
        _ => Err(LogPathError::NotFound),
    }
}
