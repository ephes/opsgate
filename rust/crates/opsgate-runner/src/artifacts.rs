//! Artifact paths and writes (PLAN.md 4.13.2, 4.13.7).
//!
//! JSON artifacts (`context.json`, `session_metadata.json`, `summary.json`)
//! and runner state files are published by same-directory atomic
//! replacement of a 0600 temporary file (`_atomic_write_json`): on any
//! failure the destination is untouched and the temporary file is removed,
//! and a failing removal never replaces the original error. The JSON text is
//! `json.dump(payload, sort_keys=True, indent=2)` plus a newline in Python;
//! here `serde_json`'s two-space pretty printer (formatting P2).

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::api::JsonObject;
use crate::commands;

/// The file names of one step (`StepPaths`, `_prepare_step_paths`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepPaths {
    /// `<artifacts>/steps/<NN>-<role_slug>`.
    pub step_dir: PathBuf,
    pub prompt_path: PathBuf,
    /// `<artifacts>/context.json` (the artifacts root, not the step dir).
    pub context_path: PathBuf,
    pub previous_summary_path: PathBuf,
    pub log_path: PathBuf,
    pub summary_path: PathBuf,
    pub metadata_path: PathBuf,
    pub script_path: PathBuf,
    pub exit_code_path: PathBuf,
}

impl StepPaths {
    /// The paths of step `step_index` with role `role` under the ticket's
    /// artifacts root.
    pub fn new(artifacts_root: &Path, step_index: usize, role: &str) -> Self {
        let step_dir = artifacts_root
            .join("steps")
            .join(commands::step_name(step_index, role));
        Self {
            prompt_path: step_dir.join("prompt.md"),
            context_path: artifacts_root.join("context.json"),
            previous_summary_path: step_dir.join("previous_step_summary.md"),
            log_path: step_dir.join("session.log"),
            summary_path: step_dir.join("summary.json"),
            metadata_path: step_dir.join("session_metadata.json"),
            script_path: step_dir.join("run_step.sh"),
            exit_code_path: step_dir.join("exit_code"),
            step_dir,
        }
    }
}

/// `pathlib.Path(base) / name` as Python prints it: repeated separators and
/// `.` components dropped, no trailing separator. The paths end up in
/// artifacts and status payloads (`log_path`, …), so they read as Python's.
pub fn py_path_join(base: &str, name: &str) -> PathBuf {
    let joined = Path::new(base).join(name);
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        if component != Component::CurDir {
            normalized.push(component.as_os_str());
        }
    }
    if normalized.as_os_str().is_empty() {
        normalized.push(".");
    }
    normalized
}

/// The text of a JSON artifact: two-space indentation and a final newline.
pub fn artifact_json(value: &Value) -> Vec<u8> {
    // Serialising a `Value` into memory cannot fail (every key is a string).
    let mut text = serde_json::to_vec_pretty(value).unwrap_or_default();
    text.push(b'\n');
    text
}

/// `_atomic_write_json(path, payload)`.
pub fn atomic_write_json(path: &Path, payload: &Value) -> io::Result<()> {
    let text = artifact_json(payload);
    atomic_write_with(path, |temp| temp.as_file_mut().write_all(&text))
}

/// [`atomic_write_json`] with the content written by `write` (the test seam
/// for failures while writing).
pub(crate) fn atomic_write_with(
    path: &Path,
    write: impl FnOnce(&mut NamedTempFile) -> io::Result<()>,
) -> io::Result<()> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    fs::create_dir_all(parent)?;
    // `NamedTempFile` creates the file with mode 0600 and removes it when
    // dropped, ignoring a failing removal; `persist` renames it over the
    // destination and hands it back (and drops it) on failure.
    let mut temp = tempfile::Builder::new().prefix("tmp").tempfile_in(parent)?;
    write(&mut temp)?;
    temp.persist(path).map_err(|error| error.error)?;
    Ok(())
}

/// `_load_summary(path)`: the JSON object in `path`, or `None` when the file
/// is missing, unreadable, not UTF-8, not JSON or not an object.
pub fn load_json_object(path: &Path) -> Option<JsonObject> {
    let data = fs::read(path).ok()?;
    let text = String::from_utf8(data).ok()?;
    match opsgate_core::json::parse(&text) {
        Ok(Value::Object(object)) => Some(object),
        _ => None,
    }
}

/// `_sha256(path)`: lowercase hex SHA-256 of the file, read in 64 KiB chunks.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        digest.update(&buffer[..read]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn entries(dir: &Path) -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        found.sort();
        found
    }

    fn injected() -> io::Error {
        io::Error::other("injected failure")
    }

    /// `test_failed_publication_cleans_temp[serialize|write]`: a failure
    /// before anything or after part of the content was written.
    #[test]
    fn failed_publication_cleans_temp() {
        for partial in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let destination = dir.path().join("state.json");
            fs::write(&destination, b"previous state").unwrap();
            let mut invoked = false;
            let error = atomic_write_with(&destination, |temp| {
                invoked = true;
                if partial {
                    temp.as_file_mut().write_all(b"partial JSON")?;
                }
                Err(injected())
            })
            .unwrap_err();
            assert!(invoked);
            assert_eq!(error.to_string(), "injected failure");
            assert_eq!(fs::read(&destination).unwrap(), b"previous state");
            assert_eq!(entries(dir.path()), [destination]);
        }
    }

    /// `test_failed_publication_cleans_temp[replace]`: the rename fails (the
    /// destination is a non-empty directory).
    #[test]
    fn failed_replace_cleans_temp() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("state.json");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("keep"), b"previous state").unwrap();
        atomic_write_json(&destination, &json!({"state": "running"})).unwrap_err();
        assert_eq!(
            fs::read(destination.join("keep")).unwrap(),
            b"previous state"
        );
        assert_eq!(entries(dir.path()), [destination]);
    }

    /// `test_successful_publication_is_private`.
    #[test]
    fn successful_publication_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("nested").join("state.json");
        atomic_write_json(&destination, &json!({"state": "running"})).unwrap();
        let text = fs::read(&destination).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&text).unwrap(),
            json!({"state": "running"})
        );
        assert!(text.ends_with(b"\n"));
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(entries(destination.parent().unwrap()), [destination]);
    }

    /// `test_cleanup_refusal_preserves_publication_error`: the directory
    /// refuses the removal of the temporary file; the caller still gets the
    /// publication error and the destination is unchanged.
    #[test]
    fn cleanup_refusal_preserves_publication_error() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("state.json");
        fs::write(&destination, b"previous state").unwrap();
        let error = atomic_write_with(&destination, |_| {
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500))?;
            Err(injected())
        })
        .unwrap_err();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(error.to_string(), "injected failure");
        assert_eq!(fs::read(&destination).unwrap(), b"previous state");
    }

    /// `test_success_does_not_unlink_released_temp_name`: the published file
    /// is the temporary file itself (same inode) and nothing else is left or
    /// removed afterwards.
    #[test]
    fn success_does_not_unlink_released_temp_name() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("state.json");
        let mut temp_name = None;
        atomic_write_with(&destination, |temp| {
            temp_name = Some((temp.path().to_owned(), temp.as_file().metadata()?.ino()));
            temp.as_file_mut()
                .write_all(&artifact_json(&json!({"state": "running"})))
        })
        .unwrap();
        let (temp_path, inode) = temp_name.unwrap();
        assert!(!temp_path.exists());
        assert_eq!(fs::metadata(&destination).unwrap().ino(), inode);
        assert_eq!(
            load_json_object(&destination),
            json!({"state": "running"}).as_object().cloned()
        );
        assert_eq!(entries(dir.path()), [destination]);
    }

    #[test]
    fn artifact_json_sorts_keys_and_indents() {
        let text = artifact_json(&json!({"b": 1, "a": {"c": [1, 2]}}));
        assert_eq!(
            String::from_utf8(text).unwrap(),
            "{\n  \"a\": {\n    \"c\": [\n      1,\n      2\n    ]\n  },\n  \"b\": 1\n}\n"
        );
    }

    #[test]
    fn load_json_object_rejects_what_python_treats_as_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.json");
        assert_eq!(load_json_object(&path), None);
        for content in [&b"{not json"[..], b"\xff\xfe{", b"[1]", b"\"x\""] {
            fs::write(&path, content).unwrap();
            assert_eq!(load_json_object(&path), None, "{content:?}");
        }
        fs::write(&path, b"{\"status\": \"succeeded\"}").unwrap();
        assert_eq!(
            load_json_object(&path),
            json!({"status": "succeeded"}).as_object().cloned()
        );
    }

    #[test]
    fn sha256_of_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        fs::write(&path, b"ok\n").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            opsgate_core::json::sha256_hex(b"ok\n")
        );
        let big = vec![b'x'; 200 * 1024 + 7];
        fs::write(&path, &big).unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            opsgate_core::json::sha256_hex(&big)
        );
    }

    #[test]
    fn paths_read_as_pythons() {
        assert_eq!(
            py_path_join("/Users/ops/remediation/sessions/", "t"),
            PathBuf::from("/Users/ops/remediation/sessions/t")
        );
        assert_eq!(py_path_join("/a//./b", "t").to_str().unwrap(), "/a/b/t");
        assert_eq!(py_path_join("rel/./x", "t").to_str().unwrap(), "rel/x/t");
        let paths = StepPaths::new(Path::new("/s/t"), 0, "Investigator");
        assert_eq!(paths.step_dir, PathBuf::from("/s/t/steps/01-investigator"));
        assert_eq!(paths.context_path, PathBuf::from("/s/t/context.json"));
        assert_eq!(
            paths.exit_code_path,
            PathBuf::from("/s/t/steps/01-investigator/exit_code")
        );
    }
}
