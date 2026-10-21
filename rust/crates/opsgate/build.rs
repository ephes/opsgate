//! Embeds the git commit into `opsgate --version` (PLAN.md section 9:
//! `opsgate <version> (<full commit>)`).
//!
//! Source of the commit, in order:
//! 1. `OPSGATE_GIT_COMMIT` (set by the release workflow to the commit it
//!    checked out, or by a build from a source tree without `.git`);
//! 2. `git rev-parse HEAD` in the source tree;
//! 3. `unknown` (no git, not a repository).
//!
//! `OPSGATE_GIT_COMMIT_SOURCE` (`env`, `git` or `none`) records which one, so
//! the tests can compare a `git` commit with the checked-out HEAD.
//!
//! The value must be a full object name, 40 (SHA-1) or 64 (SHA-256) lowercase
//! hex digits, or `unknown`; anything else fails the build so an odd value
//! never reaches a release binary.

use std::path::{Path, PathBuf};
use std::process::Command;

const ENV: &str = "OPSGATE_GIT_COMMIT";

pub(crate) fn is_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    Some(text.trim().to_owned())
}

/// The paths whose change means HEAD may have moved (`--git-path` resolves
/// worktree and common directories):
/// - the HEAD file (detached commits, branch switches);
/// - `packed-refs`, when it exists;
/// - the nearest existing directory above the branch's loose ref, not the ref
///   file: a branch that lives only in `packed-refs` (after `git pack-refs`,
///   which also removes the empty directories of a nested branch such as
///   `feature/x`) gets a new loose file below it on its next commit, which a
///   directory watch sees (Cargo scans watched directories recursively). A
///   missing path is never watched, because Cargo would rerun the script on
///   every build.
pub(crate) fn git_head_paths(dir: &Path) -> Vec<PathBuf> {
    let git_path = |name: &str| {
        git(
            dir,
            &["rev-parse", "--path-format=absolute", "--git-path", name],
        )
        .map(PathBuf::from)
    };
    let mut paths = Vec::new();
    paths.extend(git_path("HEAD"));
    paths.extend(git_path("packed-refs").filter(|path| path.exists()));
    if let Some(file) =
        git(dir, &["symbolic-ref", "-q", "HEAD"]).and_then(|reference| git_path(&reference))
    {
        // Packing a nested branch (`feature/x`) also removes its now empty
        // directories, so climb to the nearest directory that exists.
        paths.extend(
            file.ancestors()
                .skip(1)
                .find(|dir| dir.is_dir())
                .map(Path::to_path_buf),
        );
    }
    paths
}

// The helpers above are also compiled into `tests/build_script.rs`.
fn main() {
    println!("cargo:rerun-if-env-changed={ENV}");
    println!("cargo:rerun-if-changed=build.rs");
    let (commit, source) = match std::env::var(ENV) {
        Ok(value) if !value.is_empty() => {
            assert!(
                is_commit(&value),
                "{ENV} must be 40 or 64 lowercase hex digits, got {value:?}"
            );
            (value, "env")
        }
        _ => {
            let dir = Path::new(".");
            for path in git_head_paths(dir) {
                println!("cargo:rerun-if-changed={}", path.display());
            }
            git(dir, &["rev-parse", "HEAD"])
                .filter(|value| is_commit(value))
                .map_or_else(|| ("unknown".to_owned(), "none"), |value| (value, "git"))
        }
    };
    println!("cargo:rustc-env={ENV}={commit}");
    println!("cargo:rustc-env={ENV}_SOURCE={source}");
}
