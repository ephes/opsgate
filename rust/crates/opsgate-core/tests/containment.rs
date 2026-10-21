//! Step-log path containment (PLAN.md 4.12, `app.py:resolve_session_log_path`)
//! and the non-strict resolution it relies on (`Path.resolve()`, CPython 3.14
//! `posixpath.realpath(strict=False)`): symbolic-link escapes, missing files
//! inside and outside the ticket's artifact directory, and the order of the
//! checks.

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use opsgate_core::paths::{
    LogPathError, resolve, resolve_session_log_path, session_artifacts_root,
};

const TICKET: &str = "0b0e8f5e-7d43-4c55-9d4f-6f1c1bd1f6a1";

/// A temporary execution data dir (canonical, so macOS `/var` → `/private/var`
/// does not matter) with `sessions/<ticket>/steps/01-investigator/session.log`.
struct Tree {
    _directory: tempfile::TempDir,
    root: PathBuf,
}

impl Tree {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let step = root
            .join("sessions")
            .join(TICKET)
            .join("steps/01-investigator");
        std::fs::create_dir_all(&step).unwrap();
        std::fs::write(step.join("session.log"), "hello\n").unwrap();
        std::fs::create_dir_all(root.join("outside")).unwrap();
        std::fs::write(root.join("outside/secret.log"), "secret\n").unwrap();
        Self {
            _directory: directory,
            root,
        }
    }

    fn exec_dir(&self) -> &str {
        self.root.to_str().unwrap()
    }

    fn path(&self, relative: &str) -> String {
        self.root.join(relative).to_str().unwrap().to_owned()
    }

    fn check(&self, raw: &str) -> Result<PathBuf, LogPathError> {
        resolve_session_log_path(self.exec_dir(), TICKET, raw)
    }
}

fn code(result: Result<PathBuf, LogPathError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(error) => error.code().unwrap_or("unresolvable"),
    }
}

#[test]
fn log_inside_the_ticket_directory_resolves() {
    let tree = Tree::new();
    let log = tree.path(&format!(
        "sessions/{TICKET}/steps/01-investigator/session.log"
    ));
    assert_eq!(tree.check(&log).unwrap(), PathBuf::from(&log));
    // Surrounding Python whitespace is stripped; `.`, `..` and `//` are normalised.
    let messy = format!(
        "\u{3000} {}/sessions//{TICKET}/./steps/x/../01-investigator/session.log\n",
        tree.exec_dir()
    );
    assert_eq!(tree.check(&messy).unwrap(), PathBuf::from(&log));
}

#[test]
fn blank_log_path_is_not_found() {
    let tree = Tree::new();
    for raw in ["", "  ", "\t\u{a0}"] {
        assert_eq!(code(tree.check(raw)), "log_not_found");
    }
}

#[test]
fn missing_inside_is_not_found_and_missing_outside_is_invalid() {
    let tree = Tree::new();
    let missing_inside = tree.path(&format!("sessions/{TICKET}/steps/02-reviewer/session.log"));
    assert_eq!(code(tree.check(&missing_inside)), "log_not_found");
    // Containment is checked before existence (P1).
    assert_eq!(
        code(tree.check(&tree.path("outside/missing.log"))),
        "invalid_log_path"
    );
    assert_eq!(
        code(tree.check("/nonexistent/opsgate/session.log")),
        "invalid_log_path"
    );
    // An existing file outside.
    assert_eq!(
        code(tree.check(&tree.path("outside/secret.log"))),
        "invalid_log_path"
    );
}

#[test]
fn directories_are_not_found() {
    let tree = Tree::new();
    assert_eq!(
        code(tree.check(&tree.path(&format!("sessions/{TICKET}/steps")))),
        "log_not_found"
    );
    // The ticket directory itself is "within" the root, but not a file.
    assert_eq!(
        code(tree.check(&tree.path(&format!("sessions/{TICKET}")))),
        "log_not_found"
    );
}

#[test]
fn dot_dot_escapes_are_invalid() {
    let tree = Tree::new();
    let escape = tree.path(&format!("sessions/{TICKET}/../../outside/secret.log"));
    assert_eq!(code(tree.check(&escape)), "invalid_log_path");
    // A sibling ticket whose id has this ticket's id as prefix is outside.
    let sibling = tree.path(&format!("sessions/{TICKET}-other/session.log"));
    std::fs::create_dir_all(Path::new(&sibling).parent().unwrap()).unwrap();
    std::fs::write(&sibling, "x").unwrap();
    assert_eq!(code(tree.check(&sibling)), "invalid_log_path");
}

#[test]
fn symlink_escape_is_invalid() {
    let tree = Tree::new();
    let step = tree
        .root
        .join("sessions")
        .join(TICKET)
        .join("steps/01-investigator");
    symlink(
        tree.root.join("outside/secret.log"),
        step.join("escape.log"),
    )
    .unwrap();
    assert_eq!(
        code(tree.check(step.join("escape.log").to_str().unwrap())),
        "invalid_log_path"
    );
    // A symlinked directory inside the ticket pointing outside.
    symlink(tree.root.join("outside"), step.join("out")).unwrap();
    assert_eq!(
        code(tree.check(step.join("out/secret.log").to_str().unwrap())),
        "invalid_log_path"
    );
    // A dangling symlink pointing outside is outside, not merely missing.
    symlink(
        tree.root.join("outside/missing.log"),
        step.join("dangling.log"),
    )
    .unwrap();
    assert_eq!(
        code(tree.check(step.join("dangling.log").to_str().unwrap())),
        "invalid_log_path"
    );
    // A relative symlink climbing out of the ticket directory.
    symlink("../../../../outside/secret.log", step.join("relative.log")).unwrap();
    assert_eq!(
        code(tree.check(step.join("relative.log").to_str().unwrap())),
        "invalid_log_path"
    );
}

#[test]
fn symlink_after_a_missing_component_and_dot_dot_is_still_resolved() {
    // realpath: `missing/..` is removed after the missing component was
    // appended, and the following symbolic link is resolved.
    let tree = Tree::new();
    let step = tree
        .root
        .join("sessions")
        .join(TICKET)
        .join("steps/01-investigator");
    symlink(
        tree.root.join("outside/secret.log"),
        step.join("escape.log"),
    )
    .unwrap();
    let raw = format!("{}/missing/../escape.log", step.to_str().unwrap());
    assert_eq!(code(tree.check(&raw)), "invalid_log_path");
}

#[test]
fn symlink_into_the_ticket_directory_is_allowed() {
    let tree = Tree::new();
    let log = tree
        .root
        .join("sessions")
        .join(TICKET)
        .join("steps/01-investigator/session.log");
    symlink(&log, tree.root.join("outside/link.log")).unwrap();
    assert_eq!(
        tree.check(tree.root.join("outside/link.log").to_str().unwrap())
            .unwrap(),
        log
    );
}

#[test]
fn symlinked_execution_dir_is_resolved_on_both_sides() {
    let tree = Tree::new();
    let alias = tree.root.join("alias");
    symlink(&tree.root, &alias).unwrap();
    let log = alias
        .join("sessions")
        .join(TICKET)
        .join("steps/01-investigator/session.log");
    let resolved =
        resolve_session_log_path(alias.to_str().unwrap(), TICKET, log.to_str().unwrap()).unwrap();
    assert_eq!(
        resolved,
        tree.root
            .join("sessions")
            .join(TICKET)
            .join("steps/01-investigator/session.log")
    );
    assert_eq!(
        session_artifacts_root(alias.to_str().unwrap(), TICKET).unwrap(),
        tree.root.join("sessions").join(TICKET)
    );
}

#[test]
fn symlink_loops_do_not_hang() {
    let tree = Tree::new();
    let dir = tree.root.join("sessions").join(TICKET);
    symlink(dir.join("b"), dir.join("a")).unwrap();
    symlink(dir.join("a"), dir.join("b")).unwrap();
    // The looping link stays unresolved (inside the root) and is no file.
    assert_eq!(
        code(tree.check(dir.join("a/session.log").to_str().unwrap())),
        "log_not_found"
    );
    assert_eq!(resolve(&dir.join("a")).unwrap(), dir.join("a"));
}

#[test]
fn resolve_matches_realpath_basics() {
    assert_eq!(resolve(Path::new("/")).unwrap(), PathBuf::from("/"));
    assert_eq!(resolve(Path::new("//")).unwrap(), PathBuf::from("/"));
    assert_eq!(resolve(Path::new("/..")).unwrap(), PathBuf::from("/"));
    assert_eq!(
        resolve(Path::new("/nonexistent-opsgate/a/../b/./c/")).unwrap(),
        PathBuf::from("/nonexistent-opsgate/b/c")
    );
    let cwd = std::env::current_dir().unwrap();
    assert_eq!(
        resolve(Path::new("relative-missing")).unwrap(),
        cwd.join("relative-missing")
    );
}

#[test]
fn nul_byte_is_unresolvable() {
    let tree = Tree::new();
    let error = tree
        .check(&format!("{}/a\0b", tree.exec_dir()))
        .unwrap_err();
    assert!(matches!(error, LogPathError::Unresolvable(_)));
    assert_eq!(error.status(), 500);
}

#[test]
fn error_codes_and_statuses() {
    assert_eq!(
        (
            LogPathError::NotFound.code(),
            LogPathError::NotFound.status()
        ),
        (Some("log_not_found"), 404)
    );
    assert_eq!(
        (
            LogPathError::OutsideRoot.code(),
            LogPathError::OutsideRoot.status()
        ),
        (Some("invalid_log_path"), 400)
    );
    assert_eq!(
        LogPathError::OutsideRoot.to_string(),
        "Log file path is outside the ticket artifact root"
    );
    assert_eq!(
        LogPathError::NotFound.to_string(),
        "Log file is not available for this step"
    );
}
