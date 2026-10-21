//! Names, agent commands and the step script (PLAN.md 4.13.2, 4.13.3; P1,
//! security-relevant).
//!
//! Ported Python: `runner._slugify`, `_build_agent_command`,
//! `_build_attach_command`, `TicketExecutor._create_step_script` and the
//! session name of `_run_step`. Shell quoting uses the `shlex` crate: its
//! style differs from Python's `shlex.quote` for some inputs (P2), the
//! result is the same word for a POSIX shell.

use std::borrow::Cow;
use std::path::Path;

use opsgate_core::pytext;

/// `service.SUPPORTED_AGENTS`, in Python's order.
pub const SUPPORTED_AGENTS: [&str; 2] = ["codex", "claude"];

/// A shell word cannot hold a NUL character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NulInWord;

impl std::fmt::Display for NulInWord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a shell word cannot contain a NUL character")
    }
}

impl std::error::Error for NulInWord {}

/// `shlex.quote(value)`: one POSIX shell word.
pub fn quote(value: &str) -> Result<String, NulInWord> {
    shlex::try_quote(value)
        .map(Cow::into_owned)
        .map_err(|_| NulInWord)
}

/// `_slugify`: strip, lowercase, every run of characters outside `[a-z0-9]`
/// becomes `-`, leading and trailing `-` removed, empty → `step`.
pub fn slugify(value: &str) -> String {
    let lowered = pytext::py_lower(pytext::strip(value));
    let mut slug = String::with_capacity(lowered.len());
    let mut pending_dash = false;
    for character in lowered.chars() {
        if character.is_ascii_lowercase() || character.is_ascii_digit() {
            if pending_dash && !slug.is_empty() {
                slug.push('-');
            }
            pending_dash = false;
            slug.push(character);
        } else {
            pending_dash = true;
        }
    }
    if slug.is_empty() {
        "step".to_owned()
    } else {
        slug
    }
}

/// `NN-<role_slug>`: the step directory name and the tail of the tmux
/// session name (`NN` = step index + 1, at least two digits).
pub fn step_name(step_index: usize, role: &str) -> String {
    format!("{:02}-{}", step_index + 1, slugify(role))
}

/// `job-<ticket_id>-<NN>-<role_slug>`.
pub fn session_name(ticket_id: &str, step_index: usize, role: &str) -> String {
    format!("job-{ticket_id}-{}", step_name(step_index, role))
}

/// Why no agent command can be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentCommandError {
    /// Not `codex` or `claude` (Python: `ValueError("unsupported agent: …")`).
    Unsupported { agent: String },
    /// The prompt path contains a NUL character.
    Nul,
}

impl std::fmt::Display for AgentCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { agent } => {
                let shown = if agent.is_empty() { "<empty>" } else { agent };
                write!(
                    f,
                    "unsupported agent: {shown}; allowed agents: {}",
                    SUPPORTED_AGENTS.join(", ")
                )
            }
            Self::Nul => NulInWord.fmt(f),
        }
    }
}

impl std::error::Error for AgentCommandError {}

/// `_build_agent_command`: the agent reads the prompt file on stdin.
///
/// - `codex` → `codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox - < <prompt>`
/// - `claude` → `claude -p --dangerously-skip-permissions < <prompt>`
///
/// The agent name is compared after strip and lowercasing; anything else is
/// [`AgentCommandError::Unsupported`]. Tickets are approved by the operator
/// before they run, so both agents run without their own sandbox prompts.
pub fn build_agent_command(agent: &str, prompt_path: &Path) -> Result<String, AgentCommandError> {
    let normalized = pytext::strip(agent);
    let lower = pytext::py_lower(normalized);
    let prompt = quote(&prompt_path.to_string_lossy()).map_err(|_| AgentCommandError::Nul)?;
    match lower.as_str() {
        "codex" => Ok(format!(
            "codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox - < {prompt}"
        )),
        "claude" => Ok(format!(
            "claude -p --dangerously-skip-permissions < {prompt}"
        )),
        _ => Err(AgentCommandError::Unsupported {
            agent: normalized.to_owned(),
        }),
    }
}

/// `_build_attach_command`: how an operator attaches to the step's session
/// (shown in the UI; quoting P2).
pub fn build_attach_command(
    tmux_socket_label: &str,
    session_name: &str,
    tmux_tmpdir: &str,
) -> Result<String, NulInWord> {
    let label = quote(tmux_socket_label)?;
    let session = quote(session_name)?;
    if tmux_tmpdir.is_empty() {
        Ok(format!("sudo -u ops tmux -L {label} attach -t {session}"))
    } else {
        let tmpdir = quote(tmux_tmpdir)?;
        Ok(format!(
            "sudo -u ops env TMUX_TMPDIR={tmpdir} tmux -L {label} attach -t {session}"
        ))
    }
}

/// The text of `run_step.sh` (`_create_step_script`): the agent's output is
/// appended to the session log, its exit status written to `exit_code`.
pub fn step_script(
    command: &str,
    log_path: &Path,
    exit_code_path: &Path,
) -> Result<String, NulInWord> {
    let log = quote(&log_path.to_string_lossy())?;
    let exit_code = quote(&exit_code_path.to_string_lossy())?;
    Ok([
        "#!/bin/bash".to_owned(),
        "set -uo pipefail".to_owned(),
        format!("{command} 2>&1 | tee -a {log}"),
        "cmd_rc=${PIPESTATUS[0]}".to_owned(),
        format!("printf \"%s\\n\" \"$cmd_rc\" > {exit_code}"),
        "exit \"$cmd_rc\"".to_owned(),
        String::new(),
    ]
    .join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn slugify_matches_python() {
        for (input, expected) in [
            ("investigator", "investigator"),
            ("  Code Reviewer ", "code-reviewer"),
            ("--a__b--", "a-b"),
            ("Ünïcode Rôle", "n-code-r-le"),
            ("", "step"),
            ("***", "step"),
            ("\u{212a}EY", "key"),
            ("step 2", "step-2"),
        ] {
            assert_eq!(slugify(input), expected, "{input:?}");
        }
    }

    #[test]
    fn names_are_zero_padded() {
        assert_eq!(step_name(0, "Investigator"), "01-investigator");
        assert_eq!(step_name(99, "x"), "100-x");
        assert_eq!(
            session_name("aaaaaaaa-1111-4111-8111-111111111111", 1, "reviewer"),
            "job-aaaaaaaa-1111-4111-8111-111111111111-02-reviewer"
        );
    }

    /// `test_build_agent_command_rejects_unsupported_agent`.
    #[test]
    fn build_agent_command_rejects_unsupported_agent() {
        let error = build_agent_command(
            "custom-agent --flag '; rm -rf /'",
            Path::new("/tmp/prompt.md"),
        )
        .unwrap_err();
        assert!(
            error.to_string().starts_with("unsupported agent"),
            "{error}"
        );
        assert_eq!(
            build_agent_command("  ", Path::new("/tmp/p")).unwrap_err(),
            AgentCommandError::Unsupported {
                agent: String::new()
            }
        );
    }

    /// `test_build_agent_command_uses_codex_exec_with_stdin`.
    #[test]
    fn build_agent_command_uses_codex_exec_with_stdin() {
        let prompt = PathBuf::from("/Users/ops/remediation/sessions/t/steps/01-x/prompt.md");
        assert_eq!(
            build_agent_command("codex", &prompt).unwrap(),
            "codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox - < /Users/ops/remediation/sessions/t/steps/01-x/prompt.md"
        );
        assert_eq!(
            build_agent_command(" CODEX\n", &prompt).unwrap(),
            build_agent_command("codex", &prompt).unwrap()
        );
    }

    /// `test_build_agent_command_uses_claude_print_with_bypass_permissions`.
    #[test]
    fn build_agent_command_uses_claude_print_with_bypass_permissions() {
        let prompt = PathBuf::from("/tmp/prompt.md");
        assert_eq!(
            build_agent_command("Claude", &prompt).unwrap(),
            "claude -p --dangerously-skip-permissions < /tmp/prompt.md"
        );
    }

    #[test]
    fn quoted_paths_stay_one_word() {
        let prompt = PathBuf::from("/tmp/it's a $(dir)/prompt.md");
        let command = build_agent_command("claude", &prompt).unwrap();
        let words = shlex::split(&command).unwrap();
        assert_eq!(words.last().unwrap(), "/tmp/it's a $(dir)/prompt.md");
        assert_eq!(quote(""), Ok("''".to_owned()));
        assert_eq!(quote("a\0b"), Err(NulInWord));
    }

    /// `test_build_attach_command_includes_tmux_tmpdir`.
    #[test]
    fn build_attach_command_includes_tmux_tmpdir() {
        assert_eq!(
            build_attach_command("remediation", "job-1", "/Users/ops/remediation/tmux").unwrap(),
            "sudo -u ops env TMUX_TMPDIR=/Users/ops/remediation/tmux tmux -L remediation attach -t job-1"
        );
        assert_eq!(
            build_attach_command("remediation", "job-1", "").unwrap(),
            "sudo -u ops tmux -L remediation attach -t job-1"
        );
        let spaced = build_attach_command("my label", "job-1", "/tmp/a b").unwrap();
        assert_eq!(
            shlex::split(&spaced).unwrap(),
            [
                "sudo",
                "-u",
                "ops",
                "env",
                "TMUX_TMPDIR=/tmp/a b",
                "tmux",
                "-L",
                "my label",
                "attach",
                "-t",
                "job-1"
            ]
        );
    }

    #[test]
    fn step_script_is_pythons_text() {
        let script = step_script(
            "claude -p --dangerously-skip-permissions < /s/prompt.md",
            Path::new("/s/session.log"),
            Path::new("/s/exit_code"),
        )
        .unwrap();
        assert_eq!(
            script,
            "#!/bin/bash\nset -uo pipefail\nclaude -p --dangerously-skip-permissions < /s/prompt.md 2>&1 | tee -a /s/session.log\ncmd_rc=${PIPESTATUS[0]}\nprintf \"%s\\n\" \"$cmd_rc\" > /s/exit_code\nexit \"$cmd_rc\"\n"
        );
    }
}
