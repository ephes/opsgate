//! Command line (`__main__.py:main`, PLAN.md 4.1 and D-15).
//!
//! `opsgate [serve]`, `opsgate runner [--once]` replace `python -m opsgate
//! [serve|runner] [--once]`; as in Python, no command means `serve`.
//! `check-config`, `check-db`, `--version` and the `serve` overrides `--db`,
//! `--bind-host`, `--bind-port` exist only in Rust (D-15). Usage errors exit 2,
//! as with argparse.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// `--version` text after the program name: the package version and the full
/// git commit the binary was built from (`build.rs`), e.g.
/// `0.3.0 (5d4c4d8…)`. The release checks and the deployment role parse it
/// (PLAN.md section 9).
pub const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("OPSGATE_GIT_COMMIT"),
    ")"
);

/// Exit code of a command whose slice has not landed yet (PLAN.md 12, S1).
pub const NOT_IMPLEMENTED: u8 = 2;

/// OpsGate control service (API and web UI) and runner
#[derive(Debug, Parser)]
#[command(name = "opsgate", version = VERSION)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    /// The command to run; `serve` when none is given (`__main__.py`).
    pub fn into_command(self) -> Command {
        self.command
            .unwrap_or_else(|| Command::Serve(ServeArgs::default()))
    }
}

#[derive(Debug, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Serve the JSON API and web UI (the default command)
    Serve(ServeArgs),
    /// Claim and execute approved tickets
    Runner(RunnerArgs),
    /// Load the settings of the API or the runner like they would, print
    /// nothing secret, and exit 0 or 1
    CheckConfig {
        #[arg(value_enum)]
        target: ConfigTarget,
    },
    /// Verify a database read-only (schema and stored JSON) and exit 0 or 1
    CheckDb {
        /// Path to the SQLite database
        #[arg(long)]
        db: PathBuf,
    },
}

impl Command {
    /// The command name as typed on the command line.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Serve(_) => "serve",
            Self::Runner(_) => "runner",
            Self::CheckConfig { .. } => "check-config",
            Self::CheckDb { .. } => "check-db",
        }
    }
}

/// Overrides of the env-file settings for tests and the shadow run (D-15).
#[derive(Debug, Default, PartialEq, Eq, Args)]
pub struct ServeArgs {
    /// Use this database instead of OPSGATE_DB_PATH
    #[arg(long)]
    pub db: Option<PathBuf>,
    /// Listen on this address instead of OPSGATE_BIND_HOST
    #[arg(long)]
    pub bind_host: Option<String>,
    /// Listen on this port instead of OPSGATE_BIND_PORT
    #[arg(long)]
    pub bind_port: Option<u16>,
}

#[derive(Debug, Default, PartialEq, Eq, Args)]
pub struct RunnerArgs {
    /// Run one runner iteration and exit
    #[arg(long)]
    pub once: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ConfigTarget {
    /// The settings of `serve` (`config.py:load_settings`)
    Api,
    /// The settings of `runner` (`config.py:load_runner_settings`)
    Runner,
}

/// Runs a parsed command line. A command whose slice has not landed yet
/// (PLAN.md 12) is a stub: it says so on stderr and exits 2.
pub fn run(cli: Cli) -> ExitCode {
    match cli.into_command() {
        Command::CheckDb { db } => check_db(&db),
        command => {
            eprintln!(
                "opsgate {}: not implemented yet (rust/PLAN.md section 12)",
                command.name()
            );
            ExitCode::from(NOT_IMPLEMENTED)
        }
    }
}

/// `check-db --db <path>` (slice S3a): the report on stdout; exit 0 when the
/// schema and every stored row are fine, 1 otherwise or when the file cannot
/// be read as an OpsGate database (one line on stderr). Nothing is written.
fn check_db(path: &std::path::Path) -> ExitCode {
    match opsgate_store::check::check_db(path) {
        Ok(report) => {
            print!("{report}");
            ExitCode::from(u8::from(!report.is_ok()))
        }
        Err(error) => {
            eprintln!("opsgate check-db: {}: {error}", path.display());
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, clap::Error> {
        Cli::try_parse_from(std::iter::once("opsgate").chain(args.iter().copied()))
            .map(Cli::into_command)
    }

    #[test]
    fn no_command_means_serve() {
        assert_eq!(parse(&[]).unwrap(), Command::Serve(ServeArgs::default()));
    }

    #[test]
    fn serve_overrides() {
        assert_eq!(
            parse(&[
                "serve",
                "--db",
                "/tmp/x.sqlite3",
                "--bind-host",
                "127.0.0.1",
                "--bind-port",
                "8712",
            ])
            .unwrap(),
            Command::Serve(ServeArgs {
                db: Some(PathBuf::from("/tmp/x.sqlite3")),
                bind_host: Some("127.0.0.1".to_owned()),
                bind_port: Some(8712),
            })
        );
        for port in ["65536", "-1", "x"] {
            let error = parse(&["serve", "--bind-port", port]).unwrap_err();
            assert_eq!(error.exit_code(), 2, "{port}");
        }
    }

    #[test]
    fn runner_once() {
        assert_eq!(
            parse(&["runner"]).unwrap(),
            Command::Runner(RunnerArgs { once: false })
        );
        assert_eq!(
            parse(&["runner", "--once"]).unwrap(),
            Command::Runner(RunnerArgs { once: true })
        );
        // `--once` belongs to the runner (4.1).
        assert_eq!(parse(&["serve", "--once"]).unwrap_err().exit_code(), 2);
    }

    #[test]
    fn check_commands() {
        assert_eq!(
            parse(&["check-config", "api"]).unwrap(),
            Command::CheckConfig {
                target: ConfigTarget::Api
            }
        );
        assert_eq!(
            parse(&["check-config", "runner"]).unwrap(),
            Command::CheckConfig {
                target: ConfigTarget::Runner
            }
        );
        assert_eq!(
            parse(&["check-db", "--db", "opsgate.sqlite3"]).unwrap(),
            Command::CheckDb {
                db: PathBuf::from("opsgate.sqlite3")
            }
        );
        for args in [
            &["check-config"][..],
            &["check-config", "web"],
            &["check-db"],
            &["unknown"],
        ] {
            assert_eq!(parse(args).unwrap_err().exit_code(), 2, "{args:?}");
        }
    }

    #[test]
    fn names_match_the_command_line() {
        for (args, name) in [
            (&[][..], "serve"),
            (&["serve"], "serve"),
            (&["runner"], "runner"),
            (&["check-config", "api"], "check-config"),
            (&["check-db", "--db", "x"], "check-db"),
        ] {
            assert_eq!(parse(args).unwrap().name(), name);
        }
    }

    #[test]
    fn version_names_package_version_and_commit() {
        let (version, commit) = VERSION.split_once(' ').unwrap();
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
        let commit = commit.strip_prefix('(').unwrap().strip_suffix(')').unwrap();
        assert!(
            commit == "unknown"
                || (matches!(commit.len(), 40 | 64)
                    && commit
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
            "{commit}"
        );
    }
}
