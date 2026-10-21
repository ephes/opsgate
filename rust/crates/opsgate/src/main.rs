//! The `opsgate` binary (PLAN.md 4.1): `serve`, `runner`, and the Rust-only
//! `check-config`, `check-db` and `--version` (D-15).

use std::process::ExitCode;

use clap::Parser;
use opsgate::cli::{Cli, run};

fn main() -> ExitCode {
    run(Cli::parse())
}
