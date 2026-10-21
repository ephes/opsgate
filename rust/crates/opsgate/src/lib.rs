//! The `opsgate` binary of the Rust port (`rust/PLAN.md` section 0): one
//! executable for `serve` and `runner`, plus the Rust-only operational
//! commands `check-config`, `check-db` and `--version` (D-15).

pub mod check_config;
pub mod cli;
pub mod runner;
pub mod serve;
