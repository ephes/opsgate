//! Pure logic of the OpsGate Rust port (`rust/PLAN.md` section 0): settings
//! (4.2), canonical JSON and the payload checksum (4.8), timestamps (4.9),
//! ticket validation (4.7.1), log previews and path containment (4.12).
//!
//! Everything here is pinned by the Python-generated fixtures in
//! `rust/fixtures` (PLAN.md 7.2). Slices S2a and S2b landed their modules;
//! S2c adds ticket validation.

pub mod json;
pub mod log_preview;
pub mod paths;
pub mod proxy_fix;
pub mod pytext;
pub mod settings;
pub mod time;
