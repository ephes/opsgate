//! Shared helpers of the store tests: API settings for a temporary database
//! (the values of `rust/fixtures/generate.py:_store_settings`).

#![allow(dead_code)]

use std::path::Path;

use opsgate_core::settings::{ApiSettings, Environment, SubmitterPolicy, load_api_settings};
use opsgate_store::Store;
use serde_json::{Map, Value};

pub const HASH_ONE: &str = "$2b$12$fixture.hash.one.not.verified.by.these.scenarios.xx";

/// Settings options as `store.json` gives them: `ui_username`,
/// `ui_password_bcrypt`, `operator_floor`.
pub fn settings(db_path: &Path, options: &Map<String, Value>) -> ApiSettings {
    let text = |key: &str, default: &str| {
        options
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or(default)
            .to_owned()
    };
    let operator_floor = options
        .get("operator_floor")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut environment = Environment::from_vars([
        ("OPSGATE_DB_PATH", db_path.to_str().unwrap().to_owned()),
        ("OPSGATE_UI_USERNAME", text("ui_username", "opsgate-admin")),
        (
            "OPSGATE_UI_PASSWORD_BCRYPT",
            text("ui_password_bcrypt", HASH_ONE),
        ),
        ("OPSGATE_SESSION_SECRET", "x".repeat(32)),
        (
            "OPSGATE_RUNNER_TOKEN",
            "runner-token-000000000000".to_owned(),
        ),
        (
            "OPSGATE_SUBMIT_TOKEN_OPENCLAW",
            "openclaw-token-0000000000".to_owned(),
        ),
        (
            "OPSGATE_SUBMIT_TOKEN_NYXMON",
            "nyxmon-token-000000000000".to_owned(),
        ),
        (
            "OPSGATE_SUBMIT_TOKEN_OPERATOR",
            "operator-token-00000000000".to_owned(),
        ),
        (
            "OPSGATE_SUBMIT_POLICY_OPERATOR_REQUIRE_REVIEWER_STEP",
            operator_floor.to_string(),
        ),
    ]);
    load_api_settings(&mut environment).expect("test settings are valid")
}

/// A store on `<dir>/opsgate.sqlite3` with the default options.
pub fn store(dir: &Path) -> Store {
    Store::open(settings(&dir.join("opsgate.sqlite3"), &Map::new())).expect("store opens")
}

/// The submitter policy of `source`.
pub fn submitter(store: &Store, source: &str) -> SubmitterPolicy {
    store
        .settings()
        .submitter_policies
        .iter()
        .find(|policy| policy.source == source)
        .cloned()
        .expect("configured submitter")
}

/// A JSON object from a `serde_json::json!` literal.
pub fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}
