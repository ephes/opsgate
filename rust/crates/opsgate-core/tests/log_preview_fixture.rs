//! `rust/fixtures/log_preview.json` (PLAN.md 4.12): the preview lines and the
//! step log text Python's `read_tail_lines` and `read_step_log` produce for
//! the same file content and limits.

use opsgate_core::log_preview::{
    LINE_BYTE_LIMIT, Limits, PREVIEW_LINE_LIMIT, STEP_LOG_BYTE_LIMIT, STEP_LOG_TRUNCATION_MARKER,
    TAIL_BYTE_LIMIT, TRUNCATION_MARKER, read_step_log_with, read_tail_lines, read_tail_lines_with,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE: &str = include_str!("../../../fixtures/log_preview.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("log_preview.json parses")
}

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}

/// The bytes of a content recipe (`generate.py:_content`).
fn content(recipe: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    for segment in recipe.as_array().unwrap() {
        let piece = match segment["text"].as_str() {
            Some(text) => text.as_bytes().to_vec(),
            None => decode_hex(segment["hex"].as_str().unwrap()),
        };
        for _ in 0..segment["repeat"].as_u64().unwrap() {
            out.extend_from_slice(&piece);
        }
    }
    out
}

#[test]
fn constants_match_python() {
    let fixture = fixture();
    let constants = &fixture["constants"];
    assert_eq!(constants["TAIL_BYTE_LIMIT"], TAIL_BYTE_LIMIT);
    assert_eq!(constants["LINE_BYTE_LIMIT"], LINE_BYTE_LIMIT);
    assert_eq!(constants["STEP_LOG_BYTE_LIMIT"], STEP_LOG_BYTE_LIMIT);
    assert_eq!(constants["TRUNCATION_MARKER"], TRUNCATION_MARKER);
    assert_eq!(
        constants["STEP_LOG_TRUNCATION_MARKER"],
        STEP_LOG_TRUNCATION_MARKER
    );
    assert_eq!(PREVIEW_LINE_LIMIT, 40);
}

#[test]
fn cases_match_python() {
    let fixture = fixture();
    let cases = fixture["cases"].as_array().unwrap();
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("session.log");
        std::fs::write(&path, content(&case["content"])).unwrap();
        let limits_value = &case["limits"];
        let defaults = Limits::default();
        let limits = Limits {
            tail_bytes: limits_value["tail"].as_u64().unwrap_or(defaults.tail_bytes),
            line_bytes: limits_value["line"]
                .as_u64()
                .map_or(defaults.line_bytes, |line| line as usize),
            step_log_bytes: limits_value["step"]
                .as_u64()
                .unwrap_or(defaults.step_log_bytes),
        };
        let max_lines = limits_value["max_lines"]
            .as_u64()
            .map_or(PREVIEW_LINE_LIMIT, |lines| lines as usize);

        let preview = read_tail_lines_with(&path, max_lines, limits).unwrap();
        let expected: Vec<String> = case["preview"]
            .as_array()
            .unwrap()
            .iter()
            .map(|line| line.as_str().unwrap().to_owned())
            .collect();
        if preview != expected {
            failures.push(format!(
                "{name}: preview {preview:?}\n  expected {expected:?}"
            ));
        }

        let step_log = read_step_log_with(&path, limits).unwrap();
        let record = &case["step_log"];
        let matches = match record["text"].as_str() {
            Some(text) => step_log == text,
            None => {
                let digest: String = Sha256::digest(step_log.as_bytes())
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                let chars: Vec<char> = step_log.chars().collect();
                let head: String = chars[..80].iter().collect();
                let tail: String = chars[chars.len() - 80..].iter().collect();
                digest == record["sha256"].as_str().unwrap()
                    && chars.len() as u64 == record["chars"].as_u64().unwrap()
                    && head == record["head"].as_str().unwrap()
                    && tail == record["tail"].as_str().unwrap()
            }
        };
        if !matches {
            let shown: String = step_log.chars().take(200).collect();
            failures.push(format!("{name}: step log {shown:?}… differs from {record}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

#[test]
fn missing_file_matches_python() {
    let fixture = fixture();
    let directory = tempfile::tempdir().unwrap();
    let preview =
        read_tail_lines(&directory.path().join("missing.log"), PREVIEW_LINE_LIMIT).unwrap();
    assert_eq!(
        serde_json::to_value(preview).unwrap(),
        fixture["missing_file_preview"]
    );
}
