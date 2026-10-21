//! Python `str` behaviours the contract depends on: `str.strip()` without
//! arguments and the line boundaries of `str.splitlines()` (settings and the
//! env-file loader, `rust/PLAN.md` 4.2), `str.lower()` and `str()` of a
//! decoded JSON value as `service.py` and `app.py` apply them to request
//! fields (`source`, `title`, `reason`, runner `event`, ...; 4.6). The latter
//! two are pinned by `fixtures/pystr.json`.

use std::borrow::Cow;

use serde_json::Value;

use crate::json::{PyNumber, py_float_repr, py_number};

/// Python's `str.isspace()`: Unicode `White_Space` plus the four ASCII
/// information separators U+001C..U+001F, which CPython also treats as
/// whitespace (bidirectional class B/S).
pub fn is_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

/// Python's `str.strip()` (no argument).
pub fn strip(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// The line boundaries of Python's `str.splitlines()`.
pub fn is_line_boundary(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r'
            | '\u{0b}'
            | '\u{0c}'
            | '\u{1c}'
            | '\u{1d}'
            | '\u{1e}'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// Python's `str.lower()`.
///
/// Rust's `str::to_lowercase` applies the same full Unicode lowercase
/// mappings, including the context-dependent final sigma. The Unicode version
/// may differ from the CPython in production for characters added in newer
/// versions; that cannot change a decision, because every lowered value is
/// only compared with ASCII constants (agents, roles, runner events, boolean
/// spellings) and the only non-ASCII character whose lowercase is ASCII is
/// U+212A KELVIN SIGN in both (fixture `lower_to_ascii`).
pub fn py_lower(value: &str) -> String {
    value.to_lowercase()
}

/// Why a JSON value has no `str()` the Rust port accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyStrError {
    /// An array or object: Python stores its `repr`, Rust rejects (D-3).
    Container,
    /// A number token that overflows to infinity: Python stores `inf`, Rust
    /// rejects (D-2).
    NonFiniteFloat,
}

impl std::fmt::Display for PyStrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Container => "a JSON array or object is not text",
            Self::NonFiniteFloat => "the number is out of range",
        })
    }
}

impl std::error::Error for PyStrError {}

/// Python's `str()` of a value decoded by `json.loads` (PLAN.md 4.6): a
/// string is itself, an integer its decimal digits, a float its `repr`,
/// `true`/`false`/`null` become `True`/`False`/`None`.
pub fn py_str(value: &Value) -> Result<Cow<'_, str>, PyStrError> {
    match value {
        Value::String(text) => Ok(Cow::Borrowed(text)),
        Value::Null => Ok(Cow::Borrowed("None")),
        Value::Bool(true) => Ok(Cow::Borrowed("True")),
        Value::Bool(false) => Ok(Cow::Borrowed("False")),
        Value::Number(number) => match py_number(number) {
            PyNumber::Int(digits) => Ok(digits),
            PyNumber::Float(float) if float.is_finite() => Ok(Cow::Owned(py_float_repr(float))),
            PyNumber::Float(_) => Err(PyStrError::NonFiniteFloat),
        },
        Value::Array(_) | Value::Object(_) => Err(PyStrError::Container),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `[hex(c) for c in range(0x110000) if chr(c).isspace()]` (CPython 3.11-3.15).
    const PYTHON_SPACE: &[u32] = &[
        0x9, 0xa, 0xb, 0xc, 0xd, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001,
        0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029,
        0x202f, 0x205f, 0x3000,
    ];

    /// Characters `c` for which `("a" + c + "b").splitlines()` has two parts.
    const PYTHON_LINE_BOUNDARY: &[u32] =
        &[0xa, 0xb, 0xc, 0xd, 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029];

    #[test]
    fn whitespace_set_is_pythons() {
        let ours: Vec<u32> = (0..=0x10ffff_u32)
            .filter_map(char::from_u32)
            .filter(|c| is_space(*c))
            .map(u32::from)
            .collect();
        assert_eq!(ours, PYTHON_SPACE);
    }

    #[test]
    fn line_boundaries_are_pythons() {
        let ours: Vec<u32> = (0..=0x10ffff_u32)
            .filter_map(char::from_u32)
            .filter(|c| is_line_boundary(*c))
            .map(u32::from)
            .collect();
        assert_eq!(ours, PYTHON_LINE_BOUNDARY);
    }

    #[test]
    fn strip_removes_python_whitespace_only_at_the_ends() {
        assert_eq!(strip("\u{1c}\u{3000} a b\u{a0}\u{1f}"), "a b");
        assert_eq!(strip("\u{feff}a"), "\u{feff}a");
        assert_eq!(strip("\u{180e}a"), "\u{180e}a");
        assert_eq!(strip(" \t\n "), "");
    }

    #[test]
    fn lower_handles_final_sigma_and_kelvin() {
        assert_eq!(py_lower("ΟΔΟΣ"), "οδος");
        assert_eq!(py_lower("\u{212a}ODEX"), "kodex");
        assert_eq!(py_lower("İ"), "i\u{307}");
    }

    #[test]
    fn str_of_scalars() {
        assert_eq!(py_str(&json!("x")).unwrap(), "x");
        assert_eq!(py_str(&json!(null)).unwrap(), "None");
        assert_eq!(py_str(&json!(true)).unwrap(), "True");
        assert_eq!(py_str(&json!(false)).unwrap(), "False");
        assert_eq!(py_str(&json!(3600)).unwrap(), "3600");
        assert_eq!(py_str(&json!(3.0)).unwrap(), "3.0");
        assert_eq!(py_str(&json!([1])), Err(PyStrError::Container));
        assert_eq!(py_str(&json!({})), Err(PyStrError::Container));
        let overflow = crate::json::parse("1e400").unwrap();
        assert_eq!(py_str(&overflow), Err(PyStrError::NonFiniteFloat));
        let negative_zero = crate::json::parse("-0").unwrap();
        assert_eq!(py_str(&negative_zero).unwrap(), "0");
    }
}
