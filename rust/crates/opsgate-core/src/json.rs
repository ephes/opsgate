//! JSON as Python's `json` module reads and writes it (PLAN.md 4.6, 4.8).
//!
//! Parsing is `serde_json` with `arbitrary_precision`, so every number keeps
//! its token and is classified the way `json.loads` does (an integer token
//! becomes a Python `int` of any size, anything with a fraction or exponent a
//! `float`). Writing is `serde_json`'s serializer with [`PyFormatter`], a
//! `serde_json::ser::Formatter` that reproduces
//! `json.dumps(value, sort_keys=True, ensure_ascii=True)`: ASCII-only string
//! escapes, Python's float `repr`, and either the compact separators of the
//! payload checksum (`compute_payload_checksum`, byte-exact, 4.8) or the
//! default separators of the stored JSON columns and audit metadata.
//!
//! Ported Python: `service.py:compute_payload_checksum`, `check_json_depth`,
//! `parse_stored_json`, the `json.dumps(..., sort_keys=True)` calls of
//! `_insert_ticket`, `_record_audit_event` and the runner-status update, and
//! the `json.loads` number rules (4300-digit integer limit). Pinned by
//! `fixtures/checksum.json`, `float_repr.json` and `storage_json.json`.

use std::borrow::Cow;
use std::cell::Cell;
use std::fmt::Write as _;
use std::io;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use serde_json::ser::{CharEscape, Formatter};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

/// Maximum nesting of arrays and objects, the root counting as level 1
/// (`check_json_depth`).
pub const MAX_DEPTH: usize = 64;

/// CPython's default limit for integer string conversion
/// (`sys.get_int_max_str_digits()`): `json.loads` fails on longer integer
/// tokens.
pub const MAX_INT_DIGITS: usize = 4300;

/// Why a JSON text cannot be decoded. Python's `json.loads` raises
/// `ValueError` (or `RecursionError`) in each case, except the D-2 inputs
/// Python decodes and Rust does not (`NaN`/`Infinity` literals, lone
/// surrogate escapes, UTF-16/UTF-32 bodies).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Not JSON, including nesting beyond `serde_json`'s 128 levels (deeper
    /// than [`MAX_DEPTH`] anyway, so every caller answers the same code as
    /// Python's depth check).
    Syntax(String),
    /// An integer token with more than [`MAX_INT_DIGITS`] digits.
    IntegerTooLong,
    /// The bytes are not UTF-8.
    NotUtf8,
}

impl ParseError {
    /// Whether decoding stopped at `serde_json`'s recursion limit (nesting
    /// beyond 128 levels): the text is deeper than [`MAX_DEPTH`] up to that
    /// point, which request bodies answer like Python's depth check
    /// (`invalid_json`, PLAN.md 4.6) instead of as undecodable text.
    pub fn exceeds_recursion_limit(&self) -> bool {
        matches!(self, Self::Syntax(message) if message.starts_with("recursion limit exceeded"))
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syntax(message) => write!(f, "invalid JSON: {message}"),
            Self::IntegerTooLong => write!(f, "integer token exceeds {MAX_INT_DIGITS} digits"),
            Self::NotUtf8 => f.write_str("JSON body is not UTF-8"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Nesting deeper than [`MAX_DEPTH`] (`check_json_depth`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooDeep;

impl std::fmt::Display for TooDeep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JSON nesting exceeds {MAX_DEPTH} levels")
    }
}

impl std::error::Error for TooDeep {}

/// A stored JSON column that `parse_stored_json` rejects
/// (`invalid_stored_json`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredJsonError {
    Undecodable(ParseError),
    TooDeep,
}

impl std::fmt::Display for StoredJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Undecodable(_) => f.write_str("Stored JSON cannot be decoded"),
            Self::TooDeep => TooDeep.fmt(f),
        }
    }
}

impl std::error::Error for StoredJsonError {}

/// A float that overflowed to infinity when its token was read, which
/// Python writes as `Infinity` and Rust refuses to write (D-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonFiniteFloat;

impl std::fmt::Display for NonFiniteFloat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON number out of range")
    }
}

impl std::error::Error for NonFiniteFloat {}

/// `json.loads(text)` for a `str` (stored columns, form fields): no BOM, no
/// `NaN`/`Infinity` literals or lone surrogate escapes (D-2), integer tokens
/// of at most [`MAX_INT_DIGITS`] digits (checked for every token, also one a
/// duplicate key later replaces, as CPython converts each token while
/// decoding). Duplicate keys keep the last value, as a Python dict does.
pub fn parse(text: &str) -> Result<Value, ParseError> {
    let integer_too_long = Cell::new(false);
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let decoded = ValueSeed {
        integer_too_long: &integer_too_long,
    }
    .deserialize(&mut deserializer)
    .and_then(|value| deserializer.end().map(|()| value));
    match decoded {
        Ok(value) => Ok(value),
        Err(_) if integer_too_long.get() => Err(ParseError::IntegerTooLong),
        Err(error) => Err(ParseError::Syntax(error.to_string())),
    }
}

/// `json.loads(body)` for request bytes (Flask `get_json`): a leading UTF-8
/// BOM is skipped, anything but UTF-8 is rejected (D-2), then as [`parse`].
pub fn parse_bytes(body: &[u8]) -> Result<Value, ParseError> {
    let body = body.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(body);
    let text = std::str::from_utf8(body).map_err(|_| ParseError::NotUtf8)?;
    parse(text)
}

/// `parse_stored_json`: decode a stored column, then [`check_depth`].
pub fn parse_stored(text: &str) -> Result<Value, StoredJsonError> {
    let value = parse(text).map_err(StoredJsonError::Undecodable)?;
    check_depth(&value).map_err(|TooDeep| StoredJsonError::TooDeep)?;
    Ok(value)
}

/// `check_json_depth`: arrays and objects may nest [`MAX_DEPTH`] levels
/// (the root container is level 1; scalars add none).
pub fn check_depth(value: &Value) -> Result<(), TooDeep> {
    let mut pending = vec![(value, 0_usize)];
    while let Some((item, depth)) = pending.pop() {
        let children: Box<dyn Iterator<Item = &Value>> = match item {
            Value::Array(items) => Box::new(items.iter()),
            Value::Object(map) => Box::new(map.values()),
            _ => continue,
        };
        let depth = depth + 1;
        if depth > MAX_DEPTH {
            return Err(TooDeep);
        }
        pending.extend(children.map(|child| (child, depth)));
    }
    Ok(())
}

/// A JSON number as Python's `json.loads` returns it.
#[derive(Debug, Clone, PartialEq)]
pub enum PyNumber<'a> {
    /// An `int`: its decimal digits as `str(int)` writes them (`-0` is `0`).
    Int(Cow<'a, str>),
    /// A `float`, correctly rounded from the token like CPython's `float()`;
    /// infinite when the token overflows (D-2 for writers).
    Float(f64),
}

/// Classify a number the way `json.loads` does: a token with a fraction or
/// an exponent is a `float`, any other an `int`.
pub fn py_number(number: &Number) -> PyNumber<'_> {
    py_number_token(number.as_str())
}

fn py_number_token(token: &str) -> PyNumber<'_> {
    if token.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
        // serde_json validated the token; a parse failure cannot happen and
        // would be rejected by every writer like an overflow.
        PyNumber::Float(token.parse().unwrap_or(f64::NAN))
    } else if token == "-0" {
        PyNumber::Int(Cow::Borrowed("0"))
    } else {
        PyNumber::Int(Cow::Borrowed(token))
    }
}

/// The map key under which `serde_json` (`arbitrary_precision`) hands a
/// number token to a visitor: `visit_map` with this single key and the token
/// as an owned `String` value.
const NUMBER_TOKEN_KEY: &str = "$serde_json::private::Number";

/// Builds a [`Value`] from `serde_json`'s parser like
/// `serde_json::Value::deserialize`, with two differences: an object whose
/// first key is [`NUMBER_TOKEN_KEY`] stays an object unless its value is the
/// owned token string of a real number (`serde_json`'s own `Value` turns such
/// a user object into a number), and every integer token is checked against
/// [`MAX_INT_DIGITS`] as it is read.
#[derive(Clone, Copy)]
struct ValueSeed<'a> {
    integer_too_long: &'a Cell<bool>,
}

impl ValueSeed<'_> {
    fn number<E: de::Error>(self, token: &str) -> Result<Value, E> {
        let number: Number = token.parse().map_err(E::custom)?;
        if let PyNumber::Int(digits) = py_number(&number)
            && digits.trim_start_matches('-').len() > MAX_INT_DIGITS
        {
            self.integer_too_long.set(true);
            return Err(E::custom(format!(
                "integer token exceeds {MAX_INT_DIGITS} digits"
            )));
        }
        Ok(Value::Number(number))
    }
}

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ValueSeed<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    // Only reached without `arbitrary_precision` tokens (never from text).
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(self)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        let Some(first_key) = map.next_key::<String>()? else {
            return Ok(Value::Object(object));
        };
        if first_key == NUMBER_TOKEN_KEY {
            match map.next_value_seed(FirstValueSeed(self))? {
                FirstValue::NumberToken(token) => return self.number(&token),
                FirstValue::Json(value) => object.insert(first_key, value),
            };
        } else {
            let value = map.next_value_seed(self)?;
            object.insert(first_key, value);
        }
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value_seed(self)?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

/// The value after a [`NUMBER_TOKEN_KEY`] key: `serde_json` passes a number
/// token as an owned `String` (`visit_string`); a string in the JSON text
/// always arrives through `visit_borrowed_str` or `visit_str`.
enum FirstValue {
    NumberToken(String),
    Json(Value),
}

struct FirstValueSeed<'a>(ValueSeed<'a>);

impl<'de> DeserializeSeed<'de> for FirstValueSeed<'_> {
    type Value = FirstValue;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<FirstValue, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for FirstValueSeed<'_> {
    type Value = FirstValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<FirstValue, E> {
        Ok(FirstValue::NumberToken(value))
    }

    fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<FirstValue, E> {
        self.0.visit_str(value).map(FirstValue::Json)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<FirstValue, E> {
        self.0.visit_str(value).map(FirstValue::Json)
    }

    fn visit_unit<E: de::Error>(self) -> Result<FirstValue, E> {
        self.0.visit_unit().map(FirstValue::Json)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<FirstValue, E> {
        self.0.visit_bool(value).map(FirstValue::Json)
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<FirstValue, E> {
        self.0.visit_i64(value).map(FirstValue::Json)
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<FirstValue, E> {
        self.0.visit_u64(value).map(FirstValue::Json)
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<FirstValue, E> {
        self.0.visit_f64(value).map(FirstValue::Json)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<FirstValue, A::Error> {
        self.0.visit_seq(seq).map(FirstValue::Json)
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<FirstValue, A::Error> {
        self.0.visit_map(map).map(FirstValue::Json)
    }
}

/// CPython's `repr(float)` (`float_repr_style` "short"): the shortest digits
/// that round-trip, in fixed notation for decimal exponents -4 to 15 and in
/// exponent notation (`1e+16`, `1e-05`) outside; integral values keep `.0`.
/// Non-finite values give Python's `inf`, `-inf` and `nan`.
pub fn py_float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.to_owned();
    }
    let mut buffer = ryu::Buffer::new();
    let (negative, digits, point) = decompose(buffer.format_finite(value));
    let mut out = String::with_capacity(digits.len() + 8);
    if negative {
        out.push('-');
    }
    if digits.is_empty() {
        out.push_str("0.0");
        return out;
    }
    let count = digits.len() as i32;
    if point <= -4 || point > 16 {
        out.push_str(&digits[..1]);
        if count > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let exponent = point - 1;
        let sign = if exponent < 0 { '-' } else { '+' };
        let _ = write!(out, "e{sign}{:02}", exponent.unsigned_abs());
    } else if point <= 0 {
        out.push_str("0.");
        out.extend(std::iter::repeat_n('0', point.unsigned_abs() as usize));
        out.push_str(&digits);
    } else if point >= count {
        out.push_str(&digits);
        out.extend(std::iter::repeat_n('0', (point - count) as usize));
        out.push_str(".0");
    } else {
        out.push_str(&digits[..point as usize]);
        out.push('.');
        out.push_str(&digits[point as usize..]);
    }
    out
}

/// Split a `ryu` rendering (`1.5e-7`, `0.001`, `123.0`, `1e16`) into the sign,
/// the significant digits without leading or trailing zeros, and the decimal
/// point position: value = 0.DIGITS × 10^point.
fn decompose(text: &str) -> (bool, String, i32) {
    let mut negative = false;
    let mut digits = String::with_capacity(text.len());
    let mut integer_digits = 0_i32;
    let mut seen_point = false;
    let mut in_exponent = false;
    let mut exponent_negative = false;
    let mut exponent = 0_i32;
    for byte in text.bytes() {
        match byte {
            b'-' if in_exponent => exponent_negative = true,
            b'-' => negative = true,
            b'.' => seen_point = true,
            b'e' | b'E' => in_exponent = true,
            b'0'..=b'9' if in_exponent => exponent = exponent * 10 + i32::from(byte - b'0'),
            b'0'..=b'9' => {
                digits.push(char::from(byte));
                if !seen_point {
                    integer_digits += 1;
                }
            }
            _ => {}
        }
    }
    if exponent_negative {
        exponent = -exponent;
    }
    let mut point = integer_digits + exponent;
    let leading = digits.bytes().take_while(|&byte| byte == b'0').count();
    digits.drain(..leading);
    point -= leading as i32;
    let significant = digits.trim_end_matches('0').len();
    digits.truncate(significant);
    (negative, digits, point)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Separators {
    /// `separators=(",", ":")`: the payload checksum.
    Compact,
    /// `json.dumps` defaults `(", ", ": ")`: stored columns, audit metadata.
    Default,
}

/// `serde_json` formatter producing `json.dumps(..., ensure_ascii=True)`
/// text: every character outside U+0020..U+007E is escaped (`\"`, `\\`,
/// `\n`, `\r`, `\t`, `\b`, `\f`, otherwise `\u00XX` or a lowercase UTF-16
/// surrogate pair), numbers are written as Python writes the decoded
/// `int`/`float`, and non-finite floats are refused (D-2).
#[derive(Debug, Clone, Copy)]
pub struct PyFormatter {
    separators: Separators,
}

impl PyFormatter {
    /// The checksum form: `separators=(",", ":")`.
    pub fn compact() -> Self {
        Self {
            separators: Separators::Compact,
        }
    }

    /// The default `json.dumps` separators `", "` and `": "`.
    pub fn default_separators() -> Self {
        Self {
            separators: Separators::Default,
        }
    }

    fn item_separator(self) -> &'static [u8] {
        match self.separators {
            Separators::Compact => b",",
            Separators::Default => b", ",
        }
    }

    fn write_float<W: ?Sized + io::Write>(writer: &mut W, value: f64) -> io::Result<()> {
        if !value.is_finite() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, NonFiniteFloat));
        }
        writer.write_all(py_float_repr(value).as_bytes())
    }
}

fn write_unicode_escape<W: ?Sized + io::Write>(writer: &mut W, unit: u16) -> io::Result<()> {
    write!(writer, "\\u{unit:04x}")
}

impl Formatter for PyFormatter {
    fn write_f32<W: ?Sized + io::Write>(&mut self, writer: &mut W, value: f32) -> io::Result<()> {
        Self::write_float(writer, f64::from(value))
    }

    fn write_f64<W: ?Sized + io::Write>(&mut self, writer: &mut W, value: f64) -> io::Result<()> {
        Self::write_float(writer, value)
    }

    fn write_number_str<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        value: &str,
    ) -> io::Result<()> {
        match py_number_token(value) {
            PyNumber::Int(digits) => writer.write_all(digits.as_bytes()),
            PyNumber::Float(float) => Self::write_float(writer, float),
        }
    }

    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let bytes = fragment.as_bytes();
        let mut start = 0;
        for (index, character) in fragment.char_indices() {
            if (' '..='~').contains(&character) {
                continue;
            }
            writer.write_all(&bytes[start..index])?;
            let mut units = [0_u16; 2];
            for unit in character.encode_utf16(&mut units) {
                write_unicode_escape(writer, *unit)?;
            }
            start = index + character.len_utf8();
        }
        writer.write_all(&bytes[start..])
    }

    fn write_char_escape<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        escape: CharEscape,
    ) -> io::Result<()> {
        let short: &[u8] = match escape {
            CharEscape::Quote => b"\\\"",
            CharEscape::ReverseSolidus => b"\\\\",
            // Never produced by the serializer; Python does not escape `/`.
            CharEscape::Solidus => b"/",
            CharEscape::Backspace => b"\\b",
            CharEscape::FormFeed => b"\\f",
            CharEscape::LineFeed => b"\\n",
            CharEscape::CarriageReturn => b"\\r",
            CharEscape::Tab => b"\\t",
            CharEscape::AsciiControl(byte) => return write_unicode_escape(writer, u16::from(byte)),
        };
        writer.write_all(short)
    }

    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(self.item_separator())
        }
    }

    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(self.item_separator())
        }
    }

    fn begin_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        writer.write_all(match self.separators {
            Separators::Compact => b":",
            Separators::Default => b": ",
        })
    }
}

/// A [`Value`] serialized with its object keys sorted by code point
/// (`sort_keys=True`; UTF-8 byte order is code point order), independent of
/// the map type `serde_json` was built with.
struct SortedKeys<'a>(&'a Value);

impl Serialize for SortedKeys<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Object(map) => {
                let mut entries: Vec<(&String, &Value)> = map.iter().collect();
                entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
                let mut object = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    object.serialize_entry(key, &SortedKeys(value))?;
                }
                object.end()
            }
            Value::Array(items) => {
                let mut array = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    array.serialize_element(&SortedKeys(item))?;
                }
                array.end()
            }
            scalar => scalar.serialize(serializer),
        }
    }
}

fn dumps(value: &Value, formatter: PyFormatter) -> Result<String, NonFiniteFloat> {
    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, formatter);
    // Writing into a Vec cannot fail and every key is a string, so the
    // formatter's refusal of a non-finite float is the only possible error.
    SortedKeys(value)
        .serialize(&mut serializer)
        .map_err(|_| NonFiniteFloat)?;
    // The formatter writes ASCII only.
    Ok(String::from_utf8(out).unwrap_or_default())
}

/// `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`:
/// the canonical text the payload checksum hashes (byte-exact, 4.8).
pub fn canonical_json(value: &Value) -> Result<String, NonFiniteFloat> {
    dumps(value, PyFormatter::compact())
}

/// `compute_payload_checksum`: lowercase hex SHA-256 of [`canonical_json`].
pub fn payload_checksum(value: &Value) -> Result<String, NonFiniteFloat> {
    Ok(sha256_hex(canonical_json(value)?.as_bytes()))
}

/// `json.dumps(value, sort_keys=True)`: the text of the stored JSON columns
/// (`execution_plan_json`, `policy_requirements_json`, `context_json`,
/// `tmux_sessions_json`) and of audit `metadata_json` (format P2, 4.8).
pub fn stored_json(value: &Value) -> Result<String, NonFiniteFloat> {
    dumps(value, PyFormatter::default_separators())
}

/// `hashlib.sha256(data).hexdigest()`.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canonical(text: &str) -> String {
        canonical_json(&parse(text).unwrap()).unwrap()
    }

    #[test]
    fn canonical_form_sorts_keys_and_escapes_like_python() {
        assert_eq!(
            canonical(r#"{"b": 1, "a": {"d": [1, 2.50], "c": "é\u0000\"\\/"}}"#),
            { r#"{"a":{"c":"\u00e9\u0000\"\\/","d":[1,2.5]},"b":1}"# }
        );
        assert_eq!(
            canonical("\"\u{1f600}\u{7f}\u{2028}\""),
            r#""\ud83d\ude00\u007f\u2028""#
        );
        assert_eq!(canonical(r#""\b\f\n\r\t\u001f""#), r#""\b\f\n\r\t\u001f""#);
    }

    #[test]
    fn stored_form_uses_default_separators() {
        let value = json!({"b": [1, {"x": null}], "a": true});
        assert_eq!(
            stored_json(&value).unwrap(),
            r#"{"a": true, "b": [1, {"x": null}]}"#
        );
        assert_eq!(stored_json(&json!({})).unwrap(), "{}");
        assert_eq!(stored_json(&json!([])).unwrap(), "[]");
    }

    #[test]
    fn numbers_are_written_as_python_reads_them() {
        assert_eq!(
            canonical("[-0, -0.0, 1E2, 0.1e1, 1e16, 1e15, 1e-5, 1e-4, 1e-400]"),
            { "[0,-0.0,100.0,1.0,1e+16,1000000000000000.0,1e-05,0.0001,0.0]" }
        );
        assert_eq!(
            canonical("123456789012345678901234567890"),
            "123456789012345678901234567890"
        );
        assert_eq!(
            canonical_json(&parse("[1e400]").unwrap()),
            Err(NonFiniteFloat)
        );
        assert_eq!(
            stored_json(&parse("{\"a\": -1e400}").unwrap()),
            Err(NonFiniteFloat)
        );
        // Values built in Rust go through the same rules.
        assert_eq!(
            canonical_json(&json!([3.0, 0.95, 3600, -7])).unwrap(),
            "[3.0,0.95,3600,-7]"
        );
    }

    #[test]
    fn float_repr_matches_cpython_examples() {
        for (value, expected) in [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (0.1 + 0.2, "0.30000000000000004"),
            (1e16, "1e+16"),
            (1.5e16, "1.5e+16"),
            (9_999_999_999_999_998.0, "9999999999999998.0"),
            (1e-5, "1e-05"),
            (0.0001, "0.0001"),
            (5e-324, "5e-324"),
            (f64::MAX, "1.7976931348623157e+308"),
            (123_456_789.125, "123456789.125"),
            (f64::INFINITY, "inf"),
            (f64::NEG_INFINITY, "-inf"),
            (f64::NAN, "nan"),
        ] {
            assert_eq!(py_float_repr(value), expected, "{value:?}");
        }
    }

    #[test]
    fn checksum_is_sha256_of_the_canonical_text() {
        assert_eq!(
            payload_checksum(&json!({})).unwrap(),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn parse_follows_json_loads() {
        assert!(matches!(parse("NaN"), Err(ParseError::Syntax(_))));
        assert!(matches!(parse("[Infinity]"), Err(ParseError::Syntax(_))));
        assert!(matches!(parse(r#""\ud800""#), Err(ParseError::Syntax(_))));
        assert!(matches!(parse("\u{feff}{}"), Err(ParseError::Syntax(_))));
        assert_eq!(parse(&"9".repeat(4300)).map(|_| ()), Ok(()));
        assert_eq!(parse(&format!("-{}", "9".repeat(4300))).map(|_| ()), Ok(()));
        assert_eq!(
            parse(&format!("[{}]", "9".repeat(4301))),
            Err(ParseError::IntegerTooLong)
        );
        assert_eq!(
            parse(&format!("{}.0", "9".repeat(5000))).map(|_| ()),
            Ok(())
        );
    }

    #[test]
    fn serde_jsons_number_key_is_ordinary_data() {
        let key = "$serde_json::private::Number";
        for text in [
            format!(r#"{{"{key}":"123"}}"#),
            format!(r#"{{"{key}":"1\u002e5"}}"#),
            format!(r#"{{"{key}":1}}"#),
            format!(r#"{{"{key}":"2","b":1}}"#),
            format!(r#"{{"b":1,"{key}":"2"}}"#),
        ] {
            let value = parse(&text).unwrap();
            assert!(value.is_object(), "{text} became {value}");
            assert!(value.get(key).is_some(), "{text}");
        }
        assert_eq!(
            canonical(&format!(r#"{{"c":{{"{key}":"123"}}}}"#)),
            format!(r#"{{"c":{{"{key}":"123"}}}}"#)
        );
    }

    #[test]
    fn digit_limit_applies_before_duplicate_keys_are_merged() {
        let long = "9".repeat(4301);
        assert_eq!(
            parse(&format!(r#"{{"a":{long},"a":1}}"#)),
            Err(ParseError::IntegerTooLong)
        );
        assert_eq!(parse(r#"{"a":1,"a":2}"#).unwrap(), json!({"a": 2}));
    }

    #[test]
    fn parse_bytes_accepts_a_utf8_bom_only() {
        assert_eq!(
            parse_bytes(b"\xEF\xBB\xBF{\"a\": 1}").unwrap(),
            json!({"a": 1})
        );
        assert_eq!(parse_bytes(b"\xFF\xFE{\x00}\x00"), Err(ParseError::NotUtf8));
        assert_eq!(parse_bytes(b"\"\xED\xA0\x80\""), Err(ParseError::NotUtf8));
        assert!(matches!(
            parse_bytes(b"{\x00}\x00"),
            Err(ParseError::Syntax(_))
        ));
    }

    #[test]
    fn depth_counts_containers_from_the_root() {
        let nested = |levels: usize| format!("{}{}", "[".repeat(levels), "]".repeat(levels));
        assert_eq!(check_depth(&parse(&nested(64)).unwrap()), Ok(()));
        assert_eq!(check_depth(&parse(&nested(65)).unwrap()), Err(TooDeep));
        assert_eq!(check_depth(&json!(1)), Ok(()));
        let mut object = json!(1);
        for _ in 0..64 {
            object = json!({ "k": object });
        }
        assert_eq!(check_depth(&object), Ok(()));
        assert_eq!(check_depth(&json!([object])), Err(TooDeep));
        // serde_json stops at 128 levels; deeper text is undecodable.
        assert!(matches!(parse(&nested(200)), Err(ParseError::Syntax(_))));
        assert!(parse(&nested(200)).unwrap_err().exceeds_recursion_limit());
        // The deepest text serde_json decodes has 127 levels.
        assert!(parse(&nested(127)).is_ok());
        assert!(parse(&nested(128)).unwrap_err().exceeds_recursion_limit());
        assert!(!parse("[").unwrap_err().exceeds_recursion_limit());
        assert!(
            !parse(&"[".repeat(100))
                .unwrap_err()
                .exceeds_recursion_limit()
        );
        assert_eq!(parse_stored(&nested(65)), Err(StoredJsonError::TooDeep));
        assert!(matches!(
            parse_stored("{"),
            Err(StoredJsonError::Undecodable(_))
        ));
        assert_eq!(parse_stored(&nested(64)).map(|_| ()), Ok(()));
    }

    #[test]
    fn numbers_are_classified_like_json_loads() {
        let classify = |text: &str| match parse(text).unwrap() {
            Value::Number(number) => match py_number(&number) {
                PyNumber::Int(digits) => format!("int {digits}"),
                PyNumber::Float(value) => format!("float {}", py_float_repr(value)),
            },
            other => panic!("not a number: {other}"),
        };
        assert_eq!(classify("900"), "int 900");
        assert_eq!(classify("-0"), "int 0");
        assert_eq!(classify("900.0"), "float 900.0");
        assert_eq!(classify("9e2"), "float 900.0");
        assert_eq!(classify("1e309"), "float inf");
    }
}
