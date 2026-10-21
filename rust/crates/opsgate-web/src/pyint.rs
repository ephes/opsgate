//! Python's `int()` of decoded JSON values as exact decimals (PLAN.md 4.12):
//! the step pages convert a session entry's `step_index` with `int()` and
//! keep the result as a Python integer of any size, so the step numbers here
//! are decimal texts rather than machine integers.

use opsgate_core::json::{PyNumber, py_number};
use opsgate_core::settings::py_int_decimal;
use serde_json::Value;

/// The outcome of `int(value)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PyIntOf {
    /// The integer as [`py_int_decimal`] writes it (`-` and digits without
    /// leading zeros).
    Value(String),
    /// `TypeError` or `ValueError` (`None`, arrays, objects, text that is no
    /// integer, NaN).
    Invalid,
    /// `OverflowError`: `int()` of an infinite float.
    Overflow,
}

/// `int(value)` of a value `json.loads` returned: booleans are 0 and 1,
/// integers themselves, floats truncated toward zero, strings parsed with
/// Python's `int(str)` grammar.
pub fn py_int_of(value: &Value) -> PyIntOf {
    let decimal = match value {
        Value::Bool(flag) => Some(if *flag { "1" } else { "0" }.to_owned()),
        Value::Number(number) => match py_number(number) {
            PyNumber::Int(digits) => py_int_decimal(&digits),
            PyNumber::Float(float) if float.is_nan() => None,
            PyNumber::Float(float) if float.is_infinite() => return PyIntOf::Overflow,
            PyNumber::Float(float) => Some(float_int_decimal(float)),
        },
        Value::String(text) => py_int_decimal(text),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    };
    decimal.map_or(PyIntOf::Invalid, PyIntOf::Value)
}

/// `int(value)` of a finite float: the exact integer of its truncation.
fn float_int_decimal(value: f64) -> String {
    let truncated = value.trunc();
    // Every integral double below 2^127 in magnitude is an exact `i128`.
    if truncated.abs() < 2_f64.powi(127) {
        #[allow(clippy::cast_possible_truncation)]
        return (truncated as i128).to_string();
    }
    // Larger doubles are mantissa × 2^exponent with a positive exponent:
    // double the mantissa's decimal digits (little-endian, base 10^9).
    let bits = truncated.abs().to_bits();
    let exponent = ((bits >> 52) & 0x7ff) - 1075;
    let mantissa = (bits & ((1 << 52) - 1)) | (1 << 52);
    let mut limbs = vec![
        u32::try_from(mantissa % 1_000_000_000).unwrap_or_default(),
        u32::try_from(mantissa / 1_000_000_000 % 1_000_000_000).unwrap_or_default(),
        u32::try_from(mantissa / 1_000_000_000_000_000_000).unwrap_or_default(),
    ];
    for _ in 0..exponent {
        let mut carry = 0_u32;
        for limb in &mut limbs {
            let doubled = *limb * 2 + carry;
            *limb = doubled % 1_000_000_000;
            carry = doubled / 1_000_000_000;
        }
        if carry > 0 {
            limbs.push(carry);
        }
    }
    while limbs.len() > 1 && limbs.last() == Some(&0) {
        limbs.pop();
    }
    let mut text = if value < 0.0 {
        "-".to_owned()
    } else {
        String::new()
    };
    let mut parts = limbs.iter().rev();
    if let Some(first) = parts.next() {
        text.push_str(&first.to_string());
    }
    for limb in parts {
        text.push_str(&format!("{limb:09}"));
    }
    text
}

/// `n + 1` of a non-negative decimal without leading zeros.
pub fn increment(decimal: &str) -> String {
    let mut digits: Vec<u8> = decimal.bytes().collect();
    for digit in digits.iter_mut().rev() {
        if *digit == b'9' {
            *digit = b'0';
        } else {
            *digit += 1;
            return String::from_utf8(digits).unwrap_or_default();
        }
    }
    digits.insert(0, b'1');
    String::from_utf8(digits).unwrap_or_default()
}

/// The decimal as a JSON integer (any size, `arbitrary_precision`), for the
/// templates.
pub fn decimal_value(decimal: &str) -> Value {
    serde_json::from_str(decimal).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn int_of(value: Value) -> PyIntOf {
        py_int_of(&value)
    }

    #[test]
    fn int_follows_python() {
        let value = |text: &str| PyIntOf::Value(text.to_owned());
        assert_eq!(int_of(json!(0)), value("0"));
        assert_eq!(int_of(json!(-3)), value("-3"));
        assert_eq!(int_of(json!(true)), value("1"));
        assert_eq!(int_of(json!(false)), value("0"));
        assert_eq!(int_of(json!(1.9)), value("1"));
        assert_eq!(int_of(json!(-0.5)), value("0"));
        assert_eq!(int_of(json!(-1.5)), value("-1"));
        assert_eq!(int_of(json!(" 2 ")), value("2"));
        assert_eq!(int_of(json!("\u{661}")), value("1"));
        assert_eq!(int_of(json!("1.0")), PyIntOf::Invalid);
        assert_eq!(int_of(json!("abc")), PyIntOf::Invalid);
        assert_eq!(int_of(json!(null)), PyIntOf::Invalid);
        assert_eq!(int_of(json!([0])), PyIntOf::Invalid);
        assert_eq!(int_of(json!({})), PyIntOf::Invalid);
        let big: Value = serde_json::from_str(&"9".repeat(50)).unwrap();
        assert_eq!(int_of(big), value(&"9".repeat(50)));
        let infinite: Value = serde_json::from_str("1e400").unwrap();
        assert_eq!(int_of(infinite), PyIntOf::Overflow);
    }

    #[test]
    fn large_floats_are_exact() {
        // Python: int(1e300), int(2.0**127), int(-1e38).
        assert_eq!(
            float_int_decimal(1e300),
            "1000000000000000052504760255204420248704468581108159154915854115511802457988908195786371375080447864043704443832883878176942523235360430575644792184786706982848387200926575803737830233794788090059368953234970799945081119038967640880074652742780142494579258788820056842838115669472196386865459400540160"
        );
        assert_eq!(
            float_int_decimal(2_f64.powi(127)),
            "170141183460469231731687303715884105728"
        );
        assert_eq!(
            float_int_decimal(-1e38),
            "-99999999999999997748809823456034029568"
        );
        assert_eq!(float_int_decimal(f64::MAX).len(), 309);
    }

    #[test]
    fn increments() {
        assert_eq!(increment("0"), "1");
        assert_eq!(increment("8"), "9");
        assert_eq!(increment("9"), "10");
        assert_eq!(increment("1999"), "2000");
        assert_eq!(increment(&"9".repeat(40)), format!("1{}", "0".repeat(40)));
        assert_eq!(decimal_value("12"), json!(12));
    }
}
