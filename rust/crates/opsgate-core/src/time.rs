//! Timestamps as `service.py` writes and reads them (PLAN.md 4.9).
//!
//! Ported Python: `utc_now`, `isoformat_z` and `parse_iso_datetime`
//! (`datetime.fromisoformat` of CPython 3.14 on the extended ISO 8601 forms;
//! the other forms Python accepts are D-7). Pinned by `fixtures/datetime.json`.

use chrono::{
    DateTime, Datelike, Days, NaiveDate, NaiveDateTime, NaiveTime, SubsecRound, TimeDelta,
    Timelike, Utc,
};

use crate::pytext;

/// Microseconds in Python's bound for a UTC offset (strictly less than one
/// day either way).
const DAY_MICROS: i64 = 86_400_000_000;

/// `utc_now()`: the current time at Python's microsecond resolution.
pub fn utc_now() -> DateTime<Utc> {
    Utc::now().trunc_subsecs(6)
}

/// `isoformat_z(value)`: `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`, the fraction left
/// out when the microseconds are 0 (P1: stored timestamps are compared as
/// text, so a whole-second value sorts after fractional ones of the same
/// second). Sub-microsecond parts are truncated; the year is written with at
/// least four digits, as Python does for its years 1 to 9999.
pub fn isoformat_z(value: &DateTime<Utc>) -> String {
    let micros = value.nanosecond() % 1_000_000_000 / 1_000;
    let mut text = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        value.year(),
        value.month(),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    );
    if micros != 0 {
        text.push_str(&format!(".{micros:06}"));
    }
    text.push('Z');
    text
}

/// Why `parse_iso_datetime` rejects a text (Python: `ValueError`). Every
/// variant maps to the same error code (`invalid_expires_at`, or a logged-out
/// session for `auth_at`); the messages are P2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsoError {
    /// Not in the accepted ISO 8601 subset (or not ISO 8601 at all), or a
    /// field out of range.
    Invalid,
    /// No UTC offset: "Datetime must include timezone information".
    Naive,
    /// The instant is outside Python's years 1 to 9999 in UTC.
    OutOfRange,
}

impl std::fmt::Display for IsoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "Invalid isoformat string",
            Self::Naive => "Datetime must include timezone information",
            Self::OutOfRange => "Datetime is outside supported UTC bounds",
        })
    }
}

impl std::error::Error for IsoError {}

/// `parse_iso_datetime(raw)`: strip Python whitespace, read a trailing `Z`
/// as `+00:00`, parse, require an offset, convert to UTC.
///
/// Accepted (the same results as CPython 3.14 `datetime.fromisoformat`):
/// `YYYY-MM-DD`, any single separator character, `HH:MM`, `HH:MM:SS` or
/// `HH:MM:SS.f…` (any number of fraction digits, truncated to microseconds;
/// `24:00` with zero minutes, seconds and microseconds is midnight of the next
/// day), then `±HH:MM`, `±HH:MM:SS` or `±HH:MM:SS.f…`. Like Python, offset
/// fields are two digits each and only the total must be less than 24 hours.
/// Basic forms, week and ordinal dates, `,` fractions, hour-only times and
/// offsets and a space before the offset are rejected (D-7).
pub fn parse_iso_datetime(raw: &str) -> Result<DateTime<Utc>, IsoError> {
    let stripped = pytext::strip(raw);
    let replaced;
    let text = match stripped.strip_suffix('Z') {
        Some(prefix) => {
            replaced = format!("{prefix}+00:00");
            replaced.as_str()
        }
        None => stripped,
    };
    let date = parse_date(text.get(..10).ok_or(IsoError::Invalid)?)?;
    let mut rest = text[10..].chars();
    if rest.next().is_none() {
        // A date alone is a naive midnight in Python.
        return Err(IsoError::Naive);
    }
    let mut cursor = Cursor {
        bytes: rest.as_str().as_bytes(),
        position: 0,
    };
    let clock = cursor.clock()?;
    let offset_micros = match cursor.peek() {
        None => return Err(IsoError::Naive),
        Some(sign @ (b'+' | b'-')) => {
            cursor.position += 1;
            let micros = cursor.clock()?.total_micros();
            if micros >= DAY_MICROS {
                return Err(IsoError::Invalid);
            }
            if sign == b'-' { -micros } else { micros }
        }
        Some(_) => return Err(IsoError::Invalid),
    };
    if cursor.peek().is_some() {
        return Err(IsoError::Invalid);
    }
    let local = local_datetime(date, &clock)?;
    let utc = local
        .checked_sub_signed(TimeDelta::microseconds(offset_micros))
        .filter(|utc| (1..=9999).contains(&utc.year()))
        .ok_or(IsoError::OutOfRange)?;
    Ok(utc.and_utc())
}

fn parse_date(text: &str) -> Result<NaiveDate, IsoError> {
    let bytes = text.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return Err(IsoError::Invalid);
    }
    let year = digits(&bytes[..4])?;
    let month = digits(&bytes[5..7])?;
    let day = digits(&bytes[8..10])?;
    if year == 0 {
        return Err(IsoError::Invalid);
    }
    NaiveDate::from_ymd_opt(year as i32, month, day).ok_or(IsoError::Invalid)
}

fn digits(bytes: &[u8]) -> Result<u32, IsoError> {
    bytes.iter().try_fold(0_u32, |value, &byte| {
        if byte.is_ascii_digit() {
            Ok(value * 10 + u32::from(byte - b'0'))
        } else {
            Err(IsoError::Invalid)
        }
    })
}

/// `HH:MM[:SS[.f…]]` of a time or an offset, fields not yet range-checked.
struct Clock {
    hours: u32,
    minutes: u32,
    seconds: u32,
    micros: u32,
}

impl Clock {
    fn total_micros(&self) -> i64 {
        (i64::from(self.hours) * 3600 + i64::from(self.minutes) * 60 + i64::from(self.seconds))
            * 1_000_000
            + i64::from(self.micros)
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn two_digits(&mut self) -> Result<u32, IsoError> {
        let field = self
            .bytes
            .get(self.position..self.position + 2)
            .ok_or(IsoError::Invalid)?;
        self.position += 2;
        digits(field)
    }

    fn expect(&mut self, byte: u8) -> Result<(), IsoError> {
        if self.peek() != Some(byte) {
            return Err(IsoError::Invalid);
        }
        self.position += 1;
        Ok(())
    }

    fn clock(&mut self) -> Result<Clock, IsoError> {
        let hours = self.two_digits()?;
        self.expect(b':')?;
        let minutes = self.two_digits()?;
        let mut clock = Clock {
            hours,
            minutes,
            seconds: 0,
            micros: 0,
        };
        if self.peek() != Some(b':') {
            return Ok(clock);
        }
        self.position += 1;
        clock.seconds = self.two_digits()?;
        if self.peek() != Some(b'.') {
            return Ok(clock);
        }
        self.position += 1;
        let start = self.position;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.position += 1;
        }
        let fraction = &self.bytes[start..self.position];
        if fraction.is_empty() {
            return Err(IsoError::Invalid);
        }
        // Python keeps the first six digits and drops the rest.
        clock.micros = fraction
            .iter()
            .chain(std::iter::repeat(&b'0'))
            .take(6)
            .try_fold(0_u32, |value, &byte| {
                Ok::<u32, IsoError>(value * 10 + u32::from(byte - b'0'))
            })?;
        Ok(clock)
    }
}

fn local_datetime(date: NaiveDate, clock: &Clock) -> Result<NaiveDateTime, IsoError> {
    if clock.hours == 24 {
        // Python 3.14: `24:00` is the next midnight; the next day must still
        // be a valid date (year 9999 at most).
        if clock.minutes != 0 || clock.seconds != 0 || clock.micros != 0 {
            return Err(IsoError::Invalid);
        }
        let next = date
            .checked_add_days(Days::new(1))
            .filter(|next| next.year() <= 9999)
            .ok_or(IsoError::Invalid)?;
        return Ok(next.and_time(NaiveTime::MIN));
    }
    if clock.hours > 23 || clock.minutes > 59 || clock.seconds > 59 {
        return Err(IsoError::Invalid);
    }
    let time =
        NaiveTime::from_hms_micro_opt(clock.hours, clock.minutes, clock.seconds, clock.micros)
            .ok_or(IsoError::Invalid)?;
    Ok(date.and_time(time))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn isoformat_z_drops_a_zero_fraction() {
        let whole = Utc.with_ymd_and_hms(2026, 10, 21, 10, 0, 0).unwrap();
        assert_eq!(isoformat_z(&whole), "2026-10-21T10:00:00Z");
        let fractional = whole + TimeDelta::microseconds(1);
        assert_eq!(isoformat_z(&fractional), "2026-10-21T10:00:00.000001Z");
        let nanos = whole + TimeDelta::nanoseconds(999);
        assert_eq!(isoformat_z(&nanos), "2026-10-21T10:00:00Z");
        let year_one = Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(isoformat_z(&year_one), "0001-01-01T00:00:00Z");
    }

    #[test]
    fn utc_now_has_microsecond_resolution() {
        assert_eq!(utc_now().nanosecond() % 1_000, 0);
    }

    /// Port of `test_datetime_overflow_is_value_error` and the time half of
    /// `test_api_rejects_utc_expiry_overflow` (tests/test_api.py).
    #[test]
    fn utc_overflow_is_out_of_range() {
        for raw in ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"] {
            let error = parse_iso_datetime(raw).unwrap_err();
            assert_eq!(error, IsoError::OutOfRange, "{raw}");
            assert_eq!(
                error.to_string(),
                "Datetime is outside supported UTC bounds"
            );
        }
    }

    #[test]
    fn parse_normalises_to_utc() {
        let parse = |raw: &str| parse_iso_datetime(raw).map(|value| isoformat_z(&value));
        assert_eq!(
            parse("2026-10-21T10:00:00+02:00").unwrap(),
            "2026-10-21T08:00:00Z"
        );
        assert_eq!(
            parse(" 2026-10-21 10:00Z\u{3000}").unwrap(),
            "2026-10-21T10:00:00Z"
        );
        assert_eq!(
            parse("2026-10-21T10:00:00.1234567Z").unwrap(),
            "2026-10-21T10:00:00.123456Z"
        );
        assert_eq!(parse("2026-10-21T24:00Z").unwrap(), "2026-10-22T00:00:00Z");
        assert_eq!(
            parse("2026-10-21T10:00+00:60").unwrap(),
            "2026-10-21T09:00:00Z"
        );
        assert_eq!(parse("2026-10-21T10:00:00"), Err(IsoError::Naive));
        assert_eq!(parse("2026-10-21"), Err(IsoError::Naive));
        assert_eq!(parse("0001-01-01T00:00+00:01"), Err(IsoError::OutOfRange));
        assert_eq!(parse("2026-10-21T10:00:00+24:00"), Err(IsoError::Invalid));
        assert_eq!(parse("20261021T1000Z"), Err(IsoError::Invalid));
        assert_eq!(parse("2026-10-21T10:00:00z"), Err(IsoError::Invalid));
        assert_eq!(parse(""), Err(IsoError::Invalid));
        assert_eq!(parse("2026-10-2\u{e9}"), Err(IsoError::Invalid));
    }
}
