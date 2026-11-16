// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! ISO 8601 text of `datetime` values (`{"$date":"2026-01-01T00:00:00.000Z"}`).
//!
//! The full i64 millisecond range (±292 million years) is supported: years 0000–9999 use four
//! digits, others the ISO 8601 expanded form (sign and at least six digits). Calendar arithmetic
//! is the proleptic Gregorian `days_from_civil` / `civil_from_days` of H. Hinnant
//! ("chrono-Compatible Low-Level Date Algorithms").

use std::fmt::Write as _;

use crate::codec::error::{DocError, DocResult};

const MS_PER_DAY: i64 = 86_400_000;
/// Days between 0000-03-01 and 1970-01-01 (Hinnant's epoch shift).
const EPOCH_SHIFT: i64 = 719_468;
/// Days in a 400-year Gregorian era.
const DAYS_PER_ERA: i64 = 146_097;

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * DAYS_PER_ERA + doe - EPOCH_SHIFT
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + EPOCH_SHIFT;
    let era = z.div_euclid(DAYS_PER_ERA);
    let doe = z - era * DAYS_PER_ERA;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Formats milliseconds since the epoch as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub(crate) fn format(ms: i64) -> String {
    let days = ms.div_euclid(MS_PER_DAY);
    let rem = ms.rem_euclid(MS_PER_DAY);
    let (y, mo, d) = civil_from_days(days);
    let mut s = String::with_capacity(24);
    if (0..=9999).contains(&y) {
        let _ = write!(s, "{y:04}");
    } else {
        let sign = if y < 0 { '-' } else { '+' };
        let _ = write!(s, "{sign}{:06}", y.unsigned_abs());
    }
    let _ = write!(
        s,
        "-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600_000,
        rem / 60_000 % 60,
        rem / 1000 % 60,
        rem % 1000
    );
    s
}

/// Parses the text produced by [`format`]; the fraction may have 0–3 digits.
pub(crate) fn parse(s: &str) -> DocResult<i64> {
    let bad = || DocError::malformed(0, "invalid $date (expected YYYY-MM-DDTHH:MM:SS.mmmZ)");
    let b = s.as_bytes();
    let mut i = 0;
    let num = |i: &mut usize, n: usize| -> Option<i64> {
        let digits = b.get(*i..*i + n)?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        *i += n;
        Some(
            digits
                .iter()
                .fold(0i64, |a, d| a * 10 + i64::from(d - b'0')),
        )
    };
    let year = match b.first() {
        Some(sign @ (b'+' | b'-')) => {
            i = 1;
            let len = b[1..].iter().take_while(|c| c.is_ascii_digit()).count();
            // Six digits minimum (ISO 8601 expanded); 12 maximum keeps the arithmetic in i64.
            if !(6..=12).contains(&len) {
                return Err(bad());
            }
            let y = num(&mut i, len).ok_or_else(bad)?;
            if *sign == b'-' { -y } else { y }
        }
        _ => num(&mut i, 4).ok_or_else(bad)?,
    };
    let expect = |i: &mut usize, c: u8| -> DocResult<()> {
        if b.get(*i) == Some(&c) {
            *i += 1;
            Ok(())
        } else {
            Err(bad())
        }
    };
    expect(&mut i, b'-')?;
    let month = num(&mut i, 2).ok_or_else(bad)?;
    expect(&mut i, b'-')?;
    let day = num(&mut i, 2).ok_or_else(bad)?;
    expect(&mut i, b'T')?;
    let hour = num(&mut i, 2).ok_or_else(bad)?;
    expect(&mut i, b':')?;
    let minute = num(&mut i, 2).ok_or_else(bad)?;
    expect(&mut i, b':')?;
    let second = num(&mut i, 2).ok_or_else(bad)?;
    let mut millis = 0;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let len = b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
        if !(1..=3).contains(&len) {
            return Err(bad());
        }
        millis = num(&mut i, len).ok_or_else(bad)? * 10i64.pow(3 - u32::try_from(len).unwrap_or(3));
    }
    expect(&mut i, b'Z')?;
    if i != b.len()
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(bad());
    }
    // i128: the day start can lie below i64::MIN while the instant itself is in range.
    let day_start = i128::from(days_from_civil(year, month, day)) * i128::from(MS_PER_DAY);
    let time = i128::from(hour * 3_600_000 + minute * 60_000 + second * 1000 + millis);
    i64::try_from(day_start + time).map_err(|_| bad())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datetime_known_values_and_extremes() {
        assert_eq!(format(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format(-1), "1969-12-31T23:59:59.999Z");
        assert_eq!(
            parse("2026-01-01T00:00:00.000Z").unwrap(),
            1_767_225_600_000
        );
        assert_eq!(parse("2024-02-29T12:00:00Z").unwrap(), 1_709_208_000_000);
        assert_eq!(parse("2024-02-29T12:00:00.5Z").unwrap(), 1_709_208_000_500);
        for ms in [
            i64::MIN,
            i64::MAX,
            0,
            -62_167_219_200_001,
            253_402_300_800_000,
        ] {
            assert_eq!(parse(&format(ms)).unwrap(), ms, "{}", format(ms));
        }
        assert!(format(i64::MIN).starts_with("-292275055"));
        for bad in [
            "2023-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:00:00",
            "2026-01-01T00:00:00.0000Z",
            "+2026-01-01T00:00:00Z",
            "+999999999999-01-01T00:00:00Z",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
