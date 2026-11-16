// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Date functions (query-language.md §4.2) on `datetime` values (ms since the Unix epoch, UTC,
//! proleptic Gregorian calendar).
//!
//! *Provisional (PD pending)* conventions, not fixed by the specification:
//! - units (case-insensitive, singular or plural): `millisecond`, `second`, `minute`, `hour`,
//!   `day`, `week` (ISO, weeks start on Monday), `month`, `quarter`, `year`; `extract` also
//!   knows `dow` (0 = Sunday), `doy` (1-based) and `epoch` (seconds);
//! - `date_add(d, n, unit)` clamps the day of month (Jan 31 + 1 month = Feb 28/29);
//!   `date_diff(a, b, unit)` is the number of whole units from `a` to `b` (negative when `b`
//!   is earlier), calendar-aware for months, quarters and years;
//! - `date_format(d, fmt [, tz])` supports `%Y %m %d %H %M %S %L` (milliseconds) `%j %a %b %%`,
//!   `tz` being `UTC` or a fixed offset `±HH:MM` (named zones need a time-zone database: later);
//! - `time_bucket(width, d [, origin])`: `width` is an interval (text such as `'1h'` or a
//!   number of ms), buckets are aligned to `origin` (default: the epoch);
//! - interval text: one or more `<number><unit>` groups (`'7 days'`, `'1h30m'`, `'-10s'`) with
//!   units `ms`, `s`, `m`/`min`, `h`, `d`, `w` and their long forms; months and years have no
//!   fixed length and are rejected.

use rustegon_doc::Value;

use super::{Func, ops};

const MS_PER_SECOND: i64 = 1_000;
const MS_PER_MINUTE: i64 = 60 * MS_PER_SECOND;
const MS_PER_HOUR: i64 = 60 * MS_PER_MINUTE;
const MS_PER_DAY: i64 = 24 * MS_PER_HOUR;
const MS_PER_WEEK: i64 = 7 * MS_PER_DAY;
/// 1970-01-01 was a Thursday: day 0 has ISO weekday index 3 (Monday = 0).
const EPOCH_WEEKDAY_FROM_MONDAY: i64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    Millisecond,
    Second,
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Quarter,
    Year,
}

fn unit(text: &str) -> Option<Unit> {
    let t = text.to_ascii_lowercase();
    let t = t
        .strip_suffix('s')
        .filter(|s| !s.is_empty() && *s != "m")
        .unwrap_or(&t);
    Some(match t {
        "millisecond" | "ms" => Unit::Millisecond,
        "second" | "sec" | "s" => Unit::Second,
        "minute" | "min" => Unit::Minute,
        "hour" | "h" => Unit::Hour,
        "day" | "d" => Unit::Day,
        "week" | "w" => Unit::Week,
        "month" => Unit::Month,
        "quarter" => Unit::Quarter,
        "year" => Unit::Year,
        _ => return None,
    })
}

fn fixed_ms(u: Unit) -> Option<i64> {
    Some(match u {
        Unit::Millisecond => 1,
        Unit::Second => MS_PER_SECOND,
        Unit::Minute => MS_PER_MINUTE,
        Unit::Hour => MS_PER_HOUR,
        Unit::Day => MS_PER_DAY,
        Unit::Week => MS_PER_WEEK,
        Unit::Month | Unit::Quarter | Unit::Year => return None,
    })
}

/// Parses interval text (module docs) into milliseconds.
#[must_use]
pub fn parse_interval(text: &str) -> Option<i64> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let (negative, mut rest) = match compact.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, compact.strip_prefix('+').unwrap_or(&compact)),
    };
    if rest.is_empty() {
        return None;
    }
    let mut total: i64 = 0;
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let amount: i64 = rest[..digits].parse().ok()?;
        rest = &rest[digits..];
        let letters = rest
            .find(|c: char| c.is_ascii_digit())
            .unwrap_or(rest.len());
        let u = match &rest[..letters] {
            "m" => Unit::Minute,
            other => unit(other)?,
        };
        rest = &rest[letters..];
        total = total.checked_add(amount.checked_mul(fixed_ms(u)?)?)?;
    }
    if negative {
        total.checked_neg()
    } else {
        Some(total)
    }
}

/// Days since the epoch of a civil date (H. Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Civil date `(year, month 1–12, day 1–31)` of a day number (H. Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        if m <= 2 {
            yoe + era * 400 + 1
        } else {
            yoe + era * 400
        },
        m,
        d,
    )
}

fn days_in_month(y: i64, m: i64) -> i64 {
    days_from_civil(
        if m == 12 { y + 1 } else { y },
        if m == 12 { 1 } else { m + 1 },
        1,
    ) - days_from_civil(y, m, 1)
}

/// Splits ms into (day number, ms within the day).
fn split(ms: i64) -> (i64, i64) {
    (ms.div_euclid(MS_PER_DAY), ms.rem_euclid(MS_PER_DAY))
}

fn add_months(ms: i64, months: i64) -> Option<i64> {
    let (day, rem) = split(ms);
    let (y, m, d) = civil_from_days(day);
    let total = y.checked_mul(12)?.checked_add(m - 1)?.checked_add(months)?;
    let (ny, nm) = (total.div_euclid(12), total.rem_euclid(12) + 1);
    let nd = d.min(days_in_month(ny, nm));
    days_from_civil(ny, nm, nd)
        .checked_mul(MS_PER_DAY)?
        .checked_add(rem)
}

fn trunc(ms: i64, u: Unit) -> Option<i64> {
    let (day, _) = split(ms);
    let (y, m, _) = civil_from_days(day);
    Some(match u {
        Unit::Week => {
            let monday = day - (day + EPOCH_WEEKDAY_FROM_MONDAY).rem_euclid(7);
            monday * MS_PER_DAY
        }
        Unit::Month => days_from_civil(y, m, 1) * MS_PER_DAY,
        Unit::Quarter => days_from_civil(y, (m - 1) / 3 * 3 + 1, 1) * MS_PER_DAY,
        Unit::Year => days_from_civil(y, 1, 1) * MS_PER_DAY,
        fixed => {
            let w = fixed_ms(fixed)?;
            ms - ms.rem_euclid(w)
        }
    })
}

fn months_between(a: i64, b: i64) -> i64 {
    let (da, ra) = split(a);
    let (db, rb) = split(b);
    let (ya, ma, dda) = civil_from_days(da);
    let (yb, mb, ddb) = civil_from_days(db);
    let mut months = (yb - ya) * 12 + (mb - ma);
    // Only whole months count: step back when the day/time of `b` has not reached `a`'s.
    if months > 0 && (ddb, rb) < (dda, ra) {
        months -= 1;
    } else if months < 0 && (ddb, rb) > (dda, ra) {
        months += 1;
    }
    months
}

fn extract(ms: i64, part: &str) -> Option<i64> {
    let (day, rem) = split(ms);
    let (y, m, d) = civil_from_days(day);
    Some(match part.to_ascii_lowercase().as_str() {
        "year" | "years" => y,
        "quarter" | "quarters" => (m - 1) / 3 + 1,
        "month" | "months" => m,
        "day" | "days" => d,
        "hour" | "hours" => rem / MS_PER_HOUR,
        "minute" | "minutes" => rem % MS_PER_HOUR / MS_PER_MINUTE,
        "second" | "seconds" => rem % MS_PER_MINUTE / MS_PER_SECOND,
        "millisecond" | "milliseconds" => rem % MS_PER_SECOND,
        "dow" => (day + EPOCH_WEEKDAY_FROM_MONDAY + 1).rem_euclid(7),
        "doy" => day - days_from_civil(y, 1, 1) + 1,
        "week" | "weeks" => iso_week(day),
        "epoch" => ms.div_euclid(MS_PER_SECOND),
        _ => return None,
    })
}

/// ISO 8601 week number of a day.
fn iso_week(day: i64) -> i64 {
    let weekday = (day + EPOCH_WEEKDAY_FROM_MONDAY).rem_euclid(7); // Monday = 0
    let thursday = day - weekday + 3;
    let (y, _, _) = civil_from_days(thursday);
    (thursday - days_from_civil(y, 1, 1)) / 7 + 1
}

fn tz_offset_ms(tz: &str) -> Option<i64> {
    if tz.eq_ignore_ascii_case("utc") || tz == "Z" {
        return Some(0);
    }
    let (sign, rest) = match tz.as_bytes().first()? {
        b'+' => (1, &tz[1..]),
        b'-' => (-1, &tz[1..]),
        _ => return None,
    };
    let (h, m) = rest.split_once(':')?;
    let (h, m): (i64, i64) = (h.parse().ok()?, m.parse().ok()?);
    (h <= 23 && m <= 59).then(|| sign * (h * MS_PER_HOUR + m * MS_PER_MINUTE))
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

fn format(ms: i64, fmt: &str, tz: &str) -> Option<String> {
    let local = ms.checked_add(tz_offset_ms(tz)?)?;
    let (day, rem) = split(local);
    let (y, m, d) = civil_from_days(day);
    let mut out = String::new();
    let mut chars = fmt.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let piece = match chars.next()? {
            'Y' => format!("{y:04}"),
            'm' => format!("{m:02}"),
            'd' => format!("{d:02}"),
            'H' => format!("{:02}", rem / MS_PER_HOUR),
            'M' => format!("{:02}", rem % MS_PER_HOUR / MS_PER_MINUTE),
            'S' => format!("{:02}", rem % MS_PER_MINUTE / MS_PER_SECOND),
            'L' => format!("{:03}", rem % MS_PER_SECOND),
            'j' => format!("{:03}", day - days_from_civil(y, 1, 1) + 1),
            'a' => DAYS
                [usize::try_from((day + EPOCH_WEEKDAY_FROM_MONDAY + 1).rem_euclid(7)).ok()?]
            .to_owned(),
            'b' => MONTHS[usize::try_from(m - 1).ok()?].to_owned(),
            '%' => "%".to_owned(),
            _ => return None,
        };
        out.push_str(&piece);
    }
    Some(out)
}

fn as_datetime(v: &Value) -> Option<i64> {
    match v {
        Value::DateTime(ms) => Some(*ms),
        _ => None,
    }
}

fn interval_ms(v: &Value) -> Option<i64> {
    match v {
        Value::String(s) => parse_interval(s),
        other => ops::as_int(other),
    }
}

/// Evaluates a date function on present, non-null arguments.
#[allow(clippy::many_single_char_names)] // Calendar arithmetic names (`n`, `u`, `x`, `y`).
pub(super) fn call(f: Func, a: &[Value]) -> Option<Value> {
    let text = |i: usize| match a.get(i) {
        Some(Value::String(t)) => Some(t.as_str()),
        _ => None,
    };
    match f {
        Func::ToDate => match &a[0] {
            Value::DateTime(_) => Some(a[0].clone()),
            Value::String(s) => crate::ast::literal::parse_datetime(s).map(Value::DateTime),
            other => ops::as_int(other).map(Value::DateTime),
        },
        Func::DateTrunc => trunc(as_datetime(&a[1])?, unit(text(0)?)?).map(Value::DateTime),
        Func::DateAdd => {
            let (ms, n, u) = (as_datetime(&a[0])?, ops::as_int(&a[1])?, unit(text(2)?)?);
            let r = match u {
                Unit::Month => add_months(ms, n),
                Unit::Quarter => add_months(ms, n.checked_mul(3)?),
                Unit::Year => add_months(ms, n.checked_mul(12)?),
                fixed => ms.checked_add(n.checked_mul(fixed_ms(fixed)?)?),
            };
            r.map(Value::DateTime)
        }
        Func::DateDiff => {
            let (x, y, u) = (as_datetime(&a[0])?, as_datetime(&a[1])?, unit(text(2)?)?);
            let n = match u {
                Unit::Month => months_between(x, y),
                Unit::Quarter => months_between(x, y) / 3,
                Unit::Year => months_between(x, y) / 12,
                fixed => y.checked_sub(x)? / fixed_ms(fixed)?,
            };
            Some(Value::Int64(n))
        }
        Func::Extract => extract(as_datetime(&a[1])?, text(0)?).map(Value::Int64),
        Func::DateFormat => {
            let tz = if a.len() > 2 { text(2)? } else { "UTC" };
            format(as_datetime(&a[0])?, text(1)?, tz).map(Value::String)
        }
        Func::TimeBucket => {
            let width = interval_ms(&a[0]).filter(|w| *w > 0)?;
            let ms = as_datetime(&a[1])?;
            let origin = match a.get(2) {
                Some(o) => as_datetime(o)?,
                None => 0,
            };
            let off = ms.checked_sub(origin)?;
            off.checked_sub(off.rem_euclid(width))?
                .checked_add(origin)
                .map(Value::DateTime)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_round_trip_and_known_dates() {
        for day in [-1_000_000, -1, 0, 1, 19_000, 2_932_896] {
            let (y, m, d) = civil_from_days(day);
            assert_eq!(days_from_civil(y, m, d), day);
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
    }

    #[test]
    fn interval_text() {
        assert_eq!(parse_interval("7 days"), Some(7 * MS_PER_DAY));
        assert_eq!(parse_interval("1h30m"), Some(90 * MS_PER_MINUTE));
        assert_eq!(parse_interval("-10s"), Some(-10_000));
        assert_eq!(parse_interval("500ms"), Some(500));
        assert_eq!(parse_interval("1 month"), None);
        assert_eq!(parse_interval(""), None);
    }

    #[test]
    fn month_arithmetic_clamps() {
        let jan31 = days_from_civil(2024, 1, 31) * MS_PER_DAY;
        let feb29 = days_from_civil(2024, 2, 29) * MS_PER_DAY;
        assert_eq!(add_months(jan31, 1), Some(feb29));
        assert_eq!(months_between(jan31, feb29), 0);
        assert_eq!(months_between(feb29, jan31), 0);
        assert_eq!(extract(feb29, "dow"), Some(4)); // Thursday
        assert_eq!(iso_week(days_from_civil(2021, 1, 3)), 53);
    }
}
