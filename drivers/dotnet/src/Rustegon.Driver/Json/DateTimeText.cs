// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Globalization;
using System.Text;

namespace Rustegon.Driver.Internal.Json;

/// <summary>
/// ISO 8601 text of datetime values (<c>{"$date":"2026-01-01T00:00:00.000Z"}</c>) over the full
/// i64 millisecond range (±292 million years, beyond <see cref="DateTime"/>): years 0000–9999 use
/// four digits, others the expanded form (sign and at least six digits). Calendar arithmetic is the
/// proleptic Gregorian days_from_civil / civil_from_days of H. Hinnant ("chrono-Compatible
/// Low-Level Date Algorithms"), as <c>crates/rustegon-doc/src/json/datetime.rs</c>.
/// </summary>
internal static class DateTimeText
{
    private const long MsPerDay = 86_400_000;

    // Days between 0000-03-01 and 1970-01-01 (Hinnant's epoch shift).
    private const long EpochShift = 719_468;

    // Days in a 400-year Gregorian era.
    private const long DaysPerEra = 146_097;

    private static long DaysFromCivil(long y, long m, long d)
    {
        y = m <= 2 ? y - 1 : y;
        long era = FloorDiv(y, 400);
        long yoe = y - (era * 400);
        long mp = m > 2 ? m - 3 : m + 9;
        long doy = (((153 * mp) + 2) / 5) + d - 1;
        long doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy;
        return (era * DaysPerEra) + doe - EpochShift;
    }

    private static (long Y, long M, long D) CivilFromDays(long z)
    {
        z += EpochShift;
        long era = FloorDiv(z, DaysPerEra);
        long doe = z - (era * DaysPerEra);
        long yoe = (doe - (doe / 1460) + (doe / 36_524) - (doe / 146_096)) / 365;
        long doy = doe - ((365 * yoe) + (yoe / 4) - (yoe / 100));
        long mp = ((5 * doy) + 2) / 153;
        long d = doy - (((153 * mp) + 2) / 5) + 1;
        long m = mp < 10 ? mp + 3 : mp - 9;
        long y = yoe + (era * 400);
        return (m <= 2 ? y + 1 : y, m, d);
    }

    private static long FloorDiv(long a, long b) => (a / b) - ((a % b != 0 && ((a < 0) ^ (b < 0))) ? 1 : 0);

    private static long FloorMod(long a, long b) => a - (FloorDiv(a, b) * b);

    private static long DaysInMonth(long y, long m) => m switch
    {
        2 when (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 or 6 or 9 or 11 => 30,
        _ => 31,
    };

    /// <summary>Formats milliseconds since the epoch as <c>YYYY-MM-DDTHH:MM:SS.mmmZ</c>.</summary>
    internal static string Format(long ms)
    {
        long days = FloorDiv(ms, MsPerDay);
        long rem = FloorMod(ms, MsPerDay);
        (long y, long mo, long d) = CivilFromDays(days);
        var s = new StringBuilder(32);
        CultureInfo inv = CultureInfo.InvariantCulture;
        if (y is >= 0 and <= 9999)
        {
            s.Append(y.ToString("D4", inv));
        }
        else
        {
            s.Append(y < 0 ? '-' : '+').Append(Math.Abs(y).ToString("D6", inv));
        }

        s.Append('-').Append(mo.ToString("D2", inv))
         .Append('-').Append(d.ToString("D2", inv))
         .Append('T').Append((rem / 3_600_000).ToString("D2", inv))
         .Append(':').Append((rem / 60_000 % 60).ToString("D2", inv))
         .Append(':').Append((rem / 1000 % 60).ToString("D2", inv))
         .Append('.').Append((rem % 1000).ToString("D3", inv))
         .Append('Z');
        return s.ToString();
    }

    /// <summary>Parses the text of <see cref="Format"/>; the fraction may have 0–3 digits.</summary>
    internal static bool TryParse(string s, out long ms)
    {
        ms = 0;
        int i = 0;
        long year;
        if (s.Length > 0 && (s[0] == '+' || s[0] == '-'))
        {
            i = 1;
            int len = 0;
            while (i + len < s.Length && char.IsAsciiDigit(s[i + len]))
            {
                len++;
            }

            // Six digits minimum (ISO 8601 expanded); 12 maximum keeps the arithmetic in i64.
            if (len is < 6 or > 12 || !Number(s, ref i, len, out year))
            {
                return false;
            }

            year = s[0] == '-' ? -year : year;
        }
        else if (!Number(s, ref i, 4, out year))
        {
            return false;
        }

        if (!Expect(s, ref i, '-') || !Number(s, ref i, 2, out long month) || !Expect(s, ref i, '-')
            || !Number(s, ref i, 2, out long day) || !Expect(s, ref i, 'T')
            || !Number(s, ref i, 2, out long hour) || !Expect(s, ref i, ':')
            || !Number(s, ref i, 2, out long minute) || !Expect(s, ref i, ':')
            || !Number(s, ref i, 2, out long second))
        {
            return false;
        }

        long millis = 0;
        if (i < s.Length && s[i] == '.')
        {
            i++;
            int len = 0;
            while (i + len < s.Length && char.IsAsciiDigit(s[i + len]))
            {
                len++;
            }

            if (len is < 1 or > 3 || !Number(s, ref i, len, out millis))
            {
                return false;
            }

            millis *= len switch { 1 => 100, 2 => 10, _ => 1 };
        }

        if (!Expect(s, ref i, 'Z') || i != s.Length || month is < 1 or > 12 || day < 1
            || day > DaysInMonth(year, month) || hour > 23 || minute > 59 || second > 59)
        {
            return false;
        }

        // Int128: the day start can lie below long.MinValue while the instant itself is in range.
        Int128 dayStart = (Int128)DaysFromCivil(year, month, day) * MsPerDay;
        Int128 total = dayStart + (hour * 3_600_000) + (minute * 60_000) + (second * 1000) + millis;
        if (total < long.MinValue || total > long.MaxValue)
        {
            return false;
        }

        ms = (long)total;
        return true;
    }

    private static bool Number(string s, ref int i, int n, out long value)
    {
        value = 0;
        if (i + n > s.Length)
        {
            return false;
        }

        for (int k = 0; k < n; k++)
        {
            char c = s[i + k];
            if (!char.IsAsciiDigit(c))
            {
                return false;
            }

            value = (value * 10) + (c - '0');
        }

        i += n;
        return true;
    }

    private static bool Expect(string s, ref int i, char c)
    {
        if (i < s.Length && s[i] == c)
        {
            i++;
            return true;
        }

        return false;
    }
}
