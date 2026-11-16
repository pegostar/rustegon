// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

/**
 * ISO 8601 text of {@code datetime} values ({@code {"$date":"2026-01-01T00:00:00.000Z"}}),
 * a port of the server's {@code rustegon-doc} implementation (data-model.md §2).
 *
 * <p>The full int64 millisecond range (±292 million years) is supported: years 0000–9999 use
 * four digits, others the ISO 8601 expanded form (sign and at least six digits). Calendar
 * arithmetic is the proleptic Gregorian {@code days_from_civil} / {@code civil_from_days} of
 * H. Hinnant ("chrono-Compatible Low-Level Date Algorithms"); {@link java.time} is not used
 * because its year range (±999 999 999) and parser differ from the server's grammar.
 */
final class IsoDate {
    private static final long MS_PER_DAY = 86_400_000L;
    /** Days between 0000-03-01 and 1970-01-01 (Hinnant's epoch shift). */
    private static final long EPOCH_SHIFT = 719_468L;
    /** Days in a 400-year Gregorian era. */
    private static final long DAYS_PER_ERA = 146_097L;

    private IsoDate() {}

    private static long daysFromCivil(long y, long m, long d) {
        y = m <= 2 ? y - 1 : y;
        long era = Math.floorDiv(y, 400);
        long yoe = y - era * 400;
        long mp = m > 2 ? m - 3 : m + 9;
        long doy = (153 * mp + 2) / 5 + d - 1;
        long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * DAYS_PER_ERA + doe - EPOCH_SHIFT;
    }

    /** {@code {year, month, day}} of a day number. */
    private static long[] civilFromDays(long z) {
        z += EPOCH_SHIFT;
        long era = Math.floorDiv(z, DAYS_PER_ERA);
        long doe = z - era * DAYS_PER_ERA;
        long yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        long mp = (5 * doy + 2) / 153;
        long d = doy - (153 * mp + 2) / 5 + 1;
        long m = mp < 10 ? mp + 3 : mp - 9;
        long y = yoe + era * 400;
        return new long[] {m <= 2 ? y + 1 : y, m, d};
    }

    private static long daysInMonth(long y, long m) {
        if (m == 2) {
            return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 ? 29 : 28;
        }
        return m == 4 || m == 6 || m == 9 || m == 11 ? 30 : 31;
    }

    /** {@code YYYY-MM-DDTHH:MM:SS.mmmZ} of milliseconds since the epoch. */
    static String format(long ms) {
        long days = Math.floorDiv(ms, MS_PER_DAY);
        long rem = Math.floorMod(ms, MS_PER_DAY);
        long[] ymd = civilFromDays(days);
        long y = ymd[0];
        StringBuilder s = new StringBuilder(24);
        if (y >= 0 && y <= 9999) {
            s.append(String.format(java.util.Locale.ROOT, "%04d", y));
        } else {
            s.append(y < 0 ? '-' : '+').append(String.format(java.util.Locale.ROOT, "%06d", Math.abs(y)));
        }
        s.append(String.format(java.util.Locale.ROOT, "-%02d-%02dT%02d:%02d:%02d.%03dZ", ymd[1], ymd[2],
                rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000));
        return s.toString();
    }

    /** Parses the text of {@link #format}; the fraction may have 0–3 digits. */
    static long parse(String s) {
        Cursor c = new Cursor(s);
        long year;
        char first = s.isEmpty() ? 0 : s.charAt(0);
        if (first == '+' || first == '-') {
            c.i = 1;
            int len = c.digitRun();
            // Six digits minimum (ISO 8601 expanded); 12 maximum keeps the arithmetic in range.
            if (len < 6 || len > 12) {
                throw bad();
            }
            year = c.num(len);
            if (first == '-') {
                year = -year;
            }
        } else {
            year = c.num(4);
        }
        c.expect('-');
        long month = c.num(2);
        c.expect('-');
        long day = c.num(2);
        c.expect('T');
        long hour = c.num(2);
        c.expect(':');
        long minute = c.num(2);
        c.expect(':');
        long second = c.num(2);
        long millis = 0;
        if (c.i < s.length() && s.charAt(c.i) == '.') {
            c.i++;
            int len = c.digitRun();
            if (len < 1 || len > 3) {
                throw bad();
            }
            millis = c.num(len) * (len == 1 ? 100 : len == 2 ? 10 : 1);
        }
        c.expect('Z');
        if (c.i != s.length() || month < 1 || month > 12 || day < 1
                || day > daysInMonth(year, month) || hour > 23 || minute > 59 || second > 59) {
            throw bad();
        }
        // The day start can lie below Long.MIN_VALUE while the instant itself is in range.
        java.math.BigInteger total = java.math.BigInteger.valueOf(daysFromCivil(year, month, day))
                .multiply(java.math.BigInteger.valueOf(MS_PER_DAY))
                .add(java.math.BigInteger.valueOf(
                        hour * 3_600_000 + minute * 60_000 + second * 1000 + millis));
        if (total.bitLength() > 63) {
            throw bad();
        }
        return total.longValue();
    }

    private static RDocException bad() {
        return RDocException.invalid("invalid $date (expected YYYY-MM-DDTHH:MM:SS.mmmZ)");
    }

    /** Position in the text being parsed. */
    private static final class Cursor {
        private final String s;
        private int i;

        Cursor(String s) {
            this.s = s;
        }

        int digitRun() {
            int n = 0;
            while (i + n < s.length() && s.charAt(i + n) >= '0' && s.charAt(i + n) <= '9') {
                n++;
            }
            return n;
        }

        long num(int n) {
            if (i + n > s.length()) {
                throw bad();
            }
            long v = 0;
            for (int k = 0; k < n; k++) {
                char ch = s.charAt(i + k);
                if (ch < '0' || ch > '9') {
                    throw bad();
                }
                v = v * 10 + (ch - '0');
            }
            i += n;
            return v;
        }

        void expect(char ch) {
            if (i >= s.length() || s.charAt(i) != ch) {
                throw bad();
            }
            i++;
        }
    }
}
