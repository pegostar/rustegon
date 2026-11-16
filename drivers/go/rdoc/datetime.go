// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rdoc

import (
	"fmt"
	"math/big"
)

// `$date` text: proleptic Gregorian calendar over the whole i64 millisecond range, which
// time.Time cannot format (years beyond 9999 need the ISO 8601 expanded form ±YYYYYY). The day
// arithmetic is Howard Hinnant's civil-from-days, as in the Rust and .NET implementations.

const (
	msPerDay   = 86_400_000
	epochShift = 719_468 // days from 0000-03-01 to 1970-01-01
	daysPerEra = 146_097 // days in 400 Gregorian years
)

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

func daysFromCivil(y, m, d int64) int64 {
	if m <= 2 {
		y--
	}
	era := floorDiv(y, 400)
	yoe := y - era*400
	mp := m + 9
	if m > 2 {
		mp = m - 3
	}
	doy := (153*mp+2)/5 + d - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return era*daysPerEra + doe - epochShift
}

func civilFromDays(z int64) (y, m, d int64) {
	z += epochShift
	era := floorDiv(z, daysPerEra)
	doe := z - era*daysPerEra
	yoe := (doe - doe/1460 + doe/36_524 - doe/146_096) / 365
	doy := doe - (365*yoe + yoe/4 - yoe/100)
	mp := (5*doy + 2) / 153
	d = doy - (153*mp+2)/5 + 1
	m = mp - 9
	if mp < 10 {
		m = mp + 3
	}
	y = yoe + era*400
	if m <= 2 {
		y++
	}
	return y, m, d
}

func daysInMonth(y, m int64) int64 {
	switch m {
	case 2:
		if (y%4 == 0 && y%100 != 0) || y%400 == 0 {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}

// formatDate prints YYYY-MM-DDTHH:MM:SS.mmmZ (expanded ±YYYYYY outside 0000–9999).
func formatDate(ms int64) string {
	days := floorDiv(ms, msPerDay)
	rem := ms - days*msPerDay
	y, mo, d := civilFromDays(days)
	var year string
	switch {
	case y >= 0 && y <= 9999:
		year = fmt.Sprintf("%04d", y)
	case y < 0:
		year = fmt.Sprintf("-%06d", -y)
	default:
		year = fmt.Sprintf("+%06d", y)
	}
	return fmt.Sprintf("%s-%02d-%02dT%02d:%02d:%02d.%03dZ", year, mo, d,
		rem/3_600_000, rem/60_000%60, rem/1000%60, rem%1000)
}

// parseDate parses YYYY-MM-DDTHH:MM:SS[.f{1,3}]Z (expanded years: sign + 6..12 digits).
func parseDate(s string) (int64, bool) {
	i := 0
	num := func(n int) (int64, bool) {
		if i+n > len(s) {
			return 0, false
		}
		var v int64
		for k := 0; k < n; k++ {
			c := s[i+k]
			if !isDigit(c) {
				return 0, false
			}
			v = v*10 + int64(c-'0')
		}
		i += n
		return v, true
	}
	expect := func(c byte) bool {
		if i < len(s) && s[i] == c {
			i++
			return true
		}
		return false
	}
	digitRun := func() int {
		n := 0
		for i+n < len(s) && isDigit(s[i+n]) {
			n++
		}
		return n
	}
	var year int64
	var ok bool
	if s != "" && (s[0] == '+' || s[0] == '-') {
		i = 1
		// Six digits minimum (ISO 8601 expanded); twelve maximum keeps the arithmetic in i64.
		n := digitRun()
		if n < 6 || n > 12 {
			return 0, false
		}
		year, _ = num(n)
		if s[0] == '-' {
			year = -year
		}
	} else if year, ok = num(4); !ok {
		return 0, false
	}
	var month, day, hour, minute, second, millis int64
	for _, step := range []struct {
		sep byte
		dst *int64
	}{{'-', &month}, {'-', &day}, {'T', &hour}, {':', &minute}, {':', &second}} {
		if !expect(step.sep) {
			return 0, false
		}
		if *step.dst, ok = num(2); !ok {
			return 0, false
		}
	}
	if expect('.') {
		n := digitRun()
		if n < 1 || n > 3 {
			return 0, false
		}
		millis, _ = num(n)
		millis *= [...]int64{1, 100, 10, 1}[n]
	}
	if !expect('Z') || i != len(s) || month < 1 || month > 12 || day < 1 ||
		day > daysInMonth(year, month) || hour > 23 || minute > 59 || second > 59 {
		return 0, false
	}
	// big.Int: the day start can lie below MinInt64 while the instant itself is in range.
	total := big.NewInt(daysFromCivil(year, month, day))
	total.Mul(total, big.NewInt(msPerDay))
	total.Add(total, big.NewInt(hour*3_600_000+minute*60_000+second*1000+millis))
	if !total.IsInt64() {
		return 0, false
	}
	return total.Int64(), true
}
