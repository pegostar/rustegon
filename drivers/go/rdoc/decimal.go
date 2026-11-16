// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rdoc

import (
	"math/big"
	"strings"
)

// Decimal128 is an IEEE 754-2008 decimal128 in the BID encoding. It always holds the canonical
// bits: FromBits and the decoder normalize non-canonical encodings (NaN payloads, coefficients
// above 10^34−1, the large-coefficient form), so equal values have equal bits and the cohort
// (12.50 vs 12.5) is preserved. The zero value is 0E-6176.
type Decimal128 struct {
	hi, lo uint64
}

const (
	decMaxDigits   = 34
	decMinExponent = -6176
	decMaxExponent = 6111
	decBias        = 6176
	decSignBit     = uint64(1) << 63
	decInfHi       = uint64(0x78) << 56
	decNaNHi       = uint64(0x7C) << 56
	decCoefHiMask  = uint64(1)<<49 - 1 // the coefficient is 113 bits: 49 in hi, 64 in lo
)

var decMaxCoefficient, _ = new(big.Int).SetString("9999999999999999999999999999999999", 10)

// FromBits builds a Decimal128 from its IEEE BID bits (hi = bits 127..64), normalizing
// non-canonical encodings.
func FromBits(hi, lo uint64) Decimal128 {
	d, _ := decimalFromBits(hi, lo)
	return d
}

// Bits returns the canonical IEEE BID bits.
func (d Decimal128) Bits() (hi, lo uint64) { return d.hi, d.lo }

// IsNaN reports whether d is NaN.
func (d Decimal128) IsNaN() bool { return d.hi == decNaNHi }

// IsInf reports whether d is ±Infinity.
func (d Decimal128) IsInf() bool { return d.hi&^decSignBit == decInfHi }

// decimalFromBits decodes bits and reports whether they were already canonical.
func decimalFromBits(hi, lo uint64) (Decimal128, bool) {
	sign := hi & decSignBit
	switch (hi >> 58) & 0x1F {
	case 0x1F:
		return Decimal128{hi: decNaNHi}, hi == decNaNHi && lo == 0
	case 0x1E:
		return Decimal128{hi: sign | decInfHi}, hi&(uint64(1)<<58-1) == 0 && lo == 0
	}
	var biased uint64
	var cHi, cLo uint64
	canonical := false
	if (hi>>61)&3 == 3 {
		// Large-coefficient form: the implied coefficient is >= 2^113 > 10^34−1, so the value
		// is zero and the encoding never canonical.
		biased = (hi >> 47) & 0x3FFF
	} else {
		biased = (hi >> 49) & 0x3FFF
		cHi, cLo = hi&decCoefHiMask, lo
		canonical = coefficient(cHi, cLo).Cmp(decMaxCoefficient) <= 0
		if !canonical {
			cHi, cLo = 0, 0
		}
	}
	// The large form can carry a biased exponent above 12287; the value is zero, so clamp.
	if biased > decMaxExponent+decBias {
		biased = decMaxExponent + decBias
	}
	return Decimal128{hi: sign | biased<<49 | cHi, lo: cLo}, canonical
}

func coefficient(hi, lo uint64) *big.Int {
	c := new(big.Int).SetUint64(hi)
	c.Lsh(c, 64)
	return c.Or(c, new(big.Int).SetUint64(lo))
}

// ParseDecimal128 parses the IEEE decimal string syntax (Infinity/Inf/NaN case-insensitive,
// optional sign, digits with an optional point, optional exponent). The value must be exact:
// at most 34 significant digits after dropping trailing zeros; the exponent is brought into range
// only by adding or removing zeros (data-model.md §2 notes). Errors are RGN-1001.
func ParseDecimal128(s string) (Decimal128, error) {
	body := s
	var sign uint64
	if body != "" && (body[0] == '-' || body[0] == '+') {
		if body[0] == '-' {
			sign = decSignBit
		}
		body = body[1:]
	}
	switch strings.ToLower(body) {
	case "inf", "infinity":
		return Decimal128{hi: sign | decInfHi}, nil
	case "nan":
		return Decimal128{hi: decNaNHi}, nil
	}
	bad := func(reason string) (Decimal128, error) {
		return Decimal128{}, newError(CodeMalformed, "decimal128 %q: %s", s, reason)
	}
	var digits []byte // significant digits, leading zeros dropped
	var fracLen int64
	seen := false
	i := 0
	push := func(c byte) {
		if c != '0' || len(digits) > 0 {
			digits = append(digits, c-'0')
		}
		seen = true
	}
	for ; i < len(body) && isDigit(body[i]); i++ {
		push(body[i])
	}
	if i < len(body) && body[i] == '.' {
		for i++; i < len(body) && isDigit(body[i]); i++ {
			push(body[i])
			fracLen++
		}
	}
	if !seen {
		return bad("no digits")
	}
	var exp int64
	if i < len(body) && (body[i] == 'e' || body[i] == 'E') {
		i++
		neg := false
		if i < len(body) && (body[i] == '-' || body[i] == '+') {
			neg = body[i] == '-'
			i++
		}
		start := i
		for ; i < len(body) && isDigit(body[i]); i++ {
			// Saturate: beyond ±10^12 is out of range whatever the digits are.
			exp = min(exp*10+int64(body[i]-'0'), 1_000_000_000_000)
		}
		if i == start {
			return bad("empty exponent")
		}
		if neg {
			exp = -exp
		}
	}
	if i != len(body) {
		return bad("unexpected character")
	}
	exp -= fracLen
	if len(digits) == 0 {
		// Zero: clamping the exponent does not change the value (IEEE 754 does the same).
		exp = max(min(exp, decMaxExponent), decMinExponent)
		return Decimal128{hi: sign | uint64(exp+decBias)<<49}, nil
	}
	for len(digits) > decMaxDigits && digits[len(digits)-1] == 0 {
		digits = digits[:len(digits)-1]
		exp++
	}
	if len(digits) > decMaxDigits {
		return bad("more than 34 significant digits (inexact)")
	}
	for exp > decMaxExponent && len(digits) < decMaxDigits {
		digits = append(digits, 0)
		exp--
	}
	if exp > decMaxExponent {
		return bad("exponent overflow")
	}
	for exp < decMinExponent && digits[len(digits)-1] == 0 {
		digits = digits[:len(digits)-1]
		exp++
	}
	if exp < decMinExponent {
		return bad("exponent underflow (inexact)")
	}
	c := new(big.Int)
	ten := big.NewInt(10)
	for _, d := range digits {
		c.Mul(c, ten).Add(c, big.NewInt(int64(d)))
	}
	lo := c.Uint64()
	hi := new(big.Int).Rsh(c, 64).Uint64()
	return Decimal128{hi: sign | uint64(exp+decBias)<<49 | hi, lo: lo}, nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// String is the IEEE "to-scientific-string", which preserves the cohort (12.50, 1E+3, -0).
func (d Decimal128) String() string {
	if d.IsNaN() {
		return "NaN"
	}
	neg := d.hi&decSignBit != 0
	if d.IsInf() {
		if neg {
			return "-Infinity"
		}
		return "Infinity"
	}
	var sb strings.Builder
	if neg {
		sb.WriteByte('-')
	}
	digits := coefficient(d.hi&decCoefHiMask, d.lo).String()
	n := int64(len(digits))
	exponent := int64((d.hi>>49)&0x3FFF) - decBias
	adjusted := exponent + n - 1
	if exponent <= 0 && adjusted >= -6 {
		if exponent == 0 {
			sb.WriteString(digits)
			return sb.String()
		}
		point := n + exponent
		if point > 0 {
			sb.WriteString(digits[:point])
			sb.WriteByte('.')
			sb.WriteString(digits[point:])
			return sb.String()
		}
		sb.WriteString("0.")
		sb.WriteString(strings.Repeat("0", int(-point)))
		sb.WriteString(digits)
		return sb.String()
	}
	sb.WriteByte(digits[0])
	if len(digits) > 1 {
		sb.WriteByte('.')
		sb.WriteString(digits[1:])
	}
	sb.WriteByte('E')
	if adjusted < 0 {
		sb.WriteByte('-')
		adjusted = -adjusted
	} else {
		sb.WriteByte('+')
	}
	sb.WriteString(big.NewInt(adjusted).String())
	return sb.String()
}
