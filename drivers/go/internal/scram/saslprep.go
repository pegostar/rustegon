// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package scram

import (
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// errSASLPrep never carries the input: the input is usually a password.
var errSASLPrep = errors.New("scram: the string is not valid SASLprep text")

// randALCatRanges is RFC 3454 D.1 (bidirectional property R or AL, Unicode 3.2) as inclusive
// pairs; identical to the .NET driver's table.
var randALCatRanges = []rune{
	0x05BE, 0x05BE, 0x05C0, 0x05C0, 0x05C3, 0x05C3, 0x05D0, 0x05EA, 0x05F0, 0x05F4,
	0x061B, 0x061B, 0x061F, 0x061F, 0x0621, 0x063A, 0x0640, 0x064A, 0x066D, 0x066F,
	0x0671, 0x06D5, 0x06DD, 0x06DD, 0x06E5, 0x06E6, 0x06FA, 0x06FE, 0x0700, 0x070D,
	0x0710, 0x0710, 0x0712, 0x072C, 0x0780, 0x07A5, 0x07B1, 0x07B1, 0x200F, 0x200F,
	0xFB1D, 0xFB1D, 0xFB1F, 0xFB28, 0xFB2A, 0xFB36, 0xFB38, 0xFB3C, 0xFB3E, 0xFB3E,
	0xFB40, 0xFB41, 0xFB43, 0xFB44, 0xFB46, 0xFBB1, 0xFBD3, 0xFD3D, 0xFD50, 0xFD8F,
	0xFD92, 0xFDC7, 0xFDF0, 0xFDFC, 0xFE70, 0xFE74, 0xFE76, 0xFEFC,
}

// SASLPrep prepares a user name or password with SASLprep (RFC 4013, the stringprep profile of
// RFC 3454), mirroring the .NET driver (PD-074): map (C.1.2 -> space, then drop B.1), NFKC, reject
// prohibited output (C.1.2, C.2.1, C.2.2, C.3-C.9) and unassigned code points (A.1, Unicode 3.2,
// the server's table), check bidirectional text. The error never contains the input.
//
// NFKC uses x/text's current Unicode version, as .NET and Java do; it differs from 3.2 only on
// code points A.1 rejects anyway. LCat is approximated as "letter outside the right-to-left
// blocks", so the bidi check can only accept a string the server rejects (a plain wrong-password
// login), never reject one it accepts (drivers/DIVERGENCES.md).
func SASLPrep(s string) (string, error) {
	// Invalid UTF-8 is Go's analogue of a lone surrogate (C.5): not a character.
	if !utf8.ValidString(s) {
		return "", errSASLPrep
	}
	// Fast path, as the Rust crate: printable ASCII is unchanged by every step.
	if strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r >= 0x7F }) < 0 {
		return s, nil
	}

	var mapped strings.Builder
	for _, r := range s {
		switch {
		case isNonASCIISpace(r): // checked first: U+200B is in both C.1.2 and B.1
			mapped.WriteByte(' ')
		case !isMappedToNothing(r):
			mapped.WriteRune(r)
		}
	}
	normalized := norm.NFKC.String(mapped.String())

	var anyRandAL, anyL bool
	var first, last rune = -1, -1
	for _, r := range normalized {
		if isProhibited(r) || inRanges(unassignedRanges, r) {
			return "", errSASLPrep
		}
		if first < 0 {
			first = r
		}
		last = r
		anyRandAL = anyRandAL || inRanges(randALCatRanges, r)
		anyL = anyL || isLCat(r)
	}
	// RFC 3454 §6: with any RandALCat there must be no LCat, and first and last must be RandALCat.
	if anyRandAL && (anyL || !inRanges(randALCatRanges, first) || !inRanges(randALCatRanges, last)) {
		return "", errSASLPrep
	}
	return normalized, nil
}

// isNonASCIISpace is RFC 3454 C.1.2.
func isNonASCIISpace(c rune) bool {
	return c == 0x00A0 || c == 0x1680 || (c >= 0x2000 && c <= 0x200B) || c == 0x202F || c == 0x205F || c == 0x3000
}

// isMappedToNothing is RFC 3454 B.1.
func isMappedToNothing(c rune) bool {
	return c == 0x00AD || c == 0x034F || c == 0x1806 || (c >= 0x180B && c <= 0x180D) ||
		(c >= 0x200B && c <= 0x200D) || c == 0x2060 || (c >= 0xFE00 && c <= 0xFE0F) || c == 0xFEFF
}

// isProhibited is RFC 4013 §2.3: tables C.1.2, C.2.1, C.2.2, C.3 to C.9.
func isProhibited(c rune) bool {
	return isNonASCIISpace(c) || // C.1.2
		c <= 0x1F || c == 0x7F || // C.2.1
		(c >= 0x80 && c <= 0x9F) || c == 0x06DD || c == 0x070F || c == 0x180E || c == 0x200C ||
		c == 0x200D || c == 0x2028 || c == 0x2029 || (c >= 0x2060 && c <= 0x2063) ||
		(c >= 0x206A && c <= 0x206F) || c == 0xFEFF || (c >= 0xFFF9 && c <= 0xFFFC) ||
		(c >= 0x1D173 && c <= 0x1D17A) || // C.2.2
		(c >= 0xE000 && c <= 0xF8FF) || (c >= 0xF0000 && c <= 0xFFFFD) || (c >= 0x100000 && c <= 0x10FFFD) || // C.3
		(c >= 0xFDD0 && c <= 0xFDEF) || c&0xFFFE == 0xFFFE || // C.4
		(c >= 0xD800 && c <= 0xDFFF) || // C.5
		(c >= 0xFFF9 && c <= 0xFFFD) || // C.6
		(c >= 0x2FF0 && c <= 0x2FFB) || // C.7
		c == 0x0340 || c == 0x0341 || c == 0x200E || c == 0x200F || (c >= 0x202A && c <= 0x202E) || // C.8
		c == 0xE0001 || (c >= 0xE0020 && c <= 0xE007F) // C.9
}

// isLCat approximates RFC 3454 D.2: letters outside the right-to-left blocks (see SASLPrep).
func isLCat(c rune) bool {
	if (c >= 0x0590 && c <= 0x08FF) || (c >= 0xFB1D && c <= 0xFDFF) || (c >= 0xFE70 && c <= 0xFEFF) ||
		(c >= 0x10800 && c <= 0x10FFF) || (c >= 0x1E800 && c <= 0x1EFFF) {
		return false
	}
	return unicode.IsLetter(c)
}

// inRanges binary-searches sorted inclusive [start, end] pairs.
func inRanges(ranges []rune, c rune) bool {
	n := len(ranges) / 2
	i := sort.Search(n, func(i int) bool { return ranges[2*i+1] >= c })
	return i < n && ranges[2*i] <= c
}
