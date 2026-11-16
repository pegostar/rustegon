// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rdoc

import (
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// JSONMode selects the JSON form (data-model.md §2 notes).
type JSONMode int

const (
	// Canonical is plain JSON wherever lossless (int64 within ±2^53, finite float64) and the `$`
	// wrappers otherwise.
	Canonical JSONMode = iota
	// Extended wraps every int64 in {"$int64":…} and every float64 in {"$float":…}.
	Extended
)

// maxSafeInteger is the largest integer magnitude a JSON number carries losslessly through
// IEEE-double parsers.
const maxSafeInteger = 1 << 53

// MarshalJSON prints a model value: compact, fields in stored order, only '"', '\' and C0
// controls escaped, non-ASCII verbatim; the same value always yields the same text.
func MarshalJSON(v any, mode JSONMode) (string, error) {
	var sb strings.Builder
	if err := writeJSON(&sb, v, mode); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func wrap(sb *strings.Builder, key, text string) {
	sb.WriteString(`{"`)
	sb.WriteString(key)
	sb.WriteString(`":"`)
	sb.WriteString(text)
	sb.WriteString(`"}`)
}

func writeJSON(sb *strings.Builder, v any, mode JSONMode) error {
	switch x := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		sb.WriteString(strconv.FormatBool(x))
	case int64:
		if mode == Canonical && x >= -maxSafeInteger && x <= maxSafeInteger {
			sb.WriteString(strconv.FormatInt(x, 10))
		} else {
			wrap(sb, "$int64", strconv.FormatInt(x, 10))
		}
	case float64:
		switch {
		case math.IsNaN(x):
			wrap(sb, "$float", "NaN")
		case math.IsInf(x, 1):
			wrap(sb, "$float", "Infinity")
		case math.IsInf(x, -1):
			wrap(sb, "$float", "-Infinity")
		case mode == Canonical:
			sb.WriteString(formatFloat(x, 64))
		default:
			wrap(sb, "$float", formatFloat(x, 64))
		}
	case Decimal128:
		wrap(sb, "$decimal", x.String())
	case string:
		return writeString(sb, x)
	case Binary:
		sb.WriteString(`{"$binary":{"base64":"`)
		sb.WriteString(base64.StdEncoding.EncodeToString(x.Data))
		fmt.Fprintf(sb, `","subType":"%02x"}}`, x.Subtype)
	case DateTime:
		wrap(sb, "$date", formatDate(int64(x)))
	case Timestamp:
		wrap(sb, "$ts", x.String())
	case ObjectID:
		wrap(sb, "$oid", x.Hex())
	case UUID:
		wrap(sb, "$uuid", x.String())
	case []any:
		sb.WriteByte('[')
		for i, it := range x {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := writeJSON(sb, it, mode); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case Document:
		sb.WriteByte('{')
		for i, f := range x {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := writeString(sb, f.Name); err != nil {
				return err
			}
			sb.WriteByte(':')
			if err := writeJSON(sb, f.Value, mode); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	case Vector:
		sb.WriteString(`{"$vector":[`)
		for i, f := range x {
			if i > 0 {
				sb.WriteByte(',')
			}
			if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
				return newError(CodeInvalidVector, "non-finite vector element")
			}
			sb.WriteString(formatFloat(float64(f), 32))
		}
		sb.WriteString("]}")
	case Counter:
		fmt.Fprintf(sb, `{"$counter":%d}`, int64(x))
	case MinKey:
		sb.WriteString(`{"$minKey":1}`)
	case MaxKey:
		sb.WriteString(`{"$maxKey":1}`)
	default:
		return newError(CodeMalformed, "unsupported Go type %T (use Normalize)", v)
	}
	return nil
}

func writeString(sb *strings.Builder, s string) error {
	if !utf8.ValidString(s) {
		return newError(CodeMalformed, "string is not valid UTF-8")
	}
	sb.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		default:
			if c < 0x20 {
				fmt.Fprintf(sb, `\u%04x`, c)
			} else {
				// Multi-byte UTF-8 sequences pass byte by byte: non-ASCII is verbatim.
				sb.WriteByte(c)
			}
		}
	}
	sb.WriteByte('"')
	return nil
}

// formatFloat is the canonical float text: the shortest round-trip digits (for bitSize 32 the
// shortest float32 digits), always with '.' or an exponent so it parses back as a float;
// exponent form when |x| < 1e-4 or ≥ 1e16 ("1.0", "0.1", "1e300", "9.223372036854776e18").
// This is the rule of the .NET FloatText and the Rust printer.
func formatFloat(x float64, bitSize int) string {
	neg := math.Signbit(x)
	abs := math.Abs(x)
	var exponential bool
	if bitSize == 32 {
		a := float32(abs)
		exponential = a != 0 && (a < 1e-4 || a >= 1e16)
	} else {
		exponential = abs != 0 && (abs < 1e-4 || abs >= 1e16)
	}
	// 'e' with precision -1 gives the shortest digits as "d.ddde±XX".
	e := strconv.FormatFloat(abs, 'e', -1, bitSize)
	mant, expText, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expText)
	digits := strings.Replace(mant, ".", "", 1)
	// value = digits × 10^e10
	e10 := exp - (len(digits) - 1)
	d := strings.TrimLeft(digits, "0")
	n := len(d)
	d = strings.TrimRight(d, "0")
	e10 += n - len(d)

	var sb strings.Builder
	if neg {
		sb.WriteByte('-')
	}
	switch {
	case d == "":
		sb.WriteString("0.0")
	case exponential:
		sb.WriteByte(d[0])
		if len(d) > 1 {
			sb.WriteByte('.')
			sb.WriteString(d[1:])
		}
		sb.WriteByte('e')
		sb.WriteString(strconv.Itoa(e10 + len(d) - 1))
	case e10 >= 0:
		sb.WriteString(d)
		sb.WriteString(strings.Repeat("0", e10))
		sb.WriteString(".0")
	case len(d)+e10 > 0:
		p := len(d) + e10
		sb.WriteString(d[:p])
		sb.WriteByte('.')
		sb.WriteString(d[p:])
	default:
		sb.WriteString("0.")
		sb.WriteString(strings.Repeat("0", -(len(d) + e10)))
		sb.WriteString(d)
	}
	return sb.String()
}
