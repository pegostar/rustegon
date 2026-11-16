// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rdoc

import (
	"encoding/base64"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ParseJSON parses one canonical or extended JSON value (data-model.md §2 notes). Objects keep
// their field order (a hand-written parser: encoding/json maps would lose it). Errors: syntax and
// wrapper errors RGN-1001, names RGN-1004 (`$`-prefixed outside a wrapper, duplicates, NUL,
// empty, `$counter` as input), depth RGN-1003, non-finite vectors RGN-1040.
func ParseJSON(text string) (any, error) {
	if !utf8.ValidString(text) {
		return nil, newError(CodeMalformed, "JSON text is not valid UTF-8")
	}
	p := jsonParser{s: text}
	p.ws()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.pos != len(p.s) {
		return nil, p.err("trailing characters")
	}
	return v, nil
}

// ParseDocumentJSON parses a JSON object as a Document.
func ParseDocumentJSON(text string) (Document, error) {
	v, err := ParseJSON(text)
	if err != nil {
		return nil, err
	}
	d, ok := v.(Document)
	if !ok {
		return nil, newError(CodeMalformed, "a document must be a JSON object")
	}
	return d, nil
}

type jsonParser struct {
	s   string
	pos int
}

func (p *jsonParser) err(reason string) *Error {
	return newError(CodeMalformed, "%s at offset %d", reason, p.pos)
}

// peek returns the next byte, or 0 at the end (0 is never valid where it is tested).
func (p *jsonParser) peek() byte {
	if p.pos < len(p.s) {
		return p.s[p.pos]
	}
	return 0
}

func (p *jsonParser) ws() {
	for {
		switch p.peek() {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *jsonParser) eat(c byte) error {
	p.ws()
	if p.peek() != c {
		return p.err("expected '" + string(c) + "'")
	}
	p.pos++
	return nil
}

func (p *jsonParser) value(depth int) (any, error) {
	p.ws()
	switch c := p.peek(); {
	case c == '{':
		return p.object(depth + 1)
	case c == '[':
		return p.array(depth + 1)
	case c == '"':
		return p.str()
	case c == 't':
		return p.literal("true", true)
	case c == 'f':
		return p.literal("false", false)
	case c == 'n':
		return p.literal("null", nil)
	case c == '-' || isDigit(c):
		text, integral, err := p.number()
		if err != nil {
			return nil, err
		}
		return p.numberValue(text, integral)
	}
	return nil, p.err("expected a value")
}

func (p *jsonParser) literal(word string, v any) (any, error) {
	if !strings.HasPrefix(p.s[p.pos:], word) {
		return nil, p.err("invalid literal")
	}
	p.pos += len(word)
	return v, nil
}

func (p *jsonParser) array(depth int) (any, error) {
	if err := checkDepth(depth); err != nil {
		return nil, err
	}
	p.pos++ // '['
	items := []any{}
	p.ws()
	if p.peek() == ']' {
		p.pos++
		return items, nil
	}
	for {
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
		p.ws()
		switch p.peek() {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return items, nil
		default:
			return nil, p.err("expected ',' or ']'")
		}
	}
}

func (p *jsonParser) object(depth int) (any, error) {
	if err := checkDepth(depth); err != nil {
		return nil, err
	}
	p.pos++ // '{'
	doc := Document{}
	seen := map[string]struct{}{}
	p.ws()
	if p.peek() == '}' {
		p.pos++
		return doc, nil
	}
	for {
		p.ws()
		if p.peek() != '"' {
			return nil, p.err("expected a field name")
		}
		name, err := p.str()
		if err != nil {
			return nil, err
		}
		if err := p.eat(':'); err != nil {
			return nil, err
		}
		if len(doc) == 0 && strings.HasPrefix(name, "$") {
			// A `$` name is legal only as the single key of an extended-JSON wrapper.
			w, err := p.wrapper(name)
			if err != nil {
				return nil, err
			}
			if err := p.eat('}'); err != nil {
				return nil, err
			}
			return w, nil
		}
		if r := fieldNameError(name); r != "" {
			return nil, newError(CodeInvalidFieldName, "%s at offset %d", r, p.pos)
		}
		if _, dup := seen[name]; dup {
			return nil, newError(CodeInvalidFieldName, "duplicate field name %q", name)
		}
		seen[name] = struct{}{}
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		doc = append(doc, Field{name, v})
		p.ws()
		switch p.peek() {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return doc, nil
		default:
			return nil, p.err("expected ',' or '}'")
		}
	}
}

func (p *jsonParser) str() (string, error) {
	p.pos++ // opening quote
	var sb strings.Builder
	for {
		start := p.pos
		for p.pos < len(p.s) && p.s[p.pos] != '"' && p.s[p.pos] != '\\' && p.s[p.pos] >= ' ' {
			p.pos++
		}
		sb.WriteString(p.s[start:p.pos])
		switch p.peek() {
		case '"':
			p.pos++
			return sb.String(), nil
		case '\\':
			p.pos++
			if err := p.escape(&sb); err != nil {
				return "", err
			}
		default:
			if p.pos >= len(p.s) {
				return "", p.err("unterminated string")
			}
			return "", p.err("control character in string")
		}
	}
}

func (p *jsonParser) escape(sb *strings.Builder) error {
	if p.pos >= len(p.s) {
		return p.err("unterminated escape")
	}
	c := p.s[p.pos]
	p.pos++
	switch c {
	case '"', '\\', '/':
		sb.WriteByte(c)
	case 'b':
		sb.WriteByte('\b')
	case 'f':
		sb.WriteByte('\f')
	case 'n':
		sb.WriteByte('\n')
	case 'r':
		sb.WriteByte('\r')
	case 't':
		sb.WriteByte('\t')
	case 'u':
		hi, err := p.hex4()
		if err != nil {
			return err
		}
		switch {
		case hi >= 0xD800 && hi < 0xDC00:
			if !strings.HasPrefix(p.s[p.pos:], `\u`) {
				return p.err("lone surrogate")
			}
			p.pos += 2
			lo, err := p.hex4()
			if err != nil {
				return err
			}
			if lo < 0xDC00 || lo >= 0xE000 {
				return p.err("lone surrogate")
			}
			sb.WriteRune(utf16.DecodeRune(hi, lo))
		case hi >= 0xDC00 && hi < 0xE000:
			return p.err("lone surrogate")
		default:
			sb.WriteRune(hi)
		}
	default:
		return p.err("invalid escape")
	}
	return nil
}

func (p *jsonParser) hex4() (rune, error) {
	if p.pos+4 > len(p.s) {
		return 0, p.err(`bad \u escape`)
	}
	v, err := strconv.ParseUint(p.s[p.pos:p.pos+4], 16, 32)
	if err != nil {
		return 0, p.err(`bad \u escape`)
	}
	p.pos += 4
	return rune(v), nil
}

func (p *jsonParser) digits() int {
	from := p.pos
	for isDigit(p.peek()) {
		p.pos++
	}
	return p.pos - from
}

// number scans JSON number syntax and returns its text and whether it is an integer literal.
func (p *jsonParser) number() (string, bool, error) {
	start := p.pos
	if p.peek() == '-' {
		p.pos++
	}
	intStart := p.pos
	n := p.digits()
	if n == 0 || (n > 1 && p.s[intStart] == '0') {
		return "", false, p.err("invalid number")
	}
	integral := true
	if p.peek() == '.' {
		p.pos++
		integral = false
		if p.digits() == 0 {
			return "", false, p.err("invalid number fraction")
		}
	}
	if c := p.peek(); c == 'e' || c == 'E' {
		p.pos++
		integral = false
		if c := p.peek(); c == '+' || c == '-' {
			p.pos++
		}
		if p.digits() == 0 {
			return "", false, p.err("invalid number exponent")
		}
	}
	return p.s[start:p.pos], integral, nil
}

// numberValue: integers within i64 → int64 ("-0" is 0), anything else → the nearest float64;
// beyond the float64 range is rejected, since plain JSON cannot mean infinity.
func (p *jsonParser) numberValue(text string, integral bool) (any, error) {
	if integral {
		if i, err := strconv.ParseInt(text, 10, 64); err == nil {
			return i, nil
		}
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(f, 0) {
		return nil, p.err("number outside the float64 range")
	}
	return f, nil
}

func (p *jsonParser) wrapperString() (string, error) {
	p.ws()
	if p.peek() != '"' {
		return "", p.err("expected a string")
	}
	return p.str()
}

func (p *jsonParser) wrapper(key string) (any, error) {
	at := p.pos
	bad := func(reason string) error {
		return newError(CodeMalformed, "%s: %s at offset %d", key, reason, at)
	}
	switch key {
	case "$minKey", "$maxKey":
		p.ws()
		if c := p.peek(); c != '-' && !isDigit(c) {
			return nil, bad("expected 1")
		}
		text, _, err := p.number()
		if err != nil || text != "1" {
			return nil, bad("expected 1")
		}
		if key == "$minKey" {
			return MinKey{}, nil
		}
		return MaxKey{}, nil
	case "$binary":
		return p.binary()
	case "$vector":
		return p.vector()
	case "$counter":
		return nil, newError(CodeInvalidFieldName, "$counter is a read-only projection, not accepted as input")
	case "$int64", "$float", "$decimal", "$date", "$oid", "$uuid", "$ts":
	default:
		return nil, newError(CodeInvalidFieldName, "field name %q starts with '$'", key)
	}
	s, err := p.wrapperString()
	if err != nil {
		return nil, err
	}
	switch key {
	case "$int64":
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, bad("not an int64")
		}
		return i, nil
	case "$float":
		return floatWrapper(s, bad)
	case "$decimal":
		d, err := ParseDecimal128(s)
		if err != nil {
			return nil, bad("not an exact decimal128")
		}
		return d, nil
	case "$date":
		ms, ok := parseDate(s)
		if !ok {
			return nil, bad("invalid $date (expected YYYY-MM-DDTHH:MM:SS.mmmZ)")
		}
		return DateTime(ms), nil
	case "$oid":
		id, err := ParseObjectID(s)
		if err != nil {
			return nil, bad("objectId must be 24 hex digits")
		}
		return id, nil
	case "$uuid":
		u, err := ParseUUID(s)
		if err != nil {
			return nil, bad("expected 8-4-4-4-12 hex")
		}
		return u, nil
	}
	// $ts: "<wall>.<logical>", decimal u64.u32.
	w, l, ok := strings.Cut(s, ".")
	if !ok || !allDigits(w) || !allDigits(l) {
		return nil, bad("expected wall.logical")
	}
	wall, err := strconv.ParseUint(w, 10, 64)
	if err != nil {
		return nil, bad("wall out of range")
	}
	logical, err := strconv.ParseUint(l, 10, 32)
	if err != nil {
		return nil, bad("logical out of range")
	}
	return Timestamp{wall, uint32(logical)}, nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// floatWrapper: "NaN", "Infinity", "-Infinity" or a JSON number string. As Rust's
// str::parse::<f64>, an out-of-range magnitude gives ±Infinity here.
func floatWrapper(s string, bad func(string) error) (any, error) {
	switch s {
	case "NaN":
		return math.NaN(), nil
	case "Infinity":
		return math.Inf(1), nil
	case "-Infinity":
		return math.Inf(-1), nil
	}
	if s == "" || (s[0] != '-' && !isDigit(s[0])) {
		return nil, bad("not a number")
	}
	q := jsonParser{s: s}
	text, _, err := q.number()
	if err != nil || q.pos != len(s) {
		return nil, bad("not a number")
	}
	f, _ := strconv.ParseFloat(text, 64) // syntax already checked; overflow is ±Inf
	return f, nil
}

func (p *jsonParser) binary() (any, error) {
	at := p.pos
	bad := func(reason string) error {
		return newError(CodeMalformed, "$binary: %s at offset %d", reason, at)
	}
	if err := p.eat('{'); err != nil {
		return nil, err
	}
	var data []byte
	haveData := false
	subtype := -1
	for i := 0; i < 2; i++ {
		if i > 0 {
			if err := p.eat(','); err != nil {
				return nil, err
			}
		}
		p.ws()
		if p.peek() != '"' {
			return nil, bad("expected base64 and subType")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		if err := p.eat(':'); err != nil {
			return nil, err
		}
		v, err := p.wrapperString()
		if err != nil {
			return nil, err
		}
		switch {
		case k == "base64" && !haveData:
			if data, err = strictBase64(v); err != nil {
				return nil, bad("invalid base64")
			}
			haveData = true
		case k == "subType" && subtype < 0:
			b, err := hex.DecodeString(v)
			if len(v) != 2 || err != nil {
				return nil, bad("subType is 2 hex digits")
			}
			subtype = int(b[0])
		default:
			return nil, bad("expected base64 and subType")
		}
	}
	if err := p.eat('}'); err != nil {
		return nil, err
	}
	if r := checkBinary(byte(subtype), len(data)); r != "" {
		return nil, bad(r)
	}
	if data == nil {
		data = []byte{}
	}
	return Binary{Subtype: byte(subtype), Data: data}, nil
}

// strictBase64 accepts RFC 4648 with padding and zero unused bits only: the one canonical text.
func strictBase64(s string) ([]byte, error) {
	data, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(data) != s {
		return nil, newError(CodeMalformed, "invalid base64")
	}
	return data, nil
}

func (p *jsonParser) vector() (any, error) {
	if err := p.eat('['); err != nil {
		return nil, err
	}
	xs := Vector{}
	p.ws()
	if p.peek() == ']' {
		p.pos++
		return xs, nil
	}
	for {
		p.ws()
		if c := p.peek(); c != '-' && !isDigit(c) {
			return nil, p.err("invalid number")
		}
		text, _, err := p.number()
		if err != nil {
			return nil, err
		}
		// Parsed straight to float32 (correctly rounded, as .NET and Rust do); overflow is ±Inf.
		f, _ := strconv.ParseFloat(text, 32)
		if math.IsInf(f, 0) {
			return nil, newError(CodeInvalidVector, "vector element outside the f32 range")
		}
		xs = append(xs, float32(f))
		p.ws()
		switch p.peek() {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return xs, nil
		default:
			return nil, p.err("expected ',' or ']'")
		}
	}
}
