// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rdoc

import (
	"encoding/hex"
	"errors"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const vectorDir = "../../conformance/codec"

// TC-DRV-GO-001: the codec golden vectors (drivers/conformance/README.md §3).
func TestTCDrvGo001CodecValueVectors(t *testing.T) {
	if err := CheckVectors(vectorDir, "values.yaml"); err != nil {
		t.Fatal(err)
	}
}

func TestTCDrvGo001CodecDocumentVectors(t *testing.T) {
	if err := CheckVectors(vectorDir, "documents.yaml"); err != nil {
		t.Fatal(err)
	}
}

func TestTCDrvGo001CodecInvalidVectors(t *testing.T) {
	if err := CheckVectors(vectorDir, "invalid.yaml"); err != nil {
		t.Fatal(err)
	}
}

func TestTCDrvGo001Decimal128ParsePrint(t *testing.T) {
	cases := []struct{ in, out string }{
		{"12.50", "12.50"},
		{"+1.0", "1.0"},
		{"0.000001", "0.000001"},
		{"0.0000001", "1E-7"},
		{"1E+3", "1E+3"},
		{"1000", "1000"},
		{"123e-2", "1.23"},
		{"-0", "-0"},
		{"0E+7000", "0E+6111"}, // zero clamps silently
		{"0E-7000", "0E-6176"},
		{"1E+6144", "1.000000000000000000000000000000000E+6144"}, // zeros added to fit
		{"1000E-6178", "1.0E-6175"},                              // zeros removed to fit
		{"inf", "Infinity"},
		{"-INFINITY", "-Infinity"},
		{"nan", "NaN"},
		{"12345678901234567890123456789012340", "1.234567890123456789012345678901234E+34"},
	}
	for _, c := range cases {
		d, err := ParseDecimal128(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got := d.String(); got != c.out {
			t.Errorf("%s: want %s, got %s", c.in, c.out, got)
		}
		hi, lo := d.Bits()
		if FromBits(hi, lo) != d {
			t.Errorf("%s: bits do not round trip", c.in)
		}
	}
	for _, bad := range []string{"", "-", ".", "1e", "1.2.3", "1E+6145", "1E-6177", "abc", " 1",
		"12345678901234567890123456789012345", "1E+99999999999999999999"} {
		if _, err := ParseDecimal128(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTCDrvGo001ObjectIDGeneration(t *testing.T) {
	before := time.Now().Unix()
	seen := map[ObjectID]bool{}
	var first ObjectID
	for i := 0; i < 10000; i++ {
		id := NewObjectID()
		if seen[id] {
			t.Fatalf("duplicate %s", id)
		}
		seen[id] = true
		if i == 0 {
			first = id
		}
		if string(id[4:9]) != string(first[4:9]) {
			t.Fatal("process-random part changed")
		}
	}
	secs := int64(first[0])<<24 | int64(first[1])<<16 | int64(first[2])<<8 | int64(first[3])
	if secs < before || secs > time.Now().Unix() {
		t.Fatalf("timestamp %d not current", secs)
	}
	p, err := ParseObjectID(strings.ToUpper(first.Hex()))
	if err != nil || p != first || first.String() != first.Hex() {
		t.Fatal("hex round trip failed")
	}
	for _, bad := range []string{"", "65a1b2", "65a1b2c3d4e5f60718293a4g", "65a1b2c3d4e5f60718293a4b0"} {
		if _, err := ParseObjectID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	u, err := ParseUUID("01234567-89AB-cdef-0123-456789abcdef")
	if err != nil || u.String() != "01234567-89ab-cdef-0123-456789abcdef" {
		t.Fatalf("uuid: %v %s", err, u)
	}
	if _, err := ParseUUID("0123456789abcdef0123456789abcdef"); err == nil {
		t.Error("uuid without hyphens accepted")
	}
}

func TestTCDrvGo001Normalize(t *testing.T) {
	when := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	in := map[string]any{
		"z": 1, "a": []string{"x"}, "t": when, "b": []byte{1}, "f": float32(1.5),
		"d": &Document{{"k", uint8(2)}}, "n": []Document{{}},
	}
	got, err := Normalize(in)
	if err != nil {
		t.Fatal(err)
	}
	want := Document{
		{"a", []any{"x"}}, {"b", Binary{0, []byte{1}}}, {"d", Document{{"k", int64(2)}}},
		{"f", 1.5}, {"n", []any{Document{}}}, {"t", NewDateTime(when)}, {"z", int64(1)},
	}
	if !Equal(got, want, true) {
		t.Fatalf("got %#v", got)
	}
	if _, err := Normalize(uint64(math.MaxUint64)); err == nil {
		t.Error("uint64 overflow accepted")
	}
	if _, err := Normalize(struct{}{}); err == nil {
		t.Error("struct accepted")
	}
	if ty, _ := TypeOf(Vector{}); ty.String() != "vector_f32" || TypeObjectID.String() != "objectId" {
		t.Error("type names")
	}
}

func TestTCDrvGo001EncodeValidation(t *testing.T) {
	cases := []struct {
		name string
		doc  Document
		code int
	}{
		{"dollar", Document{{"$a", nil}}, CodeInvalidFieldName},
		{"empty", Document{{"", nil}}, CodeInvalidFieldName},
		{"nul", Document{{"a\x00", nil}}, CodeInvalidFieldName},
		{"dup", Document{{"a", nil}, {"a", nil}}, CodeInvalidFieldName},
		{"counter", Document{{"c", Counter(1)}}, CodeInvalidFieldName},
		{"nan vector", Document{{"v", Vector{float32(math.NaN())}}}, CodeInvalidVector},
		{"bad utf8", Document{{"s", "\xff"}}, CodeMalformed},
		{"int", Document{{"i", 1}}, CodeMalformed},
		{"reserved subtype", Document{{"b", Binary{5, nil}}}, CodeMalformed},
		{"too large", Document{{"s", strings.Repeat("x", MaxDocumentSize)}}, CodeTooLarge},
	}
	deep := Document{}
	for i := 0; i < MaxDepth; i++ {
		deep = Document{{"a", deep}}
	}
	cases = append(cases, struct {
		name string
		doc  Document
		code int
	}{"too deep", deep, CodeTooDeep})
	for _, c := range cases {
		_, err := EncodeDocument(c.doc)
		var e *Error
		if !errors.As(err, &e) || e.Code != c.code {
			t.Errorf("%s: want %d, got %v", c.name, c.code, err)
		}
	}
}

// randomValue builds a random model value (no Counter: it is decode-only).
func randomValue(r *rand.Rand, depth int) any {
	k := r.Intn(17)
	if depth > 4 && k >= 15 {
		k = 0
	}
	switch k {
	case 0:
		return nil
	case 1:
		return r.Intn(2) == 1
	case 2:
		return r.Int63() - r.Int63()
	case 3:
		return math.Float64frombits(r.Uint64())
	case 4:
		return FromBits(r.Uint64(), r.Uint64())
	case 5:
		b := make([]byte, r.Intn(20))
		r.Read(b)
		return strings.ToValidUTF8(string(b), "?") + "é"
	case 6:
		b := make([]byte, r.Intn(5))
		r.Read(b)
		return Binary{byte(0x80 + r.Intn(0x80)), b}
	case 7:
		return DateTime(r.Int63() - r.Int63())
	case 8:
		return Timestamp{r.Uint64(), r.Uint32()}
	case 9:
		var id ObjectID
		r.Read(id[:])
		return id
	case 10:
		var u UUID
		r.Read(u[:])
		return u
	case 11:
		v := make(Vector, r.Intn(4))
		for i := range v {
			v[i] = float32(r.NormFloat64())
		}
		return v
	case 12:
		return MinKey{}
	case 13:
		return MaxKey{}
	case 14:
		return "plain"
	case 15:
		a := make([]any, r.Intn(4))
		for i := range a {
			a[i] = randomValue(r, depth+1)
		}
		return a
	}
	return randomDocument(r, depth+1)
}

func randomDocument(r *rand.Rand, depth int) Document {
	n := r.Intn(6)
	d := make(Document, 0, n)
	for i := 0; i < n; i++ {
		d = append(d, Field{"f" + string(rune('a'+i)) + strings.Repeat("ü", r.Intn(3)), randomValue(r, depth)})
	}
	return d
}

func TestTCDrvGo001RoundTripProperty(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		d := randomDocument(r, 1)
		b, err := EncodeDocument(d)
		if err != nil {
			t.Fatalf("encode %#v: %v", d, err)
		}
		got, err := DecodeDocument(b)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !Equal(d, got, true) {
			t.Fatalf("binary round trip differs: %#v vs %#v", d, got)
		}
		for _, mode := range []JSONMode{Canonical, Extended} {
			text, err := MarshalJSON(d, mode)
			if err != nil {
				t.Fatal(err)
			}
			back, err := ParseDocumentJSON(text)
			if err != nil {
				t.Fatalf("parse %s: %v", text, err)
			}
			if !Equal(d, back, true) {
				t.Fatalf("JSON round trip differs: %s", text)
			}
		}
	}
}

func TestTCDrvGo001FloatText(t *testing.T) {
	cases := map[float64]string{
		1: "1.0", 0.1: "0.1", 1e300: "1e300", 1e16: "1e16", 1e15: "1000000000000000.0",
		1e-4: "0.0001", 1.5e-5: "1.5e-5", -2.5: "-2.5", 123456.789: "123456.789",
	}
	for f, want := range cases {
		if got := formatFloat(f, 64); got != want {
			t.Errorf("%v: want %s, got %s", f, want, got)
		}
	}
}

// FuzzDecodeDocument: no input may panic or hang; accepted input re-encodes and decodes equal.
func FuzzDecodeDocument(f *testing.F) {
	for _, file := range []string{"documents.yaml", "invalid.yaml"} {
		raw, err := os.ReadFile(filepath.Join(vectorDir, file))
		if err != nil {
			f.Fatal(err)
		}
		var vf vectorFile
		if err := yaml.Unmarshal(raw, &vf); err != nil {
			f.Fatal(err)
		}
		for _, e := range append(append(vf.Documents, vf.Noncanonical...), vf.Values...) {
			if b, err := hex.DecodeString(e.Hex); err == nil {
				f.Add(b)
			}
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := DecodeDocument(b)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("non-codec error %T", err)
			}
			_, _ = DecodeValue(b)
			return
		}
		out, err := EncodeDocument(d)
		if err != nil {
			var e *Error
			if errors.As(err, &e) && e.Code == CodeInvalidFieldName {
				return // a Counter inside: decode-only by design
			}
			t.Fatalf("re-encode: %v", err)
		}
		back, err := DecodeDocument(out)
		if err != nil || !Equal(d, back, true) {
			t.Fatalf("re-decode: %v", err)
		}
	})
}

// FuzzParseJSON: no JSON text may panic or hang; accepted documents print and parse back equal.
func FuzzParseJSON(f *testing.F) {
	for _, s := range []string{`{"a":[1,2.5,{"$date":"2026-01-01T00:00:00Z"}]}`, `{"$binary":{"base64":"AQID","subType":"00"}}`,
		`{"$vector":[0.5]}`, `{"$decimal":"1E+3"}`, `"😀"`, `{"$ts":"1.2"}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseJSON(s)
		if err != nil {
			return
		}
		text, err := MarshalJSON(v, Extended)
		if err != nil {
			t.Fatalf("print: %v", err)
		}
		back, err := ParseJSON(text)
		if err != nil || !Equal(v, back, true) {
			t.Fatalf("reparse %s: %v", text, err)
		}
	})
}
