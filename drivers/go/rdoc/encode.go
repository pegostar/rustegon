// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rdoc

import (
	"encoding/binary"
	"math"
	"sort"
	"unicode/utf8"

	"github.com/zeebo/xxh3"
)

// RDoc v1 header constants (data-model.md §4).
const (
	rdocMagic         = 0xD7
	rdocVersion       = 1
	rdocFlagCanonical = 0x01
	rdocHeaderLength  = 7
	indexEntryLength  = 6
	arrayOffsetLength = 4
	canonicalNaNBits  = 0x7FF8000000000000
)

// NameHash16 is the object-index hash of a field name: the low 16 bits of xxh3_64(name, seed 0).
func NameHash16(name string) uint16 { return uint16(xxh3.HashString(name)) }

func zigzag(v int64) uint64   { return uint64(v<<1) ^ uint64(v>>63) }
func unzigzag(z uint64) int64 { return int64(z>>1) ^ -int64(z&1) }

func varintLength(v uint64) int64 {
	n := int64(1)
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}

// EncodeDocument encodes d as canonical RDoc v1 (flags 0x01), validating it first: field names
// (RGN-1004, duplicates included), depth ≤ 100 (RGN-1003), 16 MiB (RGN-1002), finite vectors
// (RGN-1040), binary subtypes and UTF-8 (RGN-1001); a Counter is never accepted as input
// (RGN-1004, as the server and the JSON parser).
func EncodeDocument(d Document) ([]byte, error) {
	var e encoder
	size, err := e.measureObject(d, 1)
	if err != nil {
		return nil, err
	}
	total := rdocHeaderLength + size
	if total > MaxDocumentSize {
		return nil, tooLarge(total)
	}
	e.out = make([]byte, rdocHeaderLength, total)
	e.out[0], e.out[1], e.out[2] = rdocMagic, rdocVersion, rdocFlagCanonical
	binary.LittleEndian.PutUint32(e.out[3:], uint32(total))
	e.object(d)
	return e.out, nil
}

// EncodeValue encodes one value in the value encoding (tag + payload exactly as inside a
// document, no header: Value.rdoc_value of protocol.md §3), with EncodeDocument's validations.
func EncodeValue(v any) ([]byte, error) {
	var e encoder
	size, err := e.measureValue(v, 0)
	if err != nil {
		return nil, err
	}
	e.out = make([]byte, 0, size)
	e.value(v)
	return e.out, nil
}

func tooLarge(size int64) *Error {
	return newError(CodeTooLarge, "document of %d bytes exceeds the %d-byte limit", size, MaxDocumentSize)
}

// encoder writes in two passes like the Rust encoder: measure validates everything and records
// every container's body length in pre-order (lengths are varint prefixes, so they must be known
// before the body), then the write pass appends without further checks.
type encoder struct {
	sizes []int64
	next  int
	out   []byte
}

func lengthPrefixed(n int64) int64 { return varintLength(uint64(n)) + n }

func containerSize(n int, entry int64, body int64) int64 {
	return 1 + varintLength(uint64(n)) + varintLength(uint64(body)) + entry*int64(n) + body
}

func checkDepth(depth int) error {
	if depth > MaxDepth {
		return newError(CodeTooDeep, "nesting deeper than %d levels", MaxDepth)
	}
	return nil
}

func (e *encoder) measureValue(v any, depth int) (int64, error) {
	var size int64
	switch x := v.(type) {
	case nil, MinKey, MaxKey:
		size = 1
	case bool:
		size = 2
	case int64:
		size = 1 + varintLength(zigzag(x))
	case DateTime:
		size = 1 + varintLength(zigzag(int64(x)))
	case float64:
		size = 9
	case Decimal128, UUID:
		size = 17
	case Timestamp, ObjectID:
		size = 13
	case string:
		if !utf8.ValidString(x) {
			return 0, newError(CodeMalformed, "string is not valid UTF-8")
		}
		size = 1 + lengthPrefixed(int64(len(x)))
	case Binary:
		if r := checkBinary(x.Subtype, len(x.Data)); r != "" {
			return 0, newError(CodeMalformed, "%s", r)
		}
		size = 2 + lengthPrefixed(int64(len(x.Data)))
	case Vector:
		for _, f := range x {
			if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
				return 0, newError(CodeInvalidVector, "non-finite vector element")
			}
		}
		size = 1 + varintLength(uint64(len(x))) + 4*int64(len(x))
	case []any:
		var err error
		if size, err = e.measureArray(x, depth+1); err != nil {
			return 0, err
		}
	case Document:
		var err error
		if size, err = e.measureObject(x, depth+1); err != nil {
			return 0, err
		}
	case Counter:
		return 0, newError(CodeInvalidFieldName, "counter is a read-only projection, not accepted as input")
	default:
		return 0, newError(CodeMalformed, "unsupported Go type %T (use Normalize)", v)
	}
	if size > MaxDocumentSize {
		return 0, tooLarge(size)
	}
	return size, nil
}

func (e *encoder) measureObject(d Document, depth int) (int64, error) {
	if err := checkDepth(depth); err != nil {
		return 0, err
	}
	slot := len(e.sizes)
	e.sizes = append(e.sizes, 0)
	var body int64
	seen := make(map[string]struct{}, len(d))
	for _, f := range d {
		if !utf8.ValidString(f.Name) {
			return 0, newError(CodeInvalidFieldName, "field name is not valid UTF-8")
		}
		if r := fieldNameError(f.Name); r != "" {
			return 0, newError(CodeInvalidFieldName, "%s", r)
		}
		if _, dup := seen[f.Name]; dup {
			return 0, newError(CodeInvalidFieldName, "duplicate field name %q", f.Name)
		}
		seen[f.Name] = struct{}{}
		size, err := e.measureValue(f.Value, depth)
		if err != nil {
			return 0, err
		}
		body += lengthPrefixed(int64(len(f.Name))) + size
		if body > MaxDocumentSize {
			return 0, tooLarge(body)
		}
	}
	e.sizes[slot] = body
	return containerSize(len(d), indexEntryLength, body), nil
}

func (e *encoder) measureArray(items []any, depth int) (int64, error) {
	if err := checkDepth(depth); err != nil {
		return 0, err
	}
	slot := len(e.sizes)
	e.sizes = append(e.sizes, 0)
	var body int64
	for _, it := range items {
		size, err := e.measureValue(it, depth)
		if err != nil {
			return 0, err
		}
		body += size
		if body > MaxDocumentSize {
			return 0, tooLarge(body)
		}
	}
	e.sizes[slot] = body
	return containerSize(len(items), arrayOffsetLength, body), nil
}

func (e *encoder) varint(v uint64) {
	for v >= 0x80 {
		e.out = append(e.out, byte(v)|0x80)
		v >>= 7
	}
	e.out = append(e.out, byte(v))
}

func (e *encoder) nextSize() int64 {
	s := e.sizes[e.next]
	e.next++
	return s
}

// value writes a value already validated by measureValue.
func (e *encoder) value(v any) {
	switch x := v.(type) {
	case nil:
		e.out = append(e.out, byte(TypeNull))
	case MinKey:
		e.out = append(e.out, byte(TypeMinKey))
	case MaxKey:
		e.out = append(e.out, byte(TypeMaxKey))
	case bool:
		b := byte(0)
		if x {
			b = 1
		}
		e.out = append(e.out, byte(TypeBool), b)
	case int64:
		e.out = append(e.out, byte(TypeInt64))
		e.varint(zigzag(x))
	case DateTime:
		e.out = append(e.out, byte(TypeDateTime))
		e.varint(zigzag(int64(x)))
	case float64:
		bits := math.Float64bits(x)
		if x != x {
			// One NaN: canonical bytes make equal values byte-equal (data-model.md §4).
			bits = canonicalNaNBits
		}
		e.out = append(e.out, byte(TypeFloat64))
		e.out = binary.LittleEndian.AppendUint64(e.out, bits)
	case Decimal128:
		e.out = append(e.out, byte(TypeDecimal128))
		e.out = binary.LittleEndian.AppendUint64(e.out, x.lo)
		e.out = binary.LittleEndian.AppendUint64(e.out, x.hi)
	case string:
		e.out = append(e.out, byte(TypeString))
		e.varint(uint64(len(x)))
		e.out = append(e.out, x...)
	case Binary:
		e.out = append(e.out, byte(TypeBinary), x.Subtype)
		e.varint(uint64(len(x.Data)))
		e.out = append(e.out, x.Data...)
	case Timestamp:
		e.out = append(e.out, byte(TypeTimestamp))
		e.out = binary.LittleEndian.AppendUint64(e.out, x.Wall)
		e.out = binary.LittleEndian.AppendUint32(e.out, x.Logical)
	case ObjectID:
		e.out = append(e.out, byte(TypeObjectID))
		e.out = append(e.out, x[:]...)
	case UUID:
		e.out = append(e.out, byte(TypeUUID))
		e.out = append(e.out, x[:]...)
	case Vector:
		e.out = append(e.out, byte(TypeVectorF32))
		e.varint(uint64(len(x)))
		for _, f := range x {
			e.out = binary.LittleEndian.AppendUint32(e.out, math.Float32bits(f))
		}
	case []any:
		e.array(x)
	case Document:
		e.object(x)
	}
}

type indexEntry struct {
	hash   uint16
	name   string
	offset uint32
}

func (e *encoder) object(d Document) {
	e.out = append(e.out, byte(TypeObject))
	e.varint(uint64(len(d)))
	e.varint(uint64(e.nextSize()))
	indexAt := len(e.out)
	e.out = append(e.out, make([]byte, indexEntryLength*len(d))...)
	fieldsAt := len(e.out)
	entries := make([]indexEntry, len(d))
	for i, f := range d {
		entries[i] = indexEntry{NameHash16(f.Name), f.Name, uint32(len(e.out) - fieldsAt)}
		e.varint(uint64(len(f.Name)))
		e.out = append(e.out, f.Name...)
		e.value(f.Value)
	}
	// Index order (hash, name bytes) makes lookups a binary search and the bytes canonical.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].hash != entries[j].hash {
			return entries[i].hash < entries[j].hash
		}
		return entries[i].name < entries[j].name
	})
	for j, en := range entries {
		slot := e.out[indexAt+j*indexEntryLength:]
		binary.LittleEndian.PutUint16(slot, en.hash)
		binary.LittleEndian.PutUint32(slot[2:], en.offset)
	}
}

func (e *encoder) array(items []any) {
	e.out = append(e.out, byte(TypeArray))
	e.varint(uint64(len(items)))
	e.varint(uint64(e.nextSize()))
	tableAt := len(e.out)
	e.out = append(e.out, make([]byte, arrayOffsetLength*len(items))...)
	elementsAt := len(e.out)
	for i, it := range items {
		binary.LittleEndian.PutUint32(e.out[tableAt+i*arrayOffsetLength:], uint32(len(e.out)-elementsAt))
		e.value(it)
	}
}
