// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rdoc

import (
	"bytes"
	"encoding/binary"
	"math"
	"unicode/utf8"
)

// DecodeDocument decodes and fully validates an RDoc v1 document (data-model.md §4). Every input
// is untrusted: reads are bounds-checked against the enclosing value, counts are bounded by the
// bytes that could hold them before anything is allocated, recursion is bounded by the depth
// limit, and every inconsistency is an *Error. With the canonical flag set, non-canonical
// encodings (non-minimal varints, NaN payloads, non-canonical decimal128) are rejected; without
// it they are accepted and normalized.
func DecodeDocument(b []byte) (Document, error) {
	if len(b) < rdocHeaderLength+1 {
		return nil, newError(CodeMalformed, "truncated header")
	}
	if b[0] != rdocMagic {
		return nil, newError(CodeMalformed, "bad magic")
	}
	if b[1] != rdocVersion {
		return nil, newError(CodeMalformed, "unsupported RDoc version %d", b[1])
	}
	if b[2]&^rdocFlagCanonical != 0 {
		return nil, newError(CodeMalformed, "unknown flag bits")
	}
	total := binary.LittleEndian.Uint32(b[3:])
	if total > MaxDocumentSize {
		return nil, tooLarge(int64(total))
	}
	if int64(total) != int64(len(b)) {
		return nil, newError(CodeMalformed, "total_len does not match the input length")
	}
	if b[rdocHeaderLength] != byte(TypeObject) {
		return nil, newError(CodeMalformed, "root is not an object")
	}
	d := decoder{buf: b, strict: b[2]&rdocFlagCanonical != 0}
	doc, next, err := d.object(rdocHeaderLength+1, len(b), 1)
	if err != nil {
		return nil, err
	}
	if next != len(b) {
		return nil, d.malformed(next, "trailing bytes after the root object")
	}
	return doc, nil
}

// DecodeValue decodes exactly one value in the value encoding (tag + payload, no header).
// Non-canonical variants are accepted and normalized.
func DecodeValue(b []byte) (any, error) {
	d := decoder{buf: b}
	v, next, err := d.value(0, len(b), 0)
	if err != nil {
		return nil, err
	}
	if next != len(b) {
		return nil, d.malformed(next, "trailing bytes after value")
	}
	return v, nil
}

type decoder struct {
	buf    []byte
	strict bool
}

func (d *decoder) malformed(pos int, reason string) *Error {
	return newError(CodeMalformed, "%s at byte %d", reason, pos)
}

// checkedEnd returns pos+length if it stays within end (int64 math: no overflow on 32-bit).
func (d *decoder) checkedEnd(pos int, length int64, end int) (int, error) {
	stop := int64(pos) + length
	if length < 0 || stop > int64(end) {
		return 0, d.malformed(pos, "length exceeds the enclosing value")
	}
	return int(stop), nil
}

// varint reads an unsigned LEB128 at pos bounded by end.
func (d *decoder) varint(pos, end int) (uint64, int, error) {
	var v uint64
	for i := 0; i < 10; i++ {
		p := pos + i
		if p >= end {
			return 0, 0, d.malformed(p, "truncated varint")
		}
		b := d.buf[p]
		if i == 9 && b > 1 {
			return 0, 0, d.malformed(p, "varint overflows u64")
		}
		v |= uint64(b&0x7F) << (7 * i)
		if b&0x80 == 0 {
			if d.strict && i > 0 && b == 0 {
				return 0, 0, d.malformed(p, "non-minimal varint")
			}
			return v, p + 1, nil
		}
	}
	return 0, 0, d.malformed(pos, "varint too long")
}

// length reads a varint length; anything beyond the input cannot be satisfied, and rejecting it
// here keeps later arithmetic in range.
func (d *decoder) length(pos, end int) (int64, int, error) {
	v, next, err := d.varint(pos, end)
	if err != nil {
		return 0, 0, err
	}
	if v > uint64(len(d.buf)) {
		return 0, 0, d.malformed(pos, "length exceeds the enclosing value")
	}
	return int64(v), next, nil
}

func (d *decoder) utf8(pos, end int) (s string, next, at int, err error) {
	n, at, err := d.length(pos, end)
	if err != nil {
		return "", 0, 0, err
	}
	if next, err = d.checkedEnd(at, n, end); err != nil {
		return "", 0, 0, err
	}
	raw := d.buf[at:next]
	if !utf8.Valid(raw) {
		return "", 0, 0, d.malformed(at, "invalid UTF-8")
	}
	return string(raw), next, at, nil
}

type containerHeader struct {
	count                    int
	tableAt, bodyAt, bodyEnd int
}

func (d *decoder) header(pos, end int, entry int64) (containerHeader, error) {
	n, p, err := d.length(pos, end)
	if err != nil {
		return containerHeader{}, err
	}
	bodyLength, tableAt, err := d.length(p, end)
	if err != nil {
		return containerHeader{}, err
	}
	bodyAt, err := d.checkedEnd(tableAt, n*entry, end)
	if err != nil {
		return containerHeader{}, err
	}
	bodyEnd, err := d.checkedEnd(bodyAt, bodyLength, end)
	if err != nil {
		return containerHeader{}, err
	}
	return containerHeader{int(n), tableAt, bodyAt, bodyEnd}, nil
}

// value decodes the value whose tag is at pos; containers get depth+1.
func (d *decoder) value(pos, end, depth int) (any, int, error) {
	if pos >= end {
		return nil, 0, d.malformed(pos, "missing value")
	}
	at := pos + 1
	switch Type(d.buf[pos]) {
	case TypeNull:
		return nil, at, nil
	case TypeMinKey:
		return MinKey{}, at, nil
	case TypeMaxKey:
		return MaxKey{}, at, nil
	case TypeBool:
		next, err := d.checkedEnd(at, 1, end)
		if err != nil {
			return nil, 0, err
		}
		switch d.buf[at] {
		case 0:
			return false, next, nil
		case 1:
			return true, next, nil
		}
		return nil, 0, d.malformed(at, "bool byte not 0 or 1")
	case TypeInt64, TypeDateTime, TypeCounter:
		z, next, err := d.varint(at, end)
		if err != nil {
			return nil, 0, err
		}
		switch Type(d.buf[pos]) {
		case TypeInt64:
			return unzigzag(z), next, nil
		case TypeDateTime:
			return DateTime(unzigzag(z)), next, nil
		}
		return Counter(unzigzag(z)), next, nil
	case TypeFloat64:
		next, err := d.checkedEnd(at, 8, end)
		if err != nil {
			return nil, 0, err
		}
		bits := binary.LittleEndian.Uint64(d.buf[at:])
		f := math.Float64frombits(bits)
		if f != f {
			if d.strict && bits != canonicalNaNBits {
				return nil, 0, d.malformed(at, "non-canonical NaN")
			}
			f = math.Float64frombits(canonicalNaNBits)
		}
		return f, next, nil
	case TypeDecimal128:
		next, err := d.checkedEnd(at, 16, end)
		if err != nil {
			return nil, 0, err
		}
		dec, canonical := decimalFromBits(binary.LittleEndian.Uint64(d.buf[at+8:]), binary.LittleEndian.Uint64(d.buf[at:]))
		if d.strict && !canonical {
			return nil, 0, d.malformed(at, "non-canonical decimal128")
		}
		return dec, next, nil
	case TypeString:
		s, next, _, err := d.utf8(at, end)
		if err != nil {
			return nil, 0, err
		}
		return s, next, nil
	case TypeBinary:
		if _, err := d.checkedEnd(at, 1, end); err != nil {
			return nil, 0, err
		}
		subtype := d.buf[at]
		n, dataAt, err := d.length(at+1, end)
		if err != nil {
			return nil, 0, err
		}
		next, err := d.checkedEnd(dataAt, n, end)
		if err != nil {
			return nil, 0, err
		}
		if r := checkBinary(subtype, int(n)); r != "" {
			return nil, 0, d.malformed(at, r)
		}
		return Binary{Subtype: subtype, Data: bytes.Clone(d.buf[dataAt:next])}, next, nil
	case TypeTimestamp:
		next, err := d.checkedEnd(at, 12, end)
		if err != nil {
			return nil, 0, err
		}
		return Timestamp{binary.LittleEndian.Uint64(d.buf[at:]), binary.LittleEndian.Uint32(d.buf[at+8:])}, next, nil
	case TypeObjectID:
		next, err := d.checkedEnd(at, 12, end)
		if err != nil {
			return nil, 0, err
		}
		var id ObjectID
		copy(id[:], d.buf[at:next])
		return id, next, nil
	case TypeUUID:
		next, err := d.checkedEnd(at, 16, end)
		if err != nil {
			return nil, 0, err
		}
		var u UUID
		copy(u[:], d.buf[at:next])
		return u, next, nil
	case TypeVectorF32:
		dims, q, err := d.length(at, end)
		if err != nil {
			return nil, 0, err
		}
		next, err := d.checkedEnd(q, 4*dims, end)
		if err != nil {
			return nil, 0, err
		}
		v := make(Vector, dims)
		for i := range v {
			x := math.Float32frombits(binary.LittleEndian.Uint32(d.buf[q+4*i:]))
			if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
				return nil, 0, newError(CodeInvalidVector, "non-finite vector element at byte %d", q+4*i)
			}
			v[i] = x
		}
		return v, next, nil
	case TypeArray:
		return d.array(at, end, depth+1)
	case TypeObject:
		return d.object(at, end, depth+1)
	}
	return nil, 0, d.malformed(pos, "unknown type tag")
}

type decodedField struct {
	start  int // offset from the body start
	nameAt int
	name   string
}

// object decodes an object (after its tag) and checks the index against the fields: every entry
// points at a field start and carries that field's name hash, and entries strictly increase by
// (hash, name bytes) — which also proves the names unique and the index a permutation.
func (d *decoder) object(pos, end, depth int) (Document, int, error) {
	if err := checkDepth(depth); err != nil {
		return nil, 0, err
	}
	h, err := d.header(pos, end, indexEntryLength)
	if err != nil {
		return nil, 0, err
	}
	// Each field takes at least 3 bytes (name length, one name byte, tag): bound the count before
	// allocating so a forged count cannot reserve gigabytes.
	if h.count > (h.bodyEnd-h.bodyAt)/3 {
		return nil, 0, d.malformed(pos, "field count exceeds the body")
	}
	doc := make(Document, 0, h.count)
	fields := make([]decodedField, 0, h.count)
	q := h.bodyAt
	for i := 0; i < h.count; i++ {
		start := q - h.bodyAt
		name, afterName, nameAt, err := d.utf8(q, h.bodyEnd)
		if err != nil {
			return nil, 0, err
		}
		if r := fieldNameError(name); r != "" {
			return nil, 0, newError(CodeInvalidFieldName, "%s at byte %d", r, q)
		}
		v, next, err := d.value(afterName, h.bodyEnd, depth)
		if err != nil {
			return nil, 0, err
		}
		q = next
		doc = append(doc, Field{name, v})
		fields = append(fields, decodedField{start, nameAt, name})
	}
	if q != h.bodyEnd {
		return nil, 0, d.malformed(q, "object body length mismatch")
	}
	var prev *decodedField
	var prevHash uint16
	for i := 0; i < h.count; i++ {
		at := h.tableAt + i*indexEntryLength
		hash := binary.LittleEndian.Uint16(d.buf[at:])
		offset := binary.LittleEndian.Uint32(d.buf[at+2:])
		j := findStart(fields, offset)
		if j < 0 {
			return nil, 0, d.malformed(at, "index offset is not a field start")
		}
		f := &fields[j]
		if NameHash16(f.name) != hash {
			return nil, 0, d.malformed(at, "index hash mismatch")
		}
		if prev != nil {
			c := 0
			switch {
			case prevHash < hash:
				c = -1
			case prevHash > hash:
				c = 1
			case prev.name < f.name:
				c = -1
			case prev.name > f.name:
				c = 1
			}
			if c == 0 {
				return nil, 0, newError(CodeInvalidFieldName, "duplicate field name %q", f.name)
			}
			if c > 0 {
				return nil, 0, d.malformed(at, "index not sorted")
			}
		}
		prev, prevHash = f, hash
	}
	return doc, h.bodyEnd, nil
}

// findStart binary-searches a field start (starts ascend: fields are in order).
func findStart(fields []decodedField, offset uint32) int {
	lo, hi := 0, len(fields)-1
	for lo <= hi {
		mid := lo + (hi-lo)/2
		s := int64(fields[mid].start)
		switch {
		case s == int64(offset):
			return mid
		case s < int64(offset):
			lo = mid + 1
		default:
			hi = mid - 1
		}
	}
	return -1
}

func (d *decoder) array(pos, end, depth int) ([]any, int, error) {
	if err := checkDepth(depth); err != nil {
		return nil, 0, err
	}
	h, err := d.header(pos, end, arrayOffsetLength)
	if err != nil {
		return nil, 0, err
	}
	if h.count > h.bodyEnd-h.bodyAt {
		return nil, 0, d.malformed(pos, "element count exceeds the body")
	}
	items := make([]any, 0, h.count)
	q := h.bodyAt
	for i := 0; i < h.count; i++ {
		at := h.tableAt + i*arrayOffsetLength
		if int64(binary.LittleEndian.Uint32(d.buf[at:])) != int64(q-h.bodyAt) {
			return nil, 0, d.malformed(at, "array offset mismatch")
		}
		v, next, err := d.value(q, h.bodyEnd, depth)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, v)
		q = next
	}
	if q != h.bodyEnd {
		return nil, 0, d.malformed(q, "array body length mismatch")
	}
	return items, h.bodyEnd, nil
}
