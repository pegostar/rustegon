// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

// Package rdoc is the Rustegon data model (data-model.md §2): the RDoc v1 binary codec (§4) and
// the canonical / extended JSON forms, byte for byte as the server (crates/rustegon-doc) and the
// .NET and Java drivers.
//
// A value is an `any` holding exactly one of: nil (null), bool, int64, float64, Decimal128,
// string, Binary, DateTime, Timestamp, ObjectID, UUID, []any (array), Document (object), Vector,
// Counter, MinKey, MaxKey. Normalize converts convenience Go values (int, time.Time, maps, ...)
// into that model.
package rdoc

import (
	"fmt"
	"time"
)

// Document is an ordered object; field order is significant and preserved by the codec.
type Document []Field

// Field is one name/value pair of a Document.
type Field struct {
	Name  string
	Value any
}

// Get returns the value of the first field named name.
func (d Document) Get(name string) (any, bool) {
	for _, f := range d {
		if f.Name == name {
			return f.Value, true
		}
	}
	return nil, false
}

// Binary is binary data with a subtype: 0 generic, 4 UUID (16 bytes), 0x80–0xFF user defined.
type Binary struct {
	Subtype byte
	Data    []byte
}

// Binary subtypes of data-model.md §2.
const (
	BinaryGeneric     byte = 0x00
	BinaryUUID        byte = 0x04
	BinaryUserDefined byte = 0x80
)

// checkBinary returns the reason a subtype/length pair is invalid, or "".
func checkBinary(subtype byte, length int) string {
	switch {
	case subtype == BinaryGeneric, subtype >= BinaryUserDefined:
		return ""
	case subtype == BinaryUUID && length == 16:
		return ""
	case subtype == BinaryUUID:
		return "binary subtype 4 (uuid) needs 16 bytes"
	default:
		return "reserved binary subtype"
	}
}

// DateTime is a UTC instant in milliseconds since the Unix epoch.
type DateTime int64

// Time converts to a time.Time in UTC.
func (t DateTime) Time() time.Time { return time.UnixMilli(int64(t)).UTC() }

// NewDateTime truncates t to milliseconds.
func NewDateTime(t time.Time) DateTime { return DateTime(t.UnixMilli()) }

// Timestamp is a hybrid logical clock timestamp (mostly system generated).
type Timestamp struct {
	Wall    uint64
	Logical uint32
}

// String is the `$ts` text "<wall>.<logical>".
func (t Timestamp) String() string { return fmt.Sprintf("%d.%d", t.Wall, t.Logical) }

// Vector is a vector of finite 32-bit floats.
type Vector []float32

// Counter is the read-only projection of a document counter: decoded, never encoded.
type Counter int64

// MinKey is the smallest value of the total order (range bounds).
type MinKey struct{}

// MaxKey is the largest value of the total order (range bounds).
type MaxKey struct{}

// Type is a data-model type; its numeric value is the RDoc v1 type tag.
type Type byte

// Type tags of data-model.md §2.
const (
	TypeNull       Type = 0x01
	TypeBool       Type = 0x02
	TypeInt64      Type = 0x03
	TypeFloat64    Type = 0x04
	TypeDecimal128 Type = 0x05
	TypeString     Type = 0x06
	TypeBinary     Type = 0x07
	TypeDateTime   Type = 0x08
	TypeTimestamp  Type = 0x09
	TypeObjectID   Type = 0x0A
	TypeUUID       Type = 0x0B
	TypeArray      Type = 0x0C
	TypeObject     Type = 0x0D
	TypeVectorF32  Type = 0x0E
	TypeCounter    Type = 0x0F
	TypeMinKey     Type = 0x10
	TypeMaxKey     Type = 0x11
)

var typeNames = [...]string{
	TypeNull: "null", TypeBool: "bool", TypeInt64: "int64", TypeFloat64: "float64",
	TypeDecimal128: "decimal128", TypeString: "string", TypeBinary: "binary", TypeDateTime: "datetime",
	TypeTimestamp: "timestamp", TypeObjectID: "objectId", TypeUUID: "uuid", TypeArray: "array",
	TypeObject: "object", TypeVectorF32: "vector_f32", TypeCounter: "counter", TypeMinKey: "minKey",
	TypeMaxKey: "maxKey",
}

// String returns the data-model §2 name ("int64", "objectId", "vector_f32", ...).
func (t Type) String() string {
	if int(t) < len(typeNames) && typeNames[t] != "" {
		return typeNames[t]
	}
	return fmt.Sprintf("Type(0x%02x)", byte(t))
}

// TypeOf returns the type of a model value; anything outside the model is RGN-1001.
func TypeOf(v any) (Type, error) {
	switch v.(type) {
	case nil:
		return TypeNull, nil
	case bool:
		return TypeBool, nil
	case int64:
		return TypeInt64, nil
	case float64:
		return TypeFloat64, nil
	case Decimal128:
		return TypeDecimal128, nil
	case string:
		return TypeString, nil
	case Binary:
		return TypeBinary, nil
	case DateTime:
		return TypeDateTime, nil
	case Timestamp:
		return TypeTimestamp, nil
	case ObjectID:
		return TypeObjectID, nil
	case UUID:
		return TypeUUID, nil
	case []any:
		return TypeArray, nil
	case Document:
		return TypeObject, nil
	case Vector:
		return TypeVectorF32, nil
	case Counter:
		return TypeCounter, nil
	case MinKey:
		return TypeMinKey, nil
	case MaxKey:
		return TypeMaxKey, nil
	}
	return 0, newError(CodeMalformed, "unsupported Go type %T (use Normalize)", v)
}

// Error codes of codec failures (proto/errors.yaml).
const (
	CodeMalformed        = 1001
	CodeTooLarge         = 1002
	CodeTooDeep          = 1003
	CodeInvalidFieldName = 1004
	CodeInvalidVector    = 1040
)

// Error is a codec failure with its catalog code (RGN-<Code>).
type Error struct {
	Code    int
	Kind    string // malformed, too_large, too_deep, invalid_field_name, invalid_vector
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("RGN-%d %s: %s", e.Code, e.Kind, e.Message) }

var errorKinds = map[int]string{
	CodeMalformed: "malformed", CodeTooLarge: "too_large", CodeTooDeep: "too_deep",
	CodeInvalidFieldName: "invalid_field_name", CodeInvalidVector: "invalid_vector",
}

func newError(code int, format string, args ...any) *Error {
	return &Error{Code: code, Kind: errorKinds[code], Message: fmt.Sprintf(format, args...)}
}

// Limits of data-model.md §2.2 / §4.
const (
	MaxDocumentSize    = 16 * 1024 * 1024 // header included (RGN-1002)
	MaxDepth           = 100              // the root object is depth 1 (RGN-1003)
	MaxFieldNameLength = 1024             // UTF-8 bytes
)

// fieldNameError validates a field name (§2.2): 1–1024 bytes, no NUL, no leading '$'.
func fieldNameError(name string) string {
	switch {
	case name == "":
		return "empty field name"
	case len(name) > MaxFieldNameLength:
		return "field name longer than 1024 bytes"
	}
	for i := 0; i < len(name); i++ {
		if name[i] == 0 {
			return "field name contains NUL"
		}
	}
	if name[0] == '$' {
		return "field name starts with '$'"
	}
	return ""
}
