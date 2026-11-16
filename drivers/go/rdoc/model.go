// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rdoc

import (
	"bytes"
	"math"
	"reflect"
	"sort"
	"time"
)

// Normalize converts convenience Go values into the model, recursively: signed and unsigned
// integers → int64 (uint64/uint only up to MaxInt64), float32 → float64, time.Time → DateTime,
// []byte → Binary{0}, other slices and arrays → []any, maps with string keys → Document with the
// keys sorted (deterministic: Go map order is random), *Document and other pointers → the pointee
// (nil → null). Model values pass through, their contents normalized. Anything else is RGN-1001.
func Normalize(v any) (any, error) {
	switch x := v.(type) {
	case nil, bool, int64, float64, Decimal128, string, Binary, DateTime, Timestamp, ObjectID,
		UUID, Vector, Counter, MinKey, MaxKey:
		return v, nil
	case int:
		return int64(x), nil
	case int8:
		return int64(x), nil
	case int16:
		return int64(x), nil
	case int32:
		return int64(x), nil
	case uint8:
		return int64(x), nil
	case uint16:
		return int64(x), nil
	case uint32:
		return int64(x), nil
	case uint:
		return normalizeUint(uint64(x))
	case uint64:
		return normalizeUint(x)
	case float32:
		return float64(x), nil
	case time.Time:
		return NewDateTime(x), nil
	case []byte:
		return Binary{Subtype: BinaryGeneric, Data: x}, nil
	case Document:
		out := make(Document, len(x))
		for i, f := range x {
			nv, err := Normalize(f.Value)
			if err != nil {
				return nil, err
			}
			out[i] = Field{f.Name, nv}
		}
		return out, nil
	case *Document:
		if x == nil {
			return nil, nil
		}
		return Normalize(*x)
	case []any:
		out := make([]any, len(x))
		for i, it := range x {
			nv, err := Normalize(it)
			if err != nil {
				return nil, err
			}
			out[i] = nv
		}
		return out, nil
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil, nil
		}
		return Normalize(rv.Elem().Interface())
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return nil, nil
		}
		out := make([]any, rv.Len())
		for i := range out {
			nv, err := Normalize(rv.Index(i).Interface())
			if err != nil {
				return nil, err
			}
			out[i] = nv
		}
		return out, nil
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			break
		}
		if rv.IsNil() {
			return nil, nil
		}
		keys := rv.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		out := make(Document, len(keys))
		for i, k := range keys {
			nv, err := Normalize(rv.MapIndex(k).Interface())
			if err != nil {
				return nil, err
			}
			out[i] = Field{k.String(), nv}
		}
		return out, nil
	case reflect.Bool:
		return rv.Bool(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return normalizeUint(rv.Uint())
	case reflect.Float32, reflect.Float64:
		return rv.Float(), nil
	case reflect.String:
		return rv.String(), nil
	}
	return nil, newError(CodeMalformed, "unsupported Go type %T", v)
}

func normalizeUint(u uint64) (any, error) {
	if u > math.MaxInt64 {
		return nil, newError(CodeMalformed, "unsigned integer %d exceeds int64", u)
	}
	return int64(u), nil
}

// Equal reports whether two model values are equal: same types and values; all NaNs are equal;
// otherwise floats compare by bits (-0.0 != 0.0); Decimal128 by bits (cohort-sensitive). With
// fieldOrder false, Document field order is ignored (names are unique, so matching by name is
// exact); with true it must match too.
func Equal(a, b any, fieldOrder bool) bool {
	switch x := a.(type) {
	case float64:
		y, ok := b.(float64)
		return ok && (math.Float64bits(x) == math.Float64bits(y) || (x != x && y != y))
	case Binary:
		y, ok := b.(Binary)
		return ok && x.Subtype == y.Subtype && bytes.Equal(x.Data, y.Data)
	case Vector:
		y, ok := b.(Vector)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if math.Float32bits(x[i]) != math.Float32bits(y[i]) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !Equal(x[i], y[i], fieldOrder) {
				return false
			}
		}
		return true
	case Document:
		y, ok := b.(Document)
		if !ok || len(x) != len(y) {
			return false
		}
		for i, f := range x {
			var w any
			if fieldOrder {
				if y[i].Name != f.Name {
					return false
				}
				w = y[i].Value
			} else if w, ok = y.Get(f.Name); !ok {
				return false
			}
			if !Equal(f.Value, w, fieldOrder) {
				return false
			}
		}
		return true
	case nil, bool, int64, Decimal128, string, DateTime, Timestamp, ObjectID, UUID, Counter, MinKey, MaxKey:
		return a == b
	}
	return false
}
