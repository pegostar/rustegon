// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rustegon/rustegon/drivers/go/rdoc"
)

// ymap is an ordered YAML/JSON mapping: field order matters for documents.
type ymap struct {
	keys []string
	vals map[string]any
}

func (m *ymap) get(k string) any {
	if m == nil {
		return nil
	}
	return m.vals[k]
}

func (m *ymap) has(k string) bool {
	if m == nil {
		return false
	}
	_, ok := m.vals[k]
	return ok
}

func (m *ymap) str(k string) string { s, _ := m.get(k).(string); return s }
func (m *ymap) mp(k string) *ymap   { v, _ := m.get(k).(*ymap); return v }
func (m *ymap) list(k string) []any { v, _ := m.get(k).([]any); return v }
func (m *ymap) isTrue(k string) bool {
	b, _ := m.get(k).(bool)
	return b
}

// single returns the only key and value of a one-key mapping.
func (m *ymap) single() (string, any) {
	if m == nil || len(m.keys) != 1 {
		panic(fmt.Sprintf("expected a one-key mapping, got %v", m))
	}
	return m.keys[0], m.vals[m.keys[0]]
}

func conformanceDir() string {
	return filepath.Join("..", "conformance")
}

func loadYAML(path string) (any, error) {
	text, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseYAML(text)
}

func parseYAML(text []byte) (any, error) {
	var n yaml.Node
	if err := yaml.Unmarshal(text, &n); err != nil {
		return nil, err
	}
	if len(n.Content) == 0 {
		return nil, nil
	}
	return toModel(n.Content[0])
}

// toModel converts a node: YAML integers are int64, floats float64 (README §5 "Values").
func toModel(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.AliasNode:
		return toModel(n.Alias)
	case yaml.MappingNode:
		m := &ymap{vals: map[string]any{}}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			v, err := toModel(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			m.keys = append(m.keys, k)
			m.vals[k] = v
		}
		return m, nil
	case yaml.SequenceNode:
		out := []any{}
		for _, c := range n.Content {
			v, err := toModel(c)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!null":
			return nil, nil
		case "!!bool":
			return strings.EqualFold(n.Value, "true"), nil
		case "!!int":
			v, err := strconv.ParseInt(n.Value, 0, 64)
			if err != nil {
				f, ferr := strconv.ParseFloat(n.Value, 64)
				if ferr != nil {
					return nil, err
				}
				return f, nil
			}
			return v, nil
		case "!!float":
			switch strings.ToLower(n.Value) {
			case ".nan":
				return math.NaN(), nil
			case ".inf", "+.inf":
				return math.Inf(1), nil
			case "-.inf":
				return math.Inf(-1), nil
			}
			return strconv.ParseFloat(n.Value, 64)
		default:
			return n.Value, nil
		}
	}
	return nil, fmt.Errorf("unsupported YAML node kind %v", n.Kind)
}

var wrappers = map[string]bool{"$oid": true, "$date": true, "$int64": true, "$float": true, "$decimal": true, "$binary": true,
	"$uuid": true, "$vector": true, "$ts": true, "$minKey": true, "$maxKey": true, "$counter": true}

func isWrapper(m *ymap) bool { return len(m.keys) == 1 && wrappers[m.keys[0]] }

var systemFields = map[string]bool{"_rev": true, "_createdAt": true, "_updatedAt": true}

// toJSON writes a model value as JSON text (wrappers become extended JSON input).
func toJSON(v any) string {
	var b strings.Builder
	writeJSON(&b, v)
	return b.String()
}

func writeJSON(b *strings.Builder, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case float64:
		t := strconv.FormatFloat(x, 'g', -1, 64)
		if !strings.ContainsAny(t, ".eE") {
			t += ".0"
		}
		b.WriteString(t)
	case string:
		s, _ := rdoc.MarshalJSON(x, rdoc.Canonical)
		b.WriteString(s)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSON(b, e)
		}
		b.WriteByte(']')
	case *ymap:
		b.WriteByte('{')
		for i, k := range x.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			s, _ := rdoc.MarshalJSON(k, rdoc.Canonical)
			b.WriteString(s)
			b.WriteByte(':')
			writeJSON(b, x.vals[k])
		}
		b.WriteByte('}')
	default:
		panic(fmt.Sprintf("unsupported model value %T", v))
	}
}

// toValue converts a model value to an rdoc value; strings go through resolve ($$ref, ${…}).
func toValue(v any, resolve func(string) any) any {
	switch x := v.(type) {
	case nil, bool, int64, float64:
		return x
	case string:
		if resolve != nil {
			return resolve(x)
		}
		return x
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = toValue(e, resolve)
		}
		return out
	case *ymap:
		if isWrapper(x) {
			w, err := rdoc.ParseJSON(toJSON(x))
			if err != nil {
				panic(fmt.Sprintf("bad wrapper %s: %v", toJSON(x), err))
			}
			return w
		}
		return toDocument(x, resolve)
	}
	panic(fmt.Sprintf("unsupported model value %T", v))
}

func toDocument(m *ymap, resolve func(string) any) rdoc.Document {
	d := make(rdoc.Document, 0, len(m.keys))
	for _, k := range m.keys {
		d = append(d, rdoc.Field{Name: k, Value: toValue(m.vals[k], resolve)})
	}
	return d
}

func typeName(v any) string {
	t, err := rdoc.TypeOf(v)
	if err != nil {
		return "missing"
	}
	return t.String()
}

func valueJSON(v any) string {
	s, err := rdoc.MarshalJSON(v, rdoc.Canonical)
	if err != nil {
		return fmt.Sprintf("<%v>", err)
	}
	return s
}
