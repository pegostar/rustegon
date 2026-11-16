// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rdoc

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Codec conformance vectors (drivers/conformance/README.md §3), shared by this package's tests
// and the driver's conformance runner (TC-DRV-GO-001).

type vectorFile struct {
	Version      int            `yaml:"version"`
	Values       []vectorEntry  `yaml:"values"`
	Documents    []vectorEntry  `yaml:"documents"`
	Noncanonical []vectorEntry  `yaml:"noncanonical"`
	JSON         []invalidJSONV `yaml:"json"`
}

type vectorEntry struct {
	Name         string `yaml:"name"`
	Input        string `yaml:"input"`
	ExtJSON      string `yaml:"ext_json"`
	ExtendedJSON string `yaml:"extended_json"`
	Hex          string `yaml:"hex"`
	CanonicalHex string `yaml:"canonical_hex"`
	DecodeOnly   bool   `yaml:"decode_only"`
	Error        string `yaml:"error"`
	Code         int    `yaml:"code"`
	NameHash16   []struct {
		Name string `yaml:"name"`
		Hash string `yaml:"hash"`
	} `yaml:"name_hash16"`
}

type invalidJSONV struct {
	Name  string `yaml:"name"`
	Kind  string `yaml:"kind"`
	JSON  string `yaml:"json"`
	Error string `yaml:"error"`
	Code  int    `yaml:"code"`
}

// CheckVectors runs every vector of one codec vector file (values.yaml, documents.yaml or
// invalid.yaml) in dir and returns the first failure, named "file#section/vector".
func CheckVectors(dir string, file string) error {
	raw, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		return err
	}
	var vf vectorFile
	if err := yaml.Unmarshal(raw, &vf); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	if vf.Version != 1 {
		return fmt.Errorf("%s: unsupported version %d", file, vf.Version)
	}
	type run struct {
		section string
		name    string
		check   func() error
	}
	var runs []run
	add := func(section string, entries []vectorEntry, check func(vectorEntry) error) {
		for _, e := range entries {
			runs = append(runs, run{section, e.Name, func() error { return check(e) }})
		}
	}
	switch file {
	case "values.yaml":
		add("values", vf.Values, checkValueVector)
		add("noncanonical", vf.Noncanonical, checkNoncanonicalValue)
	case "documents.yaml":
		add("documents", vf.Documents, checkDocumentVector)
		add("noncanonical", vf.Noncanonical, checkNoncanonicalDocument)
	case "invalid.yaml":
		add("documents", vf.Documents, func(e vectorEntry) error {
			return checkRejected(e.Code, func() error { _, err := DecodeDocument(mustHex(e.Hex)); return err })
		})
		add("values", vf.Values, func(e vectorEntry) error {
			return checkRejected(e.Code, func() error { _, err := DecodeValue(mustHex(e.Hex)); return err })
		})
		for _, j := range vf.JSON {
			runs = append(runs, run{"json", j.Name, func() error {
				switch j.Kind {
				case "document":
					return checkRejected(j.Code, func() error { _, err := ParseDocumentJSON(j.JSON); return err })
				case "value":
					return checkRejected(j.Code, func() error { _, err := ParseJSON(j.JSON); return err })
				}
				return fmt.Errorf("unknown kind %q", j.Kind)
			}})
		}
	default:
		return fmt.Errorf("no runner for %s", file)
	}
	if len(runs) == 0 {
		return fmt.Errorf("%s: no vectors", file)
	}
	for _, r := range runs {
		if err := r.check(); err != nil {
			return fmt.Errorf("%s#%s/%s: %w", file, r.section, r.name, err)
		}
	}
	return nil
}

// mustHex decodes vector hex; a malformed vector file then yields bytes that fail the check.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		return []byte("<bad hex in vector file>")
	}
	return b
}

func expectEqual(what, want, got string) error {
	if want != got {
		return fmt.Errorf("%s: want %s, got %s", what, want, got)
	}
	return nil
}

func encodeJSONValue(text string) (string, error) {
	v, err := ParseJSON(text)
	if err != nil {
		return "", err
	}
	b, err := EncodeValue(v)
	return hex.EncodeToString(b), err
}

func checkValueVector(e vectorEntry) error {
	if !e.DecodeOnly {
		in, err := ParseJSON(e.Input)
		if err != nil {
			return fmt.Errorf("parse input: %w", err)
		}
		ext, err := ParseJSON(e.ExtJSON)
		if err != nil {
			return fmt.Errorf("parse ext_json: %w", err)
		}
		if !Equal(in, ext, true) {
			return errors.New("input and ext_json parse to different values")
		}
		for _, text := range []string{e.Input, e.ExtJSON, e.ExtendedJSON} {
			got, err := encodeJSONValue(text)
			if err != nil {
				return fmt.Errorf("encode %s: %w", text, err)
			}
			if err := expectEqual("encode "+text, e.Hex, got); err != nil {
				return err
			}
		}
	}
	v, err := DecodeValue(mustHex(e.Hex))
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return printsBoth(v, e.ExtJSON, e.ExtendedJSON)
}

func printsBoth(v any, canonical, extended string) error {
	got, err := MarshalJSON(v, Canonical)
	if err != nil {
		return err
	}
	if err := expectEqual("canonical JSON", canonical, got); err != nil {
		return err
	}
	if extended == "" {
		return nil
	}
	if got, err = MarshalJSON(v, Extended); err != nil {
		return err
	}
	return expectEqual("extended JSON", extended, got)
}

func checkNoncanonicalValue(e vectorEntry) error {
	v, err := DecodeValue(mustHex(e.Hex))
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	b, err := EncodeValue(v)
	if err != nil {
		return err
	}
	if err := expectEqual("re-encode", e.CanonicalHex, hex.EncodeToString(b)); err != nil {
		return err
	}
	return printsBoth(v, e.ExtJSON, "")
}

func checkDocumentVector(e vectorEntry) error {
	raw := mustHex(e.Hex)
	if !e.DecodeOnly {
		d, err := ParseDocumentJSON(e.ExtJSON)
		if err != nil {
			return fmt.Errorf("parse: %w", err)
		}
		b, err := EncodeDocument(d)
		if err != nil {
			return fmt.Errorf("encode: %w", err)
		}
		if err := expectEqual("encode", e.Hex, hex.EncodeToString(b)); err != nil {
			return err
		}
	}
	if len(raw) < 3 || raw[2] != rdocFlagCanonical {
		return errors.New("canonical flag not set in the vector")
	}
	d, err := DecodeDocument(raw)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if err := printsBoth(d, e.ExtJSON, ""); err != nil {
		return err
	}
	// Counters are decode-only: re-encoding a document that holds one is refused by design.
	if !e.DecodeOnly {
		b, err := EncodeDocument(d)
		if err != nil {
			return fmt.Errorf("re-encode: %w", err)
		}
		if err := expectEqual("re-encode", e.Hex, hex.EncodeToString(b)); err != nil {
			return err
		}
	}
	for _, h := range e.NameHash16 {
		want, err := strconv.ParseUint(h.Hash, 16, 16)
		if err != nil {
			return fmt.Errorf("bad hash %q", h.Hash)
		}
		if got := NameHash16(h.Name); uint64(got) != want {
			return fmt.Errorf("name_hash16(%q): want %04x, got %04x", h.Name, want, got)
		}
		// The index stores the hash little-endian: it must be in the encoded document.
		le := binary.LittleEndian.AppendUint16(nil, uint16(want))
		if !bytes.Contains(raw, le) {
			return fmt.Errorf("hash %s not in the index", h.Hash)
		}
	}
	return nil
}

func checkNoncanonicalDocument(e vectorEntry) error {
	raw := mustHex(e.Hex)
	if len(raw) < 3 || raw[2] != 0 {
		return errors.New("noncanonical vector has the canonical flag")
	}
	d, err := DecodeDocument(raw)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	b, err := EncodeDocument(d)
	if err != nil {
		return err
	}
	if err := expectEqual("re-encode", e.CanonicalHex, hex.EncodeToString(b)); err != nil {
		return err
	}
	return printsBoth(d, e.ExtJSON, "")
}

func checkRejected(code int, parse func() error) error {
	err := parse()
	if err == nil {
		return errors.New("accepted, want rejection")
	}
	var re *Error
	if !errors.As(err, &re) {
		return fmt.Errorf("want *rdoc.Error, got %T: %v", err, err)
	}
	if re.Code != code {
		return fmt.Errorf("want code %d, got %d (%s)", code, re.Code, re.Message)
	}
	return nil
}
