// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rdoc

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"sync/atomic"
	"time"
)

// ObjectID is a 12-byte identifier: 4 bytes Unix seconds (big endian, so ids sort by creation
// second), 5 bytes random per process, 3 bytes counter (big endian).
type ObjectID [12]byte

// The per-process part and the counter start come from the OS CSPRNG once, as the .NET and Java
// drivers do: two processes then collide only if both 40-bit draws match.
var (
	oidProcess [5]byte
	oidCounter atomic.Uint32
)

func init() {
	var seed [4]byte
	// crypto/rand.Read never returns an error on supported platforms (it panics instead).
	_, _ = rand.Read(oidProcess[:])
	_, _ = rand.Read(seed[:])
	oidCounter.Store(binary.LittleEndian.Uint32(seed[:]))
}

// NewObjectID generates a fresh ObjectID for the current second.
func NewObjectID() ObjectID {
	var id ObjectID
	binary.BigEndian.PutUint32(id[:4], uint32(time.Now().Unix()))
	copy(id[4:9], oidProcess[:])
	c := oidCounter.Add(1)
	id[9], id[10], id[11] = byte(c>>16), byte(c>>8), byte(c)
	return id
}

// ParseObjectID parses 24 hex digits (either case). Errors are RGN-1001.
func ParseObjectID(s string) (ObjectID, error) {
	var id ObjectID
	if len(s) != 24 {
		return id, newError(CodeMalformed, "objectId must be 24 hex digits")
	}
	if _, err := hex.Decode(id[:], []byte(s)); err != nil {
		return id, newError(CodeMalformed, "objectId must be 24 hex digits")
	}
	return id, nil
}

// Hex returns the 24 lowercase hex digits.
func (id ObjectID) Hex() string { return hex.EncodeToString(id[:]) }

// String returns Hex().
func (id ObjectID) String() string { return id.Hex() }

// UUID is a 16-byte UUID.
type UUID [16]byte

// ParseUUID parses the 8-4-4-4-12 hex form (either case). Errors are RGN-1001.
func ParseUUID(s string) (UUID, error) {
	var u UUID
	bad := newError(CodeMalformed, "uuid: expected 8-4-4-4-12 hex")
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, bad
	}
	compact := s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	if _, err := hex.Decode(u[:], []byte(compact)); err != nil {
		return u, bad
	}
	return u, nil
}

// String returns the lowercase 8-4-4-4-12 form.
func (u UUID) String() string {
	h := hex.EncodeToString(u[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
