// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/metadata"
)

// IsolationLevel is the isolation of a transaction; the zero value is the server default
// (serializable).
type IsolationLevel int

// Isolation levels.
const (
	ServerDefaultIsolation IsolationLevel = iota
	Serializable
	Snapshot
	ReadCommitted
)

// ValidationLevel and ValidationAction of a collection validator (zero = server default).
type (
	ValidationLevel  int
	ValidationAction int
)

// Validation levels and actions.
const (
	ValidationDefault ValidationLevel = iota
	ValidationOff
	ValidationModerate
	ValidationStrict
)

// Validation actions.
const (
	ValidationActionDefault ValidationAction = iota
	ValidationError
	ValidationWarn
)

// Validator is a JSON Schema validator of a collection.
type Validator struct {
	// JSONSchema is the schema as JSON text.
	JSONSchema string
	Level      ValidationLevel
	Action     ValidationAction
}

// opOptions collects the per-operation options; each operation reads the ones that apply.
type opOptions struct {
	session      *Session
	timeout      time.Duration
	ifRev        *string
	upsert       bool
	unordered    bool
	ifExists     bool
	ifNotExists  bool
	unique       bool
	batchSize    int
	consistency  ReadConsistency
	maxStaleness time.Duration
	writeConcern WriteConcern
	validator    *Validator
	isolation    IsolationLevel
	readOnly     bool
	maxRetryTime *time.Duration
	causal       *bool
}

// OpOption is an option of an operation. An option that does not apply is ignored.
type OpOption func(*opOptions)

func collect(opts []OpOption) opOptions {
	var o opOptions
	for _, f := range opts {
		if f != nil {
			f(&o)
		}
	}
	return o
}

// InSession runs the operation in a causally consistent session.
func InSession(s *Session) OpOption { return func(o *opOptions) { o.session = s } }

// Timeout bounds the whole operation, retries included (PD-097).
func Timeout(d time.Duration) OpOption { return func(o *opOptions) { o.timeout = d } }

// IfRev makes a by-id write conditional on the document's current _rev.
func IfRev(rev string) OpOption { return func(o *opOptions) { o.ifRev = &rev } }

// Upsert makes ReplaceOne with ID insert the document when it does not exist.
func Upsert() OpOption { return func(o *opOptions) { o.upsert = true } }

// Unordered lets a bulk write continue after a failed operation.
func Unordered() OpOption { return func(o *opOptions) { o.unordered = true } }

// IfExists makes a drop succeed (dropped = false) when the object does not exist.
func IfExists() OpOption { return func(o *opOptions) { o.ifExists = true } }

// IfNotExists makes a create succeed (created = false) when the object exists.
func IfNotExists() OpOption { return func(o *opOptions) { o.ifNotExists = true } }

// Unique makes an index unique.
func Unique() OpOption { return func(o *opOptions) { o.unique = true } }

// BatchSize sets the number of documents per batch of a cursor.
func BatchSize(n int) OpOption { return func(o *opOptions) { o.batchSize = n } }

// ReadConsistencyOf overrides the read consistency of a read (or a read-only transaction).
func ReadConsistencyOf(level ReadConsistency, maxStaleness time.Duration) OpOption {
	return func(o *opOptions) { o.consistency, o.maxStaleness = level, maxStaleness }
}

// WriteConcernOf overrides the write concern of a write (or a transaction).
func WriteConcernOf(wc WriteConcern) OpOption { return func(o *opOptions) { o.writeConcern = wc } }

// WithValidator sets the validator of CreateCollection.
func WithValidator(v Validator) OpOption { return func(o *opOptions) { o.validator = &v } }

// Isolation sets the isolation of a transaction.
func Isolation(level IsolationLevel) OpOption { return func(o *opOptions) { o.isolation = level } }

// ReadOnly declares a read-only transaction.
func ReadOnly() OpOption { return func(o *opOptions) { o.readOnly = true } }

// MaxRetryTime bounds the retries of WithTransaction (default 2 minutes).
func MaxRetryTime(d time.Duration) OpOption { return func(o *opOptions) { o.maxRetryTime = &d } }

// CausalConsistency sets whether a session propagates causality tokens (default true).
func CausalConsistency(on bool) OpOption { return func(o *opOptions) { o.causal = &on } }

// Session carries the causality token between operations (protocol.md §5.2). It performs no I/O
// and is safe for concurrent use.
type Session struct {
	causal bool
	mu     sync.Mutex
	token  string
	closed atomic.Bool
}

// CausalityToken returns the last token observed, or "".
func (s *Session) CausalityToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token
}

// Close ends the session (idempotent).
func (s *Session) Close() { s.closed.Store(true) }

func (s *Session) tokenToSend() (string, error) {
	if s.closed.Load() {
		return "", closedError("the session is closed")
	}
	if !s.causal {
		return "", nil
	}
	return s.CausalityToken(), nil
}

func (s *Session) observe(trailer metadata.MD) {
	if v := trailer.Get(causalityTokenHeader); len(v) > 0 && v[0] != "" {
		s.mu.Lock()
		s.token = v[0]
		s.mu.Unlock()
	}
}
