// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/pegostar/rustegon/drivers/go/internal/pb/rustegon/v1"
)

// ErrArgument is matched (errors.Is) by every error caused by invalid arguments or settings,
// detected by the driver before any network I/O (conformance class "Argument").
var ErrArgument = errors.New("rustegon: invalid argument")

// ErrClosed is matched by every error caused by using a closed client, session, cursor or
// transaction (conformance class "InvalidState").
var ErrClosed = errors.New("rustegon: use of a closed object")

func argumentError(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrArgument, fmt.Sprintf(format, a...))
}

func closedError(what string) error {
	return fmt.Errorf("%w: %s", ErrClosed, what)
}

// ErrorClass is a class of the shared exception hierarchy (drivers/conformance/errors-map.yaml),
// named by its language-neutral id. An ErrorClass is itself an error so that
// errors.Is(err, ClassClient) reports whether err is a *Error of that class or of a descendant.
type ErrorClass int

// The classes of errors-map.yaml.
const (
	ClassBase ErrorClass = iota
	ClassClient
	ClassQuerySyntax
	ClassDuplicateKey
	ClassDocumentValidation
	ClassTransactionConflict
	ClassTransactionAborted
	ClassCommitOutcomeUnknown
	ClassAuthentication
	ClassPasswordChangeRequired
	ClassAuthorization
	ClassUnavailable
	ClassRateLimited
	ClassTimeout
	ClassServer
)

var classNames = map[ErrorClass]string{
	ClassBase: "Base", ClassClient: "Client", ClassQuerySyntax: "QuerySyntax",
	ClassDuplicateKey: "DuplicateKey", ClassDocumentValidation: "DocumentValidation",
	ClassTransactionConflict: "TransactionConflict", ClassTransactionAborted: "TransactionAborted",
	ClassCommitOutcomeUnknown: "CommitOutcomeUnknown", ClassAuthentication: "Authentication",
	ClassPasswordChangeRequired: "PasswordChangeRequired", ClassAuthorization: "Authorization",
	ClassUnavailable: "Unavailable", ClassRateLimited: "RateLimited", ClassTimeout: "Timeout",
	ClassServer: "Server",
}

// String returns the language-neutral class id of errors-map.yaml.
func (c ErrorClass) String() string {
	if n, ok := classNames[c]; ok {
		return n
	}
	return fmt.Sprintf("ErrorClass(%d)", int(c))
}

// Error makes a class usable as an errors.Is target; it is the class id, as String.
func (c ErrorClass) Error() string { return c.String() }

// IsA reports whether c is ancestor or c itself.
func (c ErrorClass) IsA(ancestor ErrorClass) bool {
	for k := c; ; {
		if k == ancestor {
			return true
		}
		p, ok := classParents[k]
		if !ok {
			return false
		}
		k = p
	}
}

type catalogEntry struct {
	name      string
	retryable string
	internal  bool
	class     ErrorClass
}

type transportEntry struct {
	code      int
	retryable bool
	class     ErrorClass
}

// Error is a failure reported by the server (its ErrorDetail) or synthesized from a transport
// failure (errors-map.yaml `transport`). Retryable and Committed come from the response, never
// from the catalog (RGN-2002 for instance depends on the abort reason).
type Error struct {
	// Code is the catalog code (RGN-<Code>).
	Code int
	// Name is the stable error name.
	Name string
	// Class is the class of the shared hierarchy chosen by Code.
	Class ErrorClass
	// Retryable is the server's verdict on retrying the operation.
	Retryable bool
	// Committed tells, when known, whether a write was committed despite the error.
	Committed *bool
	// Details are machine-readable details of the server.
	Details map[string]string
	// TraceID identifies the request in the server logs.
	TraceID string
	// RetryAfter is the minimum wait the server asks for (RateLimited), zero otherwise.
	RetryAfter time.Duration
	// Message is a human-readable description.
	Message string

	cause error
}

func (e *Error) Error() string {
	return fmt.Sprintf("rustegon: RGN-%d %s: %s", e.Code, e.Name, e.Message)
}

// Unwrap returns the underlying transport error, if any.
func (e *Error) Unwrap() error { return e.cause }

// Is matches ErrorClass targets by class inheritance.
func (e *Error) Is(target error) bool {
	if c, ok := target.(ErrorClass); ok {
		return e.Class.IsA(c)
	}
	return false
}

func classOfCode(code int) ErrorClass {
	if c, ok := catalog[int32(code)]; ok {
		return c.class
	}
	return unknownCodeClass
}

func nameOfCode(code int) string {
	if c, ok := catalog[int32(code)]; ok {
		return c.name
	}
	return fmt.Sprintf("RGN-%d", code)
}

// newError builds an error of a catalog code with its mapped class.
func newError(code int, retryable bool, message string) *Error {
	return &Error{Code: code, Name: nameOfCode(code), Class: classOfCode(code), Retryable: retryable, Message: message}
}

func fromDetail(d *pb.ErrorDetail, message string, cause error) *Error {
	name := d.GetName()
	if name == "" {
		name = nameOfCode(int(d.GetCode()))
	}
	e := &Error{
		Code: int(d.GetCode()), Name: name, Class: classOfCode(int(d.GetCode())),
		Retryable: d.GetRetryable(), TraceID: d.GetTraceId(), Message: message, cause: cause,
	}
	if d.Committed != nil {
		c := d.GetCommitted()
		e.Committed = &c
	}
	if len(d.GetDetails()) > 0 {
		e.Details = make(map[string]string, len(d.GetDetails()))
		for k, v := range d.GetDetails() {
			e.Details[k] = v
		}
	}
	if d.RetryAfterMs != nil {
		e.RetryAfter = time.Duration(d.GetRetryAfterMs()) * time.Millisecond
	}
	return e
}

func fromTransport(code codes.Code, message string, cause error) *Error {
	t, ok := transportFallbacks[code]
	if !ok {
		t = transportDefault
	}
	// The fallback names the class as well as the code: a bare status maps by the fallback entry.
	return &Error{Code: t.code, Name: nameOfCode(t.code), Class: t.class, Retryable: t.retryable, Message: message, cause: cause}
}

// detailOf extracts the ErrorDetail packed in grpc-status-details-bin, or nil.
func detailOf(st *status.Status) *pb.ErrorDetail {
	for _, d := range st.Details() {
		if ed, ok := d.(*pb.ErrorDetail); ok {
			return ed
		}
	}
	return nil
}

// mapError converts an error of a gRPC call. Context cancellation of the caller is returned
// unchanged (errors-map.yaml: the language's own cancellation error, not a Rustegon error).
func mapError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	var re *Error
	if errors.As(err, &re) {
		return err
	}
	if ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled) {
		return fmt.Errorf("rustegon: operation cancelled: %w", ctx.Err())
	}
	st, ok := status.FromError(err)
	if !ok {
		if errors.Is(err, context.DeadlineExceeded) {
			return fromTransport(codes.DeadlineExceeded, err.Error(), err)
		}
		return fromTransport(codes.Unknown, err.Error(), err)
	}
	msg := st.Message()
	if msg == "" {
		msg = st.Code().String()
	}
	if d := detailOf(st); d != nil {
		return fromDetail(d, msg, err)
	}
	return fromTransport(st.Code(), msg, err)
}

// reachedServer reports whether a failed call may have reached the server: no ErrorDetail and
// no proof that nothing was sent. A Commit failing this way may have been applied (PD-119).
func reachedServer(err error) bool {
	var re *Error
	if errors.As(err, &re) && re.cause != nil {
		st, ok := status.FromError(re.cause)
		if !ok || detailOf(st) != nil {
			return false
		}
		// grpc-go reports a connection that could not be established as Unavailable with the
		// dial error text; such a call never reached the server.
		if st.Code() == codes.Unavailable && isConnectFailure(st.Message()) {
			return false
		}
		return true
	}
	return false
}

func isConnectFailure(msg string) bool {
	for _, s := range []string{"connection error", "connection refused", "no such host", "handshake", "actively refused", "unreachable"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
